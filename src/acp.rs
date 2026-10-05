//! Minimal ACP (Agent Client Protocol) client: JSON-RPC 2.0, one JSON object
//! per line over the agent's stdio.
//!
//! Enough for one job: `initialize` → `session/new` → `session/prompt`, while
//! collecting `session/update` notifications. Agent-to-client requests are
//! answered: `session/request_permission` is auto-allowed (the plugin's `yolo`
//! policy); everything else gets "method not found".

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

const PROTOCOL_VERSION: u64 = 1;

/// What one prompt turn produced.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub stop_reason: String,
    /// Concatenated `agent_message_chunk` text.
    pub text: String,
    /// True when `bound_capture` dropped bytes from the transcript front, so the
    /// caller's own cap does not misreport a truncated transcript as complete.
    pub truncated: bool,
    pub updates: usize,
    pub tool_calls: usize,
    /// Count of `session/update` notifications that persist a transcript turn (a
    /// message, a tool call, or a TERMINAL tool result) or carry a valid plan —
    /// the ONLY updates Node 1.70.1 treats as evidence the agent did work.
    /// Unlike `updates`, this excludes ignored/intermediate notifications (an
    /// `in_progress` `tool_call_update`, an empty chunk, a bare status) so an
    /// otherwise-empty agent that emits one such update is not mistaken for a
    /// run that produced turns. See [`update_is_effective_turn`].
    pub effective_turns: usize,
    pub permissions_granted: usize,
    /// The prompt response's `_meta.outcome` object, if the agent emitted one.
    /// Node parity (plugin 1.70.1): an explicit ACP outcome is an effective
    /// fallback result (its `status`/`summary`/`question` vars) AND evidence the
    /// run was non-empty, so it must survive to result selection / empty
    /// detection rather than being discarded with the rest of the response.
    pub outcome: Option<Map<String, Value>>,
}

#[derive(Default)]
struct Shared {
    pending: HashMap<u64, oneshot::Sender<Result<Value>>>,
    text: String,
    /// Set when `bound_capture` trims `text`, so the truncation survives to the
    /// `Outcome` even though the trimmed length no longer reveals it.
    truncated: bool,
    updates: usize,
    tool_calls: usize,
    effective_turns: usize,
    permissions_granted: usize,
    last_activity: Option<Instant>,
}

pub struct Agent {
    child: Child,
    /// Bounded so a misbehaving agent that emits requests without draining its
    /// stdin cannot make `read_loop` queue replies without limit (see
    /// `OUT_CHANNEL_CAP`).
    out: mpsc::Sender<Value>,
    /// Explicit stdin-close signal for `write_loop`. Dropping `out` alone does
    /// not close stdin: `read_loop` holds an `out.clone()` (to answer the
    /// agent's requests) that keeps the channel — and thus `write_loop`'s owned
    /// `stdin` — alive until the agent closes its stdout. Firing this on
    /// `shutdown` makes `write_loop` drop `stdin` so the agent sees EOF promptly
    /// instead of waiting out the full terminate grace on every job.
    close_stdin: Option<oneshot::Sender<()>>,
    shared: Arc<Mutex<Shared>>,
    next_id: u64,
    /// Cancellation cleanup: SIGKILLs the agent's process group if this `Agent`
    /// is dropped while the child is still running (e.g. the slot aborts
    /// `execute` on lease loss instead of calling `shutdown`), so descendants the
    /// agent started cannot survive and overlap the job's redelivery.
    group_guard: crate::pdeath::GroupGuard,
    /// The agent's process-group id (its pid at spawn), preserved so the group
    /// can still be torn down after `child.wait()` has reaped the leader and
    /// dropped `child.id()` to `None`.
    pgid: Option<u32>,
}

impl Agent {
    /// Start `program args…` in the pinned working directory `cwd`, in its own
    /// process group.
    pub fn spawn(
        program: &str,
        args: &[String],
        cwd: &crate::safecwd::CwdHandle,
        env: &[(String, String)],
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        // Enter the working directory through the pinned, no-follow directory
        // handle (`fchdir` in the child's `pre_exec`) rather than re-resolving
        // a path at spawn time, so a same-UID actor cannot swap an ancestor for
        // a symlink between provisioning and launch and redirect the agent's
        // cwd outside the validated run tree (#35).
        cwd.apply(&mut cmd)
            .context("binding agent working directory")?;
        // Strip the daemon's own engine-connection secrets from the inherited
        // environment before layering the agent env, so the agent can never read
        // or exfiltrate the credentials the daemon uses to talk to the engine.
        for k in crate::slot::SENSITIVE_DAEMON_ENV {
            cmd.env_remove(k);
        }
        cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Discard the agent's stderr rather than inheriting the daemon's:
            // stdout is the structured ACP channel (and is bounded), while an
            // untrusted or misbehaving agent could otherwise stream unbounded
            // diagnostics into the daemon's journal/disk and exhaust it.
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        #[cfg(unix)]
        crate::pdeath::arm(&mut cmd);
        let mut child = cmd
            .spawn()
            .with_context(|| format!("starting agent {program:?}"))?;
        // Preserve the pgid (== leader pid) before anything can reap the leader.
        let pgid = child.id();
        #[cfg(unix)]
        if let Some(pid) = pgid {
            crate::pdeath::watch(pid);
        }
        let stdin = child.stdin.take().context("agent stdin")?;
        let stdout = child.stdout.take().context("agent stdout")?;
        let group_guard = crate::pdeath::GroupGuard::new(pgid);

        let shared = Arc::new(Mutex::new(Shared {
            last_activity: Some(Instant::now()),
            ..Default::default()
        }));
        let (out, rx) = mpsc::channel::<Value>(OUT_CHANNEL_CAP);
        let (close_stdin, close_rx) = oneshot::channel::<()>();
        tokio::spawn(write_loop(stdin, rx, close_rx));
        tokio::spawn(read_loop(
            BufReader::new(stdout),
            shared.clone(),
            out.clone(),
        ));
        Ok(Self {
            child,
            out,
            close_stdin: Some(close_stdin),
            shared,
            next_id: 1,
            group_guard,
            pgid,
        })
    }

    async fn request(&mut self, method: &str, params: Value, idle: Duration) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let (tx, rx) = oneshot::channel();
        self.shared.lock().unwrap().pending.insert(id, tx);
        // Bound the enqueue with the same idle budget the wait loop below uses.
        // `out` is a *bounded* channel, so this `send` blocks while it is full —
        // and it stays full when `write_loop` is wedged on a stdin the agent has
        // stopped draining (the agent floods requests, `read_loop` stops on the
        // full channel). Awaiting it unbounded would hang here *before* we ever
        // reach the idle-timeout arms, so a wedged agent could occupy the slot
        // forever and `Agent::run` could never tear the child down. On timeout,
        // drop the pending entry and fail so the caller shuts the agent down.
        let send = self
            .out
            .send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        match tokio::time::timeout(idle, send).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                self.shared.lock().unwrap().pending.remove(&id);
                bail!("agent stdin closed");
            }
            Err(_) => {
                self.shared.lock().unwrap().pending.remove(&id);
                bail!(
                    "agent stdin blocked for {}s during {method} (idle timeout)",
                    idle.as_secs()
                );
            }
        }
        let mut rx = rx;
        loop {
            tokio::select! {
                r = &mut rx => return r.map_err(|_| anyhow!("agent exited before answering {method}"))?,
                status = self.child.wait() => {
                    // Give the reader a moment to deliver a final response.
                    if let Ok(Ok(r)) = tokio::time::timeout(Duration::from_millis(200), &mut rx).await {
                        return r;
                    }
                    bail!("agent exited ({}) during {method}", status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string()));
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    let last = self.shared.lock().unwrap().last_activity.unwrap_or_else(Instant::now);
                    if last.elapsed() > idle {
                        bail!("agent produced no output for {}s during {method} (idle timeout)", idle.as_secs());
                    }
                }
            }
        }
    }

    /// Run one prompt turn to completion.
    pub async fn run(
        &mut self,
        cwd: &crate::safecwd::CwdHandle,
        prompt: &str,
        idle: Duration,
    ) -> Result<Outcome> {
        let init = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                    "clientInfo": { "name": "nano-supervisor", "version": env!("CARGO_PKG_VERSION") }
                }),
                idle,
            )
            .await
            .context("ACP initialize")?;
        if init.get("protocolVersion").is_none() {
            bail!("agent answered initialize without protocolVersion: {init}");
        }
        // The session workspace must name the SAME directory the launch bound:
        // recover it through the pinned fd (`fchdir`+`getcwd`) rather than
        // re-sending the provisioning-time path, so an ancestor swapped after
        // preparation cannot make the agent resolve a requested workspace that
        // now points at the attacker's tree (#35). The value sent is the
        // pinned inode's current path — the directory the agent is running in.
        //
        // DESIGN DECISION (maintainer, #36): we deliberately send the
        // fd-recovered ABSOLUTE path here, not `.` or an omitted field. ACP's
        // `session/new` takes a `cwd` STRING and offers no fd/capability
        // handoff, so a path string is the strongest binding the protocol
        // allows. The real protection is not this string: the agent process is
        // already launched with its cwd `fchdir`-pinned to the validated
        // checkout inode (via `CwdHandle::apply` in `pre_exec`), so it operates
        // inside the pinned inode regardless. Recovering the name through the
        // pinned fd (rather than reusing the stale provisioning path) keeps the
        // string naming that same inode, so it is informational and consistent
        // with the launch — the correct, ACP-compatible handoff.
        let session_cwd = cwd
            .path()
            .context("recovering the pinned session workspace path")?;
        let session = self
            .request(
                "session/new",
                json!({ "cwd": session_cwd, "mcpServers": [] }),
                idle,
            )
            .await
            .context("ACP session/new")?;
        let session_id = session["sessionId"]
            .as_str()
            .context("session/new returned no sessionId")?
            .to_string();
        let done = self
            .request(
                "session/prompt",
                json!({ "sessionId": session_id, "prompt": [{ "type": "text", "text": prompt }] }),
                idle,
            )
            .await
            .context("ACP session/prompt")?;
        let s = self.shared.lock().unwrap();
        Ok(Outcome {
            stop_reason: done["stopReason"].as_str().unwrap_or("unknown").to_string(),
            text: s.text.clone(),
            truncated: s.truncated,
            updates: s.updates,
            tool_calls: s.tool_calls,
            effective_turns: s.effective_turns,
            permissions_granted: s.permissions_granted,
            // Preserve the prompt response's `_meta.outcome` (plugin 1.70.1): a
            // `blocked`/explicit outcome is a usable fallback result and proof
            // the run did work, so it must not be dropped here.
            outcome: prompt_outcome(&done),
        })
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Close stdin, give the agent a moment to exit, then kill its process group.
    pub async fn shutdown(mut self) {
        // Close stdin so the agent sees EOF and can flush + exit. Dropping `out`
        // is not enough on its own — `read_loop` keeps a clone alive — so signal
        // `write_loop` to drop `stdin` explicitly as well.
        if let Some(close) = self.close_stdin.take() {
            let _ = close.send(());
        }
        drop(self.out);
        // Tear the whole process group down (TERM → grace → SIGKILL → reap), not
        // just the ACP leader: a tool the agent started shares its group but is
        // not reaped by `child.wait()`, so killing only the leader would leave a
        // TERM-resistant descendant running under the daemon while the job may be
        // redelivered. The preserved `pgid` is used so the group is still torn
        // down even if a prior `request` reaped the leader (dropping `child.id()`
        // to None); only then is the guard disarmed (the pid must not be
        // re-signalled once the group is gone — it may be recycled).
        crate::pdeath::terminate_group_and_reap(&mut self.child, self.pgid, Duration::from_secs(3))
            .await;
        self.group_guard.disarm();
    }
}

async fn write_loop(
    mut stdin: ChildStdin,
    mut rx: mpsc::Receiver<Value>,
    mut close: oneshot::Receiver<()>,
) {
    loop {
        let msg = tokio::select! {
            // An explicit close signal (or its sender being dropped) wins over
            // draining `rx`: `read_loop`'s retained `out` clone would otherwise
            // keep `rx` open — and `stdin` alive — until the agent closes stdout.
            _ = &mut close => break,
            msg = rx.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
        };
        let mut line = msg.to_string();
        line.push('\n');
        if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
            break;
        }
    }
    // Dropping `stdin` here closes the agent's stdin so it sees EOF.
}

/// Upper bound on a single JSON-RPC line the ACP agent may send. A misbehaving
/// agent could otherwise stream one huge unterminated line, and a line reader
/// would buffer it whole before we ever parse it — exhausting daemon memory (one
/// buffer per slot). Frames larger than this are dropped rather than accumulated.
const MAX_ACP_FRAME: usize = 1 << 20; // 1 MiB

/// Bound on outbound ACP frames (our requests plus replies to the agent's own
/// requests) queued for `write_loop`. The channel is bounded so a misbehaving
/// agent that emits requests without draining its stdin cannot make `read_loop`
/// queue replies without limit and exhaust daemon memory: once the buffer fills
/// (write_loop stalled on a blocked stdin), a further agent reply is treated as
/// fatal backpressure and the read loop stops rather than accumulating.
const OUT_CHANNEL_CAP: usize = 1024;

/// Per-frame byte budget for a reply we queue back to the agent. The count cap
/// [`OUT_CHANNEL_CAP`] alone does not bound *memory*: a reply echoes the agent's
/// own request `id` (and, for a permission prompt, an outcome derived from its
/// params) verbatim, and a single frame may be up to [`MAX_ACP_FRAME`] (1 MiB).
/// A hostile agent could therefore send requests carrying a multi-hundred-KB
/// `id` and, with `OUT_CHANNEL_CAP` such replies queued while `write_loop` is
/// wedged on a stdin it stopped draining, amplify them into ~1 GiB of buffered
/// frames. A well-formed JSON-RPC id/outcome serialises to far under this, so a
/// reply exceeding it means an abusive payload: it is dropped rather than queued
/// (see [`handle_message`]), capping queued outbound memory at
/// `OUT_CHANNEL_CAP * MAX_ACP_REPLY`.
const MAX_ACP_REPLY: usize = 64 * 1024; // 64 KiB

async fn read_loop<R: tokio::io::AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    shared: Arc<Mutex<Shared>>,
    out: mpsc::Sender<Value>,
) {
    // Read fixed-size chunks and split them into newline-delimited frames here,
    // instead of `lines()` whose reader buffers a whole line unbounded before
    // yielding. This caps memory at `MAX_ACP_FRAME`: an oversized unterminated
    // frame is discarded up to its next newline rather than held in full.
    let mut buf = [0u8; 64 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    let mut skipping = false; // discarding an oversized frame until its newline
    'read: loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut chunk = &buf[..n];
        while let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            let (line_bytes, rest) = chunk.split_at(pos);
            chunk = &rest[1..]; // skip the newline
            if skipping {
                // The newline ends the oversized frame we were discarding.
                skipping = false;
                pending.clear();
                continue;
            }
            if pending.len() + line_bytes.len() > MAX_ACP_FRAME {
                // A *complete* (newline-terminated) frame that overflows the cap
                // must be dropped too, not just parsed because it happened to end
                // within this chunk: buffering + parsing it would blow the
                // `MAX_ACP_FRAME` memory bound the trailing-chunk check below
                // enforces. Discard it and move on to the next frame.
                pending.clear();
                continue;
            }
            pending.extend_from_slice(line_bytes);
            let line = String::from_utf8_lossy(&pending).into_owned();
            pending.clear();
            // A `false` return means outbound backpressure (the agent is
            // flooding requests without draining stdin): stop reading so replies
            // cannot accumulate without bound.
            if !handle_message(&line, &shared, &out) {
                break 'read;
            }
        }
        if skipping {
            continue; // still discarding until a newline arrives
        }
        pending.extend_from_slice(chunk);
        if pending.len() > MAX_ACP_FRAME {
            // Oversized unterminated frame: stop buffering and skip to its end.
            pending.clear();
            skipping = true;
        }
    }
    // stdout closed: fail anything still waiting.
    let mut s = shared.lock().unwrap();
    for (_, tx) in s.pending.drain() {
        let _ = tx.send(Err(anyhow!("agent closed stdout")));
    }
}

/// Extract the text of an ACP `content` value the way the canonical transcript
/// bridge's `content_block_text` does (contract-tests `hub/transcript.rs`): a
/// bare string is its own text, an array's block texts concatenate, and an
/// object yields its `text` (`{"type":"text"}`) or its nested `resource.text`
/// (`{"type":"resource"}`). Anything else has no text. Message chunks carry all
/// of these shapes, so both the transcript accumulator and the effective-turn
/// classifier must read them all — a flat `content["text"]` lookup misses the
/// string/array/resource shapes the bridge persists as turns.
fn content_block_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut parts = String::new();
            let mut any = false;
            for item in items {
                if let Some(t) = content_block_text(item) {
                    parts.push_str(&t);
                    any = true;
                }
            }
            any.then_some(parts)
        }
        Value::Object(obj) => match obj.get("type").and_then(Value::as_str) {
            Some("text") => obj.get("text").and_then(Value::as_str).map(str::to_string),
            Some("resource") => obj
                .get("resource")
                .and_then(Value::as_object)
                .and_then(|r| r.get("text"))
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        },
        _ => None,
    }
}

/// Does this `session/update` persist a transcript turn or carry a valid plan —
/// the signals Node 1.70.1 counts as "the agent did work"? This mirrors the
/// canonical transcript bridge's non-`Ignored` classification (a message chunk
/// with text, a `tool_call` with an id, a TERMINAL `tool_call_update` with an
/// id) plus a `plan` update that carries at least one entry.
///
/// Everything else — an `in_progress`/unknown `tool_call_update`, an empty or
/// text-less chunk, an empty plan, a bare status, any unrecognised update — is
/// NOT a turn. Counting every `session/update` (as a raw `updates` tally does)
/// would let an otherwise-empty agent that emits a single status notification
/// masquerade as having produced work, so empty-run detection must key off this
/// instead.
fn update_is_effective_turn(update: &Value) -> bool {
    let Some(kind) = update["sessionUpdate"].as_str() else {
        return false;
    };
    match kind {
        // Reasoning (`agent_thought_chunk`) folds to an assistant turn; a chunk
        // with no text content persists nothing, so it does not count. The
        // bridge persists a chunk whose `content` is a bare string, an array of
        // blocks, or a resource block too — not only a flat `{"text": …}` — so
        // extract via `content_block_text` exactly as it does.
        "agent_message_chunk" | "agent_thought_chunk" | "user_message_chunk" => {
            content_block_text(&update["content"]).is_some_and(|t| !t.is_empty())
        }
        "tool_call" => update["toolCallId"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        // Only a TERMINAL tool result is a transcript turn; an intermediate
        // `in_progress`/`pending` update (or one without an id) is ignored.
        "tool_call_update" => {
            matches!(update["status"].as_str(), Some("completed" | "failed"))
                && update["toolCallId"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty())
        }
        "plan" => update["entries"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        _ => false,
    }
}

/// The human-readable text of an ACP `content` value the way the Node worker's
/// `describeUpdate` reads it (plugin 1.70.1): a bare string is its own text, an
/// array's block texts concatenate, and an object yields only its TOP-LEVEL
/// `text` (`{"type":"text"}`). Unlike [`content_block_text`], a
/// `{"type":"resource"}` block's NESTED `resource.text` is NOT read — Node's
/// `describeUpdate` never emits it, so folding it into the captured output would
/// produce substantive text (and a re-emit nudge / non-empty `output`) where the
/// Node worker reports none. Keep `content_block_text` (which reads the resource
/// shape) for TURN classification; use this only for the captured human output.
fn human_output_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut parts = String::new();
            let mut any = false;
            for item in items {
                if let Some(t) = human_output_text(item) {
                    parts.push_str(&t);
                    any = true;
                }
            }
            any.then_some(parts)
        }
        Value::Object(obj) => obj.get("text").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// Serialise one ACP `session/update` into the short human-readable line the
/// Node worker's `describeUpdate` produces for its captured output (plugin
/// 1.70.1 parity). Node folds EVERY update into captured output — thought/user
/// text plus tool, plan, status, and unknown-update lines — not only agent
/// message chunks, so a tool-only run is non-empty there. Returns `None` only
/// for a non-object update (Node's `describeUpdate` yields `""` for one).
fn describe_update(update: &Value) -> Option<String> {
    let obj = update.as_object()?;
    let kind = obj
        .get("sessionUpdate")
        .or_else(|| obj.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("update");
    let line = match kind {
        "agent_message_chunk" | "user_message_chunk" => {
            human_output_text(&update["content"]).unwrap_or_default()
        }
        "agent_thought_chunk" => format!(
            "\u{1F4AD} {}",
            human_output_text(&update["content"]).unwrap_or_default()
        ),
        "tool_call" | "tool_call_update" => {
            let title = obj
                .get("title")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .or_else(|| obj.get("toolCallId").and_then(Value::as_str))
                .unwrap_or("tool");
            let status = obj.get("status").and_then(Value::as_str);
            match status {
                Some(s) if !s.is_empty() => format!("\u{2699} [tool: {title} — {s}]\n"),
                _ => format!("\u{2699} [tool: {title}]\n"),
            }
        }
        "plan" => "\u{1F4CB} [plan updated]\n".to_string(),
        other => format!("[{other}]\n"),
    };
    Some(line)
}

/// Process one JSON-RPC line: a response to one of our requests, a notification,
/// or a request from the agent (permission prompts are auto-answered).
fn handle_message(line: &str, shared: &Arc<Mutex<Shared>>, out: &mpsc::Sender<Value>) -> bool {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return true;
    };
    let mut s = shared.lock().unwrap();
    s.last_activity = Some(Instant::now());
    let method = msg.get("method").and_then(Value::as_str);
    match (method, msg.get("id")) {
        // Response to one of our requests.
        (None, Some(id)) => {
            if let Some(tx) = id.as_u64().and_then(|id| s.pending.remove(&id)) {
                let r = match msg.get("error") {
                    Some(e) => Err(anyhow!("agent error: {e}")),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
                let _ = tx.send(r);
            }
            true
        }
        // Notification.
        (Some("session/update"), None) => {
            s.updates += 1;
            let update = &msg["params"]["update"];
            // Count effective transcript turns / valid plans the Node way, BEFORE
            // the narrower match below (which only tracks message text and tool
            // calls): `updates` alone overcounts ignored/intermediate updates.
            if update_is_effective_turn(update) {
                s.effective_turns += 1;
            }
            if update["sessionUpdate"].as_str() == Some("tool_call") {
                s.tool_calls += 1;
            }
            // Fold EVERY update into the captured output text the way Node's
            // `describeUpdate` does (plugin 1.70.1 parity): not only agent
            // message chunks but thought/user text and tool, plan, status, and
            // unknown-update lines. Node serializes each `session/update` into
            // captured output, so a tool-only run is non-empty there while a
            // status-only run is not failed as empty; capturing only message
            // chunks here would diverge on both. The same 1 MiB bound applies.
            if let Some(line) = describe_update(update) {
                s.text.push_str(&line);
                // Bound the transcript the same way the pipe path bounds stdout:
                // `Agent::run` appends every update to this `String`, so a
                // verbose or misbehaving ACP agent could otherwise exhaust daemon
                // memory (one unbounded buffer per slot). The tail is retained
                // for result detection. Record whether any bytes were dropped so
                // the truncation is reported even though the capped length hides
                // it.
                if crate::pipe::bound_capture(&mut s.text) {
                    s.truncated = true;
                }
            }
            true
        }
        (Some(_), None) | (None, None) => true,
        // Request from the agent.
        (Some(m), Some(id)) => {
            let reply = if m == "session/request_permission" {
                s.permissions_granted += 1;
                json!({"jsonrpc": "2.0", "id": id, "result": { "outcome": permission_choice(&msg["params"]) }})
            } else {
                json!({"jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {m}") }})
            };
            // `try_send` never blocks (we hold the shared lock here). A full
            // channel means `write_loop` has stalled on a blocked stdin: report
            // it as fatal backpressure so the read loop stops instead of queuing
            // replies without bound.
            //
            // Bound the frame by *bytes* too, not only by count: the reply echoes
            // the agent-supplied `id`/outcome verbatim, so an abusive payload
            // could make a single queued frame enormous. A reply over
            // `MAX_ACP_REPLY` means such a payload — drop it (do not enqueue an
            // oversized frame) rather than answer it. Not replying to a request
            // that violated the protocol is safe; the idle timeout tears down a
            // genuinely wedged agent.
            if reply.to_string().len() > MAX_ACP_REPLY {
                return true;
            }
            out.try_send(reply).is_ok()
        }
    }
}

/// The Node plugin's cap on an ACP outcome's `summary` (plugin 1.70.1): a
/// longer summary is TRUNCATED to this many characters, not discarded.
const OUTCOME_SUMMARY_MAX: usize = 8_000;

/// Truncate `s` to at most `max` UTF-16 code units, the way the Node plugin's
/// `s.slice(0, max)` does. JavaScript strings are UTF-16, so `slice` counts
/// code UNITS, not Unicode scalar values: an astral character (an emoji, a
/// supplementary-plane ideograph) is a surrogate PAIR — two code units — and
/// `char::len_utf16()` reports its width. A `chars().take(max)` cut instead
/// counts scalar values, so `8001` emoji survive where Node keeps only `4000`,
/// letting roughly twice the intended UTF-16 length into a result variable.
/// The cut never splits a surrogate pair: a character is included only when it
/// fits whole within the remaining budget, matching how `slice` rounds a
/// boundary that lands mid-pair down to the last complete character.
pub(crate) fn truncate_utf16(s: &str, max: usize) -> String {
    let mut units = 0usize;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        let w = c.len_utf16();
        if units + w > max {
            end = i;
            break;
        }
        units += w;
    }
    s[..end].to_string()
}

/// Keep at most the last `max` UTF-16 code units of `s` — the TAIL — the way
/// the Node plugin's `s.slice(-max)` does. This is the from-the-end analogue of
/// [`truncate_utf16`]: JavaScript counts code UNITS, so an astral character (an
/// emoji) is a surrogate pair and costs two units via `char::len_utf16()`. A
/// `chars()` tail cut instead counts scalar values, keeping roughly twice the
/// intended UTF-16 length for astral-heavy output. The cut never splits a
/// surrogate pair: a character is included only when it fits whole within the
/// remaining budget, matching how `slice` rounds a boundary that lands mid-pair
/// up to the first complete character.
pub(crate) fn tail_utf16(s: &str, max: usize) -> String {
    let mut units = 0usize;
    let mut start = 0;
    for (i, c) in s.char_indices().rev() {
        let w = c.len_utf16();
        if units + w > max {
            start = i + c.len_utf8();
            break;
        }
        units += w;
    }
    s[start..].to_string()
}

/// Extract the prompt response's `_meta.outcome` object (plugin 1.70.1),
/// validated and canonicalized the way the Node plugin does before it uses one.
///
/// The plugin accepts an outcome only when its `status` is EXACTLY `completed`
/// or `blocked` (lowercase, no surrounding whitespace) and its `summary` is a
/// non-blank string; any other shape is discarded (`None`) rather than
/// forwarded, so an arbitrary `_meta.outcome` object can neither suppress the
/// nudge/empty guard nor be promoted into process variables. A summary longer
/// than 8,000 characters is TRUNCATED to the cap (the plugin slices it), not
/// dropped, so a valid long `blocked` outcome still escalates instead of being
/// lost. The canonical outcome keeps ONLY `status` and `summary` here — the
/// blocked-only result mapping (`question: summary`) is applied later, at the
/// slot's candidate-selection step, so this canonical form stays the pure
/// `io.nanobpm.agentResult.outcome` audit record.
fn prompt_outcome(done: &Value) -> Option<Map<String, Value>> {
    let outcome = done.get("_meta")?.get("outcome")?.as_object()?;
    // Plugin 1.70.1: an EXACT lowercase status match — no case folding, no
    // trim. An uppercase/whitespace variant is not a valid outcome and must not
    // suppress empty-result handling.
    let status = outcome.get("status")?.as_str()?;
    if status != "completed" && status != "blocked" {
        return None;
    }
    let summary = outcome.get("summary")?.as_str()?.trim();
    if summary.is_empty() {
        return None;
    }
    // Plugin 1.70.1 truncates an overlong summary to the cap rather than
    // discarding the outcome. The cap counts UTF-16 code units (the plugin's
    // `summary.slice(0, 8000)`), so cut by code units — this never splits a
    // surrogate pair and, unlike a char count, keeps the cut faithful for
    // astral (emoji) summaries, which Node measures as two units each.
    let summary: String = truncate_utf16(summary, OUTCOME_SUMMARY_MAX);
    let mut canonical = Map::new();
    canonical.insert("status".to_string(), Value::String(status.to_string()));
    canonical.insert("summary".to_string(), Value::String(summary));
    Some(canonical)
}

/// The blocked-only result mapping (plugin 1.70.1): only a `blocked` ACP
/// outcome derives fallback result variables — `{status, summary, question}`
/// with `question` synthesized from the summary (the escalation a blocked run
/// must surface to a human). A `completed` outcome derives NO result vars, so
/// it must not suppress the re-emit nudge or inject a guessed top-level
/// `status`; the canonical outcome is still recorded separately as
/// `io.nanobpm.agentResult.outcome`.
pub fn outcome_result_vars(outcome: &Map<String, Value>) -> Option<Map<String, Value>> {
    if outcome.get("status")?.as_str()? != "blocked" {
        return None;
    }
    let mut vars = outcome.clone();
    if let Some(summary) = outcome.get("summary").cloned() {
        vars.insert("question".to_string(), summary);
    }
    Some(vars)
}

/// `yolo`: pick an allow option, preferring allow_always, else the first option.
fn permission_choice(params: &Value) -> Value {
    let options = params["options"].as_array().cloned().unwrap_or_default();
    let pick = ["allow_always", "allow_once"]
        .iter()
        .find_map(|kind| options.iter().find(|o| o["kind"] == *kind))
        .or_else(|| options.first());
    match pick.and_then(|o| o["optionId"].as_str()) {
        Some(id) => json!({ "outcome": "selected", "optionId": id }),
        None => json!({ "outcome": "cancelled" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_prefers_allow_always() {
        let p = json!({"options": [
            {"optionId": "no", "kind": "reject_once"},
            {"optionId": "once", "kind": "allow_once"},
            {"optionId": "always", "kind": "allow_always"}
        ]});
        assert_eq!(permission_choice(&p)["optionId"], "always");
        assert_eq!(
            permission_choice(&json!({"options": []}))["outcome"],
            "cancelled"
        );
    }

    #[test]
    fn oversized_request_id_is_not_enqueued() {
        // A hostile agent sends a permission request whose `id` is a huge string.
        // The reply must NOT be queued (it would echo the id verbatim, and
        // OUT_CHANNEL_CAP such frames could exhaust memory); the read loop should
        // simply ignore the abusive request and keep going.
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (out, mut rx) = mpsc::channel::<Value>(OUT_CHANNEL_CAP);
        let huge_id = "x".repeat(MAX_ACP_REPLY + 1);
        let line = json!({
            "jsonrpc": "2.0",
            "id": huge_id,
            "method": "session/request_permission",
            "params": {"options": [{"optionId": "ok", "kind": "allow_always"}]}
        })
        .to_string();
        assert!(
            handle_message(&line, &shared, &out),
            "an oversized request must not be treated as fatal backpressure"
        );
        assert!(
            rx.try_recv().is_err(),
            "no oversized reply frame may be enqueued"
        );
    }

    #[test]
    fn normal_request_reply_is_enqueued() {
        // A well-formed permission request is answered and its reply queued.
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (out, mut rx) = mpsc::channel::<Value>(OUT_CHANNEL_CAP);
        let line = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "session/request_permission",
            "params": {"options": [{"optionId": "ok", "kind": "allow_always"}]}
        })
        .to_string();
        assert!(handle_message(&line, &shared, &out));
        let reply = rx.try_recv().expect("a normal reply must be enqueued");
        assert_eq!(reply["id"], 7);
    }

    #[test]
    fn prompt_outcome_keeps_canonical_status_and_summary_only() {
        // The canonical outcome is the pure audit record: status + summary only.
        // The blocked-only `question` mapping is applied later, at the slot's
        // candidate-selection step — NOT here.
        let done = json!({
            "stopReason": "end_turn",
            "_meta": { "outcome": { "status": "blocked", "summary": "need creds" } }
        });
        let out = prompt_outcome(&done).expect("blocked outcome must be extracted");
        assert_eq!(out["status"], "blocked");
        assert_eq!(out["summary"], "need creds");
        assert!(
            out.get("question").is_none(),
            "the canonical outcome must not carry the synthesized question"
        );
    }

    #[test]
    fn outcome_result_vars_maps_only_blocked() {
        // Plugin 1.70.1: only a `blocked` outcome derives fallback result vars,
        // synthesizing `question: summary`. A `completed` outcome derives NONE.
        let blocked = json!({ "status": "blocked", "summary": "need creds" });
        let vars = outcome_result_vars(blocked.as_object().unwrap())
            .expect("a blocked outcome must derive result vars");
        assert_eq!(vars["status"], "blocked");
        assert_eq!(vars["summary"], "need creds");
        assert_eq!(vars["question"], "need creds");

        let completed = json!({ "status": "completed", "summary": "shipped" });
        assert!(
            outcome_result_vars(completed.as_object().unwrap()).is_none(),
            "a completed outcome must derive no result vars"
        );
    }

    #[test]
    fn prompt_outcome_requires_exact_lowercase_status() {
        // Plugin 1.70.1 accepts ONLY the exact lowercase statuses. A case
        // variant or surrounding whitespace is NOT a valid outcome and must not
        // suppress empty-result handling.
        for status in ["Blocked", "BLOCKED", " blocked", "blocked ", "Completed"] {
            let done = json!({ "_meta": { "outcome": { "status": status, "summary": "s" } } });
            assert!(
                prompt_outcome(&done).is_none(),
                "a non-exact status must be discarded: {status:?}"
            );
        }
        for status in ["completed", "blocked"] {
            let done = json!({ "_meta": { "outcome": { "status": status, "summary": "s" } } });
            assert!(prompt_outcome(&done).is_some());
        }
    }

    #[test]
    fn prompt_outcome_truncates_an_overlong_summary() {
        // Plugin 1.70.1 TRUNCATES a nonblank overlong summary to 8,000 chars
        // rather than discarding the outcome, so a valid long `blocked` outcome
        // still escalates instead of being lost.
        let over_limit = "x".repeat(OUTCOME_SUMMARY_MAX + 50);
        let done =
            json!({ "_meta": { "outcome": { "status": "blocked", "summary": over_limit } } });
        let out =
            prompt_outcome(&done).expect("an overlong summary must be truncated, not dropped");
        assert_eq!(
            out["summary"].as_str().unwrap().chars().count(),
            OUTCOME_SUMMARY_MAX
        );
        // Exactly at the limit is kept whole.
        let at_limit = "y".repeat(OUTCOME_SUMMARY_MAX);
        let done =
            json!({ "_meta": { "outcome": { "status": "completed", "summary": at_limit } } });
        let out = prompt_outcome(&done).expect("an at-limit summary must be accepted");
        assert_eq!(
            out["summary"].as_str().unwrap().chars().count(),
            OUTCOME_SUMMARY_MAX
        );
    }

    #[test]
    fn prompt_outcome_truncates_an_overlong_multibyte_summary_by_chars() {
        // Regression: the cap counts UTF-16 code units, not bytes. A summary of
        // BMP multibyte characters (`€` is 3 bytes but ONE UTF-16 code unit)
        // must truncate to exactly OUTCOME_SUMMARY_MAX — a byte-indexed cut
        // would keep only ~1/3.
        let over_limit = "\u{20ac}".repeat(OUTCOME_SUMMARY_MAX + 1);
        let done =
            json!({ "_meta": { "outcome": { "status": "blocked", "summary": over_limit } } });
        let out = prompt_outcome(&done).expect("an overlong multibyte summary must be truncated");
        assert_eq!(
            out["summary"].as_str().unwrap().chars().count(),
            OUTCOME_SUMMARY_MAX
        );
    }

    #[test]
    fn prompt_outcome_truncates_an_overlong_astral_summary_by_utf16_units() {
        // Regression: the cap counts UTF-16 code units (the plugin's
        // `summary.slice(0, 8000)`), not Unicode scalar values. An astral
        // character (an emoji) is a surrogate PAIR — two code units — so 8,001
        // emoji are truncated by Node to 4,000 emoji (8,000 units), NOT the
        // 8,000 a `chars().take(8000)` cut would keep.
        let over_limit = "\u{1F600}".repeat(OUTCOME_SUMMARY_MAX + 1); // 😀
        let done =
            json!({ "_meta": { "outcome": { "status": "blocked", "summary": over_limit } } });
        let out = prompt_outcome(&done).expect("an overlong astral summary must be truncated");
        let summary = out["summary"].as_str().unwrap();
        // 4,000 emoji = 8,000 UTF-16 code units = 4,000 scalar values.
        assert_eq!(summary.chars().count(), OUTCOME_SUMMARY_MAX / 2);
        assert_eq!(
            summary.chars().map(char::len_utf16).sum::<usize>(),
            OUTCOME_SUMMARY_MAX
        );
    }

    #[test]
    fn prompt_outcome_drops_arbitrary_extra_fields() {
        // An arbitrary object must not be promoted into process variables: only
        // the canonical status/summary(/question) survive.
        let done = json!({
            "stopReason": "end_turn",
            "_meta": { "outcome": { "status": "blocked", "summary": "s", "evil": "x", "pushed": true } }
        });
        let out = prompt_outcome(&done).expect("valid outcome must be extracted");
        assert!(out.get("evil").is_none());
        assert!(out.get("pushed").is_none());
    }

    #[test]
    fn prompt_outcome_rejects_invalid_status_and_summary() {
        // Only an exact completed|blocked status with a non-blank summary is a
        // valid outcome; every other shape is discarded (None), so it can
        // neither suppress the nudge/empty guard nor become process variables.
        // (An overlong summary is TRUNCATED, not rejected — see
        // `prompt_outcome_truncates_an_overlong_summary`.)
        for done in [
            json!({ "_meta": { "outcome": { "status": "failed", "summary": "s" } } }),
            json!({ "_meta": { "outcome": { "status": "blocked" } } }),
            json!({ "_meta": { "outcome": { "status": "blocked", "summary": "   " } } }),
            json!({ "_meta": { "outcome": { "summary": "s" } } }),
        ] {
            assert!(
                prompt_outcome(&done).is_none(),
                "invalid outcome must be discarded: {done}"
            );
        }
    }

    #[test]
    fn prompt_outcome_absent_shapes_yield_none() {
        // Every non-outcome shape must yield `None` (not a panic, not an empty
        // map): a bare response, missing `_meta`, `_meta` without `outcome`, and
        // an `outcome` that is not an object. Guards the schema/path drift class
        // that would otherwise silently drop a real outcome.
        for done in [
            json!({ "stopReason": "end_turn" }),
            json!({ "stopReason": "end_turn", "_meta": {} }),
            json!({ "stopReason": "end_turn", "_meta": { "outcome": "blocked" } }),
            json!({ "stopReason": "end_turn", "_meta": { "outcome": ["x"] } }),
            json!({ "stopReason": "end_turn", "_meta": { "outcome": null } }),
        ] {
            assert!(
                prompt_outcome(&done).is_none(),
                "non-object outcome must extract to None: {done}"
            );
        }
    }

    #[test]
    fn update_is_effective_turn_counts_only_persisted_turns_or_valid_plans() {
        // Persisted transcript turns: a message/thought/user chunk WITH text, a
        // tool_call with an id, and a TERMINAL tool_call_update with an id. A
        // plan counts only when it carries at least one entry. Message chunks
        // count under EVERY content shape the canonical bridge's
        // `content_block_text` extracts: a `{"type":"text"}` object, a bare
        // string, an array of blocks, and a `{"type":"resource"}` block.
        let effective = [
            json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "hi" } }),
            json!({ "sessionUpdate": "agent_thought_chunk", "content": { "type": "text", "text": "hmm" } }),
            json!({ "sessionUpdate": "user_message_chunk", "content": { "type": "text", "text": "go" } }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": "hi" }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": [ { "type": "text", "text": "a" }, { "type": "text", "text": "b" } ] }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": [ "a", { "type": "resource", "resource": { "uri": "file://x", "text": "b" } } ] }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "resource", "resource": { "uri": "file://x", "text": "body" } } }),
            json!({ "sessionUpdate": "tool_call", "toolCallId": "c1", "title": "read" }),
            json!({ "sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed", "rawOutput": {} }),
            json!({ "sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "failed" }),
            json!({ "sessionUpdate": "plan", "entries": [ { "content": "step", "status": "pending" } ] }),
        ];
        for u in &effective {
            assert!(update_is_effective_turn(u), "should count as a turn: {u}");
        }

        // Ignored/intermediate updates: an empty or text-less chunk (under any
        // content shape), a tool_call without an id, an in_progress/unknown
        // tool_call_update, an id-less terminal update, an empty plan, a bare
        // status, and any unknown update.
        let ignored = [
            json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "" } }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": "" }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": [] }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": [ { "type": "image", "data": "…" } ] }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "resource", "resource": { "uri": "file://x" } } }),
            json!({ "sessionUpdate": "agent_message_chunk" }),
            json!({ "sessionUpdate": "tool_call", "title": "read" }),
            json!({ "sessionUpdate": "tool_call", "toolCallId": "" }),
            json!({ "sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "in_progress" }),
            json!({ "sessionUpdate": "tool_call_update", "status": "completed" }),
            json!({ "sessionUpdate": "plan", "entries": [] }),
            json!({ "sessionUpdate": "plan" }),
            json!({ "sessionUpdate": "current_mode_update", "modeId": "x" }),
            json!({ "sessionUpdate": "available_commands_update" }),
            json!({ "foo": "bar" }),
        ];
        for u in &ignored {
            assert!(
                !update_is_effective_turn(u),
                "should NOT count as a turn: {u}"
            );
        }
    }

    #[test]
    fn describe_update_mirrors_the_node_human_text_for_every_update_kind() {
        // Plugin 1.70.1 `describeUpdate` folds EVERY `session/update` into the
        // captured output, not only agent message chunks: thought/user text plus
        // tool, plan, status, and unknown-update lines. `Outcome.text` must
        // accumulate the same lines or a tool-only run reads empty here while
        // Node reports it non-empty (and a status-only run is failed as empty).
        assert_eq!(
            describe_update(
                &json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "hi" } })
            ),
            Some("hi".to_string())
        );
        assert_eq!(
            describe_update(&json!({ "sessionUpdate": "user_message_chunk", "content": "go" })),
            Some("go".to_string())
        );
        assert_eq!(
            describe_update(
                &json!({ "sessionUpdate": "agent_thought_chunk", "content": { "type": "text", "text": "hmm" } })
            ),
            Some("\u{1F4AD} hmm".to_string())
        );
        // A tool call serializes a `⚙ [tool: …]` line (with its status when one
        // is present), so a tool-only run is non-empty.
        assert_eq!(
            describe_update(
                &json!({ "sessionUpdate": "tool_call", "toolCallId": "c1", "title": "read" })
            ),
            Some("\u{2699} [tool: read]\n".to_string())
        );
        assert_eq!(
            describe_update(
                &json!({ "sessionUpdate": "tool_call", "toolCallId": "c1", "title": "read", "status": "completed" })
            ),
            Some("\u{2699} [tool: read — completed]\n".to_string())
        );
        assert_eq!(
            describe_update(
                &json!({ "sessionUpdate": "tool_call_update", "toolCallId": "c1", "status": "completed" })
            ),
            Some("\u{2699} [tool: c1 — completed]\n".to_string())
        );
        // A plan and an unknown/status update contribute a marker line too.
        assert_eq!(
            describe_update(&json!({ "sessionUpdate": "plan", "entries": [] })),
            Some("\u{1F4CB} [plan updated]\n".to_string())
        );
        assert_eq!(
            describe_update(&json!({ "sessionUpdate": "current_mode_update", "modeId": "x" })),
            Some("[current_mode_update]\n".to_string())
        );
        // A non-object update has no line (Node's `describeUpdate` yields "").
        assert_eq!(describe_update(&json!(null)), None);
        assert_eq!(describe_update(&json!("str")), None);
    }

    #[test]
    fn describe_update_omits_nested_resource_text_like_node() {
        // Plugin 1.70.1 `describeUpdate` reads only a content object's TOP-LEVEL
        // `text`; it never emits a `{"type":"resource"}` block's nested
        // `resource.text`. A resource-only chunk therefore yields an EMPTY output
        // line (no re-emit nudge, empty `output`) even though the same block IS
        // an effective transcript turn via `content_block_text`.
        let resource = json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "resource", "resource": { "uri": "file://x", "text": "body" } } });
        assert_eq!(describe_update(&resource), Some(String::new()));
        // ... while turn classification still counts the resource text.
        assert!(update_is_effective_turn(&resource));
        // A top-level `text` object and a bare string still produce output.
        assert_eq!(
            describe_update(
                &json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "hi" } })
            ),
            Some("hi".to_string())
        );
        assert_eq!(
            describe_update(&json!({ "sessionUpdate": "agent_message_chunk", "content": "go" })),
            Some("go".to_string())
        );
    }

    #[test]
    fn content_block_text_matches_the_canonical_bridge_shapes() {
        // Every shape the canonical transcript bridge's `content_block_text`
        // extracts — a bare string, an array of blocks (concatenated), a text
        // object, and a resource object's nested text — plus the shapes it
        // rejects (no text anywhere).
        assert_eq!(
            content_block_text(&json!("hello")).as_deref(),
            Some("hello")
        );
        assert_eq!(
            content_block_text(&json!({ "type": "text", "text": "hi" })).as_deref(),
            Some("hi")
        );
        assert_eq!(
            content_block_text(
                &json!([{ "type": "text", "text": "a" }, "b", { "type": "resource", "resource": { "text": "c" } }])
            )
            .as_deref(),
            Some("abc")
        );
        assert_eq!(
            content_block_text(
                &json!({ "type": "resource", "resource": { "uri": "file://x", "text": "body" } })
            )
            .as_deref(),
            Some("body")
        );
        for v in [
            json!([]),
            json!([{ "type": "image", "data": "…" }]),
            json!({ "type": "image", "data": "…" }),
            json!({ "type": "resource", "resource": { "uri": "file://x" } }),
            json!(42),
            json!(null),
        ] {
            assert_eq!(content_block_text(&v), None, "no text expected: {v}");
        }
    }

    /// A minimal fake ACP agent: answers `initialize`, records the
    /// `session/new` params, replies with a sessionId, answers the prompt, and
    /// exits. Used to observe what `session/new.cwd` the client sends.
    #[cfg(unix)]
    fn fake_agent_script() -> &'static str {
        r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      ;;
    *'"session/new"'*)
      printf '%s\n' "$line" > "$NANO_FAKE_AGENT_CAPTURE"
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s1"}}'
      ;;
    *'"session/prompt"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      exit 0
      ;;
  esac
done
"#
    }

    /// The `session/new` workspace must name the SAME directory the launch
    /// bound: recover it through the pinned fd, so an ancestor swapped for a
    /// symlink after the pin cannot make the agent resolve a requested
    /// workspace that now points at the attacker's tree (#35). The fake agent
    /// captures the verbatim `session/new` request; the `cwd` in it must be the
    /// pinned inode's current path (the moved-aside real dir), never the
    /// swapped-in attacker path the provisioning-time string would now name.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn session_new_cwd_names_the_pinned_inode_after_an_ancestor_swap() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "nano-acp-swap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor (macOS /var).
        let base = std::fs::canonicalize(&base).unwrap();

        // The real workspace the agent is pinned to.
        let ancestor = base.join("ancestor");
        let real = ancestor.join("run");
        std::fs::create_dir_all(&real).unwrap();
        let handle = crate::safecwd::CwdHandle::open(&real).unwrap();

        // The fake agent script + the file it captures the session/new into.
        let script = base.join("fake-agent.sh");
        std::fs::write(&script, fake_agent_script()).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let capture = base.join("capture.json");
        let env = vec![(
            "NANO_FAKE_AGENT_CAPTURE".to_string(),
            capture.to_string_lossy().into_owned(),
        )];

        let mut agent = Agent::spawn(
            "sh",
            &[script.to_string_lossy().into_owned()],
            &handle,
            &env,
        )
        .expect("spawn fake agent");

        // Attacker swaps the ancestor for a symlink to their tree AFTER the
        // pin but BEFORE session/new: the provisioning-time path string would
        // now resolve to the attacker; the pinned fd must not.
        let moved = base.join("ancestor-moved");
        std::fs::rename(&ancestor, &moved).unwrap();
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join("run")).unwrap();
        std::os::unix::fs::symlink(&evil, &ancestor).unwrap();

        let out = agent
            .run(&handle, "hi", Duration::from_secs(10))
            .await
            .expect("fake agent turn");
        agent.shutdown().await;
        assert_eq!(out.stop_reason, "end_turn");

        // The captured session/new cwd must be the pinned inode's real
        // (moved-aside) path, never the attacker tree the original path now
        // resolves to.
        let sent: Value =
            serde_json::from_str(&std::fs::read_to_string(&capture).unwrap()).unwrap();
        let sent_cwd = sent["params"]["cwd"].as_str().expect("session/new cwd");
        assert_eq!(
            std::fs::canonicalize(sent_cwd).unwrap(),
            std::fs::canonicalize(moved.join("run")).unwrap(),
            "session/new cwd must name the pinned inode, not the swapped-in attacker path"
        );
        assert_ne!(
            std::fs::canonicalize(sent_cwd).unwrap(),
            std::fs::canonicalize(evil.join("run")).unwrap(),
            "session/new cwd must not resolve into the attacker's tree"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
