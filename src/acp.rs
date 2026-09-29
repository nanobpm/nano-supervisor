//! Minimal ACP (Agent Client Protocol) client: JSON-RPC 2.0, one JSON object
//! per line over the agent's stdio.
//!
//! Enough for one job: `initialize` → `session/new` → `session/prompt`, while
//! collecting `session/update` notifications. Agent-to-client requests are
//! answered: `session/request_permission` is auto-allowed (the plugin's `yolo`
//! policy); everything else gets "method not found".

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, oneshot};

const PROTOCOL_VERSION: u64 = 1;

/// What one prompt turn produced.
#[derive(Debug, Default)]
pub struct Outcome {
    pub stop_reason: String,
    /// Concatenated `agent_message_chunk` text.
    pub text: String,
    pub updates: usize,
    pub tool_calls: usize,
    pub permissions_granted: usize,
}

#[derive(Default)]
struct Shared {
    pending: HashMap<u64, oneshot::Sender<Result<Value>>>,
    text: String,
    updates: usize,
    tool_calls: usize,
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
    /// Start `program args…` in `cwd`, in its own process group.
    pub fn spawn(
        program: &str,
        args: &[String],
        cwd: &Path,
        env: &[(String, String)],
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args).current_dir(cwd);
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
                bail!("agent stdin blocked for {}s during {method} (idle timeout)", idle.as_secs());
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
    pub async fn run(&mut self, cwd: &Path, prompt: &str, idle: Duration) -> Result<Outcome> {
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
        let session = self
            .request("session/new", json!({ "cwd": cwd, "mcpServers": [] }), idle)
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
            updates: s.updates,
            tool_calls: s.tool_calls,
            permissions_granted: s.permissions_granted,
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
            match update["sessionUpdate"].as_str() {
                Some("agent_message_chunk") => {
                    if let Some(t) = update["content"]["text"].as_str() {
                        s.text.push_str(t);
                        // Bound the transcript the same way the pipe path bounds
                        // stdout: `Agent::run` appends every chunk to this
                        // `String`, so a verbose or misbehaving ACP agent could
                        // otherwise exhaust daemon memory (one unbounded buffer
                        // per slot). The tail is retained for result detection.
                        crate::pipe::bound_capture(&mut s.text);
                    }
                }
                Some("tool_call") => s.tool_calls += 1,
                _ => {}
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
            out.try_send(reply).is_ok()
        }
    }
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
}
