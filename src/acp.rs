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
    out: mpsc::UnboundedSender<Value>,
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
        cmd.args(args)
            .current_dir(cwd)
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
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
        let (out, rx) = mpsc::unbounded_channel::<Value>();
        tokio::spawn(write_loop(stdin, rx));
        tokio::spawn(read_loop(
            BufReader::new(stdout),
            shared.clone(),
            out.clone(),
        ));
        Ok(Self {
            child,
            out,
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
        self.out
            .send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .map_err(|_| anyhow!("agent stdin closed"))?;
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
        drop(self.out); // close stdin: the agent sees EOF and can flush + exit
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

async fn write_loop(mut stdin: ChildStdin, mut rx: mpsc::UnboundedReceiver<Value>) {
    while let Some(msg) = rx.recv().await {
        let mut line = msg.to_string();
        line.push('\n');
        if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
            break;
        }
    }
}

/// Upper bound on a single JSON-RPC line the ACP agent may send. A misbehaving
/// agent could otherwise stream one huge unterminated line, and a line reader
/// would buffer it whole before we ever parse it — exhausting daemon memory (one
/// buffer per slot). Frames larger than this are dropped rather than accumulated.
const MAX_ACP_FRAME: usize = 1 << 20; // 1 MiB

async fn read_loop<R: tokio::io::AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    shared: Arc<Mutex<Shared>>,
    out: mpsc::UnboundedSender<Value>,
) {
    // Read fixed-size chunks and split them into newline-delimited frames here,
    // instead of `lines()` whose reader buffers a whole line unbounded before
    // yielding. This caps memory at `MAX_ACP_FRAME`: an oversized unterminated
    // frame is discarded up to its next newline rather than held in full.
    let mut buf = [0u8; 64 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    let mut skipping = false; // discarding an oversized frame until its newline
    loop {
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
            pending.extend_from_slice(line_bytes);
            let line = String::from_utf8_lossy(&pending).into_owned();
            pending.clear();
            handle_message(&line, &shared, &out);
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
fn handle_message(line: &str, shared: &Arc<Mutex<Shared>>, out: &mpsc::UnboundedSender<Value>) {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return;
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
        }
        (Some(_), None) | (None, None) => {}
        // Request from the agent.
        (Some(m), Some(id)) => {
            let reply = if m == "session/request_permission" {
                s.permissions_granted += 1;
                json!({"jsonrpc": "2.0", "id": id, "result": { "outcome": permission_choice(&msg["params"]) }})
            } else {
                json!({"jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {m}") }})
            };
            let _ = out.send(reply);
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
