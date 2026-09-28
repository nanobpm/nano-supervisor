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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            crate::pdeath::watch(pid);
        }
        let stdin = child.stdin.take().context("agent stdin")?;
        let stdout = child.stdout.take().context("agent stdout")?;

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
        drop(self.out);
        if tokio::time::timeout(Duration::from_secs(3), self.child.wait())
            .await
            .is_err()
        {
            #[cfg(unix)]
            if let Some(pid) = self.child.id() {
                // Negative pid = the whole process group (tools the agent started).
                let _ = std::process::Command::new("kill")
                    .args(["-TERM", &format!("-{pid}")])
                    .status();
            }
            let _ = self.child.kill().await;
        }
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

async fn read_loop<R: tokio::io::AsyncRead + Unpin>(
    reader: BufReader<R>,
    shared: Arc<Mutex<Shared>>,
    out: mpsc::UnboundedSender<Value>,
) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
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
    // stdout closed: fail anything still waiting.
    let mut s = shared.lock().unwrap();
    for (_, tx) in s.pending.drain() {
        let _ = tx.send(Err(anyhow!("agent closed stdout")));
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
