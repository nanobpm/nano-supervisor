//! Building, spawning and driving the [`fake-agent`](../bin/fake-agent.rs), and
//! reading back what it recorded.
//!
//! [`FakeAgent`] builds the `NS_FAKE_SCRIPT` / `NS_FAKE_RECORD` environment and a
//! `Command`. [`AcpClient`] is a blocking ACP client (a reference twin of the
//! worker's `src/acp.rs`) so worker tests can observe the job-to-agent contract
//! without a live engine. [`FakeRecord`] parses the recording.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::fake_agent_path;

/// What the fake agent recorded to `NS_FAKE_RECORD`.
#[derive(Debug, Clone, Deserialize)]
pub struct FakeRecord {
    pub mode: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    pub prompts: Vec<String>,
    #[serde(default)]
    pub initialize: Option<Value>,
    #[serde(default)]
    pub session_new: Option<Value>,
    #[serde(default)]
    pub permissions: Vec<Value>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub hung: bool,
}

impl FakeRecord {
    pub fn read(path: &Path) -> FakeRecord {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("reading fake record {}: {e}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("parsing fake record {}: {e}", path.display()))
    }

    /// The initial prompt the agent received (index 0), if any.
    pub fn first_prompt(&self) -> Option<&str> {
        self.prompts.first().map(String::as_str)
    }
}

/// A builder for a `fake-agent` invocation: its script, environment, working
/// directory and recording path.
#[derive(Default)]
pub struct FakeAgent {
    steps: Vec<Value>,
    env: Vec<(String, String)>,
    cwd: Option<PathBuf>,
    record: Option<PathBuf>,
    acp: bool,
}

impl FakeAgent {
    pub fn new() -> Self {
        FakeAgent::default()
    }

    /// Drive the agent over ACP (`--acp`) instead of pipe mode.
    pub fn acp(mut self) -> Self {
        self.acp = true;
        self
    }

    /// Append one script step (see `fake-agent.rs` for the vocabulary).
    pub fn step(mut self, step: Value) -> Self {
        self.steps.push(step);
        self
    }

    /// Emit some agent text (a message chunk in ACP, stdout in pipe mode).
    pub fn emit(self, text: &str) -> Self {
        self.step(json!({ "emit": text }))
    }

    /// Write `value` to `AGENT_RESULT_FILE`.
    pub fn write_result(self, value: Value) -> Self {
        self.step(json!({ "write_result": value }))
    }

    /// Print a `::nano:result::<json>` marker line.
    pub fn result_marker(self, value: Value) -> Self {
        self.step(json!({ "result_marker": value }))
    }

    /// Exit with `code` mid-turn.
    pub fn exit(self, code: i32) -> Self {
        self.step(json!({ "exit": code }))
    }

    /// Sleep, then leave the turn unanswered so the worker idle-times-out.
    pub fn go_silent(self, ms: u64) -> Self {
        self.step(json!({ "go_silent": ms }))
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Where the agent writes its recording (`NS_FAKE_RECORD`).
    pub fn record_to(mut self, path: impl Into<PathBuf>) -> Self {
        self.record = Some(path.into());
        self
    }

    fn script_json(&self) -> String {
        serde_json::to_string(&Value::Array(self.steps.clone())).unwrap()
    }

    /// Build the `Command`, wiring `NS_FAKE_SCRIPT`, `NS_FAKE_RECORD`, the cwd and
    /// any extra environment. stdio is piped.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(fake_agent_path());
        if self.acp {
            cmd.arg("--acp");
        }
        cmd.env("NS_FAKE_SCRIPT", self.script_json());
        if let Some(rec) = &self.record {
            cmd.env("NS_FAKE_RECORD", rec);
        }
        if let Some(dir) = &self.cwd {
            cmd.current_dir(dir);
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        cmd
    }

    /// Run in pipe mode, feed `prompt` on stdin, and return (stdout, exit code).
    pub fn run_pipe(&self, prompt: &str) -> (String, i32) {
        let mut child = self.command().spawn().expect("spawn fake-agent");
        {
            let mut stdin = child.stdin.take().expect("stdin");
            let _ = stdin.write_all(prompt.as_bytes());
        }
        let out = child.wait_with_output().expect("wait fake-agent");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            out.status.code().unwrap_or(-1),
        )
    }

    /// Drive the agent over ACP with `prompt` and an `idle` timeout, as the
    /// worker does. Returns the collected outcome.
    pub fn drive_acp(&self, prompt: &str, idle: Duration) -> Result<AcpOutcome, AcpError> {
        assert!(self.acp, "drive_acp requires .acp()");
        let child = self.command().spawn().expect("spawn fake-agent");
        AcpClient::new(child).run(prompt, idle)
    }
}

/// What one ACP prompt turn produced, mirroring the worker's `Outcome`.
#[derive(Debug, Default, Clone)]
pub struct AcpOutcome {
    pub stop_reason: String,
    pub text: String,
    pub updates: usize,
    pub tool_calls: usize,
    pub permissions_granted: usize,
}

#[derive(Debug)]
pub enum AcpError {
    /// No output for the idle window during a request — the worker's idle timeout.
    Idle(String),
    /// The agent closed stdout before answering.
    Closed(String),
    Protocol(String),
}

impl std::fmt::Display for AcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcpError::Idle(m) => write!(f, "idle: {m}"),
            AcpError::Closed(m) => write!(f, "closed: {m}"),
            AcpError::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

/// A blocking ACP client: initialize -> session/new -> session/prompt, auto-
/// allowing `session/request_permission` (the plugin's `yolo` policy), with an
/// idle timeout. A reference twin of `nano-supervisor`'s `src/acp.rs`.
struct AcpClient {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    rx: mpsc::Receiver<String>,
    next_id: u64,
    out: AcpOutcome,
}

impl AcpClient {
    fn new(mut child: Child) -> Self {
        let stdin = Some(child.stdin.take().expect("agent stdin"));
        let stdout = child.stdout.take().expect("agent stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        AcpClient {
            child,
            stdin,
            rx,
            next_id: 1,
            out: AcpOutcome::default(),
        }
    }

    fn send(&mut self, msg: &Value) -> Result<(), AcpError> {
        let mut line = msg.to_string();
        line.push('\n');
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| AcpError::Closed("agent stdin already closed".into()))?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|_| stdin.flush())
            .map_err(|e| AcpError::Closed(format!("writing to agent: {e}")))
    }

    /// Send a request and pump notifications/agent-requests until its response.
    fn request(&mut self, method: &str, params: Value, idle: Duration) -> Result<Value, AcpError> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let line = match self.rx.recv_timeout(idle) {
                Ok(l) => l,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(AcpError::Idle(format!(
                        "no output for {}s during {method}",
                        idle.as_secs()
                    )))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AcpError::Closed(format!(
                        "agent closed stdout during {method}"
                    )))
                }
            };
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let msg_method = msg.get("method").and_then(Value::as_str);
            match (msg_method, msg.get("id")) {
                // Response to our request.
                (None, Some(rid)) if rid.as_u64() == Some(id) => {
                    if let Some(err) = msg.get("error") {
                        return Err(AcpError::Protocol(format!(
                            "agent error during {method}: {err}"
                        )));
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
                // Notification from the agent.
                (Some("session/update"), None) => self.on_update(&msg),
                // Request from the agent (e.g. permission): answer it.
                (Some(m), Some(rid)) => self.on_agent_request(m, rid.clone(), &msg)?,
                _ => {}
            }
        }
    }

    fn on_update(&mut self, msg: &Value) {
        self.out.updates += 1;
        let update = &msg["params"]["update"];
        match update["sessionUpdate"].as_str() {
            Some("agent_message_chunk") => {
                if let Some(t) = update["content"]["text"].as_str() {
                    self.out.text.push_str(t);
                }
            }
            Some("tool_call") => self.out.tool_calls += 1,
            _ => {}
        }
    }

    fn on_agent_request(&mut self, method: &str, id: Value, msg: &Value) -> Result<(), AcpError> {
        if method == "session/request_permission" {
            self.out.permissions_granted += 1;
            // Pick an allowed option actually offered by the request, mirroring
            // the worker's `permission_choice`: prefer `allow_always`, then
            // `allow_once`, then the first option. A hardcoded `"allow"` would
            // be an invalid selection whenever the agent offers different ids.
            let options = msg["params"]["options"].as_array();
            let pick = |kind: &str| -> Option<String> {
                options?.iter().find_map(|o| {
                    (o["kind"].as_str() == Some(kind))
                        .then(|| o["optionId"].as_str().map(str::to_string))
                        .flatten()
                })
            };
            let option_id = pick("allow_always").or_else(|| pick("allow_once")).or_else(|| {
                options
                    .and_then(|o| o.first())
                    .and_then(|o| o["optionId"].as_str().map(str::to_string))
            });
            // Mirror the worker's `permission_choice` (src/acp.rs): with no
            // offered options there is nothing to select, so report `cancelled`
            // rather than a synthetic `allow` id that no request offered.
            let reply = match option_id {
                Some(opt) => json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "outcome": { "outcome": "selected", "optionId": opt } }
                }),
                None => json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "outcome": { "outcome": "cancelled" } }
                }),
            };
            self.send(&reply)
        } else {
            self.send(&json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("method not found: {method}") }
            }))
        }
    }

    fn run(mut self, prompt: &str, idle: Duration) -> Result<AcpOutcome, AcpError> {
        let init = self.request(
            "initialize",
            json!({
                "protocolVersion": 1,
                "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false } },
                "clientInfo": { "name": "contract-tests", "version": "0" }
            }),
            idle,
        )?;
        if init.get("protocolVersion").is_none() {
            return Err(AcpError::Protocol(format!(
                "initialize had no protocolVersion: {init}"
            )));
        }
        let session = self.request("session/new", json!({ "cwd": ".", "mcpServers": [] }), idle)?;
        let session_id = session["sessionId"]
            .as_str()
            .ok_or_else(|| AcpError::Protocol("session/new returned no sessionId".into()))?
            .to_string();
        let done = self.request(
            "session/prompt",
            json!({ "sessionId": session_id, "prompt": [{ "type": "text", "text": prompt }] }),
            idle,
        )?;
        self.out.stop_reason = done["stopReason"].as_str().unwrap_or("unknown").to_string();
        // Close stdin and reap the child.
        self.stdin.take();
        let _ = self.child.wait();
        Ok(self.out.clone())
    }
}

impl Drop for AcpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
