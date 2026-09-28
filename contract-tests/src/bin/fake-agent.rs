//! `fake-agent` — a scripted stand-in for Copilot / nano-coder, for the worker
//! contract tests (issue #4; #3 and #5 reuse it).
//!
//! It speaks two shapes a Nano worker can drive:
//!
//! - **ACP** (`--acp`): the Agent Client Protocol, JSON-RPC 2.0 with one JSON
//!   object per line over stdio — the same handshake `src/acp.rs` drives
//!   (`initialize` -> `session/new` -> `session/prompt`, with `session/update`
//!   notifications and auto-answered `session/request_permission` requests).
//! - **pipe** (default): the prompt arrives on stdin (or `--prompt`), output goes
//!   to stdout, and a result is written to `AGENT_RESULT_FILE` and/or announced
//!   with a `::nano:result::` line.
//!
//! What it does is **scripted** with `NS_FAKE_SCRIPT` (inline JSON or `@path`): a
//! JSON array of steps (emit text, a tool call, request a permission, write the
//! result file, print the marker, sleep, go silent, exit with a code, crash).
//! What it **received** (argv, the AGENT_*/NANO_* environment, the working
//! directory, the prompt and any steers, the permission requests) is recorded as
//! JSON to `NS_FAKE_RECORD`, so a test can assert on the job-to-agent contract.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::time::Duration;

use serde_json::{json, Value};

const PROTOCOL_VERSION: u64 = 1;

/// Everything the agent observed, written to `NS_FAKE_RECORD` as JSON.
#[derive(Default, serde::Serialize)]
struct Record {
    mode: String,
    argv: Vec<String>,
    cwd: String,
    /// Every `AGENT_*` and `NANO_*` variable (sorted), the observable environment
    /// the worker hands the agent.
    env: BTreeMap<String, String>,
    /// The `session/prompt` texts in order: index 0 is the initial prompt, the
    /// rest are steers.
    prompts: Vec<String>,
    /// The client params from `initialize` (ACP only).
    initialize: Option<Value>,
    /// The params from `session/new` (ACP only).
    session_new: Option<Value>,
    /// Each `session/request_permission` we raised and the option the client chose.
    permissions: Vec<Value>,
    stop_reason: Option<String>,
    /// The exit code we finished with (when a step forced one).
    exit_code: Option<i32>,
    /// True when a step made us finish a prompt turn without replying (idle-timeout).
    hung: bool,
}

impl Record {
    fn capture_env() -> BTreeMap<String, String> {
        std::env::vars()
            .filter(|(k, _)| k.starts_with("AGENT_") || k.starts_with("NANO_"))
            .collect()
    }

    fn flush(&self) {
        if let Ok(path) = std::env::var("NS_FAKE_RECORD") {
            let json = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into());
            // Best effort: a failed write must not change the agent's exit code.
            let _ = std::fs::write(path, json);
        }
    }
}

fn load_script() -> Vec<Value> {
    let raw = match std::env::var("NS_FAKE_SCRIPT") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let text = if let Some(path) = raw.strip_prefix('@') {
        std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("fake-agent: cannot read NS_FAKE_SCRIPT file {path}: {e}");
            std::process::exit(2);
        })
    } else {
        raw
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Array(steps)) => steps,
        Ok(other) => {
            eprintln!("fake-agent: NS_FAKE_SCRIPT must be a JSON array, got {other}");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("fake-agent: NS_FAKE_SCRIPT is not valid JSON: {e}");
            std::process::exit(2);
        }
    }
}

fn write_result_file(value: &Value) {
    match std::env::var("AGENT_RESULT_FILE") {
        Ok(path) => {
            if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()) {
                eprintln!("fake-agent: cannot write AGENT_RESULT_FILE {path}: {e}");
            }
        }
        Err(_) => eprintln!("fake-agent: write_result step but AGENT_RESULT_FILE is unset"),
    }
}

fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let acp = argv.iter().any(|a| a == "--acp");
    let mut record = Record {
        mode: if acp { "acp" } else { "pipe" }.into(),
        argv: argv.clone(),
        cwd: std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        env: Record::capture_env(),
        ..Default::default()
    };
    let script = load_script();

    let code = if acp {
        run_acp(&mut record, &script)
    } else {
        run_pipe(&mut record, &argv, &script)
    };
    record.exit_code = Some(code);
    record.flush();
    std::process::exit(code);
}

/// Run the scripted steps for one prompt turn. Returns `Some(exit_code)` when a
/// step asked us to terminate the whole process, else `None` (turn finished
/// normally). `emit` writes agent-visible output; `on_permission` raises a
/// permission request and returns the chosen option.
fn run_steps(
    record: &mut Record,
    script: &[Value],
    mut emit: impl FnMut(&str),
    mut emit_tool_call: impl FnMut(&Value),
    mut on_permission: impl FnMut(&Value) -> Value,
) -> StepEnd {
    for step in script {
        let obj = match step.as_object() {
            Some(o) => o,
            None => continue,
        };
        if let Some(t) = obj.get("emit").and_then(Value::as_str) {
            emit(t);
        } else if let Some(tc) = obj.get("tool_call") {
            emit_tool_call(tc);
        } else if let Some(v) = obj.get("write_result") {
            write_result_file(v);
        } else if let Some(v) = obj.get("result_marker") {
            // A single line the worker scrapes: `::nano:result::<compact-json>`.
            println!("::nano:result::{}", serde_json::to_string(v).unwrap());
            let _ = std::io::stdout().flush();
        } else if let Some(ms) = obj.get("sleep_ms").and_then(Value::as_u64) {
            sleep_ms(ms);
        } else if let Some(ms) = obj.get("go_silent").and_then(Value::as_u64) {
            // Produce nothing for `ms`, then leave the turn unanswered so the
            // worker's idle timeout fires.
            sleep_ms(ms);
            record.hung = true;
            return StepEnd::Hang;
        } else if obj.get("go_silent").is_some() {
            record.hung = true;
            return StepEnd::Hang;
        } else if let Some(p) = obj.get("request_permission") {
            let outcome = on_permission(p);
            record
                .permissions
                .push(json!({ "params": p, "outcome": outcome }));
        } else if let Some(code) = obj.get("exit").and_then(Value::as_i64) {
            return StepEnd::Exit(code as i32);
        } else if obj.get("crash").is_some() {
            // A hard crash: abort with no unwinding, like a segfault/panic=abort.
            record.exit_code = Some(-1);
            record.flush();
            std::process::abort();
        }
    }
    StepEnd::Done
}

enum StepEnd {
    /// All steps ran; finish the turn normally.
    Done,
    /// A step left the turn unanswered (idle-timeout test).
    Hang,
    /// A step asked the process to exit with this code.
    Exit(i32),
}

// ---- pipe mode -------------------------------------------------------------

fn run_pipe(record: &mut Record, argv: &[String], script: &[Value]) -> i32 {
    let prompt = pipe_prompt(argv);
    record.prompts.push(prompt);
    let end = run_steps(
        record,
        script,
        |t| {
            print!("{t}");
            let _ = std::io::stdout().flush();
        },
        // Pipe mode has no tool-call channel; surface it as a line for visibility.
        |tc| {
            println!("[tool_call] {tc}");
            let _ = std::io::stdout().flush();
        },
        // Pipe mode has no permission channel; auto-"allow" and record it.
        |_| json!({ "outcome": "selected", "note": "pipe mode auto-allow" }),
    );
    match end {
        StepEnd::Exit(code) => code,
        // Hang in pipe mode simply means "produce no result": the worker nudges,
        // then fails the job. We still exit 0 — the crash is the silence.
        StepEnd::Done | StepEnd::Hang => 0,
    }
}

fn pipe_prompt(argv: &[String]) -> String {
    if let Some(i) = argv.iter().position(|a| a == "--prompt") {
        if let Some(p) = argv.get(i + 1) {
            return p.clone();
        }
    }
    let mut buf = String::new();
    // Read the prompt from stdin when one is piped in; empty when the worker
    // passes it another way.
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

// ---- ACP mode --------------------------------------------------------------

fn run_acp(record: &mut Record, script: &[Value]) -> i32 {
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut next_id: u64 = 10_000;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str);
        match method {
            Some("initialize") => {
                record.initialize = msg.get("params").cloned();
                send(&json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "agentCapabilities": { "promptCapabilities": { "image": false, "audio": false } },
                        "authMethods": [],
                        "agentInfo": { "name": "fake-agent", "version": env!("CARGO_PKG_VERSION") }
                    }
                }));
            }
            Some("session/new") => {
                record.session_new = msg.get("params").cloned();
                send(&json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "sessionId": "fake-session-1" }
                }));
            }
            Some("session/prompt") => {
                let sid = msg["params"]["sessionId"]
                    .as_str()
                    .unwrap_or("fake-session-1");
                record.prompts.push(prompt_text(&msg["params"]["prompt"]));
                let end = run_acp_turn(record, script, sid, &mut next_id, &mut lines);
                match end {
                    StepEnd::Exit(code) => return code,
                    StepEnd::Hang => {
                        // Never send the prompt response: the worker idle-times-out.
                        // Keep the process alive so the pipe stays open until it is
                        // stopped, mirroring a wedged agent.
                        loop {
                            sleep_ms(60_000);
                        }
                    }
                    StepEnd::Done => {
                        let stop = script_stop_reason(script);
                        record.stop_reason = Some(stop.clone());
                        send(&json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": { "stopReason": stop }
                        }));
                    }
                }
            }
            Some("session/cancel") => { /* notification, nothing to answer */ }
            Some(other) => {
                if let Some(id) = id {
                    send(&json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": format!("method not found: {other}") }
                    }));
                }
            }
            None => { /* a response to one of our requests handled inline elsewhere */ }
        }
    }
    0
}

/// Run one prompt turn's steps, translating them to `session/update`
/// notifications and `session/request_permission` requests on the given session.
fn run_acp_turn<I: Iterator<Item = std::io::Result<String>>>(
    record: &mut Record,
    script: &[Value],
    session_id: &str,
    next_id: &mut u64,
    lines: &mut I,
) -> StepEnd {
    // `emit` and `on_permission` need the session id and the id counter; collect
    // updates through closures that borrow them.
    let mut pending_permission: Option<Value> = None;
    let end = run_steps(
        record,
        script,
        |text| {
            send(&json!({
                "jsonrpc": "2.0", "method": "session/update",
                "params": {
                    "sessionId": session_id,
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": { "type": "text", "text": text }
                    }
                }
            }));
        },
        |tc| {
            // A tool_call notification the client counts (title/kind pass through).
            send(&json!({
                "jsonrpc": "2.0", "method": "session/update",
                "params": {
                    "sessionId": session_id,
                    "update": {
                        "sessionUpdate": "tool_call",
                        "toolCallId": tc.get("toolCallId").cloned().unwrap_or_else(|| json!("fake-tool-1")),
                        "title": tc.get("title").cloned().unwrap_or_else(|| json!("fake tool")),
                        "kind": tc.get("kind").cloned().unwrap_or_else(|| json!("other")),
                        "status": "completed"
                    }
                }
            }));
        },
        |req| {
            // Ask the client to allow; block for its answer on the next line.
            let rid = *next_id;
            *next_id += 1;
            let options = req.get("options").cloned().unwrap_or_else(
                || json!([{ "optionId": "allow", "kind": "allow_once", "name": "Allow" }]),
            );
            send(&json!({
                "jsonrpc": "2.0", "id": rid, "method": "session/request_permission",
                "params": {
                    "sessionId": session_id,
                    "options": options,
                    "toolCall": req.get("toolCall").cloned().unwrap_or(json!({ "title": "fake tool" }))
                }
            }));
            pending_permission = Some(json!(rid));
            read_response(lines, rid)
        },
    );
    let _ = pending_permission;
    end
}

/// Read lines until the JSON-RPC response with `id` arrives; return its result.
fn read_response<I: Iterator<Item = std::io::Result<String>>>(lines: &mut I, id: u64) -> Value {
    for line in lines.by_ref() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if msg.get("id").and_then(Value::as_u64) == Some(id) {
            return msg
                .get("result")
                .cloned()
                .unwrap_or_else(|| json!({ "outcome": "cancelled" }));
        }
        // A stray request from the client while we wait: answer method-not-found.
        if let (Some(other), Some(oid)) = (msg.get("method").and_then(Value::as_str), msg.get("id"))
        {
            send(&json!({
                "jsonrpc": "2.0", "id": oid,
                "error": { "code": -32601, "message": format!("method not found: {other}") }
            }));
        }
    }
    json!({ "outcome": "cancelled" })
}

fn prompt_text(prompt: &Value) -> String {
    // ACP prompt is an array of content blocks; concatenate the text ones.
    prompt
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

fn script_stop_reason(script: &[Value]) -> String {
    script
        .iter()
        .find_map(|s| s.get("stop_reason").and_then(Value::as_str))
        .unwrap_or("end_turn")
        .to_string()
}

fn send(msg: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}
