//! Contract tests for the `fake-agent` itself (issue #4 owns it). These run in
//! CI with no engine: they exercise the scripted stand-in directly, over both
//! pipe mode and ACP, and assert its recording of the job-to-agent contract.

use std::time::Duration;

use contract_tests::fake::{AcpError, FakeAgent, FakeRecord};
use serde_json::json;

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ns-fake-")
        .tempdir()
        .unwrap()
}

#[test]
fn pipe_records_prompt_env_cwd_and_argv() {
    let dir = tmp();
    let rec = dir.path().join("record.json");
    let (stdout, code) = FakeAgent::new()
        .record_to(&rec)
        .cwd(dir.path())
        .env("AGENT_MODEL", "fake-model")
        .env("NANO_JOB_KEY", "job-1")
        .env("NANO_AGENTIC_TEAM", "t")
        .env("UNRELATED", "ignored")
        .emit("hello ")
        .emit("world")
        .run_pipe("do the thing");

    assert_eq!(stdout, "hello world");
    assert_eq!(code, 0);

    let r = FakeRecord::read(&rec);
    assert_eq!(r.mode, "pipe");
    assert_eq!(r.first_prompt(), Some("do the thing"));
    assert_eq!(
        r.env.get("AGENT_MODEL").map(String::as_str),
        Some("fake-model")
    );
    assert_eq!(r.env.get("NANO_JOB_KEY").map(String::as_str), Some("job-1"));
    assert_eq!(
        r.env.get("NANO_AGENTIC_TEAM").map(String::as_str),
        Some("t")
    );
    // Only AGENT_*/NANO_* are observable; unrelated vars are not recorded.
    assert!(!r.env.contains_key("UNRELATED"));
    assert_eq!(
        r.cwd,
        dir.path().canonicalize().unwrap().display().to_string()
    );
    assert!(!r.argv.is_empty());
}

#[test]
fn pipe_writes_result_file() {
    let dir = tmp();
    let result = dir.path().join("result.json");
    let (_out, code) = FakeAgent::new()
        .env("AGENT_RESULT_FILE", result.to_str().unwrap())
        .write_result(json!({ "status": "opened", "pr": "o/r#1" }))
        .run_pipe("go");
    assert_eq!(code, 0);
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&result).unwrap()).unwrap();
    assert_eq!(written["status"], "opened");
    assert_eq!(written["pr"], "o/r#1");
}

#[test]
fn pipe_prints_result_marker_line() {
    let (stdout, _code) = FakeAgent::new()
        .result_marker(json!({ "status": "opened" }))
        .run_pipe("go");
    let line = stdout
        .lines()
        .find(|l| l.starts_with("::nano:result::"))
        .unwrap();
    let payload = line.strip_prefix("::nano:result::").unwrap();
    let v: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(v["status"], "opened");
}

#[test]
fn pipe_exit_code_is_honoured() {
    let (_out, code) = FakeAgent::new().emit("partial").exit(7).run_pipe("go");
    assert_eq!(code, 7);
}

#[test]
fn acp_handshake_and_text() {
    let dir = tmp();
    let rec = dir.path().join("record.json");
    let out = FakeAgent::new()
        .acp()
        .record_to(&rec)
        .emit("Reply: ")
        .emit("SPIKE-OK")
        .drive_acp("say SPIKE-OK", Duration::from_secs(5))
        .expect("acp turn");

    assert_eq!(out.text, "Reply: SPIKE-OK");
    assert_eq!(out.stop_reason, "end_turn");
    assert!(out.updates >= 2);

    let r = FakeRecord::read(&rec);
    assert_eq!(r.mode, "acp");
    assert_eq!(r.first_prompt(), Some("say SPIKE-OK"));
    // The client params from initialize were captured.
    assert!(r.initialize.is_some());
    assert!(r.session_new.is_some());
    assert_eq!(r.stop_reason.as_deref(), Some("end_turn"));
}

#[test]
fn acp_tool_call_is_counted() {
    let out = FakeAgent::new()
        .acp()
        .step(json!({ "tool_call": { "title": "run tests" } }))
        .emit("done")
        .drive_acp("work", Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.tool_calls, 1);
    assert_eq!(out.text, "done");
}

#[test]
fn acp_request_permission_is_auto_allowed_and_recorded() {
    let dir = tmp();
    let rec = dir.path().join("record.json");
    let out = FakeAgent::new()
        .acp()
        .record_to(&rec)
        .step(json!({ "request_permission": {
            "options": [
                { "optionId": "no", "kind": "reject_once", "name": "No" },
                { "optionId": "allow", "kind": "allow_once", "name": "Allow" }
            ]
        }}))
        .emit("ran the tool")
        .drive_acp("please", Duration::from_secs(5))
        .expect("acp turn");

    assert_eq!(out.permissions_granted, 1);
    let r = FakeRecord::read(&rec);
    assert_eq!(r.permissions.len(), 1);
    // The recorded outcome is whatever the client chose (yolo: selected).
    let outcome = &r.permissions[0]["outcome"];
    assert_eq!(outcome["outcome"]["outcome"], "selected");
}

#[test]
fn acp_go_silent_triggers_idle_timeout() {
    let err = FakeAgent::new()
        .acp()
        .emit("thinking")
        .go_silent(60_000)
        .drive_acp("work", Duration::from_millis(400))
        .expect_err("should idle-time-out");
    match err {
        AcpError::Idle(_) => {}
        other => panic!("expected idle timeout, got {other}"),
    }
}

#[test]
fn acp_exit_before_reply_is_a_closed_error() {
    // The agent crashes mid-turn: the client sees stdout close before the reply.
    let err = FakeAgent::new()
        .acp()
        .emit("about to die")
        .exit(3)
        .drive_acp("work", Duration::from_secs(5))
        .expect_err("should see the agent exit");
    match err {
        AcpError::Closed(_) => {}
        other => panic!("expected closed, got {other}"),
    }
}

#[test]
fn acp_custom_stop_reason() {
    let out = FakeAgent::new()
        .acp()
        .emit("hit the wall")
        .step(json!({ "stop_reason": "max_tokens" }))
        .drive_acp("work", Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.stop_reason, "max_tokens");
}

#[test]
fn acp_empty_output_is_observable_as_empty_text() {
    // The worker fails a job whose agent produced no text (c8ctl-plugin-nano#275);
    // the fake agent must be able to reproduce exactly that: a clean turn, no text.
    let out = FakeAgent::new()
        .acp()
        .drive_acp("work", Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.stop_reason, "end_turn");
    assert!(out.text.is_empty());
}
