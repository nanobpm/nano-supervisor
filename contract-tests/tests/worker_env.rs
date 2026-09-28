//! Job in, agent input out — **the environment and working directory**.
//!
//! The worker hands the agent a working directory (with the repo provisioned)
//! and an environment: `AGENT_*` (`AGENT_RESULT_FILE`, `AGENT_MODEL`, …), `NANO_*`
//! and `NANO_AGENTIC_*`. The fake agent records exactly what it received.

use std::time::Duration;

use contract_tests::fake::FakeAgent;
use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// CI, no engine: every `AGENT_*` / `NANO_*` variable the agent is given is
/// recorded verbatim, and nothing else is. This pins the recorder the end-to-end
/// env assertions rely on.
#[test]
fn agent_records_agent_and_nano_env_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let rec = dir.path().join("record.json");
    let out = FakeAgent::new()
        .acp()
        .record_to(&rec)
        .env("AGENT_MODEL", "claude-x")
        .env("NANO_JOB_KEY", "42")
        .env("NANO_AGENTIC_RUN", "r1")
        .env("PATH_LIKE_NOISE", "should-not-be-recorded")
        .emit("ok")
        .drive_acp("go", Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.text, "ok");
    let record = contract_tests::fake::FakeRecord::read(&rec);
    assert_eq!(
        record.env.get("AGENT_MODEL").map(String::as_str),
        Some("claude-x")
    );
    assert_eq!(
        record.env.get("NANO_JOB_KEY").map(String::as_str),
        Some("42")
    );
    assert_eq!(
        record.env.get("NANO_AGENTIC_RUN").map(String::as_str),
        Some("r1")
    );
    assert!(!record.env.contains_key("PATH_LIKE_NOISE"));
}

/// End-to-end: the worker sets `AGENT_RESULT_FILE` and at least one `NANO_*`
/// variable, and runs the agent in a per-job working directory.
#[test]
fn worker_gives_agent_result_file_and_nano_env() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "env-contract",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "note your environment" }),
        &[],
        &[],
    );
    let record = outcome.record();
    assert!(
        record.env.contains_key("AGENT_RESULT_FILE"),
        "worker must set AGENT_RESULT_FILE; env was {:?}",
        record.env
    );
    assert!(
        record.env.keys().any(|k| k.starts_with("NANO_")),
        "worker must set NANO_* variables; env was {:?}",
        record.env
    );
    assert!(
        !record.cwd.is_empty(),
        "agent must run in a working directory"
    );
}
