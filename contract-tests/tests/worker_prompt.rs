//! Job in, agent input out — **prompt assembly**.
//!
//! The worker turns a job into the prompt the agent receives: the job's `prompt`
//! variable, linked prompts pulled with `get_resource_content`, and task
//! `secretRefs` resolved with `--secret-resolver host`. The agent-boundary shape
//! (an ACP text prompt) is checked in CI with the fake agent; the full assembly
//! is checked end-to-end against a live worker and skips when none is reachable.

use std::time::Duration;

use contract_tests::fake::FakeAgent;
use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// CI, no engine: the prompt the worker sends arrives at the agent intact as an
/// ACP text block (the shape `src/acp.rs` sends: `[{type:text,text}]`).
#[test]
fn prompt_reaches_agent_intact_over_acp() {
    let dir = tempfile::tempdir().unwrap();
    let rec = dir.path().join("record.json");
    let prompt = "line one\nline two\n\tindented — unicode ✓";
    let out = FakeAgent::new()
        .acp()
        .record_to(&rec)
        .emit("ok")
        .drive_acp(prompt, Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.text, "ok");
    let record = contract_tests::fake::FakeRecord::read(&rec);
    assert_eq!(record.first_prompt(), Some(prompt));
}

/// End-to-end: the job's `prompt` variable is what the agent is prompted with.
#[test]
fn job_prompt_variable_becomes_the_agent_prompt() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let prompt = "Reply with exactly SPIKE-OK";
    let outcome = run_worker_job(
        &engine,
        &target,
        "prompt-passthrough",
        &[
            json!({ "emit": "SPIKE-OK" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": prompt }),
        &[],
        &[],
    );
    let record = outcome.record();
    assert_eq!(
        record.first_prompt(),
        Some(prompt),
        "the agent should be prompted with the job's `prompt` variable; worker stderr:\n{}",
        outcome.stderr()
    );
}
