//! Agent result in, engine command out — **the result**.
//!
//! The worker reads the agent's result from `AGENT_RESULT_FILE` and the
//! `::nano:result::` marker, nudges an agent that stops without one, and — the
//! rule from jwulf/c8ctl-plugin-nano#275 — treats an **empty** result as a
//! **failure**, never a completion.

use std::time::Duration;

use contract_tests::fake::FakeAgent;
use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// CI, no engine: an agent that finishes a clean turn with no text is observable
/// as empty output — exactly the case the worker must turn into a failure.
#[test]
fn empty_agent_turn_is_observably_empty() {
    let out = FakeAgent::new()
        .acp()
        .drive_acp("do nothing", Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.stop_reason, "end_turn");
    assert!(out.text.is_empty(), "no text was emitted");
}

/// End-to-end: a non-empty result completes the job, and the agent's result file
/// is what the worker forwards.
#[test]
fn non_empty_result_completes_the_job() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "result-complete",
        &[
            json!({ "emit": "done" }),
            json!({ "write_result": { "status": "opened", "summary": "did it" } }),
        ],
        json!({ "prompt": "do it" }),
        &[],
        &[],
    );
    assert_eq!(outcome.result_file().unwrap()["status"], "opened");
    let logs = outcome.stderr();
    assert!(
        logs.contains("completed") || outcome.output.status.success(),
        "job should complete; worker stderr:\n{logs}"
    );
}

/// End-to-end: an agent that produces nothing must make the worker **fail** the
/// job, never complete it (c8ctl-plugin-nano#275).
#[test]
fn empty_result_fails_never_completes() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "result-empty-fails",
        // A clean `end_turn` with no text and no result file — the canonical
        // empty result (c8ctl-plugin-nano#275), not an idle-timeout hang.
        &[],
        json!({ "prompt": "produce nothing" }),
        &[],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        !logs.contains("completed in"),
        "an empty result must never complete the job; worker stderr:\n{logs}"
    );
    assert!(
        logs.contains("fail") || logs.contains("without any output"),
        "an empty result must fail the job; worker stderr:\n{logs}"
    );
}

/// End-to-end: an agent that stops without a result gets a **nudge** before the
/// worker gives up on it.
#[test]
fn stop_without_result_is_nudged() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "result-nudge",
        // Emit chatter but never write the result file / marker.
        &[json!({ "emit": "still thinking" })],
        json!({ "prompt": "forget to finish" }),
        &[],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.to_lowercase().contains("nudge"),
        "worker should nudge an agent that stops without a result; stderr:\n{logs}"
    );
}
