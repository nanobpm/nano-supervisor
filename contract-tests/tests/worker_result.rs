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
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    // Completion variables: the result's keys spread at the top level, plus the
    // worker's run metadata and the versioned result envelope.
    let vars = outcome.variables();
    assert_eq!(vars["status"], "opened", "{vars:#?}");
    assert_eq!(vars["summary"], "did it", "{vars:#?}");
    assert_eq!(vars["output"], "done", "{vars:#?}");
    assert_eq!(vars["exitCode"], 0, "{vars:#?}");
    assert_eq!(vars["truncated"], false, "{vars:#?}");
    assert!(
        vars["agent"]
            .as_str()
            .is_some_and(|a| a.starts_with("ctfake")),
        "{vars:#?}"
    );
    let env = &vars["io.nanobpm.agentResult"];
    assert_eq!(env["schemaVersion"], 1, "{env:#}");
    assert_eq!(env["status"], "completed", "{env:#}");
    assert_eq!(env["output"], "done", "{env:#}");
    assert_eq!(env["result"]["status"], "opened", "{env:#}");
    assert_eq!(
        outcome.record().runs,
        1,
        "a job with a result is never nudged"
    );
}

#[test]
fn empty_result_fails_never_completes() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target == contract_tests::Target::Node {
        // c8ctl-plugin-nano ≤1.69.4 crashes settling an agent job with no
        // transcript turns (`preGuardDrainTimedOut` is read outside the block
        // that declares it → ReferenceError), so the job is never failed. The
        // plugin's settle code fails it with retries-1, which Rust mirrors.
        skip!("node plugin bug: empty-result settle throws ReferenceError (preGuardDrainTimedOut)");
    }
    let outcome = run_worker_job(
        &engine,
        &target,
        "result-empty-fails",
        &[],
        json!({ "prompt": "produce nothing" }),
        &[],
        &[],
    );
    let job = outcome.settled_job();
    assert_ne!(
        job["state"], "COMPLETED",
        "an empty result must never complete: {job:#}"
    );
    assert_eq!(
        job["retries"],
        2,
        "an empty result fails the job, consuming one retry: {job:#}\nstderr:\n{}",
        outcome.stderr()
    );
    // Engine 0.0.24 records neither the `errorMessage` nor the variables sent
    // with a job failure (verified by failing a job by hand), so the reason and
    // the failure's `io.nanobpm.agentResult` envelope are not observable here;
    // when the engine does surface the message, it carries the reason.
    if let Some(msg) = job["errorMessage"].as_str() {
        assert!(
            msg.starts_with("agent \"ctfake") && msg.contains("produced an empty result"),
            "{job:#}"
        );
    }
    let vars = outcome.variables();
    assert!(
        !vars.contains_key("output"),
        "no completion variables: {vars:#?}"
    );
}

#[test]
fn stop_without_result_is_nudged() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The agent answers but never emits a result: the worker re-invokes it once
    // with the re-emit nudge (a fresh process, prompted with the prior output),
    // then settles on what it has — the agent did work, so the job completes.
    let outcome = run_worker_job(
        &engine,
        &target,
        "result-nudge",
        &[json!({ "emit": "still thinking" })],
        json!({ "prompt": "forget to finish" }),
        &[],
        &[],
    );
    let record = outcome.record();
    assert_eq!(
        record.runs,
        2,
        "exactly one nudge run; stderr:\n{}",
        outcome.stderr()
    );
    let nudge = record.prompts.get(1).cloned().unwrap_or_default();
    assert!(
        nudge.starts_with("You already completed the task in your previous turn")
            && nudge.ends_with("still thinking"),
        "the nudge prompt carries the prior output tail: {nudge:?}"
    );
    assert_eq!(outcome.job_state(), "COMPLETED");
    assert_eq!(
        outcome.variables()["output"],
        "still thinking\nstill thinking"
    );
}
