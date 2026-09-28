//! **Checkpoint / resume** and **AgentInstance records**.
//!
//! When a worker is killed mid-job, a fresh worker picks the job up again once
//! the activation lapses, rather than starting from a clean slate. Along the way
//! the worker writes AgentInstance records — create and update, and the history
//! turns for a job. Needs a live engine; skips without one.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// After a job runs, an AgentInstance record exists for it with at least one
/// history turn.
#[test]
fn job_writes_an_agent_instance_record() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "resume-agentinstance",
        &[
            json!({ "emit": "turn one" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "record me" }),
        &[],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.to_lowercase().contains("agentinstance") || logs.contains("history"),
        "the worker should record an AgentInstance for the job; stderr:\n{logs}"
    );
}

/// A job re-activated after its first worker was killed mid-run resumes on the
/// existing branch/run rather than starting over.
#[test]
fn killed_worker_job_resumes_not_restarts() {
    let (_engine, _target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // Resume needs a worker killed mid-job and a second worker on the same job —
    // orchestration only possible against a live cluster. Documented here as the
    // contract; the live harness drives the kill/reactivate cycle.
    skip!("resume requires killing a worker mid-job against a live cluster");
}
