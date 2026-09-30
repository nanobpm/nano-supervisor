//! **Job selection**: a worker only activates the job type it is configured
//! for, and ignores unrelated types deployed alongside it.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// A worker configured for a job type takes exactly that job type.
#[test]
fn worker_takes_its_configured_job_type() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "selection-basic",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "pick me" }),
        &[],
        &[],
    );
    let record = outcome.record();
    assert_eq!(
        record.first_prompt(),
        Some("pick me"),
        "the worker should activate its configured job type and prompt the agent \
         with that job's `prompt`; worker stderr:\n{}",
        outcome.stderr()
    );
}

/// A worker configured for one job type does **not** take an unrelated job type
/// deployed alongside it.
#[test]
fn worker_ignores_other_job_types() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // Deploy an unrelated process/job and start it; our worker (a different,
    // unique job type via run_worker_job) must not touch it.
    let other = engine.unique_type("selection-other");
    let other_proc = format!("p-{other}");
    engine
        .deploy_bpmn(
            &other_proc,
            &contract_tests::bpmn::single_task(&other_proc, &other),
        )
        .expect("deploy other");
    engine
        .create_instance(&other_proc, json!({ "prompt": "not for you" }))
        .expect("start other");

    let outcome = run_worker_job(
        &engine,
        &target,
        "selection-scoped",
        &[
            json!({ "emit": "mine" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "mine only" }),
        &[],
        &[],
    );
    let record = outcome.record();
    assert_eq!(
        record.first_prompt(),
        Some("mine only"),
        "the worker took the wrong job; it must only take its own job type"
    );
    // The worker taking only its own job is necessary but not sufficient: a
    // worker that activated *every* job type would still record its own job.
    // Prove the unrelated instance was never touched by confirming its job is
    // still activatable now that the worker has exited.
    assert_eq!(
        engine.activatable_count(&other),
        1,
        "the unrelated `{other}` job must remain waiting — the worker must not activate other job types"
    );
}
