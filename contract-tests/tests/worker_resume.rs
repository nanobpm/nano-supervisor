//! **Checkpoint / resume** and **AgentInstance records**.
//!
//! When a worker is killed mid-job, a fresh worker picks the job up again once
//! the activation lapses, rather than starting from a clean slate. Along the way
//! the worker writes AgentInstance records — create and update, and the history
//! turns for a job. Needs a live engine; skips without one.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip, Target};
use serde_json::json;

/// After a job runs, an AgentInstance record exists for it with at least one
/// history turn — asserted against the ENGINE's AgentInstance read model, not a
/// worker log line.
#[test]
fn job_writes_an_agent_instance_record() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The Rust worker has no AgentInstance/history producer yet (it never calls
    // createAgentInstance/updateAgentInstance), so the engine-observable record
    // is pinned for the Node target until the Rust worker grows the producer
    // (issues #1/#3) — same gate as before, but the assertion below is now the
    // engine's record, not a stderr substring.
    if target != Target::Node {
        skip!("AgentInstance/history recording is deferred for the Rust worker (issues #1/#3)");
    }
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
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );

    // The durable record: an AgentInstance correlated on this process instance,
    // carrying at least one AgentHistory turn (the agent's "turn one").
    let instances = engine.agent_instances(&outcome.process_instance_key);
    assert!(
        !instances.is_empty(),
        "the worker must mint an AgentInstance for the job's process instance \
         (processInstanceKey {}); the engine has none",
        outcome.process_instance_key
    );
    let key = instances[0]["agentInstanceKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            instances[0]["agentInstanceKey"]
                .as_i64()
                .map(|k| k.to_string())
        })
        .expect("an AgentInstance carries its key");
    let history = engine.agent_instance_history(&key);
    assert!(
        !history.is_empty(),
        "the AgentInstance {key} must have at least one recorded history turn; \
         the engine has none"
    );
}

/// A job whose first worker is KILLED mid-run is picked up by a fresh worker
/// once the activation lapses, and runs to completion — observed at the engine
/// (the SAME job is redelivered, then completed) and at the agent (two runs:
/// the killed attempt and the redelivered one).
///
/// Scope note: this pins the engine REDELIVERY contract (same `jobKey`, full
/// retry budget, completion by the second attempt), not worker-side checkpoint
/// restore. The Rust worker deliberately wipes every prior-attempt run
/// directory before execution (`src/slot.rs` `execute`: "a retry starts from a
/// clean slate"), so attempt-local filesystem state is NOT carried over by
/// design; "resume" here means the engine hands the same job to a fresh worker,
/// which is exactly what the assertions below observe.
#[test]
fn killed_worker_job_resumes_not_restarts() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The kill/reactivate orchestration needs the scoped mid-run harness and a
    // worker that self-exits after one job; pinned for the Rust worker first
    // (the Node worker never self-exits, so this suite reaps it differently).
    if target != Target::Rust {
        skip!("kill/resume orchestration is pinned for the Rust worker first");
    }

    // One shared job type + instance across both phases: phase 1's worker is
    // killed mid-run; phase 2's fresh worker resumes THAT job.
    let job_type = engine.unique_type("resume-kill");
    let process_id = format!("p-{job_type}");
    engine
        .deploy_bpmn(
            &process_id,
            &contract_tests::bpmn::single_task(&process_id, &job_type),
        )
        .expect("deploy bpmn");
    let instance = engine
        .create_instance(&process_id, json!({ "prompt": "be killed, then resumed" }))
        .expect("create instance");
    let pik = instance["processInstanceKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            instance["processInstanceKey"]
                .as_i64()
                .map(|k| k.to_string())
        })
        .expect("processInstanceKey");

    // Phase 1: a worker picks the job up and is killed mid-run. The activation
    // (2s window) lapses with the dead refresher, so the engine redelivers.
    let (outcome1, ()) = contract_tests::with_worker_running_on(
        &engine,
        &target,
        &job_type,
        &pik,
        &[
            json!({ "sleep_ms": 30000 }),
            json!({ "emit": "first attempt" }),
            json!({ "write_result": { "attempt": 1 } }),
        ],
        &["--recovery-window", "2000"],
        &[],
        |run| {
            for _ in 0..50 {
                if run.agent_started() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            assert!(
                run.agent_started(),
                "the agent never started — there is no mid-run worker to kill"
            );
            run.kill_worker();
        },
    );
    // The killed worker never settled: the job is back to CREATED (or still
    // ACTIVATED until the deadline lapses) with its full retry budget.
    let job = engine.job(&job_type).expect("job exists");
    assert_ne!(
        job["state"].as_str().unwrap_or(""),
        "COMPLETED",
        "a killed worker must not complete the job: {job:#}"
    );

    // Phase 2: a fresh worker (a new process, new activation) picks the SAME
    // job up once the lapsed deadline lets the engine redeliver it, and runs it
    // to completion. The first attempt's 30s sleep is replaced by an immediate
    // result so the resumed run finishes at once. The second worker is started
    // a beat after the kill so it does not long-poll in vain before the
    // activation lapses (its 30s poll outlasts the 2s lapse regardless).
    let (outcome2, ()) = contract_tests::with_worker_running_on(
        &engine,
        &target,
        &job_type,
        &pik,
        &[
            json!({ "emit": "resumed" }),
            json!({ "write_result": { "attempt": 2 } }),
        ],
        &["--recovery-window", "2000"],
        &[],
        |_| {},
    );
    assert_eq!(
        outcome2.job_state(),
        "COMPLETED",
        "the resumed job must complete; phase-1 stderr:\n{}\nphase-2 stderr:\n{}",
        outcome1.stderr(),
        outcome2.stderr()
    );
    assert_eq!(
        outcome2.variables()["attempt"],
        json!(2),
        "the resumed run's result is what completes the job"
    );
    // Two agent processes ran across the two attempts (the killed one and the
    // resumed one): each phase's record shows its own single run, and the
    // resumed run's prompt is the SAME job's payload (resume, not a new job).
    assert_eq!(outcome1.record().runs, 1, "phase 1 ran its agent once");
    assert_eq!(outcome2.record().runs, 1, "phase 2 ran its agent once");
    assert_eq!(
        outcome2.payload()["jobKey"].as_str().map(str::to_string),
        outcome1.payload()["jobKey"].as_str().map(str::to_string),
        "the resumed run is the SAME job, re-activated — not a fresh one"
    );
}
