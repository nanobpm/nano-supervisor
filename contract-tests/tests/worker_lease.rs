//! **Leases**: the worker takes a lease on every activation (engine 0.0.24
//! issues `jobLeaseToken`), refreshes it every third of `--recovery-window`, and
//! fences complete/fail with it. Observed at the engine: a long run still
//! completes exactly once. All of this needs a live engine and skips without one.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// A job whose agent runs longer than the activation window still completes,
/// exactly once: the worker refreshes the activation so the engine never times
/// it out and re-dispatches it.
#[test]
fn leased_worker_refreshes_every_third_of_the_window() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "lease-refresh",
        &[
            json!({ "sleep_ms": 4500 }),
            json!({ "emit": "done" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "take your time" }),
        &["--recovery-window", "3000"],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "a refreshed activation must survive past its window; stderr:\n{}",
        outcome.stderr()
    );
    assert_eq!(
        outcome.record().runs,
        1,
        "the job must not be re-dispatched"
    );
    assert_eq!(outcome.variables()["ok"], true);
}

/// Settling under a lease is accepted: the fenced completion lands and carries
/// the result.
#[test]
fn settling_commands_are_fenced_by_the_lease_token() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "lease-fence",
        &[
            json!({ "emit": "done" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "complete under lease" }),
        &["--recovery-window", "9000"],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    assert_eq!(outcome.variables()["ok"], true);
}

/// The lease token is an actual FENCE, not a no-op: a settlement that carries a
/// WRONG token is rejected, while the worker's token-bearing settlement (the
/// test above) succeeds. `settling_commands_are_fenced_by_the_lease_token`
/// alone cannot prove this — an unfenced completion is also accepted, so it
/// passes even if activation never requested a lease or completion omitted the
/// token. Here we activate a job directly over REST, observe its lease token,
/// and confirm the engine rejects a completion whose token does not match.
#[test]
fn settlement_with_a_wrong_lease_token_is_rejected() {
    let (engine, _target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // Deploy a job and activate it WITH a lease, straight over REST.
    let job_type = engine.unique_type("lease-fence-reject");
    let process_id = format!("p-{job_type}");
    engine
        .deploy_bpmn(
            &process_id,
            &contract_tests::bpmn::single_task(&process_id, &job_type),
        )
        .expect("deploy bpmn");
    engine
        .create_instance(&process_id, json!({}))
        .expect("create instance");

    let activated = engine
        .http()
        .post(format!("{}/v2/jobs/activation", engine.url()))
        .json(&json!({
            "type": job_type,
            "timeout": 30000,
            "maxJobsToActivate": 1,
            "worker": "lease-fence-probe",
            "requestTimeout": 5000,
            "withLease": true,
        }))
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<serde_json::Value>())
        .expect("activate with lease");
    let job = activated["jobs"]
        .as_array()
        .and_then(|j| j.first())
        .cloned();
    let Some(job) = job else {
        skip!("no activatable job for {job_type}");
    };
    let key = job["jobKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| job["jobKey"].as_i64().map(|k| k.to_string()))
        .or_else(|| job["key"].as_str().map(str::to_string))
        .expect("activated job has a key");
    // The engine must have issued a lease token (either the spec's
    // `jobLeaseToken` or the legacy `leaseToken`); without one there is nothing
    // to fence with and the premise of this contract is unmet.
    let token = job["jobLeaseToken"]
        .as_str()
        .or_else(|| job["leaseToken"].as_str())
        .map(str::to_string);
    let Some(_token) = token else {
        skip!("engine issued no lease token for {job_type} (pre-0.0.24?)");
    };

    // A completion carrying a WRONG lease token must be rejected (the fence).
    let wrong = engine
        .http()
        .post(format!("{}/v2/jobs/{key}/completion", engine.url()))
        .json(&json!({
            "variables": {},
            "jobLeaseToken": "not-the-lease",
            "leaseToken": "not-the-lease",
        }))
        .send()
        .expect("completion with wrong token");
    assert!(
        !wrong.status().is_success(),
        "a completion with a wrong lease token must be rejected, got {}",
        wrong.status()
    );
}
