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
    // The refresh loop must actually have FIRED, not merely "not lost the job":
    // parse the settle line's `refreshes=<n>` and require at least one refresh.
    // A 4.5s agent run on a 3s recovery window cannot survive without one, so
    // the COMPLETED state above already implies it — but only the parsed count
    // pins the refresh loop itself (a worker that never refreshed yet completed
    // by luck would pass the state assertions). The `refreshes=` instrumentation
    // is the Rust worker's; the Node plugin logs no per-settle refresh count, so
    // the count assertion is Rust-only while the engine-observable completion
    // above stays the both-targets contract.
    if target == contract_tests::Target::Rust {
        let counts = outcome.refresh_counts();
        let latest = counts.first().copied().unwrap_or(0);
        assert!(
            latest >= 1,
            "a 4.5s run on a 3s recovery window must log refreshes>=1 at settle; \
             counts: {counts:?}\nstderr:\n{}",
            outcome.stderr()
        );
    }
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
    // to fence with and the premise of this contract is unmet. Record WHICH
    // field the activation returned so the settlement below speaks the same
    // dialect this engine actually exposed.
    let token_field = if job["jobLeaseToken"].is_string() {
        "jobLeaseToken"
    } else if job["leaseToken"].is_string() {
        "leaseToken"
    } else {
        skip!("engine issued no lease token for {job_type} (pre-0.0.24?)");
    };
    let token = job[token_field]
        .as_str()
        .map(str::to_string)
        .expect("token_field was selected because job[token_field] is a string");
    // The fence is only meaningful if the wrong token differs from the real one.
    assert_ne!(
        token, "not-the-lease",
        "test premise: the wrong token must differ from the real lease token"
    );

    // A completion carrying a WRONG lease token must be rejected (the fence).
    // Send ONLY the token field the activation returned (`token_field`) —
    // sending the other dialect's field, or both, can make a strict engine
    // reject the body with a 400 schema error, which is NOT the lease fence.
    // Assert the specific `409 Conflict` the engine answers for a token
    // mismatch, so a schema or endpoint error cannot satisfy this test.
    let wrong = engine
        .http()
        .post(format!("{}/v2/jobs/{key}/completion", engine.url()))
        .json(&json!({
            "variables": {},
            token_field: "not-the-lease",
        }))
        .send()
        .expect("completion with wrong token");
    assert_eq!(
        wrong.status(),
        reqwest::StatusCode::CONFLICT,
        "a completion with a wrong lease token must be fenced with 409 Conflict, got {}",
        wrong.status()
    );
}

/// Induced activation loss: the worker is KILLED mid-run, its refresher dies
/// with it, the activation's deadline lapses, and the engine redelivers the job
/// to a fresh activation. The job is observably lost by the first (dead) worker
/// — the engine hands it out again — and the dead worker's agent never settles
/// it: the job survives with its full retry budget, ready to run again.
///
/// The inducement is real, not conditional: the worker runs a 30s agent on a 2s
/// recovery window, the test SIGKILLs the worker once the agent is mid-run,
/// waits out the lapsed deadline, and activates the job directly over REST —
/// the engine's redelivery IS the induced loss.
#[test]
fn killed_workers_activation_is_lost_and_redelivered() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The kill/reactivate orchestration needs the scoped, mid-run harness; the
    // Node plugin's worker is reaped differently by this suite (it never
    // self-exits), so the kill contract is pinned for the Rust worker first.
    if target != contract_tests::Target::Rust {
        skip!("mid-run kill/redelivery orchestration is pinned for the Rust worker first");
    }
    let (outcome, redelivered) = contract_tests::with_worker_running(
        &engine,
        &target,
        "lease-kill",
        &[
            // Long enough to still be running when the lapsed activation is
            // redelivered (2s window + polling margin).
            json!({ "sleep_ms": 30000 }),
            json!({ "emit": "too late" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "be killed mid-run" }),
        &["--recovery-window", "2000"],
        &[],
        |run| {
            // Wait for the agent to be mid-run, then kill the worker outright —
            // the refresher dies with it and the activation starts lapsing.
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
            // The activation's deadline (≈ kill time + 2s) must lapse before the
            // engine will hand the job out again; poll for the redelivery.
            let mut redelivered: Option<serde_json::Value> = None;
            for _ in 0..60 {
                let v: serde_json::Value = engine
                    .http()
                    .post(format!("{}/v2/jobs/activation", engine.url()))
                    .json(&json!({
                        "type": run.job_type,
                        "timeout": 30000,
                        "maxJobsToActivate": 1,
                        "worker": "ct-redeliver",
                        "requestTimeout": 0,
                        "withLease": true,
                    }))
                    .send()
                    .and_then(|r| r.error_for_status())
                    .and_then(|r| r.json())
                    .unwrap_or_else(|_| json!({ "jobs": [] }));
                if let Some(job) = v["jobs"].as_array().and_then(|j| j.first()).cloned() {
                    redelivered = Some(job);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            redelivered
        },
    );
    let Some(redelivered) = redelivered else {
        panic!(
            "the engine never redelivered the job after the worker was killed — \
             the induced-loss premise failed (the activation outlived its worker).\nstderr:\n{}",
            outcome.stderr()
        );
    };
    let redelivered_key = redelivered["jobKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| redelivered["jobKey"].as_i64().map(|k| k.to_string()))
        .expect("redelivered activation carries a job key");

    // The killed worker never settled: the job kept its full retry budget (a
    // settle-fail would have consumed one) and was redelivered, not completed.
    let job = engine.job(&outcome.job_type).expect("job exists");
    assert_eq!(
        job["retries"].as_i64().unwrap_or(-1),
        3,
        "a killed worker must not fail the job from beyond the grave: {job:#}"
    );
    assert_ne!(
        job["state"].as_str().unwrap_or(""),
        "COMPLETED",
        "a killed worker must not complete the job: {job:#}"
    );

    // The redelivered activation is settleable by its new owner (the lease
    // moved with the redelivery); complete it so the instance is not stranded.
    let token_field = if redelivered["jobLeaseToken"].is_string() {
        "jobLeaseToken"
    } else {
        "leaseToken"
    };
    let settled = engine
        .http()
        .post(format!(
            "{}/v2/jobs/{redelivered_key}/completion",
            engine.url()
        ))
        .json(&json!({
            "variables": { "redelivered": true },
            token_field: redelivered[token_field],
        }))
        .send()
        .expect("redelivery completion");
    assert!(
        settled.status().is_success(),
        "the redelivered activation must be settleable, got {}",
        settled.status()
    );
}
