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
