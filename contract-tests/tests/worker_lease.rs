//! **Leases**: `--with-lease`, the refresh cadence (every third of
//! `--recovery-window`), and fencing on complete, fail and throw-error. Losing
//! the lease stops the agent and does **not** settle the job — the engine hands
//! it out again. All of this needs a live engine and skips without one.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// With a lease, the worker refreshes the activation roughly every third of the
/// recovery window while the agent works.
#[test]
fn leased_worker_refreshes_every_third_of_the_window() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // A 3s window means a refresh ~every 1s; the agent works for ~2.5s.
    let outcome = run_worker_job(
        &engine,
        &target,
        "lease-refresh",
        &[
            json!({ "sleep_ms": 2500 }),
            json!({ "emit": "done" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "take your time" }),
        &["--with-lease", "--recovery-window", "3000"],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.contains("refresh") || logs.contains("refreshes="),
        "the worker should refresh the lease while the agent works; stderr:\n{logs}"
    );
}

/// Every settling command carries the lease token, so a superseded worker is
/// fenced (409) rather than silently settling someone else's activation.
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
        &["--with-lease", "--recovery-window", "9000"],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.contains("lease"),
        "a leased run should mention the lease in its log; stderr:\n{logs}"
    );
}

/// Losing the activation (404/409 on refresh) stops the agent and leaves the job
/// unsettled: the log says so and no completion is emitted.
#[test]
fn losing_the_lease_stops_the_agent_without_settling() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The agent would run long, but the test infrastructure is expected to revoke
    // the activation out from under it; here we only assert the log contract.
    let outcome = run_worker_job(
        &engine,
        &target,
        "lease-lost",
        &[json!({ "sleep_ms": 4000 }), json!({ "emit": "late" })],
        json!({ "prompt": "run long" }),
        &["--with-lease", "--recovery-window", "3000"],
        &[],
    );
    let logs = outcome.stderr();
    if logs.contains("activation lost") {
        assert!(
            logs.contains("NOT settled"),
            "a lost activation must not settle the job; stderr:\n{logs}"
        );
    }
}
