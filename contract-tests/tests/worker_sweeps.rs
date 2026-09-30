//! **Housekeeping**: the startup and periodic sweeps (`--reap-age`,
//! `--reap-interval`), the disk-space check (`--min-free-mb`), and
//! `--keep-runs`. The worker reaps stale run directories on startup and on a
//! cadence; the disk floor gates container sandboxes only.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

#[test]
fn startup_sweep_reaps_stale_runs() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The reaper knobs (ms) and the boolean `--keep-runs` are accepted and the
    // worker still services its job with the reaper running on a tight cadence.
    let outcome = run_worker_job(
        &engine,
        &target,
        "sweep-reap",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "sweep first" }),
        &[
            "--reap-age",
            "1000",
            "--reap-interval",
            "1000",
            "--keep-runs",
        ],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
}

/// `--min-free-mb` is the disk floor for *container* sandboxes; a host-sandbox
/// hire is not gated by it (Node behaviour), so even an absurd floor still
/// lets the job run.
#[test]
fn min_free_mb_does_not_gate_host_runs() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "sweep-minfree",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "runs on the host" }),
        &["--min-free-mb", "999999999"],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    assert!(outcome.record_exists());
}
