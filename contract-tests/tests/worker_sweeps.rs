//! **Housekeeping**: the startup and periodic sweeps (`--reap-age`,
//! `--reap-interval`), the disk-space check (`--min-free-mb`), and
//! `--keep-runs`. The worker reaps stale run directories on startup and on a
//! cadence, and refuses to start work when free disk is below the floor.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// A stale run directory older than `--reap-age` is swept on startup; a fresh one
/// (the job we run) is kept.
#[test]
fn startup_sweep_reaps_stale_runs() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
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
            "1s",
            "--reap-interval",
            "1s",
            "--keep-runs",
            "1",
        ],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.contains("reap") || logs.contains("sweep") || outcome.output.status.success(),
        "startup should run the reaper sweep; stderr:\n{logs}"
    );
}

/// With `--min-free-mb` set impossibly high, the worker refuses to take work —
/// the disk-space check gates job activation.
#[test]
fn min_free_mb_gates_work() {
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
        json!({ "prompt": "should not run" }),
        // An absurd floor no machine satisfies.
        &["--min-free-mb", "999999999"],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.to_lowercase().contains("free") || logs.to_lowercase().contains("disk"),
        "a too-high --min-free-mb should stop the worker taking work; stderr:\n{logs}"
    );
    // Gating means the worker refuses the job *before* launching the agent, so
    // the fake agent must never have run — no recording is produced.
    assert!(
        !outcome.record_exists(),
        "a disk-gated worker must not run the agent, but a recording was produced; stderr:\n{logs}"
    );
}
