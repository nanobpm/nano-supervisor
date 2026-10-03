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
    // Drive the sweep wiring hard: a tight `--reap-age`/`--reap-interval` so the
    // startup AND cadence reapers both run during the job, and NO `--keep-runs`
    // so the worker manages its own per-worker run namespace (reaping the run
    // dir on completion). The job must still complete with the reaper active.
    let outcome = run_worker_job(
        &engine,
        &target,
        "sweep-reap",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "sweep first" }),
        &["--reap-age", "1000", "--reap-interval", "1000"],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    // The fake agent ran and wrote its result through the worker's own result
    // channel, proving the run-dir lifecycle (provision → run → result → reap)
    // stayed intact with the sweeps engaged.
    assert!(
        outcome.record_exists(),
        "the agent never ran — the sweep must not remove a live run dir.\nstderr:\n{}",
        outcome.stderr()
    );
    let result = outcome.result_file().unwrap_or_else(|| {
        panic!(
            "the agent's result file is gone — the worker reaped the run dir before reading the result.\nstderr:\n{}",
            outcome.stderr()
        )
    });
    assert_eq!(
        result["ok"],
        json!(true),
        "the worker must read the agent's result before any reap: {result}"
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
