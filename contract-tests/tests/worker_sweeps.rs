//! **Housekeeping**: the startup and periodic sweeps (`--reap-age`,
//! `--reap-interval`), the disk-space check (`--min-free-mb`), and
//! `--keep-runs`. The worker reaps stale run directories on startup and on a
//! cadence; the disk floor gates container sandboxes only.

use contract_tests::{
    require_engine_and_target, run_worker_job, run_worker_job_in, skip, Skip, Target, TempHome,
};
use serde_json::json;

#[test]
fn startup_sweep_reaps_stale_runs() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // Both runs share ONE home so the stale tree seeded after the first run sits
    // in the same `agent-runs` root the second worker's startup sweep walks. The
    // home stays alive in `home` for the whole test (the outcomes only borrow a
    // path clone), so the temp dir is not torn down between runs.
    let home = TempHome::new();
    let sweep_root = home.path().join("agent-runs");
    // Drive the sweep wiring hard: a tight `--reap-age`/`--reap-interval` so the
    // startup AND cadence reapers both run during the job, and NO `--keep-runs`
    // so the worker manages its own per-worker run namespace (reaping the run
    // dir on completion). The job must still complete with the reaper active.
    let outcome = run_worker_job_in(
        &engine,
        &target,
        &home,
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
    // The worker consumed the agent's result and completed the job with it. The
    // per-job `result.json` is deliberately unlinked and the run dir reaped on a
    // successful settle, so the durable proof the result was parsed is the
    // completion variable the worker wrote back to the engine — not the file,
    // which is gone by the time the worker exits.
    let vars = outcome.variables();
    assert_eq!(
        vars.get("ok"),
        Some(&json!(true)),
        "the worker must read the agent's result and complete the job with it before any reap.\nstderr:\n{}",
        outcome.stderr()
    );
    // The point of the test: the sweep actually REAPS a stale dead-worker tree.
    // Previously this test only proved a live job completes with the reaper
    // enabled — a broken sweep that removes nothing would still pass. Now seed a
    // genuinely stale, dead-worker namespace plus a live-owned one into the
    // sweep root (the SHARED parent of the worker's `rust-worker-<pid>`
    // namespace), then run a SECOND worker (same home) whose startup sweep must
    // reap the dead tree and spare the live one. Only the Rust worker owns
    // `rust-worker-<pid>` namespaces; the Node plugin has no equivalent, so this
    // seeding is Rust-only.
    if target == Target::Rust {
        let stale = sweep_root.join("rust-worker-999999999").join("stale-job");
        let live = sweep_root
            .join(format!("rust-worker-{}", std::process::id()))
            .join("live-job");
        std::fs::create_dir_all(&stale).expect("seed stale run dir");
        std::fs::create_dir_all(&live).expect("seed live run dir");

        // The stale fixture is seeded immediately before this second worker
        // starts, so its mtime is younger than any non-zero `--reap-age`; a
        // `--reap-age 1000` startup sweep would RETAIN it and the fast
        // `--max-jobs 1` run can exit before the first cadence tick, making the
        // `!stale.exists()` assertion timing-dependent. Use a zero reap age so
        // the startup sweep reaps the aged-out (any age) dead-worker tree
        // deterministically; the cross-process live-owner check still spares the
        // live-owned namespace regardless of age.
        let outcome2 = run_worker_job_in(
            &engine,
            &target,
            &home,
            "sweep-reap-2",
            &[
                json!({ "emit": "ok" }),
                json!({ "write_result": { "ok": true } }),
            ],
            json!({ "prompt": "sweep second" }),
            &["--reap-age", "0", "--reap-interval", "1000"],
            &[],
        );
        assert_eq!(
            outcome2.job_state(),
            "COMPLETED",
            "stderr:\n{}",
            outcome2.stderr()
        );
        assert!(
            !stale.exists(),
            "the sweep must reap the aged dead-worker run dir {}.\nstderr:\n{}",
            stale.display(),
            outcome2.stderr()
        );
        assert!(
            live.exists(),
            "the sweep must NOT reap a run dir owned by a live worker {}.\nstderr:\n{}",
            live.display(),
            outcome2.stderr()
        );
    }
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

/// `--keep-runs` promises retained runs are KEPT: it gates the startup sweep,
/// the cadence sweep, the per-job execute-start reap, and the per-completion
/// cleanup. A regression that deletes a supposedly retained run would otherwise
/// go undetected — every other sweep test runs WITHOUT the flag. Run one job
/// with `--keep-runs` (and an aggressive `--reap-age 0` so any sweep that DID
/// fire would delete it) and assert the completed run directory survives.
#[test]
fn keep_runs_preserves_completed_run() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // Only the Rust worker owns `rust-worker-<pid>` namespaces; the Node plugin
    // has no equivalent run-dir layout to assert against.
    if target != Target::Rust {
        skip!("rust-worker-<pid> run namespaces are a Rust-worker layout");
    }
    let home = TempHome::new();
    let sweep_root = home.path().join("agent-runs");
    let outcome = run_worker_job_in(
        &engine,
        &target,
        &home,
        "keep-runs",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "keep my run" }),
        // `--reap-age 0` makes every run dir "stale", so if `--keep-runs` failed
        // to gate ANY sweep (startup, cadence, execute-start, or completion) the
        // run dir would be reaped and this test would catch it.
        &["--keep-runs", "--reap-age", "0", "--reap-interval", "1000"],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    assert!(
        outcome.record_exists(),
        "the agent never ran.\nstderr:\n{}",
        outcome.stderr()
    );
    // The completed run dir must survive under SOME `rust-worker-<pid>`
    // namespace (the worker's pid is a child process we cannot predict, so scan
    // the shared `agent-runs` root for any retained run dir).
    let retained = std::fs::read_dir(&sweep_root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("rust-worker-"))
                .unwrap_or(false)
        })
        .flat_map(|ns| {
            std::fs::read_dir(ns)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .collect::<Vec<_>>()
        })
        .filter(|p| p.is_dir())
        .count();
    assert!(
        retained > 0,
        "--keep-runs must preserve the completed run dir under {}.\nstderr:\n{}",
        sweep_root.display(),
        outcome.stderr()
    );
}
