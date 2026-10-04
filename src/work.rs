//! `work <hire>`: run ONE capacity-1 worker for a hired profile — the Rust
//! counterpart of the Node plugin's `c8 nano work <profile>`.
//!
//! The hire (agent command, protocol, rank, capabilities, model, env) is read
//! from the c8ctl-nano `config.json`, exactly as `c8 nano hire` wrote it. The
//! worker polls the hire's rank×capability job-type matrix plus any explicit
//! `--job-type`, and runs each job through the same core as the daemon
//! ([`crate::slot`]), so the agent sees the same payload/env and the engine the
//! same completion variables as with the Node worker.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;

use crate::daemon::{short_hostname, validate, wait_for_signal};
use crate::engine::{self, JobApi};
use crate::runtime::log;
use crate::slot::{self, SlotConfig};
use crate::state;

/// sysexits.h `EX_CONFIG` — the Node plugin's `NANO_EXIT_CONFIG`: a
/// non-restartable configuration failure (unknown/invalid hire) that a
/// supervisor must not restart-loop.
pub const EXIT_CONFIG: i32 = 78;

/// Only the host sandbox is run; the disk floor gates container sandboxes only
/// (as in the Node plugin), so it is accepted and has no effect here.
pub struct WorkOptions {
    pub hire: String,
    pub job_types: Vec<String>,
    pub profile: Option<String>,
    pub job_api: JobApi,
    pub name: Option<String>,
    pub recovery_window: Duration,
    pub idle_timeout: Duration,
    pub poll_timeout: Duration,
    pub clone_timeout: Duration,
    pub runs_dir: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub max_jobs: Option<usize>,
    pub keep_runs: bool,
    pub min_free_mb: Option<u64>,
    pub reap_age: Duration,
    pub reap_interval: Duration,
}

/// Log a configuration error and exit with [`EXIT_CONFIG`].
fn config_exit(msg: &str) -> ! {
    log(msg);
    eprintln!("✗ {msg}");
    std::process::exit(EXIT_CONFIG);
}

pub async fn run(opts: WorkOptions) -> Result<()> {
    let config_path = match opts.config_path.clone() {
        Some(p) => p,
        None => state::config_file().unwrap_or_else(|| {
            config_exit("cannot locate the c8ctl-nano state home (set HOME or C8CTL_NANO_HOME)")
        }),
    };
    // A malformed or unreadable config.json is a non-restartable configuration
    // failure, exactly like an unknown hire or failed validation below, so it
    // must exit EX_CONFIG (78) via `config_exit` rather than bubbling `?` out
    // through `main` as a generic status-1 error — otherwise a supervisor would
    // restart-loop a permanently invalid hire configuration.
    let hires = match state::read_hires_from(&config_path) {
        Ok(hires) => hires,
        Err(e) => config_exit(&format!(
            "cannot read hire config {}: {e:#}",
            config_path.display()
        )),
    };
    let Some(hire) = hires.into_iter().find(|h| h.name == opts.hire) else {
        config_exit(&format!(
            "No hire named \"{}\". List profiles with: c8 nano hire --list",
            opts.hire
        ));
    };
    if let Err(reason) = validate(&hire) {
        config_exit(&format!("hire \"{}\" cannot run: {reason:#}", hire.name));
    }
    if let Some(mb) = opts.min_free_mb {
        log(&format!(
            "--min-free-mb {mb} applies to container sandboxes only; hire \"{}\" runs on the host",
            hire.name
        ));
    }

    let mut job_types = state::job_type_matrix(&hire.rank, &hire.capabilities);
    for t in &opts.job_types {
        if !job_types.contains(t) {
            job_types.push(t.clone());
        }
    }

    // Per-worker run namespace, unless `--runs-dir` overrides it. Both the
    // default (state home) and an explicit `--runs-dir` get a per-process
    // `rust-worker-<pid>` namespace so two worker processes never share one run
    // root: liveness is tracked only in-process (`slot::active_runs`), so a
    // shared root would let either worker's sweep treat the other's long-running
    // run dir as inactive and delete it once it ages past `--reap-age`.
    //
    // `anchor` is the TRUSTED base that may legitimately contain a PLATFORM
    // symlink (on macOS the system temp dir is `/var/folders/...` and `/var` is a
    // symlink to `/private/var`); everything at or below `anchor` is the
    // OPERATOR-CONTROLLED tail a same-UID attacker can plant a link in. For the
    // default path the anchor is the state home (or the temp-dir fallback); for
    // an explicit `--runs-dir` the whole path is operator-controlled, so the
    // anchor is the filesystem root and the entire path is validated no-follow.
    let (runs_dir, anchor) = match opts.runs_dir.clone() {
        Some(d) => (
            d.join(format!("rust-worker-{}", std::process::id())),
            PathBuf::from(std::path::Component::RootDir.as_os_str()),
        ),
        None => {
            let ns = format!("rust-worker-{}", std::process::id());
            match state::state_home() {
                // Normalize the environment-derived state home (`$C8CTL_NANO_HOME`
                // / `$HOME` / `$XDG_DATA_HOME`) BEFORE it becomes the anchor, so a
                // `.`/leading-`..` in those variables is resolved consistently
                // with an explicit `--runs-dir` (main::normalize_runs_dir) and a
                // stray `..` fails closed here with a clear error instead of
                // breaking every job's no-follow preparation on Linux.
                Some(h) => {
                    let h = crate::normalize_runs_dir(&h)?;
                    (h.join("agent-runs").join(&ns), h)
                }
                None => {
                    let t = crate::normalize_runs_dir(&std::env::temp_dir())?;
                    // Use the SAME `rust-worker-<pid>` namespace prefix as the
                    // normal paths: the shared-parent sweeper recognises only
                    // that prefix (`slot::namespace_owner_liveness`), so a
                    // distinctly named fallback would be skipped by every later
                    // sweep and a crashed worker's run tree would leak forever.
                    (t.join(format!("rust-worker-{}", std::process::id())), t)
                }
            }
        }
    };
    // Resolve the run root WITHOUT ever following a symlink in the
    // OPERATOR-CONTROLLED tail. Canonicalize ONLY the trusted `anchor` (resolving
    // its platform symlinks — the contract harness hands us a `C8CTL_NANO_HOME`
    // under macOS's `/var` -> `/private/var`, and the Rust worker matrix includes
    // `macos-latest`), then re-attach the tail (operator path + the predictable
    // `rust-worker-<pid>` leaf) LITERALLY onto the canonical anchor.
    //
    // Canonicalizing any part of the tail is a TOCTOU hole (issue: "symlink
    // replacement bypasses no-follow path validation"): between a no-follow check
    // and a later `canonicalize`, a same-UID process can swap a tail ancestor
    // (e.g. `--runs-dir /shared/link/runs` with `link` -> an attacker target, or
    // the predictable leaf) for a symlink; `canonicalize` then FOLLOWS the swap
    // and the no-follow checks afterwards inspect only the real target and pass,
    // redirecting both the workspace and the recursive stale-run sweep. Because
    // the tail is never canonicalized here, the no-follow checks below always run
    // on the literal intended path and REJECT a planted/swapped link instead of
    // following it.
    let canon_anchor = slot::canonicalize_existing_base(&anchor)?;
    let runs_dir = match runs_dir.strip_prefix(&anchor) {
        Ok(tail) => canon_anchor.join(tail),
        Err(_) => runs_dir,
    };
    // Establish the runs root through pinned no-follow handles on Linux 5.6+
    // (path-based reject+create+recheck fallback elsewhere). An inline
    // `reject_symlinked_ancestors_below` → `create_dir_all` → recheck here was a
    // check-then-create TOCTOU: a same-UID actor could swap a tail ancestor for
    // a symlink during the create and restore it before the recheck, redirecting
    // the created tree — and the recursive stale-run sweep below — outside the
    // workspace. `create_runs_root` builds every component relative to a pinned
    // parent, so a swapped/planted symlink is refused by the open, not followed.
    slot::create_runs_root(&runs_dir, &canon_anchor)?;
    // Sweep at the SHARED parent of this worker's namespace, not the namespace
    // itself: a crashed worker leaves `rust-worker-<old-pid>` as a sibling of
    // the next launch's root, so sweeping only `runs_dir` could never discover
    // it and repeated crashes would leak run trees despite `--reap-age`. The
    // sweep recurses one level (worker namespaces, then their run dirs),
    // honours cross-process namespace liveness, and skips any in-flight run
    // registered in `active_runs`. For BOTH the default and an explicit
    // `--runs-dir` the shared parent holds per-process namespaces, so sweep it
    // with namespace recursion — an explicit dir is now namespaced exactly like
    // the default, so two workers pointed at the same `--runs-dir` sweep the
    // shared parent but never touch each other's live namespace.
    let sweep_root = runs_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| runs_dir.clone());
    // Startup reap, then on a cadence: run dirs older than `--reap-age`. Both
    // sweeps are skipped under `--keep-runs`: that flag promises retained runs
    // are kept, so the age-based reaper must not delete them at startup or on
    // the cadence (the per-completion cleanup and the per-job execute-start
    // reap in `slot.rs` are gated on the same flag). Each sweep is a recursive
    // filesystem removal, so it is dispatched to the blocking pool rather than
    // run inline on a Tokio worker thread: a large stale checkout removed on a
    // worker thread can block the executor long enough to starve the lease
    // refresher (especially on a single-core host) and lose an active job's
    // lease.
    if !opts.keep_runs {
        slot::sweep_stale_runs_blocking(sweep_root.clone(), opts.reap_age, true).await;
    }
    let reaper = {
        let dir = sweep_root.clone();
        let (age, every, keep) = (
            opts.reap_age,
            opts.reap_interval.max(Duration::from_millis(100)),
            opts.keep_runs,
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if !keep {
                    slot::sweep_stale_runs_blocking(dir.clone(), age, true).await;
                }
            }
        })
    };

    let (_profile, jobs) = engine::connect(opts.profile.as_deref(), opts.job_api)?;
    let worker_name = opts.name.clone().unwrap_or_else(|| {
        // Node parity: the default worker name must be unique per `work`
        // PROCESS, not per (host, hire) — otherwise two concurrent workers on
        // the same hire share a name, defeating per-process isolation and making
        // broker ownership/logs ambiguous. Suffix the PID so same-profile workers
        // stay distinct.
        format!(
            "{}-nano-{}-{}",
            short_hostname(),
            hire.name,
            std::process::id()
        )
    });
    log(&format!(
        "worker {worker_name} for hire \"{}\" [{}] over job types {job_types:?}",
        hire.name, hire.rank
    ));
    let cfg = Arc::new(SlotConfig {
        hire,
        worker_name,
        job_types,
        recovery_window: opts.recovery_window,
        idle_timeout: opts.idle_timeout,
        poll_timeout: opts.poll_timeout,
        clone_timeout: opts.clone_timeout,
        runs_dir: runs_dir.clone(),
        with_lease: true,
        require_lease: false,
        max_jobs: opts.max_jobs,
        propagate_job_panic: true,
        keep_runs: opts.keep_runs,
    });
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut slot_task = tokio::spawn(slot::run(jobs, cfg, shutdown_rx, shutdown_tx.clone()));
    // The slot's `JoinHandle` resolves to `Result<(), JoinError>`: `Ok(())` on a
    // clean return, `Err` on a PANIC/abort. That error must NOT be discarded —
    // a panicked worker loop that `work` then reports as exit 0 tells the
    // supervisor the worker stopped cleanly when it actually crashed, so the
    // daemon never restarts it and the failure is invisible. Capture the join
    // outcome and propagate any error as a non-zero exit (below).
    let slot_result: std::result::Result<(), tokio::task::JoinError>;
    tokio::select! {
        r = &mut slot_task => {
            slot_result = r;
        }
        _ = wait_for_signal(&shutdown_tx) => {
            log("shutdown signal received; draining…");
            let _ = shutdown_tx.send(true);
            // A graceful drain that ends in a slot panic is still a crash —
            // surface it rather than reporting a clean shutdown. On timeout the
            // slot is STILL RUNNING: `timeout` only cancels the join *wait*, and
            // dropping the `JoinHandle` would detach the live task, so cleanup
            // (the namespace teardown below) could race a worker that is still
            // writing run dirs, and `work::run` would return while its worker
            // runs on. Abort the task and then JOIN it, so the handle is awaited
            // to completion and no slot outlives this function. The abort join
            // error is expected (we cancelled it), not a crash, so map it to
            // `Ok(())` rather than propagating it as a worker failure.
            slot_result = match tokio::time::timeout(Duration::from_secs(20), &mut slot_task).await
            {
                Ok(r) => r,
                Err(_) => {
                    log("slot did not drain within 20s of shutdown; aborting it");
                    slot_task.abort();
                    match slot_task.await {
                        // Aborted as requested: the task is finished, not running.
                        Err(e) if e.is_cancelled() => Ok(()),
                        // It completed (or panicked) just as we aborted: keep the
                        // real outcome so a panic still surfaces as a crash.
                        other => other,
                    }
                }
            };
        }
    }
    reaper.abort();
    // Drop this worker's namespace on a clean exit, unless `--keep-runs`. Only
    // remove it when EMPTY: `execute` intentionally retains failed run dirs for
    // post-mortem and age-based reaping, so a recursive delete here would erase
    // those diagnostics. An empty namespace means every run was reaped on
    // completion, so removing it just cleans up the per-worker dir. This applies
    // to an explicit `--runs-dir` too: it is now a per-process namespace, so the
    // empty dir removed here is this worker's own, never the shared parent.
    if !opts.keep_runs {
        match std::fs::remove_dir(&runs_dir) {
            Ok(()) => {}
            // NotEmpty: retained failed runs survive for post-mortem/reaping.
            // NotFound: already gone. Anything else is best-effort cleanup.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(e) => log(&format!(
                "could not remove worker namespace {}: {e:#}",
                runs_dir.display()
            )),
        }
    }
    // Propagate a slot crash AFTER cleanup so the run-dir teardown above still
    // runs, but the process exits non-zero: a panicked worker loop must surface
    // as a failure, not a clean exit 0 that a supervisor reads as intentional.
    if let Err(e) = slot_result {
        return Err(anyhow::anyhow!("worker slot task failed: {e}"));
    }
    Ok(())
}
