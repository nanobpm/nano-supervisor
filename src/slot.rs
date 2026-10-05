//! A worker slot: one capacity-1 worker that services a hire's whole
//! rank×capability job-type matrix, one job at a time — the job core shared by
//! `daemon` (N slots) and `work` (one slot), mirroring the Node plugin's worker.
//!
//! A slot is a single tokio task that round-robins its job types (so capacity is
//! naturally one — while it runs an agent it polls nothing). It uses leased
//! activation + lease-refresh fencing ([`crate::jobs`],
//! [`crate::runtime::refresh_loop`]) and handles each job: payload assembly,
//! repo clone, ACP/pipe execution, the re-emit nudge, and result settlement.
//!
//! The per-job execution runs on its own spawned task so a panic in one slot
//! fails only that job — the slot loop catches the join error, fails the job
//! (preserving retries), and carries on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use camunda_orchestration_sdk::models::ActivatedJobResult;
use serde_json::{json, Map, Value};
use tokio::sync::watch;

use crate::acp::Agent;
use crate::envelope::{self, Envelope};
use crate::jobs::{Job, Jobs};
use crate::result;
use crate::runtime::{log, refresh_loop};
use crate::state::{Hire, Protocol};

/// Per-type long-poll cap when a slot round-robins several job types.
const MULTI_TYPE_POLL_CAP: Duration = Duration::from_secs(1);

/// Everything a slot needs, shared (via `Arc`) across its per-job tasks.
#[derive(Debug, Clone)]
pub struct SlotConfig {
    pub hire: Hire,
    /// The worker name reported to the engine — distinct from the Node
    /// supervisor's so the daemon's jobs can be told apart.
    pub worker_name: String,
    /// The hire's job-type matrix, polled round-robin.
    pub job_types: Vec<String>,
    pub recovery_window: Duration,
    pub idle_timeout: Duration,
    pub poll_timeout: Duration,
    pub clone_timeout: Duration,
    pub runs_dir: PathBuf,
    /// Ask the engine for a lease on each activation.
    pub with_lease: bool,
    /// Refuse to run unfenced: an unleased activation shuts the process down
    /// (the daemon leases by default; opt out with `--no-lease`). `work`
    /// requests leases but, like the Node plugin, runs unfenced when the engine
    /// does not issue one.
    pub require_lease: bool,
    /// Stop after handling this many jobs (`work --max-jobs`); `None` = forever.
    pub max_jobs: Option<usize>,
    /// Propagate a per-job task PANIC as a slot crash instead of logging it and
    /// carrying on. `true` for standalone `work` (a swallowed panic would let
    /// the slot return `Ok(())` and the process exit 0, telling the supervisor
    /// the worker stopped cleanly when it crashed); `false` for the `daemon`,
    /// whose explicit policy is that one panicked job fails only that job.
    pub propagate_job_panic: bool,
    /// Keep per-job run directories instead of reaping them (`--keep-runs`).
    pub keep_runs: bool,
}

/// Run the slot until `shutdown` is set. Never returns an error — a slot is
/// resilient, logging and retrying transient failures — so one wedged engine
/// can't take the daemon down.
pub async fn run(
    jobs: Jobs,
    cfg: Arc<SlotConfig>,
    mut shutdown: watch::Receiver<bool>,
    fatal: watch::Sender<bool>,
) {
    log(&format!(
        "slot {} up: types {:?} (recovery {}s, poll {}s, idle {}s, lease {}, protocol {:?})",
        cfg.worker_name,
        cfg.job_types,
        cfg.recovery_window.as_secs(),
        cfg.poll_timeout.as_secs(),
        cfg.idle_timeout.as_secs(),
        if cfg.with_lease { "on" } else { "off" },
        cfg.hire.protocol,
    ));
    let mut next = 0usize;
    let mut handled = 0usize;
    // Consecutive activation failures, for the reconnect backoff below. Reset by
    // any successful activation (even an empty batch — reaching the engine at
    // all means the connection is healthy again).
    let mut activation_failures = 0u32;
    loop {
        if cfg.max_jobs.is_some_and(|max| handled >= max) {
            log(&format!(
                "slot {} handled {handled} job(s) (--max-jobs); stopping",
                cfg.worker_name
            ));
            return;
        }
        if *shutdown.borrow() {
            log(&format!("slot {} draining", cfg.worker_name));
            return;
        }
        let job_type = &cfg.job_types[next % cfg.job_types.len()];
        next = next.wrapping_add(1);
        // One long-poll per type, round-robin: with several types a full-length
        // poll on an idle type would hold a waiting job on another type for the
        // whole window, so cap each poll to keep pickup latency ~one cycle.
        let poll = if cfg.job_types.len() > 1 {
            cfg.poll_timeout.min(MULTI_TYPE_POLL_CAP)
        } else {
            cfg.poll_timeout
        };

        let batch = tokio::select! {
            // Bias the drain watch ahead of activation: if SIGTERM makes
            // `shutdown` ready in the same tick an activation response arrives,
            // the shutdown arm must win so the slot does not lease/start newly
            // returned work while draining was requested.
            biased;
            _ = shutdown.changed() => continue,
            b = jobs.activate(job_type, &cfg.worker_name, cfg.recovery_window, poll, cfg.with_lease) => b,
        };
        let batch = match batch {
            Ok(b) => b,
            Err(e) => {
                activation_failures = activation_failures.saturating_add(1);
                // Bounded exponential backoff with equal jitter, interruptible by
                // the drain watch. A fixed 5s retry let a fleet of idle slots
                // hammer an unreachable gateway — each attempt opening fresh TCP
                // connections the kernel then holds in `TIME_WAIT` — until the
                // host's ephemeral port range was exhausted and the gateway (and
                // every other local client) became unreachable
                // (nanobpm/nano-supervisor#23). The backoff bounds each slot to
                // ~one reconnect attempt per 30s at the ceiling, and the equal
                // jitter's nonzero `cap/2` floor spreads a fleet's retries so a
                // recovering gateway is not hit by every slot in the same tick.
                // The engine is still polled promptly once it answers: the
                // streak resets on the first successful activation.
                let wait = crate::runtime::activation_backoff(activation_failures);
                log(&format!(
                    "slot {} activation of {job_type:?} failed ({activation_failures} in a row): {e:#}; retrying in {:.1}s",
                    cfg.worker_name,
                    wait.as_secs_f64()
                ));
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => continue,
                    _ = tokio::time::sleep(wait) => {}
                }
                continue;
            }
        };
        activation_failures = 0;
        // Re-check the drain watch before touching the returned batch: `select!`
        // resolves the activation the instant it is ready, but a SIGTERM may have
        // set `shutdown` while `activate` was in flight. Starting these jobs now
        // would lease/run work after draining was requested, so drop the batch
        // (the activations simply expire and are redelivered) and stop the slot.
        if *shutdown.borrow() {
            log(&format!("slot {} draining", cfg.worker_name));
            return;
        }
        for job in batch {
            if cfg.require_lease && job.lease.is_none() {
                // Leasing is on by default (opt out with `--no-lease`); its
                // contract is to fail LOUDLY when the engine does not issue
                // leases. Merely skipping would leave the activation to expire
                // and be re-delivered forever — a silent spin that never fences.
                // If the engine returns an unleased activation here it will do so
                // for every job, so the requested fencing is impossible: shut the
                // whole daemon down loudly instead of running on unfenced.
                log(&format!(
                    "slot {}: job {} activated without a lease token while leasing is enabled (the \
                     default; opt out with --no-lease); the engine is not issuing leases, so the \
                     requested fencing is impossible — shutting the daemon down instead of running \
                     unfenced",
                    cfg.worker_name,
                    job.job.job_key.value()
                ));
                let _ = fatal.send(true);
                return;
            }
            // Run the job on its own task and ABORT it (not detach) when the slot
            // is asked to drain. Awaiting `handle` directly would let a drain
            // timeout that aborts the OUTER slot task drop `handle` mid-await —
            // detaching its inner `execute`/agent, which could keep writing under
            // `runs_dir` after `work::run` tears the namespace down and returns.
            // Aborting this task drops `handle`, whose inner `execute` handle is
            // wrapped in `AbortOnDrop` so that drop aborts (never detaches) it;
            // the execute child processes are `kill_on_drop`, so the whole per-job
            // tree is torn down and no job outlives the slot.
            let mut job_task = tokio::spawn(handle(jobs.clone(), cfg.clone(), job));
            tokio::select! {
                // Bias the drain watch: if SIGTERM lands in the same tick the job
                // finishes, draining wins and the job task is aborted below.
                biased;
                _ = shutdown.changed() => {
                    log(&format!(
                        "slot {} draining; aborting in-flight job",
                        cfg.worker_name
                    ));
                    job_task.abort();
                    // Join the aborted task so the execute/agent is fully torn
                    // down before the slot returns (the abort error is expected).
                    let _ = job_task.await;
                    return;
                }
                r = &mut job_task => {
                    // Surface a panic in the job task rather than swallowing it.
                    // In standalone `work` mode a swallowed panic would let the
                    // slot return `Ok(())` and the process exit 0 — the
                    // supervisor-visible clean-exit failure `work::run`'s join
                    // propagation exists to prevent — so re-raise it to crash the
                    // slot task (its `JoinHandle` carries the panic up to
                    // `work::run`, which exits non-zero). A cancellation (drain
                    // abort) is never a crash, and the daemon keeps its explicit
                    // per-job resilience policy (log and carry on).
                    if job_panic_is_fatal(&r, cfg.propagate_job_panic) {
                        log(&format!(
                            "slot {} job task panicked; propagating as a worker crash",
                            cfg.worker_name
                        ));
                        std::panic::resume_unwind(r.unwrap_err().into_panic());
                    }
                    if let Err(e) = r {
                        if !e.is_cancelled() {
                            log(&format!("slot {} job task failed: {e:#}", cfg.worker_name));
                        }
                    }
                }
            }
            handled += 1;
        }
    }
}

/// Whether a finished per-job task's join outcome must crash the slot (so a
/// standalone `work` process exits non-zero) rather than being logged and
/// skipped. Only a PANIC in standalone work mode (`propagate == true`) is
/// fatal: a cancellation (drain abort) never is, a clean completion never is,
/// and the daemon (`propagate == false`) always keeps its job-level resilience.
/// Pure/testable; the caller re-raises the panic when this returns `true`.
fn job_panic_is_fatal(r: &Result<(), tokio::task::JoinError>, propagate: bool) -> bool {
    matches!(r, Err(e) if propagate && e.is_panic())
}

/// Reconcile the join outcome of the inner `execute` task into the job's settle
/// result.
///
/// `handle` runs `execute` on its OWN spawned task (so a drain/loss can abort it
/// without killing the slot loop). That extra task is a second place a per-job
/// PANIC can hide: a panic surfaces here as `Err(JoinError)` on the *inner*
/// handle, NOT as a panic of the `handle` task the slot loop's
/// `job_panic_is_fatal` check guards. Downgrading it to a plain `anyhow::Error`
/// (the old behaviour) let a standalone `work` process fail only the job and
/// still exit 0 — the exact swallowed-crash the `propagate_job_panic` flag
/// exists to prevent. So in standalone mode (`propagate == true`) re-raise a
/// panic here, which panics the `handle` task; the slot loop then re-raises it
/// again up to `work::run`'s join handle for a non-zero exit. The daemon
/// (`propagate == false`) keeps its job-level resilience: the panic is
/// downgraded to a failed job and the slot loop carries on. A cancellation is
/// never a panic (`is_panic()` gates the re-raise), so a drain abort still
/// downgrades cleanly.
fn reconcile_exec_join<T>(
    key: &str,
    r: std::result::Result<Result<T>, tokio::task::JoinError>,
    propagate: bool,
) -> Result<T> {
    match r {
        Ok(inner) => inner,
        Err(join) => {
            if propagate && join.is_panic() {
                log(&format!(
                    "slot job {key} task panicked; propagating as a worker crash"
                ));
                std::panic::resume_unwind(join.into_panic());
            }
            Err(anyhow::anyhow!("slot task for job {key} panicked: {join}"))
        }
    }
}

/// Decide whether a raced job outcome is still ours to settle.
///
/// [`handle`] races job execution against activation loss with `select!`. That
/// macro can pick the completed-`exec` branch (`Some(..)`) even when the
/// refresher set the loss watch to `true` in the same tick, so the raw outcome
/// must be downgraded to "lost" (`None`) whenever the activation was fenced —
/// otherwise a job would be `complete`/`fail`ed with a stale lease after a
/// 404/409. Keyed only on the post-select watch value, so it is pure/testable.
fn reconcile_lost<T>(outcome: Option<T>, lost: bool) -> Option<T> {
    if lost {
        None
    } else {
        outcome
    }
}

/// A spawned task's [`JoinHandle`](tokio::task::JoinHandle) that **aborts** its
/// task when dropped, instead of tokio's default of *detaching* it.
///
/// [`handle`] spawns the per-job `execute` task and is itself spawned by the
/// slot loop ([`run`]), which `abort()`s the `handle` task when the slot drains
/// (or when a drain timeout aborts the whole slot mid-await). Aborting `handle`
/// drops its in-flight locals — including the inner `execute` handle. A bare
/// `JoinHandle` drop would **detach** `execute`, leaving the agent running and
/// still writing under `runs_dir` after `work::run` tore the namespace down and
/// returned. Wrapping it so drop aborts the task guarantees the whole per-job
/// tree (whose child processes are `kill_on_drop`) is torn down with the slot —
/// no job outlives it. The explicit abort on the activation-loss path still
/// works through `.0`; a second abort from this drop on an already-finished or
/// already-aborted task is a harmless no-op.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn handle(
    jobs: Jobs,
    cfg: Arc<SlotConfig>,
    Job {
        job,
        lease,
        dispatched_at,
    }: Job,
) {
    let key = job.job_key.value().to_string();
    // The lease was started by the engine at dispatch; `dispatched_at` (derived
    // in `Jobs::activate` from the engine's `deadline`) is the conservative
    // lower bound we thread into the refresher. A separate `Instant::now()` here
    // would be LATER than dispatch by the response-transit + spawn gap, so it
    // would over-grant the first window — the exact overrun the reviewer flagged.
    let started = dispatched_at;
    // Validate the engine-supplied key BEFORE it is used to build any request
    // path. The refresher below (`extend`) and the `complete`/`fail` settle all
    // interpolate it into `/jobs/{key}` on the Nano backend, so a malformed key
    // must be rejected up front — and an activation we cannot even address must
    // not be settled. Drop it and let the engine redeliver.
    if let Err(e) = crate::jobs::validate_job_key(&key) {
        log(&format!(
            "job {key}: refusing malformed engine key ({e:#}); not spawning refresher and not settling"
        ));
        return;
    }
    log(&format!(
        "job {key} activated on {} (type {}, retries {}, lease {})",
        cfg.worker_name,
        job.r#type,
        job.retries,
        lease.as_deref().unwrap_or("none")
    ));

    // Keep the activation alive while the agent works; a 404/409 fences us out.
    let refreshes = Arc::new(AtomicUsize::new(0));
    let (lost_tx, mut lost_rx) = watch::channel(false);
    let (stop_tx, stop_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_loop(
        jobs.clone(),
        key.clone(),
        lease.clone(),
        cfg.recovery_window,
        // Base the refresher's initial lease deadline on `started` (=
        // `dispatched_at`, derived in `Jobs::activate` from the engine's
        // `deadline` — before validation/logging/spawn) rather than an
        // `Instant::now()` taken inside the loop: the lease began at dispatch,
        // so the earlier timestamp avoids over-granting the first window by the
        // response-transit + validation/logging/spawn gap.
        started,
        refreshes.clone(),
        lost_tx,
        stop_rx,
    ));

    // Run the job on its own task so a panic fails only THIS job (the slot loop
    // survives). Race it against activation loss so a superseded worker stops.
    // `handle` is itself spawned by `run` (below) and aborted when the slot
    // drains; the `AbortOnDrop` wrapper makes that cancellation abort this inner
    // task too — never detach it (see `run`). Returning here (rather than
    // aborting) leaves the task running so the slot can settle the job; only a
    // drain/loss aborts it.
    let mut exec = AbortOnDrop(tokio::spawn(execute(cfg.clone(), key.clone(), job.clone())));
    let raced = tokio::select! {
        r = &mut exec.0 => Some(reconcile_exec_join(&key, r, cfg.propagate_job_panic)),
        // Drop the watch guard immediately; the abort/await happens below.
        _ = lost_rx.wait_for(|lost| *lost) => None,
    };
    // Pre-settlement fence check. `select!` can pick the `exec` branch even when
    // the refresher set `lost` to true in the same tick (both futures ready), so
    // re-check the watch before settling. The refresher is NOT stopped yet: a
    // `complete`/`fail` request can take up to 30s while the recovery window may
    // be ~1s, so stopping here would let the activation expire mid-settlement and
    // fence the very request that settles the job. The refresher keeps the
    // activation alive through settlement and is stopped only after it returns.
    let outcome = reconcile_lost(raced, *lost_rx.borrow());
    if outcome.is_none() {
        // We lost the activation: actually stop the agent instead of detaching
        // the task. Aborting drops the execute future, whose child processes are
        // spawned `kill_on_drop`, so the clone/agent tree is torn down before we
        // return.
        exec.0.abort();
        let _ = (&mut exec.0).await;
    }
    let elapsed = started.elapsed().as_secs_f32();
    let n = refreshes.load(Ordering::Relaxed);

    match outcome {
        None => log(&format!(
            "job {key}: activation lost after {elapsed:.1}s; agent stopped, job NOT settled (the engine will redeliver it)"
        )),
        Some(Ok(Settle::Complete(vars))) => {
            // Keep the refresher alive through the completion request so the
            // activation cannot expire while `complete` is in flight.
            let result = jobs.complete(&key, vars, &lease).await;
            stop_refresher(stop_tx, refresher).await;
            match result {
                Ok(()) => log(&format!(
                    "job {key} completed in {elapsed:.1}s (refreshes={n})"
                )),
                Err(e) => log(&format!("job {key}: complete failed: {e:#}")),
            }
        }
        Some(outcome) => {
            let (msg, vars) = match outcome {
                Ok(Settle::Fail { message, vars }) => (message, vars),
                // An infrastructure error (provisioning, run-dir setup, a
                // panic) before the agent could run.
                Err(e) => (format!("agent \"{}\" failed: {e:#}", cfg.hire.name), None),
                Ok(Settle::Complete(_)) => unreachable!("handled above"),
            };
            let retries = (job.retries - 1).max(0);
            let msg = truncate(&msg, 2000);
            // Keep the refresher alive through the failure request so the
            // activation cannot expire while `fail` is in flight.
            let result = jobs.fail(&key, retries, &msg, vars, &lease).await;
            stop_refresher(stop_tx, refresher).await;
            match result {
                Ok(()) => log(&format!(
                    "job {key} failed after {elapsed:.1}s (refreshes={n}, retries left {retries}): {msg}"
                )),
                Err(e2) => log(&format!(
                    "job {key}: fail failed: {e2:#} (original error: {msg})"
                )),
            }
        }
    }
}

/// Stop the lease refresher and wait for it to fully exit. Signal a graceful
/// stop and AWAIT the task — never `abort()`: aborting could cancel an in-flight
/// `extend`, dropping the very request that would report a 404/409 fence. A
/// graceful stop lets any in-flight extend run to completion first; once the
/// task is joined no further writes to the loss watch can happen.
async fn stop_refresher(stop_tx: watch::Sender<bool>, refresher: tokio::task::JoinHandle<()>) {
    let _ = stop_tx.send(true);
    let _ = refresher.await;
}

/// Restrict a directory to owner-only access (mode 0700) on Unix, so job data
/// placed under the shared temp directory is not readable/traversable by other
/// local users. A no-op when the path is absent. Used only by the non-Unix
/// path-based prepare fallback (Unix preparation chmods through the pinned fd
/// instead); kept non-Unix-only so a Unix build has no dead code.
#[cfg(not(unix))]
fn restrict_dir_mode(dir: &Path) -> Result<()> {
    let _ = dir;
    Ok(())
}

/// Bail when `dir` (or the runs root above it) is a symlink. The check/remove/
/// create sequence in [`execute`] is not atomic: another local process can swap
/// a numeric job dir — or the runs root — for a symlink between operations, so
/// the agent cwd and `restrict_dir_mode` would otherwise target a path outside
/// `runs_dir`. `symlink_metadata` inspects the link itself rather than
/// following it, so a dangling or replaced link is still caught.
///
/// On Unix the pinned prepare/sweep paths refuse a symlink atomically at the
/// no-follow open instead, so this path-based check is only reached by the
/// non-Unix fallback (and the tests exercising the rejection).
#[cfg(any(not(unix), test))]
pub(crate) fn reject_symlink(dir: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!(
            "refusing to use symlinked path {} (possible local symlink attack)",
            dir.display()
        );
    }
    Ok(())
}

/// Bail when any *existing ancestor* of `dir` is a symlink. [`reject_symlink`]
/// only inspects the leaf `runs_dir` / `run_dir`, but `create_dir_all` follows a
/// symlinked ancestor: if a configurable `--runs-dir` (or an `$XDG_STATE_HOME`
/// state root) is missing under a world-writable parent, another local user can
/// pre-create a symlinked ancestor so the job directory is materialised outside
/// the intended root — and the leaf check cannot see it, because the final path
/// is then a real directory at the redirected location. Walking every existing
/// ancestor and rejecting the first symlink refuses that redirection before we
/// create or touch job data. A non-existent ancestor (`symlink_metadata` errors)
/// is skipped: `create_dir_all` will materialise it as a fresh real directory,
/// not follow a link. Paired with the leaf [`reject_symlink`] and re-run after
/// the non-atomic create, this closes the whole chain to symlink redirection.
///
/// On Unix the runs root is now materialised no-follow component-by-component
/// ([`crate::saferoot::DirHandle::open_or_create_root_nofollow`]), so this
/// path-based whole-chain check is only reached by the non-Unix fallback (and
/// the tests exercising the rejection) — exactly like [`reject_symlink`].
#[cfg(any(not(unix), test))]
pub(crate) fn reject_symlinked_ancestors(dir: &Path) -> Result<()> {
    for ancestor in dir.ancestors() {
        if std::fs::symlink_metadata(ancestor)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            bail!(
                "refusing to use {}: ancestor {} is a symlink (possible local symlink attack)",
                dir.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

/// Bail when any component of `dir` strictly *below* `anchor` is a symlink,
/// leaving the anchor itself and its own ancestors unchecked (the anchor is
/// trusted: on macOS the system temp base contains the platform symlink `/var` →
/// `/private/var`). [`reject_symlinked_ancestors`] walks the whole chain to the
/// filesystem root, which would reject that legitimate platform link. When the
/// trusted base is known, the operator-controlled tail beneath it is the part a
/// same-UID attacker can plant a link in — so validate exactly that tail
/// no-follow, on the ORIGINAL (pre-canonicalization) path, before
/// [`canonicalize_existing_base`] resolves the trusted anchor's platform links.
/// `anchor` must be an ancestor of `dir` (or equal to it); components at or
/// above `anchor` are trusted and skipped. A non-existent component is skipped:
/// `create_dir_all` materialises it as a fresh real directory, not a link.
/// Only the non-Unix fallback (and the tests exercising the rejection) use this
/// now: on Unix the worker-namespace bootstrap materialises the root via the
/// component-wise pinned `open_or_create_root_nofollow` instead, which closes
/// the check→create race rather than merely re-checking after it.
#[cfg(any(not(unix), test))]
pub(crate) fn reject_symlinked_ancestors_below(dir: &Path, anchor: &Path) -> Result<()> {
    // Walk dir's ancestors from the leaf up to (but not past) `anchor`, stopping
    // before the anchor's own (trusted) ancestors. The anchor itself is trusted:
    // break at it WITHOUT inspecting its own type, so a platform symlink in the
    // anchor (macOS `/var`) is not rejected.
    for ancestor in dir.ancestors() {
        if ancestor == anchor {
            break;
        }
        if std::fs::symlink_metadata(ancestor)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            bail!(
                "refusing to use {}: component {} is a symlink (possible local symlink attack)",
                dir.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

/// Canonicalize only the *existing* prefix of `dir`, leaving any not-yet-created
/// trailing components unresolved. This resolves PLATFORM symlinks in a trusted
/// base (macOS `/var` → `/private/var`, where the system temp dir lives) so the
/// no-follow [`reject_symlink`] / [`reject_symlinked_ancestors`] checks do not
/// reject a legitimate temp root — while a USER-planted symlink in the
/// not-yet-created tail (e.g. the worker's own `rust-worker-<pid>` leaf) is left
/// unresolved and so still rejected by those checks. A symlinked ancestor of the
/// existing base is resolved here (the base is trusted), but a symlinked
/// ancestor of the *canonical* base is still caught by the re-validation.
pub(crate) fn canonicalize_existing_base(dir: &Path) -> Result<PathBuf> {
    // Collect the leading components that already exist on disk.
    let mut existing = PathBuf::new();
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut split = false;
    for comp in dir.components() {
        if split {
            rest.push(comp.as_os_str());
            continue;
        }
        let mut candidate = existing.clone();
        candidate.push(comp.as_os_str());
        if candidate.exists() {
            existing = candidate;
        } else {
            // First component that does not (yet) exist: everything from here on
            // is the unresolved tail.
            split = true;
            rest.push(comp.as_os_str());
        }
    }
    // Canonicalize the existing prefix (resolves platform symlinks), then
    // re-attach the unresolved tail. If nothing exists, fall back to the
    // current directory as the anchor.
    let base = if existing.as_os_str().is_empty() {
        std::env::current_dir().context("resolving current directory for run-dir base")?
    } else {
        std::fs::canonicalize(&existing)
            .with_context(|| format!("canonicalizing existing base {}", existing.display()))?
    };
    let mut out = base;
    for comp in rest {
        out.push(comp);
    }
    Ok(out)
}

/// The per-job run directory, prepared once and carried as a pinned, no-follow
/// capability: every later step that needs to *enter* or *name* the run dir
/// derives it from this handle (fd-relative `open_child` / fd-recovered
/// `path()`), never by re-resolving the path — so a same-UID actor swapping or
/// replacing a path component after preparation cannot redirect a launch or
/// the ACP session workspace outside the validated tree (#35).
pub(crate) struct PreparedRun {
    /// The pinned run directory (opened no-follow, held by fd).
    cwd: crate::safecwd::CwdHandle,
}

impl PreparedRun {
    /// The pinned run directory itself, for a job with no repository (the
    /// agent and the HEAD probe run in the run dir directly).
    pub(crate) fn agent_cwd(&self) -> &crate::safecwd::CwdHandle {
        &self.cwd
    }
}

/// Prepare a per-job run directory under `runs_dir` with the full symlink and
/// permission hardening, wiping any stale prior-attempt contents. Shared by the
/// `daemon` and `work` (both run jobs through [`execute`]) so every run gets
/// identical protection: reject a symlinked leaf / ancestor before *and* after
/// the non-atomic remove+create (a local process can swap the fresh dir for a
/// link in between), then restrict both the runs root and the job dir to 0700 so
/// the clone, prompt-derived files, and `result.json` are not readable by other
/// local users regardless of umask — this still matters when `runs_dir` falls
/// back to a shared system temp location.
pub(crate) fn prepare_run_dir(
    runs_dir: &Path,
    run_dir: &Path,
) -> Result<crate::safecwd::CwdHandle> {
    #[cfg(unix)]
    {
        prepare_run_dir_pinned(runs_dir, run_dir).map_err(|e| match e {
            crate::saferoot::PinError::Io(e) => {
                anyhow::Error::new(e).context(format!("preparing run dir {}", run_dir.display()))
            }
        })
    }
    #[cfg(not(unix))]
    {
        prepare_run_dir_path_based(runs_dir, run_dir)
    }
}

/// `prepare_run_dir` dispatched to the blocking pool. Preparing a run dir wipes
/// any stale prior-attempt checkout (a recursive removal); run inline on a Tokio
/// worker thread that can block the executor long enough to starve the lease
/// refresher (especially on a single-core host) and lose the very lease this job
/// is running under. Use this from async contexts; `prepare_run_dir` remains for
/// synchronous callers and tests.
pub(crate) async fn prepare_run_dir_blocking(
    runs_dir: PathBuf,
    run_dir: PathBuf,
) -> Result<crate::safecwd::CwdHandle> {
    // The wipe/create is synchronous; a panic in the blocking task surfaces as a
    // `JoinError`, which we treat as the prepare failing (the run dir state is
    // then unknown, so failing the job is the safe outcome).
    tokio::task::spawn_blocking(move || prepare_run_dir(&runs_dir, &run_dir))
        .await
        .map_err(|e| anyhow::Error::new(e).context("prepare_run_dir blocking task panicked"))?
}

/// `prepare_run_dir` via a no-follow handle pinned to the runs root: the
/// stale-wipe, create, and 0700 chmod of both the root and the job dir all
/// happen *relative to that pinned handle*, so a same-UID actor cannot swap
/// `runs_dir` (or an ancestor) for a symlink between a check and the operation
/// and redirect the remove/create outside the workspace — and the job-dir
/// handle preparation returns is the *exact* inode it wiped and secured, so the
/// launch never reopens `run_dir` by path (which a same-UID actor could have
/// replaced with an ordinary, unprepared tree in between). This is the atomic
/// fix the path-based `reject_symlink` re-checks can only approximate.
/// `run_dir` is always `<runs_dir>/<key>` (a single, engine-validated numeric
/// component), so its `file_name()` is the child directory to prepare.
#[cfg(unix)]
fn prepare_run_dir_pinned(
    runs_dir: &Path,
    run_dir: &Path,
) -> std::result::Result<crate::safecwd::CwdHandle, crate::saferoot::PinError> {
    use crate::saferoot::{DirHandle, PinError};
    let name = run_dir.file_name().ok_or_else(|| {
        PinError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("run dir {} has no final component", run_dir.display()),
        ))
    })?;
    // Bootstrap: the runs root must exist before it can be opened no-follow.
    // Materialise it by walking and creating each missing component RELATIVE to
    // its already-pinned parent (`open_or_create_root_nofollow`), never via a
    // path-based `create_dir_all`: a path-based create *follows* a symlinked
    // ancestor, so a same-UID actor swapping a writable ancestor for a symlink
    // between a no-follow check and the create could redirect the materialised
    // root into an attacker-chosen target — building the run dir outside the
    // workspace before the no-follow open ever ran. The component-wise
    // create+pin closes that window: each step is anchored on the previous
    // step's pinned inode, and an existing or swapped-in symlinked component is
    // refused by the no-follow open rather than followed.
    let root = DirHandle::open_or_create_root_nofollow(runs_dir, 0o700)?;
    let child = root.prepare_child_dir(name, 0o700).map_err(PinError::Io)?;
    // Carry the EXACT pinned child inode preparation just created and secured
    // into the launch — never reopen `run_dir` by path, which a same-UID actor
    // could have swapped for an ordinary (unwiped, unsecured) tree in between.
    Ok(crate::safecwd::CwdHandle::from_fd(child.into_fd()))
}

/// Path-based `prepare_run_dir`: the non-Unix fallback (no `openat`/`fchmod`
/// pinned-handle support — not a supported daemon host). Rejects a symlinked
/// leaf / ancestor before *and* after the non-atomic remove+create — a
/// best-effort approximation of the pinned-handle guarantee that cannot fully
/// close the TOCTOU window. Every Unix host uses the pinned
/// [`prepare_run_dir_pinned`] instead.
#[cfg(not(unix))]
fn prepare_run_dir_path_based(
    runs_dir: &Path,
    run_dir: &Path,
) -> Result<crate::safecwd::CwdHandle> {
    reject_symlink(runs_dir)?;
    reject_symlink(run_dir)?;
    reject_symlinked_ancestors(run_dir)?;
    if run_dir.exists() {
        std::fs::remove_dir_all(run_dir)
            .with_context(|| format!("clearing stale {}", run_dir.display()))?;
    }
    std::fs::create_dir_all(run_dir).with_context(|| format!("creating {}", run_dir.display()))?;
    reject_symlink(runs_dir)?;
    reject_symlink(run_dir)?;
    reject_symlinked_ancestors(run_dir)?;
    restrict_dir_mode(runs_dir)?;
    restrict_dir_mode(run_dir)?;
    // Pin the prepared dir no-follow and hand the handle back, so the caller
    // carries the validated inode into the launch rather than reopening the
    // path (this backend cannot pin atomically, but a leaf re-open right after
    // the final no-follow checks above is the closest this fallback gets).
    crate::safecwd::CwdHandle::open(run_dir)
        .with_context(|| format!("pinning prepared run dir {}", run_dir.display()))
}

/// Reap a completed run directory under `runs_dir` with the same pinned
/// no-follow guarantee as [`prepare_run_dir`]: the removal happens *relative to*
/// a no-follow pinned handle on the runs root, so a same-UID actor cannot swap
/// `run_dir` (or an ancestor) for a symlink between the job's completion and
/// this cleanup and redirect a path-based `remove_dir_all` into deleting an
/// unrelated tree outside the workspace. Falls back to a plain `remove_dir_all`
/// only on a non-Unix host (no pinned-handle support). `run_dir` is always
/// `<runs_dir>/<key>` (a single engine-validated component), so its
/// `file_name()` is the child to remove. A missing dir is treated as success.
pub(crate) fn reap_run_dir(runs_dir: &Path, run_dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use crate::saferoot::{DirHandle, PinError};
        if let Some(name) = run_dir.file_name() {
            match DirHandle::open_root_nofollow(runs_dir, false) {
                Ok(root) => return root.remove_tree(name),
                // A refused symlinked root (ELOOP) or any other error is a real,
                // security-relevant outcome — surface it, never retry the weaker
                // path-based remove that would follow the very link we refused.
                Err(PinError::Io(e)) => return Err(e),
            }
        }
    }
    #[cfg(not(unix))]
    let _ = runs_dir;
    match std::fs::remove_dir_all(run_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// `reap_run_dir` dispatched to the blocking pool. Reaping removes a job's whole
/// checkout (a recursive removal); run inline on a Tokio worker thread it can
/// block the executor long enough to starve the lease refresher (especially on a
/// single-core host) and lose the lease before `complete_job` lands, redelivering
/// the job. Use this from async contexts; `reap_run_dir` remains for synchronous
/// callers and tests. Best-effort like the caller: a panic in the blocking task
/// is logged and swallowed, never propagated.
pub(crate) async fn reap_run_dir_blocking(runs_dir: PathBuf, run_dir: PathBuf, key: &str) {
    let label = run_dir.clone();
    let outcome = tokio::task::spawn_blocking(move || reap_run_dir(&runs_dir, &run_dir)).await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log(&format!(
            "job {key}: failed to reap run dir {}: {e:#}",
            label.display()
        )),
        Err(join) => log(&format!(
            "job {key}: reap_run_dir blocking task panicked for {}: {join}",
            label.display()
        )),
    }
}

/// How long a *failed* run directory is retained under `runs_dir` for
/// post-mortem inspection before it is swept. Successful runs are reaped
/// immediately on completion (see [`execute`]); only failed runs — which bail
/// via `?` and are deliberately left in place — accumulate. On a long-lived
/// daemon that retention is otherwise unbounded, so leftover failed runs are
/// deleted once they age past this window (3 days).
pub(crate) const FAILED_RUN_RETENTION: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// Process-global set of run directories currently being serviced by a slot.
///
/// [`sweep_stale_runs`] reaps aged directories purely from their mtime, but an
/// in-flight agent can legitimately run *longer* than [`FAILED_RUN_RETENTION`]
/// without ever writing to its run dir (so its mtime ages out) — and a
/// *different* slot runs the sweep at the start of every job. Without this
/// guard, that concurrent sweep could delete a live checkout out from under a
/// still-running agent, corrupting its work or losing its result. Every slot
/// registers its run dir here for the duration of the job (see
/// [`ActiveRunGuard`]) and the sweep skips any registered path, so only genuinely
/// abandoned (failed, post-mortem) directories are ever removed.
///
/// Registrations are **reference-counted**: a job dir is keyed by job key and so
/// is reused across retries, and an old attempt's [`ActiveRunGuard`] can still be
/// dropping (its `execute` future unwinding) while the retry has already
/// registered the same path. A plain set would let that late drop unregister the
/// path out from under the live retry, re-exposing its checkout to the sweep. The
/// count keeps the path registered until the *last* overlapping guard drops.
fn active_runs() -> &'static Mutex<HashMap<PathBuf, usize>> {
    static ACTIVE: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// RAII registration of an in-flight run directory in [`active_runs`]. The dir
/// is protected from the sweep from construction until this guard drops, which
/// covers every exit path of [`execute`] — normal return, an early `?` bail, or
/// a panic — so a registration can never leak and permanently pin a dir.
struct ActiveRunGuard(PathBuf);

impl ActiveRunGuard {
    fn new(run_dir: &Path) -> Self {
        if let Ok(mut map) = active_runs().lock() {
            *map.entry(run_dir.to_path_buf()).or_insert(0) += 1;
        }
        ActiveRunGuard(run_dir.to_path_buf())
    }
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = active_runs().lock() {
            if let Some(count) = map.get_mut(&self.0) {
                *count -= 1;
                if *count == 0 {
                    map.remove(&self.0);
                }
            }
        }
    }
}

/// Per-run-dir **exclusive execution claims**.
///
/// The refcounted [`active_runs`] registry protects a run dir from the *sweep*,
/// but it deliberately permits *overlapping* registrations (a retry registers
/// while the superseded attempt's guard is still dropping). That is correct for
/// sweep-protection but is NOT workspace ownership: [`execute`] *wipes and
/// recreates* the run dir in [`prepare_run_dir`]. If a lease expires and the
/// engine redelivers the job to a second slot before the first observes the
/// fence, both attempts would otherwise mutate the same path — the retry's wipe
/// could delete the first agent's live checkout/`result.json`, and the retry's
/// fresh checkout could be polluted by the first agent's not-yet-killed writes
/// (or its `remove_dir_all`/`create_dir_all` could race those writes and fail).
///
/// This map hands each run dir a single async mutex, so [`RunClaim::acquire`]
/// gives exactly one attempt exclusive ownership of the workspace. A retry
/// `await`s the claim and only wipes/runs once the superseded attempt has fully
/// released it — which happens when that attempt's `execute` future drops, i.e.
/// after its abort has torn the process tree down (`kill_on_drop`). So no two
/// attempts ever own the workspace at once. The wait is bounded: the only way a
/// second attempt for a key exists is lease expiry, which fences and tears down
/// the first.
fn run_claims() -> &'static Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>> {
    static CLAIMS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// RAII exclusive claim on a run dir (see [`run_claims`]). Held for the whole
/// duration an attempt mutates its workspace; dropping it releases the claim and
/// prunes the map entry when no other attempt references it, so the claim table
/// cannot grow without bound across distinct job keys.
struct RunClaim {
    run_dir: PathBuf,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl RunClaim {
    async fn acquire(run_dir: &Path) -> RunClaim {
        // Clone-or-create the per-path lock under the brief std mutex, then await
        // exclusive ownership of it. Acquiring the inner lock is NOT done while
        // holding the std mutex, so a long-held claim never blocks claims on
        // other run dirs.
        let lock = {
            let mut map = run_claims()
                .lock()
                // The map is only ever touched for these brief, panic-free entry
                // ops, so poisoning is effectively impossible; recover the guard
                // rather than panic (matching `active_runs`' fail-safe style) so a
                // claim still enforces exclusivity even after unrelated poisoning.
                .unwrap_or_else(|e| e.into_inner());
            map.entry(run_dir.to_path_buf())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = lock.lock_owned().await;
        RunClaim {
            run_dir: run_dir.to_path_buf(),
            guard: Some(guard),
        }
    }
}

impl Drop for RunClaim {
    fn drop(&mut self) {
        // Release the lock FIRST so a waiter can proceed, then prune the map
        // entry if nothing else references it. `strong_count == 1` means only the
        // map holds the `Arc` (our owned guard — which also held a clone — is now
        // dropped and no other attempt is parked on or owns it), so it is safe to
        // remove. A concurrent `acquire` serialises on the same std mutex: if it
        // cloned the `Arc` first the count is >= 2 and we leave the entry for it
        // to prune later; if we remove first it simply inserts a fresh lock. Any
        // waiter that already owns the lock keeps it alive via its own clone.
        drop(self.guard.take());
        let mut map = run_claims().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lock) = map.get(&self.run_dir) {
            if Arc::strong_count(lock) == 1 {
                map.remove(&self.run_dir);
            }
        }
    }
}

/// Whether `path` is a currently in-flight run dir that must not be swept.
/// Only the tests probe this directly; the sweep itself uses the atomic
/// [`remove_if_inactive`] so the check and the removal stay one locked step.
#[cfg(test)]
fn is_active_run(path: &Path) -> bool {
    active_runs()
        .lock()
        .map(|map| map.contains_key(path))
        .unwrap_or(false)
}

/// Test-only seam for the check/remove TOCTOU regression test: when armed with a
/// `(path, closure)`, [`remove_if_inactive`] invokes the closure after the active
/// check has found that exact path inactive but BEFORE the removal runs, letting a
/// test land a registration in that window. `None` in every non-test build and
/// whenever no test has armed it, so production behaviour is unchanged. The hook
/// is PATH-SCOPED — it fires (and clears) only for the path it was armed with — so
/// unrelated sweeps running concurrently in other tests never trip it, and because
/// it is taken out of the slot BEFORE firing, a panicking test cannot leave the
/// hook armed for its neighbours.
#[cfg(test)]
type RemovePauseHook = Box<dyn FnOnce() + Send>;
#[cfg(test)]
static REMOVE_IF_INACTIVE_PAUSE: Mutex<Option<(std::path::PathBuf, RemovePauseHook)>> =
    Mutex::new(None);

/// Process-local monotonically increasing sequence folded into the per-activation
/// fallback-branch suffix (`nano/agent-work/<base>-<rand>-<pid>-<nanos>-<seq>`).
/// All slots share the worker PID and can observe the same wall-clock tick, so
/// the timestamp alone is not unique; this counter guarantees two activations in
/// one process never mint the same suffix. `Relaxed` ordering suffices — only the
/// fetch_add's atomicity/uniqueness matters, not any happens-before edge.
static ACTIVATION_SEQ: AtomicUsize = AtomicUsize::new(0);

/// A per-process random token folded into every fallback-branch suffix so the
/// suffix is unique ACROSS worker processes, not merely across slots in one
/// process. `pid`+`nanos`+`seq` is only process-local: two *separate* workers
/// can share a PID (PID 1 is common in containers), both start `ACTIVATION_SEQ`
/// at 0, and observe the same wall-clock tick — then they cut the identical
/// fallback ref and one activation's push is rejected non-fast-forward. The
/// fallback contract requires uniqueness per activation across the whole fleet,
/// so we mix in a token drawn once from the OS CSPRNG (matching the mirrored
/// worker's per-run UUID). Generated lazily and cached for the process's life.
fn process_rand_token() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let mut buf = [0u8; 8];
        // Prefer the OS CSPRNG. Never panic if it is unavailable — a weaker
        // token still beats cutting no branch at all, so fall back to stirring
        // together pid, a high-res timestamp, and a live stack address (ASLR).
        let have_os_entropy = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| {
                use std::io::Read;
                f.read_exact(&mut buf)
            })
            .is_ok();
        if !have_os_entropy {
            let seed = (std::process::id() as u128)
                ^ ((&buf as *const _ as usize) as u128)
                ^ std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
            buf = (seed as u64).to_le_bytes();
        }
        buf.iter().map(|b| format!("{b:02x}")).collect()
    })
}

/// Atomically check `path` against [`active_runs`] and, when it is not
/// registered, remove it — all while holding the active-runs mutex. This closes
/// the check/remove TOCTOU that a bare `is_active_run` + `remove_*` pair leaves
/// open: a retry's [`ActiveRunGuard::new`] registers the run dir under the same
/// mutex, so holding the lock across the check and the removal guarantees no
/// registration can slip in between and have its live workspace deleted out from
/// under it. `remove` performs the actual deletion (pinned `remove_tree` or the
/// path-based fallback); it runs with the lock held, so it must stay quick and
/// must not itself try to acquire [`active_runs`]. Returns `true` when the path
/// was inactive and the removal was attempted.
fn remove_if_inactive(path: &Path, remove: impl FnOnce()) -> bool {
    let map = match active_runs().lock() {
        Ok(m) => m,
        // A poisoned mutex means a panicking slot may still hold a registration;
        // fail closed (treat as active) rather than risk deleting a live run.
        Err(_) => return false,
    };
    if map.contains_key(path) {
        return false;
    }
    // Test-only: let the regression test park the sweep exactly here — after
    // the check, before the removal — so it can attempt a registration in the
    // window the atomic fix closes. A correct (locked) implementation blocks
    // that registration until the delete is decided; the pre-fix pair held no
    // lock here, so the registration landed and the live run was deleted. The
    // hook is PATH-SCOPED: it fires (and clears) only for the exact path the
    // test armed it with, so unrelated sweeps running concurrently in other
    // tests never trip it (test isolation).
    #[cfg(test)]
    {
        let armed = REMOVE_IF_INACTIVE_PAUSE
            .lock()
            .ok()
            .and_then(|mut slot| match slot.as_ref() {
                Some((p, _)) if p == path => slot.take().map(|(_, hook)| hook),
                _ => None,
            });
        if let Some(pause) = armed {
            pause();
        }
    }
    // The lock is held continuously from the check through the removal, so no
    // `ActiveRunGuard::new` can register `path` in between — the retry blocks on
    // the mutex until the delete finishes, then registers a path that no longer
    // exists (its own `prepare_run_dir` recreates it). The removal is therefore
    // never of a live run.
    remove();
    true
}

/// Best-effort sweep of stale retained run directories under `runs_dir`.
///
/// Successful runs are reaped the instant their result is captured, so the only
/// directories that linger here are *failed* runs kept for post-mortem. This
/// bounds that retention: any entry whose last modification is older than
/// [`FAILED_RUN_RETENTION`] is removed — **unless** it is a currently in-flight
/// run (registered in [`active_runs`]), which is skipped no matter how stale its
/// mtime looks, so a long-running agent's live checkout is never reaped by a
/// concurrent slot's sweep. A symlinked root (or one reached through a symlinked
/// ancestor) is refused up front — `read_dir`/`remove_dir_all` follow such a
/// link, so a symlinked `runs_dir` could otherwise redirect the sweep to delete
/// aged directories outside the configured workspace. Entirely best-effort: a
/// `read_dir`/`metadata`/`remove` failure is logged and skipped, never fatal,
/// because reaping old debris must not block servicing a new job.
///
/// `recurse_namespaces` selects WHAT the top-level entries are:
///   - `false` — each top-level entry IS a job run (an explicit `--runs-dir`, or
///     a worker's own `cfg.runs_dir` namespace). Sweep those entries by mtime and
///     **never descend** into them: a retained failed run holds its own repo
///     checkout and scratch dirs, which are not independent runs and must not be
///     aged out individually (that would corrupt post-mortem data).
///   - `true` — `runs_dir` is the SHARED `agent-runs` parent, so each top-level
///     entry is a *worker namespace* (`rust-worker-<pid>`), not a run. A namespace
///     is NEVER removed wholesale by its own mtime (a live worker's namespace can
///     age out immediately under `--reap-age 0`); instead the sweep refuses to
///     touch a namespace whose owning process is still alive (cross-process
///     liveness), and only descends into our own or a dead worker's namespace to
///     reap its aged, inactive child runs — then removes that namespace only if
///     it is left empty.
pub(crate) fn sweep_stale_runs(runs_dir: &Path, max_age: Duration, recurse_namespaces: bool) {
    #[cfg(unix)]
    {
        // The pinned sweep handles every outcome on Unix (reaping, or skipping
        // with a log on a refused/errored root), so there is nothing further.
        if let Err(crate::saferoot::PinError::Io(e)) =
            sweep_stale_runs_pinned(runs_dir, max_age, recurse_namespaces)
        {
            // A refused symlinked root (ELOOP) or any other error: skip the
            // sweep entirely rather than risk traversing a redirected root —
            // exactly the behaviour the path-based version's up-front reject
            // provided, now enforced atomically at open time.
            log(&format!(
                "skipping stale-run sweep of {}: {e} (possible local symlink attack)",
                runs_dir.display()
            ));
        }
    }
    #[cfg(not(unix))]
    sweep_stale_runs_path_based(runs_dir, max_age, recurse_namespaces);
}

/// `sweep_stale_runs` dispatched to the blocking pool. The sweep is a recursive
/// filesystem removal; run inline on a Tokio worker thread it can block the
/// executor long enough to starve the lease refresher (especially on a
/// single-core host) and lose an active job's lease. Use this from async
/// contexts; `sweep_stale_runs` remains for synchronous callers and tests.
pub(crate) async fn sweep_stale_runs_blocking(
    runs_dir: PathBuf,
    max_age: Duration,
    recurse_namespaces: bool,
) {
    // The sweep is best-effort and self-logging; a panic or a cancelled spawn
    // must not propagate, so discard the join outcome.
    let _ = tokio::task::spawn_blocking(move || {
        sweep_stale_runs(&runs_dir, max_age, recurse_namespaces);
    })
    .await;
}

/// Parse a worker-namespace dir name (`rust-worker-<pid>`) and report its owner
/// PID together with whether that process is still alive:
///   - `Some((pid, true))`  — a parseable owner PID whose process is still live
///   - `Some((pid, false))` — a parseable owner PID whose process is gone
///   - `None`               — not a `rust-worker-<pid>` namespace this binary owns
///     (e.g. a Node worker's `worker-<incarnation>`, or any other sibling); the
///     caller must leave it untouched, since it may be another live owner's tree.
fn namespace_owner_liveness(name: &std::ffi::OsStr) -> Option<(i32, bool)> {
    let pid: i32 = name.to_str()?.strip_prefix("rust-worker-")?.parse().ok()?;
    Some((pid, process_is_alive(pid)))
}

/// Whether `pid` names a live process. Best-effort; a reused PID can read as
/// alive, which only *defers* reaping — never a wrongful delete.
#[cfg(unix)]
fn process_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // `kill(pid, 0)` sends no signal: 0 => alive; EPERM => alive but not ours;
    // ESRCH => no such process.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Non-Unix fallback: assume alive so we never delete a namespace that might
/// still be owned by a live process we cannot probe.
#[cfg(not(unix))]
fn process_is_alive(_pid: i32) -> bool {
    true
}

/// `sweep_stale_runs` via an `openat2(RESOLVE_NO_SYMLINKS)` handle pinned to the
/// runs root: `read_dir`, the per-entry `lstat`, and every `remove` run
/// *relative to that pinned handle* with the `*at` syscalls, never re-resolving
/// the path. A same-UID actor can therefore not swap `runs_dir` (or an
/// ancestor) for a symlink between the check and the traversal to redirect the
/// sweep's deletions outside the workspace — the race path-based re-checks
/// cannot atomically close. Descent into an aged run dir is likewise no-follow,
/// so a symlink *inside* a swept dir deletes the link, never its target.
#[cfg(unix)]
fn sweep_stale_runs_pinned(
    runs_dir: &Path,
    max_age: Duration,
    recurse_namespaces: bool,
) -> std::result::Result<(), crate::saferoot::PinError> {
    use crate::saferoot::{DirHandle, PinError};
    let root = match DirHandle::open_root_nofollow(runs_dir, false) {
        Ok(h) => h,
        // A missing runs_dir (first job) is nothing to sweep — not an error;
        // the prepare path will (re)create and validate it.
        Err(PinError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // `execute` registers each in-flight run by its `normalize_run_path` form
    // (absolute AND lexically parent-free), so derive the comparison key with
    // the matching lexical resolver — even when `runs_dir` is relative or
    // parent-relative. `std::path::absolute` would keep an interior `..`,
    // producing a different registry key for the same directory and letting
    // the sweep reap a live run (#36). `resolve_run_path` collapses rather
    // than refuses, so the key always resolves.
    let runs_abs =
        crate::safecwd::resolve_run_path(runs_dir).unwrap_or_else(|_| runs_dir.to_path_buf());
    let now = SystemTime::now();
    let self_pid = std::process::id() as i32;
    for name in root.entry_names().map_err(PinError::Io)? {
        let meta = match root.symlink_metadata(&name) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Only sweep real directories — never follow a symlink (which could
        // point outside runs_dir), and leave stray files be.
        if !meta.is_dir || meta.is_symlink {
            continue;
        }

        if !recurse_namespaces {
            // Top-level entry IS a job run: age it by its own mtime, never
            // descend into it (its repo checkout / scratch dirs are not runs).
            // The active check and the removal are one atomic step (under the
            // active-runs mutex) so a retry registering this same path cannot
            // slip in between and have its live workspace deleted.
            if is_aged_out(meta.modified, now, max_age) {
                let path = runs_abs.join(&name);
                remove_if_inactive(&path, || reap_pinned(&root, &name, &path, max_age));
            }
            continue;
        }

        // Shared-parent mode: this entry is a worker NAMESPACE, not a run, and
        // is NEVER removed wholesale by its own mtime. Honour cross-process
        // liveness — a live owner's namespace (even aged under `--reap-age 0`)
        // is left entirely untouched, as its child runs may be in-flight in that
        // other process and are not in *our* `active_runs`.
        let owner_dead = match namespace_owner_liveness(&name) {
            // Another live owner (or a different-target namespace we don't own):
            // do not touch it or any of its descendants.
            None => continue,
            Some((pid, true)) if pid != self_pid => continue,
            Some((_, alive)) => !alive,
        };
        // Our own namespace, or a dead worker's: descend one level (pinned,
        // no-follow) and reap aged, inactive child runs. Readable (`trav =
        // false`): the child is enumerated and stat'd, not merely traversed.
        let child = match root.open_child_dir(&name, false) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let child_abs = runs_abs.join(&name);
        for sub in child.entry_names().map_err(PinError::Io)? {
            let smeta = match child.symlink_metadata(&sub) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !smeta.is_dir || smeta.is_symlink {
                continue;
            }
            if !is_aged_out(smeta.modified, now, max_age) {
                continue;
            }
            // Atomic check-and-remove (see the top-level branch): a retry can
            // register this same child path between a bare check and the delete.
            let cpath = child_abs.join(&sub);
            remove_if_inactive(&cpath, || reap_pinned(&child, &sub, &cpath, max_age));
        }
        // A dead worker's namespace that is now empty (every child reaped, none
        // retained) is itself removed, so repeated crashes don't leak empty
        // namespaces. Only when empty: a non-aged retained failed run must
        // survive for post-mortem, and `remove_tree` on a non-empty dir would
        // erase it. Never remove our OWN namespace here — `work` does that on
        // its clean exit, also only when empty.
        if owner_dead && child.entry_names().map(|e| e.is_empty()).unwrap_or(false) {
            if let Err(e) = root.remove_tree(&name) {
                log(&format!(
                    "failed to remove empty stale namespace {}: {e:#}",
                    child_abs.display()
                ));
            }
        }
    }
    Ok(())
}

/// Reap a single aged run dir `name` (relative to pinned `dir`), logging the
/// outcome. Shared by the top-level and one-level-descent sweep paths.
#[cfg(unix)]
fn reap_pinned(
    dir: &crate::saferoot::DirHandle,
    name: &std::ffi::OsStr,
    path: &Path,
    max_age: Duration,
) {
    match dir.remove_tree(name) {
        Ok(()) => log(&format!(
            "swept stale run dir {} (older than {}d)",
            path.display(),
            max_age.as_secs() / 86_400
        )),
        Err(e) => log(&format!(
            "failed to sweep stale run dir {}: {e:#}",
            path.display()
        )),
    }
}

/// Whether a directory's `modified` time is older than `max_age`. Keep the dir
/// when the platform withholds a modified time rather than risk deleting a
/// fresh run.
fn is_aged_out(modified: Option<SystemTime>, now: SystemTime, max_age: Duration) -> bool {
    modified
        .and_then(|m| now.duration_since(m).ok())
        .is_some_and(|age| age >= max_age)
}

/// Path-based `sweep_stale_runs`: the non-Unix fallback (no pinned-handle
/// support — not a supported daemon host). Rejects a symlinked root/ancestor up
/// front, then reads and removes by path — a best-effort approximation that
/// cannot fully close the check/traverse TOCTOU the pinned version does. Every
/// Unix host uses the pinned [`sweep_stale_runs_pinned`] instead.
#[cfg(not(unix))]
fn sweep_stale_runs_path_based(runs_dir: &Path, max_age: Duration, recurse_namespaces: bool) {
    // Refuse to traverse a symlinked root, or one reached through a symlinked
    // ancestor, before touching it: `read_dir` (and the `remove_dir_all` below)
    // follow such a link, so a symlinked `--runs-dir` — or an attacker-planted
    // symlinked ancestor under a world-writable parent — could redirect the
    // sweep to delete aged directories *outside* the configured workspace.
    // `prepare_run_dir` validates the same root, but only when a job is later
    // provisioned — after this sweep has already read and deleted — so the
    // check has to be repeated here, before the very first `read_dir`.
    if reject_symlink(runs_dir).is_err() || reject_symlinked_ancestors(runs_dir).is_err() {
        log(&format!(
            "skipping stale-run sweep of {}: symlinked root or ancestor (possible local symlink attack)",
            runs_dir.display()
        ));
        return;
    }
    let entries = match std::fs::read_dir(runs_dir) {
        Ok(e) => e,
        // A missing runs_dir (first job) or an unreadable one is nothing to
        // sweep — the normal prepare path will (re)create/validate it.
        Err(_) => return,
    };
    let now = SystemTime::now();
    let self_pid = std::process::id() as i32;
    for entry in entries.flatten() {
        let path = entry.path();
        // Only sweep directories (real ones — never follow a symlink, which
        // could point outside runs_dir); leave any stray files be.
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue;
        }

        if !recurse_namespaces {
            // Top-level entry IS a job run: age it by its own mtime, never
            // descend into it (its repo checkout / scratch dirs are not runs).
            // Atomic check-and-remove (see the pinned branch). Resolve with the
            // same lexical form `execute` registers by, so the key matches even
            // for a relative/parent-relative `runs_dir` (#36).
            let abs = crate::safecwd::resolve_run_path(&path).unwrap_or_else(|_| path.clone());
            if is_aged_out(meta.modified().ok(), now, max_age) {
                remove_if_inactive(&abs, || reap_path(&path, max_age));
            }
            continue;
        }

        // Shared-parent mode: this entry is a worker NAMESPACE, not a run, and
        // is NEVER removed wholesale by its own mtime. Honour cross-process
        // liveness — a live owner's namespace is left entirely untouched, as its
        // children may be in-flight in that other process.
        let name = match path.file_name() {
            Some(n) => n,
            None => continue,
        };
        let owner_dead = match namespace_owner_liveness(name) {
            None => continue,
            Some((pid, true)) if pid != self_pid => continue,
            Some((_, alive)) => !alive,
        };
        // Our own namespace, or a dead worker's: descend one level and reap
        // aged, inactive child runs, still never following symlinks.
        let children = match std::fs::read_dir(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for child in children.flatten() {
            let cpath = child.path();
            let cmeta = match std::fs::symlink_metadata(&cpath) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !cmeta.is_dir() {
                continue;
            }
            // Resolve with the same lexical form `execute` registers by, so the
            // key matches even for a relative runs root (#36).
            let cabs = crate::safecwd::resolve_run_path(&cpath).unwrap_or_else(|_| cpath.clone());
            if !is_aged_out(cmeta.modified().ok(), now, max_age) {
                continue;
            }
            // Atomic check-and-remove (see the pinned branch).
            remove_if_inactive(&cabs, || reap_path(&cpath, max_age));
        }
        // Remove a dead worker's now-empty namespace (see the pinned version);
        // only when empty, so a retained failed run survives. Never our own.
        if owner_dead
            && std::fs::read_dir(&path)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false)
        {
            if let Err(e) = std::fs::remove_dir(&path) {
                log(&format!(
                    "failed to remove empty stale namespace {}: {e:#}",
                    path.display()
                ));
            }
        }
    }
}

/// Reap a single aged run dir at `path` by path (the non-Unix fallback sweep),
/// logging the outcome. Unix sweeps reap through the pinned handle instead.
#[cfg(not(unix))]
fn reap_path(path: &Path, max_age: Duration) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => log(&format!(
            "swept stale run dir {} (older than {}d)",
            path.display(),
            max_age.as_secs() / 86_400
        )),
        Err(e) => log(&format!(
            "failed to sweep stale run dir {}: {e:#}",
            path.display()
        )),
    }
}

/// Redact any embedded userinfo (`user:token@`) from a URL's authority before
/// logging it. A repository URL from the task envelope may carry an HTTPS
/// credential (`https://x-access-token:<pat>@host/...`); logging it verbatim
/// would leak the secret into the daemon's stdout/journal. Every `scheme://…`
/// occurrence in the string is stripped — not just the first — so a value
/// carrying two credential-bearing URLs (e.g. a prompt or task field) never
/// forwards the second token. Only `http`/`https` authorities are redacted:
/// other schemes carry a *login*, not a secret — `ssh://git@host` uses `git`
/// as the required SSH username — so stripping their userinfo would corrupt an
/// otherwise-valid remote handed to the agent via the ACP prompt / pipe
/// payload. This mirrors `provision::scrub_url_credentials`, which likewise
/// scopes its scrub to HTTP(S). Non-URL or credential-free inputs are returned
/// unchanged.
pub(crate) fn redact_url(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find("://") {
        let after = pos + 3;
        // Only an HTTP(S) authority's userinfo is a credential to redact; for any
        // other scheme the userinfo is a login we must preserve verbatim.
        let redact = {
            let scheme = url_scheme_before(&rest[..pos]);
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        };
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        // The authority runs until the first character that cannot be part of it
        // (path/query/fragment separators, or any whitespace/quoting that ends
        // the URL inside surrounding prose).
        let auth_end = tail
            .find(|c: char| {
                matches!(
                    c,
                    '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '|' | '\\' | '`'
                ) || c.is_whitespace()
            })
            .unwrap_or(tail.len());
        let authority = &tail[..auth_end];
        match authority.rfind('@') {
            Some(at) if redact => out.push_str(&authority[at + 1..]),
            _ => out.push_str(authority),
        }
        rest = &tail[auth_end..];
    }
    out.push_str(rest);
    out
}

/// Extract the URL scheme immediately preceding a `://` separator: the trailing
/// run of scheme-valid characters (`[A-Za-z0-9+.-]`) in `prefix` (the substring
/// before the `://`). Mirrors `provision::scheme_of` — `slot` cannot see that
/// private helper — so `redact_url`'s scheme scoping matches the scrub's.
fn url_scheme_before(prefix: &str) -> &str {
    let start = prefix
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
        .map(|i| i + 1)
        .unwrap_or(0);
    &prefix[start..]
}

/// How a finished job is settled — mirrors the Node plugin's settle block.
#[derive(Debug)]
pub(crate) enum Settle {
    /// Complete with these variables.
    Complete(HashMap<String, Value>),
    /// Fail (retries decremented) with this message and optional variables.
    Fail {
        message: String,
        vars: Option<HashMap<String, Value>>,
    },
}

/// The job-variable key the Node plugin stores its result envelope under.
pub(crate) const AGENT_RESULT_KEY: &str = "io.nanobpm.agentResult";

/// The Node plugin's per-stream capture cap (`MAX_CAPTURE_BYTES`, 1 MiB).
const MAX_CAPTURE_BYTES: usize = 1_048_576;

/// The Node plugin's cap on the prior output echoed into the re-emit nudge.
/// The plugin slices the tail with `.slice(-24000)`, so the cap counts UTF-16
/// code units (an astral character is a surrogate pair and costs two), not
/// Unicode scalar values.
const NUDGE_CONTEXT_CAP_CHARS: usize = 24_000;

/// What one agent invocation produced (the Node plugin's `result` object).
#[derive(Debug, Default)]
struct RunResult {
    ok: bool,
    stdout: String,
    truncated: bool,
    exit_code: Option<i32>,
    error: Option<String>,
    timed_out: bool,
    /// ACP `session/update` activity (the transcript turns Node counts).
    has_turns: bool,
    /// The ACP prompt response's canonical `_meta.outcome` (plugin 1.70.1):
    /// `{status, summary}` only. It is non-empty evidence (threaded through
    /// empty detection) and is recorded separately as
    /// `io.nanobpm.agentResult.outcome`, but it contributes fallback RESULT
    /// variables only via the blocked-only mapping (`acp::outcome_result_vars`)
    /// at candidate selection. `None` for the pipe protocol (no ACP outcome
    /// channel).
    acp_outcome: Option<Map<String, Value>>,
}

/// Best-effort `git rev-parse HEAD` of a checkout, for the empty-job detector's
/// "did the agent commit anything" signal. Returns `None` when `dir` is not a
/// git work tree (a no-repository run dir) or git fails — both read as "no
/// commits", which is the safe default (a genuinely empty no-git run is still
/// failed; only a *repository* run gets the commit signal). Never fails the job.
///
/// The checkout is AGENT-CONTROLLED by the time of the post-run probe, so the
/// probe must be bounded: a run can leave blocking Git metadata behind (for
/// example `.git/HEAD` replaced by a FIFO), and an unbounded synchronous
/// `Command::output()` on a Tokio worker thread would then hang forever — the
/// job would never settle and a small runtime would be starved. The probe
/// therefore runs under [`GIT_HEAD_TIMEOUT`]: a git that has not exited by then
/// is killed and reaped, and the read reports `None` ("no commits" — the safe
/// default above) instead of hanging settlement.
fn git_head(dir: &crate::safecwd::CwdHandle) -> Option<String> {
    git_head_timeout(dir, GIT_HEAD_TIMEOUT)
}

/// `git_head` dispatched to the blocking pool. The probe polls a spawned
/// `Command` with `thread::sleep` (see `git_head_timeout`); run inline on a
/// Tokio worker thread that occupies the worker for the whole probe, and a
/// wedged agent-controlled checkout (e.g. `.git/HEAD` a FIFO) then holds it for
/// the full [`GIT_HEAD_TIMEOUT`] — long enough to starve the lease refresher
/// (especially on a single-core host) and lose the very lease this job runs
/// under. Use this from async contexts; `git_head` remains for synchronous
/// callers and tests. Best-effort like the probe itself: a panicked or
/// cancelled blocking task reads as `None` ("no commits"), the safe default.
pub(crate) async fn git_head_blocking(dir: crate::safecwd::CwdHandle) -> Option<String> {
    tokio::task::spawn_blocking(move || git_head(&dir))
        .await
        .ok()
        .flatten()
}

/// Upper bound on one `git rev-parse HEAD` probe of an agent-controlled
/// checkout. A healthy read is milliseconds; 5s is generous headroom for a
/// loaded host while still bounding a blocked one well under any activation
/// recovery window, so a wedged probe can never stall settlement (or starve a
/// small runtime's Tokio worker threads) indefinitely.
const GIT_HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for the bounded `git rev-parse` probe to exit.
const GIT_HEAD_POLL: Duration = Duration::from_millis(10);

fn git_head_timeout(dir: &crate::safecwd::CwdHandle, timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("git");
    cmd.args(["rev-parse", "--verify", "HEAD"])
        // An agent-controlled checkout could carry a prompt/sidebar config; keep
        // the invocation minimal and non-interactive.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        // stdin must not be inherited: a git that blocks reading it (a hostile
        // checkout's config can arrange that) would otherwise never finish.
        // stdout is piped (not `output()`) so the deadline below owns the wait
        // instead of blocking unboundedly inside `Child::wait_with_output`.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Enter the checkout through the pinned run-dir capability (`fchdir` in the
    // child's `pre_exec`) rather than re-resolving a path at spawn time: the
    // handle was opened no-follow at provisioning, so a same-UID actor swapping
    // a path component between provisioning and this probe cannot redirect
    // `git rev-parse` to an attacker repo and spoof the pre/post HEAD that is
    // the empty-job detector's only "did the agent commit" signal (#35, as for
    // the git()/agent launches).
    dir.apply_std(&mut cmd).ok()?;
    let mut child = cmd.spawn().ok()?;
    // Bounded wait: poll `try_wait` so a git wedged on agent-planted blocking
    // metadata (e.g. `.git/HEAD` a FIFO) is killed and reaped at the deadline
    // rather than waited on forever. Killing also guarantees no git child is
    // left running once this thread moves on.
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(GIT_HEAD_POLL),
            Ok(None) => {
                let _ = child.kill();
                break None;
            }
            Err(_) => break None,
        }
    };
    // Reap the child (a no-op once `try_wait` observed the exit; collects the
    // zombie after a kill) so a timed-out probe never leaks one.
    let _ = child.wait();
    if !status.is_some_and(|s| s.success()) {
        return None;
    }
    // The child has exited, so this read returns at EOF without blocking.
    let mut buf = Vec::new();
    child.stdout.take()?.read_to_end(&mut buf).ok()?;
    let sha = String::from_utf8_lossy(&buf).trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}

/// The empty-job detector's "did the agent commit anything" signal, as a pure
/// function of the pre/post HEAD and whether this job provisioned a repository.
/// Mirrors Node's non-empty `gitResult.commits`: any HEAD advance is a commit,
/// and — for a newly provisioned (initially HEAD-less) repository — the
/// *appearance* of a first commit (`before` `None`, `after` `Some`) is a commit
/// too, so a quiet pipe agent that made its first commit is not misread as an
/// empty run and retried. A non-repository run dir (`before`/`after` both
/// `None`) stays "no commits".
fn detect_commits(before: Option<&str>, after: Option<&str>, provisioned: bool) -> bool {
    match (before, after) {
        (Some(b), Some(a)) => b != a,
        (None, Some(_)) => provisioned,
        _ => false,
    }
}

/// Fallback "the run dir holds agent work" decision when finalize reported no
/// enumerated `commits`. `retain` (finalize's incomplete/failed-scan signal) and
/// `work_found` (stranded work the enumeration deliberately cleared) EACH mean
/// the job-keyed run dir may hold the ONLY copy of agent work even though the
/// checkout HEAD never moved (`head_has_commits` false). Either one must make the
/// run count as having commits, so a retained/stranded result is never misread as
/// empty and failed — a failure retries the job and the retry wipes the run dir,
/// destroying the very work `retain`/`work_found` was protecting (e.g. finalize
/// returns `retain=true, commits=[], work_found=false` after an inconclusive
/// branch/reflog scan).
fn retained_result_counts_as_commits(
    retain: bool,
    work_found: bool,
    head_has_commits: bool,
) -> bool {
    retain || work_found || head_has_commits
}

/// Whether a successfully-completed run's directory may be reaped. A provisioned
/// checkout that advanced HEAD (`has_commits`) whose commits were NOT pushed
/// (`!pushed`) holds work that lives ONLY in the run dir, so reaping would
/// destroy the single copy of work the job just reported successful. Retain
/// those (they are aged out later by `sweep_stale_runs`); reap everything else —
/// non-repository runs, provisioned runs that made no commit, and provisioned
/// runs whose commits finalize PUSHED to the origin (durable off-box).
///
/// `retained` is finalize's explicit stranded-work/incomplete-scan signal
/// ([`crate::provision::GitResult::retain`]). It forces retention INDEPENDENTLY
/// of the HEAD compare: a side-branch/detached commit that is then abandoned
/// leaves the final HEAD unchanged (so `has_commits` reads false) while the only
/// copy of that work sits in the run dir — the HEAD compare alone would reap it.
fn may_reap_completed_run(
    provisioned: bool,
    has_commits: bool,
    pushed: bool,
    retained: bool,
) -> bool {
    if retained {
        return false;
    }
    !(provisioned && has_commits && !pushed)
}

async fn execute(cfg: Arc<SlotConfig>, key: String, job: ActivatedJobResult) -> Result<Settle> {
    let custom_headers: Map<String, Value> = job.custom_headers.clone().into_iter().collect();
    let variables: Map<String, Value> = job.variables.clone().into_iter().collect();
    let env = envelope::assemble(&custom_headers, &variables);
    if env.prompt.as_deref().is_none_or(|p| p.trim().is_empty()) {
        bail!("job carries no prompt (task.prompt / prompt / task)");
    }

    // Per-job working directory; the repo (when present) is cloned inside it.
    // The dir is keyed by job key and so is reused across retries — wipe any
    // prior attempt's checkout and stale `result.json` first, so a retry starts
    // from a clean slate. Validate the key against the engine's numeric format
    // *before* joining it to a path (a malformed `../` key must never make
    // `remove_dir_all` / `create_dir_all` operate outside `runs_dir`).
    crate::jobs::validate_job_key(&key)?;
    // Absolute AND lexically resolved, so the agent (whose cwd is inside
    // `run_dir`) and the worker resolve `AGENT_RESULT_FILE` identically, and so
    // every launch backend resolves the same path. `normalize_run_path`
    // resolves only a LEADING `..` (e.g. a parent-relative `--runs-dir ../runs`)
    // against the trusted cwd and REFUSES any interior `..`: a lexical collapse
    // of an interior `..` is unsafe across a symlinked component (the Linux
    // `openat2` open would accept it while the portable `O_NOFOLLOW` chain
    // resolves it fd-relative — NOT path resolution — so a renamed ancestor
    // could silently redirect the descent). Resolving at this input boundary
    // (trusted prefix only; the not-yet-created job-dir tail stays literal)
    // gives both backends one identical, parent-free path (#35/#36). Purely
    // lexical — the symlink hardening in `prepare_run_dir` still inspects the
    // real on-disk structure.
    let run_dir =
        crate::safecwd::normalize_run_path(&cfg.runs_dir.join(&key)).with_context(|| {
            format!(
                "resolving absolute run dir under {}",
                cfg.runs_dir.display()
            )
        })?;
    // Claim exclusive ownership of this run dir BEFORE wiping/preparing it, so a
    // concurrent attempt for the same key (a lease-recovery redelivery to another
    // slot) cannot wipe our live checkout or share the workspace. The claim is
    // held for the whole job; a superseded attempt releases it when its aborted
    // `execute` future drops, so the wait here is bounded.
    let _claim = RunClaim::acquire(&run_dir).await;
    // Register this run dir as in-flight for the whole job so a concurrent
    // slot's retention sweep can never reap it.
    let _active = ActiveRunGuard::new(&run_dir);
    // `cfg.runs_dir` is this worker's own namespace, so its top-level entries
    // are job runs, not namespaces: sweep them directly, never descending into a
    // retained failed run's own checkout/scratch dirs. Gated on `--keep-runs`
    // like every other age-based reaper (startup/cadence in `work.rs`, the
    // per-completion cleanup below): that flag promises retained failed runs are
    // kept for post-mortem, so this per-job reap must not delete them either.
    if !cfg.keep_runs {
        sweep_stale_runs_blocking(cfg.runs_dir.clone(), FAILED_RUN_RETENTION, false).await;
    }
    // Prepare the run dir and carry the EXACT pinned capability it returns
    // through provisioning, the agent launches, and the HEAD probes. Preparation
    // pins the inode it wiped and secured (0700) and hands that fd back, so we
    // never reopen the job dir by path afterwards — a same-UID actor replacing
    // the job dir (or an ancestor) with an ordinary directory tree between
    // preparation and a reopen would pass no-follow resolution yet bind a
    // different, unsecured inode from the one preparation validated (#35).
    let prepared = PreparedRun {
        cwd: prepare_run_dir_blocking(cfg.runs_dir.clone(), run_dir.clone()).await?,
    };
    // The `branch` envelope's base/create/push selection, parsed once so the
    // pre-agent work-branch cut and the post-agent finalize agree on it.
    let branch_cfg = env.normalized.get("branch").and_then(|v| v.as_object());
    let branch_base = branch_cfg
        .and_then(|b| b.get("base"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let branch_create = branch_cfg
        .and_then(|b| b.get("create"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let branch_push = branch_cfg
        .and_then(|b| b.get("push"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let (agent_cwd, git_prep) = match &env.repository {
        Some(repo) => {
            log(&format!(
                "job {key}: cloning {} ({})",
                redact_url(&repo.url),
                repo.provider
            ));
            // `provision` returns the pinned checkout handle it used for every
            // git step; carry THAT exact inode into the agent/HEAD launches
            // rather than reopening `repo` by name (which a same-UID actor could
            // swap between the opens) (#35).
            let cwd = crate::provision::provision(repo, prepared.agent_cwd(), cfg.clone_timeout)
                .await
                .context("provisioning repository")?;
            // Cut the work branch the agent commits onto BEFORE it runs, so
            // finalize has a pushable branch (never the shared base).
            //
            // The fallback-branch suffix must be unique PER ACTIVATION, not per
            // job: the job `key` is stable across redelivery, so if this push
            // lands but the lease is lost before completion, the retry
            // wipes/reclones, regenerates the SAME fallback name from the base,
            // and its later push is rejected non-fast-forward against the first
            // attempt's branch. A fresh per-activation id makes each attempt's
            // fallback distinct. `key` stays the job/run-directory identity.
            //
            // Uniqueness: `pid` + wall-clock nanos alone is NOT enough — every
            // slot shares the worker PID, and two concurrent slots can observe
            // the SAME clock tick (or the clock can move backward), recreating
            // the very collision the suffix exists to prevent. Fold in a
            // process-local monotonically increasing sequence so two activations
            // can never mint the same suffix even on an identical timestamp, AND
            // a per-process random token (`process_rand_token`) so the suffix is
            // unique across SEPARATE workers too — they can share a PID (PID 1 in
            // containers), both start the sequence at 0, and observe the same
            // tick, which `pid`+`nanos`+`seq` alone would not disambiguate.
            let activation = format!(
                "{}-{}-{}-{}",
                process_rand_token(),
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
                ACTIVATION_SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let prep = crate::provision::prepare_work_branch(
                &cwd,
                repo,
                branch_base.as_deref(),
                branch_create.as_deref(),
                branch_push,
                &activation,
                cfg.clone_timeout,
            )
            .await;
            (cwd, Some(prep))
        }
        None => {
            // No repository: the agent and HEAD probes run in the run dir
            // itself. Dup the pinned handle fallibly — a dup failure (e.g.
            // descriptor exhaustion, EMFILE) must surface as a normal job
            // error here, not a worker-crashing panic from `Clone`.
            let cwd = prepared
                .agent_cwd()
                .try_clone()
                .context("dup the pinned run-dir handle")?;
            (cwd, None)
        }
    };
    // Baseline HEAD of the agent's checkout, captured BEFORE the agent runs so
    // the empty-job detector can tell whether the agent committed anything.
    // Node feeds `gitResult.commits`/`pushed` into `detectEmptyAgentJob`; the
    // Rust worker has no `finalizeGit` push stage yet, so it derives the
    // "commits" signal from a pre/post `rev-parse` of this HEAD (any advance =
    // a commit) and reports no push. `None` for a non-git run dir (no
    // repository) or when HEAD can't be read — treated as "no commits".
    // Dup the pinned handle FALLIBLY: this probe is best-effort (a failure is
    // already `None` = "HEAD unreadable"), so a dup failure (descriptor
    // exhaustion, EMFILE) must yield `None` here, never a worker-crashing
    // panic from `Clone` — the same class as the launch-cwd dup above.
    let start_head = match agent_cwd.try_clone() {
        Ok(cwd) => git_head_blocking(cwd).await,
        Err(_) => None,
    };

    let result_file = run_dir.join("result.json");
    let agent_env = build_agent_env(&cfg, &key, &job, &result_file, &run_dir);
    let payload = build_agent_payload(&cfg, &job, &env);
    let acp = cfg.hire.protocol == Protocol::Acp;

    // First turn: every protocol receives the JSON job payload (Node's
    // `buildAgentStdin` — ACP delivers it verbatim as the `session/prompt` text).
    let first = run_agent(&cfg, &key, &agent_cwd, &payload.to_string(), &agent_env).await;

    // Result-nudge (Node #678): a clean run that produced output but no usable
    // result gets exactly ONE bounded "emit your result now" turn, in a fresh
    // agent process in the same workspace, writing to the same result file.
    // Select the first EFFECTIVE result across file → stdout → ACP-outcome
    // sources (plugin 1.70.1), not merely the first that parses, so a `{}`
    // result file does not shadow a usable stdout sentinel or ACP outcome. The
    // ACP outcome contributes only its BLOCKED-only result mapping
    // (`outcome_result_vars`): a `completed` outcome derives no result vars, so
    // it must not suppress this nudge.
    let already = result::select_effective_result([
        result::read_result_file(&result_file),
        result::parse_result_from_stdout(&first.stdout),
        first
            .acp_outcome
            .as_ref()
            .and_then(crate::acp::outcome_result_vars),
    ]);
    let mut run = first;
    if run.ok
        && !run.stdout.trim().is_empty()
        && !already
            .as_ref()
            .is_some_and(result::has_effective_result_vars)
    {
        let nudge_text = build_result_nudge_prompt(&run.stdout);
        let stdin = if acp {
            nudge_text
        } else {
            nudge_payload(&payload, &nudge_text).to_string()
        };
        let nudge = run_agent(&cfg, &key, &agent_cwd, &stdin, &agent_env).await;
        if let Some(e) = &nudge.error {
            log(&format!("job {key}: re-emit nudge rerun failed — {e}"));
        }
        let joined = if nudge.stdout.is_empty() {
            std::mem::take(&mut run.stdout)
        } else {
            format!("{}\n{}", run.stdout, nudge.stdout)
        };
        let (text, capped) = cap_stdout_tail(joined);
        run.stdout = text;
        // Merge the nudge run's OWN collector-level truncation too: if the ACP
        // transcript / pipe capture dropped bytes while reading the second
        // invocation, that output is incomplete even when the joined tail still
        // fits this second cap (so `capped` is false), e.g. because UTF-8
        // boundary trimming left it just under the limit. Dropping `nudge.truncated`
        // would mislabel such a run `truncated: false`.
        run.truncated = run.truncated || nudge.truncated || capped;
        run.has_turns = run.has_turns || nudge.has_turns;
        // Propagate the nudge's latest outcome (plugin 1.70.1): the second turn's
        // explicit outcome supersedes the first's, and is the one that attests to
        // this recovery attempt.
        if nudge.acp_outcome.is_some() {
            run.acp_outcome = nudge.acp_outcome;
        }
        let recovered = result::select_effective_result([
            result::read_result_file(&result_file),
            result::parse_result_from_stdout(&run.stdout),
            run.acp_outcome
                .as_ref()
                .and_then(crate::acp::outcome_result_vars),
        ])
        .is_some_and(|r| result::has_effective_result_vars(&r));
        log(&format!(
            "job {key}: no result on the first turn — {}",
            if recovered {
                "recovered it via one re-emit nudge"
            } else {
                "re-emit nudge did not recover one"
            }
        ));
    }

    // Read the agent's structured result, selecting the first EFFECTIVE source
    // across file → stdout → ACP-outcome (plugin 1.70.1), and remove the result
    // channel, as the Node plugin does. The ACP outcome contributes only its
    // BLOCKED-only result mapping (`outcome_result_vars`): a `completed`
    // outcome derives no result vars, so it injects no guessed top-level
    // `status`. The canonical outcome is recorded SEPARATELY in the envelope as
    // `io.nanobpm.agentResult.outcome` (see `build_result_envelope`).
    let raw_result = result::select_effective_result([
        result::read_result_file(&result_file),
        result::parse_result_from_stdout(&run.stdout),
        run.acp_outcome
            .as_ref()
            .and_then(crate::acp::outcome_result_vars),
    ]);
    let _ = std::fs::remove_file(&result_file);
    let envelope = build_result_envelope(&run, &cfg.hire.sandbox, raw_result.as_ref());
    let name = &cfg.hire.name;
    let envelope_vars = || HashMap::from([(AGENT_RESULT_KEY.to_string(), envelope.clone())]);

    // Git finalize: enumerate the agent's commits on the work branch and push
    // it to the fallback `nano/agent-work/...` branch (the agent opened no PR of
    // its own). Only on a clean agent run — a failed run is retried, so its
    // partial work must not be published. `None` for an unprovisioned run (no
    // `gitResult`, so no branch/commits/pushed completion variables).
    let git_result = match (env.repository.as_ref(), git_prep.as_ref()) {
        (Some(repo), Some(prep)) if run.ok => {
            Some(crate::provision::finalize_git(&agent_cwd, prep, repo, cfg.clone_timeout).await)
        }
        _ => None,
    };

    // Node's `gitResult.commits.length > 0` / `pushed === true` empty-detection
    // signals. A repository agent that advanced the checkout HEAD committed
    // real work, so it is NOT empty even with no stdout/result; failing it
    // would burn a retry. When finalize ran, its commit enumeration is
    // authoritative ONLY when it found commits: a rev-list failure (or a
    // >1 MiB stdout-tail truncation inside `git()`) also reads as an empty
    // list, so an empty enumeration falls back to the pre/post HEAD compare
    // rather than condemning a quiet committing agent as an empty run. A
    // NON-repository run dir reads "no commits".
    let provisioned = env.repository.is_some();
    let pushed = git_result.as_ref().is_some_and(|g| g.pushed);
    // Finalize's explicit stranded-work / incomplete-scan signal. When set, the
    // run dir may hold the only copy of agent work (a side-branch/detached
    // commit, or a scan that failed open), so it must be retained regardless of
    // what the pre/post HEAD compare concludes about `has_commits`.
    let retain = git_result.as_ref().is_some_and(|g| g.retain);
    // Finalize's "real work exists" signal, DISTINCT from `retain` (incomplete
    // scan) and from `commits` (which the stranded-work paths deliberately
    // clear). A quiet commit-only run that strands work on a side branch or a
    // detached HEAD leaves the final HEAD unchanged AND `commits` empty, so
    // neither the enumeration nor the pre/post HEAD compare would see it — and
    // the empty-job detector would fail the run as "empty", its retry wiping the
    // job-keyed dir that holds the only copy. Treat `work_found` as commits.
    let work_found = git_result.as_ref().is_some_and(|g| g.work_found);
    // The post-run HEAD probe is best-effort too: dup the pinned handle
    // fallibly so a dup failure (EMFILE) reads as `None` ("HEAD unreadable"),
    // not a `Clone` panic — mirroring `start_head` above.
    let end_head = match agent_cwd.try_clone() {
        Ok(cwd) => git_head_blocking(cwd).await,
        Err(_) => None,
    };
    let has_commits = match &git_result {
        Some(g) if !g.commits.is_empty() => true,
        _ => {
            // `retain` (an incomplete/failed scan) and `work_found` (stranded
            // work the enumeration deliberately cleared) each mean the run dir
            // may hold the ONLY copy of agent work, even with `commits` empty and
            // the checkout HEAD unchanged. Treat BOTH as "has commits" so a
            // retained result cannot fall through to the empty-result path below:
            // failing it there would retry the job, and the retry wipes the
            // job-keyed run dir — destroying the very work `retain` was protecting
            // (e.g. finalize returns `retain=true, commits=[], work_found=false`
            // after a branch/reflog scan failed inconclusively).
            retained_result_counts_as_commits(
                retain,
                work_found,
                detect_commits(start_head.as_deref(), end_head.as_deref(), provisioned),
            )
        }
    };

    let settle = if !run.ok {
        let detail = run.error.clone().unwrap_or_else(|| match run.exit_code {
            Some(c) => format!("exit code {c}"),
            None => "terminated by signal".to_string(),
        });
        Settle::Fail {
            message: format!("agent \"{name}\" failed: {detail}"),
            vars: Some(envelope_vars()),
        }
    } else if let Some(reason) = result::detect_empty(
        raw_result.as_ref(),
        &run.stdout,
        run.has_turns,
        has_commits,
        pushed,
        run.acp_outcome.is_some(),
    ) {
        Settle::Fail {
            message: format!("agent \"{name}\" produced an empty result: {reason}"),
            vars: Some(envelope_vars()),
        }
    } else {
        let mut vars: HashMap<String, Value> = raw_result
            .as_ref()
            .map(result::sanitize_result_vars)
            .unwrap_or_default();
        if vars.is_empty() {
            log(&format!(
                "job {key}: agent returned no usable result vars — write a JSON object of result \
                 variables to $AGENT_RESULT_FILE (or print a \"::nano:result:: {{…}}\" line)"
            ));
        }
        vars.insert(AGENT_RESULT_KEY.into(), envelope.clone());
        vars.insert("output".into(), json!(run.stdout));
        vars.insert("exitCode".into(), json!(0));
        vars.insert("agent".into(), json!(name));
        vars.insert("truncated".into(), json!(run.truncated));
        // Surface the finalize outcome (`gitResult`) as completion variables,
        // mirroring the Node plugin's `branch`/`commits`/`pushed`/`pullRequest`.
        if let Some(g) = &git_result {
            vars.insert("branch".into(), json!(g.branch));
            vars.insert("commits".into(), json!(g.commits));
            vars.insert("pushed".into(), json!(g.pushed));
            vars.insert("pullRequest".into(), g.pr.clone().unwrap_or(Value::Null));
        }
        Settle::Complete(vars)
    };

    // Reap the run directory unless `--keep-runs`. Only successful runs are
    // reaped here; a failed run is left for post-mortem and aged out by
    // `sweep_stale_runs`. Best-effort, pinned no-follow (see `reap_run_dir`), and
    // dispatched to the blocking pool so a large checkout removal cannot stall
    // the executor and starve the lease refresher before `complete_job` lands.
    //
    // DO NOT reap a provisioned checkout whose commits were not pushed: those
    // commits are not durable — they live ONLY in this run dir, so deleting it
    // would destroy the single copy of work the job just reported successful.
    // `retain` (finalize's stranded-work/incomplete-scan signal) also forces
    // retention independently of the HEAD compare. Retain such a run (like a
    // failed one) for recovery; `sweep_stale_runs` ages it out on the cadence.
    if matches!(settle, Settle::Complete(_)) && !cfg.keep_runs {
        if may_reap_completed_run(provisioned, has_commits, pushed, retain) {
            reap_run_dir_blocking(cfg.runs_dir.clone(), run_dir.clone(), &key).await;
        } else {
            log(&format!(
                "job {key}: retaining run dir {} — provisioned checkout holds commits that were \
                 not pushed (or finalize flagged stranded/incomplete work), so they are not \
                 durable; reaping would delete their only copy (aged out later by sweep_stale_runs)",
                run_dir.display()
            ));
        }
    }
    Ok(settle)
}

/// Run the hired agent once with `stdin` (the ACP prompt text, or the pipe
/// harness's stdin) and report what happened. Never errors: a harness failure is
/// a failed [`RunResult`], settled by the caller.
async fn run_agent(
    cfg: &SlotConfig,
    key: &str,
    cwd: &crate::safecwd::CwdHandle,
    stdin: &str,
    env: &[(String, String)],
) -> RunResult {
    match cfg.hire.protocol {
        Protocol::Acp => {
            // Plugin 1.70.1 parity: a plain ACP hire whose command carries no
            // ACP selector is launched with `--acp` appended, so the agent starts
            // in ACP mode and the JSON-RPC handshake succeeds (otherwise it boots
            // in its default/non-ACP mode and the handshake fails). A hire that
            // already selects ACP is spawned unchanged (never doubled).
            let args = crate::daemon::acp_spawn_args(&cfg.hire);
            let mut agent = match Agent::spawn(&cfg.hire.command, &args, cwd, env) {
                Ok(a) => a,
                Err(e) => {
                    return RunResult {
                        error: Some(format!("{e:#}")),
                        ..RunResult::default()
                    }
                }
            };
            // Name the pinned directory for the log line, recovered through
            // the fd so a post-prepare rename cannot put a stale pathname in
            // the log; fall back to the raw handle debug if it cannot be read.
            let whereami = cwd
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<pinned run dir>".to_string());
            log(&format!(
                "job {key}: acp agent pid {} in {}",
                agent.pid().unwrap_or(0),
                whereami
            ));
            let out = agent.run(cwd, stdin, cfg.idle_timeout).await;
            agent.shutdown().await;
            match out {
                Ok(o) => {
                    log(&format!(
                        "job {key}: acp turn ended ({}; {} update(s), {} tool call(s), {} permission(s) granted)",
                        o.stop_reason, o.updates, o.tool_calls, o.permissions_granted
                    ));
                    let (stdout, capped) = cap_stdout_tail(o.text);
                    // `Agent::run` already bounds the transcript to 1 MiB while
                    // reading; combine its truncation flag with this second cap
                    // so a truncated ACP transcript is not misreported as whole.
                    RunResult {
                        ok: true,
                        stdout,
                        truncated: capped || o.truncated,
                        exit_code: Some(0),
                        has_turns: o.effective_turns > 0,
                        acp_outcome: o.outcome,
                        ..RunResult::default()
                    }
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    RunResult {
                        timed_out: msg.contains("idle"),
                        error: Some(msg),
                        ..RunResult::default()
                    }
                }
            }
        }
        Protocol::Pipe => {
            let whereami = cwd
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<pinned run dir>".to_string());
            log(&format!("job {key}: pipe agent in {whereami}"));
            match crate::pipe::run(
                &cfg.hire.command,
                &cfg.hire.args,
                cwd,
                env,
                stdin,
                cfg.idle_timeout,
            )
            .await
            {
                Ok(o) => {
                    let (stdout, capped) = cap_stdout_tail(o.stdout);
                    let error = o.idle_timed_out.then(|| {
                        format!(
                            "agent produced no output for {}s (idle timeout)",
                            cfg.idle_timeout.as_secs()
                        )
                    });
                    // `pipe::run` already bounds stdout to 1 MiB while reading;
                    // combine its truncation flag with this second cap so output
                    // the collector dropped is not misreported as complete.
                    RunResult {
                        ok: o.exit_code == Some(0) && !o.idle_timed_out,
                        stdout,
                        truncated: capped || o.truncated,
                        exit_code: o.exit_code,
                        timed_out: o.idle_timed_out,
                        error,
                        has_turns: false,
                        acp_outcome: None,
                    }
                }
                Err(e) => RunResult {
                    error: Some(format!("{e:#}")),
                    ..RunResult::default()
                },
            }
        }
    }
}

/// Cap a string to [`MAX_CAPTURE_BYTES`] of UTF-8, keeping the TAIL (so a
/// trailing `::nano:result::` sentinel survives) on a char boundary — the Node
/// plugin's `capStdoutTail`. Returns `(text, truncated)`.
fn cap_stdout_tail(s: String) -> (String, bool) {
    if s.len() <= MAX_CAPTURE_BYTES {
        return (s, false);
    }
    let mut start = s.len() - MAX_CAPTURE_BYTES;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    (s[start..].to_string(), true)
}

/// The re-emit nudge prompt — the Node plugin's `buildResultNudgePrompt` (with a
/// result file, which this worker always provides).
fn build_result_nudge_prompt(prior_stdout: &str) -> String {
    // The Node plugin echoes the prior output's TAIL via `.slice(-24000)`, which
    // counts UTF-16 code units, not scalar values. Cut by code units so an
    // astral-heavy tail keeps Node's intended length (an emoji costs two units).
    let ctx = crate::acp::tail_utf16(prior_stdout, NUDGE_CONTEXT_CAP_CHARS);
    [
        "You already completed the task in your previous turn, but you did NOT emit a",
        "machine-readable result, so the orchestrator cannot read your status and the",
        "run cannot advance.",
        "",
        "Do NOT redo the work, re-run tools, edit files, push, or open/modify a PR. Just",
        "emit the result for the work you already did: a single flat JSON object of your",
        "result variables (at minimum {\"status\":\"...\"}).",
        "",
        "Write it to the file named by the AGENT_RESULT_FILE environment variable, e.g.:",
        "",
        "    printf '%s' '{\"status\":\"...\",\"summary\":\"...\"}' > \"$AGENT_RESULT_FILE\"",
        "",
        "If you truly cannot write that file, print exactly one line: ::nano:result:: {json}",
        "",
        "Your previous output (reference — derive the status/summary from it):",
        "-----",
        &ctx,
    ]
    .join("\n")
}

/// The non-ACP nudge stdin: the JSON job payload with its prompt fields (the
/// top-level `prompt` and `task.task.prompt`) replaced by the nudge text.
fn nudge_payload(payload: &Value, nudge: &str) -> Value {
    let mut p = payload.clone();
    p["prompt"] = json!(nudge);
    if let Some(task) = p.get_mut("task").and_then(|t| t.get_mut("task")) {
        if task.is_object() {
            task["prompt"] = json!(nudge);
        }
    }
    p
}

/// The audit envelope stored under `io.nanobpm.agentResult` — the Node plugin's
/// `buildResultEnvelope` for a host (`sandbox: none`) run without git.
fn build_result_envelope(
    run: &RunResult,
    sandbox: &str,
    agent_result: Option<&Map<String, Value>>,
) -> Value {
    let status = if run.ok {
        "completed"
    } else if run.timed_out {
        "timedOut"
    } else {
        "failed"
    };
    let mut env = json!({
        "schemaVersion": 1,
        "status": status,
        "sandbox": sandbox,
        "image": null,
        "output": run.stdout,
        "truncated": run.truncated,
        "stderrTruncated": false,
        "exitCode": run.exit_code,
        "signal": null,
        "error": run.error,
    });
    if let Some(r) = agent_result {
        env["result"] = Value::Object(r.clone());
    }
    // Plugin 1.70.1: record the canonical ACP outcome SEPARATELY from the
    // selected `result`. The `result` field is the blocked-only result mapping
    // (or a file/stdout result); the canonical `{status, summary}` outcome is a
    // distinct audit record, preserved even when a file/stdout result shadows
    // it in `result`, and never carrying the synthesized `question`.
    if let Some(outcome) = &run.acp_outcome {
        env["outcome"] = Value::Object(outcome.clone());
    }
    env
}

/// The JSON job payload every harness receives — the Node plugin's
/// `buildAgentPayload`, with clone credentials scrubbed from every string.
fn build_agent_payload(cfg: &SlotConfig, job: &ActivatedJobResult, env: &Envelope) -> Value {
    let variables: Map<String, Value> = job.variables.clone().into_iter().collect();
    let custom_headers: Map<String, Value> = job.custom_headers.clone().into_iter().collect();
    let mut payload = json!({
        "jobKey": job.job_key.value(),
        "jobType": job.r#type,
        "processInstanceKey": job.process_instance_key.value(),
        "elementInstanceKey": job.element_instance_key.value(),
        "elementId": job.element_id.value(),
        "bpmnProcessId": job.process_definition_id.value(),
        "prompt": env.prompt,
        "task": env.normalized,
        "variables": variables,
        "customHeaders": custom_headers,
        "profile": {
            "name": cfg.hire.name,
            "rank": cfg.hire.rank,
            "model": cfg.hire.model,
            "capabilities": cfg.hire.capabilities,
        },
    });
    // Strip clone-credential userinfo from any URL anywhere in the payload before
    // it reaches the agent: the envelope can carry a credential-bearing
    // repository URL that `provision` supports for the clone, but the agent
    // already receives a checkout and never needs that token. `redact_url` is a
    // no-op on strings without `scheme://user:secret@` userinfo.
    redact_credential_urls(&mut payload);
    payload
}

/// Recursively rewrite every string in `value` through [`redact_url`], stripping
/// embedded `user:secret@` userinfo from any credential-bearing URL while leaving
/// all other strings untouched.
fn redact_credential_urls(value: &mut Value) {
    match value {
        Value::String(s) => {
            let redacted = redact_url(s);
            if redacted != *s {
                *s = redacted;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_credential_urls),
        Value::Object(map) => map.values_mut().for_each(redact_credential_urls),
        _ => {}
    }
}

/// The daemon's own engine-connection credentials, read from its environment by
/// [`crate::profile`]. A coding agent never needs them, so they are stripped
/// from the inherited environment at every agent launch (`acp` and `pipe`) —
/// otherwise a daemon configured via ambient `CAMUNDA_*`/`ZEEBE_*` OAuth or
/// basic-auth secrets would expose those secrets to the agent, which could read
/// and exfiltrate them even with `NANO_AGENTIC=off`. The `*_REST_ADDRESS`
/// connection URLs are stripped for the same reason: an operator may embed
/// HTTP(S) userinfo (`https://user:secret@host`) directly in the address, so the
/// URL itself carries an engine credential that must not be inherited by an
/// agent. The `NANO_AGENTIC_*`
/// credentials are stripped for the same reason: `NANO_AGENTIC=off` disables the
/// visibility channel but does not stop a host agent from reading an inherited
/// agentic token/secret out of its environment. Deployment secrets the agent
/// legitimately needs (e.g. its own GitHub credentials for push) are delivered
/// through the deliberate `hire.env` channel and are re-applied after this strip,
/// so an explicitly hired value is unaffected.
pub(crate) const SENSITIVE_DAEMON_ENV: &[&str] = &[
    "CAMUNDA_CLIENT_ID",
    "CAMUNDA_CLIENT_SECRET",
    "CAMUNDA_BASIC_AUTH_USERNAME",
    "CAMUNDA_BASIC_AUTH_PASSWORD",
    "ZEEBE_CLIENT_ID",
    "ZEEBE_CLIENT_SECRET",
    "ZEEBE_BASIC_AUTH_USERNAME",
    "ZEEBE_BASIC_AUTH_PASSWORD",
    "CAMUNDA_REST_ADDRESS",
    "ZEEBE_REST_ADDRESS",
    "NANO_AGENTIC_TOKEN",
    "NANO_AGENTIC_SECRET",
    "NANO_AGENTIC_CREDENTIAL",
];

/// The environment every harness gets: the reserved `AGENT_*`/`NANO_*` vars, the
/// result-file path, the agentic off-switch, and the hire's own env last-but-one
/// (reserved vars always win).
fn build_agent_env(
    cfg: &SlotConfig,
    key: &str,
    job: &ActivatedJobResult,
    result_file: &std::path::Path,
    run_dir: &std::path::Path,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    // #283: a headless agent has no interactive terminal, so any git command that
    // launches an editor (a `commit` without `-m`, a `rebase -i`/`merge` without a
    // message) blocks until the idle timeout. Point every editor git might spawn at
    // its built-in `:` no-op for BOTH launch protocols. Pushed FIRST — beneath the
    // hire env and the reserved vars below — so an explicit `hire.env` override
    // still wins, while these defaults override any ambient `EDITOR`/`VISUAL`
    // inherited from the daemon's environment.
    for (k, v) in [
        ("GIT_EDITOR", ":"),
        ("GIT_SEQUENCE_EDITOR", ":"),
        ("EDITOR", ":"),
        ("VISUAL", ":"),
    ] {
        env.push((k.to_string(), v.to_string()));
    }
    // Hire-configured env next, so reserved vars below can never be shadowed.
    for (k, v) in &cfg.hire.env {
        env.push((k.clone(), v.clone()));
    }
    env.push(("NANO_JOB_KEY".into(), key.to_string()));
    env.push(("NANO_AGENT_NAME".into(), cfg.worker_name.clone()));
    // #40: mark this process tree as an agent run. A supervisor/worker that an
    // agent tries to start reads these and refuses to daemonise (see
    // `main::guard_nested_supervisor`), so a job can never spawn a phantom fleet
    // that escapes its teardown. `NANO_AGENT_RUN` is the run identity (the job
    // key); `NANO_AGENT_RUN_DIR` is its working-directory root, so a host sweep
    // can also find descendants by cwd.
    env.push(("NANO_AGENT_RUN".into(), key.to_string()));
    env.push((
        "NANO_AGENT_RUN_DIR".into(),
        run_dir.to_string_lossy().into_owned(),
    ));
    // MVP: the agentic visibility channel is off (host sandbox only).
    env.push(("NANO_AGENTIC".into(), "off".into()));
    env.push((
        "AGENT_RESULT_FILE".into(),
        result_file.to_string_lossy().into_owned(),
    ));
    env.push(("AGENT_PROFILE".into(), cfg.hire.name.clone()));
    env.push(("AGENT_RANK".into(), cfg.hire.rank.clone()));
    env.push(("AGENT_MODEL".into(), cfg.hire.model.clone()));
    env.push(("AGENT_CAPABILITIES".into(), cfg.hire.capabilities.join(",")));
    env.push(("AGENT_JOB_TYPE".into(), job.r#type.clone()));
    env
}

fn truncate(s: &str, max: usize) -> String {
    // Hard cut, no ellipsis — the Node plugin's `.slice(0, 2000)`. JavaScript
    // strings are UTF-16, so the cap counts code units, not scalar values; an
    // astral character (an emoji) is a surrogate pair and costs two. Delegate
    // to the shared UTF-16 cut so this mirrors Node exactly.
    crate::acp::truncate_utf16(s, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_rand_token_is_stable_hex_and_feeds_the_suffix() {
        // Regression for the cross-worker fallback-branch collision class: the
        // token must be stable within a process (so a retry inside ONE process
        // is driven by the sequence/time, not a re-roll) yet high-entropy hex so
        // SEPARATE workers sharing a PID + clock tick + seq=0 still mint
        // distinct suffixes.
        let a = process_rand_token();
        let b = process_rand_token();
        assert_eq!(a, b, "token must be cached for the life of the process");
        assert_eq!(a.len(), 16, "8 random bytes rendered as hex");
        assert!(
            a.bytes().all(|c| c.is_ascii_hexdigit()),
            "token must be ref-safe hex, got {a:?}"
        );
    }

    fn hire() -> Hire {
        Hire {
            name: "coder".into(),
            rank: "senior".into(),
            command: "true".into(),
            args: vec![],
            model: "m".into(),
            capabilities: vec!["pr-review".into()],
            protocol: Protocol::Pipe,
            sandbox: "none".into(),
            env: Default::default(),
        }
    }

    fn cfg() -> SlotConfig {
        SlotConfig {
            hire: hire(),
            worker_name: "host-nanod-coder-0".into(),
            job_types: vec!["senior".into(), "senior:pr-review".into()],
            recovery_window: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(300),
            poll_timeout: Duration::from_secs(30),
            clone_timeout: Duration::from_secs(120),
            runs_dir: std::env::temp_dir(),
            with_lease: true,
            require_lease: true,
            max_jobs: None,
            propagate_job_panic: false,
            keep_runs: false,
        }
    }

    #[test]
    fn agent_env_has_reserved_and_off_switch() {
        let job = ActivatedJobResult {
            r#type: "senior:pr-review".into(),
            ..Default::default()
        };
        let rf = std::path::Path::new("/tmp/r.json");
        let env = build_agent_env(&cfg(), "42", &job, rf, std::path::Path::new("/tmp/run"));
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("NANO_AGENTIC"), Some("off"));
        assert_eq!(get("NANO_JOB_KEY"), Some("42"));
        assert_eq!(get("AGENT_RESULT_FILE"), Some("/tmp/r.json"));
        assert_eq!(get("AGENT_JOB_TYPE"), Some("senior:pr-review"));
        assert_eq!(get("AGENT_PROFILE"), Some("coder"));
    }

    #[test]
    fn agent_env_marks_the_agent_run() {
        // #40: every agent is told which run it belongs to so a supervisor/worker
        // it tries to start can refuse to daemonise and a host sweep can find its
        // descendants by cwd.
        let job = ActivatedJobResult::default();
        let rf = std::path::Path::new("/tmp/r.json");
        let env = build_agent_env(&cfg(), "42", &job, rf, std::path::Path::new("/tmp/runs/42"));
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("NANO_AGENT_RUN"), Some("42"));
        assert_eq!(get("NANO_AGENT_RUN_DIR"), Some("/tmp/runs/42"));
    }

    #[test]
    fn agent_env_sets_headless_editor_noops() {
        let job = ActivatedJobResult {
            r#type: "senior:pr-review".into(),
            ..Default::default()
        };
        let rf = std::path::Path::new("/tmp/r.json");
        let env = build_agent_env(&cfg(), "42", &job, rf, std::path::Path::new("/tmp/run"));
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        // #283: every editor git might spawn points at the `:` no-op so a headless
        // agent's `git commit`/`rebase -i` can never block on an interactive editor.
        for k in ["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "EDITOR", "VISUAL"] {
            assert_eq!(get(k), Some(":"), "{k} must default to the git no-op");
        }
    }

    #[test]
    fn hire_env_overrides_editor_noops_but_not_reserved() {
        let mut h = hire();
        h.env.insert("EDITOR".into(), "vim".into());
        h.env.insert("NANO_AGENTIC".into(), "on".into());
        let mut c = cfg();
        c.hire = h;
        let job = ActivatedJobResult {
            r#type: "t".into(),
            ..Default::default()
        };
        let rf = std::path::Path::new("/tmp/r.json");
        let env = build_agent_env(&c, "1", &job, rf, std::path::Path::new("/tmp/run"));
        // `.envs()` is last-wins, so the LAST entry for a key is the effective value.
        let last = |k: &str| {
            env.iter()
                .rev()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        // An explicit hire override of an editor var wins over the no-op default…
        assert_eq!(last("EDITOR"), Some("vim"));
        // …but the editor vars the hire did NOT set keep their no-op default…
        assert_eq!(last("GIT_EDITOR"), Some(":"));
        // …and a reserved var the hire tried to shadow is still forced off.
        assert_eq!(last("NANO_AGENTIC"), Some("off"));
    }

    #[test]
    fn sensitive_daemon_env_covers_engine_secrets() {
        // The daemon's engine-connection secrets must be in the strip list so a
        // launched agent never inherits them. `build_agent_env` never emits them
        // either (it only adds reserved + hire vars), so the leak can only come
        // from the inherited environment — which the launch sites strip via this
        // list.
        for k in [
            "CAMUNDA_CLIENT_SECRET",
            "ZEEBE_CLIENT_SECRET",
            "CAMUNDA_BASIC_AUTH_PASSWORD",
            // The SDK also accepts the `ZEEBE_*` aliases as an ambient
            // connection source, so basic-auth credentials supplied that way
            // must be stripped too.
            "ZEEBE_BASIC_AUTH_USERNAME",
            "ZEEBE_BASIC_AUTH_PASSWORD",
            // A `*_REST_ADDRESS` connection URL can embed HTTP(S) userinfo
            // (`https://user:secret@host`), so the address itself carries an
            // engine credential and must be stripped from the agent env too.
            "CAMUNDA_REST_ADDRESS",
            "ZEEBE_REST_ADDRESS",
            // `NANO_AGENTIC=off` disables the channel but does not stop a host
            // agent reading an inherited agentic credential, so these must be
            // stripped too.
            "NANO_AGENTIC_TOKEN",
            "NANO_AGENTIC_SECRET",
            "NANO_AGENTIC_CREDENTIAL",
        ] {
            assert!(
                SENSITIVE_DAEMON_ENV.contains(&k),
                "{k} missing from SENSITIVE_DAEMON_ENV"
            );
        }
        let job = ActivatedJobResult::default();
        let env = build_agent_env(
            &cfg(),
            "1",
            &job,
            std::path::Path::new("/tmp/r.json"),
            std::path::Path::new("/tmp/run"),
        );
        for (k, _) in &env {
            assert!(
                !SENSITIVE_DAEMON_ENV.contains(&k.as_str()),
                "build_agent_env must never emit daemon secret {k}"
            );
        }
    }

    #[test]
    fn hire_env_cannot_shadow_reserved() {
        let mut c = cfg();
        c.hire.env.insert("NANO_AGENTIC".into(), "on".into());
        let job = ActivatedJobResult::default();
        let env = build_agent_env(
            &c,
            "1",
            &job,
            std::path::Path::new("/tmp/r.json"),
            std::path::Path::new("/tmp/run"),
        );
        // The reserved value is pushed AFTER the hire env, so it wins for any
        // consumer that reads the last occurrence (as a child process does).
        let last = env
            .iter()
            .rfind(|(k, _)| k == "NANO_AGENTIC")
            .map(|(_, v)| v.as_str());
        assert_eq!(last, Some("off"));
    }

    #[test]
    fn redact_url_strips_embedded_credentials() {
        assert_eq!(
            redact_url("https://x-access-token:ghp_secret@github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            redact_url("https://user:pw@host:8443/path?x=1"),
            "https://host:8443/path?x=1"
        );
        // No credentials / non-URL inputs are returned unchanged.
        assert_eq!(
            redact_url("https://github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            redact_url("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );
        // Non-HTTP(S) schemes carry a *login*, not a secret: `ssh://git@host`
        // uses `git` as the required SSH username, so it must be preserved
        // verbatim — stripping it would corrupt an otherwise-valid remote.
        assert_eq!(
            redact_url("ssh://git@github.com/o/r.git"),
            "ssh://git@github.com/o/r.git"
        );
        assert_eq!(
            redact_url("ssh://user@git.example.com:22/o/r.git"),
            "ssh://user@git.example.com:22/o/r.git"
        );
    }

    #[test]
    fn redact_url_strips_every_occurrence() {
        // A single string carrying two credential-bearing URLs must have BOTH
        // tokens stripped, not just the first (the field could be a prompt or a
        // task value forwarded to a pipe agent). Build the userinfo at runtime so
        // no credential-like literal is stored in source.
        let a = format!("{}:{}", "x-access-token", "tokenA1");
        let b = format!("{}:{}", "x-access-token", "tokenB2");
        let s = format!("clone https://{a}@h1/x.git then https://{b}@h2/y.git done");
        let out = redact_url(&s);
        assert!(!out.contains("tokenA1"), "first credential leaked: {out}");
        assert!(!out.contains("tokenB2"), "second credential leaked: {out}");
        assert!(out.contains("https://h1/x.git"));
        assert!(out.contains("https://h2/y.git"));
    }

    #[test]
    fn pipe_payload_redacts_repository_clone_credentials() {
        let cfg = cfg();
        let job = ActivatedJobResult::default();
        // Build the credential-bearing URL at runtime so no credential-like
        // literal is stored in source (mirrors the provision.rs tests).
        let token = format!("{}-{}", "x-access", "token");
        let secret = format!("pat{}value", 1234);
        let cred_url = format!("https://{token}:{secret}@github.com/o/r.git");
        let env = Envelope {
            prompt: Some("do it".into()),
            repository: None,
            normalized: json!({ "repository": { "url": cred_url } }),
        };
        let payload = build_agent_payload(&cfg, &job, &env).to_string();
        assert!(
            !payload.contains(&secret),
            "clone credential must not reach the agent payload: {payload}"
        );
        assert!(payload.contains("https://github.com/o/r.git"));
    }

    #[test]
    fn nudge_payload_overrides_both_prompt_fields() {
        let payload = json!({
            "prompt": "orig",
            "task": { "schemaVersion": 1, "task": { "prompt": "orig", "allowPr": false } },
            "jobKey": "1",
        });
        let p = nudge_payload(&payload, "emit it");
        assert_eq!(p["prompt"], "emit it");
        assert_eq!(p["task"]["task"]["prompt"], "emit it");
        assert_eq!(p["task"]["task"]["allowPr"], false);
        assert_eq!(p["jobKey"], "1");
        // The original payload is never mutated.
        assert_eq!(payload["prompt"], "orig");
    }

    #[test]
    fn nudge_prompt_echoes_the_prior_output_tail() {
        let p = build_result_nudge_prompt("did the work");
        assert!(p.starts_with("You already completed the task in your previous turn"));
        assert!(p.ends_with("-----\ndid the work"));
        let long = "x".repeat(NUDGE_CONTEXT_CAP_CHARS + 10);
        let p = build_result_nudge_prompt(&long);
        assert!(p.ends_with(&"x".repeat(NUDGE_CONTEXT_CAP_CHARS)));
        assert!(!p.contains(&"x".repeat(NUDGE_CONTEXT_CAP_CHARS + 1)));
    }

    #[test]
    fn nudge_prompt_tail_counts_utf16_units_not_chars() {
        // The Node plugin's `.slice(-24000)` counts UTF-16 code units: an emoji
        // is a surrogate pair (two units), so an astral-heavy tail keeps half as
        // many CHARACTERS as a chars()-based cut would.
        let emoji = "\u{1F600}".repeat(NUDGE_CONTEXT_CAP_CHARS); // 2 units each
        let p = build_result_nudge_prompt(&emoji);
        let kept = NUDGE_CONTEXT_CAP_CHARS / 2; // whole pairs only, never split
        assert!(p.ends_with(&"\u{1F600}".repeat(kept)));
        assert!(!p.contains(&"\u{1F600}".repeat(kept + 1)));
    }

    #[test]
    fn tail_utf16_never_splits_a_surrogate_pair() {
        // An astral character costs two UTF-16 units. When it does not fit whole
        // in the remaining budget it is dropped entirely (JS `slice` would keep a
        // lone surrogate, which a Rust String cannot represent), never split.
        let s = format!("{}\u{1F600}", "a".repeat(10)); // 10 units + 2 units
        let tail = crate::acp::tail_utf16(&s, 1);
        assert_eq!(tail, ""); // the emoji (2 units) does not fit in 1 unit
        let tail = crate::acp::tail_utf16(&s, 2);
        assert_eq!(tail, "\u{1F600}"); // exactly the emoji
        let tail = crate::acp::tail_utf16(&s, 3);
        assert_eq!(tail, "a\u{1F600}"); // one BMP char + the emoji
        let tail = crate::acp::tail_utf16(&s, 12);
        assert_eq!(tail, s); // the whole string fits
    }

    #[test]
    fn stdout_cap_keeps_the_tail_on_a_char_boundary() {
        let (t, cut) = cap_stdout_tail("short".into());
        assert_eq!((t.as_str(), cut), ("short", false));
        let s = format!("é{}", "a".repeat(MAX_CAPTURE_BYTES));
        let (t, cut) = cap_stdout_tail(s);
        assert!(cut);
        assert_eq!(t.len(), MAX_CAPTURE_BYTES);
    }

    #[test]
    fn result_envelope_matches_the_node_shape() {
        let run = RunResult {
            ok: true,
            stdout: "out".into(),
            exit_code: Some(0),
            ..RunResult::default()
        };
        let mut r = Map::new();
        r.insert("status".into(), json!("done"));
        let env = build_result_envelope(&run, "none", Some(&r));
        assert_eq!(
            env,
            json!({
                "schemaVersion": 1, "status": "completed", "sandbox": "none", "image": null,
                "output": "out", "truncated": false, "stderrTruncated": false,
                "exitCode": 0, "signal": null, "error": null, "result": { "status": "done" },
            })
        );
        let failed = RunResult {
            timed_out: true,
            error: Some("idle".into()),
            ..RunResult::default()
        };
        assert_eq!(
            build_result_envelope(&failed, "none", None)["status"],
            "timedOut"
        );
    }

    #[test]
    fn result_envelope_records_the_canonical_outcome_separately() {
        // Plugin 1.70.1: the canonical ACP outcome is recorded as a DISTINCT
        // `outcome` field, separate from the selected `result` — and preserved
        // even when a file/stdout result shadows it in `result`.
        let mut outcome = Map::new();
        outcome.insert("status".into(), json!("blocked"));
        outcome.insert("summary".into(), json!("need creds"));
        let mut file_result = Map::new();
        file_result.insert("status".into(), json!("done"));
        let run = RunResult {
            ok: true,
            stdout: "out".into(),
            exit_code: Some(0),
            acp_outcome: Some(outcome.clone()),
            ..RunResult::default()
        };
        let env = build_result_envelope(&run, "none", Some(&file_result));
        // The selected result is the file result…
        assert_eq!(env["result"], json!({ "status": "done" }));
        // …while the canonical outcome is recorded separately, without the
        // synthesized `question` (that mapping lives only in result vars).
        assert_eq!(
            env["outcome"],
            json!({ "status": "blocked", "summary": "need creds" })
        );
        assert!(env["outcome"].get("question").is_none());

        // No outcome → no `outcome` key at all.
        let plain = RunResult {
            ok: true,
            stdout: "out".into(),
            exit_code: Some(0),
            ..RunResult::default()
        };
        let env = build_result_envelope(&plain, "none", Some(&file_result));
        assert!(env.get("outcome").is_none());
    }

    #[test]
    fn acp_prompt_is_redacted_of_clone_credentials() {
        // The ACP first turn delivers the full JSON job payload verbatim as the
        // `session/prompt` text (slot.rs: `run_agent` sends `payload.to_string()`),
        // so a credential-bearing URL in the task prompt must be scrubbed when the
        // payload is BUILT — `build_agent_payload` runs `redact_credential_urls`
        // over every string. Build the userinfo at runtime so no credential-like
        // literal is stored in source.
        let cfg = cfg();
        let job = ActivatedJobResult::default();
        let token = format!("{}-{}", "x-access", "token");
        let secret = format!("pat{}value", 1234);
        let prompt = format!("clone https://{token}:{secret}@github.com/o/r.git and build");
        let env = Envelope {
            prompt: Some(prompt),
            repository: None,
            normalized: json!({}),
        };
        // This is exactly the string the ACP agent receives as its prompt.
        let acp_stdin = build_agent_payload(&cfg, &job, &env).to_string();
        assert!(
            !acp_stdin.contains(&secret),
            "clone credential must not reach the ACP agent prompt: {acp_stdin}"
        );
        assert!(acp_stdin.contains("https://github.com/o/r.git"));
        assert!(acp_stdin.contains("and build"));
    }

    #[test]
    fn reconcile_lost_downgrades_completed_outcome_when_activation_lost() {
        // The core of the lease-loss/completion race fix: even a job whose
        // `exec` future completed (an `Ok`/`Err` outcome) must NOT be settled
        // once the activation-loss watch reads `true`, because `select!` can
        // pick the completed branch in the same tick the refresher fences us out
        // (404/409). Settling then would `complete`/`fail` with a stale lease.
        let completed: Option<Result<()>> = Some(Ok(()));
        assert!(
            reconcile_lost(completed, true).is_none(),
            "a completed outcome must be downgraded to lost when the activation was fenced"
        );
        let failed: Option<Result<()>> = Some(Err(anyhow::anyhow!("boom")));
        assert!(
            reconcile_lost(failed, true).is_none(),
            "a failed outcome must also be downgraded to lost when the activation was fenced"
        );
        // Not lost: the outcome passes through unchanged so a genuine completion
        // still settles.
        assert!(matches!(
            reconcile_lost(Some(Ok::<(), anyhow::Error>(())), false),
            Some(Ok(()))
        ));
        // Already lost via the select's None branch stays lost.
        assert!(reconcile_lost(None::<Result<()>>, false).is_none());
    }

    #[tokio::test]
    async fn job_panic_is_fatal_only_for_a_panic_in_standalone_work_mode() {
        // A per-job task PANIC: fatal in standalone `work` (so the process exits
        // non-zero instead of swallowing the crash and exiting 0), tolerated in
        // the daemon (its explicit "one panicked job fails only that job" policy).
        let panicked = tokio::spawn(async { panic!("boom") }).await;
        assert!(
            job_panic_is_fatal(&panicked, true),
            "work mode: a panic crashes the slot"
        );
        assert!(
            !job_panic_is_fatal(&panicked, false),
            "daemon: a panic is tolerated"
        );

        // A cancellation (drain abort) is never a crash, even in work mode.
        let task = tokio::spawn(async { tokio::time::sleep(Duration::from_secs(60)).await });
        task.abort();
        let cancelled = task.await;
        assert!(
            !job_panic_is_fatal(&cancelled, true),
            "a drain abort is not a crash"
        );

        // A clean completion is never fatal.
        let ok = tokio::spawn(async {}).await;
        assert!(
            !job_panic_is_fatal(&ok, true),
            "a clean completion is not a crash"
        );
    }

    #[tokio::test]
    async fn exec_join_panic_reraised_in_standalone_but_downgraded_in_daemon() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        // Daemon (`propagate == false`): a panic in the inner `execute` task is
        // downgraded to a failed job (`Err`), never re-raised — the slot carries on.
        let joined: std::result::Result<Result<()>, _> =
            tokio::spawn(async { panic!("exec boom") }).await;
        let downgraded = reconcile_exec_join("job-daemon", joined, false);
        assert!(
            downgraded.is_err(),
            "daemon downgrades an inner-task panic to a failed job"
        );

        // Standalone work (`propagate == true`): the panic is re-raised so the
        // `handle` task crashes and `work` can exit non-zero.
        let joined2: std::result::Result<Result<()>, _> =
            tokio::spawn(async { panic!("exec boom") }).await;
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            reconcile_exec_join("job-work", joined2, true)
        }));
        assert!(
            crashed.is_err(),
            "standalone work re-raises an inner-task panic as a worker crash"
        );

        // A cancellation (drain abort) is never a crash, even in work mode: it is
        // downgraded like any non-panic join failure.
        let task = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });
        task.abort();
        let cancelled: std::result::Result<Result<()>, _> = task.await;
        let not_a_crash = catch_unwind(AssertUnwindSafe(|| {
            reconcile_exec_join("job-cancel", cancelled, true)
        }));
        assert!(
            matches!(not_a_crash, Ok(Err(_))),
            "a drain abort is downgraded, not re-raised, even in work mode"
        );

        // A clean completion passes the inner result straight through.
        let clean: std::result::Result<Result<u8>, _> = tokio::spawn(async { Ok(7u8) }).await;
        assert_eq!(reconcile_exec_join("job-ok", clean, true).unwrap(), 7);
    }

    #[test]
    fn sweep_stale_runs_removes_only_aged_dirs() {
        // Unique per-test root under the system temp dir (no tempfile dep here).
        let root = std::env::temp_dir().join(format!(
            "nano-sweep-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        // Resolve any symlinked ancestor of the system temp dir (e.g. macOS's
        // /var -> /private/var) up front: the sweep legitimately refuses a
        // symlinked root/ancestor, so exercise it against the canonical path.
        let root = std::fs::canonicalize(&root).unwrap();

        let aged = root.join("failed-run");
        std::fs::create_dir_all(&aged).unwrap();
        std::fs::write(aged.join("result.json"), b"{}").unwrap();
        let stray = root.join("stray.txt");
        std::fs::write(&stray, b"x").unwrap();

        // max_age = 0 → every existing dir is at/over the threshold and swept,
        // but stray files are left untouched.
        sweep_stale_runs(&root, Duration::ZERO, false);
        assert!(!aged.exists(), "aged-out run dir should be swept");
        assert!(stray.exists(), "stray files must be left alone");

        // A fresh dir with a long retention window is kept.
        let fresh = root.join("in-flight-run");
        std::fs::create_dir_all(&fresh).unwrap();
        sweep_stale_runs(&root, Duration::from_secs(3 * 24 * 60 * 60), false);
        assert!(fresh.exists(), "a fresh run dir must not be swept");

        // A missing runs_dir is a no-op (must not panic).
        sweep_stale_runs(&root.join("does-not-exist"), Duration::ZERO, false);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sweep_recurses_into_fresh_worker_namespaces() {
        // A worker namespace (`agent-runs/rust-worker-<pid>`) can have a fresh
        // mtime while holding a STALE run dir — e.g. a crashed worker's leftover
        // that a per-worker sweep rooted at its own namespace could never reach.
        // The sweep must descend one level and reap the stale child while keeping
        // a fresh sibling.
        let root = std::env::temp_dir().join(format!(
            "nano-sweep-ns-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        // A fresh namespace (its own mtime is now) holding one stale and one
        // fresh run dir. Backdate the stale child so a positive window selects
        // it alone.
        let ns = root.join("rust-worker-99999");
        let stale_child = ns.join("111");
        let fresh_child = ns.join("222");
        std::fs::create_dir_all(&stale_child).unwrap();
        std::fs::create_dir_all(&fresh_child).unwrap();
        std::fs::write(stale_child.join("result.json"), b"{}").unwrap();
        if !backdate_mtime(&stale_child, Duration::from_secs(10 * 24 * 60 * 60)) {
            // Cannot backdate a dir mtime on this platform: the selective case
            // is untestable here, so just verify the recursion reaches a child
            // at all (a zero window sweeps every aged child of a fresh ns).
            sweep_stale_runs(&root, Duration::ZERO, true);
            assert!(
                !stale_child.exists(),
                "a stale run dir inside a fresh namespace must be swept"
            );
            std::fs::remove_dir_all(&root).ok();
            return;
        }
        // The namespace itself stays fresh (just created), so a positive window
        // must NOT reap it wholesale, but MUST still reach the stale child.
        sweep_stale_runs(&root, Duration::from_secs(3 * 24 * 60 * 60), true);
        assert!(
            !stale_child.exists(),
            "a stale run dir inside a fresh namespace must be swept"
        );
        assert!(
            fresh_child.exists(),
            "a fresh run dir inside a fresh namespace must be kept"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// Backdate a directory's mtime by `age` (test-only). Returns false where
    /// the platform cannot set a directory's mtime, so the caller can fall back.
    #[cfg(unix)]
    fn backdate_mtime(path: &Path, age: Duration) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let t = now.saturating_sub(age);
        let ts = libc::timespec {
            tv_sec: t.as_secs() as libc::time_t,
            tv_nsec: t.subsec_nanos() as _,
        };
        // Set both atime and mtime; do not follow symlinks.
        let times = [ts, ts];
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        }
    }

    #[cfg(not(unix))]
    fn backdate_mtime(_path: &Path, _age: Duration) -> bool {
        false
    }

    #[cfg(unix)]
    #[test]
    fn sweep_leaves_a_live_owners_namespace_untouched() {
        // Cross-process liveness: the shared-parent sweep must NOT delete (or
        // descend into) a worker namespace whose owning process is still alive,
        // even under `--reap-age 0`. That namespace's child runs may be in-flight
        // in the other process and are NOT in this process's `active_runs`, so
        // reaping them would destroy a live sibling's workspace.
        let root = std::env::temp_dir().join(format!(
            "nano-sweep-live-ns-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        // PID 1 (init/launchd) is always alive and never us: a perfect stand-in
        // for a live sibling worker's namespace.
        let live_ns = root.join("rust-worker-1");
        let child = live_ns.join("some-job");
        std::fs::create_dir_all(&child).unwrap();

        sweep_stale_runs(&root, Duration::ZERO, true);
        assert!(
            child.exists(),
            "a live owner's in-flight run must never be reaped cross-process"
        );
        assert!(
            live_ns.exists(),
            "a live owner's namespace must never be removed"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sweep_run_mode_never_descends_into_a_run_dir() {
        // Non-recurse mode: top-level entries ARE runs, so the sweep must never
        // descend into a retained failed run's own subdirs (its repo checkout /
        // scratch), which are not independent runs. A fresh run holding an aged
        // inner dir must keep that inner dir intact.
        let root = std::env::temp_dir().join(format!(
            "nano-sweep-nodescend-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        let run = root.join("failed-run");
        let checkout = run.join("checkout");
        std::fs::create_dir_all(&checkout).unwrap();
        std::fs::write(checkout.join("src.rs"), b"keep").unwrap();
        // Age the inner checkout well past the window; the run itself stays fresh.
        backdate_mtime(&checkout, Duration::from_secs(10 * 24 * 60 * 60));

        // A positive window: the fresh run is kept and — crucially — the aged
        // inner dir is NOT reaped, because run mode never descends.
        sweep_stale_runs(&root, Duration::from_secs(3 * 24 * 60 * 60), false);
        assert!(run.exists(), "a fresh run dir must be kept");
        assert!(
            checkout.join("src.rs").exists(),
            "run mode must not descend into a run dir and reap its inner checkout"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn sweep_removes_a_dead_workers_empty_namespace() {
        // A crashed worker's namespace whose runs have all been reaped is left
        // empty; the shared-parent sweep removes it so repeated crashes don't
        // leak empty namespaces. (PID 99999 exceeds every platform's pid_max, so
        // it is deterministically dead.)
        let root = std::env::temp_dir().join(format!(
            "nano-sweep-deadns-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        let dead_ns = root.join("rust-worker-99999");
        let only_child = dead_ns.join("111");
        std::fs::create_dir_all(&only_child).unwrap();

        // max_age 0 reaps the (inactive) child, leaving the namespace empty, which
        // the sweep then removes.
        sweep_stale_runs(&root, Duration::ZERO, true);
        assert!(
            !dead_ns.exists(),
            "a dead worker's emptied namespace must be removed"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sweep_skips_active_run_however_aged() {
        // A long-running agent's dir can age past the retention window without
        // being touched; while it is registered as in-flight the sweep must
        // never reap it, even with max_age = 0.
        let root = std::env::temp_dir().join(format!(
            "nano-active-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        // Resolve any symlinked ancestor of the system temp dir (e.g. macOS's
        // /var -> /private/var) so the sweep's symlinked-ancestor guard does not
        // skip this exercise against an otherwise-honest root.
        let root = std::fs::canonicalize(&root).unwrap();

        let live = root.join("live-run");
        std::fs::create_dir_all(&live).unwrap();
        // Registered as absolute, exactly as `execute` does.
        let live_abs = std::path::absolute(&live).unwrap();
        let _guard = ActiveRunGuard::new(&live_abs);
        assert!(is_active_run(&live_abs));

        sweep_stale_runs(&root, Duration::ZERO, false);
        assert!(
            live.exists(),
            "an in-flight run must not be swept, however aged"
        );

        // Once the guard drops, the same dir becomes eligible again.
        drop(_guard);
        assert!(!is_active_run(&live_abs));
        sweep_stale_runs(&root, Duration::ZERO, false);
        assert!(!live.exists(), "a deregistered aged dir is swept normally");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sweep_remove_is_atomic_against_concurrent_registration() {
        // Regression for the check/remove TOCTOU, driven deterministically
        // through the test-only pause hook in `remove_if_inactive`: the sweep
        // is parked AFTER its liveness check has found the run inactive but
        // BEFORE the removal runs, and a retry's `ActiveRunGuard::new` for the
        // same path is attempted exactly in that window.
        //
        // What each implementation does with a registration in that window:
        //   - pre-fix (bare `is_active_run` + unlocked remove): no lock is
        //     held across the window, so the registration lands IMMEDIATELY
        //     and the removal then deletes the newly-registered live run out
        //     from under the retry.
        //   - fixed (mutex held across check+remove): the registration BLOCKS
        //     until the removal finishes, then registers — the delete never
        //     observes a live registration, and the retry's `prepare_run_dir`
        //     recreates the dir.
        //
        // The test asserts the observable split between the two:
        //   1. whether the registration completed while the sweep was parked
        //      (pre-fix: yes; fixed: no, it is blocked on the mutex), and
        //   2. that the live registration is never silently lost: after the
        //     sweep, `active_runs` holds the path and a subsequent sweep skips
        //     it (pre-fix: the guard registered fine but its dir was deleted —
        //     the invariant "registered ⇒ on disk" is violated).
        let root = std::env::temp_dir().join(format!(
            "nano-atomic-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        let run = root.join("retry-run");
        std::fs::create_dir_all(&run).unwrap();
        let run_abs = std::path::absolute(&run).unwrap();

        use std::sync::mpsc;
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let hook_path = run_abs.clone();
        *REMOVE_IF_INACTIVE_PAUSE.lock().unwrap() = Some((
            hook_path,
            Box::new(move || {
                // Parked in the check/remove window: tell the main thread, then
                // wait until it has attempted the racing registration.
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }),
        ));

        let sweep_path = run_abs.clone();
        let sweep = std::thread::spawn(move || {
            remove_if_inactive(&sweep_path, || {
                std::fs::remove_dir_all(&sweep_path).ok();
            })
        });

        // Wait until the sweep is provably parked between check and remove,
        // then attempt the registration a racing retry would make.
        entered_rx.recv().unwrap();
        let reg_path = run_abs.clone();
        let registration = std::thread::spawn(move || ActiveRunGuard::new(&reg_path));

        // Assertion 1: with the mutex held across the window, the registration
        // CANNOT complete while the sweep is parked. Give it a generous beat;
        // a completed registration here means no lock was held (the pre-fix
        // behaviour) — and the parked removal is about to delete a live run.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !registration.is_finished(),
            "registration completed inside the sweep's check/remove window: \
             the active-runs mutex is not held across it (pre-fix TOCTOU)"
        );

        // Release the sweep. The registration then unblocks and registers.
        // (No assertion on the sweep's own outcome here: what a hypothetical
        // re-checking implementation returns is not the invariant under test,
        // and joining the registration first keeps every failure a bounded
        // panic rather than a hang.)
        release_tx.send(()).unwrap();
        let guard = registration.join().unwrap();
        sweep.join().unwrap();

        // Assertion 2: the registration survived the sweep — the path is
        // active now, exactly as the retry expects after `ActiveRunGuard::new`
        // returns. The retry's own `prepare_run_dir` recreates the dir; the
        // sweep must then skip it no matter how aged it looks.
        assert!(
            is_active_run(&run_abs),
            "the registration that raced the sweep must not be lost"
        );
        std::fs::create_dir_all(&run).unwrap();
        sweep_stale_runs(&root, Duration::ZERO, false);
        assert!(
            run.exists(),
            "a run registered as active must never be swept, however aged"
        );
        drop(guard);

        // Once the guard drops, the same dir is eligible again.
        assert!(!is_active_run(&run_abs));
        sweep_stale_runs(&root, Duration::ZERO, false);
        assert!(!run.exists(), "a deregistered aged dir is swept normally");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sweep_recognises_an_active_run_under_a_parent_relative_root() {
        // Regression for the relative runs-dir mismatch (#36): `execute`
        // registers an in-flight run by its `normalize_run_path` form (absolute
        // AND lexically parent-free, e.g. `/parent/runs/123`), while a daemon
        // `--runs-dir ../runs` reaches the sweep as a path whose
        // `std::path::absolute` form keeps an interior `..`
        // (`/parent/cwd/../runs/123`). Those are different `active_runs` keys
        // for the SAME directory, so a sweep keyed on the un-normalized form
        // would reap a live workspace. The sweep must normalize its lookup key
        // with the same `normalize_run_path`, so the active registration is
        // honoured however the root was spelled.
        let base = std::env::temp_dir().join(format!(
            "nano-relroot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cwd_dir = base.join("cwd");
        let runs = base.join("runs");
        std::fs::create_dir_all(&cwd_dir).unwrap();
        std::fs::create_dir_all(&runs).unwrap();
        // Resolve platform symlinks (macOS /var -> /private/var) so the lexical
        // `..` below resolves honestly against the on-disk tree.
        let base = std::fs::canonicalize(&base).unwrap();
        let cwd_dir = std::fs::canonicalize(&cwd_dir).unwrap();
        let runs = std::fs::canonicalize(&runs).unwrap();

        let live = runs.join("live-run");
        std::fs::create_dir_all(&live).unwrap();
        // Register exactly as `execute` does: the normalized, parent-free form
        // (`normalize_run_path` and `resolve_run_path` agree on this valid,
        // parent-free path).
        let live_normalized = crate::safecwd::normalize_run_path(&live).unwrap();
        let _guard = ActiveRunGuard::new(&live_normalized);
        assert!(is_active_run(&live_normalized));

        // Sweep through a PARENT-RELATIVE spelling of the same root
        // (`<base>/cwd/../runs`), the shape a relative `--runs-dir` produces.
        let parent_relative_root = cwd_dir.join("..").join("runs");
        sweep_stale_runs(&parent_relative_root, Duration::ZERO, false);
        assert!(
            live.exists(),
            "an active run must survive a sweep keyed by a parent-relative root spelling"
        );

        drop(_guard);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn active_run_guard_is_refcounted_across_overlapping_retries() {
        // A job dir is keyed by job key and reused across retries, so an old
        // attempt's guard can still be dropping while the retry has already
        // re-registered the same path. A plain set would let that late drop
        // deregister the live retry; the refcount keeps the path registered
        // until the *last* overlapping guard drops.
        let root = std::env::temp_dir().join(format!(
            "nano-refcount-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let run = std::path::absolute(root.join("shared-run")).unwrap();

        let first = ActiveRunGuard::new(&run);
        let second = ActiveRunGuard::new(&run);
        assert!(is_active_run(&run));

        // The old attempt finishes and drops its guard; the live retry's
        // registration must survive.
        drop(first);
        assert!(
            is_active_run(&run),
            "overlapping registration must keep the path active"
        );

        // Only when the last guard drops is the path deregistered.
        drop(second);
        assert!(
            !is_active_run(&run),
            "path deregistered once the last guard drops"
        );
    }

    fn claim_is_registered(run_dir: &Path) -> bool {
        run_claims()
            .lock()
            .map(|m| m.contains_key(run_dir))
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn run_claim_is_exclusive_per_run_dir() {
        // Two attempts for the SAME run dir (a lease-recovery redelivery) must
        // not own the workspace at once: the second `acquire` blocks until the
        // first claim is released, so no concurrent wipe/mutate of the shared
        // path is possible.
        let run = std::path::absolute(std::env::temp_dir().join(format!(
            "nano-claim-excl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )))
        .unwrap();

        let first = RunClaim::acquire(&run).await;

        // A second acquire for the same dir cannot complete while the first is held.
        let run2 = run.clone();
        let second = tokio::spawn(async move { RunClaim::acquire(&run2).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !second.is_finished(),
            "a second claim on the same run dir must block while the first is held"
        );

        // Releasing the first lets the second proceed.
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("second claim must unblock once the first is released")
            .expect("claim task must not panic");
        drop(second);

        // Fully released: the map entry is pruned, so the claim table does not
        // grow without bound across distinct keys.
        assert!(
            !claim_is_registered(&run),
            "the claim map entry must be pruned once no attempt holds it"
        );
    }

    #[tokio::test]
    async fn run_claim_does_not_block_other_run_dirs() {
        // A long-held claim on one run dir must never block a claim on a
        // different run dir (the per-path lock is acquired without holding the
        // registry mutex).
        let base = std::env::temp_dir().join(format!(
            "nano-claim-indep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let a = std::path::absolute(base.join("run-a")).unwrap();
        let b = std::path::absolute(base.join("run-b")).unwrap();

        let held = RunClaim::acquire(&a).await;
        // Acquiring a DIFFERENT dir must succeed promptly despite `a` being held.
        let other = tokio::time::timeout(Duration::from_secs(5), RunClaim::acquire(&b))
            .await
            .expect("a claim on a different run dir must not block");
        drop(other);
        drop(held);
        assert!(!claim_is_registered(&a));
        assert!(!claim_is_registered(&b));
    }

    #[test]
    fn reap_run_dir_removes_tree_and_tolerates_missing() {
        // The pinned reap (Linux) and the path-based fallback must both remove a
        // populated run dir and treat an already-absent dir as success.
        let runs = std::env::temp_dir().join(format!(
            "nano-reap-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&runs).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor (macOS `temp_dir()`
        // is under the platform `/var` → `/private/var` symlink). The no-follow
        // reap legitimately refuses a symlinked ancestor, so an unresolved
        // `/var/...` runs root would be rejected (ENOTDIR) on macOS — mirror the
        // `unique_tmp` helper and the canonical runs root production reaps under.
        let runs = std::fs::canonicalize(&runs).unwrap();
        let run = runs.join("42");
        std::fs::create_dir_all(run.join("nested")).unwrap();
        std::fs::write(run.join("nested").join("result.json"), b"{}").unwrap();

        reap_run_dir(&runs, &run).expect("reap must remove a populated run dir");
        assert!(!run.exists(), "run dir must be gone after reap");

        // A second reap of the now-missing dir is a no-op success.
        reap_run_dir(&runs, &run).expect("reaping a missing dir must succeed");

        std::fs::remove_dir_all(&runs).ok();
    }

    #[cfg(unix)]
    #[test]
    fn sweep_refuses_symlinked_root() {
        // A symlinked `runs_dir` must never be traversed: `read_dir`/
        // `remove_dir_all` would follow the link and delete aged directories in
        // the *real* target, outside the configured workspace. The sweep must
        // refuse the symlinked root and leave the target untouched.
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(format!("nano-symlink-sweep-{uniq}"));
        std::fs::create_dir_all(&base).unwrap();

        // The real target holds an aged dir that a followed sweep would delete.
        let real_root = base.join("real-root");
        std::fs::create_dir_all(&real_root).unwrap();
        let aged = real_root.join("aged-run");
        std::fs::create_dir_all(&aged).unwrap();

        // A symlink standing in for a malicious `--runs-dir`.
        let link_root = base.join("link-root");
        std::os::unix::fs::symlink(&real_root, &link_root).unwrap();

        sweep_stale_runs(&link_root, Duration::ZERO, false);
        assert!(
            aged.exists(),
            "sweep of a symlinked root must not follow it and delete the target's contents"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// A unique scratch dir under the system temp root (no tempfile dep here).
    #[cfg(unix)]
    fn unique_tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "nano-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor (macOS `temp_dir()`
        // is commonly under the platform `/var` → `/private/var` symlink). The
        // no-follow prepare/sweep paths legitimately refuse a symlinked
        // component, so an unresolved `/var/...` scratch root would be rejected
        // (or its entries skipped) and the owner-only/symlink tests below would
        // fail on macOS. `saferoot::tests::scratch_root` canonicalizes for the
        // same reason.
        std::fs::canonicalize(&p).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn prepare_run_dir_pinned_creates_owner_only_and_wipes_stale() {
        use std::os::unix::fs::PermissionsExt;
        let runs = unique_tmp("prep-pinned");
        let run = runs.join("42");

        // A stale prior attempt with a leftover file must be wiped.
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(run.join("stale.json"), b"old").unwrap();

        prepare_run_dir(&runs, &run).unwrap();

        assert!(run.is_dir(), "run dir must exist after prepare");
        assert!(
            !run.join("stale.json").exists(),
            "a stale prior attempt must be wiped"
        );
        let mode = std::fs::metadata(&run).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "job dir must be locked to owner-only 0700");
        let root_mode = std::fs::metadata(&runs).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            root_mode, 0o700,
            "runs root must be locked to owner-only 0700"
        );

        std::fs::remove_dir_all(&runs).ok();
    }

    #[cfg(unix)]
    #[test]
    fn prepare_run_dir_pinned_refuses_symlinked_root() {
        // A symlinked runs root must be refused by the pinned open (ELOOP),
        // surfaced as an error — never silently followed to prepare a job dir
        // in the real target.
        let base = unique_tmp("prep-symlink");
        let real_root = base.join("real-runs");
        std::fs::create_dir_all(&real_root).unwrap();
        let link_root = base.join("link-runs");
        std::os::unix::fs::symlink(&real_root, &link_root).unwrap();

        let run = link_root.join("7");
        let err = prepare_run_dir(&link_root, &run).unwrap_err();
        assert!(
            !real_root.join("7").exists(),
            "a symlinked root must not be followed to create the job dir in the target"
        );
        let _ = err;

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn prepare_run_dir_pinned_does_not_materialise_root_through_a_symlinked_ancestor() {
        // Regression for the runs-root creation race (#36, review r4181639033):
        // the bootstrap used to no-follow-check the ancestors and then call the
        // path-based `create_dir_all(runs_dir)`. Between that check and the
        // create a same-UID actor could swap a writable ancestor for a symlink,
        // and `create_dir_all` would FOLLOW it — materialising the missing
        // runs-root suffix inside the attacker's target before the no-follow
        // open ever ran. The fix creates each missing component relative to its
        // pinned parent, so a symlinked component is refused, never followed.
        let base = unique_tmp("prep-root-race");
        let outside = base.join("attacker-target");
        std::fs::create_dir_all(&outside).unwrap();

        // A missing runs root whose PARENT is a symlink to the attacker target:
        // `runs_dir` = `<link>/runs`, where `link` -> `outside`. The old code
        // would create `<outside>/runs`; the fix must refuse the symlinked
        // `link` and create nothing outside.
        //
        // NOTE (adversarial-review caveat): this plants the symlink BEFORE the
        // call, so it is NOT red-before — the pre-fix `reject_symlinked_ancestors`
        // pre-check already bails on the static `link` ancestor, so these
        // assertions also pass against the old code. It pins the "refuse a
        // pre-existing symlinked ancestor, create nothing outside" guarantee the
        // fix must preserve, but it does NOT exercise the check→create race
        // window itself. A deterministic red-before race test would require a
        // test-only pause hook inside the pre-fix `create_dir_all`→`open_root`
        // window; the pre-fix `open_root_nofollow` resolves the whole path in one
        // atomic `openat2`, so there is no shared per-component seam to hook and
        // such a test is not feasible here. The race is instead closed by
        // construction: the fix creates each component relative to its pinned
        // parent, so a swapped-in symlink is refused by the no-follow open.
        let link = base.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let runs = link.join("runs");
        let run = runs.join("42");

        let err = prepare_run_dir(&runs, &run).unwrap_err();
        let _ = err;
        assert!(
            !outside.join("runs").exists(),
            "a symlinked ancestor must not be followed to materialise the runs root in the target"
        );
        assert!(
            !run.exists() && !outside.join("runs/42").exists(),
            "no run dir may be created through the symlinked ancestor"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn prepare_run_dir_pinned_creates_missing_root_components_owner_only() {
        // The handle-relative bootstrap must still materialise a multi-level
        // MISSING runs root (the common first-run case), locking each created
        // component to 0700 — now without any path-based create.
        use std::os::unix::fs::PermissionsExt;
        let base = unique_tmp("prep-root-missing");
        let runs = base.join("a/b/runs");
        let run = runs.join("7");

        prepare_run_dir(&runs, &run).unwrap();

        assert!(run.is_dir(), "run dir must exist after prepare");
        for dir in [&runs, &run] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} must be owner-only 0700", dir.display());
        }

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn sweep_pinned_does_not_follow_symlinked_entry_inside_aged_dir() {
        // An aged run dir containing a symlink to an outside directory must be
        // removed WITHOUT following the link: the link is deleted, its target
        // (and the target's contents) survive.
        let base = unique_tmp("sweep-nofollow");
        let runs = base.join("runs");
        std::fs::create_dir_all(&runs).unwrap();

        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious.txt"), b"keep me").unwrap();

        let aged = runs.join("aged-run");
        std::fs::create_dir_all(&aged).unwrap();
        std::os::unix::fs::symlink(&outside, aged.join("evil-link")).unwrap();

        sweep_stale_runs(&runs, Duration::ZERO, false);

        assert!(
            !aged.exists(),
            "aged run dir (and its symlink child) must be swept"
        );
        assert!(
            outside.join("precious.txt").exists(),
            "sweep must not follow the inner symlink and delete its target's contents"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn git_head_reads_a_real_checkout_head() {
        // The happy path: a real git work tree yields its HEAD sha, so the
        // bounded probe preserves the pre/post "did the agent commit" signal.
        let base = std::env::temp_dir().join(format!("nano-git-head-ok-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor (e.g. macOS
        // `/var`→`/private/var`): the probe now binds the run dir through the
        // no-follow handle, which legitimately refuses a symlinked component —
        // real daemon run dirs are provisioned through that same handle.
        let base = std::fs::canonicalize(&base).unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&base)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "x",
        ]);
        let head = git_head(&crate::safecwd::CwdHandle::open(&base).unwrap());
        assert!(
            head.as_deref()
                .is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "expected a 40-char hex HEAD, got {head:?}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn git_head_returns_none_for_a_non_git_dir() {
        // A no-repository run dir is "no commits", never an error.
        let base = std::env::temp_dir().join(format!("nano-git-head-nogit-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();
        assert_eq!(
            git_head(&crate::safecwd::CwdHandle::open(&base).unwrap()),
            None
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn git_head_refuses_a_symlinked_ancestor() {
        // The #35 class, for the HEAD probe: the probe now binds a pinned
        // handle, so a run dir REACHED THROUGH a symlinked ancestor cannot even
        // be pinned — `CwdHandle::open` refuses the path (fail closed) and the
        // caller reads the safe `None` ("no commits"). Before the fix the probe
        // used `current_dir(dir)`, re-resolved the symlink at spawn, and
        // returned the attacker's sha.
        let base = std::env::temp_dir().join(format!(
            "nano-git-head-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::remove_dir_all(&base).ok();
        // An attacker-controlled real git repo with a commit.
        let evil = base.join("evil");
        std::fs::create_dir_all(&evil).unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed");
        };
        git(&evil, &["init", "-q"]);
        git(
            &evil,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            ],
        );
        // `<base>/link` is a symlink to the attacker repo; the probe target
        // `<base>/link` therefore reaches the attacker repo only through it.
        let link = base.join("link");
        std::os::unix::fs::symlink(&evil, &link).unwrap();
        assert!(
            crate::safecwd::CwdHandle::open(&link).is_err(),
            "a run dir reached through a symlinked ancestor must be refused at pin time"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn git_head_stays_in_the_pinned_inode_after_an_ancestor_swap() {
        // The carried-capability guarantee: the probe binds the handle pinned
        // at provisioning, so swapping an ancestor for a symlink to an attacker
        // repo AFTER the pin cannot redirect the probe — it still reads the
        // real checkout's HEAD, never the attacker's.
        let base = std::env::temp_dir().join(format!(
            "nano-git-head-swap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::remove_dir_all(&base).ok();
        let base = std::fs::canonicalize({
            std::fs::create_dir_all(&base).unwrap();
            &base
        })
        .unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed");
        };
        let commit = |dir: &Path, msg: &str| {
            git(dir, &["init", "-q"]);
            git(
                dir,
                &[
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "user.name=t",
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    msg,
                ],
            );
        };
        // The real checkout, pinned as at provisioning.
        let ancestor = base.join("ancestor");
        let real = ancestor.join("run");
        std::fs::create_dir_all(&real).unwrap();
        commit(&real, "real");
        let handle = crate::safecwd::CwdHandle::open(&real).unwrap();

        // Attacker swaps the ancestor for a symlink to their own repo.
        let moved = base.join("ancestor-moved");
        std::fs::rename(&ancestor, &moved).unwrap();
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join("run")).unwrap();
        commit(&evil.join("run"), "evil");
        std::os::unix::fs::symlink(&evil, &ancestor).unwrap();

        // The probe still reads the REAL checkout's HEAD (the pinned inode,
        // now at `moved/run`), not the attacker's the path would resolve to.
        let real_head = {
            let out = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(moved.join("run"))
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        assert_eq!(
            git_head(&handle).as_deref(),
            Some(real_head.as_str()),
            "the probe must read the pinned inode's HEAD, not the swapped-in attacker repo"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn git_head_is_bounded_when_git_hangs() {
        // The class Copilot flagged: an agent-controlled checkout can make
        // `git rev-parse` block indefinitely (here `.git/HEAD` is a FIFO, so
        // git blocks opening it). The probe must return "no commits" within the
        // deadline instead of hanging settlement — and must not leak a child.
        let base = std::env::temp_dir().join(format!("nano-git-head-fifo-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        let git_dir = base.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor so the probe reaches
        // `git` (which then wedges on the FIFO) instead of being refused by the
        // no-follow cwd bind before it ever spawns — this test must exercise the
        // deadline, not the symlink refusal.
        let base = std::fs::canonicalize(&base).unwrap();
        // A FIFO never yields data, so git blocks reading HEAD.
        let mk = std::process::Command::new("mkfifo")
            .arg(git_dir.join("HEAD"))
            .output()
            .unwrap();
        assert!(mk.status.success(), "mkfifo failed");

        let started = Instant::now();
        let handle = crate::safecwd::CwdHandle::open(&base).unwrap();
        let head = git_head_timeout(&handle, Duration::from_millis(300));
        let elapsed = started.elapsed();
        assert_eq!(head, None, "a wedged probe must read as no commits");
        assert!(
            elapsed < Duration::from_secs(5),
            "probe must be bounded, took {elapsed:?}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn git_head_blocking_does_not_starve_the_runtime() {
        // The class Copilot flagged in review 5400515287: run inline, the
        // probe's `try_wait` + `thread::sleep` poll would occupy the single
        // Tokio worker for the whole wedged-probe timeout, starving a
        // concurrent task (the lease refresher's analogue). On the blocking
        // pool the worker stays free, so the concurrent task completes while
        // the probe is still waiting out its (wedged) deadline.
        let base =
            std::env::temp_dir().join(format!("nano-git-head-starve-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        let git_dir = base.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor so the probe reaches
        // (and wedges on) git rather than being refused early by the no-follow
        // cwd bind — this test must exercise the blocking-pool dispatch, not the
        // symlink refusal.
        let base = std::fs::canonicalize(&base).unwrap();
        // A FIFO never yields data, so git blocks reading HEAD until the
        // probe's deadline kills it — the probe takes the full timeout.
        let mk = std::process::Command::new("mkfifo")
            .arg(git_dir.join("HEAD"))
            .output()
            .unwrap();
        assert!(mk.status.success(), "mkfifo failed");

        let started = Instant::now();
        let handle = crate::safecwd::CwdHandle::open(&base).unwrap();
        let probe = tokio::spawn(git_head_blocking(handle));
        // Yield so the probe is dispatched to the blocking pool before the
        // concurrent task starts.
        tokio::task::yield_now().await;
        // The lease-refresher analogue: a task that must keep running while the
        // probe waits. On a single worker it can only complete if the probe is
        // NOT holding that worker.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let waited = started.elapsed();
        assert!(
            waited < GIT_HEAD_TIMEOUT,
            "the runtime worker was starved for the whole probe ({waited:?}); the probe must run on the blocking pool"
        );
        // The wedged probe still resolves to "no commits" once its deadline
        // kills the blocked git.
        assert_eq!(probe.await.unwrap(), None);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detect_commits_recognises_advance_and_first_commit() {
        // An existing HEAD that advanced is a commit.
        assert!(detect_commits(Some("aaa"), Some("bbb"), true));
        // An unchanged HEAD is no commit.
        assert!(!detect_commits(Some("aaa"), Some("aaa"), true));
        // A newly provisioned (HEAD-less) repo that gains its first commit IS a
        // commit — Node's non-empty `gitResult.commits` — so a quiet pipe agent
        // that committed real work is not misread as an empty run and retried.
        assert!(detect_commits(None, Some("aaa"), true));
        // ...but only when the job actually provisioned a repository: a non-repo
        // run dir (no checkout) that somehow reads a HEAD stays "no commits".
        assert!(!detect_commits(None, Some("aaa"), false));
        // No checkout before or after (a plain no-repository run): no commits.
        assert!(!detect_commits(None, None, true));
        assert!(!detect_commits(None, None, false));
        // HEAD disappeared (agent force-reset to nothing): not a new commit.
        assert!(!detect_commits(Some("aaa"), None, true));
    }

    #[test]
    fn retained_or_stranded_result_counts_as_commits() {
        // The HEAD compare says "no commit" (checkout unchanged) and finalize
        // enumerated no pushable commits — but an inconclusive/incomplete scan
        // (`retain`) or stranded work the enumeration cleared (`work_found`) each
        // mean the run dir may hold the ONLY copy of agent work. Either flag alone
        // MUST make the run count as having commits so it is never failed as empty
        // and retried (the retry wipes the job-keyed run dir).
        assert!(retained_result_counts_as_commits(true, false, false));
        assert!(retained_result_counts_as_commits(false, true, false));
        // A genuinely empty run — no retain, no stranded work, HEAD unmoved — is
        // still correctly "no commits" so the empty detector can fail it.
        assert!(!retained_result_counts_as_commits(false, false, false));
        // A moved HEAD counts regardless of the finalize flags.
        assert!(retained_result_counts_as_commits(false, false, true));
    }

    #[test]
    fn provisioned_commits_are_retained_not_reaped() {
        // A provisioned checkout that advanced HEAD whose commits were NOT pushed
        // lives ONLY in the run dir, so a successful run must NOT reap it (that
        // would destroy the sole copy).
        assert!(!may_reap_completed_run(true, true, false, false));
        // Once finalize PUSHED those commits they are durable off-box, so the run
        // dir reaps normally.
        assert!(may_reap_completed_run(true, true, true, false));
        // A provisioned run that made no commit has nothing durable to lose.
        assert!(may_reap_completed_run(true, false, false, false));
        // A non-repository run never holds commits, so it is always reapable.
        assert!(may_reap_completed_run(false, false, false, false));
        assert!(may_reap_completed_run(false, true, false, false));
    }

    #[test]
    fn finalize_retain_flag_forces_retention() {
        // `retain` is finalize's stranded-work / incomplete-scan signal. It must
        // force retention INDEPENDENTLY of the HEAD compare: a side-branch or
        // detached commit that is then abandoned leaves the final HEAD unchanged
        // (so `has_commits` reads false) while the only copy of that work sits in
        // the run dir — the HEAD compare alone would reap it.
        assert!(!may_reap_completed_run(true, false, false, true));
        assert!(!may_reap_completed_run(true, true, false, true));
        // Even a pushed run is retained when finalize flagged an incomplete scan.
        assert!(!may_reap_completed_run(true, true, true, true));
    }

    #[cfg(unix)]
    #[test]
    fn canonicalize_existing_base_resolves_platform_symlink_in_base() {
        // A PLATFORM symlink in the existing base (macOS `/var` -> `/private/var`)
        // must be resolved so the no-follow ancestor checks do not reject a
        // legitimate temp root, while a not-yet-created leaf is left unresolved.
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(format!("nano-canon-{uniq}"));
        let real = base.join("real-base");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link-base");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // The not-yet-created worker leaf under a symlinked base resolves the
        // base symlink but keeps the leaf literal (unresolved).
        let requested = link.join("rust-worker-123");
        let resolved = canonicalize_existing_base(&requested).unwrap();
        let want = std::fs::canonicalize(&real)
            .unwrap()
            .join("rust-worker-123");
        assert_eq!(resolved, want);
        // The leaf was NOT created or resolved through a planted link.
        assert!(!resolved.exists());

        // After the checks, the ancestor walk over the canonical path passes
        // (the platform link is gone) and a real leaf can be created.
        reject_symlink(&resolved).unwrap();
        reject_symlinked_ancestors(&resolved).unwrap();

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn runs_leaf_swapped_to_symlink_after_create_is_rejected_not_followed() {
        // Regression for the run-dir setup in `work::run`: after the worker leaf
        // is created, a same-UID process could swap it for a symlink before first
        // use. The post-create re-validation must REJECT that swapped leaf
        // (no-follow `reject_symlink`), not FOLLOW it to the attacker target as a
        // bare `std::fs::canonicalize` would — which this test also demonstrates.
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(format!("nano-leafswap-{uniq}"));
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();

        // The attacker-chosen target the swapped leaf points at (outside the leaf).
        let outside = base.join("attacker-target");
        std::fs::create_dir_all(&outside).unwrap();

        // The legitimate leaf is created, then swapped for a symlink to `outside`.
        let leaf = base.join("rust-worker-123");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::remove_dir(&leaf).unwrap();
        std::os::unix::fs::symlink(&outside, &leaf).unwrap();

        // The fix: no-follow re-validation rejects the swapped leaf.
        assert!(
            reject_symlink(&leaf).is_err(),
            "a leaf swapped to a symlink after create must be rejected no-follow"
        );

        // The bug it replaced: `canonicalize` would FOLLOW the swap to the
        // attacker target, and a subsequent no-follow check on that (real) target
        // would pass — redirecting the run/sweep root outside the workspace.
        let followed = std::fs::canonicalize(&leaf).unwrap();
        assert_eq!(
            followed,
            std::fs::canonicalize(&outside).unwrap(),
            "canonicalize follows the swapped leaf to the attacker target (the bug)"
        );
        assert!(
            reject_symlink(&followed).is_ok(),
            "the followed target is a real dir, so a post-canonicalize check would wrongly pass"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn canonicalize_existing_base_rejects_precreated_symlink_leaf() {
        // Regression for the run-dir setup in `work::run`: an attacker who
        // predicts the worker PID can pre-create the `rust-worker-<pid>` leaf as
        // a symlink before the worker starts. Canonicalizing the *whole* path
        // would follow that planted leaf to its target, so the no-follow checks
        // inspect the (real) target and pass — redirecting provisioning/sweeping
        // outside the configured root. `work::run` now canonicalizes only the
        // PARENT and re-appends the leaf unresolved, so the leaf stays literal
        // and `reject_symlink` rejects the planted link.
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(format!("nano-leafpre-{uniq}"));
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();

        // The attacker-chosen target (outside the leaf) the planted link points at.
        let outside = base.join("attacker-target");
        std::fs::create_dir_all(&outside).unwrap();
        // Pre-create the worker leaf as a symlink to that target.
        let requested = base.join("rust-worker-123");
        std::os::unix::fs::symlink(&outside, &requested).unwrap();

        // The fix (as `work::run` applies it): canonicalize only the parent, then
        // re-append the leaf. The leaf is left unresolved (still the planted
        // link), so the no-follow check rejects it.
        let parent = canonicalize_existing_base(requested.parent().unwrap()).unwrap();
        let resolved = parent.join(requested.file_name().unwrap());
        assert_eq!(
            resolved, requested,
            "re-appending the leaf to the canonical parent keeps the planted link literal"
        );
        assert!(
            reject_symlink(&resolved).is_err(),
            "the pre-created symlink leaf must be rejected no-follow"
        );

        // The bug it replaced: canonicalizing the whole path follows the planted
        // leaf to the attacker target, which a no-follow check would then accept.
        let followed = canonicalize_existing_base(&requested).unwrap();
        assert_eq!(
            followed,
            std::fs::canonicalize(&outside).unwrap(),
            "whole-path canonicalize follows the planted leaf to the attacker target (the bug)"
        );
        assert!(
            reject_symlink(&followed).is_ok(),
            "the followed target is a real dir, so the check would wrongly pass"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlinked_ancestors_below_rejects_user_tail_but_spares_anchor() {
        // Regression for `work::run`: canonicalizing the configurable run-dir
        // parent resolves EVERY existing symlink in it — including a planted
        // ancestor (`--runs-dir /shared/link/runs` with `link` -> an attacker
        // target) — so the no-follow checks then inspect only the canonical
        // target and pass, redirecting the workspace and the stale-run sweep.
        // The fix validates the ORIGINAL path no-follow at/below a trusted
        // anchor BEFORE canonicalizing, so the planted link is rejected, while
        // a PLATFORM symlink in the anchor itself (macOS `/var`) is spared.
        let uniq = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(format!("nano-below-{uniq}"));
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();

        // Trusted anchor (stands in for the state home / temp base).
        let anchor = base.join("anchor");
        std::fs::create_dir_all(&anchor).unwrap();
        // A planted symlink in the operator-controlled tail below the anchor.
        let outside = base.join("attacker-target");
        std::fs::create_dir_all(&outside).unwrap();
        let planted = anchor.join("link");
        std::os::unix::fs::symlink(&outside, &planted).unwrap();
        let requested = planted.join("rust-worker-123");

        // The planted ancestor below the anchor is rejected on the ORIGINAL path.
        assert!(
            reject_symlinked_ancestors_below(&requested, &anchor).is_err(),
            "a planted symlink below the trusted anchor must be rejected no-follow"
        );
        // ...even though canonicalizing it would silently follow to the target.
        assert_eq!(
            std::fs::canonicalize(requested.parent().unwrap()).unwrap(),
            std::fs::canonicalize(&outside).unwrap(),
            "canonicalize follows the planted ancestor (the bypass being prevented)"
        );

        // A clean tail below the anchor passes.
        let clean = anchor.join("real").join("rust-worker-123");
        std::fs::create_dir_all(clean.parent().unwrap()).unwrap();
        assert!(reject_symlinked_ancestors_below(&clean, &anchor).is_ok());

        // A symlink IN the anchor itself is spared (the platform-link case): the
        // walk stops at the anchor and does not inspect the anchor's own type.
        let real_anchor = base.join("real-anchor");
        std::fs::create_dir_all(&real_anchor).unwrap();
        let platform_anchor = base.join("platform-anchor");
        std::os::unix::fs::symlink(&real_anchor, &platform_anchor).unwrap();
        let under = platform_anchor.join("rust-worker-123");
        assert!(
            reject_symlinked_ancestors_below(&under, &platform_anchor).is_ok(),
            "a platform symlink in the trusted anchor must not be rejected"
        );

        std::fs::remove_dir_all(&base).ok();
    }
}
