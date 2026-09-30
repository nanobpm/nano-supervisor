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
    /// (the daemon's `--with-lease`). `work` requests leases but, like the Node
    /// plugin, runs unfenced when the engine does not issue one.
    pub require_lease: bool,
    /// Stop after handling this many jobs (`work --max-jobs`); `None` = forever.
    pub max_jobs: Option<usize>,
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
                log(&format!(
                    "slot {} activation of {job_type:?} failed: {e:#}; retrying in 5s",
                    cfg.worker_name
                ));
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
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
                // The CLI's `--with-lease` contract is to fail LOUDLY when the
                // engine does not issue leases (see the flag's help). Merely
                // skipping would leave the activation to expire and be
                // re-delivered forever — a silent spin that never fences. If the
                // engine returns an unleased activation here it will do so for
                // every job, so the requested fencing is impossible: shut the
                // whole daemon down loudly instead of running on unfenced.
                log(&format!(
                    "slot {}: job {} activated without a lease token under --with-lease; the engine \
                     is not issuing leases, so the requested fencing is impossible — shutting the \
                     daemon down instead of running unfenced",
                    cfg.worker_name,
                    job.job.job_key.value()
                ));
                let _ = fatal.send(true);
                return;
            }
            handle(&jobs, &cfg, job).await;
            handled += 1;
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

async fn handle(jobs: &Jobs, cfg: &Arc<SlotConfig>, Job { job, lease }: Job) {
    let key = job.job_key.value().to_string();
    let started = Instant::now();
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
        refreshes.clone(),
        lost_tx,
        stop_rx,
    ));

    // Run the job on its own task so a panic fails only THIS job (the slot loop
    // survives). Race it against activation loss so a superseded worker stops.
    let mut exec = tokio::spawn(execute(cfg.clone(), key.clone(), job.clone()));
    let raced = tokio::select! {
        r = &mut exec => Some(match r {
            Ok(inner) => inner,
            Err(join) => Err(anyhow::anyhow!(
                "slot task for job {key} panicked: {join}"
            )),
        }),
        // Drop the watch guard immediately; the abort/await happens below.
        _ = lost_rx.wait_for(|lost| *lost) => None,
    };
    // Stop the refresher and wait for it to fully exit BEFORE sampling the
    // activation-loss watch, so the watch value cannot change under us. Signal a
    // graceful stop and AWAIT the task — never `abort()`: aborting could cancel
    // an in-flight `extend` in the window between our exec completing and the
    // stop, dropping the very request that would report a 404/409 fence. The
    // refresher would then never publish the loss, and we would settle the job
    // with a stale lease — violating the no-settle-after-fencing guarantee. A
    // graceful stop lets any in-flight extend run to completion and publish its
    // result first; once the task is joined no further writes to the watch can
    // happen, so the value we read below is final.
    let _ = stop_tx.send(true);
    let _ = refresher.await;
    // Re-check the activation-loss watch after the select. `select!` can pick the
    // `exec` branch even when the refresher set `lost` to true in the same tick
    // (both futures are ready), which would otherwise settle the job with a stale
    // lease after a 404/409 fence. Downgrade an outcome to "lost" whenever the
    // activation was fenced, so we never `complete`/`fail` a job we no longer own.
    let outcome = reconcile_lost(raced, *lost_rx.borrow());
    if outcome.is_none() {
        // We lost the activation: actually stop the agent instead of detaching
        // the task. Aborting drops the execute future, whose child processes are
        // spawned `kill_on_drop`, so the clone/agent tree is torn down before we
        // return.
        exec.abort();
        let _ = exec.await;
    }
    let elapsed = started.elapsed().as_secs_f32();
    let n = refreshes.load(Ordering::Relaxed);

    match outcome {
        None => log(&format!(
            "job {key}: activation lost after {elapsed:.1}s; agent stopped, job NOT settled (the engine will redeliver it)"
        )),
        Some(Ok(Settle::Complete(vars))) => match jobs.complete(&key, vars, &lease).await {
            Ok(()) => log(&format!(
                "job {key} completed in {elapsed:.1}s (refreshes={n})"
            )),
            Err(e) => log(&format!("job {key}: complete failed: {e:#}")),
        },
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
            match jobs.fail(&key, retries, &msg, vars, &lease).await {
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

/// Restrict a directory to owner-only access (mode 0700) on Unix, so job data
/// placed under the shared temp directory is not readable/traversable by other
/// local users. A no-op on non-Unix platforms and when the path is absent.
fn restrict_dir_mode(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if dir.exists() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("restricting permissions on {}", dir.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Bail when `dir` (or the runs root above it) is a symlink. The check/remove/
/// create sequence in [`execute`] is not atomic: another local process can swap
/// a numeric job dir — or the runs root — for a symlink between operations, so
/// the agent cwd and `restrict_dir_mode` would otherwise target a path outside
/// `runs_dir`. `symlink_metadata` inspects the link itself rather than
/// following it, so a dangling or replaced link is still caught.
fn reject_symlink(dir: &Path) -> Result<()> {
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
fn reject_symlinked_ancestors(dir: &Path) -> Result<()> {
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

/// Prepare a per-job run directory under `runs_dir` with the full symlink and
/// permission hardening, wiping any stale prior-attempt contents. Shared by the
/// `daemon` and `work` (both run jobs through [`execute`]) so every run gets
/// identical protection: reject a symlinked leaf / ancestor before *and* after
/// the non-atomic remove+create (a local process can swap the fresh dir for a
/// link in between), then restrict both the runs root and the job dir to 0700 so
/// the clone, prompt-derived files, and `result.json` are not readable by other
/// local users regardless of umask — this still matters when `runs_dir` falls
/// back to a shared system temp location.
pub(crate) fn prepare_run_dir(runs_dir: &Path, run_dir: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        match prepare_run_dir_pinned(runs_dir, run_dir) {
            Ok(()) => return Ok(()),
            // Kernel too old for `openat2` (pre-5.6): fall through to the
            // best-effort path-based checks below.
            Err(crate::saferoot::PinError::Unsupported) => {}
            // A refused symlinked component (ELOOP) or any other error is a
            // real, security-relevant outcome — surface it, never retry the
            // weaker path-based version.
            Err(crate::saferoot::PinError::Io(e)) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("preparing run dir {}", run_dir.display())));
            }
        }
    }
    prepare_run_dir_path_based(runs_dir, run_dir)
}

/// `prepare_run_dir` via an `openat2(RESOLVE_NO_SYMLINKS)` handle pinned to the
/// runs root: the stale-wipe, create, and 0700 chmod of both the root and the
/// job dir all happen *relative to that pinned handle*, so a same-UID actor
/// cannot swap `runs_dir` (or an ancestor) for a symlink between a check and the
/// operation and redirect the remove/create outside the workspace. This is the
/// atomic fix the path-based `reject_symlink` re-checks can only approximate.
/// `run_dir` is always `<runs_dir>/<key>` (a single, engine-validated numeric
/// component), so its `file_name()` is the child directory to prepare.
#[cfg(target_os = "linux")]
fn prepare_run_dir_pinned(
    runs_dir: &Path,
    run_dir: &Path,
) -> std::result::Result<(), crate::saferoot::PinError> {
    use crate::saferoot::{DirHandle, PinError};
    let name = run_dir.file_name().ok_or_else(|| {
        PinError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("run dir {} has no final component", run_dir.display()),
        ))
    })?;
    // Bootstrap: the runs root must exist before it can be opened no-follow. A
    // symlinked component is still caught the instant we open it (openat2
    // refuses it), so this only ever materialises real directories under an
    // honest root; a planted symlink ancestor fails the open rather than being
    // silently followed. But `create_dir_all` itself *follows* symlinks, so an
    // attacker-planted symlinked ancestor could make the bootstrap materialise
    // the root through it (in an attacker-chosen target) *before* the no-follow
    // open ever runs. Reject a symlinked existing ancestor first so the create
    // cannot be redirected out of the workspace.
    if let Err(e) = reject_symlinked_ancestors(runs_dir) {
        return Err(PinError::Io(std::io::Error::other(e.to_string())));
    }
    std::fs::create_dir_all(runs_dir).map_err(PinError::Io)?;
    let root = DirHandle::open_root_nofollow(runs_dir)?;
    root.prepare_child_dir(name, 0o700).map_err(PinError::Io)?;
    Ok(())
}

/// Path-based `prepare_run_dir`: the pre-`openat2` fallback (non-Linux, or a
/// Linux kernel older than 5.6). Rejects a symlinked leaf / ancestor before
/// *and* after the non-atomic remove+create — a best-effort approximation of
/// the pinned-handle guarantee that cannot fully close the TOCTOU window.
fn prepare_run_dir_path_based(runs_dir: &Path, run_dir: &Path) -> Result<()> {
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
    Ok(())
}

/// Reap a completed run directory under `runs_dir` with the same pinned
/// no-follow guarantee as [`prepare_run_dir`]: the removal happens *relative to*
/// an `openat2(RESOLVE_NO_SYMLINKS)` handle on the runs root, so a same-UID
/// actor cannot swap `run_dir` (or an ancestor) for a symlink between the
/// job's completion and this cleanup and redirect a path-based
/// `remove_dir_all` into deleting an unrelated tree outside the workspace.
/// Falls back to a plain `remove_dir_all` only where the pinned path is
/// unavailable (non-Linux, or a pre-5.6 kernel without `openat2`). `run_dir` is
/// always `<runs_dir>/<key>` (a single engine-validated component), so its
/// `file_name()` is the child to remove. A missing dir is treated as success.
pub(crate) fn reap_run_dir(runs_dir: &Path, run_dir: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use crate::saferoot::{DirHandle, PinError};
        if let Some(name) = run_dir.file_name() {
            match DirHandle::open_root_nofollow(runs_dir) {
                Ok(root) => return root.remove_tree(name),
                // Kernel too old for `openat2` (pre-5.6): fall through to the
                // best-effort path-based remove below.
                Err(PinError::Unsupported) => {}
                // A refused symlinked root (ELOOP) or any other error is a real,
                // security-relevant outcome — surface it, never retry the weaker
                // path-based remove that would follow the very link we refused.
                Err(PinError::Io(e)) => return Err(e),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = runs_dir;
    match std::fs::remove_dir_all(run_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
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

/// Whether `path` is a currently in-flight run dir that must not be swept.
fn is_active_run(path: &Path) -> bool {
    active_runs()
        .lock()
        .map(|map| map.contains_key(path))
        .unwrap_or(false)
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
pub(crate) fn sweep_stale_runs(runs_dir: &Path, max_age: Duration) {
    #[cfg(target_os = "linux")]
    {
        match sweep_stale_runs_pinned(runs_dir, max_age) {
            Ok(()) => return,
            // Kernel too old for `openat2` (pre-5.6): fall through to the
            // best-effort path-based sweep below.
            Err(crate::saferoot::PinError::Unsupported) => {}
            // A refused symlinked root (ELOOP) or any other error: skip the
            // sweep entirely rather than risk traversing a redirected root —
            // exactly the behaviour the path-based version's up-front reject
            // provided, now enforced atomically at open time.
            Err(crate::saferoot::PinError::Io(e)) => {
                log(&format!(
                    "skipping stale-run sweep of {}: {e} (possible local symlink attack)",
                    runs_dir.display()
                ));
                return;
            }
        }
    }
    sweep_stale_runs_path_based(runs_dir, max_age);
}

/// `sweep_stale_runs` via an `openat2(RESOLVE_NO_SYMLINKS)` handle pinned to the
/// runs root: `read_dir`, the per-entry `lstat`, and every `remove` run
/// *relative to that pinned handle* with the `*at` syscalls, never re-resolving
/// the path. A same-UID actor can therefore not swap `runs_dir` (or an
/// ancestor) for a symlink between the check and the traversal to redirect the
/// sweep's deletions outside the workspace — the race path-based re-checks
/// cannot atomically close. Descent into an aged run dir is likewise no-follow,
/// so a symlink *inside* a swept dir deletes the link, never its target.
#[cfg(target_os = "linux")]
fn sweep_stale_runs_pinned(
    runs_dir: &Path,
    max_age: Duration,
) -> std::result::Result<(), crate::saferoot::PinError> {
    use crate::saferoot::{DirHandle, PinError};
    let root = match DirHandle::open_root_nofollow(runs_dir) {
        Ok(h) => h,
        // A missing runs_dir (first job) is nothing to sweep — not an error;
        // the prepare path will (re)create and validate it.
        Err(PinError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // `execute` registers each in-flight run by its ABSOLUTE path, so resolve
    // the root once to compare entries against the active set correctly even
    // when `runs_dir` is relative.
    let runs_abs = std::path::absolute(runs_dir).unwrap_or_else(|_| runs_dir.to_path_buf());
    let now = SystemTime::now();
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
        // Never reap a live run, however old its mtime.
        if is_active_run(&runs_abs.join(&name)) {
            continue;
        }
        // Age from the directory's own mtime; keep it when the platform
        // withholds a modified time rather than risk deleting a fresh run.
        let aged_out = meta
            .modified
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= max_age);
        if !aged_out {
            continue;
        }
        let path = runs_dir.join(&name);
        match root.remove_tree(&name) {
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
    Ok(())
}

/// Path-based `sweep_stale_runs`: the pre-`openat2` fallback (non-Linux, or a
/// Linux kernel older than 5.6). Rejects a symlinked root/ancestor up front,
/// then reads and removes by path — a best-effort approximation that cannot
/// fully close the check/traverse TOCTOU the pinned version does.
fn sweep_stale_runs_path_based(runs_dir: &Path, max_age: Duration) {
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
        // Never reap a live run, however old its mtime. `execute` registers the
        // run dir as its absolute path, so match against that (a relative
        // `runs_dir` would otherwise yield a relative entry path that never
        // compares equal to the stored absolute one).
        let abs = std::path::absolute(&path).unwrap_or_else(|_| path.clone());
        if is_active_run(&abs) {
            continue;
        }
        // Age from the directory's own mtime. If the platform withholds a
        // modified time, keep the dir rather than risk deleting a fresh run.
        let aged_out = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= max_age);
        if !aged_out {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
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
    // Absolute, so the agent (whose cwd is inside `run_dir`) and the worker
    // resolve `AGENT_RESULT_FILE` identically. Purely lexical — the symlink
    // hardening in `prepare_run_dir` still inspects the real on-disk structure.
    let run_dir = std::path::absolute(cfg.runs_dir.join(&key)).with_context(|| {
        format!(
            "resolving absolute run dir under {}",
            cfg.runs_dir.display()
        )
    })?;
    // Register this run dir as in-flight for the whole job so a concurrent
    // slot's retention sweep can never reap it.
    let _active = ActiveRunGuard::new(&run_dir);
    sweep_stale_runs(&cfg.runs_dir, FAILED_RUN_RETENTION);
    prepare_run_dir(&cfg.runs_dir, &run_dir)?;
    let agent_cwd = match &env.repository {
        Some(repo) => {
            log(&format!(
                "job {key}: cloning {} ({})",
                redact_url(&repo.url),
                repo.provider
            ));
            crate::provision::provision(repo, &run_dir, cfg.clone_timeout)
                .await
                .context("provisioning repository")?
        }
        None => run_dir.clone(),
    };

    let result_file = run_dir.join("result.json");
    let agent_env = build_agent_env(&cfg, &key, &job, &result_file);
    let payload = build_agent_payload(&cfg, &job, &env);
    let acp = cfg.hire.protocol == Protocol::Acp;

    // First turn: every protocol receives the JSON job payload (Node's
    // `buildAgentStdin` — ACP delivers it verbatim as the `session/prompt` text).
    let first = run_agent(&cfg, &key, &agent_cwd, &payload.to_string(), &agent_env).await;

    // Result-nudge (Node #678): a clean run that produced output but no usable
    // result gets exactly ONE bounded "emit your result now" turn, in a fresh
    // agent process in the same workspace, writing to the same result file.
    let already = result::read_result_file(&result_file)
        .or_else(|| result::parse_result_from_stdout(&first.stdout));
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
        run.truncated = run.truncated || capped;
        run.has_turns = run.has_turns || nudge.has_turns;
        let recovered = result::read_result_file(&result_file)
            .or_else(|| result::parse_result_from_stdout(&run.stdout))
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

    // Read the agent's structured result (the file, else a stdout sentinel) and
    // remove the result channel, as the Node plugin does.
    let raw_result = result::read_result_file(&result_file)
        .or_else(|| result::parse_result_from_stdout(&run.stdout));
    let _ = std::fs::remove_file(&result_file);
    let envelope = build_result_envelope(&run, &cfg.hire.sandbox, raw_result.as_ref());
    let name = &cfg.hire.name;
    let envelope_vars = || HashMap::from([(AGENT_RESULT_KEY.to_string(), envelope.clone())]);

    let settle = if !run.ok {
        let detail = run.error.clone().unwrap_or_else(|| match run.exit_code {
            Some(c) => format!("exit code {c}"),
            None => "terminated by signal".to_string(),
        });
        Settle::Fail {
            message: format!("agent \"{name}\" failed: {detail}"),
            vars: Some(envelope_vars()),
        }
    } else if let Some(reason) =
        result::detect_empty(raw_result.as_ref(), &run.stdout, run.has_turns)
    {
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
        Settle::Complete(vars)
    };

    // Reap the run directory unless `--keep-runs`. Only successful runs are
    // reaped here; a failed run is left for post-mortem and aged out by
    // `sweep_stale_runs`. Best-effort, pinned no-follow (see `reap_run_dir`).
    if matches!(settle, Settle::Complete(_)) && !cfg.keep_runs {
        if let Err(e) = reap_run_dir(&cfg.runs_dir, &run_dir) {
            log(&format!(
                "job {key}: failed to reap run dir {}: {e:#}",
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
    cwd: &Path,
    stdin: &str,
    env: &[(String, String)],
) -> RunResult {
    match cfg.hire.protocol {
        Protocol::Acp => {
            let mut agent = match Agent::spawn(&cfg.hire.command, &cfg.hire.args, cwd, env) {
                Ok(a) => a,
                Err(e) => {
                    return RunResult {
                        error: Some(format!("{e:#}")),
                        ..RunResult::default()
                    }
                }
            };
            log(&format!(
                "job {key}: acp agent pid {} in {}",
                agent.pid().unwrap_or(0),
                cwd.display()
            ));
            let out = agent.run(cwd, stdin, cfg.idle_timeout).await;
            agent.shutdown().await;
            match out {
                Ok(o) => {
                    log(&format!(
                        "job {key}: acp turn ended ({}; {} update(s), {} tool call(s), {} permission(s) granted)",
                        o.stop_reason, o.updates, o.tool_calls, o.permissions_granted
                    ));
                    let (stdout, truncated) = cap_stdout_tail(o.text);
                    RunResult {
                        ok: true,
                        stdout,
                        truncated,
                        exit_code: Some(0),
                        has_turns: o.updates > 0,
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
            log(&format!("job {key}: pipe agent in {}", cwd.display()));
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
                    let (stdout, truncated) = cap_stdout_tail(o.stdout);
                    let error = o.idle_timed_out.then(|| {
                        format!(
                            "agent produced no output for {}s (idle timeout)",
                            cfg.idle_timeout.as_secs()
                        )
                    });
                    RunResult {
                        ok: o.exit_code == Some(0) && !o.idle_timed_out,
                        stdout,
                        truncated,
                        exit_code: o.exit_code,
                        timed_out: o.idle_timed_out,
                        error,
                        has_turns: false,
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
    let chars: Vec<char> = prior_stdout.chars().collect();
    let ctx: String = chars[chars.len().saturating_sub(NUDGE_CONTEXT_CAP_CHARS)..]
        .iter()
        .collect();
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
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    // Hire-configured env first, so reserved vars below can never be shadowed.
    for (k, v) in &cfg.hire.env {
        env.push((k.clone(), v.clone()));
    }
    env.push(("NANO_JOB_KEY".into(), key.to_string()));
    env.push(("NANO_AGENT_NAME".into(), cfg.worker_name.clone()));
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
    if s.chars().count() <= max {
        return s.to_string();
    }
    // Hard cut, no ellipsis — the Node plugin's `.slice(0, 2000)`.
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let env = build_agent_env(&cfg(), "42", &job, rf);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("NANO_AGENTIC"), Some("off"));
        assert_eq!(get("NANO_JOB_KEY"), Some("42"));
        assert_eq!(get("AGENT_RESULT_FILE"), Some("/tmp/r.json"));
        assert_eq!(get("AGENT_JOB_TYPE"), Some("senior:pr-review"));
        assert_eq!(get("AGENT_PROFILE"), Some("coder"));
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
            // connection source (see `profile::env_has_oauth`), so basic-auth
            // credentials supplied that way must be stripped too.
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
        let env = build_agent_env(&cfg(), "1", &job, std::path::Path::new("/tmp/r.json"));
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
        let env = build_agent_env(&c, "1", &job, std::path::Path::new("/tmp/r.json"));
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
    fn acp_prompt_is_redacted_of_clone_credentials() {
        // The ACP branch forwards the prompt verbatim, so a credential URL
        // embedded in a task prompt must be scrubbed by the same `redact_url`
        // path the pipe payload uses before it reaches the ACP agent. Build the
        // userinfo at runtime so no credential-like literal is stored in source.
        let token = format!("{}-{}", "x-access", "token");
        let secret = format!("pat{}value", 1234);
        let prompt = format!("clone https://{token}:{secret}@github.com/o/r.git and build");
        let safe_prompt = redact_url(&prompt);
        assert!(
            !safe_prompt.contains(&secret),
            "clone credential must not reach the ACP agent prompt: {safe_prompt}"
        );
        assert!(safe_prompt.contains("https://github.com/o/r.git"));
        assert!(safe_prompt.contains("and build"));
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
        sweep_stale_runs(&root, Duration::ZERO);
        assert!(!aged.exists(), "aged-out run dir should be swept");
        assert!(stray.exists(), "stray files must be left alone");

        // A fresh dir with a long retention window is kept.
        let fresh = root.join("in-flight-run");
        std::fs::create_dir_all(&fresh).unwrap();
        sweep_stale_runs(&root, Duration::from_secs(3 * 24 * 60 * 60));
        assert!(fresh.exists(), "a fresh run dir must not be swept");

        // A missing runs_dir is a no-op (must not panic).
        sweep_stale_runs(&root.join("does-not-exist"), Duration::ZERO);

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

        sweep_stale_runs(&root, Duration::ZERO);
        assert!(
            live.exists(),
            "an in-flight run must not be swept, however aged"
        );

        // Once the guard drops, the same dir becomes eligible again.
        drop(_guard);
        assert!(!is_active_run(&live_abs));
        sweep_stale_runs(&root, Duration::ZERO);
        assert!(!live.exists(), "a deregistered aged dir is swept normally");

        std::fs::remove_dir_all(&root).ok();
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

        sweep_stale_runs(&link_root, Duration::ZERO);
        assert!(
            aged.exists(),
            "sweep of a symlinked root must not follow it and delete the target's contents"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// A unique scratch dir under the system temp root (no tempfile dep here).
    #[cfg(target_os = "linux")]
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
        p
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

        sweep_stale_runs(&runs, Duration::ZERO);

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
}
