//! Spike job loop: activate (optionally leased) → keep the activation alive →
//! run the agent over ACP → complete or fail, fenced by the lease token.
//!
//! Keep-alive = extend the activation timeout every third of the recovery
//! window. With a lease, every command carries the token, so a superseded
//! worker gets 409 instead of silently settling someone else's activation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use camunda_orchestration_sdk::models::ActivatedJobResult;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::acp::{Agent, Outcome};
use crate::jobs::{Job, Jobs};

#[derive(Debug, Clone)]
pub struct WorkerOptions {
    pub job_type: String,
    pub worker_name: String,
    pub agent_program: String,
    pub agent_args: Vec<String>,
    pub recovery_window: Duration,
    pub idle_timeout: Duration,
    pub poll_timeout: Duration,
    pub runs_dir: PathBuf,
    pub with_lease: bool,
    pub max_jobs: Option<usize>,
    /// Keep the N most recent run directories when sweeping; reap older ones.
    pub keep_runs: Option<usize>,
    /// Refuse to take work while free disk under `runs_dir` is below this (MiB).
    pub min_free_mb: Option<u64>,
    /// Reap run directories older than this, on startup and on each sweep.
    pub reap_age: Option<Duration>,
    /// Sweep `runs_dir` for stale directories on this cadence.
    pub reap_interval: Option<Duration>,
}

pub async fn run(jobs: Jobs, opts: WorkerOptions) -> Result<()> {
    // Confine this worker's runs (and its sweeper) to a *stable* per-worker
    // subtree of the configured run root. The namespace must NOT change across
    // a restart: `default_name()` embeds the PID, so keying the subtree on the
    // worker name would move every run to a fresh `.../host-spike-<pid>/` on
    // each launch — a reactivated job's prior cwd would become invisible
    // (breaking checkpoint/resume) and the old PID subtree unreachable by the
    // new worker's sweeper. Instead derive the subtree from the host plus the
    // job type — stable for a given worker role across restarts, while still
    // separating workers that run different job types. Cross-process safety
    // (two live workers, or a worker vs. a stale run) is handled by the
    // per-job active markers + the synchronized sweeper below, not by the path.
    let opts = {
        let mut opts = opts;
        let ns = stable_namespace(&opts.worker_name, &opts.job_type);
        opts.runs_dir = opts.runs_dir.join(ns);
        opts
    };
    let mut done = 0usize;
    log(&format!(
        "worker {} polling {:?} (recovery window {}s, poll {}s, lease {}, job api {})",
        opts.worker_name,
        opts.job_type,
        opts.recovery_window.as_secs(),
        opts.poll_timeout.as_secs(),
        if opts.with_lease { "on" } else { "off" },
        jobs.backend()
    ));

    // Housekeeping: make sure the run root exists before taking any work — a
    // misconfigured/unwritable run root should fail loudly here, not silently
    // burn a job's retries when its cwd can't be created. Then sweep stale run
    // dirs on startup and keep sweeping on the configured cadence.
    std::fs::create_dir_all(&opts.runs_dir)
        .with_context(|| format!("creating run root {}", opts.runs_dir.display()))?;
    // Paths of runs that are currently executing; the sweeper must never reap a
    // live agent's cwd, even under `--keep-runs 0` or when another worker's runs
    // push it out of the newest set.
    let active: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    sweep_runs(&opts, &active);
    if let Some(interval) = opts.reap_interval.filter(|d| !d.is_zero()) {
        let sweep_opts = opts.clone();
        let sweep_active = active.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                sweep_runs(&sweep_opts, &sweep_active);
            }
        });
    }

    loop {
        if opts.max_jobs.is_some_and(|m| done >= m) {
            return Ok(());
        }
        // Disk-space floor: refuse to take work when free space under the run
        // directory is below the configured floor, before touching the engine.
        if let Some(floor) = opts.min_free_mb {
            if let Some(free) = free_mb(&opts.runs_dir) {
                if free < floor {
                    log(&format!(
                        "free disk {free}MB under {} is below the floor of {floor}MB; refusing to take work",
                        opts.runs_dir.display()
                    ));
                    return Ok(());
                }
            } else {
                log(&format!(
                    "could not determine free disk under {}; refusing to take work below the {floor}MB floor",
                    opts.runs_dir.display()
                ));
                return Ok(());
            }
        }
        let batch = match jobs
            .activate(
                &opts.job_type,
                &opts.worker_name,
                opts.recovery_window,
                opts.poll_timeout,
                opts.with_lease,
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                log(&format!("activation failed: {e:#}; retrying in 5s"));
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        for job in batch {
            if opts.with_lease && job.lease.is_none() {
                // Same fail-loud rule as the SDK: never run a job we can't fence.
                anyhow::bail!(
                    "asked for a lease but job {} came back without a lease token; refusing to run unfenced",
                    job.job.job_key.value()
                );
            }
            handle(&jobs, &opts, &active, job).await;
            done += 1;
        }
    }
}

async fn handle(
    jobs: &Jobs,
    opts: &WorkerOptions,
    active: &Arc<Mutex<HashSet<PathBuf>>>,
    Job { job, lease }: Job,
) {
    let key = job.job_key.value().to_string();
    let cwd = opts.runs_dir.join(&key);
    // Claim this cwd against the background sweeper for the run's whole lifetime.
    // Because the run root is a *stable* namespace shared by every worker of the
    // same host+job type (the PID is stripped from the path), an in-process
    // `HashSet` alone cannot stop *another* worker's sweeper from reaping our
    // live cwd. So we also drop a cross-process liveness marker recording our
    // PID: a foreign sweeper reads it, sees the owner process is alive, and
    // skips the directory. Create the dir up front so the marker lands before
    // the agent starts producing output.
    if let Err(e) = std::fs::create_dir_all(&cwd) {
        log(&format!(
            "job {key}: cannot create run dir {}: {e:#}; skipping",
            cwd.display()
        ));
        return;
    }
    active.lock().unwrap().insert(cwd.clone());
    write_active_marker(&cwd);
    let _guard = ActiveGuard {
        active: active.clone(),
        path: cwd,
    };
    let started = Instant::now();
    log(&format!(
        "job {key} activated (type {}, retries {}, lease {})",
        job.r#type,
        job.retries,
        lease.as_deref().unwrap_or("none")
    ));

    let refreshes = Arc::new(AtomicUsize::new(0));
    let (lost_tx, mut lost_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_loop(
        jobs.clone(),
        key.clone(),
        lease.clone(),
        opts.recovery_window,
        refreshes.clone(),
        lost_tx,
    ));

    let result = tokio::select! {
        r = run_agent(opts, &key, &job) => Some(r),
        _ = lost_rx.wait_for(|lost| *lost) => None,
    };
    refresher.abort();
    let elapsed = started.elapsed().as_secs_f32();
    let n = refreshes.load(Ordering::Relaxed);

    match result {
        None => log(&format!(
            "job {key}: activation lost after {elapsed:.1}s; agent stopped, job NOT settled (the engine will hand it out again)"
        )),
        Some(Ok(out)) => {
            let vars = [
                ("agentResult".to_string(), json!(out.text)),
                ("agentStopReason".to_string(), json!(out.stop_reason)),
                ("agentWorker".to_string(), json!(opts.worker_name)),
            ]
            .into_iter()
            .collect();
            match jobs.complete(&key, vars, &lease).await {
                Ok(()) => log(&format!(
                    "job {key} completed in {elapsed:.1}s: stop={} updates={} tool_calls={} permissions={} refreshes={n} result={:?}",
                    out.stop_reason,
                    out.updates,
                    out.tool_calls,
                    out.permissions_granted,
                    truncate(&out.text, 120)
                )),
                Err(e) => log(&format!("job {key}: complete failed: {e:#}")),
            }
        }
        Some(Err(e)) => {
            let msg = format!("{e:#}");
            match jobs.fail(&key, (job.retries - 1).max(0), &truncate(&msg, 2000), &lease).await {
                Ok(()) => log(&format!("job {key} failed after {elapsed:.1}s (refreshes={n}): {msg}")),
                Err(e2) => log(&format!("job {key}: fail failed: {e2:#} (original error: {msg})")),
            }
        }
    }
}

async fn run_agent(opts: &WorkerOptions, key: &str, job: &ActivatedJobResult) -> Result<Outcome> {
    let prompt = job
        .variables
        .get("prompt")
        .and_then(Value::as_str)
        .context("job has no string variable `prompt`")?
        .to_string();
    let cwd = opts.runs_dir.join(key);
    std::fs::create_dir_all(&cwd).with_context(|| format!("creating {}", cwd.display()))?;
    let env = vec![
        ("NANO_JOB_KEY".to_string(), key.to_string()),
        ("NANO_AGENT_NAME".to_string(), opts.worker_name.clone()),
    ];
    let mut agent = Agent::spawn(&opts.agent_program, &opts.agent_args, &cwd, &env)?;
    log(&format!(
        "job {key}: agent pid {} in {}",
        agent.pid().unwrap_or(0),
        cwd.display()
    ));
    let out = agent.run(&cwd, &prompt, opts.idle_timeout).await;
    agent.shutdown().await;
    let out = out?;
    if out.text.trim().is_empty() {
        // Never complete a job with nothing to show for it (c8ctl-plugin-nano#275).
        anyhow::bail!("agent finished ({}) without any output", out.stop_reason);
    }
    Ok(out)
}

async fn refresh_loop(
    jobs: Jobs,
    key: String,
    lease: Option<String>,
    window: Duration,
    count: Arc<AtomicUsize>,
    lost: watch::Sender<bool>,
) {
    let every = window / 3;
    let mut failures = 0;
    loop {
        tokio::time::sleep(every).await;
        match jobs.extend(&key, window, &lease).await {
            Ok(()) => {
                failures = 0;
                count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                let msg = format!("{e:#}");
                failures += 1;
                log(&format!("job {key}: refresh failed ({failures}): {msg}"));
                // 404 = gone, 409 = superseded by a newer (leased) activation: stop
                // now. Otherwise tolerate one transient error before giving up.
                if msg.contains("404") || msg.contains("409") || failures >= 2 {
                    let _ = lost.send(true);
                    return;
                }
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

/// Derive the *stable* run-root namespace for a worker. Keyed on the host plus
/// the job type — never the live PID — so a worker that restarts keeps the same
/// run root and can see (and its sweeper can reap) the runs it owned before the
/// restart. `default_name()` is `<host>-spike-<pid>`; we strip only that exact
/// trailing `-<pid>` (a run of digits directly after a `-spike` segment) so the
/// path is restart-stable. Explicit `--name`s (e.g. `worker-1`, `worker-2`) do
/// NOT carry the `-spike-<pid>` shape and are preserved verbatim, so they keep
/// distinct namespaces instead of collapsing to a shared one.
fn stable_namespace(worker_name: &str, job_type: &str) -> String {
    let base = strip_default_pid_suffix(worker_name);
    sanitize_component(&format!("{base}-{job_type}"))
}

/// Strip the default `-spike-<pid>` PID suffix from a worker name, reducing
/// `<host>-spike-<pid>` to `<host>-spike`. Any other name (including explicit
/// `--name`s such as `worker-1`) is returned unchanged, so only the known
/// default shape is collapsed — an explicit numeric suffix is preserved.
fn strip_default_pid_suffix(name: &str) -> &str {
    match name.rsplit_once('-') {
        Some((head, tail))
            if !tail.is_empty()
                && tail.chars().all(|c| c.is_ascii_digit())
                && head.ends_with("-spike") =>
        {
            head
        }
        _ => name,
    }
}

/// Make a string safe to use as a single path component: keep alphanumerics,
/// `-`, `_` and `.`, and replace anything else (path separators, spaces, …)
/// with `-`. Never empty.
fn sanitize_component(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let out = out.trim_matches(['-', '.'].as_ref()).to_string();
    if out.is_empty() {
        "worker".to_string()
    } else {
        out
    }
}

/// Free space in MiB available under `path`, via POSIX `df -Pk` (portable across
/// macOS and Linux). `None` if `df` is unavailable or its output can't be parsed.
fn free_mb(path: &Path) -> Option<u64> {
    let out = std::process::Command::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Data line: `Filesystem 1024-blocks Used Available Capacity Mounted-on`.
    let avail_kib: u64 = text
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()?;
    Some(avail_kib / 1024)
}

/// Removes a run path from the active set when a job finishes (or its future is
/// dropped/cancelled), so the sweeper stops protecting it.
struct ActiveGuard {
    active: Arc<Mutex<HashSet<PathBuf>>>,
    path: PathBuf,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        // Drop the cross-process liveness marker first so a completed run's dir
        // (retained by `--keep-runs`) is immediately reapable by any sweeper,
        // then release the in-process guard.
        let _ = std::fs::remove_file(self.path.join(ACTIVE_MARKER));
        if let Ok(mut set) = self.active.lock() {
            set.remove(&self.path);
        }
    }
}

/// Filename of the cross-process liveness marker written inside each *active*
/// run directory. It records the owning worker's PID so a sweeper in a
/// different process (sharing the same stable run root) can distinguish a live
/// run from an orphaned one.
const ACTIVE_MARKER: &str = ".nano-active";

/// Record this process as the live owner of `cwd` by writing its PID into the
/// run's liveness marker. Best-effort: the in-process active set still guards
/// same-process runs if the marker can't be written.
fn write_active_marker(cwd: &Path) {
    let _ = std::fs::write(cwd.join(ACTIVE_MARKER), std::process::id().to_string());
}

/// Whether `dir` is a *live* run owned by some still-running worker — i.e. its
/// liveness marker names a PID that is currently alive. Such a directory must
/// never be reaped, even by a foreign worker whose in-process active set can't
/// see it. Fail-safe: a present-but-unparseable marker is treated as live so a
/// possibly-active cwd is never deleted; a missing marker means "not live".
fn marker_owner_alive(dir: &Path) -> bool {
    match std::fs::read_to_string(dir.join(ACTIVE_MARKER)) {
        Ok(contents) => match contents.trim().parse::<u32>() {
            Ok(pid) => pid_is_live(pid),
            Err(_) => true,
        },
        Err(_) => false,
    }
}

/// Best-effort liveness check for a PID on the local host (run roots are
/// host-local, so any worker sharing this namespace is on this host).
#[cfg(target_os = "linux")]
fn pid_is_live(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Off Linux there is no portable pure-`std` liveness probe, so treat a present
/// marker as live and never risk deleting an active cwd; stale dirs off Linux
/// are still reaped once their marker is removed on normal completion.
#[cfg(not(target_os = "linux"))]
fn pid_is_live(_pid: u32) -> bool {
    true
}

/// Reap stale per-job run directories: remove immediate subdirectories of
/// `runs_dir` older than `reap_age`, always keeping the `keep_runs` most recent
/// (default 1). Never touches a directory currently backing a running job. A
/// no-op unless `reap_age` is set.
fn sweep_runs(opts: &WorkerOptions, active: &Arc<Mutex<HashSet<PathBuf>>>) {
    let Some(age) = opts.reap_age else {
        return;
    };
    let keep = opts.keep_runs.unwrap_or(1);
    let now = std::time::SystemTime::now();

    let Ok(entries) = std::fs::read_dir(&opts.runs_dir) else {
        return;
    };
    // (path, modified) for each subdirectory, newest first.
    let mut dirs: Vec<(PathBuf, std::time::SystemTime)> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| {
            let modified = e.metadata().and_then(|m| m.modified()).ok()?;
            Some((e.path(), modified))
        })
        .collect();
    dirs.sort_by_key(|(_, modified)| std::cmp::Reverse(*modified));

    // Hold the active-set lock for the whole sweep so a job cannot register its
    // cwd in the gap between "snapshot the active set" and "remove_dir_all".
    // Checking membership against a cloned set and *then* deleting is a TOCTOU
    // race: a job could register its cwd after the snapshot but before the
    // delete, and we'd remove a live agent's working directory. Deleting while
    // holding the lock makes the active check and the removal atomic w.r.t.
    // registration (which takes the same lock in `handle`/`ActiveGuard`).
    let mut reaped = 0usize;
    {
        let mut active = match active.lock() {
            Ok(g) => g,
            // A poisoned lock means a job panicked while holding it; fail safe by
            // reaping nothing this pass rather than risk deleting a live cwd.
            Err(_) => return,
        };
        for (path, modified) in dirs.into_iter().skip(keep) {
            if active.contains(&path) {
                continue;
            }
            // Cross-process guard: another worker sharing this stable run root
            // may be running a job here. If its liveness marker names a live
            // PID, skip — only this in-process set sees *our* runs, so without
            // this check we could `remove_dir_all` a foreign worker's live cwd.
            if marker_owner_alive(&path) {
                continue;
            }
            let stale = now
                .duration_since(modified)
                .map(|d| d >= age)
                .unwrap_or(false);
            if stale && std::fs::remove_dir_all(&path).is_ok() {
                // Keep the set tidy if a path was reaped while (somehow) still
                // present; removal is idempotent.
                active.remove(&path);
                reaped += 1;
            }
        }
    }
    if reaped > 0 {
        log(&format!(
            "sweep: reaped {reaped} stale run dir(s) under {} (keep {keep}, age {}s)",
            opts.runs_dir.display(),
            age.as_secs()
        ));
    }
}

pub fn log(msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    eprintln!("[{now:.3}] {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_strips_pid_suffix_for_stability() {
        // `default_name()` is `<host>-spike-<pid>`; the namespace must drop the
        // PID so a restarted worker keeps the same run root.
        let a = stable_namespace("host-spike-123", "my-job");
        let b = stable_namespace("host-spike-456", "my-job");
        assert_eq!(a, b, "namespace must be stable across restarts (no PID)");
        assert_eq!(a, "host-spike-my-job");
    }

    #[test]
    fn namespace_separates_job_types() {
        let a = stable_namespace("host-spike-123", "job-a");
        let b = stable_namespace("host-spike-123", "job-b");
        assert_ne!(a, b, "different job types get different subtrees");
    }

    #[test]
    fn namespace_keeps_explicit_name_without_pid() {
        // An explicit `--name` with no trailing -<pid> is used as-is.
        assert_eq!(stable_namespace("alice", "job"), "alice-job");
    }

    #[test]
    fn namespace_preserves_explicit_numeric_names() {
        // Explicit `--name worker-1`/`worker-2` must NOT be mistaken for the
        // default `-spike-<pid>` shape; they keep distinct namespaces.
        let a = stable_namespace("worker-1", "job");
        let b = stable_namespace("worker-2", "job");
        assert_eq!(a, "worker-1-job");
        assert_eq!(b, "worker-2-job");
        assert_ne!(a, b, "explicit numeric names must not collide");
    }

    #[test]
    fn strip_only_touches_default_spike_shape() {
        assert_eq!(strip_default_pid_suffix("host-spike-99"), "host-spike");
        assert_eq!(strip_default_pid_suffix("worker-1"), "worker-1");
        assert_eq!(strip_default_pid_suffix("plain"), "plain");
        // A numeric tail not preceded by `-spike` is preserved.
        assert_eq!(strip_default_pid_suffix("a-b-7"), "a-b-7");
    }

    #[test]
    fn sanitize_replaces_unsafe_chars() {
        assert_eq!(sanitize_component("a/b c"), "a-b-c");
        assert_eq!(sanitize_component("ok_name-1.2"), "ok_name-1.2");
        assert_eq!(sanitize_component("///"), "worker");
    }

    #[test]
    fn active_marker_roundtrips_and_reads_live() {
        // A written marker names *this* live process, so it reads back as live;
        // once removed, the directory reads as not-live (reapable).
        let dir = std::env::temp_dir().join(format!("ns-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_active_marker(&dir);
        assert!(marker_owner_alive(&dir), "own PID must read as live");
        std::fs::remove_file(dir.join(ACTIVE_MARKER)).unwrap();
        assert!(!marker_owner_alive(&dir), "no marker means not live");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn marker_with_dead_pid_reads_not_live() {
        // PID 0 never names a live process on Linux, so its marker is orphaned.
        let dir = std::env::temp_dir().join(format!("ns-dead-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(ACTIVE_MARKER), "0").unwrap();
        assert!(
            !marker_owner_alive(&dir),
            "a dead PID must read as not live"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
