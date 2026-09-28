//! Spike job loop: activate (optionally leased) → keep the activation alive →
//! run the agent over ACP → complete or fail, fenced by the lease token.
//!
//! Keep-alive = extend the activation timeout every third of the recovery
//! window. With a lease, every command carries the token, so a superseded
//! worker gets 409 instead of silently settling someone else's activation.

use std::collections::HashSet;
use std::path::PathBuf;
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
    // Confine this worker's run dirs — and therefore its sweeper — to a
    // per-worker subtree `<runs_dir>/<worker_name>`. The `active` set that
    // protects a live cwd from the sweeper is only in-process, so two workers
    // sharing one reap root could delete each other's running cwd. Because
    // `worker_name` defaults to a host+PID-unique value, giving each worker its
    // own subtree means a sweeper only ever sees (and reaps) its own runs, even
    // when several workers share the same `--runs-dir` parent.
    let opts = {
        let mut o = opts;
        o.runs_dir = o.runs_dir.join(&o.worker_name);
        o
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
    // Guard this run's cwd against the background sweeper for its whole lifetime.
    active.lock().unwrap().insert(cwd.clone());
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

/// Free space in MiB available under `path`, via POSIX `df -Pk` (portable across
/// macOS and Linux). `None` if `df` is unavailable or its output can't be parsed.
fn free_mb(path: &std::path::Path) -> Option<u64> {
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
        if let Ok(mut set) = self.active.lock() {
            set.remove(&self.path);
        }
    }
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
    let active: HashSet<PathBuf> = active.lock().map(|s| s.clone()).unwrap_or_default();

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

    let mut reaped = 0usize;
    for (path, modified) in dirs.into_iter().skip(keep) {
        if active.contains(&path) {
            continue;
        }
        let stale = now
            .duration_since(modified)
            .map(|d| d >= age)
            .unwrap_or(false);
        if stale && std::fs::remove_dir_all(&path).is_ok() {
            reaped += 1;
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
