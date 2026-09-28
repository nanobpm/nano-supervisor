//! Spike job loop: activate (optionally leased) → keep the activation alive →
//! run the agent over ACP → complete or fail, fenced by the lease token.
//!
//! Keep-alive = extend the activation timeout every third of the recovery
//! window. With a lease, every command carries the token, so a superseded
//! worker gets 409 instead of silently settling someone else's activation.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
}

pub async fn run(jobs: Jobs, opts: WorkerOptions) -> Result<()> {
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
    loop {
        if opts.max_jobs.is_some_and(|m| done >= m) {
            return Ok(());
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
            handle(&jobs, &opts, job).await;
            done += 1;
        }
    }
}

async fn handle(jobs: &Jobs, opts: &WorkerOptions, Job { job, lease }: Job) {
    let key = job.job_key.value().to_string();
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

pub(crate) async fn refresh_loop(
    jobs: Jobs,
    key: String,
    lease: Option<String>,
    window: Duration,
    count: Arc<AtomicUsize>,
    lost: watch::Sender<bool>,
) {
    // Refresh at a third of the window, but never a zero-length interval: a
    // sub-3ms window divides to `Duration::ZERO`, which would spin this loop and
    // hammer the engine (saturating a Tokio worker). Floor it at a positive
    // minimum so the loop always yields between extends.
    let every = (window / 3).max(Duration::from_millis(1));
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

pub fn log(msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    eprintln!("[{now:.3}] {msg}");
}
