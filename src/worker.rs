//! Spike job loop: activate → keep the activation alive → run the agent over
//! ACP → complete or fail.
//!
//! "Lease" here is what the plugin does today against engines that don't issue
//! `jobLeaseToken`s: activate with `timeout = recovery window`, then extend the
//! timeout (`PATCH /v2/jobs/{key}`) every third of the window while the agent
//! runs. If a token *is* issued it is passed through on every command.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use camunda_orchestration_sdk::apis::job_api::UpdateJobParams;
use camunda_orchestration_sdk::models::{
    ActivatedJobResult, JobActivationRequest, JobChangeset, JobCompletionRequest, JobFailRequest,
    JobLeaseToken, JobUpdateRequest,
};
use camunda_orchestration_sdk::CamundaClient;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::acp::{Agent, Outcome};

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

pub async fn run(client: CamundaClient, opts: WorkerOptions) -> Result<()> {
    let mut done = 0usize;
    log(&format!(
        "worker {} polling {:?} (recovery window {}s, poll {}s)",
        opts.worker_name,
        opts.job_type,
        opts.recovery_window.as_secs(),
        opts.poll_timeout.as_secs()
    ));
    loop {
        if opts.max_jobs.is_some_and(|m| done >= m) {
            return Ok(());
        }
        let mut req = JobActivationRequest::new(
            opts.job_type.clone(),
            opts.recovery_window.as_millis() as i64,
            1,
        );
        req.worker = Some(opts.worker_name.clone());
        req.request_timeout = Some(opts.poll_timeout.as_millis() as i64);
        if opts.with_lease {
            req.with_lease = Some(Some(true));
        }
        let jobs = match client.activate_jobs(req).await {
            Ok(r) => r.jobs,
            Err(e) => {
                log(&format!("activation failed: {e}; retrying in 5s"));
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        for job in jobs {
            handle(&client, &opts, job).await;
            done += 1;
        }
    }
}

async fn handle(client: &CamundaClient, opts: &WorkerOptions, job: ActivatedJobResult) {
    let key = job.job_key.value().to_string();
    let token = job.job_lease_token.clone();
    let started = Instant::now();
    log(&format!(
        "job {key} activated (type {}, retries {}, lease token {})",
        job.r#type,
        job.retries,
        if token.is_some() { "yes" } else { "no" }
    ));

    // Keep the activation alive while the agent runs.
    let refreshes = Arc::new(AtomicUsize::new(0));
    let (lost_tx, mut lost_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_loop(
        client.clone(),
        key.clone(),
        token.clone(),
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
            let mut req = JobCompletionRequest::new();
            req.variables = Some(Some(
                [
                    ("agentResult".to_string(), json!(out.text)),
                    ("agentStopReason".to_string(), json!(out.stop_reason)),
                    ("agentWorker".to_string(), json!(opts.worker_name)),
                ]
                .into_iter()
                .collect(),
            ));
            req.job_lease_token = token.map(Some);
            match client.complete_job(&key, Some(req)).await {
                Ok(()) => log(&format!(
                    "job {key} completed in {elapsed:.1}s: stop={} updates={} tool_calls={} permissions={} refreshes={n} result={:?}",
                    out.stop_reason,
                    out.updates,
                    out.tool_calls,
                    out.permissions_granted,
                    truncate(&out.text, 120)
                )),
                Err(e) => log(&format!("job {key}: complete failed: {e}")),
            }
        }
        Some(Err(e)) => {
            let msg = format!("{e:#}");
            let mut req = JobFailRequest::new();
            req.retries = Some((job.retries - 1).max(0));
            req.error_message = Some(truncate(&msg, 2000));
            req.retry_back_off = Some(0);
            req.job_lease_token = token.map(Some);
            match client.fail_job(&key, Some(req)).await {
                Ok(()) => log(&format!("job {key} failed after {elapsed:.1}s (refreshes={n}): {msg}")),
                Err(e2) => log(&format!("job {key}: fail_job failed: {e2} (original error: {msg})")),
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
    client: CamundaClient,
    key: String,
    token: Option<JobLeaseToken>,
    window: Duration,
    count: Arc<AtomicUsize>,
    lost: watch::Sender<bool>,
) {
    let every = window / 3;
    let mut failures = 0;
    loop {
        tokio::time::sleep(every).await;
        let mut changeset = JobChangeset::new();
        changeset.timeout = Some(Some(window.as_millis() as i64));
        let mut body = JobUpdateRequest::new(changeset);
        body.job_lease_token = token.clone().map(Some);
        match client
            .update_job(UpdateJobParams {
                job_key: key.clone(),
                job_update_request: body,
            })
            .await
        {
            Ok(()) => {
                failures = 0;
                count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                let msg = e.to_string();
                failures += 1;
                log(&format!("job {key}: refresh failed ({failures}): {msg}"));
                // Gone or taken over: stop now. Otherwise allow transient errors
                // until the window would lapse.
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
