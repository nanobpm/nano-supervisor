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
    let hires = state::read_hires_from(&config_path)?;
    let Some(hire) = hires.into_iter().find(|h| h.name == opts.hire) else {
        config_exit(&format!(
            "No hire named \"{}\". List profiles with: c8ctl nano hire --list",
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

    // Per-worker run namespace under the state home (the Node plugin's
    // `agent-runs/worker-<incarnation>`), unless `--runs-dir` overrides it.
    let runs_dir = match opts.runs_dir.clone() {
        Some(d) => d,
        None => state::state_home()
            .map(|h| {
                h.join("agent-runs")
                    .join(format!("rust-worker-{}", std::process::id()))
            })
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!("nano-runs-{}", std::process::id()))
            }),
    };
    std::fs::create_dir_all(&runs_dir)?;
    // Resolve platform symlinks in the path (macOS `/var` → `/private/var`):
    // the run-dir sweep refuses any root with a symlinked ancestor.
    let runs_dir = std::fs::canonicalize(&runs_dir)?;
    // Startup reap, then on a cadence: run dirs older than `--reap-age`.
    slot::sweep_stale_runs(&runs_dir, opts.reap_age);
    let reaper = {
        let dir = runs_dir.clone();
        let (age, every) = (
            opts.reap_age,
            opts.reap_interval.max(Duration::from_millis(100)),
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                slot::sweep_stale_runs(&dir, age);
            }
        })
    };

    let (_profile, jobs) = engine::connect(opts.profile.as_deref(), opts.job_api)?;
    let worker_name = opts
        .name
        .clone()
        .unwrap_or_else(|| format!("{}-nano-{}", short_hostname(), hire.name));
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
        keep_runs: opts.keep_runs,
    });
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut slot_task = tokio::spawn(slot::run(jobs, cfg, shutdown_rx, shutdown_tx.clone()));
    tokio::select! {
        _ = &mut slot_task => {}
        _ = wait_for_signal(&shutdown_tx) => {
            log("shutdown signal received; draining…");
            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(20), slot_task).await;
        }
    }
    reaper.abort();
    // Drop this worker's namespace on a clean exit, unless `--keep-runs`.
    if opts.runs_dir.is_none() && !opts.keep_runs {
        let _ = std::fs::remove_dir_all(&runs_dir);
    }
    Ok(())
}
