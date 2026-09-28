//! nano-supervisor — spike.
//!
//! `nano-supervisor spike` runs ONE worker slot: poll a job type through
//! `camunda-orchestration-sdk`, keep each activation alive, drive an agent over
//! ACP, and complete/fail the job. It exists to measure memory and to decide
//! between the SDK's `JobWorker` and our own slot loop (see issue #1).

mod acp;
mod daemon;
mod engine;
mod envelope;
mod jobs;
mod pdeath;
mod pipe;
mod profile;
mod provision;
mod result;
mod slot;
mod state;
mod worker;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nano-supervisor",
    version,
    about = "Rust supervisor and job workers for Nano BPM agents (spike)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one worker slot for a job type (spike).
    Spike {
        /// Job type to service.
        #[arg(long)]
        job_type: String,
        /// c8ctl connection profile (default: c8ctl's active profile, else CAMUNDA_* env).
        #[arg(long)]
        profile: Option<String>,
        /// Agent command, split on whitespace, e.g. "nano-coder --acp".
        #[arg(long, default_value = "nano-coder --acp")]
        agent: String,
        /// Worker name reported to the engine (default ‹host›-spike-‹pid›).
        #[arg(long)]
        name: Option<String>,
        /// Activation window in ms, refreshed every third while the agent runs.
        #[arg(long, default_value_t = 300_000)]
        recovery_window: u64,
        /// Kill the agent after this many ms without output.
        #[arg(long, default_value_t = 300_000)]
        idle_timeout: u64,
        /// Long-poll window for each activation request, in ms.
        #[arg(long, default_value_t = 30_000)]
        poll_timeout: u64,
        /// Directory for per-job working directories.
        #[arg(long)]
        runs_dir: Option<PathBuf>,
        /// Ask the engine for job leases (fails loudly if the engine doesn't issue them).
        #[arg(long)]
        with_lease: bool,
        /// Exit after this many jobs.
        #[arg(long)]
        max_jobs: Option<usize>,
        /// Job command transport: `sdk`, `nano` (raw HTTP, Nano's `leaseToken`
        /// field), or `auto` (= `nano` with --with-lease, else `sdk`).
        #[arg(long, default_value = "auto")]
        job_api: String,
    },
    /// Run the MVP daemon: N slots per hire (from config.json), one shared
    /// engine connection, host sandbox only.
    Daemon {
        /// c8ctl connection profile (default: c8ctl's active profile, else CAMUNDA_* env).
        #[arg(long)]
        profile: Option<String>,
        /// Capacity-1 slots to run per hire.
        #[arg(long, default_value_t = 1)]
        slots: usize,
        /// Only run these hires by name (repeatable); default = every hire.
        #[arg(long = "hire")]
        hire: Vec<String>,
        /// Activation window in ms, refreshed every third while the agent runs.
        #[arg(long, default_value_t = 300_000)]
        recovery_window: u64,
        /// Kill the agent after this many ms without output.
        #[arg(long, default_value_t = 300_000)]
        idle_timeout: u64,
        /// Long-poll window for each activation request, in ms.
        #[arg(long, default_value_t = 30_000)]
        poll_timeout: u64,
        /// Per-git-operation timeout while provisioning a repo, in ms.
        #[arg(long, default_value_t = 120_000)]
        clone_timeout: u64,
        /// Directory for per-job working directories.
        #[arg(long)]
        runs_dir: Option<PathBuf>,
        /// Override the config.json path (default: the c8ctl-nano state home).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Ask the engine for job leases (fails loudly if the engine doesn't issue them).
        #[arg(long)]
        with_lease: bool,
        /// Job command transport: `sdk`, `nano`, or `auto` (= `nano` with
        /// --with-lease, else `sdk`).
        #[arg(long, default_value = "auto")]
        job_api: String,
    },
    /// Internal: the macOS parent-death watchdog (kills an agent's process group
    /// when the daemon dies). Not for direct use.
    #[command(name = "__reap-watchdog", hide = true)]
    ReapWatchdog {
        #[arg(long)]
        parent_pid: u32,
        #[arg(long)]
        pgid: u32,
        /// The daemon's start time (Linux `/proc/<pid>/stat` field 22), captured
        /// by the daemon *before* launching this watchdog so PID-reuse detection
        /// still works even if the daemon is SIGKILLed before this process can
        /// read `/proc` itself.
        #[arg(long)]
        parent_start: Option<u64>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Spike {
            job_type,
            profile,
            agent,
            name,
            recovery_window,
            idle_timeout,
            poll_timeout,
            runs_dir,
            with_lease,
            max_jobs,
            job_api,
        } => {
            let mut parts = agent.split_whitespace().map(String::from);
            let Some(program) = parts.next() else {
                bail!("--agent is empty")
            };
            let (_resolved, jobs) = engine::connect(
                profile.as_deref(),
                engine::JobApi::parse(&job_api)?,
                with_lease,
            )?;
            let opts = worker::WorkerOptions {
                job_type,
                worker_name: name.unwrap_or_else(default_name),
                agent_program: program,
                agent_args: parts.collect(),
                recovery_window: Duration::from_millis(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                runs_dir: runs_dir.unwrap_or_else(default_runs_dir),
                with_lease,
                max_jobs,
            };
            tokio::select! {
                r = worker::run(jobs, opts) => r,
                _ = tokio::signal::ctrl_c() => { worker::log("interrupted"); Ok(()) }
            }
        }
        Cmd::Daemon {
            profile,
            slots,
            hire,
            recovery_window,
            idle_timeout,
            poll_timeout,
            clone_timeout,
            runs_dir,
            config,
            with_lease,
            job_api,
        } => {
            let opts = daemon::DaemonOptions {
                profile,
                job_api: engine::JobApi::parse(&job_api)?,
                with_lease,
                slots: slots.max(1),
                only: hire,
                recovery_window: Duration::from_millis(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                clone_timeout: Duration::from_millis(clone_timeout),
                runs_dir: runs_dir.unwrap_or_else(default_runs_dir),
                config_path: config,
            };
            daemon::run(opts).await
        }
        Cmd::ReapWatchdog { parent_pid, pgid, parent_start } => {
            tokio::task::spawn_blocking(move || {
                pdeath::reap_watchdog(parent_pid, pgid, parent_start)
            })
            .await
            .ok();
            Ok(())
        }
    }
}

/// Default per-job working-directory root. Prefers a user-private state home
/// (`$XDG_STATE_HOME`, else `$HOME/.local/state`) over the shared system temp
/// dir: a predictable `nano-supervisor-runs` directly under world-writable
/// `/tmp` lets another local user pre-create it as a symlink before the daemon
/// starts, so `create_dir_all` would follow the link and clone job data into an
/// attacker-chosen location. The state home is owner-only, removing that
/// pre-creation/symlink race. Falls back to a per-user temp subdir (which
/// `restrict_dir_mode` then tightens to 0700) only when no home is known.
fn default_runs_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("nano-supervisor/runs");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".local/state/nano-supervisor/runs");
    }
    std::env::temp_dir().join(format!("nano-supervisor-runs-{}", current_user_id()))
}

/// Per-user discriminator for the fallback temp runs root. `libc` is a Unix-only
/// dependency (see `Cargo.toml`), so the UID lookup lives behind a Unix-only
/// helper; the non-Unix stub keeps the crate building for the `pdeath` stubs'
/// platforms by falling back to the login name (or a fixed token when unknown).
#[cfg(unix)]
fn current_user_id() -> String {
    // SAFETY: `getuid` is always successful and touches no shared state.
    unsafe { libc::getuid() }.to_string()
}

#[cfg(not(unix))]
fn current_user_id() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "shared".to_string())
}

fn default_name() -> String {
    let host = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "host".into());
    format!("{host}-spike-{}", std::process::id())
}
