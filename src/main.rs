//! nano-supervisor — spike.
//!
//! `nano-supervisor spike` runs ONE worker slot: poll a job type through
//! `camunda-orchestration-sdk`, keep each activation alive, drive an agent over
//! ACP, and complete/fail the job. It exists to measure memory and to decide
//! between the SDK's `JobWorker` and our own slot loop (see issue #1).

mod acp;
mod profile;
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
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
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
        } => {
            let mut parts = agent.split_whitespace().map(String::from);
            let Some(program) = parts.next() else {
                bail!("--agent is empty")
            };
            let resolved = profile::resolve(profile.as_deref())?;
            match &resolved {
                Some(p) => worker::log(&format!(
                    "using c8ctl profile {:?} ({})",
                    p.name,
                    p.base_url.as_deref().unwrap_or("no baseUrl")
                )),
                None => worker::log("no c8ctl profile; using CAMUNDA_* environment"),
            }
            let client = profile::client(resolved.as_ref())?;
            let opts = worker::WorkerOptions {
                job_type,
                worker_name: name.unwrap_or_else(default_name),
                agent_program: program,
                agent_args: parts.collect(),
                recovery_window: Duration::from_millis(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                runs_dir: runs_dir
                    .unwrap_or_else(|| std::env::temp_dir().join("nano-supervisor-runs")),
                with_lease,
                max_jobs,
            };
            tokio::select! {
                r = worker::run(client, opts) => r,
                _ = tokio::signal::ctrl_c() => { worker::log("interrupted"); Ok(()) }
            }
        }
    }
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
