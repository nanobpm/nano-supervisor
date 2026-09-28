//! nano-supervisor — job worker.
//!
//! `nano-supervisor work` (alias `spike`) runs ONE worker slot: poll a job type
//! through `camunda-orchestration-sdk`, keep each activation alive, drive an
//! agent over ACP, and complete/fail the job. It exists to measure memory and to
//! decide between the SDK's `JobWorker` and our own slot loop (see issue #1), and
//! is the Rust target the black-box contract-test suite drives (`NS_TARGET=rust`,
//! issues #3/#4) alongside `c8 nano work` (Node).

mod acp;
mod jobs;
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
    /// Run one worker slot for a job type.
    #[command(visible_alias = "spike")]
    Work {
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
        /// Keep the N most recent per-job run directories; older ones are reaped.
        #[arg(long)]
        keep_runs: Option<usize>,
        /// Refuse to take work when free disk under the run directory is below this (MiB).
        #[arg(long)]
        min_free_mb: Option<u64>,
        /// Reap run directories older than this, on startup and each sweep (e.g. `30s`, `500ms`).
        #[arg(long, value_parser = parse_duration)]
        reap_age: Option<Duration>,
        /// Sweep the run directory for stale directories on this cadence (e.g. `60s`).
        #[arg(long, value_parser = parse_duration)]
        reap_interval: Option<Duration>,
        /// Job command transport: `sdk`, `nano` (raw HTTP, Nano's `leaseToken`
        /// field), or `auto` (= `nano` with --with-lease, else `sdk`).
        #[arg(long, default_value = "auto")]
        job_api: String,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Work {
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
            keep_runs,
            min_free_mb,
            reap_age,
            reap_interval,
            job_api,
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
            let job_api = match job_api.as_str() {
                "auto" if with_lease => "nano",
                "auto" => "sdk",
                other => other,
            };
            let jobs = match job_api {
                "sdk" => jobs::Jobs::Sdk(Box::new(client)),
                "nano" => {
                    let (address, basic) = profile::rest_address_and_basic(resolved.as_ref());
                    jobs::Jobs::Nano(jobs::NanoHttp::new(&address, basic)?)
                }
                other => bail!("--job-api must be sdk, nano or auto (got {other:?})"),
            };
            let opts = worker::WorkerOptions {
                job_type,
                name_generated: name.is_none(),
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
                keep_runs,
                min_free_mb,
                reap_age,
                reap_interval,
            };
            tokio::select! {
                r = worker::run(jobs, opts) => r,
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

/// Parse a duration flag: a bare number is milliseconds, or a `ms`/`s`/`m`/`h`
/// suffix (e.g. `500ms`, `30s`, `5m`). Used for `--reap-age`/`--reap-interval`.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1_000)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60_000)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3_600_000)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration {s:?} (use e.g. `30s`, `500ms`, or a ms count)"))?;
    let ms = n
        .checked_mul(mult)
        .ok_or_else(|| format!("duration {s:?} is too large (overflows milliseconds)"))?;
    Ok(Duration::from_millis(ms))
}
