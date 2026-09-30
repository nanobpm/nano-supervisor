//! nano-supervisor — job worker.
//!
//! `nano-supervisor work` (alias `spike`) runs ONE worker slot: poll a job type
//! through `camunda-orchestration-sdk`, keep each activation alive, drive an
//! agent over ACP, and complete/fail the job. It exists to measure memory and to
//! decide between the SDK's `JobWorker` and our own slot loop (see issue #1), and
//! is the Rust target the black-box contract-test suite drives (`NS_TARGET=rust`,
//! issues #3/#4) alongside `c8 nano work` (Node).

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
// Linux-only: `openat2(RESOLVE_NO_SYMLINKS)` pinned-handle hardening for the
// run-dir sweep/provision paths. Other Unix platforms use the path-based checks.
#[cfg(target_os = "linux")]
mod saferoot;
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
    /// Run one worker slot for a job type.
    #[command(visible_alias = "spike")]
    Work {
        /// Job type to service.
        #[arg(long)]
        job_type: String,
        /// c8ctl connection profile (default: c8ctl's active profile, else CAMUNDA_* env).
        #[arg(long)]
        profile: Option<String>,
        /// Agent command, parsed with shell-style quoting, e.g. "nano-coder
        /// --acp" or "'/path with spaces/agent' --acp".
        #[arg(long, default_value = "nano-coder --acp")]
        agent: String,
        /// Worker name reported to the engine (default ‹host›-spike-‹pid›).
        #[arg(long)]
        name: Option<String>,
        /// Activation window in ms, refreshed every third while the agent runs (floored
        /// at a safe minimum so a zero/tiny window cannot drive rapid refreshes).
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
        /// Activation window in ms, refreshed every third while the agent runs (floored
        /// at a safe minimum so a zero/tiny window cannot drive rapid refreshes).
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

/// Floor for `--recovery-window`: the activation window doubles as the refresher's
/// cadence source (it extends every third of the window). A zero or 1–2 ms window
/// expires immediately and drives the refresher to issue extend requests as fast
/// as the loop can run, hammering the engine for an activation that is already
/// expiring. Clamp any CLI value up to a meaningful minimum so a degenerate input
/// can never produce an unsafe refresh cadence.
const MIN_RECOVERY_WINDOW: Duration = Duration::from_millis(1000);

fn clamp_recovery_window(ms: u64) -> Duration {
    Duration::from_millis(ms).max(MIN_RECOVERY_WINDOW)
}

#[tokio::main(flavor = "multi_thread")]
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
            // Shell-style split so an executable path or argument containing
            // spaces can be preserved by quoting it (plain unquoted commands
            // behave exactly like whitespace splitting).
            let Some(mut parts) = shlex::split(&agent).map(Vec::into_iter) else {
                bail!("--agent has unbalanced quotes: {agent:?}")
            };
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
                name_generated: name.is_none(),
                worker_name: name.unwrap_or_else(default_name),
                agent_program: program,
                agent_args: parts.collect(),
                recovery_window: clamp_recovery_window(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                runs_dir: runs_dir.unwrap_or_else(default_runs_dir),
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
                recovery_window: clamp_recovery_window(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                clone_timeout: Duration::from_millis(clone_timeout),
                runs_dir: runs_dir.unwrap_or_else(default_runs_dir),
                config_path: config,
            };
            daemon::run(opts).await
        }
        Cmd::ReapWatchdog {
            parent_pid,
            pgid,
            parent_start,
        } => {
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

#[cfg(test)]
mod tests {
    use super::{clamp_recovery_window, MIN_RECOVERY_WINDOW};
    use std::time::Duration;

    #[test]
    fn clamp_recovery_window_floors_degenerate_values() {
        // A zero or 1–2 ms window would expire immediately and drive rapid
        // refreshes; the clamp must lift any sub-minimum value to the floor.
        assert_eq!(clamp_recovery_window(0), MIN_RECOVERY_WINDOW);
        assert_eq!(clamp_recovery_window(1), MIN_RECOVERY_WINDOW);
        assert_eq!(clamp_recovery_window(999), MIN_RECOVERY_WINDOW);
        // A comfortably large window passes through unchanged.
        assert_eq!(
            clamp_recovery_window(300_000),
            Duration::from_millis(300_000)
        );
    }
}
