//! nano-supervisor — job worker.
//!
//! `nano-supervisor work <hire>` runs ONE worker for a hired profile — the Rust
//! counterpart of the Node plugin's `c8 nano work <profile>`, and the Rust target
//! the black-box contract-test suite drives (`NS_TARGET=rust`) alongside it.
//! `nano-supervisor daemon` runs N slots per hire over one engine connection.
//! Both share one job core ([`slot`]) that mirrors the Node plugin's behaviour.

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
mod runtime;
#[cfg(target_os = "linux")]
mod saferoot;
mod slot;
mod state;
mod work;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nano-supervisor",
    version,
    about = "Rust supervisor and job workers for Nano BPM agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one worker for a hired profile — the Rust `c8 nano work <profile>`.
    Work {
        /// The hired profile (from config.json) to run.
        hire: String,
        /// Extra job type to service on top of the hire's rank×capability
        /// matrix (repeatable).
        #[arg(long = "job-type")]
        job_type: Vec<String>,
        /// c8ctl connection profile (default: c8ctl's active profile, else CAMUNDA_* env).
        #[arg(long)]
        profile: Option<String>,
        /// Worker name reported to the engine (default ‹host›-nano-‹hire›-‹pid›).
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
        /// Per-git-operation timeout while provisioning a repo, in ms.
        #[arg(long, default_value_t = 120_000)]
        clone_timeout: u64,
        /// Reap run directories older than this (ms, or e.g. `30s`), at startup and
        /// every --reap-interval.
        #[arg(long, value_parser = parse_duration, default_value = "3600000")]
        reap_age: Duration,
        /// Run-directory reaper cadence (ms, or e.g. `60s`).
        #[arg(long, value_parser = parse_duration, default_value = "300000")]
        reap_interval: Duration,
        /// Keep per-job run directories instead of removing them.
        #[arg(long, num_args = 0..=1, default_missing_value = "true", default_value = "false")]
        keep_runs: bool,
        /// Free-disk admission floor in MiB — container sandboxes only (accepted
        /// for parity with the Node plugin; host jobs are not gated).
        #[arg(long)]
        min_free_mb: Option<u64>,
        /// Directory for per-job working directories (default: a per-worker
        /// namespace under the state home's `agent-runs/`).
        #[arg(long)]
        runs_dir: Option<PathBuf>,
        /// Override the config.json path (default: the c8ctl-nano state home).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Exit after handling this many jobs.
        #[arg(long)]
        max_jobs: Option<usize>,
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
        /// Run unfenced: do NOT ask the engine for job leases. By default the
        /// daemon leases every activation and a worker that gets no lease token
        /// refuses the job (leasing is the default; it fails loudly if the
        /// engine doesn't issue a token).
        #[arg(long)]
        no_lease: bool,
        /// Deprecated no-op: leasing is now on by default, so `--with-lease` is
        /// implied. Kept so existing invocations keep working; use `--no-lease`
        /// to opt out.
        #[arg(long, hide = true)]
        with_lease: bool,
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
            hire,
            job_type,
            profile,
            name,
            recovery_window,
            idle_timeout,
            poll_timeout,
            clone_timeout,
            reap_age,
            reap_interval,
            keep_runs,
            min_free_mb,
            runs_dir,
            config,
            max_jobs,
        } => {
            work::run(work::WorkOptions {
                hire,
                job_types: job_type,
                profile,
                name,
                recovery_window: clamp_recovery_window(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                clone_timeout: Duration::from_millis(clone_timeout),
                runs_dir,
                config_path: config,
                max_jobs,
                keep_runs,
                min_free_mb,
                reap_age,
                reap_interval,
            })
            .await
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
            no_lease,
            with_lease: _,
        } => {
            let opts = daemon::DaemonOptions {
                profile,
                with_lease: !no_lease,
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
