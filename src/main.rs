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

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
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
        /// Job command transport: `sdk` (default via `auto`) or `nano` (raw HTTP,
        /// legacy `leaseToken` dialect for engines older than 0.0.24).
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
        /// Job command transport: `sdk` (default via `auto`) or `nano` (raw HTTP,
        /// legacy `leaseToken` dialect for engines older than 0.0.24).
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
            job_api,
        } => {
            work::run(work::WorkOptions {
                hire,
                job_types: job_type,
                profile,
                job_api: engine::JobApi::parse(&job_api)?,
                name,
                recovery_window: clamp_recovery_window(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                clone_timeout: Duration::from_millis(clone_timeout),
                runs_dir: match runs_dir {
                    Some(d) => Some(normalize_runs_dir(&d)?),
                    None => None,
                },
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
                runs_dir: match runs_dir {
                    Some(d) => normalize_runs_dir(&d)?,
                    None => default_runs_dir(),
                },
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

/// Lexically normalize `.` and `..` in an operator-supplied `--runs-dir`,
/// WITHOUT touching the filesystem (no symlink is followed — that resolution
/// stays with the no-follow walk / path checks downstream). This preserves the
/// pre-hardening behaviour the non-Linux `create_dir_all` fallback still has —
/// `--runs-dir ../runs` resolves against the operator's cwd — which the Linux
/// pinned-handle walk (`saferoot::DirHandle::create_root_nofollow`) otherwise
/// rejects outright, since it refuses any `..` component to guarantee the walk
/// can never climb out of its pinned anchor. Resolving the parent traversal
/// lexically here hands the walk an equivalent path with no `..`, so the daemon
/// and `work` accept the same runs-dir on every platform instead of failing
/// only on Linux.
///
/// A relative path stays relative (`.`/`..` still resolve against the cwd at
/// use time, exactly as the fallback treated them); only the infix `.`/`..`
/// are folded. A leading `..` on a relative path cannot be folded lexically
/// (it climbs above the cwd), so it is resolved against the current directory
/// — the same target the non-Linux fallback resolves it to — yielding an
/// absolute, `..`-free path. Only a `..` that climbs past the filesystem root
/// (`/..`) is rejected, since that escapes any base.
///
/// Two invariants keep the downstream no-follow layer consistent:
/// * The result is never empty. A cwd-equivalent input (`.`, `sub/..`, `/`)
///   normalizes to `.` (or `/`), because an empty path would diverge between
///   `create_root_nofollow` (which opens the anchor, i.e. the cwd) and
///   `open_root_nofollow` (which `openat2`s the literal path and fails an
///   empty one with `ENOENT`) — breaking the sweep / completion-cleanup while
///   preparation still worked.
/// * The result never contains `..`, so the pinned-handle walk (which refuses
///   `..`) accepts it on every platform.
fn normalize_runs_dir(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    // A `..` with nothing to pop. On a relative path this is a
                    // leading `..` that climbs above the cwd: anchor the path
                    // at the current directory and re-fold, so `--runs-dir
                    // ../runs` keeps working (the non-Linux fallback always
                    // resolved it against the cwd). On an absolute path the
                    // `..` climbs past `/`, which escapes any base — reject it
                    // rather than silently clamp.
                    if path.is_absolute() {
                        return Err(anyhow::anyhow!(
                            "--runs-dir {} climbs above its base with `..`",
                            path.display()
                        ));
                    }
                    let cwd = std::env::current_dir()
                        .context("resolving current directory for a parent-relative --runs-dir")?;
                    return normalize_runs_dir(&cwd.join(path));
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    // Never hand back an empty path (see the invariant above): a `.`/`sub/..`
    // that folds to nothing means the current directory, which `.` expresses
    // without the empty-path divergence. An absolute root (`/`) keeps its
    // RootDir component, so `out` is only empty for a relative cwd-equivalent.
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Ok(out)
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
    use super::{clamp_recovery_window, normalize_runs_dir, MIN_RECOVERY_WINDOW};
    use std::path::{Path, PathBuf};
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

    // `--runs-dir ../runs` must keep working on Linux: the parent traversal is
    // folded lexically at the CLI boundary so the pinned-handle walk (which
    // refuses `..`) receives an equivalent path with no `..`. This mirrors the
    // non-Linux `create_dir_all` fallback, which always honoured it.
    #[test]
    fn normalize_runs_dir_folds_parent_traversal() {
        assert_eq!(
            normalize_runs_dir(Path::new("/a/b/../runs")).unwrap(),
            PathBuf::from("/a/runs")
        );
        assert_eq!(
            normalize_runs_dir(Path::new("sub/../runs")).unwrap(),
            PathBuf::from("runs")
        );
        assert_eq!(
            normalize_runs_dir(Path::new("/a/./b/./runs")).unwrap(),
            PathBuf::from("/a/b/runs")
        );
        // Nested parents: `/a/b/c/../../runs` → `/a/runs`.
        assert_eq!(
            normalize_runs_dir(Path::new("/a/b/c/../../runs")).unwrap(),
            PathBuf::from("/a/runs")
        );
    }

    // A path with no `.`/`..` is returned unchanged (the common case).
    #[test]
    fn normalize_runs_dir_passes_plain_paths_through() {
        assert_eq!(
            normalize_runs_dir(Path::new("/var/lib/runs")).unwrap(),
            PathBuf::from("/var/lib/runs")
        );
        assert_eq!(
            normalize_runs_dir(Path::new("runs")).unwrap(),
            PathBuf::from("runs")
        );
    }

    // A cwd-equivalent `--runs-dir` (`.`, `sub/..`) folds to nothing, which must
    // surface as `.` — never an empty path. An empty path would diverge
    // downstream: `create_root_nofollow("")` opens the cwd anchor (so
    // preparation works) while `open_root_nofollow("")` fails `ENOENT` (so the
    // sweep / completion cleanup break). `.` keeps every consumer consistent.
    #[test]
    fn normalize_runs_dir_never_returns_empty() {
        assert_eq!(
            normalize_runs_dir(Path::new(".")).unwrap(),
            PathBuf::from(".")
        );
        assert_eq!(
            normalize_runs_dir(Path::new("sub/..")).unwrap(),
            PathBuf::from(".")
        );
        assert_eq!(
            normalize_runs_dir(Path::new("./")).unwrap(),
            PathBuf::from(".")
        );
        // An absolute root keeps its RootDir component, so it is not empty.
        assert_eq!(
            normalize_runs_dir(Path::new("/")).unwrap(),
            PathBuf::from("/")
        );
    }

    // A leading `..` on a relative path climbs above the cwd and cannot be
    // folded lexically, so it is resolved against the current directory — the
    // same target the non-Linux `create_dir_all` fallback always resolved it
    // to. This keeps `--runs-dir ../runs` working on Linux (the pinned-handle
    // walk refuses a literal `..`), restoring the pre-hardening behaviour.
    #[test]
    fn normalize_runs_dir_resolves_leading_parent_against_cwd() {
        let cwd = std::env::current_dir().unwrap();
        let parent = cwd.parent().unwrap_or(&cwd).to_path_buf();
        assert_eq!(
            normalize_runs_dir(Path::new("../runs")).unwrap(),
            parent.join("runs")
        );
        // A leading `..` after infix components: `a/../../x` → `<parent>/x`.
        assert_eq!(
            normalize_runs_dir(Path::new("a/../../x")).unwrap(),
            parent.join("x")
        );
        // The result is absolute and `..`-free, so the no-follow walk accepts it.
        let out = normalize_runs_dir(Path::new("../runs")).unwrap();
        assert!(out.is_absolute());
        assert!(!out
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)));
    }

    // Only a `..` that climbs past the filesystem root (`/..`) escapes every
    // base, so it — and it alone — is rejected rather than silently clamped.
    #[test]
    fn normalize_runs_dir_rejects_climbing_above_root() {
        assert!(normalize_runs_dir(Path::new("/../x")).is_err());
        assert!(normalize_runs_dir(Path::new("/a/../../../x")).is_err());
    }
}
