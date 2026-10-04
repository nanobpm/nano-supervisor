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
        /// Test-harness escape hatch: run attached inside an agent run instead of
        /// refusing (see the `NANO_AGENT_RUN` guard). Bound to the invoking
        /// process so the job's teardown still kills it. For the hermetic
        /// contract tests only — never for a real fleet.
        #[arg(long = "foreground-for-tests", hide = true)]
        foreground_for_tests: bool,
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
        /// Test-harness escape hatch: run attached inside an agent run instead of
        /// refusing (see the `NANO_AGENT_RUN` guard). Bound to the invoking
        /// process so the job's teardown still kills it. For the hermetic
        /// contract tests only — never for a real fleet.
        #[arg(long = "foreground-for-tests", hide = true)]
        foreground_for_tests: bool,
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

/// Resolve whether the `daemon` should lease each activation, from the parsed
/// CLI flags. Leasing is the default; `--no-lease` is the only opt-out, so the
/// decision derives solely from `!no_lease`. The legacy `--with-lease` is a
/// hidden, deprecated no-op (leasing is already implied) kept so existing
/// invocations keep working — it is intentionally not consulted here, which also
/// makes `--no-lease` win when both are passed.
fn daemon_leases(no_lease: bool) -> bool {
    !no_lease
}

/// Env var the worker stamps on every agent process (`slot::build_agent_env`) to
/// mark its process tree as belonging to an agent run. Its presence here means
/// *this* `nano-supervisor` was launched by an agent.
const AGENT_RUN_ENV: &str = "NANO_AGENT_RUN";
/// Explicit opt-in letting a supervisor/worker run attached inside an agent run.
const ALLOW_NESTED_ENV: &str = "NANO_ALLOW_NESTED_SUPERVISOR";

/// Pure refusal decision for a nested supervisor/worker (#40), split out so it is
/// testable without touching process-global env. Returns the explanatory error
/// message when the command must be refused, or `None` when it may run.
///
/// * `run` — the value of `NANO_AGENT_RUN` (`None`/empty ⇒ not inside an agent
///   run ⇒ never refused).
/// * `foreground_for_tests` — the `--foreground-for-tests` flag.
/// * `allow_nested` — the value of `NANO_ALLOW_NESTED_SUPERVISOR` (`"1"` opts in).
fn nested_refusal(
    command: &str,
    run: Option<&str>,
    foreground_for_tests: bool,
    allow_nested: Option<&str>,
) -> Option<String> {
    let run = run.filter(|v| !v.is_empty())?;
    if foreground_for_tests || allow_nested == Some("1") {
        return None;
    }
    Some(format!(
        "refusing to start `nano-supervisor {command}` inside an agent run \
         ({AGENT_RUN_ENV}={run}). A supervisor or worker started by an agent \
         escapes the job's teardown and becomes a phantom that can lease real \
         jobs and misreport the fleet. Agents must never start a real supervisor \
         or daemon outside the hermetic test harness. If this IS a contract test, \
         opt in with `--foreground-for-tests` or `{ALLOW_NESTED_ENV}=1` to run \
         attached (bound to the invoking process)."
    ))
}

/// Refuse to start a long-lived supervisor/worker inside an agent run (#40).
///
/// The worker marks every agent's environment with `NANO_AGENT_RUN`. A
/// supervisor an agent starts daemonises (`setsid`, new session) and so escapes
/// the job's process-group teardown, becoming a phantom that can lease real jobs
/// and misreport the fleet. So when `NANO_AGENT_RUN` is set we refuse, unless the
/// caller explicitly opts in — `--foreground-for-tests` or
/// `NANO_ALLOW_NESTED_SUPERVISOR=1` — which the hermetic contract tests use to
/// run **attached**: no `setsid`, and bound to the invoking process so the job's
/// teardown still takes it down.
fn guard_nested_supervisor(command: &str, foreground_for_tests: bool) -> Result<()> {
    let run = std::env::var(AGENT_RUN_ENV).ok();
    let allow = std::env::var(ALLOW_NESTED_ENV).ok();
    if let Some(msg) =
        nested_refusal(command, run.as_deref(), foreground_for_tests, allow.as_deref())
    {
        anyhow::bail!(msg);
    }
    if run.as_deref().is_some_and(|r| !r.is_empty()) {
        // Opted in: run attached. Bind to the invoking agent's death so the job's
        // process-group kill (or the agent exiting) takes this process down too.
        pdeath::bind_self_to_parent_death();
    }
    Ok(())
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
            foreground_for_tests,
        } => {
            guard_nested_supervisor("work", foreground_for_tests)?;
            work::run(work::WorkOptions {
                hire,
                job_types: job_type,
                profile,
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
            no_lease,
            with_lease: _,
            foreground_for_tests,
        } => {
            guard_nested_supervisor("daemon", foreground_for_tests)?;
            let opts = daemon::DaemonOptions {
                profile,
                with_lease: daemon_leases(no_lease),
                slots: slots.max(1),
                only: hire,
                recovery_window: clamp_recovery_window(recovery_window),
                idle_timeout: Duration::from_millis(idle_timeout),
                poll_timeout: Duration::from_millis(poll_timeout),
                clone_timeout: Duration::from_millis(clone_timeout),
                runs_dir: match runs_dir {
                    Some(d) => normalize_runs_dir(&d)?,
                    None => normalize_runs_dir(&default_runs_dir())?,
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

/// Normalize an operator-supplied `--runs-dir` (or an environment-derived
/// default root) into a `..`-free path the Linux pinned-handle walk
/// (`saferoot::DirHandle::create_root_nofollow`, which refuses any `..`) will
/// accept — WITHOUT ever changing which directory the path denotes.
///
/// Only two rewrites are safe to perform lexically, because neither can cross a
/// symlink:
/// * `.` components are dropped (they never change the target).
/// * A *leading* `..` on a relative path (no normal component precedes it) is
///   resolved against the current directory. `std::env::current_dir()` returns
///   the kernel's fully resolved, symlink-free working directory, so folding
///   `..` against *its* components can never silently retarget across a link.
///   This preserves the pre-hardening `--runs-dir ../runs` behaviour the
///   non-Linux `create_dir_all` fallback still has.
///
/// Every OTHER `..` is REJECTED rather than folded. Collapsing `a/../b`
/// lexically is only correct when `a` is a real directory; if `a` is a symlink,
/// `a/..` resolves to the link *target's* parent, so folding would hand the
/// no-follow walk a path pointing at a different root than the filesystem does —
/// and the walk, seeing no `..`, could create and later wipe a job tree under
/// the wrong root (e.g. `/tmp/link/../runs` with `link -> /outside/sub` folds to
/// `/tmp/runs` but resolves to `/outside/runs`). This layer must not touch the
/// filesystem to tell a directory from a symlink, so it fails closed: any `..`
/// that would pop an operator-supplied component, and any `..` that climbs past
/// the filesystem root (`/..`), is rejected — the operator passes an
/// already-resolved path instead.
///
/// Two invariants keep the downstream no-follow layer consistent:
/// * The result never contains `..`, so the pinned-handle walk accepts it.
/// * The result is never empty. A cwd-equivalent input (`.`, `./`) normalizes
///   to `.`, because an empty path would diverge between `create_root_nofollow`
///   (which opens the anchor, i.e. the cwd) and `open_root_nofollow` (which
///   `openat2`s the literal path and fails an empty one with `ENOENT`) —
///   breaking the sweep / completion-cleanup while preparation still worked.
pub(crate) fn normalize_runs_dir(path: &Path) -> Result<PathBuf> {
    normalize_runs_dir_impl(path, || {
        std::env::current_dir()
            .context("resolving current directory for a parent-relative --runs-dir")
    })
}

/// Core of [`normalize_runs_dir`], parameterized over the current-directory
/// lookup so tests can resolve a leading `..` against a fixed base WITHOUT
/// mutating the process-wide working directory (which would race parallel
/// tests). `cwd` is invoked at most once, only when a leading `..` must be
/// anchored.
fn normalize_runs_dir_impl(path: &Path, cwd: impl FnOnce() -> Result<PathBuf>) -> Result<PathBuf> {
    // Retained components. `trusted` marks one that came from the symlink-free
    // cwd (safe to pop); operator-supplied components are untrusted, so a `..`
    // that would pop one is rejected rather than folded across a possible link.
    let mut stack: Vec<(std::ffi::OsString, bool)> = Vec::new();
    let mut prefix: Option<std::ffi::OsString> = None;
    let mut absolute = path.is_absolute();
    let mut cwd = Some(cwd);

    for comp in path.components() {
        match comp {
            // Preserve a Windows drive/UNC prefix verbatim; it is never popped
            // and anchors the rebuilt path (a no-op on Unix, where there is no
            // prefix). `RootDir` only marks the path absolute.
            Component::Prefix(p) => prefix = Some(p.as_os_str().to_os_string()),
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::Normal(name) => stack.push((name.to_os_string(), false)),
            Component::ParentDir => match stack.last() {
                // A cwd component is symlink-free, so popping it is safe.
                Some((_, true)) => {
                    stack.pop();
                }
                // Popping an operator-supplied component could cross a symlink
                // and silently retarget the path — fail closed.
                Some((_, false)) => {
                    return Err(anyhow::anyhow!(
                        "runs directory {} contains a `..` after a path component, which could \
                         change its target across a symlink; pass an already-resolved path",
                        path.display()
                    ));
                }
                None => {
                    if absolute {
                        // `/..` climbs past the filesystem root.
                        return Err(anyhow::anyhow!(
                            "runs directory {} climbs above its base with `..`",
                            path.display()
                        ));
                    }
                    // Leading `..` on a relative path: anchor at the
                    // symlink-free current directory (once) and pop one of its
                    // components for this `..`.
                    let base = match cwd.take() {
                        Some(f) => f()?,
                        // `current_dir()` returns an absolute path, so after the
                        // first anchor `absolute` is set and this arm is never
                        // reached again; guard defensively rather than panic.
                        None => {
                            return Err(anyhow::anyhow!(
                                "runs directory {} could not be resolved against a non-absolute \
                                 current directory",
                                path.display()
                            ))
                        }
                    };
                    for c in base.components() {
                        match c {
                            Component::Prefix(p) => prefix = Some(p.as_os_str().to_os_string()),
                            Component::RootDir => absolute = true,
                            Component::Normal(n) => stack.push((n.to_os_string(), true)),
                            _ => {}
                        }
                    }
                    if stack.pop().is_none() {
                        // The cwd is the filesystem root, so this `..` climbs
                        // past it.
                        return Err(anyhow::anyhow!(
                            "runs directory {} climbs above the filesystem root",
                            path.display()
                        ));
                    }
                }
            },
        }
    }

    let mut out = PathBuf::new();
    if let Some(p) = &prefix {
        out.push(p);
    }
    if absolute {
        out.push(Component::RootDir.as_os_str());
    }
    for (name, _) in &stack {
        out.push(name);
    }
    // Never hand back an empty path (see the invariant above): a relative
    // cwd-equivalent input folds to nothing, which `.` expresses without the
    // empty-path divergence. An absolute root (`/`) keeps its RootDir, so `out`
    // is only empty for a relative cwd-equivalent.
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
    use super::{
        clamp_recovery_window, daemon_leases, nested_refusal, normalize_runs_dir,
        normalize_runs_dir_impl, Cli, Cmd, MIN_RECOVERY_WINDOW,
    };
    use clap::Parser;
    use std::path::{Component, Path, PathBuf};
    use std::time::Duration;

    #[test]
    fn nested_refusal_blocks_an_agent_run_without_opt_in() {
        // Inside an agent run (NANO_AGENT_RUN set), no opt-in: refused, and the
        // message explains itself.
        let msg = nested_refusal("daemon", Some("214829"), false, None)
            .expect("must refuse inside an agent run");
        assert!(msg.contains("NANO_AGENT_RUN"), "message: {msg}");
        assert!(msg.contains("214829"), "message names the run: {msg}");
        assert!(msg.contains("daemon"), "message names the command: {msg}");
    }

    #[test]
    fn nested_refusal_allows_outside_an_agent_run() {
        // Not inside an agent run: never refused, regardless of opt-in.
        assert!(nested_refusal("daemon", None, false, None).is_none());
        assert!(nested_refusal("work", Some(""), false, None).is_none());
    }

    #[test]
    fn nested_refusal_opt_in_flag_and_env_bypass() {
        // The flag opts in.
        assert!(nested_refusal("daemon", Some("214829"), true, None).is_none());
        // `NANO_ALLOW_NESTED_SUPERVISOR=1` opts in.
        assert!(nested_refusal("daemon", Some("214829"), false, Some("1")).is_none());
        // Any other value does NOT opt in.
        assert!(nested_refusal("daemon", Some("214829"), false, Some("0")).is_some());
        assert!(nested_refusal("daemon", Some("214829"), false, Some("")).is_some());
    }

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

    // Interior `..` is REJECTED, not folded: collapsing `a/../b` lexically is
    // only correct when `a` is a real directory, but `a` could be a symlink
    // whose `..` resolves elsewhere. Since this boundary must not touch the
    // filesystem to tell them apart, it fails closed so the no-follow walk can
    // never be handed a path that silently points at a different root.
    #[test]
    fn normalize_runs_dir_rejects_interior_parent_traversal() {
        assert!(normalize_runs_dir(Path::new("/a/b/../runs")).is_err());
        assert!(normalize_runs_dir(Path::new("sub/../runs")).is_err());
        assert!(normalize_runs_dir(Path::new("/a/b/c/../../runs")).is_err());
        assert!(normalize_runs_dir(Path::new("sub/..")).is_err());
        // The reviewer's symlink-hiding case: `link` could be a symlink, so
        // `link/..` must not be folded away before the no-follow walk sees it.
        assert!(normalize_runs_dir(Path::new("/tmp/link/../runs")).is_err());
    }

    // `.` components are always safe to drop — they never change the target.
    #[test]
    fn normalize_runs_dir_folds_current_dir_components() {
        assert_eq!(
            normalize_runs_dir(Path::new("/a/./b/./runs")).unwrap(),
            PathBuf::from("/a/b/runs")
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

    // A cwd-equivalent `--runs-dir` (`.`, `./`) folds to nothing, which must
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
            normalize_runs_dir(Path::new("./")).unwrap(),
            PathBuf::from(".")
        );
        // An absolute root keeps its RootDir component, so it is not empty.
        assert_eq!(
            normalize_runs_dir(Path::new("/")).unwrap(),
            PathBuf::from("/")
        );
    }

    // A leading `..` on a relative path is resolved against the current
    // directory — the same target the non-Linux `create_dir_all` fallback
    // always resolved it to, so `--runs-dir ../runs` keeps working on Linux
    // (the pinned-handle walk refuses a literal `..`). The cwd is INJECTED
    // here so the test never mutates the process-wide working directory (which
    // would race parallel tests); the kernel's real cwd is symlink-free, so
    // folding `..` against it is safe.
    #[test]
    fn normalize_runs_dir_resolves_leading_parent_against_cwd() {
        let out = normalize_runs_dir_impl(Path::new("../runs"), || {
            Ok(PathBuf::from("/home/user/project"))
        })
        .unwrap();
        assert_eq!(out, PathBuf::from("/home/user/runs"));
        // Multiple leading `..` climb multiple cwd components.
        let out = normalize_runs_dir_impl(Path::new("../../runs"), || {
            Ok(PathBuf::from("/home/user/project"))
        })
        .unwrap();
        assert_eq!(out, PathBuf::from("/home/runs"));
        // The result is absolute and `..`-free, so the no-follow walk accepts it.
        assert!(out.is_absolute());
        assert!(!out.components().any(|c| matches!(c, Component::ParentDir)));
    }

    // Unsafe parent traversals are rejected, never silently clamped: an
    // absolute `..` that climbs past `/`, a leading `..` from the filesystem
    // root (nothing to climb to), and an interior `..` after a component on a
    // relative path (the component could be a symlink) all fail closed.
    #[test]
    fn normalize_runs_dir_rejects_unsafe_parent_traversal() {
        assert!(normalize_runs_dir(Path::new("/../x")).is_err());
        assert!(normalize_runs_dir(Path::new("/a/../../../x")).is_err());
        // Interior `..` after a relative component: rejected, not folded.
        assert!(normalize_runs_dir_impl(Path::new("a/../../x"), || {
            Ok(PathBuf::from("/home/user/project"))
        })
        .is_err());
        // A leading `..` when the cwd is the filesystem root has nothing above.
        assert!(normalize_runs_dir_impl(Path::new("../runs"), || Ok(PathBuf::from("/"))).is_err());
    }

    /// Parse a `daemon` invocation and return its `(no_lease, with_lease)` flags.
    fn parse_daemon_flags(args: &[&str]) -> (bool, bool) {
        match Cli::parse_from(args).cmd {
            Cmd::Daemon {
                no_lease,
                with_lease,
                ..
            } => (no_lease, with_lease),
            _ => panic!("expected the `daemon` subcommand for args {args:?}"),
        }
    }

    #[test]
    fn daemon_leases_by_default() {
        // The central default inversion: a bare `daemon` must fence (lease) with
        // neither opt-out nor the legacy flag supplied.
        let (no_lease, with_lease) = parse_daemon_flags(&["nano-supervisor", "daemon"]);
        assert!(!no_lease, "bare `daemon` must not set --no-lease");
        assert!(
            !with_lease,
            "bare `daemon` must not set the legacy --with-lease"
        );
        assert!(
            daemon_leases(no_lease),
            "bare `daemon` must lease by default"
        );
    }

    #[test]
    fn daemon_no_lease_opts_out() {
        let (no_lease, _) = parse_daemon_flags(&["nano-supervisor", "daemon", "--no-lease"]);
        assert!(no_lease, "--no-lease must parse as set");
        assert!(
            !daemon_leases(no_lease),
            "--no-lease must run the daemon unfenced"
        );
    }

    #[test]
    fn daemon_legacy_with_lease_still_accepted() {
        // Backward compatibility: the hidden, deprecated `--with-lease` must
        // still parse and is a no-op — leasing is already the default.
        let (no_lease, with_lease) =
            parse_daemon_flags(&["nano-supervisor", "daemon", "--with-lease"]);
        assert!(with_lease, "legacy --with-lease must still be accepted");
        assert!(!no_lease);
        assert!(
            daemon_leases(no_lease),
            "legacy --with-lease must keep leasing on"
        );
    }

    #[test]
    fn daemon_no_lease_wins_over_legacy_with_lease() {
        // Leasing derives solely from `!no_lease`, so if both flags are passed
        // the opt-out wins and the daemon runs unfenced.
        let (no_lease, with_lease) =
            parse_daemon_flags(&["nano-supervisor", "daemon", "--with-lease", "--no-lease"]);
        assert!(no_lease);
        assert!(with_lease);
        assert!(
            !daemon_leases(no_lease),
            "--no-lease must win when combined with the legacy --with-lease"
        );
    }
}
