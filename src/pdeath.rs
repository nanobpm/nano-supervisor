//! Parent-death cleanup: an agent (and the process group it leads) must die
//! with the daemon, even when the daemon is `kill -9`'d and so runs no shutdown
//! code of its own.
//!
//! - **Linux**: `PR_SET_PDEATHSIG` arms `SIGKILL` on the agent the moment its
//!   parent (the daemon) dies. Armed in the forked child before `exec`, with a
//!   getppid re-check to close the fork/parent-death race. Because PDEATHSIG
//!   only reaches the direct agent, [`watch`] additionally spawns the same
//!   process-group watchdog used on macOS so descendants the agent started are
//!   killed too.
//! - **macOS**: there is no `PR_SET_PDEATHSIG`, so we spawn a tiny kqueue
//!   watchdog (a hidden subcommand of our own binary) that waits on the daemon
//!   pid via `EVFILT_PROC`/`NOTE_EXIT` and then `SIGKILL`s the agent's process
//!   group.

// Imported unconditionally: the no-op `arm` below is compiled on every non-Linux
// target (including Windows), so the `Command` type must always resolve or the
// crate fails to build there.
use tokio::process::Command;

/// Arm parent-death cleanup on the command about to be spawned. On Linux this
/// installs a `pre_exec` hook; on other platforms it is a no-op (macOS uses the
/// post-spawn [`watch`] watchdog instead).
#[cfg(target_os = "linux")]
pub fn arm(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    let parent = std::process::id();
    // SAFETY: pre_exec runs in the forked child before exec; we only call
    // async-signal-safe libc functions (prctl, getppid, raise) and touch no
    // Rust allocator state.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Close the race: if the daemon already died between fork and here,
            // PR_SET_PDEATHSIG will never fire, so self-terminate now.
            if libc::getppid() as u32 != parent {
                libc::raise(libc::SIGKILL);
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub fn arm(_cmd: &mut Command) {}

/// `SIGKILL` a process group by its leader pid (the pid is also the pgid, since
/// agents are spawned with `process_group(0)`). Used by the ACP/pipe cancellation
/// guards so that dropping an in-flight agent — e.g. when a slot aborts its
/// `execute` future on lease loss — tears down the whole tree, not just the
/// leader that `kill_on_drop` reaps. Harmless if the group is already gone.
#[cfg(unix)]
pub(crate) fn sigkill_group(pid: u32) {
    // SAFETY: a plain libc kill of a process group; no Rust state is touched and
    // an already-dead group simply yields ESRCH.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
pub(crate) fn sigkill_group(_pid: u32) {}

/// `SIGTERM` a process group by its leader pid, via a direct libc `kill(2)`.
/// Preferred over spawning an external `kill(1)`: a spawned process would
/// inherit the daemon's environment (including `CAMUNDA_*`/`ZEEBE_*` credentials)
/// for the lifetime of that child, exposing them via `/proc/<pid>/environ` to a
/// same-user host agent during shutdown — defeating the env scrubbing applied to
/// the agent/git children. The libc call touches no Rust state and delivers the
/// same group signal without leaking the daemon environment. Harmless if the
/// group is already gone (`ESRCH`).
#[cfg(unix)]
pub(crate) fn sigterm_group(pid: u32) {
    // SAFETY: a plain libc kill of a process group; no Rust state is touched and
    // an already-dead group simply yields ESRCH.
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
    }
}

#[cfg(not(unix))]
pub(crate) fn sigterm_group(_pid: u32) {}

/// True while at least one process in the group led by `pid` is still alive.
/// `kill(-pid, 0)` probes the group without delivering a signal: `0` means a
/// member still exists, an error (`ESRCH`) means the group is gone. Used to poll
/// for graceful group exit *without reaping the leader* — reaping would free the
/// pid and invalidate the pgid we still need for the final group kill.
#[cfg(unix)]
pub(crate) fn group_alive(pid: u32) -> bool {
    // SAFETY: a plain libc kill(_, 0) liveness probe; touches no Rust state.
    unsafe { libc::kill(-(pid as libc::pid_t), 0) == 0 }
}

#[cfg(not(unix))]
pub(crate) fn group_alive(_pid: u32) -> bool {
    false
}

/// Gracefully tear down an agent's whole process group and reap the leader:
/// `SIGTERM` the group, poll up to `grace` for it to exit (reaping the leader as
/// soon as it does), then `SIGKILL` the group to catch any `TERM`-resistant
/// descendant, and finally reap the leader. Killing the group — not just
/// `start_kill`ing the direct leader — is what prevents a tool the agent started
/// from surviving a timeout / lease-loss cancellation and overlapping the
/// redelivered job. Safe to call when the group is already gone.
///
/// `pgid` is the *preserved* process-group id (the leader's pid captured at
/// spawn), passed in rather than read from `child.id()`: a caller may already
/// have reaped the leader (the pipe EOF path and ACP request path call
/// `child.wait()`), which drops `child.id()` to `None`; keying the group kill off
/// that would silently skip it and leak descendants. A reaped leader's pid stays
/// reserved as a pgid while any descendant remains in the group, so probing it
/// still identifies the right group.
#[cfg(unix)]
pub(crate) async fn terminate_group_and_reap(
    child: &mut tokio::process::Child,
    pgid: Option<u32>,
    grace: std::time::Duration,
) {
    if let Some(pid) = pgid {
        // Only signal the pgid while the group genuinely still has a member. If
        // the leader was already reaped and no descendant remains, the pid is no
        // longer reserved and could have been recycled — signalling it would risk
        // hitting an unrelated group.
        if group_alive(pid) {
            // Negative pid = the whole process group (agent + tools it started).
            // Signal via a direct libc `kill(-pgid, SIGTERM)` rather than
            // spawning `kill(1)`: a spawned child would inherit the daemon's
            // scrubbed-from-the-agent `CAMUNDA_*`/`ZEEBE_*` credentials and expose
            // them via `/proc/<pid>/environ` to a same-user host agent for the
            // duration of that child.
            sigterm_group(pid);
            let deadline = std::time::Instant::now() + grace;
            loop {
                // Reap the leader the instant it exits. Otherwise its unreaped
                // zombie keeps `group_alive` true for the entire grace window,
                // forcing a fixed multi-second wait on every clean shutdown. A
                // live descendant keeps the pgid reserved, so reaping the leader
                // here does not free the pid still needed for the group SIGKILL.
                let _ = child.try_wait();
                if !group_alive(pid) {
                    // Leader reaped and no descendant left: the group is gone.
                    // Don't re-signal (the freed pid could now be recycled).
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    // A `TERM`-resistant descendant survived; the pgid is still
                    // valid (that descendant holds it). Re-probe immediately
                    // before the SIGKILL: the last survivor can exit in the
                    // window since the loop's top-of-iteration `group_alive`
                    // check, freeing the pgid to be recycled by an unrelated
                    // group — only signal when the group is still present.
                    if group_alive(pid) {
                        sigkill_group(pid);
                    }
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let _ = child.start_kill();
    // Best-effort reap so we don't leak a zombie (no-op if already reaped).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
}

#[cfg(not(unix))]
pub(crate) async fn terminate_group_and_reap(
    child: &mut tokio::process::Child,
    _pgid: Option<u32>,
    _grace: std::time::Duration,
) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
}

/// Cancellation cleanup guard: SIGKILLs the agent's process group when dropped,
/// unless disarmed. Ensures a dropped (aborted) in-flight agent tears down the
/// whole tree — not just the leader `kill_on_drop` reaps — while the normal path
/// disarms it once the group has been reaped (so a recycled pid is never hit).
pub(crate) struct GroupGuard(Option<u32>);

impl GroupGuard {
    pub(crate) fn new(pid: Option<u32>) -> Self {
        Self(pid)
    }

    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            // Only signal while the group genuinely still has a member. A
            // cancellation can drop the guard in the window after the leader was
            // reaped (by `kill_on_drop`, or a prior `child.wait()` on the pipe
            // EOF / ACP request path) but before `disarm` runs; once the group is
            // empty the pid is no longer reserved as a pgid and may have been
            // recycled for an unrelated group, so an unconditional kill could hit
            // it. Gating on `group_alive` mirrors `terminate_group_and_reap` and
            // keeps a live descendant reserving the pgid the target of the kill.
            if group_alive(pid) {
                sigkill_group(pid);
            }
        }
    }
}

/// Start a watchdog that kills the agent's whole process group when the daemon
/// dies. `agent_pid` is the agent's pid, which is also its process-group id (the
/// agent is spawned with `process_group(0)`).
///
/// This runs on **both** macOS and Linux. On Linux `PR_SET_PDEATHSIG` ([`arm`])
/// only signals the direct agent process, not the descendants it spawns; those
/// share the agent's process group but receive no signal on parent death, so a
/// `kill -9` of the daemon would orphan them. The watchdog closes that gap by
/// signalling the entire process group once the daemon exits.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn watch(agent_pid: u32) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let parent = std::process::id();
    // Capture the daemon's start time here, while the daemon is *guaranteed*
    // alive, and pass it to the watchdog. If we left the watchdog to read
    // `/proc/<parent>/stat` itself (as it used to), a daemon SIGKILLed in the
    // window between this spawn and the watchdog reaching that read would leave
    // `expected_start = None`, disabling PID-reuse detection and letting the
    // watchdog wait forever on a recycled pid. On non-Linux the value is unused.
    #[cfg(target_os = "linux")]
    let parent_start = parent_start_time(parent);
    #[cfg(not(target_os = "linux"))]
    let parent_start: Option<u64> = None;
    // Detached so it survives independently and can reap us; it exits on its own
    // once the target process group is gone.
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__reap-watchdog")
        .arg("--parent-pid")
        .arg(parent.to_string())
        .arg("--pgid")
        .arg(agent_pid.to_string());
    if let Some(start) = parent_start {
        cmd.arg("--parent-start").arg(start.to_string());
    }
    // Scrub the environment before spawning. The watchdog is a sibling of the
    // agent's process group and needs nothing but its own executable and the CLI
    // args above; inheriting the daemon's environment would expose the OAuth /
    // basic-auth / NANO_AGENTIC_* secrets (the very ones the agent launch sites
    // strip) to a same-user agent that reads `/proc/<watchdog-pid>/environ`.
    cmd.env_clear();
    // The parent-death watchdog is a best-effort backstop, so a transient spawn
    // failure (e.g. `fork`/exec hitting a resource limit) must not abort the
    // agent launch — on Linux `PR_SET_PDEATHSIG` ([`arm`]) still tears down the
    // direct agent, and failing every job on a watchdog fork error under memory
    // pressure would be worse than the residual orphan-descendants risk. But the
    // failure must not be *silent*: surface it so an agent tree left orphaned
    // after a daemon `kill -9` is diagnosable instead of mysterious (on macOS,
    // where this watchdog is the only parent-death mechanism, that log is the
    // sole signal the gap opened).
    if let Err(e) = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        crate::worker::log(&format!(
            "warning: parent-death watchdog failed to spawn for pid {agent_pid}: {e}"
        ));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn watch(_agent_pid: u32) {}

/// The macOS watchdog loop: block on the parent pid via kqueue `NOTE_EXIT`,
/// then `SIGKILL` the agent's process group. Returns when the parent is gone
/// and the group has been signalled — or early, without signalling, once the
/// agent's process group has exited on its own (a completed job), so the
/// watchdog does not linger as a polling child for the daemon's whole lifetime.
#[cfg(target_os = "macos")]
pub fn reap_watchdog(parent_pid: u32, pgid: u32, _parent_start: Option<u64>) {
    // SAFETY: standard kqueue usage; the fd is closed before return.
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            // No kqueue: fall back to polling both conditions.
            // Re-probe the group immediately before signalling: the parent may
            // have exited while the agent's group already went away, freeing the
            // pid to be recycled by an unrelated group — `group_alive` (a
            // `kill(-pgid, 0)` liveness check) ensures we only SIGKILL a group
            // that still genuinely holds this pgid.
            if wait_parent_or_group_gone(parent_pid, pgid, None) && group_alive(pgid) {
                sigkill_group(pgid);
            }
            return;
        }
        let mut change: libc::kevent = std::mem::zeroed();
        change.ident = parent_pid as libc::uintptr_t;
        change.filter = libc::EVFILT_PROC;
        change.flags = libc::EV_ADD | libc::EV_CLEAR;
        change.fflags = libc::NOTE_EXIT;
        // Register the parent-exit filter without blocking (nevents = 0).
        let registered = libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
        let parent_died = if registered != 0 {
            // Could not watch the parent (e.g. it already exited): reap the group.
            true
        } else {
            loop {
                // Wait up to 200ms for the parent to exit, then re-check the
                // group so a watchdog whose job already finished exits instead
                // of polling until the daemon itself dies.
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 200_000_000,
                };
                let mut event: libc::kevent = std::mem::zeroed();
                let n = libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, &ts);
                if n > 0
                    && ((event.flags & libc::EV_ERROR) != 0
                        || (event.fflags & libc::NOTE_EXIT) != 0)
                {
                    break true; // parent gone -> reap the group
                }
                if libc::kill(-(pgid as libc::pid_t), 0) != 0 {
                    break false; // group already gone -> nothing to do
                }
            }
        };
        libc::close(kq);
        // Re-probe the group immediately before signalling: after the parent
        // exited the agent's group may already have vanished, freeing the pid to
        // be recycled by an unrelated group. `group_alive` gates the kill so a
        // stale numeric pgid can never target a recycled group.
        if parent_died && group_alive(pgid) {
            sigkill_group(pgid);
        }
    }
}

/// The Linux watchdog loop: wait until the daemon (parent) is gone, then
/// `SIGKILL` the agent's entire process group so descendants the agent started
/// are reaped too (PDEATHSIG alone would only kill the direct agent). Returns
/// early, without signalling, once the agent's process group has exited on its
/// own (a completed job), so the watchdog does not linger for the daemon's whole
/// lifetime.
#[cfg(target_os = "linux")]
pub fn reap_watchdog(parent_pid: u32, pgid: u32, parent_start: Option<u64>) {
    // Prefer the start time the daemon captured for us while it was still alive
    // (passed via `--parent-start`); only fall back to reading `/proc` ourselves
    // if it was not supplied. Reading it here is racy: the daemon may already be
    // gone, yielding `None` and silently disabling PID-reuse detection. Using the
    // daemon-supplied value keeps `expected_start` populated so a recycled parent
    // pid can never masquerade as the original and strand the agent group.
    let expected_start = parent_start.or_else(|| parent_start_time(parent_pid));
    // SAFETY: plain libc calls; no shared Rust state is touched.
    unsafe {
        // Re-probe the group immediately before signalling: the parent may have
        // exited while the agent's group already went away, freeing the pid to
        // be recycled by an unrelated group. `group_alive` gates the kill so a
        // stale numeric pgid can never target a recycled group.
        if wait_parent_or_group_gone(parent_pid, pgid, expected_start) && group_alive(pgid) {
            sigkill_group(pgid);
        }
    }
}

/// Read the parent's start time (field 22 of `/proc/<pid>/stat`) so the Linux
/// watchdog can detect PID reuse. After the daemon exits its numeric pid can be
/// recycled (e.g. `Restart=on-failure`); the start time is unique per pid
/// incarnation, so a later mismatch means the original parent is gone even when
/// `kill(pid, 0)` still succeeds for the unrelated reusing process.
#[cfg(target_os = "linux")]
fn parent_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` (field 2) may itself contain spaces and parentheses, so parse from
    // just past the final ')'. After it, field 3 (state) is the first token, so
    // starttime (field 22) is the 20th token — 0-based index 19.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// True when the parent pid exists but is a **zombie** (`Z`) or **dead** (`X`/`x`)
/// process — the daemon has exited but its own parent has not yet reaped it. Such
/// a process still answers `kill(pid, 0)` with success and keeps its start time,
/// so [`wait_parent_or_group_gone`]'s liveness + PID-reuse checks both miss it
/// and the watchdog would wait forever instead of reaping the agent's orphaned
/// group. Read field 3 (state) of `/proc/<pid>/stat` — the first token after the
/// final `')'` that closes the (space-containing) `comm` field.
#[cfg(target_os = "linux")]
fn parent_is_dead_or_zombie(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        // Unreadable /proc entry: treat as "not observably dead" here — the
        // caller's `kill(_, 0)` probe remains the primary liveness signal.
        return false;
    };
    let Some(rparen) = stat.rfind(')') else {
        return false;
    };
    matches!(
        stat[rparen + 1..].split_whitespace().next(),
        Some("Z") | Some("X") | Some("x")
    )
}

/// Poll until either the parent (daemon) exits or the agent's process group has
/// already gone away. Returns `true` when the parent died (the caller should
/// reap the group), `false` when the group vanished on its own (nothing to do).
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn wait_parent_or_group_gone(
    parent_pid: u32,
    pgid: u32,
    expected_start: Option<u64>,
) -> bool {
    #[cfg(not(target_os = "linux"))]
    let _ = expected_start;
    loop {
        if libc::kill(parent_pid as libc::pid_t, 0) != 0 {
            return true; // parent gone -> reap the group
        }
        // Detect PID reuse: the pid answers `kill(_, 0)` but now belongs to a
        // different process incarnation, so the daemon we guard has exited and
        // its group must be reaped rather than waited on forever.
        #[cfg(target_os = "linux")]
        if let Some(start) = expected_start {
            if parent_start_time(parent_pid) != Some(start) {
                return true;
            }
        }
        // A zombie / dead-but-unreaped daemon still answers `kill(_, 0)` and
        // keeps its start time, so the two checks above miss it; detect that
        // terminal state explicitly so the watchdog reaps the orphaned group
        // instead of waiting forever on a process that can never come back.
        #[cfg(target_os = "linux")]
        if parent_is_dead_or_zombie(parent_pid) {
            return true;
        }
        if libc::kill(-(pgid as libc::pid_t), 0) != 0 {
            return false; // process group already gone -> nothing to reap
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Stub on platforms without a watchdog process (they rely on [`arm`]).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn reap_watchdog(_parent_pid: u32, _pgid: u32, _parent_start: Option<u64>) {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parent_start_time_reads_own_incarnation() {
        // Our own process is alive, so its start time must be readable and stable
        // across reads — this is the value the daemon captures up front and hands
        // to the watchdog so PID-reuse detection survives a daemon SIGKILL that
        // races the watchdog's own `/proc` read.
        let me = std::process::id();
        let a = parent_start_time(me).expect("own start time readable");
        let b = parent_start_time(me).expect("own start time readable");
        assert_eq!(a, b);
        assert!(a > 0);
    }

    #[test]
    fn own_process_is_not_dead_or_zombie() {
        // Our own live, running process must not be classified as dead/zombie —
        // otherwise the watchdog would spuriously reap a live daemon's group.
        assert!(!parent_is_dead_or_zombie(std::process::id()));
        // A pid that cannot exist yields a false (unreadable /proc) — the
        // caller's `kill(_, 0)` probe is the authority for a truly-gone pid.
        assert!(!parent_is_dead_or_zombie(u32::MAX));
    }
}
