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
/// `SIGTERM` the group, poll up to `grace` for it to exit (without reaping the
/// leader, so the pgid stays valid), then `SIGKILL` the group to catch any
/// `TERM`-resistant descendant, and finally reap the leader. Killing the group —
/// not just `start_kill`ing the direct leader — is what prevents a tool the agent
/// started from surviving a timeout / lease-loss cancellation and overlapping the
/// redelivered job. Safe to call when the group is already gone.
#[cfg(unix)]
pub(crate) async fn terminate_group_and_reap(
    child: &mut tokio::process::Child,
    grace: std::time::Duration,
) {
    if let Some(pid) = child.id() {
        // Negative pid = the whole process group (agent + tools it started).
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &format!("-{pid}")])
            .status();
        let deadline = std::time::Instant::now() + grace;
        while std::time::Instant::now() < deadline && group_alive(pid) {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // Escalate: SIGKILL the whole group so a descendant that ignored TERM
        // cannot survive. Done before the leader is reaped, so the pgid is valid.
        sigkill_group(pid);
    }
    let _ = child.start_kill();
    // Best-effort reap so we don't leak a zombie.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
}

#[cfg(not(unix))]
pub(crate) async fn terminate_group_and_reap(
    child: &mut tokio::process::Child,
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
            sigkill_group(pid);
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
    // Detached so it survives independently and can reap us; it exits on its own
    // once the target process group is gone.
    let _ = std::process::Command::new(exe)
        .arg("__reap-watchdog")
        .arg("--parent-pid")
        .arg(parent.to_string())
        .arg("--pgid")
        .arg(agent_pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn watch(_agent_pid: u32) {}

/// The macOS watchdog loop: block on the parent pid via kqueue `NOTE_EXIT`,
/// then `SIGKILL` the agent's process group. Returns when the parent is gone
/// and the group has been signalled — or early, without signalling, once the
/// agent's process group has exited on its own (a completed job), so the
/// watchdog does not linger as a polling child for the daemon's whole lifetime.
#[cfg(target_os = "macos")]
pub fn reap_watchdog(parent_pid: u32, pgid: u32) {
    // SAFETY: standard kqueue usage; the fd is closed before return.
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            // No kqueue: fall back to polling both conditions.
            if wait_parent_or_group_gone(parent_pid, pgid) {
                libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
            }
            return;
        }
        let mut change: libc::kevent = std::mem::zeroed();
        change.ident = parent_pid as libc::uintptr_t;
        change.filter = libc::EVFILT_PROC;
        change.flags = libc::EV_ADD | libc::EV_CLEAR;
        change.fflags = libc::NOTE_EXIT;
        // Register the parent-exit filter without blocking (nevents = 0).
        let registered =
            libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
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
        if parent_died {
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
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
pub fn reap_watchdog(parent_pid: u32, pgid: u32) {
    // SAFETY: plain libc calls; no shared Rust state is touched.
    unsafe {
        if wait_parent_or_group_gone(parent_pid, pgid) {
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
        }
    }
}

/// Poll until either the parent (daemon) exits or the agent's process group has
/// already gone away. Returns `true` when the parent died (the caller should
/// reap the group), `false` when the group vanished on its own (nothing to do).
#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn wait_parent_or_group_gone(parent_pid: u32, pgid: u32) -> bool {
    loop {
        if libc::kill(parent_pid as libc::pid_t, 0) != 0 {
            return true; // parent gone -> reap the group
        }
        if libc::kill(-(pgid as libc::pid_t), 0) != 0 {
            return false; // process group already gone -> nothing to reap
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Stub on platforms without a watchdog process (they rely on [`arm`]).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn reap_watchdog(_parent_pid: u32, _pgid: u32) {}
