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

#[cfg(unix)]
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
/// and the group has been signalled.
#[cfg(target_os = "macos")]
pub fn reap_watchdog(parent_pid: u32, pgid: u32) {
    // SAFETY: standard kqueue usage; the fd is closed before return.
    unsafe {
        let kq = libc::kqueue();
        if kq >= 0 {
            let mut change: libc::kevent = std::mem::zeroed();
            change.ident = parent_pid as libc::uintptr_t;
            change.filter = libc::EVFILT_PROC;
            change.flags = libc::EV_ADD | libc::EV_ONESHOT;
            change.fflags = libc::NOTE_EXIT;
            let mut event: libc::kevent = std::mem::zeroed();
            // Registering the change also polls it: if the parent is already
            // gone, kevent returns an EV_ERROR/ESRCH immediately and we fall
            // through to the poll fallback below.
            let n = libc::kevent(kq, &change, 1, &mut event, 1, std::ptr::null());
            if n <= 0 || (event.flags & libc::EV_ERROR) != 0 {
                // Parent already dead (or could not be watched): fall back to a
                // short poll so we never block forever, then proceed to reap.
                poll_until_parent_gone(parent_pid);
            }
            libc::close(kq);
        } else {
            poll_until_parent_gone(parent_pid);
        }
        // Parent is gone: kill the whole agent process group.
        libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
    }
}

/// The Linux watchdog loop: poll until the daemon (parent) is gone, then
/// `SIGKILL` the agent's entire process group so descendants the agent started
/// are reaped too (PDEATHSIG alone would only kill the direct agent).
#[cfg(target_os = "linux")]
pub fn reap_watchdog(parent_pid: u32, pgid: u32) {
    // SAFETY: plain libc calls; no shared Rust state is touched.
    unsafe {
        poll_until_parent_gone(parent_pid);
        libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn poll_until_parent_gone(parent_pid: u32) {
    loop {
        if libc::kill(parent_pid as libc::pid_t, 0) != 0 {
            return; // no such process
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Stub on platforms without a watchdog process (they rely on [`arm`]).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn reap_watchdog(_parent_pid: u32, _pgid: u32) {}
