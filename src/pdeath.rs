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

/// [`arm`] for a **std** command (pdeath.rs otherwise works in tokio types).
/// gh_token's bounded spawn is synchronous `std::process`, so it needs the same
/// Linux parent-death hook on a `std::process::Command`; a no-op elsewhere.
#[cfg(all(target_os = "linux", unix))]
pub fn arm_std(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    let parent = std::process::id();
    // SAFETY: pre_exec runs in the forked child before exec; we only call
    // async-signal-safe libc functions (prctl, getppid, raise) and touch no
    // Rust allocator state.
    unsafe {
        cmd.pre_exec(move || {
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

#[cfg(not(all(target_os = "linux", unix)))]
pub fn arm_std(_cmd: &mut std::process::Command) {}

/// Bind the CURRENT process to die when its parent does. Used when a supervisor
/// is allowed to run *attached* inside an agent run (#40): arming
/// `PR_SET_PDEATHSIG` on ourselves means that if the invoking agent dies — or the
/// job's process-group kill reaps it — this supervisor is SIGKILLed too, instead
/// of lingering as a phantom. On non-Linux targets it is a no-op: those callers
/// stay in the invoking process group (no `setsid`), so the group kill already
/// takes them down.
///
/// Returns an error when the binding could not be installed — a rejected `prctl`
/// (e.g. under a seccomp policy) — or when the invoking parent already exited
/// before we armed (the getppid re-check mirrors [`arm`]'s fork race fix: an
/// already-dead parent never fires PDEATHSIG, so the attached supervisor would
/// linger exactly as if unbound). Callers must fail startup rather than run the
/// opted-in supervisor without the promised parent-death binding.
#[cfg(target_os = "linux")]
pub fn bind_self_to_parent_death() -> std::io::Result<()> {
    let parent = unsafe { libc::getppid() };
    // SAFETY: a single async-signal-safe libc call that only arms a signal
    // disposition for this process; it touches no Rust allocator state.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Close the race: if the invoking agent already died before we armed,
    // PR_SET_PDEATHSIG will never fire, so refuse the attachment rather than
    // linger as the phantom this binding exists to prevent.
    if unsafe { libc::getppid() } != parent {
        return Err(std::io::Error::other(
            "invoking parent exited before the parent-death binding was armed",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn bind_self_to_parent_death() -> std::io::Result<()> {
    Ok(())
}

/// `SIGKILL` a process group by its leader pid (the pid is also the pgid, since
/// agents are spawned with `process_group(0)`). Used by the ACP/pipe cancellation
/// guards so that dropping an in-flight agent — e.g. when a slot aborts its
/// `execute` future on lease loss — tears down the whole tree, not just the
/// leader that `kill_on_drop` reaps. Harmless if the group is already gone.
///
/// Callers must gate this on [`PgidGuard::still_ours`] (or an equivalent
/// identity check): a bare numeric pgid proves only that *some* group currently
/// holds it, not that it is the agent's group (issue #27 — the recycled-PGID
/// race).
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

/// Checked `u32` → `libc::pid_t` conversion for a pid we are about to signal or
/// probe. `pid_t` is a signed 32-bit int on every supported unix, so any `u32`
/// above `i32::MAX` wraps to a **negative** `pid_t` under `as` — and `kill(2)`
/// treats negative values specially (`-1` broadcasts to every process the caller
/// may signal, `<-1` targets a process group). The owner watchdog's `--self-pid`
/// is an unrestricted `u32` CLI arg, so without this gate `u32::MAX` would reach
/// `kill(-1, SIGKILL)` and broadcast across the user's processes instead of
/// reaping one daemon (issue #54 review). Reject `0` (this process's group) and
/// anything out of `pid_t`'s positive range; the watchdog only ever targets a
/// real, positive pid.
#[cfg(unix)]
fn checked_pid(pid: u32) -> Option<libc::pid_t> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return None;
    }
    Some(pid as libc::pid_t)
}

/// `SIGKILL` a single process by pid (`kill(pid, SIGKILL)`, not the group).
///
/// Used by the owner watchdog to reap an orphaned contract-test daemon/worker.
/// Unlike an agent — which is spawned with `process_group(0)` and so leads a
/// group named by its pid — the supervisor started by `TempHome::cmd`/the
/// daemon entrypoint does **not** call `setsid`/`setpgid`, so it is *not* its
/// own process-group leader (it stays in the invoking test's group). Signalling
/// `kill(-self_pid)` there targets a nonexistent group named by the daemon's pid
/// and the daemon survives; worse, `self_pid`'s real group is the *shared* test
/// group, so a group kill would be aimed at the harness and its siblings. The
/// orphan #54 is about the supervisor process itself, and its own children
/// (agents, each in its own `process_group(0)` group with a parent-death binding
/// or reap watchdog) are reaped by the existing machinery when it dies — so the
/// correct, group-agnostic target is the pid. Harmless if already gone (`ESRCH`).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn sigkill_pid(pid: u32) {
    // Reject a pid that cannot be represented as a positive `pid_t`: `as` would
    // wrap it negative and `kill(2)` would read `-1` as "broadcast to every
    // process I may signal" (issue #54 review). Out-of-range => nothing of ours
    // to reap; treat as a no-op.
    let Some(pid) = checked_pid(pid) else {
        return;
    };
    // SAFETY: a plain libc kill of a single positive pid; no Rust state is
    // touched and an already-dead (or zombie) pid simply yields ESRCH / a
    // harmless no-op.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}

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

/// True while at least one **non-zombie** process remains in the group led by
/// `pid`. This is the distinction [`group_alive`] cannot draw: an exited-but-held
/// leader zombie (the identity anchor [`terminate_group_and_reap`] keeps unreaped
/// through its grace loop) still answers `kill(-pid, 0)`, so `group_alive` reads
/// the group as live even after every real member has exited — which forced the
/// full grace wait on every clean shutdown (issue #50). Enumerating the group's
/// members and excluding zombies lets the grace loop break the instant the group
/// has drained to just that anchor, so a clean exit finishes immediately instead
/// of waiting out `grace`.
///
/// This enumeration is best-effort and non-atomic. It fails *open* only for the
/// unavoidable race — a member that forks+exits mid-scan, so its
/// `/proc`/`proc_pidinfo` entry vanishes with a *process-gone* error (`NotFound`
/// on Linux, `ESRCH` on macOS) — because that member is already leaving, so
/// missing it is harmless. It does **not** treat any other inspection failure as
/// proof of absence: a per-member read that errors for any reason other than
/// process-gone (a permission or transient I/O error), a directory read that
/// errors partway through the enumeration, or a whole-enumeration failure (an
/// unreadable `/proc`, a failed `proc_listpids`) all degrade to [`group_alive`]
/// — the pre-#50 behaviour (never break early) — because the unreadable member
/// could be a still-live one and a false `false` would bypass the grace period
/// and SIGKILL it. Linux reads one snapshot of each `/proc/<pid>/stat` (a live
/// member always has a `/proc` entry naming the group, so a member alive *and
/// readable* at scan time is seen); macOS enumerates with
/// `proc_listpids(PROC_PGRP_ONLY)` and rejects each member whose `proc_pidinfo`
/// status is `SZOMB`.
///
/// Because the scan can still under-report (a racing fork, an unreadable
/// `/proc`/`proc_pidinfo` entry), callers must **not** treat a `false` as proof
/// that the group holds nothing worth SIGKILLing. [`terminate_group_and_reap`]'s
/// fast path guards against that by sending an identity-gated group SIGKILL
/// *before* it breaks on a `false` (a no-op when only the held zombie anchor
/// remains), so a false negative cannot leak a `TERM`-resistant descendant.
#[cfg(target_os = "linux")]
pub(crate) fn group_has_live_member(pgid: u32) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        // Cannot enumerate: fall back to the numeric probe so the grace loop
        // never breaks early on a group it could not inspect.
        return group_alive(pgid);
    };
    for entry in entries {
        // A readdir error mid-enumeration makes the listing unreliable: keep the
        // grace loop open rather than conclude the group drained from a partial
        // scan that may have skipped a still-live member.
        let Ok(entry) = entry else {
            return group_alive(pgid);
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // Read raw bytes, not a `String`: a process can set an arbitrary
        // non-UTF-8 byte sequence as its `comm`, and `read_to_string` would then
        // fail the whole scan with `InvalidData` for one unrelated process. The
        // fields we parse (state, pgrp) are ASCII in the suffix after the final
        // ')', so classify the bytes directly.
        let read = std::fs::read(format!("/proc/{name}/stat"));
        match classify_proc_stat(read.as_deref().map_err(std::io::Error::kind), pgid) {
            MemberVerdict::LiveMember => return true,
            MemberVerdict::Skip => continue,
            // An inspection failure (not a clean process-gone race) means we
            // cannot prove this member is absent: degrade to the numeric probe so
            // a false negative cannot bypass the grace period and SIGKILL a
            // running process early.
            MemberVerdict::Unknown => return group_alive(pgid),
        }
    }
    false
}

/// Per-member verdict for the Linux `/proc` scan in [`group_has_live_member`].
#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq, Debug)]
enum MemberVerdict {
    /// A readable, non-zombie member of the target pgid: the group still has live
    /// work, so the grace loop must not break.
    LiveMember,
    /// Readable but not a live member of the target pgid (a different group, a
    /// zombie), or a genuine *process-gone* race — safe to pass over.
    Skip,
    /// The member could not be inspected for a reason other than process-gone:
    /// the scan is unreliable and must fall back to [`group_alive`] rather than
    /// read the unknown as absence.
    Unknown,
}

/// Classify one `/proc/<pid>/stat` read against `pgid`. Pure so the fail-safe
/// contract — only a *process-gone* (`NotFound`) read error is `Skip`; any other
/// read error is `Unknown` (never silently dropped) — is unit-tested directly.
///
/// Takes the raw file **bytes**: a process can set an arbitrary non-UTF-8 `comm`,
/// so the scan must not require UTF-8. Only the suffix after the final ')' is
/// parsed, and the fields there (state, pgrp) are ASCII.
#[cfg(target_os = "linux")]
fn classify_proc_stat(read: Result<&[u8], std::io::ErrorKind>, pgid: u32) -> MemberVerdict {
    let stat = match read {
        Ok(stat) => stat,
        // The process exited between the readdir and this read: it is gone, so it
        // cannot be the live member we are looking for.
        Err(std::io::ErrorKind::NotFound) => return MemberVerdict::Skip,
        // Any other read error (permission, transient I/O) is an *inspection*
        // failure, not proof of absence.
        Err(_) => return MemberVerdict::Unknown,
    };
    // `comm` (field 2) may contain spaces, parentheses, and arbitrary non-UTF-8
    // bytes, so parse from just past the final ')': field 3 (state) is the first
    // whitespace-separated token, field 5 (pgrp) the third. Both are ASCII.
    let Some(rparen) = stat.iter().rposition(|&b| b == b')') else {
        return MemberVerdict::Skip;
    };
    let mut fields = stat[rparen + 1..]
        .split(|b| b.is_ascii_whitespace())
        .filter(|t| !t.is_empty());
    let state = fields.next();
    let _ppid = fields.next();
    let pgrp = fields
        .next()
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse::<u32>().ok());
    let live = !matches!(state, Some(b"Z") | Some(b"X") | Some(b"x"));
    if pgrp == Some(pgid) && live {
        MemberVerdict::LiveMember
    } else {
        MemberVerdict::Skip
    }
}

/// macOS counterpart of the Linux `/proc` scan: enumerate the process group with
/// `proc_listpids(PROC_PGRP_ONLY, pgid)` and report `true` on the first member
/// whose `proc_pidinfo(PROC_PIDTBSDINFO)` status is not `SZOMB`. A failed
/// enumeration degrades to [`group_alive`] (never break early on a group we
/// could not inspect). See [`group_has_live_member`] (Linux) for the contract.
#[cfg(target_os = "macos")]
pub(crate) fn group_has_live_member(pgid: u32) -> bool {
    // `proc_listpids`'s group selector; not exposed by the `libc` crate at this
    // version, so define it locally (sys/proc_info.h: `PROC_PGRP_ONLY = 2`).
    const PROC_PGRP_ONLY: u32 = 2;
    let pid_sz = std::mem::size_of::<libc::pid_t>() as libc::c_int;
    // Size the buffer from a null-buffer probe (returns the byte count), then
    // read the pids into it.
    // SAFETY: a null-buffer `proc_listpids` only reports the required size.
    let needed = unsafe { libc::proc_listpids(PROC_PGRP_ONLY, pgid, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        // Empty (or failed) enumeration: no readable members. Fall back to the
        // numeric probe only on an outright error so a transient failure does not
        // break the grace loop early; `needed == 0` is a genuinely empty group.
        return if needed < 0 { group_alive(pgid) } else { false };
    }
    let count = (needed as usize) / (pid_sz as usize);
    let mut pids = vec![0 as libc::pid_t; count];
    // SAFETY: `pids` owns `count * size_of::<pid_t>()` writable bytes.
    let got = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            pgid,
            pids.as_mut_ptr() as *mut libc::c_void,
            (pids.len() as libc::c_int) * pid_sz,
        )
    };
    if got <= 0 {
        return if got < 0 { group_alive(pgid) } else { false };
    }
    pids.truncate((got as usize) / (pid_sz as usize));
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        match pid_liveness(pid as u32) {
            // A readable, non-zombie member: the group still has live work.
            Some(true) => return true,
            // A zombie or an already-exited member: not a live member, keep going.
            Some(false) => {}
            // The member could not be inspected (an error other than process-gone):
            // we cannot prove it is absent, so degrade to the numeric probe rather
            // than read the unknown as absence and break the grace loop early.
            None => return group_alive(pgid),
        }
    }
    false
}

/// Per-member liveness for the macOS [`group_has_live_member`] scan, read from
/// `proc_pidinfo(PROC_PIDTBSDINFO)` `pbi_status`:
/// - `Some(true)`  — a live, non-zombie process;
/// - `Some(false)` — a zombie (`SZOMB`) or an already-exited pid (`ESRCH`): not a
///   live member, safe to skip;
/// - `None`        — the status read failed for any other reason: an *inspection*
///   failure, not proof of absence, so the caller must not treat it as gone.
#[cfg(target_os = "macos")]
fn pid_liveness(pid: u32) -> Option<bool> {
    // SAFETY: `proc_pidinfo` fills a `proc_bsdinfo` for a live or zombie pid.
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let n = libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        );
        if n > 0 {
            return Some(info.pbi_status != libc::SZOMB);
        }
        // A non-positive return filled no `bsdinfo`. `ESRCH` is a genuine
        // process-gone race (treat as not-a-live-member); any other errno is an
        // inspection failure that must not read as proof of absence.
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Some(false),
            _ => None,
        }
    }
}

/// Other-unix fallback: no per-member state source, so a zombie anchor cannot be
/// told apart from a live member. Report the group as having a live member while
/// *any* member (including the held leader zombie) keeps the pgid, preserving the
/// pre-#50 behaviour — the grace loop waits out `grace` rather than risk breaking
/// early on a group that may still hold a live descendant.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) fn group_has_live_member(pgid: u32) -> bool {
    group_alive(pgid)
}

/// Whether `pid` names a live process. Best-effort; a reused PID can read as
/// alive, which only ever *delays* the owner-death reaction below — never a
/// wrongful exit, so the fail-open direction is the safe one here.
#[cfg(unix)]
pub(crate) fn pid_alive(pid: u32) -> bool {
    // Reject a pid that cannot be represented as a positive `pid_t`: `as` would
    // wrap it negative, and `kill(-1, 0)` would probe *every* signalable process
    // (returning success) rather than naming one — a recycled/out-of-range pid
    // must read as "not ours", never as "alive" (issue #54 review).
    let Some(pid) = checked_pid(pid) else {
        return false;
    };
    // `kill(pid, 0)` sends no signal: 0 => alive; EPERM => alive but not ours;
    // ESRCH => no such process.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub(crate) fn pid_alive(_pid: u32) -> bool {
    // With no liveness probe we cannot tell a dead owner from a live one, so
    // assume alive: the watchdog then never fires spuriously on a platform that
    // cannot support it (the hermetic contract tests are unix-only anyway).
    true
}

/// The owning test process a contract-test daemon/worker is bound to, read from
/// the hermetic environment the harness stamps (`C8CTL_NANO_TEST_OWNER_PID`).
/// `Some(pid)` only when the variable holds a parseable non-zero pid; any other
/// state (unset, empty, garbage) means "no owner binding" and disables the
/// watchdog, so a real fleet daemon is never affected.
pub fn test_owner_pid() -> Option<u32> {
    std::env::var("C8CTL_NANO_TEST_OWNER_PID")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|pid| *pid > 0)
}

/// The owner's start-time incarnation token, captured by the HARNESS while it is
/// still known to be the owner and stamped into the hermetic environment
/// (`C8CTL_NANO_TEST_OWNER_START`), exactly as `C8CTL_NANO_TEST_OWNER_PID`
/// carries the owner pid. Preferring this harness-captured token over a
/// child-side `owner_start_time` read closes a PID-reuse race: the harness can be
/// SIGKILLed *after* spawning this daemon but *before* the daemon reads the
/// owner's start time, and if the owner pid is recycled in that window the
/// child-side read captures the unrelated replacement's incarnation — so both
/// the liveness and start-time checks pass forever and the daemon is orphaned
/// (issue #54 review). `None` when unset, empty, unparseable, or zero (no real
/// owner process has start time 0, so a stray `0` is garbage, not a token), in
/// which case the caller falls back to child-side discovery (no worse than
/// before).
pub fn test_owner_start() -> Option<u64> {
    std::env::var("C8CTL_NANO_TEST_OWNER_START")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|start| *start > 0)
}

/// Arm the contract-test owner watchdog (issue #54). When this daemon/worker was
/// started by the hermetic test harness (a parseable `C8CTL_NANO_TEST_OWNER_PID`
/// is present), spawn a detached `__owner-watchdog` process that SIGKILLs THIS
/// process (by pid) the moment the owning test process is gone — covering the
/// cases `Drop for TempHome` cannot: a SIGKILL, a timeout kill, Ctrl-C, or
/// `panic=abort`, none of which unwind. The signal targets the daemon's pid, not
/// its process group: the daemon is not its own group leader (it shares the
/// invoking test's group), so a group kill would miss it and aim at the harness.
/// The watchdog also fires when the test's
/// `C8CTL_NANO_HOME` directory disappears (the `TempDir` was removed from under
/// a still-running daemon), which covers a recycled owner pid.
///
/// A no-op when there is no owner binding (a real fleet daemon/worker), so
/// production processes are untouched. When the owner binding IS active but the
/// watchdog cannot be armed on a platform that supports it (Linux/macOS),
/// startup FAILS (`Err`): the watchdog is the only cleanup path that survives an
/// owner SIGKILL — the in-process `Drop` cannot run on a SIGKILL/timeout/
/// `panic=abort`, and the startup sweep has neither this process's pid (the
/// marker records the *owner* pid) nor a control socket to stop it, so it can
/// only delete the home. Continuing past a failed arm would therefore still
/// permit exactly the orphan this change prevents (issue #54 review
/// r4240360017). The intentional unsupported-platform behavior is preserved:
/// where no owner watchdog exists, arming is skipped, never failed.
pub fn arm_owner_watchdog() -> anyhow::Result<()> {
    let Some(owner) = test_owner_pid() else {
        return Ok(());
    };
    let Some(home) = crate::state::state_home() else {
        return Ok(());
    };
    // Record the owner binding where the contract-test startup sweep can read it
    // (`<home>/ct-owner.pid`), so the sweep can tell an orphaned daemon (its
    // owning test process is gone) apart from a concurrently-running test's live
    // daemon (same shared `cargo test` pid, still alive) and only reap the former.
    // The marker is `<pid> <start>`: recording the owner's start-time incarnation
    // token alongside the pid lets the sweep reject a *recycled* owner pid, not
    // just a dead one (issue #54 review r4240055588). Prefer the harness-stamped
    // race-free token (`test_owner_start`) over a child-side read, exactly as the
    // watchdog does. Best-effort: a write failure just means the sweep falls back
    // to leaving the daemon to its own watchdog.
    let mut marker = owner.to_string();
    if let Some(start) = test_owner_start().or_else(|| owner_start_time(owner)) {
        marker.push(' ');
        marker.push_str(&start.to_string());
    }
    write_marker_atomic(&home.join(OWNER_PID_FILE), &marker);
    arm_outcome(spawn_owner_watchdog(owner, home))
}

/// Whether this platform has an owner-watchdog implementation at all. On
/// Linux/macOS [`spawn_owner_watchdog`] spawns a real reaper, so a `None` return
/// is a genuine spawn failure; elsewhere the function is an intentional no-op
/// that always returns `None` and must not fail startup.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const OWNER_WATCHDOG_SUPPORTED: bool = true;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const OWNER_WATCHDOG_SUPPORTED: bool = false;

/// Decide whether a failed watchdog arm must abort startup. On a supported
/// platform a `None` from [`spawn_owner_watchdog`] is a real spawn failure that
/// leaves the daemon/worker orphanable, so startup fails; on an unsupported
/// platform `None` is the intentional no-op and startup proceeds (see
/// [`arm_owner_watchdog`]).
fn arm_outcome(spawned: Option<u32>) -> anyhow::Result<()> {
    if spawned.is_none() && OWNER_WATCHDOG_SUPPORTED {
        return Err(anyhow::anyhow!(
            "issue #54: could not arm the owner watchdog; refusing to start a \
             contract-test daemon/worker that an owner SIGKILL could orphan"
        ));
    }
    Ok(())
}

/// Write the `ct-owner.pid` owner marker **atomically**: a plain
/// `std::fs::write` truncates the existing file before writing, so a concurrent
/// contract-test startup sweep can read it in that window (empty or partial),
/// fail to parse an owner, and classify this *live* daemon's home as orphaned —
/// removing the home and tripping the very watchdog this marker arms (issue #54
/// review). Write to a sibling temp file and `rename(2)` it over the target so a
/// reader always sees either the previous valid marker or the new one, never a
/// truncated intermediate. The rename is atomic on the same filesystem (the temp
/// file sits in the same directory). Best-effort: a failure just means the sweep
/// falls back to the daemon's own watchdog.
fn write_marker_atomic(path: &std::path::Path, marker: &str) {
    let tmp = path.with_extension("pid.tmp");
    if std::fs::write(&tmp, marker).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// The file (under the test's `C8CTL_NANO_HOME`) recording the owning test
/// process's pid, written by [`arm_owner_watchdog`]. The contract-test startup
/// sweep reads it to decide whether a `ct-home-*` daemon is orphaned (owner
/// dead) or merely belongs to a concurrently-running test (owner alive).
pub const OWNER_PID_FILE: &str = "ct-owner.pid";

/// The owner process's start time, captured while the owner is guaranteed alive
/// so the owner watchdog can detect a *recycled* owner pid: a bare
/// `kill(pid, 0)` answers success for the unrelated process that reused the
/// number, so without an incarnation token the watchdog would wait on it forever
/// and orphan the daemon (issue #54 review). Sourced from Linux
/// `/proc/<pid>/stat` field 22 and from macOS `proc_pidinfo` (via
/// [`leader_identity`]); `None` on a platform with no start-time source or when
/// the read fails, in which case the watchdog falls back to the
/// liveness-plus-home check alone.
#[cfg(target_os = "linux")]
fn owner_start_time(owner: u32) -> Option<u64> {
    parent_start_time(owner)
}

#[cfg(target_os = "macos")]
fn owner_start_time(owner: u32) -> Option<u64> {
    // macOS has no `/proc/<pid>/stat`, but `leader_identity` already reads the
    // process start time via `proc_pidinfo(PROC_PIDTBSDINFO)` (folded to
    // microseconds). Reuse it so owner-PID-reuse detection works on macOS too —
    // the original fleet failure was on macOS, so disabling the incarnation
    // check here would let a recycled owner pid strand the daemon indefinitely.
    leader_identity(owner).map(|id| id.start)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn owner_start_time(_owner: u32) -> Option<u64> {
    None
}

/// Resolve the owner's start-time incarnation token, preferring the value the
/// HARNESS stamped (`stamped`, read from `C8CTL_NANO_TEST_OWNER_START` while it
/// was the known owner) over a child-side `owner_start_time(owner)` discovery.
///
/// The harness-captured token is race-free; the child-side read is not. If the
/// harness is SIGKILLed between spawning this daemon and the daemon reaching the
/// read, and the owner pid is recycled in that window, the child-side read
/// captures the *replacement* process's start time — so the watchdog's liveness
/// and incarnation checks both pass forever and the orphaned daemon is never
/// reaped (issue #54 review r4239955518). Preferring the stamped token closes
/// that window entirely; falling back to discovery only when the harness did not
/// stamp one is strictly no worse than before.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_owner_start(stamped: Option<u64>, owner: u32) -> Option<u64> {
    stamped.or_else(|| owner_start_time(owner))
}

/// Spawn the detached owner watchdog for `owner`, watching `home`. Returns its
/// pid, or `None` if it could not be spawned (which [`arm_owner_watchdog`] turns
/// into a fatal startup error on this supported platform). Split from
/// [`arm_owner_watchdog`] so the regression test can drive the real subcommand
/// directly.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn spawn_owner_watchdog(owner: u32, home: std::path::PathBuf) -> Option<u32> {
    let Ok(exe) = std::env::current_exe() else {
        return None;
    };
    let self_pid = std::process::id();
    // Capture the incarnation tokens the watchdog needs (the same pattern
    // `spawn_watchdog` uses for `--parent-start`/`--pgid-start`/`--pgid-uid`):
    //
    // - The **owner's start time** lets the watchdog tell a recycled owner pid
    //   apart from the real owner (issue #54 review): a bare pid answers
    //   `kill(_, 0)` for whatever unrelated process reused the number, so a
    //   start-time mismatch — not just liveness — is what proves the owner died.
    //   We PREFER the token the harness stamped into the environment while it was
    //   the known owner (`test_owner_start`) over discovering it here in the
    //   child: discovering it here races a harness SIGKILL during startup that
    //   recycles the owner pid, which would hand us the replacement's incarnation
    //   and orphan the daemon forever (r4239955518). We fall back to child-side
    //   discovery only when the harness stamped nothing.
    // - **Our own pid's identity** gates the watchdog's SIGKILL, so a daemon
    //   that already exited and had its pid recycled by an unrelated process is
    //   never signalled (the same recycled-identity race issue #27 closes for
    //   the agent watchdog, here on the supervisor's pid rather than its group —
    //   the supervisor is not its own group leader, so the watchdog reaps it by
    //   pid; see `owner_watchdog`). `leader_identity` reads `/proc/<self_pid>`
    //   (start+uid), which is the daemon's own incarnation — a self-read, so
    //   race-free — whether or not it leads a group.
    let owner_start = resolve_owner_start(test_owner_start(), owner);
    let self_identity = leader_identity(self_pid);
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__owner-watchdog")
        .arg("--owner-pid")
        .arg(owner.to_string())
        .arg("--self-pid")
        .arg(self_pid.to_string())
        .arg("--home")
        .arg(&home);
    if let Some(start) = owner_start {
        cmd.arg("--owner-start").arg(start.to_string());
    }
    if let Some(id) = self_identity {
        cmd.arg("--self-start")
            .arg(id.start.to_string())
            .arg("--self-uid")
            .arg(id.uid.to_string());
    }
    // Scrub the environment: the watchdog needs nothing but its own executable
    // and the CLI args above, and inheriting the daemon's environment would
    // expose the engine/OAuth secrets to a same-user reader of
    // `/proc/<watchdog-pid>/environ` (the same hardening `spawn_watchdog` uses).
    cmd.env_clear();
    // Detach the watchdog into its OWN process group (pid == pgid). The daemon
    // is *not* its own group leader — it inherits the test runner's / invoking
    // shell's foreground group — so without this the watchdog shares that group
    // and a terminal Ctrl-C delivers SIGINT to it too. The watchdog installs no
    // SIGINT handler, so it would die with the group *before* observing the
    // owner's death, and the orphaned daemon would lose its guaranteed reaper
    // exactly when the fallback matters (issue #54 review). In its own group it
    // is out of the foreground group's signal fan-out and survives to reap the
    // daemon. This mirrors how agents are launched (`process_group(0)`).
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    match cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            // Reap the watchdog when it exits so it never lingers as a zombie of
            // the daemon (the same fix issue #52 applied to the agent watchdog).
            // Spawn that reaper FALLIBLY (see `spawn_watchdog`): a panicking
            // `thread::spawn` would unwind the caller on a thread-creation
            // refusal. On failure, kill + reap the watchdog inline so nothing
            // leaks, and report the watchdog as unavailable. The child is shared
            // with the reaper closure behind an Arc<Mutex>: a failed
            // `Builder::spawn` drops the closure (and its captures), so without
            // sharing, the error path could no longer reach the child.
            let pid = child.id();
            let child = std::sync::Arc::new(std::sync::Mutex::new(child));
            let reaper_child = std::sync::Arc::clone(&child);
            if std::thread::Builder::new()
                .spawn(move || {
                    if let Ok(mut c) = reaper_child.lock() {
                        let _ = c.wait();
                    }
                })
                .is_err()
            {
                if let Ok(mut c) = child.lock() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                crate::runtime::log(&format!(
                    "warning: owner watchdog reaper thread failed to spawn for owner {owner}"
                ));
                return None;
            }
            Some(pid)
        }
        Err(e) => {
            crate::runtime::log(&format!(
                "warning: owner watchdog failed to spawn for owner {owner}: {e}"
            ));
            None
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn spawn_owner_watchdog(_owner: u32, _home: std::path::PathBuf) -> Option<u32> {
    None
}

/// The owner-watchdog loop (the `__owner-watchdog` subcommand): poll until the
/// owning test process is gone OR the watched home directory has disappeared,
/// then SIGKILL the supervised daemon **by pid**. Returns without firing when the
/// supervised process has already exited on its own (a normal drain), so the
/// watchdog does not linger. This is the guaranteed reaper for a daemon whose
/// owning test died without unwinding (issue #54).
///
/// Both decisions are incarnation-aware, not bare-pid (issue #54 review):
///
/// - **Owner death** is `!pid_alive(owner)` OR a start-time mismatch against
///   `owner_start` (the token captured at arm). The mismatch arm catches a
///   *recycled* owner pid: the number still answers `kill(_, 0)` for the
///   unrelated reuser, but it is no longer the owning test, so the daemon must
///   be reaped rather than orphaned indefinitely. With no token (`None`,
///   e.g. off Linux) the watchdog degrades to liveness-plus-home alone.
/// - **The SIGKILL targets the daemon's pid, not its group** — the supervisor
///   started by `TempHome::cmd`/the daemon entrypoint does not `setsid`/`setpgid`
///   (unlike an agent, which is spawned with `process_group(0)`), so it is *not*
///   its own process-group leader: `kill(-self_pid)` would miss it entirely, and
///   its real group is the shared test group a group kill must never touch (issue
///   #54 review). The signal is gated on `pid_identity_matches(self_pid, …)` —
///   the same incarnation check the agent watchdog applies to a group, here on
///   the pid — so a daemon that already exited and had its pid recycled by an
///   unrelated process is never signalled. The captured identity refuses it then.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn owner_watchdog(
    owner_pid: u32,
    self_pid: u32,
    home: std::path::PathBuf,
    owner_start: Option<u64>,
    self_start: Option<u64>,
    self_uid: Option<u32>,
) {
    // Rebuild the identity token the daemon captured for its own pid at arm
    // (issue #27). Both halves are required; if either is missing the watchdog
    // has no identity and falls back to the numeric liveness probe alone.
    let self_identity = self_start
        .zip(self_uid)
        .map(|(start, uid)| GroupIdentity { start, uid });
    loop {
        // The supervised daemon already exited on its own: nothing to reap.
        if !pid_alive(self_pid) {
            return;
        }
        // Owner gone (SIGKILL / timeout / panic=abort — no unwinding, no Drop),
        // owner pid RECYCLED (the start time moved off the captured token), or
        // home removed (TempDir deleted under a live daemon): fire.
        //
        // The recycle arm must compare only a SUCCESSFULLY READ token: a failed
        // `owner_start_time` read returns `None`, and `None != Some(token)` would
        // misclassify a transient `/proc`/`proc_pidinfo` failure as a recycle and
        // SIGKILL a daemon whose owner is still alive (issue #54 review). Only a
        // read that returns a DIFFERENT token proves the pid was recycled; a read
        // failure degrades this poll to the liveness-plus-home check alone.
        let owner_gone = !pid_alive(owner_pid)
            || owner_start.is_some_and(
                |start| matches!(owner_start_time(owner_pid), Some(cur) if cur != start),
            );
        if owner_gone || !home.exists() {
            // Re-verify the pid's identity immediately before signalling: the
            // daemon may have exited and its pid been recycled by an unrelated
            // process in the window since the liveness check above.
            if pid_identity_matches(self_pid, self_identity) {
                sigkill_pid(self_pid);
            }
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn owner_watchdog(
    _owner_pid: u32,
    _self_pid: u32,
    _home: std::path::PathBuf,
    _owner_start: Option<u64>,
    _self_start: Option<u64>,
    _self_uid: Option<u32>,
) {
}

/// The identity of a process group, captured at spawn so a later cleanup can
/// tell *the agent's* group apart from an unrelated group that recycled the
/// numeric pgid (issue #27).
///
/// A process group has no kernel handle of its own, so its identity is pinned
/// through its **leader**: the leader's start time (the same per-incarnation
/// token [`parent_start_time`] uses for daemon PID-reuse detection) plus its
/// real uid. While any member of the group is alive the pgid stays reserved, and
/// while the leader is *alive or an unreaped zombie* its `/proc` (or `proc_pidinfo`)
/// entry keeps that original start time — so re-reading and comparing proves the
/// group currently holding the pgid is the one that was spawned, not a recycled
/// one. The uid disambiguates a *cross-user* recycle that lands on the same clock
/// tick (start times are only unique per tick). It does **not** distinguish a
/// *same-uid* recycle that lands on the same tick: such a group shares the
/// original's `(start, uid)` token byte-for-byte and so passes the live-leader
/// match — an accepted residual (window 3 under *Scope of the guarantee* below),
/// since this token is only tick-resolved and no cheaper genuinely-unique
/// per-incarnation token exists on these platforms.
///
/// **A waited-on leader does *not* stay a zombie.** Once the leader is reaped —
/// by us (`child.wait()`/`try_wait()`) or, for the detached watchdog, by `init`
/// after the daemon is `kill -9`'d — its `/proc` entry vanishes even while
/// descendants keep the group (and the pgid) alive. Re-reading then yields `None`:
/// identity becomes unverifiable. That is the gap behind the review finding this
/// addresses. The cleanup paths below therefore (a) *can* hold the leader
/// *unreaped* through the in-process terminate sequence so its identity stays
/// readable (which is what [`terminate_group_and_reap`] does on its own unless
/// the caller reaped the leader first — see *Scope of the guarantee* below), and (b) treat a *gone* leader (re-read `None`) as
/// fail-**open** while treating a *live* leader with a *different* identity as
/// fail-**closed**. See [`PgidGuard::still_ours`] for the policy and its
/// residual recycle window.
///
/// **Scope of the guarantee.** The recycled-PGID race is closed for every case
/// except three accepted residual windows:
///
/// 1. *Nested recycle.* The group empties *entirely*, the pgid is recycled by an
///    unrelated group, *and* that recycled group's own leader is reaped too — all
///    inside a single poll interval — so the re-read yields `None` and the
///    fail-open policy signals the unrelated group. (Requires a full recycle plus
///    a second leader reap inside one poll.)
///
/// 2. *Check-to-signal TOCTOU.* The identity check and the
///    `kill(2)` are separate syscalls. In the fail-open branch — where
///    the leader is already *gone* and the group is held only by orphaned
///    descendants — the last descendant can exit and the pgid be recycled in the
///    window *between* [`PgidGuard::still_ours`]/`group_identity_matches`
///    returning true and `sigkill_group` running, so the SIGKILL can land on an
///    unrelated group *without* the recycled leader needing to be reaped. This is
///    broader than window 1.
///
/// 3. *Same-tick, same-uid identity collision.* The group empties, the pgid is
///    recycled by an unrelated group, *and* that recycled group's own leader is
///    alive and happens to share the original leader's real uid *and* start on the
///    same clock tick — so its `(start, uid)` token is byte-identical to ours and
///    the live-leader match reads it as *ours* and signals it. This shares
///    windows 1/2's reaped-first precondition — the pgid can only be recycled once
///    our leader is gone, since the pgid number equals the leader's pid and an
///    unreaped zombie leader keeps it reserved — but unlike them the re-read
///    yields a *colliding live* identity (`Some`) rather than `None`, so it is a
///    false-positive **match** rather than a fail-open. Closing it needs a
///    genuinely unique per-incarnation token, which the tick-resolved start time
///    is not; none is cheaply available on these platforms.
///
/// All three are accepted — windows 1 and 2 as the price of not leaking
/// `TERM`-resistant orphans, window 3 as the price of a tick-resolved identity
/// token. They
/// **apply to the in-process cleanup paths only when the leader has already been
/// reaped before [`terminate_group_and_reap`] runs**, because that reap removes
/// the zombie anchor so the pgid can be recycled (windows 1/2 then read `None` and
/// take the fail-open branch; window 3 reads a colliding live leader). That early
/// reap happens on the
/// leader-already-exited sub-paths: `pipe.rs` (EOF-with-exit, where the agent
/// exits within the idle window and `child.wait()` completes), `provision.rs`
/// (success path, which `tokio::join!(child.wait(), …)` before terminating), and
/// `acp.rs` *only* when a prior `request` reaped the leader mid-request. On those
/// sub-paths windows 1, 2 and 3 apply as in the watchdog.
///
/// Otherwise — most notably `acp.rs`'s normal shutdown, where `acp::shutdown`
/// calls [`terminate_group_and_reap`] after a successful `run()` with the agent
/// still alive and unreaped, and `pipe.rs`'s idle-timeout path, where the loop
/// exits without the EOF `child.wait()` completing — the leader is *not* reaped
/// first. [`terminate_group_and_reap`] then holds it unreaped through its whole
/// grace loop (the zombie keeps the pgid un-recyclable and the identity
/// readable), so [`PgidGuard::still_ours`] stays fail-**closed** on a real match
/// and all three windows are **closed** for those paths (an un-recyclable pgid
/// cannot be taken over by a colliding group, closing window 3 too). The grace
/// loop no longer waits out `grace` on a clean shutdown: [`group_has_live_member`]
/// detects when the group has drained to just the held zombie anchor and breaks
/// immediately (issue #50). Deferring the
/// leader reap until after the group SIGKILL on the reaped-first sub-paths —
/// which would close the window there too — is tracked in #69. Everywhere else — a live
/// recycled leader, or any group whose leader is still readable — the identity
/// check refuses the signal.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupIdentity {
    /// Leader start time: Linux `/proc/<pid>/stat` field 22 (clock ticks since
    /// boot), macOS `proc_pidinfo(PROC_PIDTBSDINFO)` `pbi_start_tvsec`/
    /// `pbi_start_tvusec` folded to microseconds.
    start: u64,
    /// The leader's real uid at capture.
    uid: u32,
}

/// The result of probing the current leader's identity for a pgid. This is
/// richer than `Option<GroupIdentity>` because the two `None`-collapsing cases
/// a plain read conflates — a *genuinely absent* leader and a *detected
/// incarnation change* — need **opposite** signal policies (issue #27):
///
/// - [`LeaderProbe::Absent`]: the leader is gone (reaped). The pgid is held
///   only by orphaned descendants — almost certainly our own — so the caller
///   fails **open** (signals) rather than leak `TERM`-resistant orphans.
/// - [`LeaderProbe::Changed`]: the leader's identity *changed* mid-read (a
///   reap+recycle straddled the non-atomic `/proc` reads). The group holding
///   the pgid is positively **not** ours, so the caller fails **closed** (does
///   not signal). Collapsing this to `Absent` would green-light signalling the
///   unrelated replacement group — the exact race the bracketed read exists to
///   close.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaderProbe {
    /// A live, readable leader with this identity.
    Present(GroupIdentity),
    /// The leader is gone (reaped); only descendants may hold the pgid.
    Absent,
    /// The leader's identity changed mid-read — a detected reap+recycle.
    ///
    /// Only the two-file Linux probe can straddle a recycle, so this variant is
    /// constructed solely under `target_os = "linux"`; the macOS/other-unix
    /// probes read a single snapshot and never produce it. It still exists on
    /// the shared `cfg(unix)` enum because `still_ours`/`group_identity_matches`
    /// match it exhaustively on every unix target, hence the platform-scoped
    /// `dead_code` allow rather than cfg-gating the variant and every match arm.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Changed,
}

#[cfg(target_os = "linux")]
fn read_start_tick(pgid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pgid}/stat")).ok()?;
    // `comm` (field 2) may itself contain spaces and parentheses, so parse from
    // just past the final ')'. After it, field 3 (state) is the first token, so
    // starttime (field 22) is the 20th token — 0-based index 19.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "linux")]
fn read_uid(pgid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pgid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Assemble the `(start, uid)` token from two independent reads, rejecting any
/// snapshot that straddles a reap+recycle. The Linux identity is read from two
/// separate `/proc/<pid>` files (`stat` for the start tick, `status` for the
/// uid), so a plain read-one-then-the-other is **not** atomic: if the leader is
/// reaped and its pid/pgid recycled by a *same-uid* replacement in the gap, the
/// start tick comes from the original incarnation and the uid from the
/// replacement — a mixed token that still matches the captured identity and
/// green-lights signalling the unrelated group. Bracketing the uid read between
/// two start-tick reads and rejecting the snapshot when the tick moved closes
/// that window: a reap+recycle changes the start tick, so the only residual is a
/// same-tick *and* same-uid recycle (window 3 on [`GroupIdentity`], already
/// accepted). Every returned field is thus read from one stable incarnation.
///
/// The result distinguishes the two ways the read can fail, because the
/// verification callers need opposite policies for them (issue #27): a *moved*
/// start tick is a detected reap+recycle and returns [`LeaderProbe::Changed`]
/// (fail **closed** — the group is positively not ours), while a *vanished*
/// leader (either read unreadable) returns [`LeaderProbe::Absent`] (fail
/// **open** — only our own orphaned descendants remain). Collapsing the moved
/// case to `Absent` would signal the unrelated replacement group.
#[cfg(target_os = "linux")]
fn assemble_identity(
    mut read_start: impl FnMut() -> Option<u64>,
    read_uid: impl FnOnce() -> Option<u32>,
) -> LeaderProbe {
    let Some(start) = read_start() else {
        return LeaderProbe::Absent;
    };
    let Some(uid) = read_uid() else {
        return LeaderProbe::Absent;
    };
    match read_start() {
        // The tick moved between the bracketing reads: a reap+recycle straddled
        // the snapshot, so the group holding the pgid is a *different*
        // incarnation. Fail closed, not open.
        Some(tick) if tick != start => LeaderProbe::Changed,
        // The re-read is unreadable: the leader vanished (reaped) with no
        // replacement yet — the accepted fail-open case.
        None => LeaderProbe::Absent,
        // Stable tick across both reads: one stable incarnation.
        Some(_) => LeaderProbe::Present(GroupIdentity { start, uid }),
    }
}

#[cfg(target_os = "linux")]
fn probe_leader(pgid: u32) -> LeaderProbe {
    assemble_identity(|| read_start_tick(pgid), || read_uid(pgid))
}

#[cfg(target_os = "linux")]
fn leader_identity(pgid: u32) -> Option<GroupIdentity> {
    match probe_leader(pgid) {
        LeaderProbe::Present(id) => Some(id),
        // A detected incarnation change is *not* a readable identity: collapse
        // to `None` for capture sites (which store `Option<GroupIdentity>` and
        // degrade to the numeric probe). The fail-closed distinction only
        // matters at *verification* time, which uses `probe_leader` directly.
        LeaderProbe::Absent | LeaderProbe::Changed => None,
    }
}

#[cfg(target_os = "macos")]
fn leader_identity(pgid: u32) -> Option<GroupIdentity> {
    // `proc_pidinfo(PROC_PIDTBSDINFO)` fills a `proc_bsdinfo` for a live (or
    // zombie) process. `pbi_start_tvsec`/`pbi_start_tvusec` are the process's
    // start time; fold to microseconds for a single comparable token.
    // `pbi_ruid` is the real uid. (libc does not expose `kinfo_proc`/`sysctl
    // KERN_PROC` on Apple targets, so this is the available identity source.)
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let n = libc::proc_pidinfo(
            pgid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        );
        if n <= 0 {
            return None;
        }
        let start = info
            .pbi_start_tvsec
            .checked_mul(1_000_000)?
            .checked_add(info.pbi_start_tvusec)?;
        Some(GroupIdentity {
            start,
            uid: info.pbi_ruid,
        })
    }
}

/// The macOS identity read is a single `proc_pidinfo` snapshot, so it cannot
/// straddle a recycle the way the two-file Linux read can — there is no
/// mid-read incarnation change to detect, hence no `Changed` case.
#[cfg(target_os = "macos")]
fn probe_leader(pgid: u32) -> LeaderProbe {
    match leader_identity(pgid) {
        Some(id) => LeaderProbe::Present(id),
        None => LeaderProbe::Absent,
    }
}

/// No identity source on other unix targets: callers fall back to the numeric
/// liveness probe alone (the pre-#27 behaviour) rather than failing closed.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn leader_identity(_pgid: u32) -> Option<GroupIdentity> {
    None
}

/// With no identity source there is nothing to probe: report the leader as
/// absent so callers degrade to the numeric liveness probe (the pre-#27
/// behaviour), matching `leader_identity` returning `None`.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn probe_leader(_pgid: u32) -> LeaderProbe {
    LeaderProbe::Absent
}

/// A preserved process-group id **plus the identity of the group it named at
/// spawn**. Every cleanup SIGKILL is gated on [`PgidGuard::still_ours`], which
/// re-verifies the identity immediately before signalling, so a pgid that was
/// freed and recycled by an unrelated process group is never signalled outside
/// the accepted residual windows documented on [`GroupIdentity`] (issue
/// #27). Construct via [`PgidGuard::capture`] right after spawn.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PgidGuard {
    pgid: u32,
    identity: Option<GroupIdentity>,
}

#[cfg(unix)]
impl PgidGuard {
    /// Capture the pgid and its leader's identity. `pgid` is the leader's pid
    /// (agents are spawned with `process_group(0)`, so pid == pgid). When the
    /// identity cannot be read (a non-Linux/macOS unix, or a leader that exited
    /// in the spawn→capture window) it is `None` and [`PgidGuard::still_ours`]
    /// degrades to the numeric liveness probe — the pre-#27 behaviour — rather
    /// than disabling cleanup.
    pub(crate) fn capture(pgid: u32) -> Self {
        Self {
            pgid,
            identity: leader_identity(pgid),
        }
    }

    /// The numeric pgid, for passing to the watchdog / legacy call sites.
    pub(crate) fn pgid(&self) -> u32 {
        self.pgid
    }

    /// True while the group holding this pgid is alive *and* is not positively
    /// known to be a different (recycled) group. This is the check every cleanup
    /// SIGKILL must pass: a bare `kill(-pgid, 0)` (`group_alive`) proves only
    /// that *some* group holds the number, so on its own it can green-light
    /// signalling an unrelated group that recycled the pgid after the agent
    /// exited.
    ///
    /// Policy once the group is alive (`group_alive`):
    /// - **No captured identity** (`self.identity == None`, e.g. a platform
    ///   without an identity source): fall back to the numeric probe alone — the
    ///   pre-#27 behaviour.
    /// - **Leader still readable, identity matches**: ours — signal. (If our
    ///   leader was already reaped and the pgid recycled by a group whose live
    ///   leader happens to share our real uid *and* the same start tick, its
    ///   `(start, uid)` token collides and is mis-read as ours here — window 3
    ///   under the module *Scope of the guarantee*; like windows 1/2 it needs the
    ///   leader gone first, and is accepted.)
    /// - **Leader still readable, identity differs**: the pgid was recycled by a
    ///   *live* unrelated group — fail **closed**, do not signal (a live leader
    ///   with a different identity is a definite recycle).
    /// - **Leader changed mid-probe** ([`LeaderProbe::Changed`]): the bracketed
    ///   identity read detected a reap+recycle straddling it, so the group now
    ///   holding the pgid is positively a *different* incarnation — fail
    ///   **closed**, do not signal. This must not collapse into the fail-open
    ///   "leader gone" case below: a detected recycle means the replacement
    ///   group is present and unrelated, so signalling it is exactly the
    ///   recycled-PGID race #27 closes.
    /// - **Leader gone** (re-read yields [`LeaderProbe::Absent`]): the leader was reaped while
    ///   descendants kept the pgid reserved — almost certainly our own orphaned
    ///   descendants — so fail **open** and signal. This is the case the earlier
    ///   strict-equality check got wrong: it returned `false` here and *skipped*
    ///   the SIGKILL, leaking the very `TERM`-resistant descendants the cleanup
    ///   exists to kill. Two residual windows remain: (a) the nested recycle —
    ///   the group emptied entirely, the pgid was recycled, *and* the recycled
    ///   group's own leader was reaped too, all before this probe; and (b) a
    ///   check-to-signal TOCTOU — because this predicate and the `kill(2)` that
    ///   follows it are separate syscalls, a gone-leader group's last member can
    ///   exit and the pgid be recycled *between* this returning true and the
    ///   signal. Both are accepted (the price of not leaking orphans). They are
    ///   closed whenever the leader is held unreaped until after the SIGKILL.
    ///   [`terminate_group_and_reap`] does exactly that *unless the caller
    ///   already reaped the leader first*: the reaped-first sub-paths (`pipe.rs`
    ///   EOF-with-exit, `provision.rs` success, `acp.rs` mid-request exit) retain
    ///   these windows like the detached watchdog, while the leader-still-alive
    ///   paths (`acp.rs`'s normal shutdown, `pipe.rs`'s idle timeout) keep the
    ///   leader as a zombie through the grace loop and so *close* them (see the
    ///   module *Scope of the guarantee*; deferring the reap on the reaped-first
    ///   sub-paths to close them there too is tracked in #69).
    pub(crate) fn still_ours(&self) -> bool {
        if !group_alive(self.pgid) {
            return false;
        }
        match self.identity {
            Some(id) => match probe_leader(self.pgid) {
                // Live leader, identity matches: ours.
                LeaderProbe::Present(cur) => cur == id,
                // Leader reaped but the group is still alive: our orphaned
                // descendants hold the pgid — fail open (see the doc above).
                LeaderProbe::Absent => true,
                // Detected incarnation change mid-probe: a reap+recycle, so the
                // group is positively not ours — fail closed.
                LeaderProbe::Changed => false,
            },
            // No identity source on this platform: fall back to the numeric
            // probe alone (the pre-#27 behaviour).
            None => true,
        }
    }
}

/// Gracefully tear down an agent's whole process group and reap the leader:
/// `SIGTERM` the group, poll up to `grace` for it to exit (holding the leader
/// **unreaped** through the grace loop so its identity stays verifiable — see
/// below), then `SIGKILL` the group to catch any `TERM`-resistant descendant,
/// and finally reap the leader. Killing the group — not just `start_kill`ing
/// the direct leader — is what prevents a tool the agent started from surviving
/// a timeout / lease-loss cancellation and overlapping the redelivered job.
/// Safe to call when the group is already gone.
///
/// `guard` is the [`PgidGuard`] captured at **spawn** (the same one the
/// caller's [`GroupGuard`] holds), passed in rather than re-captured here: a
/// caller may already have reaped the leader (the pipe EOF path and ACP request
/// path call `child.wait()`), so a fresh capture at cleanup time would read
/// whatever group *currently* holds the pgid — blessing and signalling an
/// unrelated group if the number was recycled in between (issue #27). The
/// spawn-time identity held by `guard` instead fails the check on a recycled
/// pgid. `None` (a platform or spawn where no guard exists) skips the group
/// signals and only reaps.
///
/// Every group signal is gated on [`PgidGuard::still_ours`]: the guard
/// re-verifies the group's identity immediately before each SIGTERM/SIGKILL, so
/// a pgid that was freed and recycled by an unrelated group in the window since
/// the last check is never signalled outside the accepted residual windows (see
/// [`GroupIdentity`]) (issue #27). The leader is held
/// **unreaped** through the grace loop so that identity stays positively
/// readable (and the pgid un-recyclable) until the final SIGKILL decision; it
/// is reaped only by the `child.wait()` at the end.
#[cfg(unix)]
pub(crate) async fn terminate_group_and_reap(
    child: &mut tokio::process::Child,
    guard: Option<PgidGuard>,
    grace: std::time::Duration,
) {
    if let Some(guard) = guard {
        let pgid = guard.pgid();
        // Only signal the pgid while it still names *our* group. If the leader
        // was already reaped and no descendant remains, the pid is no longer
        // reserved and could have been recycled — signalling it would risk
        // hitting an unrelated group, so the identity check must pass first.
        if guard.still_ours() {
            // Negative pid = the whole process group (agent + tools it started).
            // Signal via a direct libc `kill(-pgid, SIGTERM)` rather than
            // spawning `kill(1)`: a spawned child would inherit the daemon's
            // scrubbed-from-the-agent `CAMUNDA_*`/`ZEEBE_*` credentials and expose
            // them via `/proc/<pid>/environ` to a same-user host agent for the
            // duration of that child.
            sigterm_group(pgid);
            let deadline = std::time::Instant::now() + grace;
            loop {
                // Hold the leader **unreaped** through the grace loop. Reaping it
                // (`child.try_wait()`) the instant it exits would free its `/proc`
                // entry, so a later `still_ours` could no longer re-read the
                // leader's identity — and while that check now fails *open* on a
                // gone leader, keeping the leader as a zombie keeps the identity
                // positively verifiable (and the pgid un-recyclable) for the whole
                // window, so the deadline SIGKILL below is gated on a real match.
                // This grace runs after every ACP job (`acp::shutdown`), so the
                // accepted cost would be ~`grace` per clean ACP shutdown — except
                // that the clean-exit fast path below breaks as soon as the group
                // has drained to just the held zombie anchor (issue #50).
                if !guard.still_ours() {
                    // The group is gone (every member exited). Don't re-signal.
                    break;
                }
                // Clean-exit fast path (issue #50). The held leader zombie keeps
                // `still_ours`/`group_alive` true even after every *real* member
                // has exited, which otherwise forced the full `grace` wait on a
                // clean shutdown. `group_has_live_member` enumerates the group and
                // excludes zombies, so once nothing but the anchor remains there is
                // nothing left to SIGKILL — break immediately. The zombie anchor is
                // still held until the final `child.wait()` below, so the identity
                // stays verifiable for the gating above right up to this break.
                //
                // That enumeration is best-effort and non-atomic, and it fails
                // *open*: a member that forks+exits mid-scan can be missed and
                // so read as absent. A bare break would then skip the SIGKILL
                // and leak that `TERM`-resistant member. So make a false
                // negative harmless: SIGKILL the group (identity-gated, exactly
                // like the deadline branch) *before* breaking. When the scan was
                // right and only the held zombie anchor remains, SIGKILL to a
                // zombie is a no-op and adds no grace wait; when the scan
                // under-reported, it still reaps the missed member on the fast
                // path instead of leaking it.
                //
                // Only that process-list race under-reports. A per-member
                // inspection failure does *not*: a non-`NotFound` `/proc` read
                // error or a non-`ESRCH` `proc_pidinfo` error falls back to
                // `group_alive`, i.e. it reads as *live* — the fail-safe
                // direction — so the grace loop keeps waiting rather than
                // breaking early. The false negative this SIGKILL covers comes
                // from the non-atomic enumeration, not from inspection failures.
                //
                // Run the scan on the blocking pool: it is a synchronous,
                // potentially system-wide traversal (Linux reads one
                // `/proc/<pid>/stat` per PID) and this loop repeats it every
                // 50 ms, so running it inline on a Tokio worker can starve
                // unrelated async work on a high-PID host — the same reason
                // `slot::prepare_run_dir_blocking` offloads its traversal. A join
                // failure (the scan task panicked) is treated as "still a live
                // member", so the grace loop keeps waiting rather than breaking
                // early — the fail-safe direction.
                //
                // Bound the wait by the grace remaining: awaiting an unbounded
                // `spawn_blocking` job before checking `deadline` would break the
                // "poll up to `grace`, then SIGKILL" contract if the blocking pool
                // is saturated or the system-wide `/proc` scan stalls, letting a
                // TERM-resistant group survive arbitrarily past the deadline. A
                // timeout conservatively means "live", so the deadline branch
                // below fires the SIGKILL as soon as `grace` is exhausted.
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let has_live_member = tokio::time::timeout(
                    remaining,
                    tokio::task::spawn_blocking(move || group_has_live_member(pgid)),
                )
                .await
                // `Err(_)` = the scan did not finish within the remaining grace:
                // treat as "still a live member" so the deadline branch SIGKILLs.
                .unwrap_or(Ok(true))
                // `Err(_)` = the scan task panicked: fail safe as "live" too.
                .unwrap_or(true);
                if !has_live_member {
                    if guard.still_ours() {
                        sigkill_group(pgid);
                    }
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    // A `TERM`-resistant descendant survived; the pgid is still
                    // ours (the leader zombie and/or that descendant holds it).
                    // Re-verify the identity immediately before the SIGKILL: the
                    // last survivor can exit in the window since the loop's
                    // top-of-iteration check, freeing the pgid to be recycled by
                    // an unrelated group — only signal when the group is still
                    // verifiably ours.
                    if guard.still_ours() {
                        sigkill_group(pgid);
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
    _guard: Option<PgidGuard>,
    _grace: std::time::Duration,
) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
}

/// Non-Unix stub so [`GroupGuard`]'s field type resolves on every platform.
/// `GroupGuard` is compiled unconditionally (it is referenced from
/// platform-independent call sites), but the real [`PgidGuard`] is Unix-only; on
/// Windows the guard is always `None` and never signals, so an empty placeholder
/// is all the type system needs.
#[cfg(not(unix))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PgidGuard;

/// Cancellation cleanup guard: SIGKILLs the agent's process group when dropped,
/// unless disarmed. Ensures a dropped (aborted) in-flight agent tears down the
/// whole tree — not just the leader `kill_on_drop` reaps — while the normal path
/// disarms it once the group has been reaped (so a recycled pid is never hit).
///
/// The guard captures the group's identity at construction ([`PgidGuard`]) and
/// re-verifies it immediately before the drop-time SIGKILL, so a pgid that was
/// freed and recycled by an unrelated group in the drop window is not signalled
/// outside the accepted residual windows (see [`GroupIdentity`]) (issue #27).
pub(crate) struct GroupGuard(Option<PgidGuard>);

impl GroupGuard {
    pub(crate) fn new(pid: Option<u32>) -> Self {
        #[cfg(unix)]
        {
            Self(pid.map(PgidGuard::capture))
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            Self(None)
        }
    }

    /// The spawn-time [`PgidGuard`] this cancellation guard holds, for passing
    /// to [`terminate_group_and_reap`]: that routine must verify against the
    /// identity captured at *spawn*, never a fresh cleanup-time capture (a
    /// caller may already have reaped the leader, and a fresh capture would
    /// read — and bless — whatever group currently holds a recycled pgid).
    /// `None` on non-Unix platforms or when no pgid was captured.
    pub(crate) fn guard(&self) -> Option<PgidGuard> {
        self.0
    }

    /// SIGKILL the captured group now, gated on the identity captured at
    /// construction (spawn time) — **never** a fresh signal-time capture. A
    /// caller that times out must reuse this guard rather than
    /// `PgidGuard::capture`-ing the pgid again at signal time: a fresh capture
    /// reads whatever group currently holds the number, so if the leader was
    /// already reaped and the pgid recycled it would bless and SIGKILL an
    /// unrelated group. The spawn-time identity held here instead fails the
    /// check on a recycled pgid (issue #27). No-op if disarmed or the group is
    /// no longer verifiably ours.
    pub(crate) fn kill_group_if_ours(&self) {
        #[cfg(unix)]
        if let Some(guard) = self.0 {
            if guard.still_ours() {
                sigkill_group(guard.pgid());
            }
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(guard) = self.0 {
            // Only signal while the group is still verifiably ours. A
            // cancellation can drop the guard in the window after the leader was
            // reaped (by `kill_on_drop`, or a prior `child.wait()` on the pipe
            // EOF / ACP request path) but before `disarm` runs; once the group is
            // empty the pid is no longer reserved as a pgid and may have been
            // recycled for an unrelated group, so an unconditional kill could hit
            // it. `still_ours` re-checks the leader's identity, so a recycled
            // pgid is not signalled outside the accepted residual windows (see
            // [`GroupIdentity`]) — including the same-tick, same-uid collision
            // (window 3), where a live recycled group *is* signalled.
            if guard.still_ours() {
                sigkill_group(guard.pgid());
            }
        }
    }
}

/// Start a watchdog that kills the agent's whole process group when the daemon
/// dies, and return an owned [`WatchdogHandle`] for it. `agent_pid` is the
/// agent's pid, which is also its process-group id (the agent is spawned with
/// `process_group(0)`).
///
/// This runs on **both** macOS and Linux. On Linux `PR_SET_PDEATHSIG` ([`arm`])
/// only signals the direct agent process, not the descendants it spawns; those
/// share the agent's process group but receive no signal on parent death, so a
/// `kill -9` of the daemon would orphan them. The watchdog closes that gap by
/// signalling the entire process group once the daemon exits.
///
/// The caller should [`WatchdogHandle::stop`] the returned handle once it has
/// finished the guarded work AND torn down the child's process group itself:
/// that stops and reaps the watchdog deterministically, which is what closes the
/// zombies-only-group leak (issue #67 / #84) WITHOUT weakening the shared
/// retirement predicate. Dropping the handle instead detaches the watchdog
/// fire-and-forget — it keeps back-stopping and self-retires once its target
/// group is numerically gone, reaped on a detached thread so it never zombies.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[must_use = "dropping the handle detaches the watchdog fire-and-forget; call \
              `stop()` after the caller's own group cleanup to stop and reap it"]
pub fn watch(agent_pid: u32) -> WatchdogHandle {
    WatchdogHandle {
        child: spawn_watchdog(agent_pid),
    }
}

/// An owned handle to a running parent-death watchdog (see [`watch`]).
///
/// Holding it lets the caller STOP and reap the watchdog deterministically —
/// [`WatchdogHandle::stop`] — once the guarded work is done and the caller has
/// torn down the child's process group itself. Dropping it without `stop`
/// instead detaches the watchdog fire-and-forget (the pre-#84 behaviour): it
/// keeps running as the parent-death backstop and is reaped on a detached thread
/// when it self-retires, so it never lingers as a zombie (issue #52).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub struct WatchdogHandle {
    /// `None` when the watchdog could not be spawned (best-effort backstop) or
    /// after `stop`/`drop` has taken ownership of the child to reap it.
    child: Option<std::process::Child>,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl WatchdogHandle {
    /// Stop the watchdog NOW and reap it. Call this only AFTER the caller has
    /// torn down the child's process group itself (so there is nothing left for
    /// the watchdog to back-stop): it SIGKILLs the watchdog, then `wait`s to
    /// reap it. This is what deterministically closes the zombies-only watchdog
    /// leak (issue #67 / #84) without weakening the shared retirement predicate
    /// — the watchdog no longer has to *observe* its group drain in order to
    /// exit. It cannot race the daemon-death kill: the caller runs inside the
    /// daemon, so if it is alive to call `stop`, the daemon is alive and no
    /// parent-death backstop is needed. `wait` returns promptly because the
    /// watchdog is our own direct child and was just SIGKILLed.
    pub fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Drop for WatchdogHandle {
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return; // already stopped/reaped
        };
        // The watchdog is our child: it must be reaped when it exits, or it
        // lingers as a zombie of the daemon (one leaked slot per watched spawn
        // until `fork` hits EAGAIN — issue #52). It can live as long as the
        // watched group, so wait on a DETACHED thread rather than block the
        // dropping caller. Spawn that reaper FALLIBLY: under a process/thread
        // limit the OS can refuse to create it, and a panicking `thread::spawn`
        // inside a `Drop` would abort the process. On failure, kill + reap the
        // watchdog inline so nothing leaks — dropping the backstop early is
        // strictly better than leaking a zombie plus its reaper. The child is
        // shared with the reaper closure behind an `Arc<Mutex>` so the error path
        // can still reach it to kill + reap after a failed `Builder::spawn`.
        let pid = child.id();
        let child = std::sync::Arc::new(std::sync::Mutex::new(child));
        let reaper_child = std::sync::Arc::clone(&child);
        if std::thread::Builder::new()
            .spawn(move || {
                if let Ok(mut c) = reaper_child.lock() {
                    let _ = c.wait();
                }
            })
            .is_err()
        {
            if let Ok(mut c) = child.lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
            crate::runtime::log(&format!(
                "warning: parent-death watchdog reaper thread failed to spawn for pid {pid}"
            ));
        }
    }
}

/// Spawn the parent-death watchdog for `agent_pid` (see [`watch`]) and return
/// its [`Child`](std::process::Child), or `None` if it could not be spawned.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn spawn_watchdog(agent_pid: u32) -> Option<std::process::Child> {
    let Ok(exe) = std::env::current_exe() else {
        return None;
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
    // Capture the agent group's identity here too, while the agent is
    // guaranteed alive, and hand it to the watchdog. The watchdog's final
    // SIGKILL is then gated on the identity (issue #27), so a pgid recycled by
    // an unrelated group between the agent's exit and the daemon's death is
    // not signalled outside the accepted residual windows (see
    // [`GroupIdentity`]). Without this the watchdog only has the numeric pgid,
    // which proves liveness of *some* group, not the agent's.
    let group_identity = leader_identity(agent_pid);
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
    if let Some(id) = group_identity {
        cmd.arg("--pgid-start")
            .arg(id.start.to_string())
            .arg("--pgid-uid")
            .arg(id.uid.to_string());
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
    match cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            // Reaping is now the owner's responsibility via the returned
            // `WatchdogHandle` (its `stop` or `Drop`), so just hand the child
            // back. This keeps the no-zombie guarantee (issue #52) while letting
            // the caller close the group deterministically (issue #67 / #84).
            Some(child)
        }
        Err(e) => {
            crate::runtime::log(&format!(
                "warning: parent-death watchdog failed to spawn for pid {agent_pid}: {e}"
            ));
            None
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[must_use]
pub fn watch(_agent_pid: u32) -> WatchdogHandle {
    WatchdogHandle
}

/// Non-unix stub of the owned watchdog handle (see the unix [`WatchdogHandle`]).
/// No watchdog runs on these platforms, so `stop` is a no-op; the type exists
/// only so call sites and the structs that store it stay platform-neutral.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub struct WatchdogHandle;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl WatchdogHandle {
    pub fn stop(self) {}
}

/// The macOS watchdog loop: block on the parent pid via kqueue `NOTE_EXIT`,
/// then `SIGKILL` the agent's process group. Returns when the parent is gone
/// and the group has been signalled — or early, without signalling, once the
/// agent's process group has exited on its own (a completed job), so the
/// watchdog does not linger as a polling child for the daemon's whole lifetime.
#[cfg(target_os = "macos")]
pub fn reap_watchdog(
    parent_pid: u32,
    pgid: u32,
    _parent_start: Option<u64>,
    pgid_start: Option<u64>,
    pgid_uid: Option<u32>,
) {
    // Rebuild the identity token the daemon captured at spawn (issue #27). Both
    // halves are required; if either is missing the watchdog has no identity and
    // falls back to the numeric liveness probe alone (the pre-#27 behaviour).
    let expected = pgid_start
        .zip(pgid_uid)
        .map(|(start, uid)| GroupIdentity { start, uid });
    let still_ours = || group_identity_matches(pgid, expected);
    // SAFETY: standard kqueue usage; the fd is closed before return.
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            // No kqueue: fall back to polling both conditions.
            // Re-verify the group's identity immediately before signalling: the
            // parent may have exited while the agent's group already went away,
            // freeing the pid to be recycled by an unrelated group — only SIGKILL
            // a group that is still verifiably the agent's.
            if wait_parent_or_group_gone(parent_pid, pgid, None) && still_ours() {
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
                // Numeric group-gone check: retire only when the group is
                // NUMERICALLY gone (`kill(-pgid, 0)` fails). This retirement
                // predicate is deliberately the bare numeric probe, NOT the
                // advisory `group_has_live_member` scan (issue #67 review / #84):
                // that scan can under-report a still-live member — a `fork()`
                // racing the enumeration, or a Linux thread-group leader shown
                // `Z` while its sibling threads still run — and on this SHARED
                // parent-death backstop a false "gone" would retire the watchdog
                // PREMATURELY and drop the daemon-death SIGKILL cleanup for a tree
                // that is still alive. The zombies-only-group leak that first
                // motivated the scan is instead closed deterministically by the
                // caller stopping this watchdog after its own group cleanup
                // (`WatchdogHandle::stop`), so retirement never has to weaken.
                if !group_alive(pgid) {
                    break false; // group numerically gone -> nothing to do
                }
            }
        };
        libc::close(kq);
        // Re-verify the group's identity immediately before signalling: after the
        // parent exited the agent's group may already have vanished, freeing the
        // pid to be recycled by an unrelated group. The identity check gates the
        // kill so a recycled pgid is not signalled outside the accepted residual
        // windows (see [`GroupIdentity`]) (issue #27).
        if parent_died && still_ours() {
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
pub fn reap_watchdog(
    parent_pid: u32,
    pgid: u32,
    parent_start: Option<u64>,
    pgid_start: Option<u64>,
    pgid_uid: Option<u32>,
) {
    // Prefer the start time the daemon captured for us while it was still alive
    // (passed via `--parent-start`); only fall back to reading `/proc` ourselves
    // if it was not supplied. Reading it here is racy: the daemon may already be
    // gone, yielding `None` and silently disabling PID-reuse detection. Using the
    // daemon-supplied value keeps `expected_start` populated so a recycled parent
    // pid can never masquerade as the original and strand the agent group.
    let expected_start = parent_start.or_else(|| parent_start_time(parent_pid));
    // Rebuild the agent group's identity token the daemon captured at spawn
    // (issue #27). Both halves are required; if either is missing the watchdog
    // has no identity and falls back to the numeric liveness probe alone.
    let expected_group = pgid_start
        .zip(pgid_uid)
        .map(|(start, uid)| GroupIdentity { start, uid });
    // SAFETY: plain libc calls; no shared Rust state is touched.
    unsafe {
        // Re-verify the group's identity immediately before signalling: the
        // parent may have exited while the agent's group already went away,
        // freeing the pid to be recycled by an unrelated group. The identity
        // check gates the kill so a recycled pgid is not signalled outside the
        // accepted residual windows (see [`GroupIdentity`]) (issue #27).
        //
        // Residual check-to-signal TOCTOU: this predicate and `sigkill_group`
        // are separate syscalls, so in the fail-open (gone-leader) branch the
        // last orphaned descendant can exit and the pgid be recycled in between,
        // broader than the nested-recycle poll-interval window. The detached
        // watchdog can never hold the leader unreaped to close this gap, and the
        // reaped-first in-process sub-paths (pipe EOF-with-exit, provision
        // success, acp mid-request exit) reap it first too, so neither closes it;
        // the leader-still-alive paths (acp normal shutdown, pipe idle timeout)
        // hold the leader unreaped through the grace loop and do close it (see the
        // module *Scope of the guarantee*). Where open it is accepted to avoid
        // leaking orphans. Shrinking it is tracked in #69.
        if wait_parent_or_group_gone(parent_pid, pgid, expected_start)
            && group_identity_matches(pgid, expected_group)
        {
            sigkill_group(pgid);
        }
    }
}

/// True while the group holding `pgid` is alive **and** is not positively known
/// to be a different (recycled) group. With no captured identity (`expected ==
/// None`, e.g. a platform without an identity source) this degrades to the
/// numeric liveness probe — the pre-#27 behaviour — rather than disabling the
/// watchdog's cleanup.
///
/// The policy mirrors [`PgidGuard::still_ours`]: a *live* leader whose identity
/// differs from `expected` is a definite recycle, so fail **closed**; a leader
/// that is *gone* (re-read yields `None`) means it was reaped while descendants
/// kept the pgid reserved — almost certainly our own orphans — so fail **open**
/// and reap them. Failing closed there (the earlier strict-equality behaviour)
/// skipped the SIGKILL and leaked the very orphaned descendants the watchdog
/// exists to kill. Two residual windows are accepted here: the nested-recycle
/// window (group emptied, pgid recycled, recycled leader also reaped, all inside
/// one poll interval) and — because this check and the caller's `sigkill_group`
/// are separate syscalls — a check-to-signal TOCTOU, where a gone-leader group's
/// last member exits and the pgid is recycled between this returning true and the
/// signal. The detached watchdog can never hold the leader unreaped to close
/// them, and the reaped-first in-process sub-paths (pipe EOF-with-exit, provision
/// success, acp mid-request exit) reap it first too, so neither closes them,
/// while the leader-still-alive paths (acp normal shutdown, pipe idle timeout)
/// hold the leader unreaped through the grace loop and close them (see the module
/// *Scope of the guarantee*); shrinking the window is tracked in #69. A same-tick,
/// same-uid recycle (window 3) collides on the identity token on those same
/// reaped-first paths and is likewise closed where the leader is held unreaped.
/// See [`PgidGuard::still_ours`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn group_identity_matches(pgid: u32, expected: Option<GroupIdentity>) -> bool {
    if !group_alive(pgid) {
        return false;
    }
    match expected {
        Some(id) => match probe_leader(pgid) {
            // Live leader, identity matches: ours.
            LeaderProbe::Present(cur) => cur == id,
            // Leader reaped but the group is still alive: our orphaned
            // descendants hold the pgid — fail open (see the doc above).
            LeaderProbe::Absent => true,
            // Detected incarnation change mid-probe: a reap+recycle straddled
            // the identity read, so the group holding the pgid is positively a
            // different incarnation — fail closed, do not signal the unrelated
            // replacement group (the race #27 closes).
            LeaderProbe::Changed => false,
        },
        None => true,
    }
}

/// Like [`group_identity_matches`] but for a **single pid** that is *not* a
/// process-group leader — the supervisor the owner watchdog reaps (see
/// [`sigkill_pid`]). `group_identity_matches` first calls `group_alive(pid)`
/// (`kill(-pid, 0)`), which answers `ESRCH` for a non-leader pid whose real
/// group is named by some other leader, so it would wrongly report the live
/// daemon as gone and skip the kill. This probes the pid directly: alive *and*
/// the same incarnation (`/proc/<pid>` start+uid) as the token captured at arm.
/// A vanished or recycled pid (`Absent`/`Changed`) fails closed — the original
/// process is gone, so there is nothing of ours to signal.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn pid_identity_matches(pid: u32, expected: Option<GroupIdentity>) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    match expected {
        Some(id) => matches!(probe_leader(pid), LeaderProbe::Present(cur) if cur == id),
        None => true,
    }
}
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
/// already drained of every member. Returns `true` when the parent died (the
/// caller should reap the group), `false` when the group is numerically gone
/// (`kill(-pgid, 0)` fails — nothing to do).
///
/// The group-gone test is the **bare numeric** probe ([`group_alive`]), NOT the
/// advisory [`group_has_live_member`] scan. The scan is zombie-aware but can
/// under-report a live member — a `fork()` racing its enumeration, or a Linux
/// thread-group leader shown `Z` while its sibling threads run — so on this
/// SHARED parent-death backstop a false "gone" would retire the watchdog
/// PREMATURELY and drop the daemon-death SIGKILL cleanup for a tree that is still
/// alive (issue #67 review / #84). The zombies-only-group leak that once pushed
/// this predicate toward the scan is instead closed deterministically by the
/// caller stopping the watchdog after its own group cleanup
/// ([`WatchdogHandle::stop`]), so retirement keeps the safe numeric test.
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
        // its group must be reaped rather than waited on forever. Only a
        // SUCCESSFULLY READ, different start time proves a recycle: a failed
        // `parent_start_time` read returns `None`, and `None != Some(token)`
        // would misclassify a transient `/proc` failure as a recycle and reap a
        // live daemon's group (issue #54 review). Degrade to liveness-only on a
        // read failure.
        #[cfg(target_os = "linux")]
        if let Some(start) = expected_start {
            if matches!(parent_start_time(parent_pid), Some(cur) if cur != start) {
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
        // Numeric group-gone check: retire only when the group is NUMERICALLY
        // gone (`kill(-pgid, 0)` fails). Deliberately NOT the advisory
        // `group_has_live_member` scan — on this SHARED retirement predicate the
        // scan's under-reporting (a `fork()` racing the enumeration, or a Linux
        // `Z` thread-group leader with live sibling threads) would retire the
        // watchdog PREMATURELY and lose the daemon-death cleanup backstop for a
        // still-live tree, at EVERY call site, not just gh-token refreshes (issue
        // #67 review / #84). The zombies-only-group leak that first pushed this
        // toward the scan is closed instead by the caller stopping the watchdog
        // explicitly after verified group cleanup (`WatchdogHandle::stop`).
        if !group_alive(pgid) {
            return false; // group numerically gone -> nothing to reap
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Stub on platforms without a watchdog process (they rely on [`arm`]).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn reap_watchdog(
    _parent_pid: u32,
    _pgid: u32,
    _parent_start: Option<u64>,
    _pgid_start: Option<u64>,
    _pgid_uid: Option<u32>,
) {
}

// The identity/watchdog unit tests run on both Linux and macOS — the two
// platforms with a real `leader_identity` source and a watchdog — so the macOS
// identity path (`proc_pidinfo`) and the shared fail-open/fail-closed policy get
// runtime coverage, not just the Linux `/proc` one (review finding: macOS had
// none). Linux-only helpers (`parent_start_time`, `parent_is_dead_or_zombie`)
// keep their own `cfg(target_os = "linux")` tests below.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    /// Regression (issue #52): the watchdog is our child, so when it exits it
    /// must be reaped. An unreaped watchdog stays a zombie of the daemon for
    /// its whole lifetime — one leaked process slot per agent/git spawn until
    /// `fork` fails with EAGAIN. Under `cargo test` the "watchdog" is the test
    /// binary, which exits at once on the unknown `__reap-watchdog` argument,
    /// so it must disappear from the process table rather than linger as `Z`.
    /// Regression (issue #52 / #84): the watchdog is our child, so when it
    /// exits it must be reaped — an unreaped watchdog stays a zombie of the
    /// daemon for its whole lifetime (one leaked slot per agent/git spawn until
    /// `fork` fails with EAGAIN). Under #84 the owning [`WatchdogHandle`] reaps
    /// it: here the handle is DROPPED (the cancellation / fire-and-forget path),
    /// so a detached thread must `wait` it. Under `cargo test` the "watchdog" is
    /// the test binary, which exits at once on the unknown `__reap-watchdog`
    /// argument, so it must disappear from the process table rather than linger
    /// as `Z`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn dropped_watchdog_handle_reaps_its_child() {
        let child = spawn_watchdog(std::process::id()).expect("watchdog spawns");
        let pid = child.id();
        // Dropping the handle must reap the child on a detached thread.
        drop(WatchdogHandle { child: Some(child) });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut last = String::new();
        while std::time::Instant::now() < deadline {
            let out = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .expect("ps runs");
            last = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if last.is_empty() {
                return; // exited and reaped
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("dropped watchdog pid {pid} was never reaped (ps stat {last:?})");
    }

    /// Regression (issue #67 / #84): [`WatchdogHandle::stop`] must stop AND reap
    /// the watchdog deterministically — this is the mechanism that replaces the
    /// retirement-predicate weakening and closes the zombies-only leak. After
    /// `stop` returns, the child must already be gone from the process table
    /// (not merely signalled): `stop` SIGKILLs then `wait`s, so there is no
    /// detached-thread delay to poll for.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn stopped_watchdog_handle_reaps_synchronously() {
        let child = spawn_watchdog(std::process::id()).expect("watchdog spawns");
        let pid = child.id();
        WatchdogHandle { child: Some(child) }.stop();
        // `stop` reaped inline, so the pid is already gone — assert without a
        // polling grace window (a lingering `Z` here would be a real regression).
        let out = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .expect("ps runs");
        let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            stat.is_empty(),
            "stop() must reap the watchdog synchronously, but pid {pid} is still \
             present (ps stat {stat:?})"
        );
    }

    /// Regression (issue #67 / #84 — the Option (a) redesign): the SHARED
    /// retirement predicate must use the bare NUMERIC liveness probe, never the
    /// advisory `group_has_live_member` scan. A zombies-only group still answers
    /// `kill(-pgid, 0)` (the zombie leader is held), so the watchdog must KEEP
    /// monitoring it — it must NOT prematurely retire — and only conclude "group
    /// gone" once the zombie is reaped and the group is numerically gone.
    ///
    /// This replaces the round-11 `watchdog_treats_a_zombies_only_group_as_gone`
    /// test, whose premise (retire on the zombie-aware scan) was reverted:
    /// retiring on the advisory scan can drop the daemon-death SIGKILL cleanup
    /// for a still-live tree (a `fork` racing enumeration, or a `Z` thread-group
    /// leader with live sibling threads). The leak the scan once addressed is
    /// now closed by the owner calling [`WatchdogHandle::stop`] instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn watchdog_keeps_monitoring_a_zombies_only_group_until_numerically_gone() {
        // SAFETY: a bare `fork`; the child only makes async-signal-safe libc
        // calls (`setpgid`, `_exit`) and the parent reaps it with `waitpid`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // Child: lead a brand-new process group, then exit at once so the
            // group is left with a single ZOMBIE leader — the state a SIGKILLed
            // descendant held unreaped by a non-reaping init leaves behind.
            unsafe {
                libc::setpgid(0, 0);
                libc::_exit(0);
            }
        }
        let child = pid as u32;
        let mut is_zombie = false;
        for _ in 0..1000 {
            if parent_is_dead_or_zombie(child) {
                is_zombie = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            is_zombie,
            "the child must become a zombie leader of its own group"
        );
        // The group is numerically alive (the zombie is held) even though it has
        // no LIVE member. The reverted predicate keys on the numeric probe, so
        // the watchdog must NOT retire yet.
        assert!(
            group_alive(child),
            "the numeric probe must still see the held zombie leader"
        );
        assert!(
            !group_has_live_member(child),
            "sanity: the zombies-only group has no live member"
        );
        let me = std::process::id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // SAFETY: `wait_parent_or_group_gone` only makes libc liveness probes.
            let parent_died = unsafe { wait_parent_or_group_gone(me, child, None) };
            let _ = tx.send(parent_died);
        });
        // It must NOT retire while the group is numerically alive (parent alive,
        // zombie still held): a premature return here is the regression.
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "the watchdog retired on a numerically-alive (zombies-only) group — \
             the reverted predicate must keep monitoring until the group is gone"
        );
        // Reap the zombie: the group is now NUMERICALLY gone, so the next poll
        // must return `false` (nothing to reap).
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(parent_died) => assert!(
                !parent_died,
                "once the group is numerically gone the watchdog must return \
                 `false` (nothing to reap), not report parent death"
            ),
            Err(_) => panic!(
                "wait_parent_or_group_gone never returned after the group became \
                 numerically gone while the parent stayed alive"
            ),
        }
    }

    /// Regression (issue #67 / #84): the retirement predicate must not retire
    /// while the group still has a genuinely LIVE member. This is the fork /
    /// live-thread concern the reviewer raised — the advisory scan could
    /// under-report a live member and retire early; the numeric probe cannot.
    /// A live child in its own group keeps the watchdog monitoring; only once it
    /// is killed AND reaped (group numerically gone) does the watchdog retire.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn watchdog_does_not_retire_while_a_live_member_remains() {
        // SAFETY: a bare `fork`; the child only makes async-signal-safe libc
        // calls (`setpgid`, `pause`/`_exit`) and the parent kills + reaps it.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // Child: lead its own group and block indefinitely so it stays a
            // genuinely LIVE member until the parent kills it.
            unsafe {
                libc::setpgid(0, 0);
                loop {
                    libc::pause();
                }
            }
        }
        let child = pid as u32;
        // Wait until the child has entered its own group and is live.
        let mut ready = false;
        for _ in 0..1000 {
            if group_alive(child) && !parent_is_dead_or_zombie_portable(child) {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(ready, "the live child must enter its own group");
        let me = std::process::id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // SAFETY: `wait_parent_or_group_gone` only makes libc liveness probes.
            let parent_died = unsafe { wait_parent_or_group_gone(me, child, None) };
            let _ = tx.send(parent_died);
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "the watchdog retired while a live member remained — premature \
             retirement would drop the daemon-death cleanup for a live tree"
        );
        // Kill the whole group and reap the leader: now numerically gone.
        unsafe {
            libc::kill(-(pid), libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(parent_died) => assert!(
                !parent_died,
                "once the member is killed + reaped the watchdog must return \
                 `false` (group numerically gone), not report parent death"
            ),
            Err(_) => panic!(
                "wait_parent_or_group_gone never returned after the live member \
                 was killed and reaped while the parent stayed alive"
            ),
        }
    }

    /// Regression (issue #67 / #84): exercise the REAL production `reap_watchdog`
    /// loop (not just its `wait_parent_or_group_gone` helper). With the parent
    /// alive but the target group already numerically gone, the loop must retire
    /// PROMPTLY and WITHOUT signalling — a watchdog whose job finished must not
    /// poll until the daemon itself dies. Run it off-thread with a deadline so a
    /// regression (polling forever) fails the test instead of hanging it.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn production_reap_watchdog_retires_when_parent_alive_and_group_gone() {
        // Create a definitely-dead pgid: fork a child into its own group, let it
        // exit, and reap it — its pgid is then numerically gone (`kill(-pgid, 0)`
        // fails). SAFETY: the child only makes async-signal-safe libc calls.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                libc::setpgid(0, 0);
                libc::_exit(0);
            }
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let dead_pgid = pid as u32;
        // Guard against the (unlikely) pid-reuse of our just-reaped child.
        if group_alive(dead_pgid) {
            return;
        }
        let me = std::process::id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Parent (`me`) is alive, group is gone -> must return promptly.
            reap_watchdog(me, dead_pgid, None, None, None);
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok(),
            "reap_watchdog did not retire for an alive parent + numerically-gone \
             group: it would poll until the daemon's own death"
        );
    }

    /// Portable "is this pid dead or a zombie" probe for the cross-platform
    /// tests above. On Linux it uses the real `/proc` classifier; on macOS,
    /// which has no equivalent here, it approximates with the numeric probe
    /// (a live member answers `kill(pid, 0)`), which is all these tests need.
    #[cfg(target_os = "linux")]
    fn parent_is_dead_or_zombie_portable(pid: u32) -> bool {
        parent_is_dead_or_zombie(pid)
    }
    #[cfg(target_os = "macos")]
    fn parent_is_dead_or_zombie_portable(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) != 0 }
    }

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
    #[test]
    fn own_process_is_not_dead_or_zombie() {
        // Our own live, running process must not be classified as dead/zombie —
        // otherwise the watchdog would spuriously reap a live daemon's group.
        assert!(!parent_is_dead_or_zombie(std::process::id()));
        // A pid that cannot exist yields a false (unreadable /proc) — the
        // caller's `kill(_, 0)` probe is the authority for a truly-gone pid.
        assert!(!parent_is_dead_or_zombie(u32::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_start_time_reads_own_incarnation() {
        // The owner watchdog's PID-reuse token: our own process is alive, so its
        // start time must be readable and stable across reads — the value the
        // daemon captures at arm and hands to the watchdog so a recycled owner
        // pid (still answering `kill(_, 0)`) is detected as owner death.
        let me = std::process::id();
        let a = owner_start_time(me).expect("own start time readable");
        let b = owner_start_time(me).expect("own start time readable");
        assert_eq!(a, b);
        assert!(a > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_recycle_is_detected_as_a_start_time_mismatch() {
        // The comparison the owner watchdog makes each poll: a live process whose
        // start time differs from the token captured at arm is a *recycled* pid,
        // not the original owner — treat it as owner death. Model the recycle by
        // comparing our own live process against a forged token; the mismatch
        // must read as "owner gone".
        let me = std::process::id();
        let real = owner_start_time(me).expect("own start time readable");
        let forged = real.wrapping_add(1);
        // Mirror the watchdog's `owner_gone` expression (post issue #54 review):
        // only a SUCCESSFULLY READ, different token proves a recycle.
        let owner_gone = !pid_alive(me)
            || (Some(forged)
                .is_some_and(|s| matches!(parent_start_time(me), Some(cur) if cur != s)));
        assert!(
            owner_gone,
            "a start-time mismatch on a live pid must read as owner death (recycled pid)"
        );
        // And the matching token must NOT read as owner death.
        let owner_gone_ok = !pid_alive(me)
            || (Some(real).is_some_and(|s| matches!(parent_start_time(me), Some(cur) if cur != s)));
        assert!(
            !owner_gone_ok,
            "the matching token must not read as owner death"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_read_failure_is_not_a_recycle() {
        // Regression (issue #54 review): a FAILED start-time read returns `None`,
        // and `None != Some(token)` must NOT read as owner death — otherwise a
        // transient `/proc` failure SIGKILLs a daemon whose owner is still alive.
        // Model the read failure by pointing the probe at a pid that cannot be
        // read (`u32::MAX`), while the captured token is a real one: the
        // expression must degrade to liveness-only and report the owner NOT gone
        // on the strength of the (failed) identity read alone.
        let me = std::process::id();
        let real = owner_start_time(me).expect("own start time readable");
        // The identity read fails (None) for an unreadable pid; the owner pid
        // itself is alive (`me`). Mirror the watchdog expression with the read
        // failing: no successfully-read-different token => not a recycle.
        let owner_gone = !pid_alive(me)
            || (Some(real)
                .is_some_and(|s| matches!(parent_start_time(u32::MAX), Some(cur) if cur != s)));
        assert!(
            !owner_gone,
            "a failed start-time read (None) must degrade to liveness-only, not read as a recycle"
        );
        // Sanity: the probe really did fail (returned None) for u32::MAX.
        assert!(parent_start_time(u32::MAX).is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn resolve_owner_start_prefers_stamped_token() {
        // The harness-stamped owner incarnation token must win over a child-side
        // `owner_start_time` read, closing the PID-reuse race where the harness
        // dies during startup and the owner pid is recycled before the child
        // reads it (issue #54 review r4239955518). Our own live start time is a
        // stand-in for "what the child would discover"; a forged token distinct
        // from it proves the stamped value is used verbatim, not the discovered
        // one.
        let me = std::process::id();
        let discovered = owner_start_time(me).expect("own start time readable");
        let stamped = discovered.wrapping_add(1);
        assert_eq!(
            resolve_owner_start(Some(stamped), me),
            Some(stamped),
            "a harness-stamped token must be preferred verbatim over child-side discovery"
        );
        // With no stamped token, it falls back to child-side discovery.
        assert_eq!(
            resolve_owner_start(None, me),
            Some(discovered),
            "without a stamped token, fall back to child-side discovery"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owner_start_time_reads_own_incarnation() {
        // The macOS owner-PID-reuse token comes from `proc_pidinfo` (via
        // `leader_identity`), not `/proc`. Our own process is alive, so its
        // start time must be readable and stable across reads — the value the
        // daemon captures at arm and hands to the watchdog so a recycled owner
        // pid (still answering `kill(_, 0)`) is detected as owner death. This
        // is the regression test for the review finding that macOS previously
        // returned `None` here, disabling owner-incarnation checking on the very
        // platform the fleet failure occurred on.
        let me = std::process::id();
        let a = owner_start_time(me).expect("own start time readable");
        let b = owner_start_time(me).expect("own start time readable");
        assert_eq!(a, b);
        assert!(a > 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owner_recycle_is_detected_as_a_start_time_mismatch() {
        // The comparison the owner watchdog makes each poll: a live process whose
        // start time differs from the token captured at arm is a *recycled* pid,
        // not the original owner — treat it as owner death. Model the recycle by
        // comparing our own live process against a forged token; the mismatch
        // must read as "owner gone".
        let me = std::process::id();
        let real = owner_start_time(me).expect("own start time readable");
        let forged = real.wrapping_add(1);
        // Mirror the watchdog's `owner_gone` expression (post issue #54 review):
        // only a SUCCESSFULLY READ, different token proves a recycle.
        let owner_gone = !pid_alive(me)
            || (Some(forged)
                .is_some_and(|s| matches!(owner_start_time(me), Some(cur) if cur != s)));
        assert!(
            owner_gone,
            "a start-time mismatch on a live pid must read as owner death (recycled pid)"
        );
        // And the matching token must NOT read as owner death.
        let owner_gone_ok = !pid_alive(me)
            || (Some(real).is_some_and(|s| matches!(owner_start_time(me), Some(cur) if cur != s)));
        assert!(
            !owner_gone_ok,
            "the matching token must not read as owner death"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owner_read_failure_is_not_a_recycle() {
        // Regression (issue #54 review): a FAILED start-time read returns `None`,
        // and `None != Some(token)` must NOT read as owner death — otherwise a
        // transient `proc_pidinfo` failure SIGKILLs a daemon whose owner is still
        // alive. Model the read failure with an unreadable pid (`u32::MAX`) while
        // the captured token is real: the expression must degrade to liveness-only.
        let me = std::process::id();
        let real = owner_start_time(me).expect("own start time readable");
        let owner_gone = !pid_alive(me)
            || (Some(real)
                .is_some_and(|s| matches!(owner_start_time(u32::MAX), Some(cur) if cur != s)));
        assert!(
            !owner_gone,
            "a failed start-time read (None) must degrade to liveness-only, not read as a recycle"
        );
        // Sanity: the probe really did fail (returned None) for u32::MAX.
        assert!(owner_start_time(u32::MAX).is_none());
    }

    /// Regression (issue #54 review): the owner watchdog must be spawned into
    /// its OWN process group, not left in the daemon's (the test runner's /
    /// shell's foreground) group. The daemon is not its own group leader, so a
    /// terminal Ctrl-C fans SIGINT out to the whole foreground group — and a
    /// watchdog that shares it would die before reaping the orphaned daemon,
    /// defeating the fallback exactly when it is needed. `spawn_owner_watchdog`
    /// therefore sets `process_group(0)`.
    ///
    /// This test cannot observe that on the watchdog child itself: the watchdog
    /// re-execs `current_exe()`, which under `cargo test` is the libtest binary.
    /// It does not dispatch `__owner-watchdog` and exits at once (exactly as the
    /// `spawn_watchdog` reaping test above documents), so reading the spawned
    /// child's pgid would race its exit/reaper thread and intermittently see
    /// `ESRCH` (issue #54 review, the "Previously missed" advisory). Instead we (1) assert
    /// `spawn_owner_watchdog` spawns successfully, exercising the real spawn path
    /// (env scrub, args, `process_group(0)`), and (2) verify the group-leadership
    /// MECHANISM it relies on against a deterministically long-lived child we
    /// fully own: a child launched with `process_group(0)` must lead its own
    /// group (pgid == pid) and must not share ours.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn owner_watchdog_leads_its_own_process_group() {
        // (1) The real spawn path must succeed. The background reaper the spawn
        // installs cleans up the short-lived child; we deliberately do not read
        // its pgid (see the doc comment — that read is racy).
        let home = std::env::temp_dir().join(format!(
            "nano-owner-wd-pgid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&home).expect("create temp home");
        assert!(
            spawn_owner_watchdog(std::process::id(), home.clone()).is_some(),
            "spawn_owner_watchdog must spawn the watchdog child"
        );
        let _ = std::fs::remove_dir_all(&home);

        // (2) The group-leadership mechanism, verified deterministically against a
        // known long-lived child. `sleep` is present on both targets this test
        // runs on. We fully own this child's lifecycle, so there is no reaper race
        // and the raw SIGKILL below can never hit a recycled pid (we waitpid it
        // ourselves before it could be reused).
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn long-lived child");
        let pid = child.id();
        // SAFETY: a single async-signal-safe libc call reading the live child's
        // group by pid; the child is alive (it is `sleep 30`) and unreaped.
        let child_pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        assert!(
            child_pgid >= 0,
            "getpgid(child) must succeed for the live child"
        );
        // SAFETY: reading our own group.
        let our_pgid = unsafe { libc::getpgid(0) };
        assert_eq!(
            child_pgid as u32, pid,
            "a process_group(0) child must lead its own group (pgid == pid)"
        );
        assert_ne!(
            child_pgid as u32, our_pgid as u32,
            "the child must not share the daemon/test group"
        );
        // Cleanup: kill and reap the child we own (no recycle risk — see above).
        // SAFETY: signalling a live child we just spawned and still hold.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    /// A failed owner-watchdog arm must FAIL startup on a platform that has a
    /// watchdog (issue #54 review r4240360017): continuing without the one reaper
    /// that survives an owner SIGKILL would leave the daemon/worker orphanable,
    /// since `Drop` cannot run on a SIGKILL and the startup sweep has no pid or
    /// socket to stop it. A successful arm proceeds. The unsupported-platform
    /// no-op (where `spawn_owner_watchdog` always returns `None` by design) is
    /// covered by `OWNER_WATCHDOG_SUPPORTED`; the test suite only runs on
    /// supported platforms, where that flag is `true`.
    #[test]
    fn failed_owner_watchdog_arm_fails_startup() {
        assert!(
            arm_outcome(None).is_err(),
            "a failed arm on a supported platform must abort startup"
        );
        assert!(
            arm_outcome(Some(4321)).is_ok(),
            "a successful arm must let startup proceed"
        );
    }

    #[test]
    fn leader_identity_reads_own_incarnation() {
        // Our own process is alive, so its identity (start time + uid) must be
        // readable and stable across reads — this is the token `PgidGuard`
        // captures at spawn and re-verifies before a cleanup SIGKILL.
        let me = std::process::id();
        let a = leader_identity(me).expect("own identity readable");
        let b = leader_identity(me).expect("own identity readable");
        assert_eq!(a, b);
        assert!(a.start > 0);
        assert_eq!(a.uid, unsafe { libc::getuid() });
    }

    #[test]
    fn leader_identity_none_for_nonexistent_pid() {
        assert!(leader_identity(u32::MAX).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn assemble_identity_rejects_recycle_straddling_snapshot() {
        use std::cell::Cell;
        // A reap+recycle between the two `/proc` reads moves the start tick, so
        // the second start read disagrees with the first: the mixed
        // (original-start, replacement-uid) token must be rejected rather than
        // returned as a false match that would signal the unrelated group (#27).
        // Crucially it must come back as `Changed` — a *detected* recycle — not
        // `Absent`, so the verification callers fail closed instead of open.
        let reads = Cell::new(0u32);
        let straddled = assemble_identity(
            || {
                let n = reads.get();
                reads.set(n + 1);
                // First read: original incarnation's tick; second: recycled tick.
                Some(if n == 0 { 100 } else { 200 })
            },
            || Some(1000),
        );
        assert_eq!(
            straddled,
            LeaderProbe::Changed,
            "a moved start tick is a detected recycle, not an absent leader"
        );

        // A start tick that is stable across both reads yields the assembled
        // token — the common, non-racing case.
        let stable = assemble_identity(|| Some(100), || Some(7));
        assert_eq!(
            stable,
            LeaderProbe::Present(GroupIdentity { start: 100, uid: 7 })
        );

        // An unreadable second start read (leader gone, no recycle) reports
        // `Absent` — the accepted fail-open case — rather than `Changed`.
        let reads2 = Cell::new(0u32);
        let vanished = assemble_identity(
            || {
                let n = reads2.get();
                reads2.set(n + 1);
                if n == 0 {
                    Some(100)
                } else {
                    None
                }
            },
            || Some(7),
        );
        assert_eq!(
            vanished,
            LeaderProbe::Absent,
            "a vanished leader (no replacement) is the fail-open case"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_incarnation_fails_closed_not_open() {
        // Regression test for the review finding: a *detected* incarnation
        // change (the bracketed read sees the start tick move) must fail
        // **closed** at both verification callers, not collapse into the
        // fail-open "leader was reaped" case. Before the fix the probe returned
        // a bare `None` for both, so `Absent` and `Changed` were
        // indistinguishable and the recycled replacement group was signalled.
        use std::cell::Cell;

        // The probe distinguishes the cases at the source.
        let reads = Cell::new(0u32);
        let probe = assemble_identity(
            || {
                let n = reads.get();
                reads.set(n + 1);
                Some(if n == 0 { 100 } else { 200 })
            },
            || Some(1000),
        );
        assert_eq!(probe, LeaderProbe::Changed);

        // And both verification sites map `Changed` to fail-closed (`false`)
        // while mapping `Absent` to fail-open (`true`). Mirror their match arms
        // against a captured identity so a future edit that re-collapses the
        // two cases trips this test.
        let captured = GroupIdentity {
            start: 100,
            uid: 1000,
        };
        let verdict = |p: LeaderProbe| match p {
            LeaderProbe::Present(cur) => cur == captured,
            LeaderProbe::Absent => true,
            LeaderProbe::Changed => false,
        };
        assert!(
            !verdict(LeaderProbe::Changed),
            "a detected incarnation change must fail closed"
        );
        assert!(
            verdict(LeaderProbe::Absent),
            "a genuinely absent leader must fail open"
        );
        assert!(
            !verdict(LeaderProbe::Present(GroupIdentity {
                start: 200,
                uid: 1000
            })),
            "a live but different identity must fail closed"
        );
        assert!(
            verdict(LeaderProbe::Present(captured)),
            "a live matching identity must pass"
        );
    }

    /// Spawn a child in its own process group that sleeps, return (child, pgid).
    fn spawn_group_leader() -> (std::process::Child, u32) {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        // Own process group: pid == pgid, mirroring the agent launch.
        cmd.process_group(0);
        let child = cmd.spawn().expect("spawn sleep");
        let pgid = child.id();
        (child, pgid)
    }

    #[test]
    fn pgid_guard_matches_live_group() {
        let (mut child, pgid) = spawn_group_leader();
        let guard = PgidGuard::capture(pgid);
        assert!(
            guard.identity.is_some(),
            "identity must be captured for a live leader"
        );
        assert!(guard.still_ours(), "a live group must verify as ours");
        // Cleanup.
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn pgid_guard_refuses_after_group_exit() {
        let (mut child, pgid) = spawn_group_leader();
        let guard = PgidGuard::capture(pgid);
        assert!(guard.still_ours());
        // Kill the whole group and reap the leader so the pgid is freed.
        let _ = child.kill();
        let _ = child.wait();
        // Once the group is gone the numeric probe fails, so still_ours is false.
        // (If the pgid were recycled by an unrelated group whose leader is *live*,
        // the identity mismatch — not just liveness — is what would refuse; that
        // path is pinned by `pgid_guard_refuses_a_recycled_identity` below. A
        // recycled group whose leader was *also* reaped is the accepted fail-open
        // window, pinned by `pgid_guard_fails_open_on_reaped_leader`.)
        assert!(!guard.still_ours(), "a gone group must not verify as ours");
    }

    #[test]
    fn pgid_guard_refuses_a_recycled_identity() {
        // Simulate the recycled-PGID race without needing to actually recycle a
        // pid: capture a guard for a live group, then forge a *different*
        // identity (wrong start time) and confirm `group_identity_matches`
        // refuses it even though the group is alive. This is the exact check
        // that stops a cleanup SIGKILL from hitting an unrelated group that
        // recycled the pgid.
        let (mut child, pgid) = spawn_group_leader();
        let real = leader_identity(pgid).expect("live leader identity");
        // A recycled leader has a different start time (and possibly uid).
        let recycled = GroupIdentity {
            start: real.start.wrapping_add(1),
            uid: real.uid,
        };
        assert!(
            !group_identity_matches(pgid, Some(recycled)),
            "a mismatched start time must refuse the kill even while the group is alive"
        );
        // A wrong uid must also refuse.
        let wrong_uid = GroupIdentity {
            start: real.start,
            uid: real.uid.wrapping_add(1),
        };
        assert!(
            !group_identity_matches(pgid, Some(wrong_uid)),
            "a mismatched uid must refuse the kill even while the group is alive"
        );
        // And the correct identity still passes.
        assert!(group_identity_matches(pgid, Some(real)));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn group_identity_matches_degrades_to_liveness_without_identity() {
        // With no captured identity (None) the check falls back to the numeric
        // liveness probe — the pre-#27 behaviour — so cleanup still works on
        // platforms without an identity source.
        let (mut child, pgid) = spawn_group_leader();
        assert!(group_identity_matches(pgid, None));
        let _ = child.kill();
        let _ = child.wait();
        assert!(!group_identity_matches(pgid, None));
    }

    /// Spawn a `sleep` in the *same* process group as an existing leader, so it
    /// survives as a descendant once that leader is reaped.
    fn spawn_group_member(pgid: u32) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        // Join the leader's group (pgid), rather than starting our own.
        cmd.process_group(pgid as i32);
        cmd.spawn().expect("spawn group member")
    }

    #[test]
    fn pgid_guard_fails_open_on_reaped_leader() {
        // The review-finding scenario: the leader exits and is reaped while a
        // `TERM`-resistant descendant keeps the group (and pgid) alive. The
        // leader's identity source then reads `None`, and the guard must fail
        // *open* — returning true so the cleanup SIGKILL is *not* skipped and the
        // orphaned descendant is reaped. (The earlier strict-equality check
        // returned false here and leaked the descendant.)
        let (mut leader, pgid) = spawn_group_leader();
        let guard = PgidGuard::capture(pgid);
        assert!(
            guard.identity.is_some(),
            "identity captured for live leader"
        );
        let mut member = spawn_group_member(pgid);

        // Kill and reap the leader; the descendant keeps the group alive.
        let _ = leader.kill();
        let _ = leader.wait();
        // Sanity: the leader's identity really is unreadable now (group alive,
        // leader gone) — this is the `None` branch the policy keys on.
        assert!(group_alive(pgid), "descendant keeps the group alive");
        assert!(
            leader_identity(pgid).is_none(),
            "a reaped leader's identity is gone even though the group lives"
        );

        assert!(
            guard.still_ours(),
            "a reaped leader with a surviving descendant must fail open so the \
             orphaned descendant is still reaped"
        );
        assert!(
            group_identity_matches(pgid, guard.identity),
            "group_identity_matches must fail open identically"
        );

        // Cleanup: kill the surviving descendant.
        let _ = member.kill();
        let _ = member.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classify_proc_stat_only_process_gone_counts_as_absent() {
        use std::io::ErrorKind;
        // A process-gone race is the *only* read error that proves absence.
        assert_eq!(
            classify_proc_stat(Err(ErrorKind::NotFound), 1234),
            MemberVerdict::Skip,
            "a vanished /proc entry is a clean exit race"
        );
        // Every other inspection failure must keep the grace loop open (Unknown),
        // never be silently dropped as absence — otherwise a transiently
        // unreadable but still-live member would bypass the grace period.
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
            ErrorKind::Interrupted,
            ErrorKind::InvalidData,
        ] {
            assert_eq!(
                classify_proc_stat(Err(kind), 1234),
                MemberVerdict::Unknown,
                "inspection failure {kind:?} must fail safe, not read as absent"
            );
        }
        // A readable, non-zombie member of the group is detected.
        assert_eq!(
            classify_proc_stat(Ok(b"999 (wo rk) R 1 1234 1234 0 -1"), 1234),
            MemberVerdict::LiveMember,
            "a live member of the target pgid counts"
        );
        // A zombie of the group is not a live member.
        assert_eq!(
            classify_proc_stat(Ok(b"999 (wo rk) Z 1 1234 1234 0 -1"), 1234),
            MemberVerdict::Skip,
            "a zombie of the group is not a live member"
        );
        // A live process in a different group is skipped.
        assert_eq!(
            classify_proc_stat(Ok(b"999 (wo rk) R 1 5678 5678 0 -1"), 1234),
            MemberVerdict::Skip,
            "a live process in another group does not count"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classify_proc_stat_tolerates_non_utf8_comm() {
        // A process can set an arbitrary non-UTF-8 byte sequence as its `comm`
        // (field 2). The scan must still parse the ASCII state/pgrp suffix after
        // the final ')' — a `read_to_string` would fail the whole scan with
        // `InvalidData` and restore the full grace delay on every clean shutdown.
        // 0xFF and 0x80 are not valid UTF-8.
        let stat = b"999 (\xFF\x80 bad name) R 1 1234 1234 0 -1";
        assert_eq!(
            classify_proc_stat(Ok(stat), 1234),
            MemberVerdict::LiveMember,
            "a non-UTF-8 comm must not defeat parsing of the ASCII suffix"
        );
        // Same, but a zombie in the target group.
        let stat = b"999 (\xFF\x80 bad name) Z 1 1234 1234 0 -1";
        assert_eq!(
            classify_proc_stat(Ok(stat), 1234),
            MemberVerdict::Skip,
            "a non-UTF-8 zombie of the group is still not a live member"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pid_liveness_reports_self_live() {
        // Our own process is a live, non-zombie member — the one deterministic
        // anchor for the macOS per-member probe. (The zombie -> `Some(false)`
        // path is covered by `group_has_live_member_false_for_held_zombie_anchor`.)
        assert_eq!(
            pid_liveness(std::process::id()),
            Some(true),
            "the running test process must read as a live member"
        );
    }

    #[test]
    fn group_has_live_member_true_for_live_group() {
        // A live leader is itself a non-zombie member, so the grace loop must not
        // treat the group as drained while it is still running.
        let (mut child, pgid) = spawn_group_leader();
        assert!(
            group_has_live_member(pgid),
            "a live leader must count as a live member"
        );
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            !group_has_live_member(pgid),
            "a reaped, empty group has no live member"
        );
    }

    #[test]
    fn group_has_live_member_sees_descendant_after_leader_reaped() {
        // A `TERM`-resistant descendant that outlives a reaped leader must still
        // be reported as a live member, so the grace loop keeps waiting (and
        // ultimately SIGKILLs) rather than breaking early and leaking it.
        let (mut leader, pgid) = spawn_group_leader();
        let mut member = spawn_group_member(pgid);
        let _ = leader.kill();
        let _ = leader.wait();
        assert!(group_alive(pgid), "the descendant keeps the group alive");
        assert!(
            group_has_live_member(pgid),
            "a live descendant counts as a live member even after the leader is reaped"
        );
        let _ = member.kill();
        let _ = member.wait();
    }

    #[test]
    fn group_has_live_member_false_for_held_zombie_anchor() {
        // The exact #50 scenario: the leader has exited but is held UNREAPED as
        // the identity anchor, with no other member. `group_alive` still reads the
        // group as live (the zombie holds the pgid), but there is no *non-zombie*
        // member — so `group_has_live_member` must report `false`, letting the
        // grace loop break immediately instead of waiting out the full grace.
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("sleep")
            .arg("0")
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn fast-exiting leader");
        let pgid = child.id();
        // Wait for the leader to exit and linger as an unreaped zombie (we never
        // call `wait` until the assertion below has run).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && group_has_live_member(pgid) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            !group_has_live_member(pgid),
            "a held leader zombie with no live member must not count as a live member"
        );
        // Now reap the zombie we deliberately held.
        let _ = child.wait();
    }

    #[tokio::test]
    async fn terminate_breaks_grace_early_on_clean_exit() {
        // A leader that exits promptly on SIGTERM must not hold the grace loop for
        // the full `grace`: the live-member fast path breaks as soon as the group
        // has drained to the held zombie anchor (issue #50). `sleep` terminates on
        // SIGTERM by default, so the group empties well within the generous grace
        // below — the elapsed time proves the early break, not a timeout.
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("30").process_group(0).kill_on_drop(true);
        let mut child = cmd.spawn().expect("spawn leader");
        let pgid = child.id().expect("leader pid");
        let guard = PgidGuard::capture(pgid);
        let grace = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();
        terminate_group_and_reap(&mut child, Some(guard), grace).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "a clean SIGTERM exit must break the grace loop early rather than wait \
             out the {grace:?} grace (took {elapsed:?})"
        );
    }

    #[tokio::test]
    async fn terminate_reaps_a_term_resistant_member() {
        // The class the fast-path SIGKILL guards (review r4266146398): a
        // `TERM`-resistant descendant must NEVER survive teardown, whichever path
        // the grace loop takes. `group_has_live_member` is best-effort and fails
        // open, so a missed live member would break the fast path early; the
        // identity-gated group SIGKILL (fast path *and* deadline) is what keeps a
        // false negative harmless. Here the member ignores SIGTERM, so the group
        // SIGKILL — not SIGTERM — is the only thing that can reap it. After
        // `terminate_group_and_reap` returns, nothing in the group may be alive.
        let mut leader_cmd = tokio::process::Command::new("sh");
        leader_cmd
            .arg("-c")
            // Leader exits on SIGTERM; it is held unreaped as the identity anchor.
            .arg("exec sleep 30")
            .process_group(0)
            .kill_on_drop(true);
        let mut child = leader_cmd.spawn().expect("spawn leader");
        let pgid = child.id().expect("leader pid");

        // A descendant in the leader's group that blocks SIGTERM: only SIGKILL
        // can reap it.
        use std::os::unix::process::CommandExt;
        // The member signals readiness (by creating this file) only *after* it
        // has installed its SIGTERM trap, so teardown never races the trap
        // install. A fixed sleep would be scheduling-dependent: on a loaded
        // runner the shell may not have run `trap` yet, and teardown's SIGTERM
        // would then kill the member before it becomes TERM-resistant, making
        // the test pass for the wrong reason (or fail nondeterministically).
        let ready_file =
            std::env::temp_dir().join(format!("nano-pdeath-ready-{}-{}", std::process::id(), pgid));
        let _ = std::fs::remove_file(&ready_file);
        let mut member_cmd = std::process::Command::new("sh");
        member_cmd
            .arg("-c")
            .arg(format!(
                "trap '' TERM; : > \"{}\"; sleep 30",
                ready_file.display()
            ))
            .process_group(pgid as i32)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut member = member_cmd.spawn().expect("spawn TERM-resistant member");
        // Wait until the member has installed its SIGTERM trap (readiness file)
        // before teardown, instead of a fixed sleep.
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready_file.exists() {
            assert!(
                std::time::Instant::now() < ready_deadline,
                "the TERM-resistant member never signalled SIGTERM-handler readiness"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(&ready_file);

        let guard = PgidGuard::capture(pgid);
        let grace = std::time::Duration::from_secs(2);
        terminate_group_and_reap(&mut child, Some(guard), grace).await;

        // The group SIGKILL must have reaped the resistant member. It ignores
        // SIGTERM and sleeps 30s, so the only way it can have exited inside this
        // window is the teardown's SIGKILL. `try_wait` reports its real exit
        // (a bare `kill(pid,0)` can't: a SIGKILLed-but-unreaped member lingers as
        // a zombie that still answers the liveness probe).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut status = None;
        while std::time::Instant::now() < deadline {
            match member.try_wait() {
                Ok(Some(s)) => {
                    status = Some(s);
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        // Reap the member so the test leaves no zombie, regardless of outcome.
        let _ = member.kill();
        let _ = member.wait();
        let status = status
            .expect("a TERM-resistant group member must be SIGKILLed by teardown, not leaked");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the resistant member must be reaped by the group SIGKILL, got {status:?}"
        );
    }

    #[test]
    fn pgid_guard_fails_closed_on_live_leader_mismatch() {
        // The other half of the policy: while the leader is *live*, a captured
        // identity that does not match it is a definite recycle — fail *closed*
        // (do not signal), even though the group is alive. This guards the
        // recycled-PGID race #27 cares about.
        let (mut child, pgid) = spawn_group_leader();
        let real = leader_identity(pgid).expect("live leader identity");
        // A guard whose captured identity belongs to a *different* incarnation.
        let stale = PgidGuard {
            pgid,
            identity: Some(GroupIdentity {
                start: real.start.wrapping_add(1),
                uid: real.uid,
            }),
        };
        assert!(
            !stale.still_ours(),
            "a live leader with a mismatched identity must fail closed"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn pid_identity_matches_reaps_a_non_group_leader() {
        // The owner-watchdog scenario (issue #54 review): the supervised daemon
        // is NOT its own process-group leader — it inherits the invoking test's
        // group (no `setsid`/`setpgid`), unlike an agent spawned with
        // `process_group(0)`. So its pid does not name a process group, and the
        // group-based check (`group_alive` → `kill(-pid, 0)`) wrongly reports it
        // gone and skips the reap. The pid-based check must verify it as ours.
        let (mut leader, pgid) = spawn_group_leader();
        let mut member = spawn_group_member(pgid);
        let member_pid = member.id();
        assert_ne!(
            member_pid, pgid,
            "the member shares the leader's group, so its pid is not a pgid"
        );
        let id = leader_identity(member_pid).expect("live member identity");
        // The bug: a group probe of a non-leader pid finds no group and fails.
        assert!(
            !group_identity_matches(member_pid, Some(id)),
            "group_identity_matches wrongly reports a live non-leader pid as gone"
        );
        // The fix: the pid probe verifies the live incarnation, so the reap fires.
        assert!(
            pid_identity_matches(member_pid, Some(id)),
            "pid_identity_matches must verify a live non-leader pid as ours"
        );
        let _ = member.kill();
        let _ = member.wait();
        let _ = leader.kill();
        let _ = leader.wait();
    }

    #[test]
    fn pid_identity_matches_refuses_recycle_and_degrades_without_token() {
        // The pid-level analogue of `pgid_guard_refuses_a_recycled_identity`: a
        // live pid whose captured start/uid no longer matches is a recycled pid —
        // fail closed. With no token the check degrades to the liveness probe.
        let (mut child, pid) = spawn_group_leader();
        let real = leader_identity(pid).expect("live identity");
        let recycled = GroupIdentity {
            start: real.start.wrapping_add(1),
            uid: real.uid,
        };
        assert!(
            !pid_identity_matches(pid, Some(recycled)),
            "a mismatched start time must refuse the kill on a live pid"
        );
        let wrong_uid = GroupIdentity {
            start: real.start,
            uid: real.uid.wrapping_add(1),
        };
        assert!(
            !pid_identity_matches(pid, Some(wrong_uid)),
            "a mismatched uid must refuse the kill on a live pid"
        );
        assert!(
            pid_identity_matches(pid, Some(real)),
            "the matching identity passes"
        );
        assert!(
            pid_identity_matches(pid, None),
            "no token degrades to the numeric liveness probe"
        );
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            !pid_identity_matches(pid, None),
            "a dead pid fails the liveness probe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn checked_pid_rejects_wrap_and_zero() {
        // `pid_t` is a signed 32-bit int, so a `u32` above `i32::MAX` wraps
        // negative under `as` — and `kill(2)` reads `-1` as "broadcast to every
        // process I may signal" (issue #54 review). The conversion must reject
        // those values before any `kill` call.
        assert_eq!(checked_pid(1), Some(1));
        assert_eq!(checked_pid(i32::MAX as u32), Some(i32::MAX));
        assert_eq!(checked_pid(0), None, "pid 0 names this process's group");
        assert_eq!(
            checked_pid(u32::MAX),
            None,
            "u32::MAX would wrap to -1 => kill(-1) broadcast"
        );
        assert_eq!(
            checked_pid((i32::MAX as u32) + 1),
            None,
            "i32::MAX+1 wraps to i32::MIN (a process-group target)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn out_of_range_pid_is_never_probed_or_signalled() {
        // The watchdog's `--self-pid` is an unrestricted `u32`. An out-of-range
        // value must read as "not ours" (never "alive") and must never reach
        // `kill` — otherwise `u32::MAX` becomes `kill(-1, …)`, a broadcast.
        assert!(
            !pid_alive(u32::MAX),
            "an out-of-range pid must not be probed as alive (would broadcast)"
        );
        assert!(!pid_alive(0), "pid 0 must not be probed as alive");
        // `sigkill_pid` on an out-of-range pid is a no-op (returns before any
        // `kill`); this must not panic or broadcast. We cannot observe the
        // absence of a signal directly, but the function returning at all — with
        // the process still alive to continue the test — is the regression guard.
        sigkill_pid(u32::MAX);
        sigkill_pid(0);
        // A real, in-range pid still works: our own process is alive.
        assert!(pid_alive(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn write_marker_atomic_leaves_a_complete_marker() {
        // The atomic write (temp + rename) must leave a complete, parseable
        // marker — never a truncated intermediate a concurrent sweep could
        // misread as "no owner" (issue #54 review).
        let dir = std::env::temp_dir().join(format!(
            "nano-marker-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create temp marker dir");
        let marker = dir.join("ct-owner.pid");
        write_marker_atomic(&marker, "1234 5678");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "1234 5678");
        // Overwriting an existing marker atomically replaces it wholesale.
        write_marker_atomic(&marker, "4321 8765");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "4321 8765");
        // The temp file must not linger after the rename.
        assert!(
            !dir.join("ct-owner.pid.tmp").exists(),
            "the temp file is renamed away, not left behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spawn_time_guard_beats_cleanup_time_recapture() {
        // The cleanup-time-recapture bug (review finding): a guard captured at
        // *cleanup* reads whatever group currently holds the pgid, so if the
        // leader was reaped and the pgid recycled, it blesses the unrelated
        // group. A guard captured at *spawn* still holds the original identity
        // and refuses the recycled group. This pins why `terminate_group_and_reap`
        // takes the spawn-time guard rather than capturing one itself.
        let (mut child, pgid) = spawn_group_leader();
        let spawn_guard = PgidGuard::capture(pgid);
        let spawn_identity = spawn_guard.identity.expect("identity captured at spawn");

        // A cleanup-time capture reads the *current* leader's identity. While
        // the group is un-recycled that equals the spawn identity…
        let cleanup_capture = PgidGuard::capture(pgid);
        assert_eq!(
            cleanup_capture.identity,
            Some(spawn_identity),
            "before any recycle, a cleanup-time capture matches the spawn capture"
        );

        // …but once the pgid is recycled the current leader presents a *new*
        // identity, which a cleanup-time capture would record and then match —
        // blessing the unrelated group. The spawn-time guard still holds the
        // original identity and refuses. Model the recycle as a leader whose
        // start time differs from the spawn capture (what a reused pgid shows):
        let recycled = GroupIdentity {
            start: spawn_identity.start.wrapping_add(1),
            uid: spawn_identity.uid,
        };
        assert!(
            !group_identity_matches(pgid, Some(recycled)),
            "the spawn-time identity must refuse a recycled group even while it is alive"
        );
        // Had we instead recaptured at cleanup we would hold `recycled` and the
        // same check would have passed — the bug. The spawn-time guard is the
        // only capture that stays pinned to the original group.
        assert!(
            group_identity_matches(pgid, spawn_guard.identity),
            "the spawn-time guard still matches its own (un-recycled) group"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bind_self_to_parent_death_arms_for_a_live_parent() {
        // The attached-mode binding must install cleanly for a live invoking
        // parent (the prctl succeeds and the getppid re-check passes), and the
        // disposition must actually be queryable afterwards.
        bind_self_to_parent_death().expect("binding must arm for a live parent");
        // SAFETY: PR_GET_PDEATHSIG only reads this process's disposition.
        let mut sig: libc::c_int = 0;
        let rc = unsafe {
            libc::prctl(
                libc::PR_GET_PDEATHSIG,
                &mut sig as *mut libc::c_int as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        assert_eq!(rc, 0, "PR_GET_PDEATHSIG failed");
        assert_eq!(sig, libc::SIGKILL, "the binding must arm SIGKILL");
    }
}
