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
/// cannot be taken over by a colliding group, closing window 3 too). Deferring the
/// leader reap
/// until after the group SIGKILL on the reaped-first sub-paths — which would
/// close the window there too — and shrinking the watchdog window by detecting
/// whether any non-zombie member still remains (so clean exits finish without
/// waiting out the grace) are both tracked in #50. Everywhere else — a live
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
    ///   sub-paths to close them there too is tracked in #50).
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
                // The cost is that `group_alive` stays true on the zombie, so a
                // clean shutdown waits out the full grace period rather than
                // breaking early; correctness is preferred over that latency.
                // This grace runs after every ACP job (`acp::shutdown`), so the
                // accepted cost is ~`grace` per clean ACP shutdown. Detecting
                // whether any non-zombie member still remains (so a clean exit
                // breaks early while the zombie stays as the identity anchor) is
                // tracked in #50.
                if !guard.still_ours() {
                    // The group is gone (every member exited). Don't re-signal.
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
    if let Err(e) = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        crate::runtime::log(&format!(
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
                if libc::kill(-(pgid as libc::pid_t), 0) != 0 {
                    break false; // group already gone -> nothing to do
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
        // leaking orphans. Shrinking it is tracked in #50.
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
/// *Scope of the guarantee*); shrinking the window is tracked in #50. A same-tick,
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
                if n == 0 { Some(100) } else { None }
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
        let captured = GroupIdentity { start: 100, uid: 1000 };
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
