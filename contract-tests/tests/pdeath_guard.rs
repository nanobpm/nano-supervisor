//! #27 — recycled-PGID race: a cleanup `SIGKILL` must never hit an unrelated
//! process group that recycled the agent's pgid.
//!
//! The daemon arms a parent-death watchdog (`__reap-watchdog`) for every agent
//! and passes it the agent group's **identity** (the leader's start time + real
//! uid, captured at spawn) via `--pgid-start`/`--pgid-uid`. Before the watchdog
//! `SIGKILL`s the group it re-verifies that identity, so a pgid that was freed
//! and recycled by an unrelated group is never signalled.
//!
//! These tests are **engine-free** and drive the real binary's hidden
//! `__reap-watchdog` subcommand directly, so they run in any environment. They
//! are **Rust-pinned**: the identity token and its verification are the Rust
//! port's hardening (the Node plugin's cleanup is the predecessor this guards),
//! so they skip on the Node target and the rest of the suite keeps both targets
//! green.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use contract_tests::{skip, Target};

/// The Rust binary under test (`$NS_BIN`, default `target/debug/nano-supervisor`).
fn bin() -> String {
    std::env::var("NS_BIN").unwrap_or_else(|_| "target/debug/nano-supervisor".to_string())
}

/// Read a process's start time (field 22 of `/proc/<pid>/stat`) and real uid,
/// the same identity token the daemon captures. Linux-only helper.
#[cfg(target_os = "linux")]
fn proc_identity(pid: u32) -> Option<(u64, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let start: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((start, uid))
}

/// Spawn a `sleep` in its own process group (pid == pgid), like an agent.
/// Returns (child, pgid). The child is killed+reaped on drop of the guard.
fn spawn_group() -> (std::process::Child, u32) {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("sleep");
    cmd.arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.process_group(0);
    let child = cmd.spawn().expect("spawn sleep group leader");
    let pgid = child.id();
    (child, pgid)
}

/// True while a process group with this pgid has a live member.
#[cfg(unix)]
fn group_alive(pgid: u32) -> bool {
    unsafe { libc::kill(-(pgid as libc::pid_t), 0) == 0 }
}

/// Wait up to `timeout` for `cond` to become true, polling every 25ms.
fn eventually<F: FnMut() -> bool>(timeout: Duration, mut cond: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    cond()
}

/// Run `__reap-watchdog` against a live agent group with a **forged** identity
/// (a wrong start time — exactly what a recycled pgid's new leader presents).
/// The watchdog must decline to signal the mismatched group: the innocent group
/// stays **alive**, and the watchdog keeps waiting on its (live) parent rather
/// than firing.
#[cfg(target_os = "linux")]
#[test]
fn watchdog_does_not_sigkill_a_recycled_pgid() {
    if Target::from_env() != Target::Rust {
        skip!("PGID-identity hardening is the Rust port's contract (issue #27)");
    }
    if !Target::Rust.available() {
        skip!("Rust binary not available (set NS_BIN)");
    }

    let (mut leader, pgid) = spawn_group();
    let (start, _uid) = proc_identity(pgid).expect("leader identity readable");
    // Forge a *recycled* identity: same pgid, but a start time that does not
    // match the real leader — what an unrelated group reusing the pgid presents.
    let forged_start = start.wrapping_add(1);
    let real_uid = unsafe { libc::getuid() };
    // The watchdog waits on this (the test process, alive for the whole test).
    let parent = std::process::id();

    let mut watchdog = Command::new(bin())
        .args([
            "__reap-watchdog",
            "--parent-pid",
            &parent.to_string(),
            "--pgid",
            &pgid.to_string(),
            "--pgid-start",
            &forged_start.to_string(),
            "--pgid-uid",
            &real_uid.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn watchdog");

    // Give the watchdog a moment to register and evaluate. It must NOT kill the
    // group (identity mismatch) and must keep waiting on the (live) parent.
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        group_alive(pgid),
        "the watchdog must not SIGKILL a group whose identity does not match \
         (a recycled pgid); the innocent group was killed"
    );
    assert!(
        watchdog.try_wait().expect("watchdog wait").is_none(),
        "the watchdog must keep waiting on the live parent, not exit after a mismatch"
    );

    // Cleanup: kill the watchdog and the group.
    let _ = watchdog.kill();
    let _ = watchdog.wait();
    let _ = leader.kill();
    let _ = leader.wait();
}

/// The positive control: with the **correct** identity, the watchdog reaps the
/// group once the parent is gone. Uses a short-lived "parent" (a child we kill)
/// so the watchdog fires, and asserts the agent group is torn down — proving the
/// identity gate does not disable legitimate cleanup.
#[cfg(target_os = "linux")]
#[test]
fn watchdog_reaps_the_group_with_the_correct_identity() {
    if Target::from_env() != Target::Rust {
        skip!("PGID-identity hardening is the Rust port's contract (issue #27)");
    }
    if !Target::Rust.available() {
        skip!("Rust binary not available (set NS_BIN)");
    }

    let (mut leader, pgid) = spawn_group();
    let (start, uid) = proc_identity(pgid).expect("leader identity readable");

    // A short-lived stand-in for the daemon: the watchdog waits on this pid and
    // reaps the group once it exits.
    let mut fake_parent = Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fake parent");
    let parent = fake_parent.id();

    let mut watchdog = Command::new(bin())
        .args([
            "__reap-watchdog",
            "--parent-pid",
            &parent.to_string(),
            "--pgid",
            &pgid.to_string(),
            "--parent-start",
            &proc_identity(parent)
                .map(|(s, _)| s.to_string())
                .unwrap_or_default(),
            "--pgid-start",
            &start.to_string(),
            "--pgid-uid",
            &uid.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watchdog");

    // Kill the fake daemon: the watchdog must now reap the (correctly
    // identified) agent group.
    let _ = fake_parent.kill();
    let _ = fake_parent.wait();

    // Poll for the group to go away. Reap the leader on every iteration: once
    // the watchdog SIGKILLs it, the leader is this process's zombie, and an
    // unreaped zombie still holds its pgid — so `kill(-pgid, 0)` would keep
    // answering "alive" until we collect it.
    let reaped = eventually(Duration::from_secs(5), || {
        let _ = leader.try_wait();
        !group_alive(pgid)
    });
    assert!(
        reaped,
        "with the correct identity the watchdog must SIGKILL the agent group \
         once the parent dies"
    );
    let _ = watchdog.wait();
    let _ = leader.kill();
    let _ = leader.wait();
}
