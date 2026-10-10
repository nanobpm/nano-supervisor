//! #54 — a killed contract-test run must not orphan its supervisor daemon.
//!
//! `Drop for TempHome` is the suite's normal daemon cleanup, but `Drop` does not
//! run when the test process dies without unwinding: a SIGKILL, a timeout kill,
//! Ctrl-C, or `panic=abort`. The fix ties each test daemon's lifetime to the
//! *owning test process* (`C8CTL_NANO_TEST_OWNER_PID`): a detached
//! `__owner-watchdog` reaps the daemon's process group the moment the owner is
//! gone (or its `C8CTL_NANO_HOME` disappears), so no daemon outlives its test.
//!
//! These tests are **engine-free** and drive the real binary's hidden
//! `__owner-watchdog` subcommand directly, exactly as `pdeath_guard.rs` drives
//! `__reap-watchdog`. They are **Rust-pinned** (the owner watchdog is the Rust
//! port's mechanism) and **unix-only** (the reaper signals a process group).

mod common;

#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use contract_tests::{skip, Target};

/// The Rust binary under test (`$NS_BIN`, default `target/debug/nano-supervisor`).
#[cfg(unix)]
fn bin() -> String {
    std::env::var("NS_BIN").unwrap_or_else(|_| "target/debug/nano-supervisor".to_string())
}

/// Spawn a long-lived stand-in for the daemon, in its OWN process group
/// (pid == pgid), the way the daemon runs. Returns (child, pid). The child is
/// killed+reaped by the caller on every path.
#[cfg(unix)]
fn spawn_daemon() -> (std::process::Child, u32) {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("sleep");
    cmd.arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.process_group(0);
    let child = cmd.spawn().expect("spawn daemon stand-in");
    let pid = child.id();
    (child, pid)
}

/// Spawn a short-lived stand-in for the owning test process. The watchdog waits
/// on this pid; killing it below is what trips the watchdog, exactly as a
/// SIGKILLed `cargo test` trips it in production.
#[cfg(unix)]
fn spawn_owner() -> (std::process::Child, u32) {
    let child = Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn owner stand-in");
    let pid = child.id();
    (child, pid)
}

/// True while `pid` names a live process.
#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Wait up to `timeout` for `cond`, polling every 25ms, reaping `reap` each pass
/// so a SIGKILLed child does not linger as a zombie that still answers `kill(_,0)`.
#[cfg(unix)]
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

/// The core regression: a daemon whose owning test process is SIGKILLed (no
/// unwinding, so `Drop` never runs) must be reaped by the owner watchdog. We
/// stand in for the daemon with a `sleep` in its own process group and for the
/// test with a short-lived child we SIGKILL; the watchdog must then SIGKILL the
/// daemon's group even though nothing unwound.
#[cfg(unix)]
#[test]
fn daemon_is_reaped_when_the_owning_test_is_killed() {
    if Target::from_env() != Target::Rust {
        skip!("the owner watchdog is the Rust port's mechanism (issue #54)");
    }
    if !Target::Rust.available() {
        skip!("Rust binary not available (set NS_BIN)");
    }

    let (mut daemon, daemon_pid) = spawn_daemon();
    let (mut owner, owner_pid) = spawn_owner();
    // A live home dir stands in for the test's `C8CTL_NANO_HOME`; the watchdog
    // also fires if it disappears, but here it stays put so only the owner-death
    // trip is exercised.
    let home = tempfile::tempdir().expect("temp home");

    let mut watchdog = Command::new(bin())
        .args([
            "__owner-watchdog",
            "--owner-pid",
            &owner_pid.to_string(),
            "--self-pid",
            &daemon_pid.to_string(),
            "--home",
            &home.path().to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn owner watchdog");

    // SIGKILL the owning test — no unwinding, no Drop. This is the leak case.
    unsafe { libc::kill(owner_pid as libc::pid_t, libc::SIGKILL) };
    let _ = owner.wait();

    // The watchdog must now reap the daemon's process group. Reap the daemon on
    // every poll: once SIGKILLed it is this process's zombie, and an unreaped
    // zombie still answers `kill(pid, 0)`, which would mask the kill.
    let reaped = eventually(Duration::from_secs(5), || {
        let _ = daemon.try_wait();
        !pid_alive(daemon_pid)
    });
    assert!(
        reaped,
        "the owner watchdog must SIGKILL the daemon once the owning test is gone"
    );
    let _ = watchdog.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();
}

/// The watchdog must also fire when the test's `C8CTL_NANO_HOME` disappears out
/// from under a still-live owner — the `TempDir`-removed case, which catches a
/// recycled owner pid the liveness probe alone would miss.
#[cfg(unix)]
#[test]
fn daemon_is_reaped_when_its_home_disappears() {
    if Target::from_env() != Target::Rust {
        skip!("the owner watchdog is the Rust port's mechanism (issue #54)");
    }
    if !Target::Rust.available() {
        skip!("Rust binary not available (set NS_BIN)");
    }

    let (mut daemon, daemon_pid) = spawn_daemon();
    // The owner stays ALIVE for the whole test; only the home is removed.
    let (mut owner, owner_pid) = spawn_owner();
    let home = tempfile::tempdir().expect("temp home");
    let home_path = home.path().to_path_buf();

    let mut watchdog = Command::new(bin())
        .args([
            "__owner-watchdog",
            "--owner-pid",
            &owner_pid.to_string(),
            "--self-pid",
            &daemon_pid.to_string(),
            "--home",
            &home_path.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn owner watchdog");

    // Remove the home from under the daemon (the TempDir cleanup path).
    std::fs::remove_dir_all(&home_path).expect("remove home");

    let reaped = eventually(Duration::from_secs(5), || {
        let _ = daemon.try_wait();
        !pid_alive(daemon_pid)
    });
    assert!(
        reaped,
        "the owner watchdog must SIGKILL the daemon once its home disappears"
    );
    let _ = watchdog.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = owner.kill();
    let _ = owner.wait();
}

/// The watchdog must NOT fire while the owner is alive and the home exists — a
/// live test's daemon is left alone. It exits on its own (without firing) once
/// the supervised daemon has terminated normally.
#[cfg(unix)]
#[test]
fn live_owner_daemon_is_left_alone() {
    if Target::from_env() != Target::Rust {
        skip!("the owner watchdog is the Rust port's mechanism (issue #54)");
    }
    if !Target::Rust.available() {
        skip!("Rust binary not available (set NS_BIN)");
    }

    let (mut daemon, daemon_pid) = spawn_daemon();
    let (mut owner, owner_pid) = spawn_owner();
    let home = tempfile::tempdir().expect("temp home");

    let mut watchdog = Command::new(bin())
        .args([
            "__owner-watchdog",
            "--owner-pid",
            &owner_pid.to_string(),
            "--self-pid",
            &daemon_pid.to_string(),
            "--home",
            &home.path().to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn owner watchdog");

    // Give the watchdog several poll intervals with a live owner + extant home:
    // the daemon must still be alive (the watchdog must not fire spuriously).
    std::thread::sleep(Duration::from_millis(800));
    assert!(
        pid_alive(daemon_pid),
        "the watchdog must not reap a daemon whose owner is alive and home exists"
    );

    // Now let the daemon exit normally: the watchdog should observe the
    // supervised pid gone and return WITHOUT having anything to reap.
    let _ = daemon.kill();
    let _ = daemon.wait();
    let exited = eventually(Duration::from_secs(5), || {
        matches!(watchdog.try_wait(), Ok(Some(_)))
    });
    assert!(
        exited,
        "the watchdog must exit once the supervised daemon is gone, not linger"
    );
    let _ = owner.kill();
    let _ = owner.wait();
}
