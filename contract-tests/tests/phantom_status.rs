//! #42 — `supervisor status` fleet hygiene: list *other* supervisors on the host
//! and flag the phantoms a torn-down agent run can leave behind (a daemon whose
//! state home is under `/tmp`, or whose cwd is a deleted run dir).
//!
//! This is a **Rust-target** feature (the host-wide discovery overlay is the
//! Rust port's; the Node plugin's `status` reports only its own home), so the
//! test is gated to `Target::Rust` and to Unix, where the control socket is a
//! Unix-domain transport.
//!
//! Black-box: the test stands up a *fake* supervisor — a Unix socket at the
//! Node-compatible derived path (`supervisor_socket_path`) answering the `status`
//! protocol with a `/tmp` home — then runs the real binary's `supervisor status`
//! from a *different* home and asserts the fake is listed and flagged `PHANTOM`.
//! No engine and no real daemon are needed, so it runs everywhere unconditionally.

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
use contract_tests::{require_target, supervisor_socket_path, Target, TempHome};

/// A fake supervisor: a Unix socket answering `{op:"status"}` with a daemon
/// descriptor whose `logFile` places the home under `/tmp`. Returns a guard that
/// serves until dropped.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
struct FakeSupervisor {
    sock: std::path::PathBuf,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
impl FakeSupervisor {
    fn start(home: &std::path::Path) -> FakeSupervisor {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let sock = supervisor_socket_path(home);
        // A stale socket from a crashed earlier run would refuse `bind`.
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind fake supervisor socket");
        listener
            .set_nonblocking(true)
            .expect("set fake supervisor socket non-blocking");

        let frame = serde_json::json!({
            "ok": true,
            "type": "status",
            "daemon": {
                "pid": 424242,
                "startedAt": "1970-01-01T00:00:00.000Z",
                "version": "0.0.0",
                "socket": sock.to_string_lossy(),
                "logFile": format!("{}/logs/supervisor/daemon.log", home.display()),
            },
            "pluginVersion": "0.0.0",
            "workers": [],
            "final": true,
        })
        .to_string();

        let done = Arc::new(AtomicBool::new(false));
        let done_thread = done.clone();
        let handle = std::thread::spawn(move || {
            while !done_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Best-effort: drain the request line (the liveness probe
                        // just connects and drops; the real query sends `op`),
                        // then reply with the terminal status frame.
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(frame.as_bytes());
                        let _ = stream.write_all(b"\n");
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        FakeSupervisor {
            sock,
            done,
            handle: Some(handle),
        }
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
impl Drop for FakeSupervisor {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// `supervisor status` lists another supervisor running on the host and flags it
/// as a phantom when its home is under the system temp dir.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[test]
fn status_lists_and_flags_a_phantom_supervisor() {
    let target = Target::from_env();
    require_target!(target);
    // The host-wide discovery overlay is Rust-only.
    if target != Target::Rust {
        eprintln!("SKIP phantom_status: Rust-target feature");
        return;
    }

    // The caller's own home. We bind a *real* fake supervisor at its derived
    // control socket (below) so that, were the self-exclusion absent, discovery
    // would enumerate and list the caller itself — which the final assertion
    // forbids. Without this socket the self-exclusion check is vacuous (there is
    // nothing at the caller's home for discovery to mistakenly list), so the
    // assertion would pass even if `path == current_sock` were removed.
    let me = TempHome::with_target(target);
    // A live supervisor bound at the caller's OWN derived socket. Discovery must
    // suppress it via the `path == current_sock` self-exclusion, never list it.
    let me_daemon = FakeSupervisor::start(me.path());

    // A phantom lives under the system temp dir, the same place the control
    // sockets and this test's `ct-home-*` homes live, so its `logFile`-derived
    // home trips the `home under temp dir` flag.
    let phantom_home = std::env::temp_dir().join(format!(
        "ct-phantom-home-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let fake = FakeSupervisor::start(&phantom_home);

    let out = me
        .cmd(&["supervisor", "status"])
        .output()
        .expect("run supervisor status");
    assert!(
        out.status.success(),
        "supervisor status should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("Other supervisors on this host"),
        "status should list other supervisors; got:\n{stdout}"
    );
    let home_str = phantom_home.display().to_string();
    let flagged = stdout
        .lines()
        .find(|l| l.contains(&home_str))
        .unwrap_or_else(|| panic!("the phantom home {home_str} was not listed; got:\n{stdout}"));
    assert!(
        flagged.contains("PHANTOM"),
        "the /tmp-home supervisor must be flagged PHANTOM; line was: {flagged}"
    );

    // The caller must never flag itself as one of the "other" supervisors, even
    // though a live supervisor is bound at its own socket (`me_daemon`): the
    // self-exclusion must suppress it.
    assert!(
        !stdout.contains(&me.path().display().to_string()),
        "status must not list the caller's own home as another supervisor; got:\n{stdout}"
    );

    drop(fake);
    drop(me_daemon);
}
