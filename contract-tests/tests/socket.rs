//! #3 — control socket: the request/response schema of every `supervisor.sock`
//! op the plugin sends, recorded from a live Node daemon.
//!
//! The wire format and the per-op schemas are documented in
//! `fixtures/socket-protocol.md`, with a redacted live `status` reply in
//! `fixtures/socket-status-frame.json`. The tests here:
//!   1. pin the socket-path derivation (deterministic, no daemon),
//!   2. validate the recorded `status` frame against the documented schema, and
//!   3. do a live round-trip against a real daemon — **opt-in and localhost-only**
//!      so it can never touch a shared fleet.

mod common;

use std::path::Path;

use contract_tests::{
    control_request, require_target, supervisor_socket_path, Engine, Target, TempHome,
};

#[test]
fn socket_path_derivation_is_deterministic() {
    // Independently derived (sha1(home)[:8]) — mirrors the plugin exactly, and
    // is stable regardless of any running daemon.
    let a = supervisor_socket_path(Path::new("/tmp/ct-b"));
    let b = supervisor_socket_path(Path::new("/tmp/ct-b"));
    assert_eq!(a, b, "same home → same socket");
    assert_ne!(
        supervisor_socket_path(Path::new("/tmp/ct-b")),
        supervisor_socket_path(Path::new("/tmp/ct-c")),
        "different home → different socket"
    );
    let name = a.file_name().unwrap().to_string_lossy();
    assert!(name.starts_with("c8ctl-nano-sup-") && name.ends_with(".sock"));
    // Pin the exact derivation, not just its shape: sha1("/tmp/ct-b")[:8] is
    // `57425ec9`. A silent change of hash (e.g. SHA-1 → something else) would
    // still produce a stable 8-char suffix and slip past a shape-only check, so
    // assert the known value the Node plugin emits.
    assert_eq!(
        name, "c8ctl-nano-sup-57425ec9.sock",
        "socket derivation drifted from the Node plugin's sha1(home)[:8]"
    );
}

#[test]
fn recorded_status_frame_matches_schema() {
    let raw = include_str!("../fixtures/socket-status-frame.json");
    let frame: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");

    assert_eq!(frame["ok"], serde_json::json!(true));
    assert_eq!(frame["type"], serde_json::json!("status"));
    assert_eq!(frame["final"], serde_json::json!(true));
    assert!(frame["pluginVersion"].is_string());

    let daemon = &frame["daemon"];
    for key in ["pid", "startedAt", "version", "socket", "logFile"] {
        assert!(daemon.get(key).is_some(), "daemon.{key} missing");
    }

    let workers = frame["workers"].as_array().expect("workers is an array");
    let w = &workers[0];
    for key in [
        "id",
        "profile",
        "pid",
        "state",
        "restarts",
        "uptimeMs",
        "startedAtMs",
        "lastExit",
        "args",
        "logFile",
        "activity",
        "engine",
        "agentic",
    ] {
        assert!(w.get(key).is_some(), "worker.{key} missing");
    }
    assert!(w["activity"]["jobs"].is_array());
    for key in ["status", "mode", "url", "discovered", "message"] {
        assert!(w["agentic"].get(key).is_some(), "agentic.{key} missing");
    }
}

/// Live round-trip against a real daemon. Opt-in only: it starts a supervised
/// worker, which connects to whatever engine/agentic hub the host is configured
/// for. To keep it off shared infrastructure it runs **only** when:
///
/// * `NS_ALLOW_LIVE_SUPERVISOR=1` is set (explicit opt-in), and
/// * the configured engine is reachable **and** local (the `Engine` guard
///   refuses non-localhost without `NS_ALLOW_REMOTE_ENGINE=1`).
///
/// It pins `NANO_BASE_URL` to that local engine and disables the hub
/// (`NANO_AGENTIC=off`) so the worker cannot reach a real fleet.
#[test]
fn live_status_round_trip() {
    let target = Target::from_env();
    require_target!(target);
    if std::env::var("NS_ALLOW_LIVE_SUPERVISOR").ok().as_deref() != Some("1") {
        eprintln!("SKIP socket::live_status_round_trip: set NS_ALLOW_LIVE_SUPERVISOR=1 to run");
        return;
    }
    let engine = Engine::from_env();
    // Safety gate: this case starts a real worker against the engine, so it must
    // never touch a shared/remote cluster even if `NS_ALLOW_REMOTE_ENGINE=1` was
    // set to let *non-live* engine checks run against a remote URL. Enforce the
    // localhost-only rule here regardless of that override.
    if !engine.is_local() {
        eprintln!(
            "SKIP socket::live_status_round_trip: engine {:?} is not localhost; \
             live-worker tests refuse remote engines (NS_ALLOW_REMOTE_ENGINE does \
             not relax this)",
            engine.url()
        );
        return;
    }
    if !engine.reachable() {
        eprintln!(
            "SKIP socket::live_status_round_trip: engine {:?} unreachable",
            engine.url()
        );
        return;
    }

    let home = TempHome::with_target(target);
    assert_eq!(
        home.run(&[
            "hire",
            "--name",
            "coder",
            "--rank",
            "senior",
            "--command",
            "nano-coder",
            "--capabilities",
            "feature",
        ])
        .code,
        Some(0)
    );

    // Start a daemon + worker, pinned to the local engine, hub off.
    let start = home
        .cmd(&["supervisor", "start", "--worker", "coder"])
        .env("NANO_BASE_URL", engine.url())
        .env("NANO_AGENTIC", "off")
        .output()
        .expect("supervisor start");
    assert!(start.status.success(), "supervisor start failed");

    // Give the daemon a moment to bind its socket.
    let sock = home.socket_path();
    for _ in 0..20 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(sock.exists(), "control socket was not created");

    let frames =
        control_request(&sock, &serde_json::json!({ "op": "status" })).expect("status round-trip");
    let final_frame = frames
        .iter()
        .find(|f| f["final"].as_bool().unwrap_or(false))
        .expect("a final frame");
    assert_eq!(final_frame["ok"], serde_json::json!(true));
    assert_eq!(final_frame["type"], serde_json::json!("status"));
    assert!(final_frame["daemon"]["pid"].is_number());
    assert!(final_frame["workers"].is_array());

    // Unknown ops are rejected uniformly.
    let unknown = control_request(&sock, &serde_json::json!({ "op": "nope" }))
        .expect("unknown-op round-trip");
    let last = unknown.last().expect("a reply frame");
    assert_eq!(last["ok"], serde_json::json!(false));
    assert!(last["error"].as_str().unwrap_or("").contains("unknown op"));

    // Tear the daemon down (TempHome::drop also force-stops as a backstop).
    let _ = home.cmd(&["supervisor", "stop", "--force"]).output();
}
