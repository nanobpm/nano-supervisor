//! #41 — the supervisor pins its engine connection in `supervisor.json` and
//! never follows c8ctl's mutable active profile again.
//!
//! The incident: an agent ran `c8 use profile local`, which rewrote the
//! operator's global `~/.config/c8ctl/session.json`; the next supervisor
//! restart re-resolved the *active* profile and re-pointed the whole fleet at
//! a stray test engine (`http://localhost:8080`), which burned real agent
//! tokens serving `probe-*`/`ct-*` test jobs while production had no workers.
//!
//! These tests pin the fix's observable surface, with no engine needed:
//!   * `work` records `connection{profile,baseUrl}` in
//!     `<C8CTL_NANO_HOME>/supervisor.json` on first start, and its startup
//!     banner names the engine;
//!   * after `activeProfile` moves to another profile, the next `work` start
//!     still connects to the PINNED profile and warns loudly about the drift —
//!     the acceptance criterion's "every worker still connects to A, and
//!     `status` shows A plus a warning that the active profile is B";
//!   * an explicit `--profile` re-pins (the operator's deliberate override).

mod common;

use contract_tests::{
    require_engine_and_target, require_target, run_worker_job_with_rank, skip, Skip, Target,
    TempHome,
};
use serde_json::json;
/// The two c8ctl profiles the acceptance scenario switches between: `alpha`
/// (the fleet's engine) and `beta` (the engine an agent's `c8 use profile`
/// would select). Written into an isolated `C8CTL_DATA_DIR` per test.
fn write_c8ctl_profiles(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).expect("create c8ctl config dir");
    std::fs::write(
        dir.join("profiles.json"),
        r#"{"profiles":[
            {"name":"alpha","baseUrl":"http://alpha.invalid:8080"},
            {"name":"beta","baseUrl":"http://beta.invalid:8080"}
        ]}"#,
    )
    .expect("write profiles.json");
}

fn set_active_profile(dir: &std::path::Path, name: &str) {
    std::fs::write(
        dir.join("session.json"),
        format!("{{\"activeProfile\":\"{name}\"}}\n"),
    )
    .expect("write session.json");
}

/// A minimal hire so `work` gets past config validation. The command is
/// irrelevant — the worker never reaches an engine in these tests (the
/// profiled baseUrls are unroutable `.invalid` names), so no agent runs.
/// Written straight into `config.json` (the Rust target's hire channel; the
/// `hire` CLI command is the Node plugin's).
fn hire(home: &TempHome) {
    let config = serde_json::json!({
        "hires": {
            "coder": {
                "rank": "senior",
                "command": "true",
                "protocol": "pipe",
                "sandbox": "none",
                "capabilities": [],
            }
        }
    });
    std::fs::write(
        home.path().join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .expect("write config.json");
}

/// Start `work coder` with the given c8ctl config dir and extra args, wait for
/// it to fail its (unroutable) engine connection, and return its output. The
/// worker must get far enough to pin and banner the engine — the pin write and
/// the banner both happen BEFORE the first activation poll.
fn run_work(
    home: &TempHome,
    c8ctl_dir: &std::path::Path,
    extra: &[&str],
) -> contract_tests::CmdOutput {
    let mut args: Vec<&str> = vec!["work", "coder", "--poll-timeout", "200"];
    args.extend_from_slice(extra);
    let mut cmd = home.cmd(&args);
    cmd.env("C8CTL_DATA_DIR", c8ctl_dir);
    // Never let a stray activation hang the test: the pin and banner are the
    // contract here, and both are logged BEFORE the first activation attempt —
    // so as soon as the banner line appears on stderr the worker has done
    // everything under test and can be reaped (an unroutable `.invalid`
    // engine's DNS retry would otherwise hold the process for minutes).
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn work");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    collected.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&collected);
                    if text.contains("engine: ") {
                        let _ = seen_tx.send(text.into_owned());
                        // Keep draining so the child never blocks on a full pipe.
                        while matches!(stderr.read(&mut buf), Ok(n) if n > 0) {}
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = seen_tx.send(String::from_utf8_lossy(&collected).into_owned());
    });
    let banner = seen_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap_or_default();
    let _ = child.kill();
    let out = child.wait_with_output().expect("reap work");
    contract_tests::CmdOutput {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: banner,
    }
}

/// Acceptance, first half: starting under profile A pins the connection in
/// `supervisor.json` and the startup banner shows the engine.
#[test]
fn first_start_pins_the_connection_and_banners_the_engine() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(
            module_path!(),
            "the Node plugin has no connection pinning (that is issue #41); Rust target only",
        );
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");
    write_c8ctl_profiles(c8ctl.path());
    set_active_profile(c8ctl.path(), "alpha");

    let out = run_work(&home, c8ctl.path(), &[]);

    // The pin landed in supervisor.json with the resolved baseUrl fingerprint.
    let state = home
        .read_json("supervisor.json")
        .expect("supervisor.json written on first start");
    assert_eq!(
        state["connection"]["profile"],
        serde_json::json!("alpha"),
        "supervisor.json must pin the profile resolved at first start: {state}"
    );
    assert_eq!(
        state["connection"]["baseUrl"],
        serde_json::json!("http://alpha.invalid:8080"),
        "supervisor.json must record the baseUrl fingerprint: {state}"
    );
    // The banner names the engine loudly (the incident's clue was buried in a
    // job-type line; now the engine leads the startup output).
    assert!(
        out.stderr
            .contains("engine: alpha (http://alpha.invalid:8080)"),
        "startup banner must name the pinned engine; stderr was:\n{}",
        out.stderr
    );
}

/// Acceptance, second half: with the pin in place, moving c8ctl's active
/// profile does NOT retarget the worker — it still connects to the pinned
/// engine and warns that the active profile drifted.
#[test]
fn moved_active_profile_does_not_retarget_a_pinned_worker() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(
            module_path!(),
            "the Node plugin follows the mutable active profile (that is issue #41); Rust target only",
        );
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");
    write_c8ctl_profiles(c8ctl.path());

    // Start under A…
    set_active_profile(c8ctl.path(), "alpha");
    let _ = run_work(&home, c8ctl.path(), &[]);
    // …then an agent (or anyone) runs `c8 use profile B`.
    set_active_profile(c8ctl.path(), "beta");

    // The next worker start must still connect to A — and say so, with a
    // warning naming the drifted active profile.
    let out = run_work(&home, c8ctl.path(), &[]);
    assert!(
        out.stderr
            .contains("engine: alpha (http://alpha.invalid:8080)"),
        "the worker must keep following the PIN (alpha), not the moved session; stderr was:\n{}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("engine: beta"),
        "the worker must NOT follow the moved active profile; stderr was:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("WARNING") && out.stderr.contains("beta"),
        "the drift warning must name the now-active profile; stderr was:\n{}",
        out.stderr
    );
    // The pin itself is untouched by the drift.
    let state = home.read_json("supervisor.json").expect("supervisor.json");
    assert_eq!(state["connection"]["profile"], serde_json::json!("alpha"));
}

/// Issue #41, client-target verification (not just the banner): the banner and
/// `supervisor.json` are both derived from the pin *decision*, so asserting
/// them proves the decision, not that the worker's constructed client actually
/// dials the pinned engine. This test closes that gap with distinguishable
/// LIVE local endpoints: after the active profile moves from alpha to beta, the
/// running worker must open a TCP connection to the PINNED engine (alpha) and
/// never to the moved one (beta).
#[test]
fn pinned_worker_dials_the_pinned_engine_not_the_moved_one() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(module_path!(), "Rust target only (issue #41)");
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");
    std::fs::create_dir_all(c8ctl.path()).expect("create c8ctl config dir");

    // Two real local endpoints, each reporting the first time it is dialed.
    let (alpha_url, alpha_rx) = dial_probe("alpha");
    let (beta_url, beta_rx) = dial_probe("beta");
    std::fs::write(
        c8ctl.path().join("profiles.json"),
        format!(
            "{{\"profiles\":[\
             {{\"name\":\"alpha\",\"baseUrl\":\"{alpha_url}\"}},\
             {{\"name\":\"beta\",\"baseUrl\":\"{beta_url}\"}}]}}"
        ),
    )
    .expect("write profiles.json");

    // Pin under alpha (the banner lands before any dial), then move to beta.
    set_active_profile(c8ctl.path(), "alpha");
    let _ = run_work(&home, c8ctl.path(), &[]);
    set_active_profile(c8ctl.path(), "beta");

    // The first pinning run shares the `alpha` listener and can race past its
    // banner into an activation dial before `run_work` reaps it, leaving a stale
    // "alpha" queued in `alpha_rx`. Drain BOTH receivers now (the first child is
    // already reaped) so the assertions below observe only the worker under
    // test's dials — otherwise a post-drift worker that never contacts alpha
    // could still satisfy `recv_timeout` on that leftover event.
    while alpha_rx.try_recv().is_ok() {}
    while beta_rx.try_recv().is_ok() {}

    // Run the worker for real — past the banner, into the activation poll — so
    // its client genuinely connects. A short poll makes it dial promptly and
    // keep retrying; the unresponsive probe never lets it hang.
    let mut cmd = home.cmd(&["work", "coder", "--poll-timeout", "200"]);
    cmd.env("C8CTL_DATA_DIR", c8ctl.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().expect("spawn work");

    let dialed_alpha = alpha_rx.recv_timeout(std::time::Duration::from_secs(30));
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        dialed_alpha.is_ok(),
        "the worker never dialed the PINNED engine (alpha) within 30s — the pin did not reach the client"
    );
    assert!(
        beta_rx.try_recv().is_err(),
        "the worker dialed the MOVED engine (beta); the pin was not enforced at the constructed client"
    );
}

/// Bind a throwaway local TCP listener and return its `http://127.0.0.1:PORT`
/// URL plus a receiver that yields `label` the first time anything dials it.
/// The accept loop drains and drops each connection so the worker's client
/// never blocks; the thread owns the listener and ends when the test binary
/// exits. Used to prove *which* engine the worker actually connects to,
/// independent of the startup banner.
fn dial_probe(label: &'static str) -> (String, std::sync::mpsc::Receiver<&'static str>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    let port = listener.local_addr().expect("probe local addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    drop(s);
                    if tx.send(label).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    (url, rx)
}

/// An explicit `--profile` is the operator's deliberate override: it re-pins
/// the connection even over an existing pin.
#[test]
fn explicit_profile_re_pins() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(module_path!(), "Rust target only (issue #41)");
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");
    write_c8ctl_profiles(c8ctl.path());

    set_active_profile(c8ctl.path(), "alpha");
    let _ = run_work(&home, c8ctl.path(), &[]);
    let state = home.read_json("supervisor.json").expect("pinned");
    assert_eq!(state["connection"]["profile"], serde_json::json!("alpha"));

    // The operator deliberately restarts on beta: the pin moves.
    let out = run_work(&home, c8ctl.path(), &["--profile", "beta"]);
    let state = home.read_json("supervisor.json").expect("re-pinned");
    assert_eq!(
        state["connection"]["profile"],
        serde_json::json!("beta"),
        "an explicit --profile must re-pin: {state}"
    );
    assert!(
        out.stderr
            .contains("engine: beta (http://beta.invalid:8080)"),
        "the banner must show the re-pinned engine; stderr was:\n{}",
        out.stderr
    );
}

/// The env-only pin (no c8ctl profile — how a systemd/env-deployed fleet and
/// this repo's own contract harness run the worker): its recorded baseUrl
/// fingerprint is ENFORCED, not just recorded. A start whose
/// `CAMUNDA_REST_ADDRESS` drifted after pinning must keep connecting to the
/// PINNED engine and warn loudly about the drift.
#[test]
fn env_pin_enforces_its_base_url_fingerprint_across_env_drift() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(module_path!(), "Rust target only (issue #41)");
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    // No c8ctl config at all: the connection comes from CAMUNDA_REST_ADDRESS.
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");

    // First start pins the env connection (engine A).
    let mut cmd = home.cmd(&["work", "coder", "--poll-timeout", "200"]);
    cmd.env("C8CTL_DATA_DIR", c8ctl.path())
        .env("CAMUNDA_REST_ADDRESS", "http://engine-a.invalid:8080");
    let out = run_to_banner(cmd);
    assert!(
        out.stderr
            .contains("engine: CAMUNDA_* env (http://engine-a.invalid:8080)"),
        "first start must pin and banner the env engine; stderr was:\n{}",
        out.stderr
    );
    let state = home.read_json("supervisor.json").expect("pinned");
    assert_eq!(
        state["connection"]["baseUrl"],
        serde_json::json!("http://engine-a.invalid:8080")
    );
    assert!(state["connection"].get("profile").is_none());

    // The environment drifts to engine B (a stray export, a unit edit). The
    // next start must NOT follow it: the banner still names the PINNED engine
    // A and a loud warning names the drift.
    let mut cmd = home.cmd(&["work", "coder", "--poll-timeout", "200"]);
    cmd.env("C8CTL_DATA_DIR", c8ctl.path())
        .env("CAMUNDA_REST_ADDRESS", "http://engine-b.invalid:8080");
    let out = run_to_banner(cmd);
    assert!(
        out.stderr
            .contains("engine: CAMUNDA_* env (http://engine-a.invalid:8080)"),
        "the worker must keep following the PIN (engine A), not the drifted env; stderr was:\n{}",
        out.stderr
    );
    assert!(
        !out.stderr
            .contains("engine: CAMUNDA_* env (http://engine-b.invalid:8080)"),
        "the banner must NOT adopt the drifted env engine; stderr was:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("WARNING") && out.stderr.contains("engine-b.invalid:8080"),
        "the drift warning must name the env's new address; stderr was:\n{}",
        out.stderr
    );
    // The pin on disk is untouched by the drift.
    let state = home.read_json("supervisor.json").expect("supervisor.json");
    assert_eq!(
        state["connection"]["baseUrl"],
        serde_json::json!("http://engine-a.invalid:8080")
    );
}

/// Issue #41, the env-REMOVED drift signal: removing `CAMUNDA_REST_ADDRESS`
/// after an env-only pin is just as much connection drift as pointing it
/// elsewhere — the deployment environment was cleared — yet the worker still
/// connects to the PINNED engine. The drift warning must fire for the unset
/// case too (rendering the cleared value explicitly), not only when a current
/// URL exists to compare.
#[test]
fn env_pin_warns_when_the_env_is_removed_after_pinning() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(module_path!(), "Rust target only (issue #41)");
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");

    // First start pins the env connection (engine A).
    let mut cmd = home.cmd(&["work", "coder", "--poll-timeout", "200"]);
    cmd.env("C8CTL_DATA_DIR", c8ctl.path())
        .env("CAMUNDA_REST_ADDRESS", "http://engine-a.invalid:8080");
    let out = run_to_banner(cmd);
    assert!(
        out.stderr
            .contains("engine: CAMUNDA_* env (http://engine-a.invalid:8080)"),
        "first start must pin and banner the env engine; stderr was:\n{}",
        out.stderr
    );

    // The environment is CLEARED (the export removed from the unit). The next
    // start must keep following the PIN (engine A) AND warn that the env is now
    // unset — a silently-ignored removal is exactly the drift the pin exists to
    // surface.
    let mut cmd = home.cmd(&["work", "coder", "--poll-timeout", "200"]);
    cmd.env("C8CTL_DATA_DIR", c8ctl.path())
        .env_remove("CAMUNDA_REST_ADDRESS");
    let out = run_to_banner(cmd);
    assert!(
        out.stderr
            .contains("engine: CAMUNDA_* env (http://engine-a.invalid:8080)"),
        "the worker must keep following the PIN (engine A) with the env unset; stderr was:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("WARNING")
            && out.stderr.contains("UNSET")
            && out.stderr.contains("engine-a.invalid:8080"),
        "the drift warning must fire for the REMOVED env and name the pinned engine; stderr was:\n{}",
        out.stderr
    );
}

/// Spawn `work` from a prepared command and collect its startup output up to
/// the `engine: ` banner (everything under test here is logged before the
/// first activation attempt).
fn run_to_banner(mut cmd: std::process::Command) -> contract_tests::CmdOutput {
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn work");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    collected.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&collected);
                    if text.contains("engine: ") {
                        let _ = seen_tx.send(text.into_owned());
                        while matches!(stderr.read(&mut buf), Ok(n) if n > 0) {}
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = seen_tx.send(String::from_utf8_lossy(&collected).into_owned());
    });
    let banner = seen_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap_or_default();
    let _ = child.kill();
    let out = child.wait_with_output().expect("reap work");
    contract_tests::CmdOutput {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: banner,
    }
}

/// The sanity guard (proposal 4): a worker whose whole job-type matrix is
/// test-looking (`probe-*`/`ct-*`) warns prominently, naming the engine, as
/// soon as it touches the engine — the log clue the incident had to be
/// diagnosed from is now explicit. Asserted here against the startup path
/// without an engine: the guard's identity wiring must at least never crash a
/// worker whose types are test-looking.
#[test]
fn test_looking_job_types_still_start_and_banner() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        contract_tests::note_skip(module_path!(), "Rust target only (issue #41)");
        return;
    }
    let home = TempHome::with_target(target);
    hire(&home);
    let c8ctl = tempfile::tempdir().expect("c8ctl dir");
    write_c8ctl_profiles(c8ctl.path());
    set_active_profile(c8ctl.path(), "alpha");

    let out = run_work(
        &home,
        c8ctl.path(),
        &["--job-type", "probe-job", "--job-type", "ct-smoke"],
    );
    // The worker got as far as resolving and bannering its engine (the guard
    // fires on the first live activation, which an unroutable engine never
    // produces — asserted end-to-end by the engine-gated suite).
    assert!(
        out.stderr
            .contains("engine: alpha (http://alpha.invalid:8080)"),
        "stderr was:\n{}",
        out.stderr
    );
}

/// Proposal 4, end-to-end: a worker whose entire job-type matrix is
/// test-looking and that gets a LIVE job from the engine emits the issue-#41
/// sanity warning — exactly once — naming the engine. This is the
/// retargeted-fleet alarm the incident lacked; the unit tests in `src/jobs.rs`
/// cover the predicate, this proves it fires on a real activation.
///
/// The hire uses a TEST-LOOKING rank (`ct-worker`) via
/// [`run_worker_job_with_rank`]: the default `junior` rank would add the
/// production-looking `junior` job type to the served matrix, disqualifying
/// `all_test_looking` so the warning could never fire. With a `ct-worker` rank
/// the worker serves only `ct-worker` + the `ct-*` test type — every type
/// test-looking. Engine-gated: skips without an engine + Rust target.
#[test]
fn live_job_on_a_test_looking_fleet_warns_once() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target != Target::Rust {
        skip!("the sanity guard is the Rust worker's issue-#41 instrumentation");
    }
    let outcome = run_worker_job_with_rank(
        &engine,
        &target,
        "sanity-warn",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "note your environment" }),
        &[],
        &[],
        "ct-worker",
    );
    let stderr = outcome.stderr();
    let hits = stderr
        .matches("every job type it serves is test-looking")
        .count();
    assert_eq!(
        hits, 1,
        "a live job on an all-test-looking fleet must warn exactly once; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("(issue #41)"),
        "the sanity warning must cite issue #41; stderr was:\n{stderr}"
    );
}
