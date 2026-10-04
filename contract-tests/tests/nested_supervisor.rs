//! #40 — agent-spawned supervisors must not escape job teardown.
//!
//! The worker stamps `NANO_AGENT_RUN` on every agent's environment. A supervisor
//! or worker an agent then tries to start would daemonise (`setsid`, new session)
//! and outlive the job as a phantom fleet that can lease real jobs. So when
//! `NANO_AGENT_RUN` is set the command must refuse unless an explicit test-only
//! opt-in (`--foreground-for-tests` / `NANO_ALLOW_NESTED_SUPERVISOR=1`) runs it
//! attached instead.
//!
//! Contract: under a job (env `NANO_AGENT_RUN` set), starting the long-lived
//! supervisor/worker exits non-zero with an explanatory message and leaves **no**
//! surviving process — in particular, no control socket is bound. This is the
//! acceptance from the issue, expressed as a black-box subprocess assertion that
//! both targets can satisfy.

use contract_tests::{require_target, Target, TempHome};

/// The per-target invocation that starts the long-lived supervisor/worker an
/// agent would nest: the Node plugin's `supervisor start`, the Rust `daemon`.
fn nested_start_args(target: Target) -> &'static [&'static str] {
    match target {
        Target::Node => &["supervisor", "start", "--worker", "coder"],
        Target::Rust => &["daemon"],
    }
}

/// With `NANO_AGENT_RUN` set and no opt-in, starting the supervisor/worker exits
/// non-zero with an explanatory message and binds no control socket, so nothing
/// from the run can survive the job.
#[test]
fn refuses_to_start_inside_an_agent_run() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        // The Node plugin's guard is tracked on the parent issue; the Rust port
        // owns the guard in this repository.
        eprintln!(
            "SKIP nested_supervisor::refuses_to_start_inside_an_agent_run: \
             the Node plugin guard is tracked separately"
        );
        return;
    }
    let home = TempHome::with_target(target);
    let out = home
        .cmd(nested_start_args(target))
        .env("NANO_AGENT_RUN", "214829")
        .env("NANO_AGENT_RUN_DIR", home.path().join("agent-runs/run-x"))
        .output()
        .expect("spawn nested supervisor");

    assert!(
        !out.status.success(),
        "a supervisor started inside an agent run must exit non-zero; got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NANO_AGENT_RUN"),
        "the refusal must explain itself (mention NANO_AGENT_RUN); stderr was: {stderr}"
    );
    assert!(
        !home.socket_path().exists(),
        "a refused supervisor must not bind a control socket — nothing may survive the run"
    );
}
