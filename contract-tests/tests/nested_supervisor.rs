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
//! both targets can satisfy, plus an end-to-end form where a *real agent
//! subprocess* (the scripted fake agent, running under a worker job) attempts
//! the nested start — proving the worker actually propagates the marker to the
//! agent's process tree, not just to a hand-built environment.

use contract_tests::{
    require_engine_and_target, require_target, run_worker_job, skip, Skip, Target, TempHome,
};
use serde_json::json;

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

/// End-to-end form of the issue #40 acceptance: a *real agent subprocess* — the
/// scripted fake agent, running under a worker job — attempts to start the
/// nested supervisor. The worker must have propagated `NANO_AGENT_RUN` into the
/// agent's environment, so the nested start refuses (the agent's shell gate
/// fails, the job FAILs rather than completing) and no control socket is bound.
/// Unlike the direct-subprocess test above, this catches a regression where the
/// worker stops stamping the marker, and observes the state the job leaves
/// behind once the worker exits.
#[test]
fn agent_run_under_a_job_cannot_start_a_supervisor() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        // The Node plugin's guard is tracked on the parent issue; the Rust port
        // owns the guard in this repository.
        eprintln!(
            "SKIP nested_supervisor::agent_run_under_a_job_cannot_start_a_supervisor: \
             the Node plugin guard is tracked separately"
        );
        return;
    }
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "nested-supervisor",
        &[
            // The agent attempts exactly what #40 forbids: start the long-lived
            // supervisor from inside its run. The worker stamped NANO_AGENT_RUN
            // on this process's environment, so the nested start must refuse
            // (exit non-zero). A failing shell step aborts the turn, so the
            // `write_result` below runs only if the nested start succeeded.
            json!({ "shell": "\"$NS_BIN\" daemon >/dev/null 2>&1" }),
            json!({ "write_result": { "nested_started": true } }),
        ],
        json!({ "prompt": "try to run a supervisor" }),
        &[],
        &[],
    );
    assert!(
        outcome.record_exists(),
        "the fake agent must have run (its record proves the worker launched it)"
    );
    let record = outcome.record();
    assert!(
        record.env.contains_key("NANO_AGENT_RUN"),
        "the worker must stamp NANO_AGENT_RUN on the agent's environment; env was {:?}",
        record.env
    );
    // The refused nested start fails the agent's shell gate, so the worker must
    // settle the job as a FAILURE — never a completion. The first failure is
    // reported with retries left (the engine keeps the job CREATED at 2 of 3
    // retries), which the harness counts as settled; poll for that signal rather
    // than a terminal state, which only arrives once the retry budget is spent.
    let job = outcome.settled_job();
    assert!(
        job_is_failed(&job),
        "the agent's nested-supervisor attempt must refuse, failing its shell gate and the job; \
         last-seen job: {job}\nworker stderr:\n{}",
        outcome.stderr()
    );
    assert!(
        outcome.result_file().is_none(),
        "a refused nested start must abort the agent turn before write_result — \
         the job can never complete as if the supervisor started"
    );
    assert!(
        !contract_tests::supervisor_socket_path(outcome.home()).exists(),
        "no control socket may survive the job — nothing from the run can outlive it"
    );
}

/// The engine-visible "the job failed" signal, in either of its settled forms:
/// a terminal `FAILED` (retry budget spent) or a retriable failure (still
/// `CREATED`, but below the BPMN default of 3 retries — see
/// `contract_tests::job_is_settled`). Anything else (COMPLETED, ERROR, or a
/// full retry budget) means the nested start was NOT refused.
fn job_is_failed(job: &serde_json::Value) -> bool {
    let state = job["state"].as_str().unwrap_or("");
    let retries = job["retries"].as_i64().unwrap_or(3);
    state == "FAILED" || (state == "CREATED" && retries < 3)
}
