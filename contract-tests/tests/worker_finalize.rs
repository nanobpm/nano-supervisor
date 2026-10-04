//! **Finalize**: commit, push and PR detection; the fallback
//! `nano/agent-work/...` branch when the agent opens no PR; and the time budgets
//! around finalizing. Needs a live engine (and git), and skips without one.

use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// When the agent reports a PR (result file / `::nano:result::`), the worker
/// forwards it rather than inventing a fallback branch.
#[test]
fn agent_reported_pr_is_forwarded() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "finalize-pr",
        &[
            json!({ "emit": "opened a PR" }),
            json!({ "result_marker": { "status": "opened", "pr": "nanobpm/x#7" } }),
            json!({ "write_result": { "status": "opened", "pr": "nanobpm/x#7" } }),
        ],
        json!({ "prompt": "open a PR" }),
        &[],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    // The agent's PR reaches the process as a result variable; the worker does
    // not invent a branch of its own.
    let vars = outcome.variables();
    assert_eq!(vars["pr"], "nanobpm/x#7", "{vars:#?}");
    assert_eq!(vars["status"], "opened", "{vars:#?}");
    assert!(
        !vars.contains_key("branch"),
        "no fallback branch: {vars:#?}"
    );
}

/// The fallback `nano/agent-work/…` branch is only created for a repository
/// the worker provisioned. A job without a `repository` runs in a scratch dir;
/// even if the agent commits there, the worker pushes nothing.
#[test]
fn unprovisioned_run_creates_no_fallback_branch() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "finalize-fallback",
        &[
            json!({ "shell": "git init -q && git init -q --bare origin.git && git remote add origin origin.git && git -c user.email=t@example.com -c user.name=tester commit -q --allow-empty -m 'agent work'" }),
            json!({ "emit": "committed but opened no PR" }),
            json!({ "write_result": { "status": "committed" } }),
        ],
        json!({ "prompt": "just commit" }),
        &[],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    let vars = outcome.variables();
    for k in ["branch", "commits", "pushed", "pullRequest"] {
        assert!(
            !vars.contains_key(k),
            "unexpected `{k}` for an unprovisioned run: {vars:#?}"
        );
    }
}
