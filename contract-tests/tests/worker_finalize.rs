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
    assert_eq!(outcome.result_file().unwrap()["pr"], "nanobpm/x#7");
}

/// An agent that commits but opens no PR falls back to a `nano/agent-work/...`
/// branch so the work is never lost. The agent provisions a real git repo with
/// a commit and a reachable `origin` in its run dir, so the worker's finalize
/// path genuinely creates **and pushes** the fallback branch (rather than
/// short-circuiting on a non-repo cwd and logging the branch name from the
/// "not created" path).
#[test]
fn no_pr_falls_back_to_nano_agent_work_branch() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "finalize-fallback",
        &[
            // Provision a repo with a commit and a local bare `origin` the
            // fallback push can actually reach, all inside the run dir.
            json!({ "shell": "git init -q && git init -q --bare origin.git && git remote add origin origin.git && git -c user.email=t@example.com -c user.name=tester commit -q --allow-empty -m 'agent work'" }),
            json!({ "emit": "committed but opened no PR" }),
        ],
        json!({ "prompt": "just commit" }),
        &[],
        &[],
    );
    let logs = outcome.stderr();
    assert!(
        logs.contains("pushed fallback branch nano/agent-work/"),
        "the worker should create AND push a nano/agent-work/ fallback branch; stderr:\n{logs}"
    );
}
