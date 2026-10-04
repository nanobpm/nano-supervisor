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

/// The positive git-finalize contract: a job whose envelope provisions a
/// repository AND whose agent commits to it is finalized by the worker — the
/// commits are detected and pushed to the fallback `nano/agent-work/...` branch
/// (the agent opened no PR), which the completion variables report.
///
/// The Rust worker has no finalize/push stage yet (its commits live only in the
/// reaped run dir; see `src/slot.rs`), so the pushed-fallback-branch contract is
/// pinned for the Node target until the Rust worker grows `finalizeGit`.
#[test]
fn provisioned_repo_finalize_pushes_a_fallback_branch() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target == contract_tests::Target::Rust {
        // The gap this contract pins: the Rust worker has no finalizeGit push
        // stage yet, so its commits live only in the reaped run dir.
        skip!("the Rust worker has no finalize/push stage yet (src/slot.rs)");
    }
    // Seed a pushable bare origin the agent's clone can commit + push back to.
    let origin_dir = tempfile::tempdir().expect("origin tempdir");
    let origin = origin_dir.path().join("origin.git");
    let seed = origin_dir.path().join("seed");
    let git = |cwd: &std::path::Path, args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    std::fs::create_dir_all(&seed).expect("seed dir");
    git(&seed, &["init", "-q", "-b", "main"]);
    git(
        &seed,
        &[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=tester",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "seed",
        ],
    );
    git(
        &seed,
        &[
            "clone",
            "-q",
            "--bare",
            "--",
            ".",
            origin.to_str().expect("origin path"),
        ],
    );

    let repo_url = format!("file://{}", origin.display());
    let outcome = run_worker_job(
        &engine,
        &target,
        "finalize-provisioned",
        &[
            // The agent commits real work inside the provisioned checkout (its
            // cwd), so the worker's finalize stage has something to push.
            json!({ "shell": "git -c user.email=t@example.com -c user.name=tester commit -q --allow-empty -m 'agent work'" }),
            json!({ "emit": "committed, opened no PR" }),
            json!({ "write_result": { "status": "committed" } }),
        ],
        json!({
            "prompt": "commit your work",
            "io.nanobpm.agentTask.repository.url": repo_url,
            "io.nanobpm.agentTask.repository.ref": "main",
        }),
        &[],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    // The worker's finalize detected the agent's commit and pushed a fallback
    // branch: the completion variables report the branch, the commit count and
    // the push — none of which an unprovisioned run (the test above) produces.
    let vars = outcome.variables();
    let branch = vars["branch"].as_str().unwrap_or("");
    assert!(
        branch.starts_with("nano/agent-work/"),
        "the fallback branch is nano/agent-work/…; vars: {vars:#?}"
    );
    assert!(
        vars["commits"].as_i64().unwrap_or(0) >= 1,
        "the agent's commit is counted: {vars:#?}"
    );
    assert_eq!(
        vars["pushed"].as_bool(),
        Some(true),
        "the finalize stage pushed the fallback branch: {vars:#?}"
    );
    // And the branch really exists on the origin (engine-observable via git).
    let ls = std::process::Command::new("git")
        .args([
            "ls-remote",
            "--heads",
            origin.to_str().expect("origin path"),
        ])
        .output()
        .expect("git ls-remote");
    let refs = String::from_utf8_lossy(&ls.stdout);
    assert!(
        refs.lines().any(|l| l.ends_with(branch)),
        "the pushed fallback branch {branch} must exist on the origin; refs:\n{refs}"
    );
}
