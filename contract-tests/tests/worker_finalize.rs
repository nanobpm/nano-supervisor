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
/// (the agent opened no PR), which the completion variables report. Exercised
/// against both targets: the Rust worker's `finalize_git` (src/provision.rs)
/// now mirrors the Node plugin's `finalizeGit`.
#[test]
fn provisioned_repo_finalize_pushes_a_fallback_branch() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
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
    // branch: the completion variables report the branch, the commit list and
    // the push — none of which an unprovisioned run (the test above) produces.
    let vars = outcome.variables();
    let branch = vars["branch"].as_str().unwrap_or("");
    assert!(
        branch.starts_with("nano/agent-work/"),
        "the fallback branch is nano/agent-work/…; vars: {vars:#?}"
    );
    // The Node worker reports `commits` as an ARRAY of the new commit SHAs
    // (`gitResult.commits = git log … .split('\n')` in c8ctl-plugin.js), not a
    // numeric count — assert the array is non-empty. A numeric parse
    // (`as_i64`) reads an array as `None` and fails even when finalize worked.
    assert!(
        vars["commits"].as_array().is_some_and(|c| !c.is_empty()),
        "the agent's commit is reported as a non-empty commits array: {vars:#?}"
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

/// Issue #49 — provisioned-completion PR detection. When the envelope sets
/// `task.allowPr`, the worker's finalize stage reconciles the pushed branch
/// against the provider with `gh pr list` (the Node plugin's `reconcileAgentPr`)
/// and surfaces the result as the `pullRequest` completion variable — which was
/// previously ALWAYS null for the Rust worker. Hermetic: a fake `gh` on `PATH`
/// returns a canned PR, so the test needs no network or real GitHub repo.
#[test]
fn provisioned_completion_detects_the_provider_pr() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
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

    // A fake `gh` on PATH: it records its arguments (so the test can assert
    // the provider lookup itself, not just the reconciled outcome) and emits a
    // canned `gh pr list --json …` array, so the worker's reconcile sees one
    // open PR without any network. The dir is kept alive for the whole test.
    //
    // Each invocation APPENDS its argv (one arg per line) followed by a `\037`
    // (unit-separator) delimiter line, so the test can recover every gh call
    // rather than only the last. A target may legitimately make more than one
    // gh call after reconcile — e.g. the Node plugin posts an attribution
    // `gh pr comment` once it has the PR number — and a last-write-wins `>`
    // record would clobber the `pr list` argv the test needs to assert on.
    let gh_dir = tempfile::tempdir().expect("gh tempdir");
    let gh_path = gh_dir.path().join("gh");
    let gh_args = gh_dir.path().join("gh-args");
    std::fs::write(
        &gh_path,
        format!(
            "#!/bin/sh\n{{ printf '%s\\n' \"$@\"; printf '\\037\\n'; }} >> \"{}\"\ncat <<'JSON'\n[{{\"number\":4242,\"url\":\"https://github.com/nanobpm/x/pull/4242\",\"state\":\"OPEN\",\"isDraft\":false,\"title\":\"agent slice\",\"author\":{{\"login\":\"nano-bot\"}}}}]\nJSON\n",
            gh_args.display()
        ),
    )
    .expect("write fake gh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&gh_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake gh");
    }
    let path_env = format!(
        "{}:{}",
        gh_dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let repo_url = format!("file://{}", origin.display());
    let outcome = run_worker_job(
        &engine,
        &target,
        "finalize-pr-detect",
        &[
            json!({ "shell": "git -c user.email=t@example.com -c user.name=tester commit -q --allow-empty -m 'agent work'" }),
            json!({ "emit": "committed, PR exists" }),
            json!({ "write_result": { "status": "committed" } }),
        ],
        json!({
            "prompt": "commit your work",
            "io.nanobpm.agentTask.repository.url": repo_url,
            "io.nanobpm.agentTask.repository.ref": "main",
            // The PR-detection gate: only an allow-PR run reconciles.
            "io.nanobpm.agentTask.task.allowPr": true,
        }),
        &[],
        &[("PATH", path_env.as_str())],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    let vars = outcome.variables();
    assert_eq!(
        vars["pushed"].as_bool(),
        Some(true),
        "the branch must be pushed before reconcile: {vars:#?}"
    );
    // The reconcile populated `pullRequest` from the fake gh's canned PR —
    // previously it was always null (issue #49).
    let pr = &vars["pullRequest"];
    assert_eq!(
        pr["found"], true,
        "the provider PR must be detected: {vars:#?}"
    );
    assert_eq!(pr["number"], 4242, "{vars:#?}");
    assert_eq!(
        pr["url"], "https://github.com/nanobpm/x/pull/4242",
        "{vars:#?}"
    );
    assert_eq!(pr["state"], "OPEN", "{vars:#?}");
    assert_eq!(pr["isDraft"], false, "{vars:#?}");
    assert_eq!(pr["title"], "agent slice", "{vars:#?}");
    assert_eq!(pr["openedBy"], "nano-bot", "{vars:#?}");

    // The provider lookup itself is covered: the fake gh must have been invoked
    // as `gh pr list --head <pushed-branch> --state all --json <fields> --limit 1`
    // — otherwise a reconcile that omitted `--head` or looked up the wrong
    // branch would still pass on the canned output. The pushed branch is the
    // completion's `branch` variable (the fallback branch the worker pushed).
    //
    // The fake gh appends each invocation's argv followed by a `\037` delimiter
    // line, so split the record back into one argv vector per gh call. A target
    // may make further gh calls after reconcile (the Node plugin posts an
    // attribution `gh pr comment`), so assert the `pr list` call is PRESENT with
    // the exact argument list rather than that it was the only/last gh call.
    let branch = vars["branch"].as_str().expect("pushed branch variable");
    let raw =
        std::fs::read_to_string(&gh_args).expect("the fake gh must have recorded its arguments");
    let invocations: Vec<Vec<String>> = raw
        .split('\u{1f}')
        .map(|rec| {
            rec.lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
        .filter(|argv| !argv.is_empty())
        .collect();
    let expected: Vec<String> = [
        "pr",
        "list",
        "--head",
        branch,
        "--state",
        "all",
        "--json",
        "number,url,state,isDraft,title,author",
        "--limit",
        "1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert!(
        invocations.contains(&expected),
        "the gh pr lookup must target the pushed branch with the full argument list; \
         recorded gh invocations: {invocations:#?}"
    );
}
