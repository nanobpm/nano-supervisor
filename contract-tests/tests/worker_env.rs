//! Job in, agent input out — **the environment and working directory**.
//!
//! The worker hands the agent a working directory (with the repo provisioned)
//! and an environment: `AGENT_*` (`AGENT_RESULT_FILE`, `AGENT_MODEL`, …), `NANO_*`
//! and `NANO_AGENTIC_*`. The fake agent records exactly what it received.

use std::time::Duration;

use contract_tests::fake::FakeAgent;
use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// CI, no engine: every `AGENT_*` / `NANO_*` variable the agent is given is
/// recorded verbatim, and nothing else is. This pins the recorder the end-to-end
/// env assertions rely on.
#[test]
fn agent_records_agent_and_nano_env_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let rec = dir.path().join("record.json");
    let out = FakeAgent::new()
        .acp()
        .record_to(&rec)
        .env("AGENT_MODEL", "claude-x")
        .env("NANO_JOB_KEY", "42")
        .env("NANO_AGENTIC_RUN", "r1")
        .env("PATH_LIKE_NOISE", "should-not-be-recorded")
        .emit("ok")
        .drive_acp("go", Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.text, "ok");
    let record = contract_tests::fake::FakeRecord::read(&rec);
    assert_eq!(
        record.env.get("AGENT_MODEL").map(String::as_str),
        Some("claude-x")
    );
    assert_eq!(
        record.env.get("NANO_JOB_KEY").map(String::as_str),
        Some("42")
    );
    assert_eq!(
        record.env.get("NANO_AGENTIC_RUN").map(String::as_str),
        Some("r1")
    );
    assert!(!record.env.contains_key("PATH_LIKE_NOISE"));
}

/// End-to-end: the worker sets `AGENT_RESULT_FILE` and at least one `NANO_*`
/// variable, and runs the agent in a per-job working directory.
#[test]
fn worker_gives_agent_result_file_and_nano_env() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "env-contract",
        &[
            json!({ "emit": "ok" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "note your environment" }),
        &[],
        &[],
    );
    let record = outcome.record();
    let env = &record.env;
    assert!(
        env.contains_key("AGENT_RESULT_FILE"),
        "worker must set AGENT_RESULT_FILE; env was {env:?}"
    );
    // The hired profile's identity, as the Node worker exports it.
    assert_eq!(
        env.get("AGENT_RANK").map(String::as_str),
        Some("junior"),
        "{env:?}"
    );
    assert_eq!(
        env.get("AGENT_JOB_TYPE").map(String::as_str),
        Some(outcome.job_type.as_str()),
        "{env:?}"
    );
    assert!(
        env.get("AGENT_PROFILE")
            .is_some_and(|p| p.starts_with("ctfake")),
        "{env:?}"
    );
    assert!(
        env.keys().any(|k| k.starts_with("NANO_")),
        "worker must set NANO_* variables; env was {env:?}"
    );
    assert!(
        !record.cwd.is_empty(),
        "agent must run in a working directory"
    );
}

/// End-to-end **repository provisioning**: a job whose envelope carries a
/// `repository` is cloned before the agent runs, and the agent's working
/// directory IS the checkout (`<run dir>/repo`, with a `.git`). The repo is a
/// local bare git repository seeded by the test — no network, no credentials.
#[test]
fn worker_provisions_the_repository_into_the_run_dir() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // Seed a throwaway ORIGIN repository with one commit, served over the
    // file:// transport so the clone needs no network or credentials.
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
    // Pin the seeded commit: the agent's script below writes a successful
    // result ONLY when its cwd is a real clone of this origin at exactly this
    // commit, so a worker that merely creates a `repo/` directory (or clones
    // the wrong ref) can no longer pass the test.
    let seed_head = {
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&seed)
            .output()
            .expect("spawn git rev-parse");
        assert!(
            out.status.success(),
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    let repo_url = format!("file://{}", origin.display());
    let outcome = run_worker_job(
        &engine,
        &target,
        "env-repo-provision",
        &[
            json!({ "emit": "ok" }),
            // Complete the job only if the checkout is genuinely provisioned:
            // a `.git` must exist and HEAD must be the seeded commit. On any
            // mismatch the script exits non-zero and never writes a result, so
            // the job cannot COMPLETE.
            json!({ "shell": format!("test -d .git && test \"$(git rev-parse HEAD)\" = '{seed_head}'") }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({
            "prompt": "work in the repo",
            // The reserved envelope namespace: the worker assembles the
            // repository block from the `io.nanobpm.agentTask.*` variables.
            "io.nanobpm.agentTask.repository.url": repo_url,
            "io.nanobpm.agentTask.repository.ref": "main",
        }),
        &[],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "a provisioned job must complete; stderr:\n{}",
        outcome.stderr()
    );
    let record = outcome.record();
    // The agent ran INSIDE the provisioned checkout: its cwd is the clone and
    // the checkout carries a `.git`. The run dir is reaped on a successful
    // settle, so assert on the RECORDED cwd's shape (it must end in the
    // worker's `repo` checkout segment), not on the post-reap filesystem.
    let cwd = std::path::Path::new(&record.cwd);
    assert_eq!(
        cwd.file_name().and_then(|n| n.to_str()),
        Some("repo"),
        "the agent must run in the provisioned checkout (<run dir>/repo); cwd was {}",
        record.cwd
    );
    assert!(
        record.cwd.contains("agent-runs"),
        "the checkout lives under the worker's agent-runs root; cwd was {}",
        record.cwd
    );
    // The clone honoured the envelope's ref: the seeded default branch is
    // `main`, and the payload the agent received carries the repository block.
    let payload = outcome.payload();
    assert_eq!(
        payload["task"]["repository"]["url"].as_str().unwrap_or(""),
        repo_url,
        "payload: {payload:#}"
    );
}
