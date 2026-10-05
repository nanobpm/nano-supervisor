//! Job in, agent input out — **the environment and working directory**.
//!
//! The worker hands the agent a working directory (with the repo provisioned)
//! and an environment: `AGENT_*` (`AGENT_RESULT_FILE`, `AGENT_MODEL`, …), `NANO_*`
//! and `NANO_AGENTIC_*`. The fake agent records exactly what it received.

use std::time::Duration;

use contract_tests::fake::FakeAgent;
use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip, Target};
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
/// directory IS the checkout (`<run dir>/<checkout>`, with a `.git`, where the
/// segment is target-specific — `workspace` for Node, `repo` for Rust). The
/// repo is a
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
    // Create a DISTINCT non-default branch at a distinct commit. Requesting this
    // branch (below) proves `repository.ref` is honoured: a worker that ignores
    // the field and performs a default clone lands on `main`'s HEAD, which is a
    // different commit than this branch's HEAD, so the seeded-commit gate fails
    // and the job cannot complete. HEAD is left back on `main` before the bare
    // clone so the origin's default branch stays `main` (not the requested ref).
    git(&seed, &["checkout", "-q", "-b", "ct-ref-target"]);
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
            "ref-target",
        ],
    );
    git(&seed, &["checkout", "-q", "main"]);
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
    // Pin the seeded commit on the NON-DEFAULT branch: the agent's script below
    // writes a successful result ONLY when its cwd is a real clone of this origin
    // at exactly this commit, so a worker that merely creates a `repo/` directory
    // (or clones the default `main` instead of the requested ref) can no longer
    // pass the test.
    let seed_head = {
        let out = std::process::Command::new("git")
            .args(["rev-parse", "ct-ref-target"])
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
            // Request the NON-DEFAULT branch so honouring `ref` is what lands the
            // seeded commit — a default clone would check out `main` and fail.
            "io.nanobpm.agentTask.repository.ref": "ct-ref-target",
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
    // worker's target-specific checkout segment), not on the post-reap
    // filesystem.
    let cwd = std::path::Path::new(&record.cwd);
    let checkout = target.checkout_dir_name();
    assert_eq!(
        cwd.file_name().and_then(|n| n.to_str()),
        Some(checkout),
        "the agent must run in the provisioned checkout (<run dir>/{checkout}); cwd was {}",
        record.cwd
    );
    assert!(
        record.cwd.contains("agent-runs"),
        "the checkout lives under the worker's agent-runs root; cwd was {}",
        record.cwd
    );
    // The clone honoured the envelope's ref: the requested branch is the
    // non-default `ct-ref-target`, and the payload the agent received carries
    // the repository block.
    let payload = outcome.payload();
    assert_eq!(
        payload["task"]["repository"]["url"].as_str().unwrap_or(""),
        repo_url,
        "payload: {payload:#}"
    );
}

/// #41, acceptance: an agent job runs with an ISOLATED c8ctl config dir, so an
/// agent's `c8 use profile X` can never rewrite the operator's
/// `~/.config/c8ctl/session.json` (the write that retargeted the production
/// fleet). The worker hands the agent a per-run `C8CTL_CONFIG_DIR` seeded with
/// exactly the pinned connection, and marks the run with `NANO_AGENT_RUN`.
#[test]
fn worker_isolates_the_agents_c8ctl_session() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target != Target::Rust {
        skip!("the isolated agent c8ctl session is the Rust worker's fix for issue #41");
    }
    // Run with `--keep-runs` so the run directory (and the agent's isolated
    // c8ctl config inside it) SURVIVES the successful run — otherwise the
    // worker reaps it before the assertions below and `session.exists()` is
    // vacuously false, so the test would pass even if the isolated dir was
    // never created or seeded. The agent also exercises a real write into the
    // isolated dir (via the `shell` step, which runs in the per-run cwd) to
    // prove it is a writable, agent-owned config root.
    let outcome = run_worker_job(
        &engine,
        &target,
        "c8ctl-isolation",
        &[
            json!({ "emit": "ok" }),
            json!({ "shell": "printf 'agent-was-here' > \"$C8CTL_CONFIG_DIR/agent-write.txt\"" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "note your environment" }),
        &["--keep-runs"],
        &[],
    );
    let record = outcome.record();
    let env = &record.env;

    // The agent's c8ctl is pointed INSIDE its own run dir — never at the
    // operator's global config — so its `c8 use profile` writes stay in the
    // run and the operator's session.json is untouched.
    let dir = env.get("C8CTL_CONFIG_DIR").unwrap_or_else(|| {
        panic!("worker must set C8CTL_CONFIG_DIR for the agent; env was {env:?}")
    });
    assert!(
        dir.contains("agent-runs"),
        "the agent's c8ctl config dir must live under the per-run tree, not the operator's ~/.config; got {dir}"
    );

    // Under `--keep-runs` the isolated dir MUST exist after the run — assert it
    // unconditionally (no `if exists`), so a worker that failed to create or
    // seed it fails the test rather than silently passing.
    let dir_path = std::path::Path::new(dir);
    assert!(
        dir_path.is_dir(),
        "the isolated c8ctl config dir must exist after a --keep-runs run: {dir}"
    );
    // The agent's own write landed inside the isolated dir, proving it is a
    // writable, agent-owned config root (not a read-only mount or a symlink
    // onto the operator's config).
    let agent_write = dir_path.join("agent-write.txt");
    assert_eq!(
        std::fs::read_to_string(&agent_write).expect("the agent's write must exist in its isolated c8ctl dir"),
        "agent-was-here",
        "the agent must be able to write inside its isolated c8ctl config dir"
    );

    // The seed, when there is one, is exactly the pinned connection: the
    // session's activeProfile and a profiles.json carrying only that profile,
    // so the agent's own `c8` sees the job's engine and nothing else. (This
    // engine-gated harness connects the worker via `CAMUNDA_REST_ADDRESS` — an
    // env-only pin — so there is no profile to seed and the isolated dir holds
    // only the agent's own write; the unit tests pin the seeded shape for a
    // profiled connection.)
    let session = dir_path.join("session.json");
    if session.exists() {
        let seeded: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&session).expect("read seeded session.json"),
        )
        .expect("seeded session.json is JSON");
        assert!(
            seeded["activeProfile"].is_string(),
            "the seeded session names the pinned profile: {seeded}"
        );
        let profiles: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(session.with_file_name("profiles.json"))
                .expect("read seeded profiles.json"),
        )
        .expect("seeded profiles.json is JSON");
        assert_eq!(
            profiles["profiles"].as_array().map(Vec::len),
            Some(1),
            "the agent's isolated config carries ONLY the pinned profile: {profiles}"
        );
    }
    // The run is marked as agent-owned (the issue-#40 sibling marker).
    assert!(
        env.get("NANO_AGENT_RUN").is_some_and(|v| !v.is_empty()),
        "worker must mark the agent run with NANO_AGENT_RUN; env was {env:?}"
    );
}
