//! Job in, agent input out — **prompt assembly**.
//!
//! The worker turns a job into the prompt the agent receives: the job's `prompt`
//! variable, linked prompts pulled with `get_resource_content`, and task
//! `secretRefs` resolved with `--secret-resolver host`. The agent-boundary shape
//! (an ACP text prompt) is checked in CI with the fake agent; the full assembly
//! is checked end-to-end against a live worker and skips when none is reachable.

use std::time::Duration;

use contract_tests::fake::FakeAgent;
use contract_tests::{require_engine_and_target, run_worker_job, skip, Skip};
use serde_json::json;

/// CI, no engine: the prompt the worker sends arrives at the agent intact as an
/// ACP text block (the shape `src/acp.rs` sends: `[{type:text,text}]`).
#[test]
fn prompt_reaches_agent_intact_over_acp() {
    let dir = tempfile::tempdir().unwrap();
    let rec = dir.path().join("record.json");
    let prompt = "line one\nline two\n\tindented — unicode ✓";
    let out = FakeAgent::new()
        .acp()
        .record_to(&rec)
        .emit("ok")
        .drive_acp(prompt, Duration::from_secs(5))
        .expect("acp turn");
    assert_eq!(out.text, "ok");
    let record = contract_tests::fake::FakeRecord::read(&rec);
    assert_eq!(record.first_prompt(), Some(prompt));
}

/// End-to-end: the job's `prompt` variable is what the agent is prompted with.
#[test]
fn job_prompt_variable_becomes_the_agent_prompt() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let prompt = "Reply with exactly SPIKE-OK";
    let outcome = run_worker_job(
        &engine,
        &target,
        "prompt-passthrough",
        &[
            json!({ "emit": "SPIKE-OK" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": prompt }),
        &[],
        &[],
    );
    // The agent is prompted with the JSON job payload (the Node plugin's
    // `buildAgentPayload`), carrying the job's `prompt` both at the top level
    // and inside the normalised task envelope.
    let payload = outcome.payload();
    assert_eq!(payload["prompt"], prompt, "payload: {payload:#}");
    assert_eq!(
        payload["task"]["task"]["prompt"], prompt,
        "payload: {payload:#}"
    );
    assert_eq!(payload["task"]["schemaVersion"], 1, "payload: {payload:#}");
    assert_eq!(payload["jobType"], outcome.job_type.as_str());
    assert_eq!(payload["variables"]["prompt"], prompt);
    assert!(payload["jobKey"].is_string(), "payload: {payload:#}");
    assert_eq!(payload["profile"]["rank"], "junior", "payload: {payload:#}");
}

/// A `linkName: prompt` linked resource is fetched from the engine and becomes
/// the agent's base prompt, winning over the header-baked `task.prompt`. The
/// resource is a real deployed text resource; the worker resolves it with
/// `get_resource_content` (`/v2/resources/{key}/content/binary`).
#[test]
fn linked_prompt_resource_becomes_the_agent_prompt() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The Rust worker has no linked-prompt fetch yet (it assembles the prompt
    // from the envelope only), so the linked-resource contract is pinned for
    // the Node target until the Rust worker grows `get_resource_content`.
    if target != contract_tests::Target::Node {
        skip!("linked-prompt fetch is deferred for the Rust worker");
    }
    // Deploy the prompt text as a real engine resource, then declare it on the
    // task via the `linkedResources` header the engine resolves at activation.
    let resource_key = engine
        .deploy_resource(
            "ct-prompt.txt",
            "LINKED-PROMPT: reply with exactly LINKED-OK",
        )
        .expect("deploy prompt resource");
    let linked = serde_json::json!([{
        "resourceKey": resource_key,
        "resourceType": "file",
        "linkName": "prompt",
    }])
    .to_string();
    let outcome = contract_tests::run_worker_job_with(
        &engine,
        &target,
        &contract_tests::TempHome::new(),
        "prompt-linked",
        &[
            json!({ "emit": "LINKED-OK" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "HEADER-PROMPT (should be overridden)" }),
        &[],
        &[],
        &[("linkedResources", &linked)],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );
    // The linked resource's content — not the header-baked prompt — is what the
    // agent was prompted with.
    let payload = outcome.payload();
    assert_eq!(
        payload["prompt"].as_str().unwrap_or(""),
        "LINKED-PROMPT: reply with exactly LINKED-OK",
        "the linked resource must supply the base prompt; payload: {payload:#}"
    );
}

/// A task `secretRefs` entry that the host resolver cannot supply FAILS the job
/// (a provisioning failure, retries decremented) rather than running the agent
/// without its secret.
#[test]
fn missing_secret_ref_fails_the_job() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The Rust worker does not resolve `secretRefs` yet (no `--secret-resolver`
    // handling), so the missing-secret settlement is pinned for the Node target.
    if target != contract_tests::Target::Node {
        skip!("secretRef resolution is deferred for the Rust worker");
    }
    let outcome = run_worker_job(
        &engine,
        &target,
        "prompt-secret-missing",
        &[
            json!({ "emit": "should not run" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({
            "prompt": "needs a secret",
            "io.nanobpm.agentTask.setup.secretRefs": ["CT_DEFINITELY_MISSING_SECRET"],
        }),
        &[],
        &[],
    );
    // The job must NOT complete: the worker fails it as a provisioning error,
    // consuming one retry (3 → 2), and the agent never runs.
    let job = outcome.settled_job();
    assert_ne!(
        job["state"].as_str().unwrap_or(""),
        "COMPLETED",
        "a job with an unresolvable secretRef must never complete: {job:#}"
    );
    assert_eq!(
        job["retries"].as_i64().unwrap_or(-1),
        2,
        "the missing-secret failure consumes one retry: {job:#}"
    );
    assert!(
        !outcome.record_exists(),
        "the agent must not run when its secretRef cannot be resolved"
    );
}

/// The dual of the missing-secret case: a `secretRefs` entry the host resolver
/// CAN supply (it is in the worker's process environment) lets the job run to
/// completion.
#[test]
fn resolvable_secret_ref_lets_the_job_run() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target != contract_tests::Target::Node {
        skip!("secretRef resolution is deferred for the Rust worker");
    }
    let outcome = run_worker_job(
        &engine,
        &target,
        "prompt-secret-ok",
        &[
            json!({ "emit": "ran with the secret" }),
            // Gate completion on the agent process actually SEEING the resolved
            // secret: the host resolver must forward CT_PRESENT_SECRET's value
            // into the agent's environment under its ref name. A resolver that
            // validates presence but drops the value fails this `test` (which
            // aborts the turn), so `write_result` never runs and the job cannot
            // COMPLETE — proving forwarding, not merely non-blocking resolution.
            json!({ "shell": "test \"$CT_PRESENT_SECRET\" = 's3cr3t-value'" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({
            "prompt": "needs a secret",
            "io.nanobpm.agentTask.setup.secretRefs": ["CT_PRESENT_SECRET"],
        }),
        &["--secret-resolver", "host"],
        // The host resolver reads the worker's process env, so provide it there.
        &[("CT_PRESENT_SECRET", "s3cr3t-value")],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "a resolvable secretRef must let the job run; stderr:\n{}",
        outcome.stderr()
    );
    assert!(outcome.record_exists(), "the agent ran");
}
