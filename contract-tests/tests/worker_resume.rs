//! **Checkpoint / resume**, **AgentInstance transcripts**, and the parity gaps
//! between the reference producer and the Rust port.
//!
//! When a worker is killed mid-job, a fresh worker picks the job up again once
//! the activation lapses, rather than starting from a clean slate. Along the way
//! the worker writes AgentInstance records — create and update, and the history
//! turns for a job. Needs a live engine; skips without one.
//!
//! The transcript half of this file is the **contract-first split of issue #59**:
//! the behaviour the Rust producer must grow is landed here as tests first, with
//! the Rust target (and, for the reference's own open bugs, the Node target too)
//! marked through the typed [`contract_tests::expect_parity`] gate. The parent
//! issue stays open until the Rust target passes with no marker.

use contract_tests::{
    assert_parity, bpmn, expect_parity, preassociate_agent_instance, require_engine_and_target,
    run_worker_against_instance, run_worker_job, run_worker_job_with_bpmn, skip, Skip, Target,
    TempHome,
};
use serde_json::{json, Value};

/// The `{role, content:[{contentType:"TEXT", text:…}, …]}` text of one history
/// turn, concatenated. `None` for a turn that carries no TEXT content.
fn turn_text(turn: &Value) -> Option<String> {
    let blocks = turn["content"].as_array()?;
    let text = blocks
        .iter()
        .filter(|b| b["contentType"].as_str() == Some("TEXT"))
        .filter_map(|b| b["text"].as_str())
        .collect::<Vec<_>>()
        .join("");
    (!text.is_empty()).then_some(text)
}

/// The roles present in a history, in order — the shape assertions read.
fn roles(history: &[Value]) -> Vec<String> {
    history
        .iter()
        .map(|t| t["role"].as_str().unwrap_or("?").to_string())
        .collect()
}

/// The AgentInstance for a process instance, or a helpful panic. Exactly one
/// producer-owned instance is expected per job.
fn sole_agent_instance(engine: &contract_tests::Engine, pik: &str, agent_stderr: &str) -> Value {
    let instances = engine.agent_instances(pik);
    assert_eq!(
        instances.len(),
        1,
        "the worker must mint exactly one AgentInstance for process instance {pik}; \
         the engine has {}.\nworker stderr:\n{agent_stderr}",
        instances.len()
    );
    instances.into_iter().next().unwrap()
}

/// The instance key as a string, tolerating the engine's numeric encoding.
fn instance_key(instance: &Value) -> String {
    instance["agentInstanceKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| instance["agentInstanceKey"].as_i64().map(|k| k.to_string()))
        .expect("an AgentInstance carries its key")
}

/// The durable transcript an agent job leaves behind: an ASSISTANT turn carrying
/// the agent's emitted text — the UPDATE path, on top of the create — plus the
/// fencing fields the engine records on every turn.
#[test]
fn job_writes_an_agent_instance_record() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let outcome = run_worker_job(
        &engine,
        &target,
        "resume-transcript",
        &[
            json!({ "emit": "transcript turn" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "record the transcript" }),
        &[],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "stderr:\n{}",
        outcome.stderr()
    );

    // The whole transcript half of the parity gap: something durable must exist
    // for the job. Rust has no producer at all (#59), so its marker gates every
    // assertion below in one place.
    let has_instance = !engine
        .agent_instances(&outcome.process_instance_key)
        .is_empty();
    assert_parity(
        expect_parity(
            target,
            (target == Target::Rust).then_some("nanobpm/nano-supervisor#59"),
            has_instance.then_some(()).ok_or_else(|| {
                format!(
                    "no AgentInstance for process instance {}",
                    outcome.process_instance_key
                )
            }),
        ),
        || {
            format!(
                "the worker must mint an AgentInstance for the job's process instance \
                 ({}); the engine has none.\nworker stderr:\n{}",
                outcome.process_instance_key,
                outcome.stderr()
            )
        },
    );
    // Return only when the instance is actually ABSENT (today's missing Rust
    // producer still XFAILs above). Never key this off the target: a partial
    // Rust producer that creates an empty or malformed instance must fall
    // through to the full contract below and fail there, not be reported as a
    // pass because the target-based return skipped validation.
    if !has_instance {
        return; // #59: no record to inspect yet — the marker above already said so.
    }

    let instance = sole_agent_instance(&engine, &outcome.process_instance_key, &outcome.stderr());
    let key = instance_key(&instance);
    let history = engine.agent_instance_history(&key);
    assert!(
        !history.is_empty(),
        "AgentInstance {key} has no history turns"
    );

    // The opening CONFIGURATION turn carries the job's system prompt and the
    // derived limits — the definition the engine exposes on the instance too.
    let config = history
        .iter()
        .find(|t| t["role"].as_str() == Some("CONFIGURATION"))
        .unwrap_or_else(|| panic!("no CONFIGURATION turn; history: {history:#?}"));
    let config_text = config["systemPrompt"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|b| b["text"].as_str())
        .collect::<Vec<_>>()
        .join("");
    assert!(
        config_text.contains("record the transcript"),
        "the CONFIGURATION turn must carry the job's system prompt; got {config_text:?}\n\
         history: {history:#?}"
    );
    assert!(
        config["limits"].is_object(),
        "the CONFIGURATION turn must carry the derived limits; got {:#?}",
        config["limits"]
    );
    assert!(
        config["jobKey"].is_string() && config["elementInstanceKey"].is_string(),
        "history turns are fenced by jobKey/elementInstanceKey; got jobKey={:?} eik={:?}",
        config["jobKey"],
        config["elementInstanceKey"]
    );

    // The UPDATE path: the agent's emitted text is appended as an ASSISTANT turn.
    let assistant = history
        .iter()
        .find(|t| t["role"].as_str() == Some("ASSISTANT"))
        .unwrap_or_else(|| {
            panic!(
                "the transcript must record the assistant turn (roles: {:?})\nhistory: {history:#?}",
                roles(&history)
            )
        });
    let text = turn_text(assistant).unwrap_or_default();
    assert!(
        text.contains("transcript turn"),
        "the ASSISTANT turn must carry the agent's emitted text; got {text:?}"
    );

    // The instance's own read model: a definition the reference derives from the
    // agent profile, and a metrics block (the reference's token metrics are
    // always zero — its recorded #289 parity gap — so only the shape is pinned).
    assert!(
        instance["definition"]["systemPrompt"].is_array(),
        "the instance definition carries the agent's system prompt; got {:#?}",
        instance["definition"]
    );
    // Require the metrics OBJECT and the key's presence: serde_json indexing
    // yields `Null` for an absent `metrics` or `modelCalls`, so a bare
    // `is_number() || is_null()` would pass vacuously on a missing block.
    let metrics = instance["metrics"].as_object().unwrap_or_else(|| {
        panic!(
            "the instance carries a metrics object; got {:#?}",
            instance["metrics"]
        )
    });
    let model_calls = metrics
        .get("modelCalls")
        .unwrap_or_else(|| panic!("the metrics block carries a modelCalls key; got {metrics:#?}"));
    assert!(
        model_calls.is_number() || model_calls.is_null(),
        "metrics.modelCalls is a number or explicit null; got {model_calls:#?}"
    );
}

/// While the process stays open, a conforming AgentInstance stays in an
/// **active** status: completion is owned by the engine, which completes the
/// instance only when the owning process instance ends
/// (jwulf/c8ctl-plugin-nano#274 — `updateAgentInstance` deliberately accepts
/// only active statuses and 422s a producer's `status:COMPLETED`). This is the
/// issue-#59 gate, the parity test that goes **green → red → green** for the
/// Rust port.
///
/// The process is gated (`bpmn::single_task_with_gate`: a parallel `userTask`
/// holds the instance ACTIVE after the agent job settles), so an engine
/// force-completion cannot mask what the producer did. The contract under test
/// is the producer's restraint: it must NOT send or retry the unsupported
/// terminal update (the pinned reference does — it 422s and logs "MANUAL
/// RECONCILIATION REQUIRED", observed live — that is its recorded #274 gap),
/// and the instance must read ACTIVE/non-terminal with no `completionDate`
/// while the process is open.
///
/// Markers: Rust = #59 (no producer at all). Node = the reference's own #274;
/// the marker drops when the pin moves to a plugin release carrying the #274
/// fix (issue #58) and the Node target passes.
#[test]
fn agent_instance_stays_active_while_the_process_stays_open() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    let job_type = engine.unique_type("resume-terminal");
    let process_id = format!("p-{job_type}");
    let outcome = run_worker_job_with_bpmn(
        &engine,
        &target,
        &job_type,
        &bpmn::single_task_with_gate(&process_id, &job_type),
        &[
            json!({ "emit": "terminal turn" }),
            json!({ "write_result": { "ok": true } }),
        ],
        json!({ "prompt": "settle me" }),
        &[],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "the agent job itself must settle regardless of the transcript; stderr:\n{}",
        outcome.stderr()
    );
    // The gate held: the process instance is still open, so the engine did NOT
    // complete the AgentInstance itself — whatever status the instance reads is
    // the producer's own doing. (If this is false the assertions below would be
    // vacuous — the engine's bookkeeping would own the status.)
    assert_eq!(
        engine.process_active(&outcome.process_instance_key),
        Some(true),
        "the gated process instance must stay ACTIVE after the agent job settles \
         (processInstanceKey {}); the gate did not hold, so the status assertions \
         below would be masked by process completion",
        outcome.process_instance_key
    );

    let gap = match target {
        Target::Rust => Some("nanobpm/nano-supervisor#59"),
        Target::Node => Some("jwulf/c8ctl-plugin-nano#274"),
    };
    let instances = engine.agent_instances(&outcome.process_instance_key);
    let restraint = match instances.first() {
        None => Err(format!(
            "no AgentInstance for process instance {} — the producer never created one",
            outcome.process_instance_key
        )),
        Some(instance) => {
            // Engine-owned completion (#274): while the process is open the
            // instance must read ACTIVE (non-terminal, no completionDate), and
            // the worker must not have sent/retried the unsupported
            // `status:COMPLETED` update — the pinned reference's 422 +
            // "MANUAL RECONCILIATION REQUIRED" is exactly that violation.
            let status = instance["status"].as_str().unwrap_or("");
            let completed = status == "COMPLETED" || instance["completionDate"].is_string();
            let reconciliation = outcome.stderr().contains("MANUAL RECONCILIATION REQUIRED");
            if completed {
                Err(format!(
                    "the AgentInstance must stay ACTIVE while the process is open — \
                     completion is engine-owned (#274); got status={status:?} \
                     completionDate={:?}",
                    instance["completionDate"]
                ))
            } else if reconciliation {
                Err(format!(
                    "the worker sent/retried the unsupported terminal AgentInstance update \
                     (#274: UPDATE rejects COMPLETED on a conforming engine); worker stderr:\n{}",
                    outcome.stderr()
                ))
            } else {
                Ok(())
            }
        }
    };
    assert_parity(expect_parity(target, gap, restraint), || {
        format!(
            "AgentInstance completion is engine-owned (#274): the producer must not \
             drive a terminal status on {target:?}; worker stderr:\n{}",
            outcome.stderr()
        )
    });
}

/// A second worker's `createAgentInstance` for an element instance the engine
/// has **already** associated must be **adopted**, not retried: the conflict is
/// permanent (`409 "element instance … is already associated with agent instance
/// …"`), so the worker must resume appending to the existing instance.
///
/// This is jwulf/c8ctl-plugin-nano#289. The harness pre-associates an instance
/// (issue #289's precondition — an element instance that already owns one), then
/// releases and lets the worker pick the job up. The pinned reference retries the
/// create futilely and then gives up with **no transcript recorded and no
/// diagnostic naming the failed precondition**, exactly the #289 report; a
/// reference carrying the fix adopts the harness instance and appends the
/// agent's turn to it.
///
/// Markers: Node = #289 (needs a plugin release past 1.70.2). Rust = #59 (no
/// producer at all).
#[test]
fn agent_instance_creation_conflict_is_adopted_not_retried() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };

    // A gated process keeps the element instance ACTIVE while the harness
    // associates it, so the later, competing create really does conflict.
    let job_type = engine.unique_type("resume-conflict");
    let process_id = format!("p-{job_type}");
    let xml = bpmn::single_task_with_gate(&process_id, &job_type);
    engine.deploy_bpmn(&process_id, &xml).expect("deploy bpmn");
    let instance = engine
        .create_instance(&process_id, json!({ "prompt": "adopt me" }))
        .expect("create instance");
    let pik = instance["processInstanceKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            instance["processInstanceKey"]
                .as_i64()
                .map(|k| k.to_string())
        })
        .expect("processInstanceKey");

    // Learn the element instance key by activating the job by hand, then
    // pre-associate an AgentInstance with it and release the activation so the
    // worker can pick the SAME element instance up.
    let activations: Value = engine
        .http()
        .post(format!("{}/v2/jobs/activation", engine.url()))
        .json(&json!({
            "type": job_type,
            "timeout": 600000,
            "maxJobsToActivate": 1,
            "worker": "contract-test-preassociation",
            "requestTimeout": 0,
        }))
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .expect("activate the job to learn its element instance key");
    let job = activations["jobs"]
        .as_array()
        .and_then(|jobs| jobs.first())
        .expect("the gated process has an activatable job");
    let element_instance_key = job["elementInstanceKey"]
        .as_str()
        .expect("the activated job carries elementInstanceKey");
    let job_key = job["jobKey"].as_str().expect("jobKey");
    let preassociated = preassociate_agent_instance(
        &engine,
        element_instance_key,
        job_key,
        "nano-lease:contract-test-preassociation",
        "pre-associated by the contract harness",
    );
    // Release the activation (retries preserved, no backoff) so the worker gets
    // the job and steps on the pre-associated element instance.
    engine
        .http()
        .post(format!("{}/v2/jobs/{job_key}/failure", engine.url()))
        .json(&json!({
            "retries": 3,
            "retryBackOff": 0,
            "errorMessage": "contract test: releasing the pre-association activation",
        }))
        .send()
        .and_then(|r| r.error_for_status())
        .expect("release the pre-association activation");

    // Run the worker against the SAME instance the harness just pre-associated —
    // never `run_worker_job_with_bpmn` here: that helper deploys the XML and
    // creates a SECOND process instance, enqueuing a duplicate job of the same
    // type the worker could settle instead, bypassing the 409 precondition this
    // test exists to pin while the assertions inspect the first instance.
    let home = TempHome::new();
    let outcome = run_worker_against_instance(
        &engine,
        &target,
        &home,
        None,
        &job_type,
        &pik,
        &[
            json!({ "emit": "adopted turn" }),
            json!({ "write_result": { "ok": true } }),
        ],
        &[],
        &[],
        "junior",
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "the job must settle whatever the transcript does; stderr:\n{}",
        outcome.stderr()
    );

    // Adopted, not orphaned: the pre-associated instance exists and the agent's
    // turn was appended to IT (the worker resumed the existing instance rather
    // than retrying a create it could never win). Marked with the reference's
    // own #289 for the Node target — the pinned reference retries the permanent
    // conflict and records nothing, observed live above — and with #59 for the
    // Rust target, which has no producer at all.
    let gap = match target {
        Target::Rust => Some("nanobpm/nano-supervisor#59"),
        Target::Node => Some("jwulf/c8ctl-plugin-nano#289"),
    };
    let instances = engine.agent_instances(&pik);
    let history = engine.agent_instance_history(&preassociated);
    let adopted_turn = history.iter().any(|t| {
        t["role"].as_str() == Some("ASSISTANT")
            && turn_text(t).is_some_and(|text| text.contains("adopted turn"))
    });
    let adopted = instances.iter().any(|i| instance_key(i) == preassociated);
    let check = match (adopted, adopted_turn) {
        (true, true) => Ok(()),
        (true, false) => Err(format!(
            "the worker adopted instance {preassociated} but did not append the agent's \
             turn to it (issue #289: the create is retried instead of adopted, or the \
             append is refused); history: {history:#?}"
        )),
        (false, _) => Err(format!(
            "the worker did not adopt the pre-associated instance {preassociated} \
             (issue #289); the process instance now has: {instances:#?}"
        )),
    };
    assert_parity(expect_parity(target, gap, check), || {
        format!(
            "AgentInstance creation conflicts must be adopted, not retried \
             (jwulf/c8ctl-plugin-nano#289).\nworker stderr:\n{}",
            outcome.stderr()
        )
    });
}

/// A job whose first worker is KILLED mid-run is picked up by a fresh worker
/// once the activation lapses, and runs to completion — observed at the engine
/// (the SAME job is redelivered, then completed) and at the agent (two runs:
/// the killed attempt and the redelivered one).
///
/// Scope note: this pins the engine REDELIVERY contract (same `jobKey`, full
/// retry budget, completion by the second attempt), not worker-side checkpoint
/// restore. The Rust worker deliberately wipes every prior-attempt run
/// directory before execution (`src/slot.rs` `execute`: "a retry starts from a
/// clean slate"), so attempt-local filesystem state is NOT carried over by
/// design; "resume" here means the engine hands the same job to a fresh worker,
/// which is exactly what the assertions below observe.
#[test]
fn killed_worker_job_resumes_not_restarts() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The kill/reactivate orchestration needs the scoped mid-run harness and a
    // worker that self-exits after one job; pinned for the Rust worker first
    // (the Node worker never self-exits, so this suite reaps it differently).
    if target != Target::Rust {
        skip!("kill/resume orchestration is pinned for the Rust worker first");
    }

    // One shared job type + instance across both phases: phase 1's worker is
    // killed mid-run; phase 2's fresh worker resumes THAT job.
    let job_type = engine.unique_type("resume-kill");
    let process_id = format!("p-{job_type}");
    engine
        .deploy_bpmn(
            &process_id,
            &contract_tests::bpmn::single_task(&process_id, &job_type),
        )
        .expect("deploy bpmn");
    let instance = engine
        .create_instance(&process_id, json!({ "prompt": "be killed, then resumed" }))
        .expect("create instance");
    let pik = instance["processInstanceKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            instance["processInstanceKey"]
                .as_i64()
                .map(|k| k.to_string())
        })
        .expect("processInstanceKey");

    // Phase 1: a worker picks the job up and is killed mid-run. The activation
    // (2s window) lapses with the dead refresher, so the engine redelivers.
    let (outcome1, ()) = contract_tests::with_worker_running_on(
        &engine,
        &target,
        &job_type,
        &pik,
        &[
            json!({ "sleep_ms": 30000 }),
            json!({ "emit": "first attempt" }),
            json!({ "write_result": { "attempt": 1 } }),
        ],
        &["--recovery-window", "2000"],
        &[],
        |run| {
            for _ in 0..50 {
                if run.agent_started() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            assert!(
                run.agent_started(),
                "the agent never started — there is no mid-run worker to kill"
            );
            run.kill_worker();
        },
    );
    // The killed worker never settled: the job is back to CREATED (or still
    // ACTIVATED until the deadline lapses) with its full retry budget.
    let job = engine.job(&job_type).expect("job exists");
    assert_ne!(
        job["state"].as_str().unwrap_or(""),
        "COMPLETED",
        "a killed worker must not complete the job: {job:#}"
    );
    // ...and with its FULL retry budget intact: a killed worker must not
    // settle the job from beyond the grave (a settle-fail would decrement
    // retries 3 → 2). Asserting the budget — not just non-completion —
    // distinguishes a true resume from a worker that wrongly failed the job
    // and let phase 2 complete it on a depleted budget.
    assert_eq!(
        job["retries"].as_i64().unwrap_or(-1),
        3,
        "a killed worker must preserve the full retry budget: {job:#}"
    );

    // Phase 2: a fresh worker (a new process, new activation) picks the SAME
    // job up once the lapsed deadline lets the engine redeliver it, and runs it
    // to completion. The first attempt's 30s sleep is replaced by an immediate
    // result so the resumed run finishes at once. The second worker is started
    // a beat after the kill so it does not long-poll in vain before the
    // activation lapses (its 30s poll outlasts the 2s lapse regardless).
    let (outcome2, ()) = contract_tests::with_worker_running_on(
        &engine,
        &target,
        &job_type,
        &pik,
        &[
            json!({ "emit": "resumed" }),
            json!({ "write_result": { "attempt": 2 } }),
        ],
        &["--recovery-window", "2000"],
        &[],
        |_| {},
    );
    assert_eq!(
        outcome2.job_state(),
        "COMPLETED",
        "the resumed job must complete; phase-1 stderr:\n{}\nphase-2 stderr:\n{}",
        outcome1.stderr(),
        outcome2.stderr()
    );
    assert_eq!(
        outcome2.variables()["attempt"],
        json!(2),
        "the resumed run's result is what completes the job"
    );
    // Two agent processes ran across the two attempts (the killed one and the
    // resumed one): each phase's record shows its own single run, and the
    // resumed run's prompt is the SAME job's payload (resume, not a new job).
    assert_eq!(outcome1.record().runs, 1, "phase 1 ran its agent once");
    assert_eq!(outcome2.record().runs, 1, "phase 2 ran its agent once");
    assert_eq!(
        outcome2.payload()["jobKey"].as_str().map(str::to_string),
        outcome1.payload()["jobKey"].as_str().map(str::to_string),
        "the resumed run is the SAME job, re-activated — not a fresh one"
    );
}
