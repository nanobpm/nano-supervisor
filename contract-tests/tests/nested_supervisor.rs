//! #40 — agent-spawned supervisors must not escape job teardown.
//!
//! The worker stamps `NANO_AGENT_RUN` on every agent's environment. Left
//! unguarded, an agent could start its own supervisor/worker and build an
//! unintended nested fleet that leases real jobs outside the job's lifecycle.
//! So when `NANO_AGENT_RUN` is set the command must refuse unless an explicit
//! test-only opt-in (`--foreground-for-tests` / `NANO_ALLOW_NESTED_SUPERVISOR=1`)
//! runs it attached instead.
//!
//! Contract: under a job (env `NANO_AGENT_RUN` set), starting the long-lived
//! supervisor/worker exits non-zero with an explanatory message and leaves **no**
//! surviving process — in particular, no daemon outlives the job (nor, for the
//! Node plugin, any bound control socket). This is the
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
/// non-zero with an explanatory message and leaves no surviving process, so
/// nothing from the run can outlive the job.
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
    // No separate survival probe is needed here: `.output()` above already waited
    // for the child to fully exit, and the Rust `daemon` subcommand refuses
    // synchronously (it never forks/`setsid`s — only the Node plugin daemonises),
    // so a non-zero exit from a process that has already terminated leaves nothing
    // behind. (A control-socket check would be meaningless for the Rust target,
    // which never binds the Node plugin's `supervisor.sock`.) The end-to-end test
    // below proves the same refusal through a real agent subprocess under a
    // worker job.
}

/// The guard is wired into the `work` entrypoint exactly as it is into `daemon`
/// (`src/main.rs` calls `guard_nested_supervisor` for both), but the test above
/// only ever invokes `daemon`. A regression that dropped the `work` call would
/// otherwise stay green and reopen nested workers. This is the black-box
/// counterpart for `work <hire>`: with `NANO_AGENT_RUN` set and no opt-in, the
/// command must refuse with the guard-specific diagnostic *before* it touches
/// config/engine startup — so it exits non-zero naming `NANO_AGENT_RUN` even
/// though no hire, config, or engine exists in the isolated home.
#[test]
fn work_refuses_to_start_inside_an_agent_run() {
    let target = Target::from_env();
    require_target!(target);
    if target == Target::Node {
        // The Node plugin's guard is tracked on the parent issue; the Rust port
        // owns the guard in this repository.
        eprintln!(
            "SKIP nested_supervisor::work_refuses_to_start_inside_an_agent_run: \
             the Node plugin guard is tracked separately"
        );
        return;
    }
    let home = TempHome::with_target(target);
    // `work <hire>` requires a positional hire; any value does, because the
    // guard fires before the hire is resolved against config.json.
    let out = home
        .cmd(&["work", "coder"])
        .env("NANO_AGENT_RUN", "214829")
        .env("NANO_AGENT_RUN_DIR", home.path().join("agent-runs/run-x"))
        .output()
        .expect("spawn nested worker");

    assert!(
        !out.status.success(),
        "a worker started inside an agent run must exit non-zero; got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NANO_AGENT_RUN"),
        "the work refusal must be the #40 guard's specifically (mention NANO_AGENT_RUN), \
         not an unrelated config/engine error; stderr was: {stderr}"
    );
    assert!(
        stderr.contains("work"),
        "the refusal must name the `work` command so the entrypoint is identifiable; \
         stderr was: {stderr}"
    );
}

/// End-to-end form of the issue #40 acceptance: a *real agent subprocess* — the
/// scripted fake agent, running under a worker job — attempts to start the
/// nested supervisor. The worker must have propagated `NANO_AGENT_RUN` into the
/// agent's environment, so the nested start refuses (the agent's shell gate
/// fails, the job FAILs rather than completing) and the daemon process exits
/// before it can detach. Unlike the direct-subprocess test above, this catches
/// a regression where the worker stops stamping the marker, and observes the
/// state the job leaves behind once the worker exits.
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

    // The agent runs in the worker's per-job run dir, not the suite's cwd, and
    // the hermetic env strips every `NS_*` selector (including `NS_BIN`) before
    // the worker starts — so a bare `"$NS_BIN"` in the agent's shell would expand
    // to an EMPTY command and fail for an unrelated reason, never exercising the
    // guard. Re-inject an ABSOLUTE binary path via `extra_env` so the nested
    // start actually runs the Rust daemon and is refused by the #40 guard.
    let ns_bin = std::env::var("NS_BIN").unwrap_or_else(|_| "target/debug/nano-supervisor".into());
    let ns_bin_abs = std::fs::canonicalize(&ns_bin)
        .unwrap_or_else(|e| panic!("cannot resolve the Rust binary at {ns_bin:?}: {e}"))
        .to_string_lossy()
        .into_owned();

    // The agent's shell captures the nested daemon's stderr into the suite's own
    // temp dir (an absolute path, so it resolves from the agent's cwd) — to
    // prove the refusal was the #40 guard's SPECIFICALLY (mentions
    // `NANO_AGENT_RUN`), not an unrelated failure like a missing binary or
    // "no hires".
    let probe_dir = tempfile::tempdir().expect("probe temp dir");
    let stderr_path = probe_dir.path().join("nested.stderr");
    let stderr_path_s = stderr_path.to_string_lossy().into_owned();

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
            // The daemon's stderr is captured (not discarded) so the assertions
            // can confirm the refusal is the #40 guard's, not an unrelated
            // error.
            json!({ "shell": "exec \"$NS_BIN\" daemon 2> \"$NS_NEST_STDERR\"" }),
            json!({ "write_result": { "nested_started": true } }),
        ],
        json!({ "prompt": "try to run a supervisor" }),
        &[],
        &[
            ("NS_BIN", ns_bin_abs.as_str()),
            ("NS_NEST_STDERR", stderr_path_s.as_str()),
        ],
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
    // The refusal must be the #40 guard's specifically — the captured daemon
    // stderr must name NANO_AGENT_RUN. Without this, a non-zero exit from any
    // unrelated cause (empty/missing binary, "no hires", a config error) would
    // masquerade as a successful refusal and the test would pass vacuously.
    let nested_stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        nested_stderr.contains("NANO_AGENT_RUN"),
        "the nested start must be refused by the #40 guard specifically — its \
         stderr must mention NANO_AGENT_RUN, not fail for an unrelated reason; \
         captured stderr was: {nested_stderr:?}"
    );
    // The issue's acceptance criterion is that NO process from the run
    // survives — a detached descendant could remain even while the job fails
    // and emits the refusal above. Probe for one directly, keyed on the run's
    // UNIQUE identity rather than a recorded PID: `NANO_AGENT_RUN` is the job
    // key (stamped by the worker, captured in the agent's env record), so any
    // process still carrying that exact marker in its environment after the
    // job settles is a survivor of THIS run. Unlike a delayed `kill -0` on a
    // recorded PID this is immune to PID reuse — it never trusts a number the
    // OS may have recycled to an unrelated live process.
    let run_marker = record
        .env
        .get("NANO_AGENT_RUN")
        .cloned()
        .expect("the worker must stamp NANO_AGENT_RUN (asserted above)");
    assert!(
        !run_marker.is_empty(),
        "the run identity must be a non-empty unique marker; got an empty NANO_AGENT_RUN"
    );
    let survivors = processes_with_env_marker("NANO_AGENT_RUN", &run_marker);
    assert!(
        survivors.is_empty(),
        "no process from the agent run may survive the settled job, but \
         {} still carry NANO_AGENT_RUN={run_marker} in their environment: {survivors:?}",
        survivors.len()
    );
    // `probe_dir` holds the captured stderr file; keep it alive until here.
    drop(probe_dir);
}

/// PIDs of every live process whose environment carries `name=value` exactly.
///
/// Linux-only scan of `/proc/<pid>/environ` (the contract suite's Linux CI is
/// where the end-to-end worker job runs); on any other platform — or if `/proc`
/// is unreadable — returns an empty Vec so the caller's "no survivors"
/// assertion stays a no-op rather than failing spuriously off Linux. The
/// current test process is excluded: it never carries the marker itself, but
/// the guard keeps the check honest if a future caller probes for a var the
/// suite DOES set. Best-effort by design: a process that exits mid-scan simply
/// fails a read and is skipped.
fn processes_with_env_marker(name: &str, value: &str) -> Vec<u32> {
    let needle = format!("{name}={value}");
    let self_pid = std::process::id();
    let mut hits = Vec::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return hits,
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        // environ is NUL-separated; an exact full-field match avoids a
        // substring false positive (e.g. marker "42" matching "...=421").
        if let Ok(env) = std::fs::read(entry.path().join("environ")) {
            if env
                .split(|b| *b == 0)
                .any(|field| field == needle.as_bytes())
            {
                hits.push(pid);
            }
        }
    }
    hits
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
