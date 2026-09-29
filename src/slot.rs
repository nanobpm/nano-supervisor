//! A daemon slot: one capacity-1 worker that services a hire's whole
//! rank×capability job-type matrix, one job at a time.
//!
//! A slot is a single tokio task that round-robins its job types (so capacity is
//! naturally one — while it runs an agent it polls nothing). It reuses the
//! spike's leased activation + lease-refresh fencing ([`crate::jobs`],
//! [`crate::worker::refresh_loop`]) and adds the MVP job handling the daemon
//! needs: prompt assembly, repo clone, ACP/pipe execution, and result parsing.
//!
//! The per-job execution runs on its own spawned task so a panic in one slot
//! fails only that job — the slot loop catches the join error, fails the job
//! (preserving retries), and carries on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use camunda_orchestration_sdk::models::ActivatedJobResult;
use serde_json::{json, Map, Value};
use tokio::sync::watch;

use crate::acp::Agent;
use crate::envelope::{self, Envelope};
use crate::jobs::{Job, Jobs};
use crate::result;
use crate::state::{Hire, Protocol};
use crate::worker::{log, refresh_loop};

/// Everything a slot needs, shared (via `Arc`) across its per-job tasks.
#[derive(Debug, Clone)]
pub struct SlotConfig {
    pub hire: Hire,
    /// The worker name reported to the engine — distinct from the Node
    /// supervisor's so the daemon's jobs can be told apart.
    pub worker_name: String,
    /// The hire's job-type matrix, polled round-robin.
    pub job_types: Vec<String>,
    pub recovery_window: Duration,
    pub idle_timeout: Duration,
    pub poll_timeout: Duration,
    pub clone_timeout: Duration,
    pub runs_dir: PathBuf,
    pub with_lease: bool,
}

/// Run the slot until `shutdown` is set. Never returns an error — a slot is
/// resilient, logging and retrying transient failures — so one wedged engine
/// can't take the daemon down.
pub async fn run(
    jobs: Jobs,
    cfg: Arc<SlotConfig>,
    mut shutdown: watch::Receiver<bool>,
    fatal: watch::Sender<bool>,
) {
    log(&format!(
        "slot {} up: types {:?} (recovery {}s, poll {}s, idle {}s, lease {}, protocol {:?})",
        cfg.worker_name,
        cfg.job_types,
        cfg.recovery_window.as_secs(),
        cfg.poll_timeout.as_secs(),
        cfg.idle_timeout.as_secs(),
        if cfg.with_lease { "on" } else { "off" },
        cfg.hire.protocol,
    ));
    let mut next = 0usize;
    loop {
        if *shutdown.borrow() {
            log(&format!("slot {} draining", cfg.worker_name));
            return;
        }
        let job_type = &cfg.job_types[next % cfg.job_types.len()];
        next = next.wrapping_add(1);

        let batch = tokio::select! {
            b = jobs.activate(job_type, &cfg.worker_name, cfg.recovery_window, cfg.poll_timeout, cfg.with_lease) => b,
            _ = shutdown.changed() => continue,
        };
        let batch = match batch {
            Ok(b) => b,
            Err(e) => {
                log(&format!(
                    "slot {} activation of {job_type:?} failed: {e:#}; retrying in 5s",
                    cfg.worker_name
                ));
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        for job in batch {
            if cfg.with_lease && job.lease.is_none() {
                // The CLI's `--with-lease` contract is to fail LOUDLY when the
                // engine does not issue leases (see the flag's help). Merely
                // skipping would leave the activation to expire and be
                // re-delivered forever — a silent spin that never fences. If the
                // engine returns an unleased activation here it will do so for
                // every job, so the requested fencing is impossible: shut the
                // whole daemon down loudly instead of running on unfenced.
                log(&format!(
                    "slot {}: job {} activated without a lease token under --with-lease; the engine \
                     is not issuing leases, so the requested fencing is impossible — shutting the \
                     daemon down instead of running unfenced",
                    cfg.worker_name,
                    job.job.job_key.value()
                ));
                let _ = fatal.send(true);
                return;
            }
            handle(&jobs, &cfg, job).await;
        }
    }
}

/// Decide whether a raced job outcome is still ours to settle.
///
/// [`handle`] races job execution against activation loss with `select!`. That
/// macro can pick the completed-`exec` branch (`Some(..)`) even when the
/// refresher set the loss watch to `true` in the same tick, so the raw outcome
/// must be downgraded to "lost" (`None`) whenever the activation was fenced —
/// otherwise a job would be `complete`/`fail`ed with a stale lease after a
/// 404/409. Keyed only on the post-select watch value, so it is pure/testable.
fn reconcile_lost<T>(outcome: Option<T>, lost: bool) -> Option<T> {
    if lost {
        None
    } else {
        outcome
    }
}

async fn handle(jobs: &Jobs, cfg: &Arc<SlotConfig>, Job { job, lease }: Job) {
    let key = job.job_key.value().to_string();
    let started = Instant::now();
    // Validate the engine-supplied key BEFORE it is used to build any request
    // path. The refresher below (`extend`) and the `complete`/`fail` settle all
    // interpolate it into `/jobs/{key}` on the Nano backend, so a malformed key
    // must be rejected up front — and an activation we cannot even address must
    // not be settled. Drop it and let the engine redeliver.
    if let Err(e) = crate::jobs::validate_job_key(&key) {
        log(&format!(
            "job {key}: refusing malformed engine key ({e:#}); not spawning refresher and not settling"
        ));
        return;
    }
    log(&format!(
        "job {key} activated on {} (type {}, retries {}, lease {})",
        cfg.worker_name,
        job.r#type,
        job.retries,
        lease.as_deref().unwrap_or("none")
    ));

    // Keep the activation alive while the agent works; a 404/409 fences us out.
    let refreshes = Arc::new(AtomicUsize::new(0));
    let (lost_tx, mut lost_rx) = watch::channel(false);
    let refresher = tokio::spawn(refresh_loop(
        jobs.clone(),
        key.clone(),
        lease.clone(),
        cfg.recovery_window,
        refreshes.clone(),
        lost_tx,
    ));

    // Run the job on its own task so a panic fails only THIS job (the slot loop
    // survives). Race it against activation loss so a superseded worker stops.
    let mut exec = tokio::spawn(execute(cfg.clone(), key.clone(), job.clone()));
    let raced = tokio::select! {
        r = &mut exec => Some(match r {
            Ok(inner) => inner,
            Err(join) => Err(anyhow::anyhow!(
                "slot task for job {key} panicked: {join}"
            )),
        }),
        // Drop the watch guard immediately; the abort/await happens below.
        _ = lost_rx.wait_for(|lost| *lost) => None,
    };
    // Re-check the activation-loss watch after the select. `select!` can pick the
    // `exec` branch even when the refresher set `lost` to true in the same tick
    // (both futures are ready), which would otherwise settle the job with a stale
    // lease after a 404/409 fence. Downgrade an outcome to "lost" whenever the
    // activation was fenced, so we never `complete`/`fail` a job we no longer own.
    let outcome = reconcile_lost(raced, *lost_rx.borrow());
    if outcome.is_none() {
        // We lost the activation: actually stop the agent instead of detaching
        // the task. Aborting drops the execute future, whose child processes are
        // spawned `kill_on_drop`, so the clone/agent tree is torn down before we
        // return.
        exec.abort();
        let _ = exec.await;
    }
    refresher.abort();
    let elapsed = started.elapsed().as_secs_f32();
    let n = refreshes.load(Ordering::Relaxed);

    match outcome {
        None => log(&format!(
            "job {key}: activation lost after {elapsed:.1}s; agent stopped, job NOT settled (the engine will redeliver it)"
        )),
        Some(Ok(vars)) => match jobs.complete(&key, vars, &lease).await {
            Ok(()) => log(&format!(
                "job {key} completed in {elapsed:.1}s (refreshes={n})"
            )),
            Err(e) => log(&format!("job {key}: complete failed: {e:#}")),
        },
        Some(Err(e)) => {
            let msg = format!("{e:#}");
            let retries = (job.retries - 1).max(0);
            match jobs.fail(&key, retries, &truncate(&msg, 2000), &lease).await {
                Ok(()) => log(&format!(
                    "job {key} failed after {elapsed:.1}s (refreshes={n}, retries left {retries}): {msg}"
                )),
                Err(e2) => log(&format!(
                    "job {key}: fail failed: {e2:#} (original error: {msg})"
                )),
            }
        }
    }
}

/// Restrict a directory to owner-only access (mode 0700) on Unix, so job data
/// placed under the shared temp directory is not readable/traversable by other
/// local users. A no-op on non-Unix platforms and when the path is absent.
fn restrict_dir_mode(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if dir.exists() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("restricting permissions on {}", dir.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Bail when `dir` (or the runs root above it) is a symlink. The check/remove/
/// create sequence in [`execute`] is not atomic: another local process can swap
/// a numeric job dir — or the runs root — for a symlink between operations, so
/// the agent cwd and `restrict_dir_mode` would otherwise target a path outside
/// `runs_dir`. `symlink_metadata` inspects the link itself rather than
/// following it, so a dangling or replaced link is still caught.
fn reject_symlink(dir: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!(
            "refusing to use symlinked path {} (possible local symlink attack)",
            dir.display()
        );
    }
    Ok(())
}

/// Bail when any *existing ancestor* of `dir` is a symlink. [`reject_symlink`]
/// only inspects the leaf `runs_dir` / `run_dir`, but `create_dir_all` follows a
/// symlinked ancestor: if a configurable `--runs-dir` (or an `$XDG_STATE_HOME`
/// state root) is missing under a world-writable parent, another local user can
/// pre-create a symlinked ancestor so the job directory is materialised outside
/// the intended root — and the leaf check cannot see it, because the final path
/// is then a real directory at the redirected location. Walking every existing
/// ancestor and rejecting the first symlink refuses that redirection before we
/// create or touch job data. A non-existent ancestor (`symlink_metadata` errors)
/// is skipped: `create_dir_all` will materialise it as a fresh real directory,
/// not follow a link. Paired with the leaf [`reject_symlink`] and re-run after
/// the non-atomic create, this closes the whole chain to symlink redirection.
fn reject_symlinked_ancestors(dir: &Path) -> Result<()> {
    for ancestor in dir.ancestors() {
        if std::fs::symlink_metadata(ancestor)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            bail!(
                "refusing to use {}: ancestor {} is a symlink (possible local symlink attack)",
                dir.display(),
                ancestor.display()
            );
        }
    }
    Ok(())
}

/// Prepare a per-job run directory under `runs_dir` with the full symlink and
/// permission hardening, wiping any stale prior-attempt contents. Shared by the
/// daemon slot path ([`execute`]) and the `spike` worker path so both get
/// identical protection: reject a symlinked leaf / ancestor before *and* after
/// the non-atomic remove+create (a local process can swap the fresh dir for a
/// link in between), then restrict both the runs root and the job dir to 0700 so
/// the clone, prompt-derived files, and `result.json` are not readable by other
/// local users regardless of umask — this still matters when `runs_dir` falls
/// back to a shared system temp location.
pub(crate) fn prepare_run_dir(runs_dir: &Path, run_dir: &Path) -> Result<()> {
    reject_symlink(runs_dir)?;
    reject_symlink(run_dir)?;
    reject_symlinked_ancestors(run_dir)?;
    if run_dir.exists() {
        std::fs::remove_dir_all(run_dir)
            .with_context(|| format!("clearing stale {}", run_dir.display()))?;
    }
    std::fs::create_dir_all(run_dir).with_context(|| format!("creating {}", run_dir.display()))?;
    reject_symlink(runs_dir)?;
    reject_symlink(run_dir)?;
    reject_symlinked_ancestors(run_dir)?;
    restrict_dir_mode(runs_dir)?;
    restrict_dir_mode(run_dir)?;
    Ok(())
}

/// Redact any embedded userinfo (`user:token@`) from a URL's authority before
/// logging it. A repository URL from the task envelope may carry an HTTPS
/// credential (`https://x-access-token:<pat>@host/...`); logging it verbatim
/// would leak the secret into the daemon's stdout/journal. Every `scheme://…`
/// occurrence in the string is stripped — not just the first — so a value
/// carrying two credential-bearing URLs (e.g. a prompt or task field) never
/// forwards the second token. Non-URL or credential-free inputs are returned
/// unchanged.
pub(crate) fn redact_url(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find("://") {
        let after = pos + 3;
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        // The authority runs until the first character that cannot be part of it
        // (path/query/fragment separators, or any whitespace/quoting that ends
        // the URL inside surrounding prose).
        let auth_end = tail
            .find(|c: char| {
                matches!(
                    c,
                    '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '|' | '\\' | '`'
                ) || c.is_whitespace()
            })
            .unwrap_or(tail.len());
        let authority = &tail[..auth_end];
        match authority.rfind('@') {
            Some(at) => out.push_str(&authority[at + 1..]),
            None => out.push_str(authority),
        }
        rest = &tail[auth_end..];
    }
    out.push_str(rest);
    out
}

async fn execute(
    cfg: Arc<SlotConfig>,
    key: String,
    job: ActivatedJobResult,
) -> Result<HashMap<String, Value>> {
    let custom_headers: Map<String, Value> = job.custom_headers.clone().into_iter().collect();
    let variables: Map<String, Value> = job.variables.clone().into_iter().collect();
    let env = envelope::assemble(&custom_headers, &variables);
    let prompt = env
        .prompt
        .clone()
        .filter(|p| !p.trim().is_empty())
        .context("job carries no prompt (task.prompt / prompt / task)")?;

    // Per-job working directory; the repo (when present) is cloned inside it.
    // The dir is keyed by job key and so is reused across retries — wipe any
    // prior attempt's checkout and stale `result.json` first, so a retry starts
    // from a clean slate (a leftover clone would fail provisioning, and a stale
    // result could be accepted as this attempt's result).
    //
    // Validate the key against the engine's numeric format *before* joining it to
    // a path: `key` originates from the engine response, and a malformed `../` or
    // absolute key would otherwise make `remove_dir_all` / `create_dir_all`
    // operate outside `runs_dir`.
    crate::jobs::validate_job_key(&key)?;
    // Resolve to an absolute path so a relative `--runs-dir` cannot break the
    // daemon↔agent result-file contract: the child runs with `cwd` set inside
    // `run_dir`, so a relative `AGENT_RESULT_FILE` would resolve against the
    // child's cwd while the daemon reads it against its own — the completion
    // would be silently missed. `std::path::absolute` is purely lexical (it does
    // not touch the filesystem or resolve symlinks), so the symlink-rejection
    // hardening in `prepare_run_dir` still inspects the real on-disk structure.
    let run_dir = std::path::absolute(cfg.runs_dir.join(&key))
        .with_context(|| format!("resolving absolute run dir under {}", cfg.runs_dir.display()))?;
    // Reject symlinked runs root / job dir / ancestors, wipe any stale prior
    // attempt, (re-)create the dir, and lock it to owner-only 0700 — the full
    // hardening lives in one shared helper (also used by the `spike` path).
    prepare_run_dir(&cfg.runs_dir, &run_dir)?;
    let agent_cwd = match &env.repository {
        Some(repo) => {
            log(&format!(
                "job {key}: cloning {} ({})",
                redact_url(&repo.url),
                repo.provider
            ));
            crate::provision::provision(repo, &run_dir, cfg.clone_timeout)
                .await
                .context("provisioning repository")?
        }
        None => run_dir.clone(),
    };

    let result_file = run_dir.join("result.json");
    let agent_env = build_agent_env(&cfg, &key, &job, &result_file);

    let (result_obj, detect_stdout) = match cfg.hire.protocol {
        Protocol::Acp => {
            // The pipe payload is recursively credential-scrubbed in
            // `build_pipe_payload`, but the ACP branch forwards the prompt
            // verbatim. A prompt carrying a `user:token@` clone URL would
            // otherwise leak the PAT to the ACP agent (and its tools/results),
            // so scrub the prompt with the same URL redactor before `run_acp`.
            let safe_prompt = redact_url(&prompt);
            run_acp(&cfg, &key, &agent_cwd, &safe_prompt, &result_file, &agent_env).await?
        }
        Protocol::Pipe => {
            run_pipe(&cfg, &key, &agent_cwd, &env, &job, &result_file, &agent_env).await?
        }
    };

    // A run that produced nothing did no work — fail it (retries preserved)
    // rather than silently complete and drop what the job carried.
    if let Some(reason) = result::detect_empty(result_obj.as_ref(), &detect_stdout) {
        bail!(reason);
    }

    // Build the completion variables: the agent's sanitized result vars plus the
    // host-owned bookkeeping the harness always stamps.
    let mut vars: HashMap<String, Value> = result_obj
        .as_ref()
        .map(result::sanitize_result_vars)
        .unwrap_or_default();
    // If the agent returned no effective structured result but still produced
    // substantive output, surface that output as `agentResult` (as the spike
    // worker does) instead of silently completing with only bookkeeping and
    // dropping the agent's response. This applies to BOTH protocols. The
    // empty-result guard above already failed runs that did NOTHING, so
    // reaching here with non-empty `detect_stdout` means real work to preserve.
    let has_effective = result_obj
        .as_ref()
        .is_some_and(result::has_effective_result_vars);
    if !has_effective && !detect_stdout.trim().is_empty() {
        vars.insert("agentResult".into(), json!(detect_stdout));
    }
    vars.insert("agentWorker".into(), json!(cfg.worker_name));
    // Reap this job's run directory now that its result has been fully captured
    // (result vars are already parsed into memory above). Without this, a
    // long-running daemon would accumulate one per-job clone per completed job —
    // job keys are unique, so nothing else ever removes them — until the runs
    // filesystem fills. Only *successful* runs are reaped here: a failing run
    // bails earlier via `?`, leaving its directory in place for post-mortem
    // inspection. Best-effort: a reap failure must not fail an otherwise-good job.
    if let Err(e) = std::fs::remove_dir_all(&run_dir) {
        log(&format!(
            "job {key}: failed to reap run dir {}: {e:#}",
            run_dir.display()
        ));
    }
    Ok(vars)
}

/// Drive an ACP harness: send the prompt, collect the message text, and read any
/// structured result the agent also wrote/printed.
async fn run_acp(
    cfg: &SlotConfig,
    key: &str,
    cwd: &std::path::Path,
    prompt: &str,
    result_file: &std::path::Path,
    env: &[(String, String)],
) -> Result<(Option<Map<String, Value>>, String)> {
    let mut agent = Agent::spawn(&cfg.hire.command, &cfg.hire.args, cwd, env)?;
    log(&format!(
        "job {key}: acp agent pid {} in {}",
        agent.pid().unwrap_or(0),
        cwd.display()
    ));
    let out = agent.run(cwd, prompt, cfg.idle_timeout).await;
    agent.shutdown().await;
    let out = out?;
    // Prefer the result file, then a `::nano:result::` sentinel in the message text.
    let result_obj = result::read_result_file(result_file)
        .or_else(|| result::parse_result_from_stdout(&out.text));
    Ok((result_obj, out.text))
}

/// Drive a pipe harness: feed it the JSON job payload on stdin and scrape its
/// stdout / result file for a structured result.
async fn run_pipe(
    cfg: &SlotConfig,
    key: &str,
    cwd: &std::path::Path,
    env: &Envelope,
    job: &ActivatedJobResult,
    result_file: &std::path::Path,
    agent_env: &[(String, String)],
) -> Result<(Option<Map<String, Value>>, String)> {
    let payload = build_pipe_payload(cfg, job, env);
    log(&format!("job {key}: pipe agent in {}", cwd.display()));
    let out = crate::pipe::run(
        &cfg.hire.command,
        &cfg.hire.args,
        cwd,
        agent_env,
        &payload,
        cfg.idle_timeout,
    )
    .await?;
    if out.idle_timed_out {
        bail!(
            "agent produced no output for {}s (idle timeout)",
            cfg.idle_timeout.as_secs()
        );
    }
    let result_obj = result::read_result_file(result_file)
        .or_else(|| result::parse_result_from_stdout(&out.stdout));
    // The harness must have exited cleanly (code 0) for its output to be trusted.
    match out.exit_code {
        // Clean exit: nothing to gate on here (empty-result is handled below).
        Some(0) => {}
        // A non-zero exit means the run failed. Only tolerate it when the agent
        // still emitted an *effective* structured result (a real result var in
        // the result file or stdout sentinel) — a reserved-only/null object such
        // as `::nano:result:: {}` carries no result, so honoring it would let
        // `detect_empty` mistake diagnostic stdout for real work and silently
        // settle a failed job. Require an effective result; otherwise fail so the
        // job is retried instead.
        Some(code) => {
            if !result_obj
                .as_ref()
                .is_some_and(result::has_effective_result_vars)
            {
                bail!("pipe agent exited with code {code} without writing an effective result");
            }
            log(&format!(
                "job {key}: pipe agent exited with code {code}; honoring the explicit result it wrote"
            ));
        }
        // No exit code at all: the child was killed by a signal or the EOF wait
        // timed out and we tore it down. The harness never exited successfully,
        // so any result it wrote may be partial/untrustworthy — never honor it;
        // fail the job so it is retried rather than settled on a broken run.
        None => {
            bail!(
                "pipe agent did not exit cleanly (killed by a signal or the EOF wait timed out); \
                 refusing to honor any result from a run that never terminated successfully"
            );
        }
    }
    // The pipe path has no "turns"; substantive stdout is the work signal.
    Ok((result_obj, out.stdout))
}

/// The JSON payload a pipe harness reads on stdin (the Node plugin's
/// `buildAgentPayload` shape).
fn build_pipe_payload(cfg: &SlotConfig, job: &ActivatedJobResult, env: &Envelope) -> String {
    let variables: Map<String, Value> = job.variables.clone().into_iter().collect();
    let custom_headers: Map<String, Value> = job.custom_headers.clone().into_iter().collect();
    let mut payload = json!({
        "jobKey": job.job_key.value(),
        "jobType": job.r#type,
        "processInstanceKey": job.process_instance_key.value(),
        "elementInstanceKey": job.element_instance_key.value(),
        "elementId": job.element_id.value(),
        "bpmnProcessId": job.process_definition_id.value(),
        "prompt": env.prompt,
        "task": if env.raw.is_null() { Value::Null } else { env.raw.clone() },
        "variables": variables,
        "customHeaders": custom_headers,
        "profile": {
            "name": cfg.hire.name,
            "rank": cfg.hire.rank,
            "model": cfg.hire.model,
            "capabilities": cfg.hire.capabilities,
        },
    });
    // Strip clone-credential userinfo from any URL anywhere in the payload before
    // it reaches the agent's stdin. The task envelope (and the raw
    // variables/customHeaders it is assembled from) can carry a credential-bearing
    // repository URL (`https://x-access-token:<pat>@host/...`) that `provision`
    // deliberately supports for the clone. The agent already receives a checkout
    // and never needs that token, so forwarding it verbatim would only expose the
    // secret to the agent (and thus its result/exfiltration path). `redact_url`
    // is a no-op on any string without `scheme://user:secret@` userinfo, so
    // ordinary URLs, prose, and non-URL values pass through unchanged.
    redact_credential_urls(&mut payload);
    payload.to_string()
}

/// Recursively rewrite every string in `value` through [`redact_url`], stripping
/// embedded `user:secret@` userinfo from any credential-bearing URL while leaving
/// all other strings untouched.
fn redact_credential_urls(value: &mut Value) {
    match value {
        Value::String(s) => {
            let redacted = redact_url(s);
            if redacted != *s {
                *s = redacted;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_credential_urls),
        Value::Object(map) => map.values_mut().for_each(redact_credential_urls),
        _ => {}
    }
}

/// The daemon's own engine-connection credentials, read from its environment by
/// [`crate::profile`]. A coding agent never needs them, so they are stripped
/// from the inherited environment at every agent launch (`acp` and `pipe`) —
/// otherwise a daemon configured via ambient `CAMUNDA_*`/`ZEEBE_*` OAuth or
/// basic-auth secrets would expose those secrets to the agent, which could read
/// and exfiltrate them even with `NANO_AGENTIC=off`. The `NANO_AGENTIC_*`
/// credentials are stripped for the same reason: `NANO_AGENTIC=off` disables the
/// visibility channel but does not stop a host agent from reading an inherited
/// agentic token/secret out of its environment. Deployment secrets the agent
/// legitimately needs (e.g. its own GitHub credentials for push) are delivered
/// through the deliberate `hire.env` channel and are re-applied after this strip,
/// so an explicitly hired value is unaffected.
pub(crate) const SENSITIVE_DAEMON_ENV: &[&str] = &[
    "CAMUNDA_CLIENT_ID",
    "CAMUNDA_CLIENT_SECRET",
    "CAMUNDA_BASIC_AUTH_USERNAME",
    "CAMUNDA_BASIC_AUTH_PASSWORD",
    "ZEEBE_CLIENT_ID",
    "ZEEBE_CLIENT_SECRET",
    "ZEEBE_BASIC_AUTH_USERNAME",
    "ZEEBE_BASIC_AUTH_PASSWORD",
    "NANO_AGENTIC_TOKEN",
    "NANO_AGENTIC_SECRET",
    "NANO_AGENTIC_CREDENTIAL",
];

/// The environment every harness gets: the reserved `AGENT_*`/`NANO_*` vars, the
/// result-file path, the agentic off-switch, and the hire's own env last-but-one
/// (reserved vars always win).
fn build_agent_env(
    cfg: &SlotConfig,
    key: &str,
    job: &ActivatedJobResult,
    result_file: &std::path::Path,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    // Hire-configured env first, so reserved vars below can never be shadowed.
    for (k, v) in &cfg.hire.env {
        env.push((k.clone(), v.clone()));
    }
    env.push(("NANO_JOB_KEY".into(), key.to_string()));
    env.push(("NANO_AGENT_NAME".into(), cfg.worker_name.clone()));
    // MVP: the agentic visibility channel is off (host sandbox only).
    env.push(("NANO_AGENTIC".into(), "off".into()));
    env.push((
        "AGENT_RESULT_FILE".into(),
        result_file.to_string_lossy().into_owned(),
    ));
    env.push(("AGENT_PROFILE".into(), cfg.hire.name.clone()));
    env.push(("AGENT_RANK".into(), cfg.hire.rank.clone()));
    env.push(("AGENT_MODEL".into(), cfg.hire.model.clone()));
    env.push(("AGENT_CAPABILITIES".into(), cfg.hire.capabilities.join(",")));
    env.push(("AGENT_JOB_TYPE".into(), job.r#type.clone()));
    env
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hire() -> Hire {
        Hire {
            name: "coder".into(),
            rank: "senior".into(),
            command: "true".into(),
            args: vec![],
            model: "m".into(),
            capabilities: vec!["pr-review".into()],
            protocol: Protocol::Pipe,
            sandbox: "none".into(),
            env: Default::default(),
        }
    }

    fn cfg() -> SlotConfig {
        SlotConfig {
            hire: hire(),
            worker_name: "host-nanod-coder-0".into(),
            job_types: vec!["senior".into(), "senior:pr-review".into()],
            recovery_window: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(300),
            poll_timeout: Duration::from_secs(30),
            clone_timeout: Duration::from_secs(120),
            runs_dir: std::env::temp_dir(),
            with_lease: true,
        }
    }

    #[test]
    fn agent_env_has_reserved_and_off_switch() {
        let job = ActivatedJobResult {
            r#type: "senior:pr-review".into(),
            ..Default::default()
        };
        let rf = std::path::Path::new("/tmp/r.json");
        let env = build_agent_env(&cfg(), "42", &job, rf);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("NANO_AGENTIC"), Some("off"));
        assert_eq!(get("NANO_JOB_KEY"), Some("42"));
        assert_eq!(get("AGENT_RESULT_FILE"), Some("/tmp/r.json"));
        assert_eq!(get("AGENT_JOB_TYPE"), Some("senior:pr-review"));
        assert_eq!(get("AGENT_PROFILE"), Some("coder"));
    }

    #[test]
    fn sensitive_daemon_env_covers_engine_secrets() {
        // The daemon's engine-connection secrets must be in the strip list so a
        // launched agent never inherits them. `build_agent_env` never emits them
        // either (it only adds reserved + hire vars), so the leak can only come
        // from the inherited environment — which the launch sites strip via this
        // list.
        for k in [
            "CAMUNDA_CLIENT_SECRET",
            "ZEEBE_CLIENT_SECRET",
            "CAMUNDA_BASIC_AUTH_PASSWORD",
            // The SDK also accepts the `ZEEBE_*` aliases as an ambient
            // connection source (see `profile::env_has_oauth`), so basic-auth
            // credentials supplied that way must be stripped too.
            "ZEEBE_BASIC_AUTH_USERNAME",
            "ZEEBE_BASIC_AUTH_PASSWORD",
            // `NANO_AGENTIC=off` disables the channel but does not stop a host
            // agent reading an inherited agentic credential, so these must be
            // stripped too.
            "NANO_AGENTIC_TOKEN",
            "NANO_AGENTIC_SECRET",
            "NANO_AGENTIC_CREDENTIAL",
        ] {
            assert!(
                SENSITIVE_DAEMON_ENV.contains(&k),
                "{k} missing from SENSITIVE_DAEMON_ENV"
            );
        }
        let job = ActivatedJobResult::default();
        let env = build_agent_env(&cfg(), "1", &job, std::path::Path::new("/tmp/r.json"));
        for (k, _) in &env {
            assert!(
                !SENSITIVE_DAEMON_ENV.contains(&k.as_str()),
                "build_agent_env must never emit daemon secret {k}"
            );
        }
    }

    #[test]
    fn hire_env_cannot_shadow_reserved() {
        let mut c = cfg();
        c.hire.env.insert("NANO_AGENTIC".into(), "on".into());
        let job = ActivatedJobResult::default();
        let env = build_agent_env(&c, "1", &job, std::path::Path::new("/tmp/r.json"));
        // The reserved value is pushed AFTER the hire env, so it wins for any
        // consumer that reads the last occurrence (as a child process does).
        let last = env
            .iter()
            .rfind(|(k, _)| k == "NANO_AGENTIC")
            .map(|(_, v)| v.as_str());
        assert_eq!(last, Some("off"));
    }

    #[test]
    fn redact_url_strips_embedded_credentials() {
        assert_eq!(
            redact_url("https://x-access-token:ghp_secret@github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            redact_url("https://user:pw@host:8443/path?x=1"),
            "https://host:8443/path?x=1"
        );
        // No credentials / non-URL inputs are returned unchanged.
        assert_eq!(
            redact_url("https://github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            redact_url("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );
    }

    #[test]
    fn redact_url_strips_every_occurrence() {
        // A single string carrying two credential-bearing URLs must have BOTH
        // tokens stripped, not just the first (the field could be a prompt or a
        // task value forwarded to a pipe agent). Build the userinfo at runtime so
        // no credential-like literal is stored in source.
        let a = format!("{}:{}", "x-access-token", "tokenA1");
        let b = format!("{}:{}", "x-access-token", "tokenB2");
        let s = format!("clone https://{a}@h1/x.git then https://{b}@h2/y.git done");
        let out = redact_url(&s);
        assert!(!out.contains("tokenA1"), "first credential leaked: {out}");
        assert!(!out.contains("tokenB2"), "second credential leaked: {out}");
        assert!(out.contains("https://h1/x.git"));
        assert!(out.contains("https://h2/y.git"));
    }

    #[test]
    fn pipe_payload_redacts_repository_clone_credentials() {
        let cfg = cfg();
        let job = ActivatedJobResult::default();
        // Build the credential-bearing URL at runtime so no credential-like
        // literal is stored in source (mirrors the provision.rs tests).
        let token = format!("{}-{}", "x-access", "token");
        let secret = format!("pat{}value", 1234);
        let cred_url = format!("https://{token}:{secret}@github.com/o/r.git");
        let env = Envelope {
            prompt: Some("do it".into()),
            repository: None,
            raw: json!({ "repository": { "url": cred_url } }),
        };
        let payload = build_pipe_payload(&cfg, &job, &env);
        assert!(
            !payload.contains(&secret),
            "clone credential must not reach the agent payload: {payload}"
        );
        assert!(payload.contains("https://github.com/o/r.git"));
    }

    #[test]
    fn acp_prompt_is_redacted_of_clone_credentials() {
        // The ACP branch forwards the prompt verbatim, so a credential URL
        // embedded in a task prompt must be scrubbed by the same `redact_url`
        // path the pipe payload uses before it reaches the ACP agent. Build the
        // userinfo at runtime so no credential-like literal is stored in source.
        let token = format!("{}-{}", "x-access", "token");
        let secret = format!("pat{}value", 1234);
        let prompt = format!("clone https://{token}:{secret}@github.com/o/r.git and build");
        let safe_prompt = redact_url(&prompt);
        assert!(
            !safe_prompt.contains(&secret),
            "clone credential must not reach the ACP agent prompt: {safe_prompt}"
        );
        assert!(safe_prompt.contains("https://github.com/o/r.git"));
        assert!(safe_prompt.contains("and build"));
    }

    #[test]
    fn reconcile_lost_downgrades_completed_outcome_when_activation_lost() {
        // The core of the lease-loss/completion race fix: even a job whose
        // `exec` future completed (an `Ok`/`Err` outcome) must NOT be settled
        // once the activation-loss watch reads `true`, because `select!` can
        // pick the completed branch in the same tick the refresher fences us out
        // (404/409). Settling then would `complete`/`fail` with a stale lease.
        let completed: Option<Result<()>> = Some(Ok(()));
        assert!(
            reconcile_lost(completed, true).is_none(),
            "a completed outcome must be downgraded to lost when the activation was fenced"
        );
        let failed: Option<Result<()>> = Some(Err(anyhow::anyhow!("boom")));
        assert!(
            reconcile_lost(failed, true).is_none(),
            "a failed outcome must also be downgraded to lost when the activation was fenced"
        );
        // Not lost: the outcome passes through unchanged so a genuine completion
        // still settles.
        assert!(matches!(reconcile_lost(Some(Ok::<(), anyhow::Error>(())), false), Some(Ok(()))));
        // Already lost via the select's None branch stays lost.
        assert!(reconcile_lost(None::<Result<()>>, false).is_none());
    }
}
