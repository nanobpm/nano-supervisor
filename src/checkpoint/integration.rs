//! Worker integration for the checkpoint port (nanobpm/nano-supervisor#66).
//!
//! Glues the pure checkpoint mechanics in [`super`] into [`crate::slot::execute`]:
//!
//!   - [`start`] builds an authenticated [`GitRunner`] on the provisioned
//!     checkout, decides eligibility, restores any predecessor/own checkpoint,
//!     kicks off the throttled orphan sweep, and spawns a periodic background
//!     checkpointer. It returns the restored-prompt note plus a [`CheckpointGuard`].
//!   - The guard runs a periodic snapshot→push loop so a checkpoint survives an
//!     abrupt interruption (crash / SLA cancel / `stop --force`) even when the
//!     job future is aborted without reaching settlement. [`CheckpointGuard::finish`]
//!     stops the loop and either deletes the WIP ref (success) or leaves the last
//!     checkpoint (and a GC-proof recovery ref) in place for a resumed run.
//!
//! Everything is BEST-EFFORT: a failure is logged and degrades to transcript-only
//! resume. It never fails the job.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tokio::sync::Notify;

use super::{
    checkpoint_eligibility, checkpoint_ref, checkpoint_restored_note, credentials_from_url,
    delete_checkpoint_ref, fetch_checkpoint, is_authenticated_remote, normalize_secret_values,
    observe_remote_ref_sha, orphan_decision, predecessor_checkpoint_ref, push_checkpoint,
    push_named_ref, recovered_checkpoint_ref, restore_checkpoint, resume_ref_is_explicit,
    snapshot_worktree, sweep_stale_checkpoints, CheckpointConfig, GitRunner, OrphanProbe,
    PushResult, Snapshot,
};
use crate::jobs::Jobs;
use crate::safecwd::CwdHandle;

const SNAPSHOT_MESSAGE: &str = "nano: WIP checkpoint (do not merge)";
/// Caps on one sweep so an opportunistic GC can never run unbounded.
const SWEEP_MAX_DELETES: usize = 25;
const SWEEP_MAX_LOOKUPS: usize = 25;

/// Process-global throttle for the opportunistic orphan sweep (`gc_every_ms`).
/// `0` = never swept yet.
static LAST_SWEEP_MS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build an authenticated runner on the checkout. `None` if the pinned handle
/// cannot be duplicated.
fn runner_for(agent_cwd: &CwdHandle, repo_url: &str, cfg: &CheckpointConfig) -> Option<GitRunner> {
    let cwd = agent_cwd.try_clone().ok()?;
    let (_, cred) = crate::provision::split_url_credential(repo_url);
    Some(GitRunner::new(cwd, cfg.git_timeout()).with_credential(cred, true))
}

/// What [`start`] hands back to `execute`.
pub struct StartResult {
    /// The note to append to the agent prompt when a checkpoint was restored.
    pub restore_note: Option<String>,
    /// The live background checkpointer; drop or [`CheckpointGuard::finish`] it.
    pub guard: Option<CheckpointGuard>,
}

/// Immutable parameters shared by the periodic loop and the finalize path.
struct Plan {
    config: CheckpointConfig,
    own_ref: String,
    recovered_ref: String,
    working_branch: String,
    base_sha: String,
    run_id: String,
    remote: String,
    secret_values: Vec<String>,
}

/// Begin checkpointing for a provisioned job. Restores a prior checkpoint (own or
/// an explicitly adopted predecessor), launches the throttled orphan sweep, and
/// starts the periodic background checkpointer. Best-effort throughout.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    agent_cwd: &CwdHandle,
    repo_url: &str,
    branch_push: bool,
    working_branch: Option<&str>,
    base_ref: Option<&str>,
    element_instance_key: &str,
    element_id: &str,
    run_id: &str,
    base_sha: Option<&str>,
    variables: &Value,
    jobs: Jobs,
) -> StartResult {
    let empty = || StartResult {
        restore_note: None,
        guard: None,
    };

    let config = CheckpointConfig::from_env();
    if !config.enabled() {
        return empty();
    }
    let authenticated = is_authenticated_remote(repo_url);
    let elig = checkpoint_eligibility(
        config.mode,
        true,
        Some(branch_push),
        authenticated,
        working_branch,
    );
    if !elig.enabled {
        crate::runtime::log(&format!(
            "checkpoint: disabled for this job — {}",
            elig.reason
        ));
        return empty();
    }

    let (own_ref, recovered_ref) = match (
        checkpoint_ref(element_instance_key),
        recovered_checkpoint_ref(element_instance_key),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            crate::runtime::log(&format!(
                    "checkpoint: element instance key {element_instance_key:?} is not a valid ref key; skipping"
                ));
            return empty();
        }
    };

    let runner = match runner_for(agent_cwd, repo_url, &config) {
        Some(r) => r,
        None => {
            crate::runtime::log(
                "checkpoint: could not bind a git runner on the checkout; skipping",
            );
            return empty();
        }
    };

    let plan = Arc::new(Plan {
        config,
        own_ref,
        recovered_ref,
        working_branch: working_branch.unwrap_or("").to_string(),
        base_sha: base_sha.unwrap_or("").to_string(),
        run_id: run_id.to_string(),
        remote: "origin".to_string(),
        secret_values: normalize_secret_values(&credentials_from_url(repo_url)),
    });

    // --- restore a prior checkpoint ---------------------------------------
    let restore_note = restore(&runner, &plan, variables, base_ref, element_id).await;

    // --- opportunistic orphan sweep (throttled, backgrounded) -------------
    maybe_sweep(agent_cwd, repo_url, &plan, jobs);

    // --- periodic background checkpointer ---------------------------------
    let guard = spawn_periodic(agent_cwd, repo_url, plan, runner);

    StartResult {
        restore_note,
        guard,
    }
}

/// Try to restore this job's own checkpoint, or an explicitly adopted
/// predecessor. Returns the prompt note on a successful restore.
async fn restore(
    runner: &GitRunner,
    plan: &Plan,
    variables: &Value,
    base_ref: Option<&str>,
    element_id: &str,
) -> Option<String> {
    let self_ref = plan.own_ref.as_str();
    let predecessor = predecessor_checkpoint_ref(variables, Some(self_ref), Some(element_id));
    // An explicit (bare-string) resume pointer is occurrence-authoritative, so it
    // is tried first; otherwise self-resume (same element redelivered) wins.
    let explicit = resume_ref_is_explicit(variables);
    let mut candidates: Vec<String> = Vec::new();
    let own = plan.own_ref.clone();
    if explicit {
        if let Some(p) = predecessor.clone() {
            candidates.push(p);
        }
        candidates.push(own);
    } else {
        candidates.push(own);
        if let Some(p) = predecessor {
            candidates.push(p);
        }
    }
    candidates.dedup();

    let branch = if plan.working_branch.is_empty() {
        None
    } else {
        Some(plan.working_branch.as_str())
    };
    for reference in candidates {
        let fetched = match fetch_checkpoint(runner, &reference, &plan.remote).await {
            Ok(Some(fc)) => fc,
            _ => continue,
        };
        let result =
            restore_checkpoint(runner, &fetched, branch, true, base_ref.unwrap_or("")).await;
        if result.restored {
            crate::runtime::log(&format!(
                "checkpoint: restored prior workspace from {reference} (mode {})",
                result.mode
            ));
            let note = checkpoint_restored_note(&result);
            return (!note.is_empty()).then_some(note);
        } else if !result.reason.is_empty() {
            crate::runtime::log(&format!(
                "checkpoint: did not restore {reference} — {}{}",
                result.reason,
                if result.branch_mismatch {
                    " (branch mismatch)"
                } else {
                    ""
                }
            ));
        }
    }
    None
}

/// Run the orphan GC sweep opportunistically, throttled to `gc_every_ms` across
/// the whole process. Spawned detached so it never adds latency to the job.
fn maybe_sweep(agent_cwd: &CwdHandle, repo_url: &str, plan: &Arc<Plan>, jobs: Jobs) {
    let now = now_ms();
    let every = plan.config.gc_every_ms.max(1);
    let last = LAST_SWEEP_MS.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < every {
        return;
    }
    // Claim the slot; a racing job that observes the same `last` loses the CAS and
    // skips, so only one sweep runs per window.
    if LAST_SWEEP_MS
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let runner = match runner_for(agent_cwd, repo_url, &plan.config) {
        Some(r) => r,
        None => return,
    };
    let plan = plan.clone();
    tokio::spawn(async move {
        let probe = SdkOrphanProbe { jobs };
        let r = sweep_stale_checkpoints(
            &runner,
            Some(&plan.own_ref),
            plan.config.ttl_ms,
            plan.config.gc_grace_ms,
            Some(&probe),
            now_ms(),
            SWEEP_MAX_DELETES,
            SWEEP_MAX_LOOKUPS,
            &plan.remote,
        )
        .await;
        if !r.deleted.is_empty() || r.error.is_some() {
            crate::runtime::log(&format!(
                "checkpoint: orphan sweep scanned {}, reclaimed {}{}",
                r.scanned,
                r.deleted.len(),
                r.error
                    .map(|e| format!(" (error: {e})"))
                    .unwrap_or_default()
            ));
        }
    });
}

/// Spawn the periodic snapshot→push loop. The returned guard aborts the loop on
/// drop, so an aborted job future (e.g. SLA cancel) leaves the LAST periodic
/// checkpoint on the remote.
fn spawn_periodic(
    agent_cwd: &CwdHandle,
    repo_url: &str,
    plan: Arc<Plan>,
    finalize_runner: GitRunner,
) -> Option<CheckpointGuard> {
    let loop_runner = runner_for(agent_cwd, repo_url, &plan.config)?;
    let stop = Arc::new(Notify::new());
    let stop_loop = stop.clone();
    let loop_plan = plan.clone();
    let handle = tokio::spawn(async move {
        periodic_loop(loop_runner, loop_plan, stop_loop).await;
    });
    Some(CheckpointGuard {
        handle,
        stop,
        plan,
        runner: finalize_runner,
        finished: false,
    })
}

async fn periodic_loop(runner: GitRunner, plan: Arc<Plan>, stop: Arc<Notify>) {
    let first = Duration::from_millis(plan.config.min_interval_ms);
    let interval = Duration::from_millis(plan.config.interval_ms.max(plan.config.min_interval_ms));
    let mut last_tree: Option<(String, String)> = None;
    let mut delay = first;
    loop {
        tokio::select! {
            _ = stop.notified() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = interval;
        if let Some((sha, tree, head)) = push_snapshot(
            &runner,
            &plan,
            last_tree.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
        )
        .await
        {
            let _ = sha;
            last_tree = Some((tree, head));
        }
    }
}

/// Snapshot the worktree and push it to the WIP ref (and promote the GC-proof
/// recovery ref). Returns `(sha, tree, head)` on a committed+pushed snapshot.
async fn push_snapshot(
    runner: &GitRunner,
    plan: &Plan,
    last_tree: Option<(&str, &str)>,
) -> Option<(String, String, String)> {
    let snap = snapshot_worktree(
        runner,
        &plan.base_sha,
        &plan.working_branch,
        &plan.run_id,
        last_tree,
        plan.config.max_file_bytes,
        &plan.secret_values,
        SNAPSHOT_MESSAGE,
    )
    .await;
    let (sha, tree, head) = match snap {
        Snapshot::Committed {
            sha,
            tree,
            head,
            excluded,
        } => {
            if !excluded.is_empty() {
                crate::runtime::log(&format!(
                    "checkpoint: snapshot excluded {} path(s) (denied/secret/oversize)",
                    excluded.len()
                ));
            }
            (sha, tree, head)
        }
        Snapshot::Skipped { reason } => {
            // "unchanged"/"clean" are the benign no-op cases every idle interval
            // hits; only surface a genuine failure reason.
            if reason != "unchanged" && reason != "clean" {
                crate::runtime::log(&format!("checkpoint: snapshot skipped — {reason}"));
            }
            return None;
        }
    };
    let expect = observe_remote_ref_sha(runner, &plan.own_ref, &plan.remote).await;
    match push_checkpoint(runner, &plan.own_ref, &sha, &expect, &plan.remote).await {
        PushResult::Ok => {}
        PushResult::StaleLease { error } | PushResult::Error { error } => {
            crate::runtime::log(&format!(
                "checkpoint: push to {} failed — {error}",
                plan.own_ref
            ));
            return None;
        }
    }
    // Promote a GC-proof recovery copy so a human escalation can still be resumed
    // even if the per-checkpoint WIP ref is later reclaimed (#295).
    let expect_rec = observe_remote_ref_sha(runner, &plan.recovered_ref, &plan.remote).await;
    let _ = push_named_ref(runner, &plan.recovered_ref, &sha, &expect_rec, &plan.remote).await;
    Some((sha, tree, head))
}

/// Live background checkpointer. Aborts its loop on drop.
pub struct CheckpointGuard {
    handle: tokio::task::JoinHandle<()>,
    stop: Arc<Notify>,
    plan: Arc<Plan>,
    runner: GitRunner,
    finished: bool,
}

impl CheckpointGuard {
    /// Stop the periodic loop and finalize. On success the WIP and recovery refs
    /// are deleted (the work is now published); on failure the last checkpoint is
    /// left in place for a resumed run.
    pub async fn finish(mut self, success: bool) {
        self.finished = true;
        self.stop.notify_waiters();
        self.handle.abort();
        let _ = (&mut self.handle).await;
        if success {
            let expect =
                observe_remote_ref_sha(&self.runner, &self.plan.own_ref, &self.plan.remote).await;
            let _ = delete_checkpoint_ref(
                &self.runner,
                &self.plan.own_ref,
                &self.plan.remote,
                Some(&expect),
            )
            .await;
            let expect_rec =
                observe_remote_ref_sha(&self.runner, &self.plan.recovered_ref, &self.plan.remote)
                    .await;
            let _ = delete_checkpoint_ref(
                &self.runner,
                &self.plan.recovered_ref,
                &self.plan.remote,
                Some(&expect_rec),
            )
            .await;
        }
    }
}

impl Drop for CheckpointGuard {
    fn drop(&mut self) {
        // An un-finished guard (the job future was aborted before settlement, e.g.
        // an SLA cancel): stop the loop so it cannot keep pushing after teardown.
        // The last periodic checkpoint already pushed survives on the remote.
        if !self.finished {
            self.stop.notify_waiters();
            self.handle.abort();
        }
    }
}

/// SDK-backed orphan probe: an element-instance checkpoint is reclaimable only
/// when the element is terminal AND its process instance has also finished. A
/// terminal element inside a STILL-ACTIVE process (an SLA-cancelled slice pending
/// human escalation, #295/#296) is spared. Any lookup error fails CLOSED (spare).
struct SdkOrphanProbe {
    jobs: Jobs,
}

impl OrphanProbe for SdkOrphanProbe {
    fn is_orphan<'a>(
        &'a self,
        key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let (element_state, process_instance_key) =
                match self.jobs.element_instance_state(key).await {
                    Ok(v) => v,
                    Err(_) => return false,
                };
            if !matches!(element_state.as_str(), "COMPLETED" | "TERMINATED") {
                return false;
            }
            let process_state = self
                .jobs
                .process_instance_state(&process_instance_key)
                .await
                .ok();
            orphan_decision(Some(&element_state), true, process_state.as_deref())
        })
    }
}
