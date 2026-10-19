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
    delete_checkpoint_ref, delete_local_ref, fetch_checkpoint, is_authenticated_remote,
    normalize_secret_values, observe_remote_ref_sha, orphan_decision, predecessor_checkpoint_ref,
    push_checkpoint, recovered_checkpoint_ref, restore_checkpoint, resume_ref_is_explicit,
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
    Some(
        GitRunner::new(cwd, cfg.git_timeout())
            .with_credential(cred, true)
            .with_max_stdout(cfg.max_file_bytes),
    )
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
    /// The configured base ref (e.g. `main`) this job branched from, recorded in
    /// the snapshot so a per-activation fallback-branch rename can be recognised
    /// on restore. Empty when unknown.
    base_ref: String,
    run_id: String,
    remote: String,
    secret_values: Vec<String>,
}

/// Per-ref ownership lease for the periodic loop.
///
/// A checkpoint ref is "owned" by exactly one live attempt. We establish a lease
/// target ONCE (an adopted/self-resume sha, or `""` = create-only for a ref we
/// expect to be absent) and thereafter advance it ONLY when OUR OWN push
/// succeeds. We never re-read the remote's current value to build the next lease:
/// doing so (the previous behaviour) laundered a concurrent sibling's write into
/// our lease and let us clobber it. If a push is rejected for a stale lease, a
/// sibling holds the ref — we drop ownership and stop publishing to it.
#[derive(Clone)]
struct RefLease {
    reference: String,
    /// The sha our lease is currently pinned to (`""` demands absence).
    expect: String,
    owned: bool,
}

/// The periodic loop's per-ref leases, shared with the finalize path so
/// [`CheckpointGuard::finish`] deletes ONLY against the shas THIS attempt last
/// wrote — never a freshly re-observed remote value, which could name a
/// replacement attempt's ref that we no longer own.
struct LeaseState {
    own: std::sync::Mutex<RefLease>,
    recovered: std::sync::Mutex<RefLease>,
}

impl RefLease {
    fn new(reference: String, seed: Option<String>) -> Self {
        Self {
            reference,
            expect: seed.unwrap_or_default(),
            owned: true,
        }
    }

    /// Fold a push result into the lease. ONLY our own successful write advances
    /// the lease target; a stale-lease rejection means a sibling moved the ref, so
    /// we drop ownership; a transient error keeps the lease so the next tick
    /// retries against the same target. Returns the result for convenience.
    fn apply(&mut self, result: &PushResult, sha: &str) {
        match result {
            PushResult::Ok => self.expect = sha.to_string(),
            PushResult::StaleLease { .. } => self.owned = false,
            PushResult::Error { .. } => {}
        }
    }
}

/// Build the ordered restore-candidate list. An EXPLICIT (occurrence-authoritative)
/// resume pointer may adopt a named predecessor — tried first, then our own ref.
/// WITHOUT one, a predecessor ref belongs to a concurrent SIBLING attempt whose
/// live workspace we must not race, so we consider ONLY our own ref (self-resume /
/// redelivery). Matches the JS port's refusal (jwulf/c8ctl-plugin-nano#296).
fn restore_candidates(explicit: bool, own: &str, predecessor: Option<&str>) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if explicit {
        if let Some(p) = predecessor {
            candidates.push(p.to_string());
        }
        candidates.push(own.to_string());
    } else {
        candidates.push(own.to_string());
    }
    candidates.dedup();
    candidates
}

/// Outcome of the push for one periodic tick.
enum TickOutcome {
    /// Snapshot pushed to our WIP ref; carries `(tree, head)` to dedupe next tick.
    Pushed(String, String),
    /// Nothing to publish (clean/unchanged) or a transient push error.
    Idle,
    /// We lost ownership of our WIP ref to a concurrent attempt — stop the loop.
    OwnershipLost,
}

/// What a successful restore seeded for the periodic loop's ownership leases.
struct RestoreOutcome {
    note: Option<String>,
    /// Lease seed for our WIP ref: a sha we now hold (self-resume or adopted), or
    /// `None` to fall back to create-only.
    seed_own: Option<String>,
    /// Lease seed for our recovery ref (only when it is genuinely ours already).
    seed_rec: Option<String>,
    /// Supersession seed for the periodic loop's `last_tree`: the restored
    /// checkpoint's `(tree, head)`. Without it a resumed run that the agent
    /// reverts to the provisioned base before the first tick keeps reporting
    /// `clean` (no prior push this session), so the stale remote checkpoint is
    /// never superseded and the discarded work returns on the next interruption.
    seed_tree: Option<(String, String)>,
}

/// Begin checkpointing for a provisioned job. Restores a prior checkpoint (own or
/// an explicitly adopted predecessor), launches the throttled orphan sweep, and
/// starts the periodic background checkpointer. Best-effort throughout.
///
/// `effective_base` is provisioning's EFFECTIVE base identity
/// (`GitPrep::effective_base`): the configured base, else the remote default /
/// checked-out branch the fallback was cut from. This is what the snapshot's
/// BaseRef trailer must record so a retry on a generated fallback branch
/// recognises its own checkpoint; `base_ref` alone is empty whenever
/// `branch.base` is omitted.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    agent_cwd: &CwdHandle,
    repo_url: &str,
    branch_push: bool,
    working_branch: Option<&str>,
    base_ref: Option<&str>,
    effective_base: Option<&str>,
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
        // Record provisioning's EFFECTIVE base (falling back to the configured
        // `branch.base`), never an empty string when only the former is known.
        base_ref: effective_base.or(base_ref).unwrap_or("").to_string(),
        run_id: run_id.to_string(),
        remote: "origin".to_string(),
        secret_values: normalize_secret_values(&credentials_from_url(repo_url)),
    });

    // --- restore a prior checkpoint ---------------------------------------
    let outcome = restore(&runner, &plan, variables, element_id).await;
    let restore_note = outcome.note;

    // --- opportunistic orphan sweep (throttled, backgrounded) -------------
    maybe_sweep(agent_cwd, repo_url, &plan, jobs);

    // --- periodic background checkpointer ---------------------------------
    let guard = spawn_periodic(
        agent_cwd,
        repo_url,
        plan,
        runner,
        outcome.seed_own,
        outcome.seed_rec,
        outcome.seed_tree,
    );

    StartResult {
        restore_note,
        guard,
    }
}

/// Try to restore this job's own checkpoint, or an explicitly adopted
/// predecessor. Returns the prompt note plus the ownership-lease seeds for the
/// periodic loop.
async fn restore(
    runner: &GitRunner,
    plan: &Plan,
    variables: &Value,
    element_id: &str,
) -> RestoreOutcome {
    let none = || RestoreOutcome {
        note: None,
        seed_own: None,
        seed_rec: None,
        seed_tree: None,
    };
    let self_ref = plan.own_ref.as_str();
    let predecessor = predecessor_checkpoint_ref(variables, Some(self_ref), Some(element_id));
    let explicit = resume_ref_is_explicit(variables);
    let candidates = restore_candidates(explicit, self_ref, predecessor.as_deref());

    let branch = if plan.working_branch.is_empty() {
        None
    } else {
        Some(plan.working_branch.as_str())
    };
    let mut fetched_refs: Vec<String> = Vec::new();
    let mut outcome = none();
    for reference in candidates {
        let fetched = match fetch_checkpoint(runner, &reference, &plan.remote).await {
            Ok(Some(fc)) => fc,
            _ => continue,
        };
        fetched_refs.push(reference.clone());
        // Validate the restore against the RESOLVED effective base (configured
        // `branch.base`, else provisioning's fallback base), not the raw
        // `branch.base`: when that field is omitted the snapshot records the
        // effective base, so passing an empty expected base here would reject the
        // generated fallback-branch rename on an otherwise valid self-restore.
        let result =
            restore_checkpoint(runner, &fetched, branch, true, plan.base_ref.as_str()).await;
        if result.restored {
            crate::runtime::log(&format!(
                "checkpoint: restored prior workspace from {reference} (mode {})",
                result.mode
            ));
            let note = checkpoint_restored_note(&result);
            outcome.note = (!note.is_empty()).then_some(note);
            // Seed the periodic loop's supersession state from the checkpoint we
            // just restored. Otherwise `last_tree` starts empty, so an agent that
            // reverts the restored work back to the provisioned base before the
            // first tick keeps producing a `clean` snapshot (no prior push this
            // session) and the stale remote checkpoint is never superseded — the
            // discarded work would then return after the next interruption.
            let tree = runner
                .run(&[
                    "rev-parse",
                    "--verify",
                    "-q",
                    &format!("{}^{{tree}}", fetched.sha),
                ])
                .await
                .out();
            if !tree.is_empty() {
                outcome.seed_tree = Some((tree, fetched.parent.clone()));
            }
            if reference == self_ref {
                // Self-resume: our WIP ref already holds this sha; lease against
                // it so our first periodic push advances rather than (re)creating.
                outcome.seed_own = Some(fetched.sha.clone());
                // The RECOVERY ref is leased independently: each tick pushes WIP
                // first, so an interruption (or a failed recovery push) can leave
                // recovery absent or at an OLDER sha than the WIP we just read.
                // Seeding its lease from the WIP sha would then be rejected as a
                // stale lease and disable recovery updates for the whole run.
                // Observe the recovery ref ONCE to establish its own baseline —
                // create-only when absent — and thereafter advance it only on our
                // own successful writes.
                let rec = observe_remote_ref_sha(runner, &plan.recovered_ref, &plan.remote).await;
                outcome.seed_rec = (!rec.is_empty()).then_some(rec);
            } else {
                // Adopted an explicit predecessor: copy its snapshot onto OUR WIP
                // ref NOW (create-only), BEFORE the orphan sweep can reclaim the
                // predecessor's ref, so the adopted work survives even if we crash
                // before the first periodic push. Seed the lease from it on
                // success; on failure a sibling already holds our ref, so we leave
                // the predecessor's ref intact and let the loop bow out.
                match push_checkpoint(runner, self_ref, &fetched.sha, "", &plan.remote).await {
                    PushResult::Ok => outcome.seed_own = Some(fetched.sha.clone()),
                    other => crate::runtime::log(&format!(
                        "checkpoint: could not adopt predecessor {reference} onto {self_ref} \
                         — {other:?}; leaving source intact"
                    )),
                }
            }
            break;
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
    // Drop the LOCAL refs materialised by `fetch_checkpoint` so finalization's
    // stranded-work scan does not mistake their snapshot commits for unpublished
    // agent work (nanobpm/nano-supervisor#66 finalize interference).
    for reference in fetched_refs {
        delete_local_ref(runner, &reference).await;
    }
    outcome
}

/// A daemon-owned scratch repository the orphan-GC sweep runs against. The sweep
/// fetches candidate refs into local `refs/nano-gc/*` and reads their commit
/// times; doing that in the JOB's checkout ties the sweep's lifetime to a
/// checkout that settlement may reap mid-sweep (removing its `.git`), failing
/// every subsequent git op while the hourly throttle suppresses a retry. A
/// dedicated, persistent repo under the daemon's temp dir outlives any single
/// job, so reaping never interrupts a sweep.
///
/// The repo is PERSISTENT (one per uid, reused across sweeps) and is never
/// removed by the sweep: it holds only transient `refs/nano-gc/*` temp refs the
/// sweep itself cleans up, so it stays tiny, and deleting it on drop would race a
/// concurrent sweep that resolved the same path. Returns the `--git-dir` path, or
/// `None` when the repo cannot be prepared (the sweep then skips, best-effort).
async fn sweep_scratch_repo(runner: &GitRunner) -> Option<std::path::PathBuf> {
    let git_dir = std::env::temp_dir()
        .join(format!("nano-gc-scratch-{}", current_uid()))
        .join("repo.git");
    // `git init --bare` is idempotent for an existing repo, so this both creates
    // the scratch repo on first use and validates it on reuse.
    std::fs::create_dir_all(&git_dir).ok()?;
    let init = runner
        .run(&["init", "--bare", "--quiet", &git_dir.to_string_lossy()])
        .await;
    if !init.ok() {
        return None;
    }
    Some(git_dir)
}

/// The uid for the scratch-repo name (isolates one user's daemon from another's
/// in the world-writable temp dir). `libc` is already a daemon dependency.
fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is async-signal-safe and always succeeds.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        std::process::id()
    }
}

/// Resolve the remote the orphan-GC sweep targets. The sweep runs against a
/// fresh scratch `--git-dir` with no named remotes, so it must reference the
/// repository by URL/path rather than the `"origin"` alias that only exists in
/// the job checkout's config.
///
/// The URL is credential-sanitized (the runner re-attaches auth out of band via
/// the credential helper, so an embedded userinfo secret must never reach the
/// sweep's argv). A relative LOCAL path is anchored to the job checkout
/// (`agent_cwd`) so it resolves to the same repository irrespective of the
/// scratch git-dir's own location; remote URLs (`scheme://…`) and scp-like SSH
/// targets (`host:path`) are passed through untouched.
fn sweep_remote_target(repo_url: &str, agent_cwd: &CwdHandle) -> String {
    let (sanitized, _cred) = crate::provision::split_url_credential(repo_url);
    if !is_local_path(&sanitized) {
        return sanitized;
    }
    let p = std::path::Path::new(&sanitized);
    if p.is_relative() {
        if let Ok(anchor) = agent_cwd.path() {
            return anchor.join(p).to_string_lossy().into_owned();
        }
    }
    sanitized
}

/// Whether a git remote string names a LOCAL filesystem path (as opposed to a
/// `scheme://…` URL or an scp-like `host:path` SSH target). Mirrors git's own
/// rule: a colon appearing before the first slash marks an scp-like remote.
fn is_local_path(remote: &str) -> bool {
    if remote.contains("://") {
        return false;
    }
    match (remote.find(':'), remote.find('/')) {
        // Colon before any slash ⇒ scp-like `host:path`, i.e. a remote.
        (Some(colon), Some(slash)) => colon > slash,
        (Some(_), None) => false,
        (None, _) => true,
    }
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
    // The sweep runs against a dedicated scratch `--git-dir` (see below), which is
    // a FRESH bare repo with no `origin`. `plan.remote` ("origin") only resolves
    // inside the job checkout's `.git/config`; against the scratch git-dir it
    // resolves to nothing, so the sweep's first `ls-remote` fails and neither TTL
    // nor orphan reclamation ever runs. Resolve the sweep's remote to the trusted
    // repository URL itself — credential-sanitized (auth rides the runner's
    // out-of-band credential helper, exactly as for "origin"), with relative local
    // paths anchored to the job checkout so they resolve the same regardless of the
    // scratch git-dir.
    let sweep_remote = sweep_remote_target(repo_url, agent_cwd);
    let plan = plan.clone();
    tokio::spawn(async move {
        // Run the sweep against a dedicated scratch repo (`--git-dir`) that
        // outlives this job's checkout. Otherwise the sweep fetches/reads
        // `refs/nano-gc/*` inside the job's `.git`, which settlement may reap
        // mid-sweep — failing every later git op while the hourly throttle
        // suppresses a retry (so repeated short jobs starve reclamation).
        let Some(git_dir) = sweep_scratch_repo(&runner).await else {
            crate::runtime::log(
                "checkpoint: orphan sweep skipped — could not prepare a scratch repo",
            );
            return;
        };
        let runner = runner.with_git_dir(git_dir);
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
            &sweep_remote,
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
    seed_own: Option<String>,
    seed_rec: Option<String>,
    seed_tree: Option<(String, String)>,
) -> Option<CheckpointGuard> {
    let loop_runner = runner_for(agent_cwd, repo_url, &plan.config)?;
    let stop = Arc::new(Notify::new());
    let stop_loop = stop.clone();
    let loop_plan = plan.clone();
    // The leases live in a shared state so finalize (`CheckpointGuard::finish`)
    // deletes against the shas THIS attempt last owned, not a fresh observation.
    let leases = Arc::new(LeaseState {
        own: std::sync::Mutex::new(RefLease::new(plan.own_ref.clone(), seed_own)),
        recovered: std::sync::Mutex::new(RefLease::new(plan.recovered_ref.clone(), seed_rec)),
    });
    let loop_leases = leases.clone();
    let handle = tokio::spawn(async move {
        periodic_loop(loop_runner, loop_plan, stop_loop, loop_leases, seed_tree).await;
    });
    Some(CheckpointGuard {
        handle,
        stop,
        plan,
        runner: finalize_runner,
        leases,
        finished: false,
    })
}

async fn periodic_loop(
    runner: GitRunner,
    plan: Arc<Plan>,
    stop: Arc<Notify>,
    leases: Arc<LeaseState>,
    seed_tree: Option<(String, String)>,
) {
    let first = Duration::from_millis(plan.config.min_interval_ms);
    let interval = Duration::from_millis(plan.config.interval_ms.max(plan.config.min_interval_ms));
    // Supersession state is seeded from a restored checkpoint so a resume →
    // discard → first-tick still publishes the clean snapshot that replaces the
    // stale remote one (rather than reporting `clean` and leaving it in place).
    let mut last_tree: Option<(String, String)> = seed_tree;
    let mut delay = first;
    loop {
        tokio::select! {
            _ = stop.notified() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = interval;
        match push_snapshot(
            &runner,
            &plan,
            last_tree.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
            &leases,
        )
        .await
        {
            TickOutcome::Pushed(tree, head) => last_tree = Some((tree, head)),
            TickOutcome::Idle => {}
            TickOutcome::OwnershipLost => {
                crate::runtime::log(&format!(
                    "checkpoint: WIP ref {} is held by a concurrent attempt; \
                     stopping this attempt's periodic checkpointer",
                    plan.own_ref
                ));
                return;
            }
        }
    }
}

/// Two-phase lease push against a SHARED (mutexed) lease, so no lock guard is
/// held across the `.await` (which would make the future `!Send`). We snapshot
/// `(owned, expect, reference)` under the lock, push outside it, then re-lock to
/// fold the result in. The periodic loop is the sole writer and `finish` only
/// reads, so the lease cannot change between the two locks.
async fn lease_push_shared(
    runner: &GitRunner,
    remote: &str,
    lock: &std::sync::Mutex<RefLease>,
    sha: &str,
) -> PushResult {
    let (owned, expect, reference) = {
        let l = lock.lock().unwrap();
        (l.owned, l.expect.clone(), l.reference.clone())
    };
    if !owned {
        return PushResult::StaleLease {
            error: "ownership already lost".into(),
        };
    }
    let res = push_checkpoint(runner, &reference, sha, &expect, remote).await;
    lock.lock().unwrap().apply(&res, sha);
    res
}

/// Snapshot the worktree and push it to the WIP ref (and promote the GC-proof
/// recovery ref), each under its own ownership lease held in the shared state.
async fn push_snapshot(
    runner: &GitRunner,
    plan: &Plan,
    last_tree: Option<(&str, &str)>,
    leases: &LeaseState,
) -> TickOutcome {
    let snap = snapshot_worktree(
        runner,
        &plan.base_sha,
        &plan.base_ref,
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
            return TickOutcome::Idle;
        }
    };
    match lease_push_shared(runner, &plan.remote, &leases.own, &sha).await {
        PushResult::Ok => {}
        PushResult::StaleLease { .. } => return TickOutcome::OwnershipLost,
        PushResult::Error { error } => {
            crate::runtime::log(&format!(
                "checkpoint: push to {} failed — {error}",
                plan.own_ref
            ));
            return TickOutcome::Idle;
        }
    }
    // Promote a GC-proof recovery copy so a human escalation can still be resumed
    // even if the per-checkpoint WIP ref is later reclaimed (#295). A lost recovery
    // lease (a sibling holds it) is non-fatal: our WIP ref still carries the work.
    let _ = lease_push_shared(runner, &plan.remote, &leases.recovered, &sha).await;
    TickOutcome::Pushed(tree, head)
}

/// Live background checkpointer. Aborts its loop on drop.
pub struct CheckpointGuard {
    handle: tokio::task::JoinHandle<()>,
    stop: Arc<Notify>,
    plan: Arc<Plan>,
    runner: GitRunner,
    leases: Arc<LeaseState>,
    finished: bool,
}

impl CheckpointGuard {
    /// Stop the periodic loop and finalize. On success the WIP and recovery refs
    /// are deleted (the work is now published); on failure the last checkpoint is
    /// left in place for a resumed run.
    ///
    /// Deletion is leased against the shas THIS attempt last wrote (the shared
    /// lease state), never a freshly re-observed remote value: after a concurrent
    /// replacement attempt advances the refs, a fresh observation would name ITS
    /// sha as deletion authority and let a successful finalize delete the
    /// replacement's in-progress WIP/recovery refs. A ref whose lease we lost (or
    /// never wrote) is left for the orphan sweep instead.
    pub async fn finish(mut self, success: bool) {
        self.finished = true;
        self.stop.notify_waiters();
        self.handle.abort();
        let _ = (&mut self.handle).await;
        if success {
            // Snapshot each lease under its lock, then delete only the sha we
            // last owned. `expect == ""` means we never wrote the ref (create-only
            // baseline): there is nothing of ours to delete, so skip it.
            let own = self.leases.own.lock().unwrap().clone();
            if own.owned && !own.expect.is_empty() {
                let _ = delete_checkpoint_ref(
                    &self.runner,
                    &self.plan.own_ref,
                    &self.plan.remote,
                    Some(&own.expect),
                )
                .await;
            }
            let rec = self.leases.recovered.lock().unwrap().clone();
            if rec.owned && !rec.expect.is_empty() {
                let _ = delete_checkpoint_ref(
                    &self.runner,
                    &self.plan.recovered_ref,
                    &self.plan.remote,
                    Some(&rec.expect),
                )
                .await;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = "refs/nano/wip/own-elem";
    const PRED: &str = "refs/nano/wip/pred-elem";

    #[test]
    fn local_path_detection_matches_git_remote_rules() {
        // Remote URLs and scp-like SSH targets are NOT local paths.
        assert!(!is_local_path("https://github.com/o/r.git"));
        assert!(!is_local_path("ssh://git@host/r.git"));
        assert!(!is_local_path("git@github.com:org/repo.git"));
        assert!(!is_local_path("file://localhost/srv/r.git"));
        // Filesystem paths (absolute, relative, with a colon AFTER a slash) are.
        assert!(is_local_path("/srv/remote.git"));
        assert!(is_local_path("./remote.git"));
        assert!(is_local_path("../a/remote.git"));
        assert!(is_local_path("remote.git"));
        assert!(is_local_path("dir/a:b.git"));
    }

    #[test]
    fn sweep_remote_target_sanitizes_and_anchors() {
        let tmp = std::env::temp_dir().join(format!("nano-anchor-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let tmp = std::fs::canonicalize(&tmp).unwrap();
        let cwd = crate::safecwd::CwdHandle::open(&tmp).expect("open anchor");

        // An embedded HTTPS credential is scrubbed from the sweep's remote argv.
        let url = sweep_remote_target("https://user:tok@github.com/o/r.git", &cwd);
        assert!(
            !url.contains("tok"),
            "credential leaked into sweep remote: {url}"
        );
        assert!(url.starts_with("https://"));

        // A relative local path is anchored to the trusted checkout so it resolves
        // the same regardless of the scratch git-dir.
        let anchor = cwd.path().expect("anchor path");
        let rel = sweep_remote_target("remote.git", &cwd);
        assert_eq!(rel, anchor.join("remote.git").to_string_lossy());

        // An absolute local path is passed through unchanged.
        let abs = anchor.join("other.git");
        let abs_s = abs.to_string_lossy().into_owned();
        assert_eq!(sweep_remote_target(&abs_s, &cwd), abs_s);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Regression: when `branch.base` is OMITTED, provisioning's resolved effective
    /// base still reaches `Plan.base_ref`, and `restore` must validate against THAT
    /// — not the empty `branch.base`. Otherwise a self-resume onto a per-activation
    /// fallback branch is rejected as a branch mismatch even though the snapshot
    /// recorded the effective base. (The direct-`restore_checkpoint` tests supply
    /// `"main"` explicitly; this exercises the `start`→`restore` wiring.)
    #[tokio::test]
    async fn restore_uses_resolved_effective_base_when_branch_base_omitted() {
        let git_ok = std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !git_ok {
            return;
        }
        let dur = Duration::from_secs(30);
        let runner_at = |p: &std::path::Path| GitRunner::new(CwdHandle::open(p).unwrap(), dur);
        let root = std::env::temp_dir().join(format!(
            "nano-restore-base-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let root_git = runner_at(&root);
        assert!(root_git.run(&["init", "--bare", "remote.git"]).await.ok());
        assert!(root_git.run(&["clone", "remote.git", "seed"]).await.ok());
        let seed = runner_at(&root.join("seed"));
        assert!(seed
            .run(&["symbolic-ref", "HEAD", "refs/heads/main"])
            .await
            .ok());
        std::fs::write(root.join("seed/README.md"), "base\n").unwrap();
        assert!(seed.run(&["add", "-A"]).await.ok());
        assert!(seed
            .run(&[
                "-c",
                "user.email=a@b.c",
                "-c",
                "user.name=a",
                "commit",
                "-m",
                "init"
            ])
            .await
            .ok());
        assert!(seed.run(&["push", "origin", "main"]).await.ok());

        // Activation A: a generated fallback branch cut from main, snapshots WIP
        // recording `main` as the base ref.
        let elem = "elem-base-omitted";
        let own = checkpoint_ref(elem).unwrap();
        let branch_a = "nano/agent-work/main-aaaaaaaaaaaaaaaa-100-200-0";
        let branch_b = "nano/agent-work/main-bbbbbbbbbbbbbbbb-101-201-1";
        assert!(root_git.run(&["clone", "remote.git", "a"]).await.ok());
        let git_a = runner_at(&root.join("a"));
        assert!(git_a.run(&["checkout", "-b", branch_a]).await.ok());
        let base_sha = git_a.run(&["rev-parse", "HEAD"]).await.out();
        std::fs::write(root.join("a/WIP.txt"), "in progress\n").unwrap();
        let snap = snapshot_worktree(
            &git_a,
            &base_sha,
            "main",
            "run-A",
            None,
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await;
        let sha = match snap {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_eq!(
            push_checkpoint(&git_a, &own, &sha, "", "origin").await,
            PushResult::Ok
        );

        // Activation B: same element key (same own ref), a FRESH fallback branch,
        // and `branch.base` omitted. Provisioning resolved the effective base to
        // `main`, carried in `Plan.base_ref`; `restore` must use it.
        assert!(root_git.run(&["clone", "remote.git", "b"]).await.ok());
        let git_b = runner_at(&root.join("b"));
        assert!(git_b.run(&["checkout", "-b", branch_b]).await.ok());
        let plan = Plan {
            config: CheckpointConfig::from_env(),
            own_ref: own.clone(),
            recovered_ref: recovered_checkpoint_ref(elem).unwrap(),
            working_branch: branch_b.to_string(),
            base_sha: String::new(),
            // effective_base.or(branch.base=None) == "main"
            base_ref: "main".to_string(),
            run_id: "run-B".to_string(),
            remote: "origin".to_string(),
            secret_values: Vec::new(),
        };
        let outcome = restore(&git_b, &plan, &serde_json::json!({}), elem).await;
        assert!(
            outcome.note.is_some(),
            "fallback-rename self-resume was rejected despite a resolved effective base"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("b/WIP.txt")).unwrap(),
            "in progress\n"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_explicit_resume_refuses_sibling_predecessor() {
        // WITHOUT an occurrence-authoritative resume pointer, a discovered
        // predecessor ref belongs to a concurrent sibling attempt — adopting its
        // live workspace would race the sibling (c8ctl-plugin-nano#296). Only our
        // own ref is a candidate.
        assert_eq!(
            restore_candidates(false, OWN, Some(PRED)),
            vec![OWN.to_string()]
        );
        assert_eq!(restore_candidates(false, OWN, None), vec![OWN.to_string()]);
    }

    #[test]
    fn explicit_resume_adopts_named_predecessor_first_then_own() {
        // An explicit pointer authorises predecessor adoption; it is tried before
        // our own ref.
        assert_eq!(
            restore_candidates(true, OWN, Some(PRED)),
            vec![PRED.to_string(), OWN.to_string()]
        );
        // A predecessor that resolves to our OWN ref must not be listed twice.
        assert_eq!(
            restore_candidates(true, OWN, Some(OWN)),
            vec![OWN.to_string()]
        );
        assert_eq!(restore_candidates(true, OWN, None), vec![OWN.to_string()]);
    }

    #[test]
    fn lease_advances_only_on_own_successful_write() {
        let mut lease = RefLease::new(OWN.to_string(), Some("aaa".into()));
        lease.apply(&PushResult::Ok, "bbb");
        // The lease target advances to the sha WE just wrote.
        assert_eq!(lease.expect, "bbb");
        assert!(lease.owned);
    }

    #[test]
    fn lease_drops_ownership_on_stale_lease() {
        let mut lease = RefLease::new(OWN.to_string(), Some("aaa".into()));
        lease.apply(
            &PushResult::StaleLease {
                error: "rejected".into(),
            },
            "bbb",
        );
        // A sibling moved the ref: we lost ownership and must stop publishing, and
        // the lease target must NOT advance to a value we never wrote.
        assert!(!lease.owned);
        assert_eq!(lease.expect, "aaa");
    }

    #[test]
    fn lease_retains_target_on_transient_error() {
        let mut lease = RefLease::new(OWN.to_string(), Some("aaa".into()));
        lease.apply(
            &PushResult::Error {
                error: "network".into(),
            },
            "bbb",
        );
        // A transient error neither advances the lease nor drops ownership, so the
        // next tick retries against the same target.
        assert!(lease.owned);
        assert_eq!(lease.expect, "aaa");
    }

    #[test]
    fn lease_seed_defaults_to_create_only() {
        // No seed => create-only (empty expect); still owned.
        let lease = RefLease::new(OWN.to_string(), None);
        assert_eq!(lease.expect, "");
        assert!(lease.owned);
    }

    #[test]
    fn recovery_lease_is_seeded_independently_of_the_wip_ref() {
        // The recovery ref can be ABSENT or at an OLDER sha than the WIP ref (each
        // tick pushes WIP first, so an interruption can leave them apart). Seeding
        // the recovery lease from the WIP sha would be rejected as a stale lease.
        // A `None` seed (absent recovery) must stay create-only, and an observed
        // recovery sha must seed only the recovery lease — never the WIP sha.
        let rec_absent = RefLease::new("refs/nano/recovered/e".to_string(), None);
        assert_eq!(rec_absent.expect, "", "absent recovery ref => create-only");
        let rec_observed = RefLease::new(
            "refs/nano/recovered/e".to_string(),
            Some("older-rec-sha".to_string()),
        );
        assert_eq!(rec_observed.expect, "older-rec-sha");
        assert_ne!(
            rec_observed.expect, "wip-sha",
            "must not borrow the WIP sha"
        );
    }

    #[test]
    fn finish_deletes_only_refs_this_attempt_still_owns() {
        // The finalize path must delete ONLY against the sha THIS attempt last
        // wrote, and skip a ref whose lease was lost (a sibling holds it) or never
        // written (create-only baseline). Model the guard's per-ref decision.
        fn may_delete(lease: &RefLease) -> Option<&str> {
            if lease.owned && !lease.expect.is_empty() {
                Some(lease.expect.as_str())
            } else {
                None
            }
        }
        // Owned with a real last-written sha => delete against it.
        let mut owned = RefLease::new(OWN.to_string(), Some("aaa".into()));
        owned.apply(&PushResult::Ok, "bbb");
        assert_eq!(may_delete(&owned), Some("bbb"));
        // Ownership lost (stale lease) => do NOT delete the replacement's ref.
        let mut lost = RefLease::new(OWN.to_string(), Some("aaa".into()));
        lost.apply(
            &PushResult::StaleLease {
                error: "rejected".into(),
            },
            "bbb",
        );
        assert_eq!(may_delete(&lost), None);
        // Never wrote (create-only baseline, no successful push) => nothing of
        // ours to delete.
        let unwritten = RefLease::new(OWN.to_string(), None);
        assert_eq!(may_delete(&unwritten), None);
    }
}
