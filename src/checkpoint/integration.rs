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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
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

/// Process-global throttle for the opportunistic orphan sweep (`gc_every_ms`),
/// keyed by the credential-sanitized repository target so one busy repository
/// cannot starve the sweep of every OTHER repository the daemon serves (a single
/// global timestamp lets whichever repo schedules first in each window claim the
/// only slot). Best-effort and process-local; the TTL backstop still bounds how
/// long any ref can live. Absent key = never swept yet.
static LAST_SWEEP_MS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

fn last_sweep_ms() -> &'static Mutex<HashMap<String, u64>> {
    LAST_SWEEP_MS.get_or_init(|| Mutex::new(HashMap::new()))
}

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
    /// The shas we have ATTEMPTED to push whose outcome is UNCERTAIN. An ambiguous
    /// push failure (the server applied the update but the client lost the
    /// response — dropped connection / timeout) leaves `expect` behind on the
    /// pre-push value while the remote may actually have moved to the attempted
    /// sha. We remember EVERY still-unresolved attempt, not just the latest: if a
    /// FIRST push lands ambiguously and a SECOND push then fails outright (e.g. the
    /// connection drops before it reaches the server, so the remote still holds the
    /// first), a single-slot field would overwrite the first sha with the second
    /// and later reconcile the remote tip against the wrong value — concluding a
    /// sibling stole the ref and halting checkpointing. Keeping the set lets us
    /// reconcile the remote against ANY of our unresolved attempts
    /// (nanobpm/nano-supervisor#82). Cleared once a push confirms the remote tip.
    attempted: Vec<String>,
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
            attempted: Vec::new(),
            owned: true,
        }
    }

    /// Fold a push result into the lease. ONLY our own successful write advances
    /// the lease target; a stale-lease rejection means a sibling moved the ref, so
    /// we drop ownership; a transient error keeps the lease so the next tick
    /// retries against the same target. An UNCERTAIN (error) attempt is remembered
    /// — accumulated alongside any earlier unresolved attempt — so an ambiguous
    /// failure can be reconciled later against the remote tip; a CONFIRMED success
    /// resolves the remote to `sha`, clearing every prior uncertain attempt.
    fn apply(&mut self, result: &PushResult, sha: &str) {
        match result {
            PushResult::Ok => {
                self.expect = sha.to_string();
                // A CAS push only succeeds against the expected parent, so the
                // remote is now definitively `sha`: no earlier attempt can still be
                // its tip. Every prior uncertainty is resolved.
                self.attempted.clear();
            }
            PushResult::StaleLease { .. } => self.owned = false,
            PushResult::Error { .. } => {
                // Outcome unknown: the push may have LANDED. Remember it ALONGSIDE
                // any earlier unresolved attempt (never overwriting) so a later
                // reconciliation can match the remote tip against ANY of them.
                if !sha.is_empty() && !self.attempted.iter().any(|s| s == sha) {
                    self.attempted.push(sha.to_string());
                }
            }
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
    /// Snapshot pushed to our WIP ref; carries `(tree, head)` to dedupe next tick
    /// and `recovery_pending` = the just-published sha whose GC-proof recovery
    /// promotion failed transiently (retried on later ticks), else `None`.
    Pushed {
        tree: String,
        head: String,
        recovery_pending: Option<String>,
    },
    /// Nothing new to publish (clean/unchanged) or a transient WIP push error.
    /// Still carries forward any recovery promotion left pending from an earlier
    /// successful WIP push, so a transient recovery failure is retried even while
    /// snapshotting no-ops.
    Idle { recovery_pending: Option<String> },
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
    let mut candidates = restore_candidates(explicit, self_ref, predecessor.as_deref());

    // Distinguish an ALREADY-ADOPTED retry from a NEW explicit adoption. When an
    // explicit pointer names a predecessor but our OWN ref already exists on the
    // remote, a prior delivery already adopted that predecessor and has since made
    // its own (newer) progress — the process re-offers the same predecessor pointer
    // every redelivery. Adopting the predecessor again would reset the worktree to
    // the STALE predecessor snapshot and then fail the create-only adoption push
    // (our ref exists), leaving ownership unseeded so the periodic loop bows out
    // (nanobpm/nano-supervisor#82). Drop the predecessor candidate and SELF-RESUME
    // our own newer checkpoint instead — never clobbering a concurrent writer, since
    // the periodic loop's first CAS push drops ownership if someone else advanced it.
    if explicit && predecessor.is_some() {
        let existing = observe_remote_ref_sha(runner, self_ref, &plan.remote).await;
        if !existing.is_empty() {
            crate::runtime::log(&format!(
                "checkpoint: {self_ref} already holds our own progress \
                 (redelivery after adoption); resuming it instead of re-adopting \
                 {}",
                predecessor.as_deref().unwrap_or("")
            ));
            candidates = vec![self_ref.to_string()];
        }
    }

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
                break;
            } else {
                // Adopted an explicit predecessor: copy its snapshot onto OUR WIP
                // ref NOW (create-only), BEFORE the orphan sweep can reclaim the
                // predecessor's ref, so the adopted work survives even if we crash
                // before the first periodic push. Seed the lease from it on success.
                // A redelivery after we already adopted-and-progressed is handled
                // earlier (the predecessor candidate is dropped when our own ref
                // already exists), so a failure here means our ref is absent and a
                // sibling raced us for the source — leave it intact and bow out.
                match push_checkpoint(runner, self_ref, &fetched.sha, "", &plan.remote).await {
                    PushResult::Ok => outcome.seed_own = Some(fetched.sha.clone()),
                    other => crate::runtime::log(&format!(
                        "checkpoint: could not adopt predecessor {reference} onto \
                         {self_ref} — {other:?}; leaving source intact"
                    )),
                }
                break;
            }
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
///
/// The scratch root is created PRIVATE (mode 0700) under an ABSOLUTE temp root:
///   * Absolute — Git resolves a relative `--git-dir` against the runner's cwd
///     (the job checkout), so a relative `TMPDIR` (e.g. `TMPDIR=tmp`) would place
///     the scratch repo INSIDE the disposable checkout rather than the intended
///     persistent location. `std::path::absolute` pins it regardless of cwd.
///   * Private + validated — the root lives in a world-writable temp dir and
///     holds fetched private repository history. A default 0755 directory would
///     leave that history world-readable, and a predictable path invites a
///     pre-created directory or symlink planted by another user. We create the
///     root 0700 and, on reuse, require it to be a real directory we own and not
///     a symlink before trusting it.
async fn sweep_scratch_repo(runner: &GitRunner) -> Option<(std::path::PathBuf, CwdHandle)> {
    // Canonicalize the temp base so the scratch path carries no symlinked
    // component: `CwdHandle::open` below pins the directory with a no-follow walk
    // that refuses a symlink anywhere in the path (e.g. macOS `/var` ->
    // `/private/var`), and the system temp root is a trusted prefix.
    let base = std::fs::canonicalize(std::env::temp_dir())
        .or_else(|_| std::path::absolute(std::env::temp_dir()))
        .ok()?;
    let root = base.join(format!("nano-gc-scratch-{}", current_uid()));
    create_private_dir(&root)?;
    let git_dir = root.join("repo.git");
    // `git init --bare` is idempotent for an existing repo, so this both creates
    // the scratch repo on first use and validates it on reuse.
    std::fs::create_dir_all(&git_dir).ok()?;
    let init = runner
        .run(&["init", "--bare", "--quiet", &git_dir.to_string_lossy()])
        .await;
    if !init.ok() {
        return None;
    }
    // Pin the persistent scratch ROOT as the sweep's cwd. The scratch repo
    // outlives the job checkout, but `with_git_dir` only redirects the
    // `--git-dir`; without rebinding cwd, every sweep git child still `fchdir`s
    // into the (reapable) job checkout and aborts once settlement removes it.
    let cwd = CwdHandle::open(&root).ok()?;
    Some((git_dir, cwd))
}

/// Create `dir` as a PRIVATE (0700) directory we own, or validate an existing one
/// is a real directory we own and not a symlink. Returns `None` (so the caller
/// skips, best-effort) when the path exists but fails that check — e.g. a symlink
/// or a directory planted by another user in the shared temp root.
fn create_private_dir(dir: &std::path::Path) -> Option<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        // `create` fails if the path already exists; a pre-existing entry is then
        // validated below rather than blindly reused.
        let _ = std::fs::DirBuilder::new().mode(0o700).create(dir);
        // `symlink_metadata` does NOT follow a final symlink, so a planted symlink
        // is rejected here instead of being silently dereferenced.
        let meta = std::fs::symlink_metadata(dir).ok()?;
        if !meta.file_type().is_dir() {
            return None;
        }
        if meta.uid() != current_uid() {
            return None;
        }
        // Tighten perms in case the directory pre-existed with looser modes.
        if meta.mode() & 0o077 != 0 {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok()?;
        }
        Some(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).ok()?;
        Some(())
    }
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
/// This MUST resolve to the SAME destination `provision()` cloned from, so it
/// delegates to [`crate::provision::trusted_fetch_source`] — the exact resolver
/// provisioning used. In particular a relative LOCAL path (e.g. `./origin.git`)
/// is re-anchored against the SUPERVISOR's cwd, not the job checkout: that is
/// where `provision()` resolved it, so anchoring anywhere else (such as the
/// checkout) would target a different — or nonexistent — repository. Remote
/// URLs (`scheme://…`) and scp-like SSH targets (`host:path`) pass through
/// unchanged. The URL is credential-sanitized (the runner re-attaches auth out
/// of band via the credential helper from the same raw `repo_url`, so an
/// embedded userinfo secret must never reach the sweep's argv).
fn sweep_remote_target(repo_url: &str) -> String {
    let (resolved, _cred) = crate::provision::trusted_fetch_source(repo_url);
    resolved
}

/// Run the orphan GC sweep opportunistically, throttled to `gc_every_ms` PER
/// repository (keyed by the sanitized target) so one busy repo cannot starve the
/// sweep of every other repo the daemon serves. Spawned detached so it never adds
/// latency to the job.
fn maybe_sweep(agent_cwd: &CwdHandle, repo_url: &str, plan: &Arc<Plan>, jobs: Jobs) {
    let now = now_ms();
    let every = plan.config.gc_every_ms.max(1);
    // Resolve the throttle key up front: the credential-sanitized repository
    // target (see the `sweep_remote` comment below). Keying on the SANITIZED
    // target — never the raw `repo_url` — keeps an embedded credential out of the
    // key and collapses credential variants of one repo onto a single slot.
    let sweep_remote = sweep_remote_target(repo_url);
    // Claim this repo's slot; a racing job for the SAME repo that observes the
    // same `last` loses and skips, so only one sweep runs per repo per window.
    // Other repos are unaffected — each has its own timestamp.
    {
        let mut stamps = match last_sweep_ms().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let last = stamps.get(&sweep_remote).copied().unwrap_or(0);
        if last != 0 && now.saturating_sub(last) < every {
            return;
        }
        stamps.insert(sweep_remote.clone(), now);
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
    // paths re-anchored against the SUPERVISOR's cwd exactly as `provision()`
    // resolved them when cloning, so the sweep targets the very repository the job
    // was provisioned from regardless of the scratch git-dir or checkout cwd.
    let plan = plan.clone();
    tokio::spawn(async move {
        // Run the sweep against a dedicated scratch repo (`--git-dir`) that
        // outlives this job's checkout. Otherwise the sweep fetches/reads
        // `refs/nano-gc/*` inside the job's `.git`, which settlement may reap
        // mid-sweep — failing every later git op while the hourly throttle
        // suppresses a retry (so repeated short jobs starve reclamation).
        let Some((git_dir, scratch_cwd)) = sweep_scratch_repo(&runner).await else {
            crate::runtime::log(
                "checkpoint: orphan sweep skipped — could not prepare a scratch repo",
            );
            return;
        };
        let runner = runner.with_git_dir(git_dir).with_cwd(scratch_cwd);
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

/// Queue a recovery promotion whenever the owned recovery ref LAGS the owned WIP
/// ref, deriving the pending sha from the leases themselves rather than only from
/// a WIP push's own success path. The recovery (GC-proof) ref is normally
/// promoted to the WIP sha right after each WIP push, but two paths advance the
/// WIP lease WITHOUT running that promotion: a self-resume that SEEDS the WIP
/// lease ahead of an absent/older recovery ref, and [`reconcile_landed_wip`]
/// re-basing the WIP lease onto an ambiguous push that actually landed. In both,
/// if the workspace then stays unchanged, `push_snapshot` keeps returning
/// `unchanged`/`clean` and the recovery ref is never repaired — so an explicit
/// resume from the recovery ref misses the latest work. Re-deriving the pending
/// promotion from the leases after reconciliation closes that gap: when WE own
/// both leases and the recovery target trails the WIP target, queue the WIP sha
/// (the retry path promotes it even on an otherwise-idle tick). Otherwise keep
/// whatever promotion was already pending (nanobpm/nano-supervisor#82).
fn derive_pending_recovery(leases: &LeaseState, pending: Option<String>) -> Option<String> {
    let own = leases.own.lock().unwrap();
    let recovered = leases.recovered.lock().unwrap();
    if own.owned && recovered.owned && !own.expect.is_empty() && own.expect != recovered.expect {
        return Some(own.expect.clone());
    }
    pending
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
    // The GC-proof recovery ref is promoted AFTER the WIP push each tick. When
    // that promotion fails transiently we remember the published sha here and
    // retry it on later ticks — WITHOUT withholding the WIP `last_tree` advance,
    // which would otherwise let a subsequent discard-to-base reappear on resume
    // (the stale snapshot never gets superseded) and would also mask the recovery
    // retry behind the resulting `clean` no-ops (nanobpm/nano-supervisor#66).
    let mut recovery_pending: Option<String> = None;
    let mut delay = first;
    loop {
        tokio::select! {
            _ = stop.notified() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = interval;
        // Reconcile any earlier WIP push whose outcome was uncertain BEFORE
        // snapshotting, so a push that actually landed updates our supersession
        // baseline even on a clean/unchanged no-op tick — otherwise a since-
        // discarded worktree would never supersede the landed (now-unwanted) work
        // on the remote and it would reappear on resume.
        last_tree = reconcile_landed_wip(&runner, &plan, &leases, last_tree).await;
        // Re-derive the pending recovery promotion from the (possibly just
        // reconciled or self-resume-seeded) leases BEFORE snapshotting. A WIP
        // lease that advanced WITHOUT a paired recovery push leaves the GC-proof
        // recovery ref behind; queue the promotion now so an unchanged-workspace
        // idle tick still repairs it instead of looping on `unchanged`/`clean`
        // forever (nanobpm/nano-supervisor#82).
        recovery_pending = derive_pending_recovery(&leases, recovery_pending);
        match push_snapshot(
            &runner,
            &plan,
            last_tree.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
            recovery_pending.as_deref(),
            &leases,
        )
        .await
        {
            TickOutcome::Pushed {
                tree,
                head,
                recovery_pending: rp,
            } => {
                last_tree = Some((tree, head));
                recovery_pending = rp;
            }
            TickOutcome::Idle {
                recovery_pending: rp,
            } => {
                recovery_pending = rp;
            }
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
    // Snapshot the shas we previously attempted BEFORE this push, so an ambiguous
    // failure of any earlier push (server applied it, client lost the response)
    // can be reconciled if this push is now rejected as stale.
    let prev_attempts = { lock.lock().unwrap().attempted.clone() };
    let res = push_checkpoint(runner, &reference, sha, &expect, remote).await;
    if matches!(res, PushResult::StaleLease { .. }) && !prev_attempts.is_empty() {
        // A stale-lease rejection usually means a sibling moved the ref — but it
        // can also mean OUR OWN previous push actually LANDED while reporting a
        // transient error, leaving `expect` behind the remote. Verify the remote
        // tip: if it holds ANY sha WE attempted-but-could-not-confirm, that push
        // was ours, so re-base the lease on it and RETRY this push against the
        // recovered expectation rather than bowing out. We only ever adopt our OWN
        // attempted shas — never an arbitrary remote tip — so a genuine sibling
        // write (remote tip matches none of our attempts) still drops ownership.
        let remote_sha = observe_remote_ref_sha(runner, &reference, remote).await;
        if !remote_sha.is_empty() && prev_attempts.iter().any(|s| s == &remote_sha) {
            crate::runtime::log(&format!(
                "checkpoint: {reference} already holds our previously-attempted sha \
                 (ambiguous push landed); re-leasing and retrying"
            ));
            {
                let mut l = lock.lock().unwrap();
                l.expect = remote_sha.clone();
                l.owned = true;
                l.attempted.clear();
            }
            let retry = push_checkpoint(runner, &reference, sha, &remote_sha, remote).await;
            lock.lock().unwrap().apply(&retry, sha);
            return retry;
        }
    }
    lock.lock().unwrap().apply(&res, sha);
    res
}

/// Reconcile an earlier WIP push whose outcome was UNCERTAIN (reported an error
/// that may actually have LANDED) BEFORE this tick takes its snapshot, so the
/// reconciliation runs even on otherwise-idle (clean/unchanged) ticks. If the
/// remote WIP ref holds a sha we attempted-but-could-not-confirm, that push
/// landed: re-base our lease onto it and return it as the supersession baseline
/// so a worktree that has since been DISCARDED publishes a clean superseding
/// snapshot this tick instead of silently leaving the landed (now-unwanted) work
/// on the remote to reappear on resume (nanobpm/nano-supervisor#82).
///
/// We ONLY advance when the remote actually holds one of our attempted shas —
/// a push that never landed (remote still at our `expect`, or moved by a sibling)
/// keeps its uncertainty and its retry, so this never masks a real publication
/// failure as complete (the reviewer's explicit caution against blindly advancing
/// `last_tree` on every error).
async fn reconcile_landed_wip(
    runner: &GitRunner,
    plan: &Plan,
    leases: &LeaseState,
    last_tree: Option<(String, String)>,
) -> Option<(String, String)> {
    let attempts = {
        let l = leases.own.lock().unwrap();
        if !l.owned {
            return last_tree;
        }
        l.attempted.clone()
    };
    if attempts.is_empty() {
        return last_tree;
    }
    let remote_sha = observe_remote_ref_sha(runner, &plan.own_ref, &plan.remote).await;
    if remote_sha.is_empty() || !attempts.iter().any(|s| s == &remote_sha) {
        return last_tree;
    }
    // Derive the `(tree, head)` the landed snapshot recorded. A snapshot commits
    // `commit-tree <tree> -p <head>`, so its tree is `<sha>^{tree}` and its head is
    // its first parent (empty for a snapshot taken on an unborn HEAD). Read them
    // BEFORE mutating the lease so a failed rev-parse leaves the lease untouched.
    let tree = runner
        .run(&[
            "rev-parse",
            "--verify",
            "-q",
            &format!("{remote_sha}^{{tree}}"),
        ])
        .await
        .out();
    if tree.is_empty() {
        return last_tree;
    }
    let head = runner
        .run(&["rev-parse", "--verify", "-q", &format!("{remote_sha}^")])
        .await
        .out();
    // Our ambiguous push LANDED. Re-base the lease onto the real remote tip and
    // clear the uncertainty so later ticks (and finalize) expect the right sha.
    {
        let mut l = leases.own.lock().unwrap();
        l.expect = remote_sha.clone();
        l.owned = true;
        l.attempted.clear();
    }
    crate::runtime::log(&format!(
        "checkpoint: WIP ref {} already holds our previously-attempted sha \
         (ambiguous push landed); reconciling supersession baseline",
        plan.own_ref
    ));
    Some((tree, head))
}

/// Snapshot the worktree and push it to the WIP ref (and promote the GC-proof
/// recovery ref), each under its own ownership lease held in the shared state.
async fn push_snapshot(
    runner: &GitRunner,
    plan: &Plan,
    last_tree: Option<(&str, &str)>,
    recovery_pending: Option<&str>,
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
            // Nothing new to publish, but an earlier successful WIP push may have
            // left its recovery promotion unfinished — retry it so a transient
            // recovery failure converges rather than stranding the recovery ref.
            let pending = retry_pending_recovery(runner, plan, leases, recovery_pending).await;
            return TickOutcome::Idle {
                recovery_pending: pending,
            };
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
            // The WIP push itself failed, so there is no newly-published sha to
            // promote and nothing to advance; keep retrying whatever recovery
            // promotion was already pending from an earlier successful push.
            let pending = retry_pending_recovery(runner, plan, leases, recovery_pending).await;
            return TickOutcome::Idle {
                recovery_pending: pending,
            };
        }
    }
    // The WIP push SUCCEEDED, so ALWAYS advance `last_tree`: the published
    // snapshot is now our dedup baseline AND — crucially — the value a later
    // discard-to-base compares against to SUPERSEDE this snapshot on the remote.
    // The GC-proof recovery copy (#295) is promoted SEPARATELY; a transient
    // failure there is remembered as `recovery_pending` and retried on later
    // ticks, but it must NOT withhold the WIP advance. The previous code returned
    // `Idle` (unadvanced `last_tree`) on a transient recovery error even though
    // the WIP snapshot was already published: a subsequent discard back to base
    // then read `last_tree` as empty/stale, reported `clean`, and never
    // superseded the published snapshot — so the discarded work reappeared on
    // resume, and the recovery promotion was itself never retried.
    let rec = lease_push_shared(runner, &plan.remote, &leases.recovered, &sha).await;
    let recovery_pending = if recovery_requires_retry(&rec) {
        crate::runtime::log(&format!(
            "checkpoint: recovery promotion to {} failed transiently; will retry next tick",
            plan.recovered_ref
        ));
        Some(sha)
    } else {
        None
    };
    TickOutcome::Pushed {
        tree,
        head,
        recovery_pending,
    }
}

/// Retry a recovery promotion a previous tick could not complete. Pushes the
/// pending sha to the recovery ref under its shared lease and returns `Some(sha)`
/// if it still needs retrying, or `None` once it has succeeded or hit a TERMINAL
/// result (a stale-lease rejection means a sibling owns the recovery ref — we
/// never reclaim it). A `None` input is a no-op. The recovery ref is a single
/// moving ref, so retrying the latest published sha is always correct — a stale
/// pending sha can never be re-promoted because each successful WIP push replaces
/// `recovery_pending` with its own (newer) sha.
async fn retry_pending_recovery(
    runner: &GitRunner,
    plan: &Plan,
    leases: &LeaseState,
    pending: Option<&str>,
) -> Option<String> {
    let sha = pending?;
    let rec = lease_push_shared(runner, &plan.remote, &leases.recovered, sha).await;
    if recovery_requires_retry(&rec) {
        Some(sha.to_string())
    } else {
        if matches!(rec, PushResult::Ok) {
            crate::runtime::log(&format!(
                "checkpoint: deferred recovery promotion to {} succeeded",
                plan.recovered_ref
            ));
        }
        None
    }
}

/// Whether a recovery-promotion push result must be retried on a later tick
/// (so `push_snapshot` withholds `last_tree` advancement). Only a TRANSIENT
/// error retries: a successful push published the recovery copy, and a
/// stale-lease rejection means a sibling owns the recovery ref (terminal — we
/// never reclaim it), so neither should stall snapshot dedup.
fn recovery_requires_retry(rec: &PushResult) -> bool {
    matches!(rec, PushResult::Error { .. })
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
    fn sweep_remote_target_resolves_like_provisioning() {
        // An embedded HTTPS credential is scrubbed from the sweep's remote argv,
        // and the scheme/host are preserved (remote URLs pass through unchanged).
        let url = sweep_remote_target("https://sekret123@github.com/o/r.git");
        assert!(
            !url.contains("sekret123"),
            "credential leaked into sweep remote: {url}"
        );
        assert_eq!(url, "https://github.com/o/r.git");

        // scp-like SSH targets pass through untouched (not treated as a path).
        assert_eq!(
            sweep_remote_target("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );

        // An absolute local path is passed through unchanged.
        let abs = std::env::temp_dir().join("sweep-abs.git");
        let abs_s = abs.to_string_lossy().into_owned();
        assert_eq!(sweep_remote_target(&abs_s), abs_s);

        // A relative local path is re-anchored against the SUPERVISOR's cwd —
        // exactly where `provision()`/`trusted_fetch_source` resolve it — so the
        // sweep and the clone target the same repository. Delegating to the same
        // resolver guarantees this.
        let (provisioned, _) = crate::provision::trusted_fetch_source("remote.git");
        assert_eq!(sweep_remote_target("remote.git"), provisioned);
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            sweep_remote_target("remote.git"),
            cwd.join("remote.git").to_string_lossy()
        );
    }

    #[test]
    fn sweep_throttle_is_scoped_per_repository() {
        // The review finding: a single GLOBAL sweep throttle lets whichever repo
        // schedules first in each window claim the only slot, so a busy repo A
        // starves the sweep of every other repo B. The throttle is now keyed by the
        // sanitized repository target, so each repo is throttled independently.
        let every = 3_600_000_u64; // 1h
        let t0 = 1_000_000_000_000_u64;
        let repo_a = "https://github.com/o/a.git".to_string();
        let repo_b = "https://github.com/o/b.git".to_string();

        // Helper mirroring maybe_sweep's claim logic against a fresh map.
        fn claim(map: &mut HashMap<String, u64>, key: &str, now: u64, every: u64) -> bool {
            let last = map.get(key).copied().unwrap_or(0);
            if last != 0 && now.saturating_sub(last) < every {
                return false; // throttled
            }
            map.insert(key.to_string(), now);
            true
        }

        let mut stamps: HashMap<String, u64> = HashMap::new();
        // A sweeps at t0 and claims its slot.
        assert!(
            claim(&mut stamps, &repo_a, t0, every),
            "A's first sweep runs"
        );
        // Within the same window A is throttled, but B — a DIFFERENT repo — is not:
        // B has its own timestamp, so the shared-window starvation is gone.
        assert!(
            !claim(&mut stamps, &repo_a, t0 + 1_000, every),
            "A throttled within its own window"
        );
        assert!(
            claim(&mut stamps, &repo_b, t0 + 1_000, every),
            "B must NOT be starved by A's window (per-repo throttle)"
        );
        // After the window elapses, A sweeps again.
        assert!(
            claim(&mut stamps, &repo_a, t0 + every, every),
            "A sweeps again once its own window elapses"
        );

        // Keying on the SANITIZED target collapses credential variants of one repo
        // onto a single throttle slot (and keeps secrets out of the key).
        assert_eq!(
            sweep_remote_target("https://sekret123@github.com/o/a.git"),
            repo_a,
            "credential variant must map to the same throttle key"
        );
    }

    /// Regression: the scratch-repo root is created PRIVATE (0700) we own, and a
    /// pre-existing entry is validated — a symlink (symlink-reuse attack) is
    /// rejected, and a reused directory with looser modes is tightened to 0700.
    #[cfg(unix)]
    #[test]
    fn create_private_dir_is_0700_and_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let base =
            std::env::temp_dir().join(format!("nano-privdir-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();

        // Fresh create: directory exists with exactly 0700.
        let fresh = base.join("fresh");
        assert!(create_private_dir(&fresh).is_some());
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "fresh dir not private: {mode:o}");

        // Reuse with loose perms: tightened back to 0700.
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(create_private_dir(&fresh).is_some());
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "reused dir not tightened: {mode:o}");

        // A planted symlink at the path is rejected, not dereferenced.
        let link = base.join("link");
        std::os::unix::fs::symlink(&fresh, &link).unwrap();
        assert!(
            create_private_dir(&link).is_none(),
            "symlink accepted as private dir"
        );

        let _ = std::fs::remove_dir_all(&base);
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

    #[tokio::test]
    async fn sweep_runs_after_job_checkout_cwd_is_reaped() {
        // The orphan sweep binds its runner to a persistent scratch directory so
        // reaping the job checkout mid-sweep cannot fail its git ops. Regression:
        // with_git_dir alone left the runner's cwd on the (reapable) checkout, so
        // once settlement removed it `getcwd` failed with ENOENT and every sweep
        // git child aborted even with an absolute --git-dir.
        let git_ok = std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !git_ok {
            return;
        }
        let dur = Duration::from_secs(30);
        let checkout = std::env::temp_dir().join(format!(
            "nano-sweep-cwd-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&checkout).unwrap();
        let checkout = std::fs::canonicalize(&checkout).unwrap();
        let runner = GitRunner::new(CwdHandle::open(&checkout).unwrap(), dur);

        // Prepare the scratch repo + persistent cwd exactly as the sweep does,
        // then rebind the runner onto the scratch directory.
        let (git_dir, scratch_cwd) = sweep_scratch_repo(&runner).await.expect("scratch repo");
        let runner = runner.with_git_dir(git_dir).with_cwd(scratch_cwd);

        // Reap the job checkout the runner was originally built on.
        std::fs::remove_dir_all(&checkout).unwrap();

        // A git op must still succeed because the sweep's cwd is the live scratch
        // directory, not the removed checkout.
        let r = runner.run(&["rev-parse", "--is-bare-repository"]).await;
        assert!(
            r.ok(),
            "sweep git op failed after checkout cwd was reaped: {}",
            r.err_text()
        );
        assert_eq!(r.out(), "true");
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
        // A CONFIRMED success resolves the remote tip to the sha we wrote, so every
        // prior uncertain attempt is cleared — nothing left to reconcile.
        assert!(lease.attempted.is_empty());
    }

    #[test]
    fn lease_records_attempted_sha_even_on_failure() {
        // An ambiguous push (server applied it, client lost the response) reports
        // a transient Error and leaves `expect` behind — but we MUST remember the
        // sha we attempted so the next stale-lease rejection can be reconciled
        // against the remote tip instead of blindly dropping ownership.
        let mut lease = RefLease::new(OWN.to_string(), Some("aaa".into()));
        lease.apply(
            &PushResult::Error {
                error: "timeout".into(),
            },
            "bbb",
        );
        assert_eq!(
            lease.expect, "aaa",
            "transient error must not advance expect"
        );
        assert_eq!(
            lease.attempted,
            vec!["bbb".to_string()],
            "attempted sha must be recorded"
        );
        assert!(lease.owned);
    }

    #[test]
    fn lease_accumulates_unresolved_attempts_without_overwriting() {
        // S1 lands ambiguously (transient error), then S2 fails outright before
        // reaching the server. A single-slot `attempted` would overwrite S1 with
        // S2 and later reconcile the remote (still at S1) against the wrong value,
        // dropping ownership. The set must keep BOTH so either can be reconciled.
        let mut lease = RefLease::new(OWN.to_string(), None);
        lease.apply(&PushResult::Error { error: "t1".into() }, "s1");
        lease.apply(&PushResult::Error { error: "t2".into() }, "s2");
        assert_eq!(lease.attempted, vec!["s1".to_string(), "s2".to_string()]);
        // The SAME sha retried must not be duplicated.
        lease.apply(&PushResult::Error { error: "t3".into() }, "s2");
        assert_eq!(lease.attempted, vec!["s1".to_string(), "s2".to_string()]);
        // A confirmed success clears every uncertain attempt.
        lease.apply(&PushResult::Ok, "s3");
        assert!(lease.attempted.is_empty());
    }

    #[tokio::test]
    async fn retry_pending_recovery_is_a_noop_when_nothing_is_pending() {
        // With no pending promotion the helper must not touch git at all and must
        // report nothing pending — the common idle-tick path.
        let dur = Duration::from_secs(5);
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let runner = GitRunner::new(CwdHandle::open(&tmp).unwrap(), dur);
        let plan = Plan {
            config: CheckpointConfig::from_env(),
            own_ref: OWN.to_string(),
            recovered_ref: "refs/nano/recovered/x".to_string(),
            working_branch: String::new(),
            base_sha: String::new(),
            base_ref: "main".to_string(),
            run_id: "r".to_string(),
            remote: "origin".to_string(),
            secret_values: Vec::new(),
        };
        let leases = LeaseState {
            own: std::sync::Mutex::new(RefLease::new(OWN.to_string(), None)),
            recovered: std::sync::Mutex::new(RefLease::new(
                "refs/nano/recovered/x".to_string(),
                None,
            )),
        };
        assert_eq!(
            retry_pending_recovery(&runner, &plan, &leases, None).await,
            None
        );
    }

    fn lease_state(own: RefLease, recovered: RefLease) -> LeaseState {
        LeaseState {
            own: std::sync::Mutex::new(own),
            recovered: std::sync::Mutex::new(recovered),
        }
    }

    #[test]
    fn derive_recovery_queues_wip_when_recovery_ref_lags() {
        const REC: &str = "refs/nano/recovered/e";
        // Self-resume seeds the WIP lease at S1 while recovery is ABSENT
        // (create-only, empty expect). The recovery ref lags, so an unchanged
        // workspace would never repair it — derive must queue the WIP sha.
        let leases = lease_state(
            RefLease::new(OWN.to_string(), Some("s1".into())),
            RefLease::new(REC.to_string(), None),
        );
        assert_eq!(
            derive_pending_recovery(&leases, None),
            Some("s1".to_string())
        );
        // Recovery present but at an OLDER sha (S0) than the WIP ref => still lags.
        let leases = lease_state(
            RefLease::new(OWN.to_string(), Some("s1".into())),
            RefLease::new(REC.to_string(), Some("s0".into())),
        );
        assert_eq!(
            derive_pending_recovery(&leases, None),
            Some("s1".to_string())
        );
    }

    #[test]
    fn derive_recovery_keeps_pending_when_not_lagging() {
        const REC: &str = "refs/nano/recovered/e";
        // Recovery already matches the WIP ref: nothing to queue. Any pending
        // promotion already in flight is preserved verbatim (not clobbered).
        let leases = lease_state(
            RefLease::new(OWN.to_string(), Some("s1".into())),
            RefLease::new(REC.to_string(), Some("s1".into())),
        );
        assert_eq!(derive_pending_recovery(&leases, None), None);
        assert_eq!(
            derive_pending_recovery(&leases, Some("s9".into())),
            Some("s9".to_string())
        );
        // A create-only WIP lease (no snapshot pushed yet) has nothing to promote.
        let leases = lease_state(
            RefLease::new(OWN.to_string(), None),
            RefLease::new(REC.to_string(), None),
        );
        assert_eq!(derive_pending_recovery(&leases, None), None);
    }

    #[test]
    fn derive_recovery_never_touches_unowned_leases() {
        const REC: &str = "refs/nano/recovered/e";
        // A lost WIP lease (a sibling moved the ref) must not drive our recovery
        // promotion — we no longer own the work it points at.
        let mut own_lost = RefLease::new(OWN.to_string(), Some("s1".into()));
        own_lost.owned = false;
        let leases = lease_state(own_lost, RefLease::new(REC.to_string(), None));
        assert_eq!(derive_pending_recovery(&leases, None), None);
        // A lost RECOVERY lease means a sibling owns the recovery ref; we never
        // reclaim it, so we must not queue a promotion against it.
        let mut rec_lost = RefLease::new(REC.to_string(), Some("s0".into()));
        rec_lost.owned = false;
        let leases = lease_state(RefLease::new(OWN.to_string(), Some("s1".into())), rec_lost);
        assert_eq!(derive_pending_recovery(&leases, None), None);
    }

    #[test]
    fn recovery_retry_only_on_transient_error() {
        // A transient recovery-promotion error must retry (so `push_snapshot`
        // withholds `last_tree` and the next tick re-promotes instead of masking
        // the failed publication as complete).
        assert!(recovery_requires_retry(&PushResult::Error {
            error: "connection reset".into()
        }));
        // A successful promotion published the recovery copy — no retry.
        assert!(!recovery_requires_retry(&PushResult::Ok));
        // A stale lease means a sibling owns the recovery ref; we never reclaim
        // it, so it is terminal, not a retryable transient failure.
        assert!(!recovery_requires_retry(&PushResult::StaleLease {
            error: "rejected".into()
        }));
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

    /// Regression (nanobpm/nano-supervisor#66, review round 9): a transient
    /// RECOVERY promotion failure must NOT withhold the WIP `last_tree` advance.
    /// The previous code returned `Idle` (unadvanced) whenever recovery promotion
    /// failed, even though the WIP snapshot was already published — so a later
    /// discard-to-base read `last_tree` as empty, reported `clean`, and never
    /// superseded the published WIP, which then reappeared on resume. Drive a
    /// recovery failure followed by discarding the work and assert the discard
    /// supersedes the published snapshot on the remote.
    #[tokio::test]
    async fn wip_advance_survives_recovery_failure_so_discard_supersedes() {
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
        let root =
            std::env::temp_dir().join(format!("nano-recov-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let root_git = runner_at(&root);
        assert!(root_git.run(&["init", "--bare", "remote.git"]).await.ok());
        assert!(root_git.run(&["clone", "remote.git", "work"]).await.ok());
        let git = runner_at(&root.join("work"));
        assert!(git
            .run(&["symbolic-ref", "HEAD", "refs/heads/main"])
            .await
            .ok());
        std::fs::write(root.join("work/README.md"), "base\n").unwrap();
        assert!(git.run(&["add", "-A"]).await.ok());
        assert!(git
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
        assert!(git.run(&["push", "origin", "main"]).await.ok());
        let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

        let elem = "recov-elem";
        let own = checkpoint_ref(elem).unwrap();
        // An INVALID recovery ref (`..` is rejected by git) deterministically
        // forces the recovery promotion to fail with a transient Error every tick
        // — the exact condition that used to withhold the WIP advance.
        let plan = Plan {
            config: CheckpointConfig::from_env(),
            own_ref: own.clone(),
            recovered_ref: "refs/nano/recovered/..bad".to_string(),
            working_branch: "main".to_string(),
            base_sha: base_sha.clone(),
            base_ref: "main".to_string(),
            run_id: "run-recov".to_string(),
            remote: "origin".to_string(),
            secret_values: Vec::new(),
        };
        let leases = LeaseState {
            own: std::sync::Mutex::new(RefLease::new(own.clone(), None)),
            recovered: std::sync::Mutex::new(RefLease::new(plan.recovered_ref.clone(), None)),
        };

        // Tick 1: WIP work. Recovery promotion fails (bad ref) but the WIP push
        // succeeds — the tick MUST still advance dedup state and remember the
        // pending recovery.
        std::fs::write(root.join("work/WIP.txt"), "in progress\n").unwrap();
        let (tree, head, rec_pending) = match push_snapshot(&git, &plan, None, None, &leases).await
        {
            TickOutcome::Pushed {
                tree,
                head,
                recovery_pending,
            } => (tree, head, recovery_pending),
            TickOutcome::Idle { .. } => {
                panic!("WIP advance withheld after a recovery failure (the bug)")
            }
            TickOutcome::OwnershipLost => panic!("unexpected OwnershipLost"),
        };
        assert!(
            rec_pending.is_some(),
            "a transient recovery failure must be remembered for retry"
        );
        let wip_remote = observe_remote_ref_sha(&git, &own, "origin").await;
        assert!(!wip_remote.is_empty(), "WIP snapshot must be published");

        // Tick 2: DISCARD the work back to base. Because tick 1 advanced
        // `last_tree`, the clean snapshot now SUPERSEDES the published WIP.
        std::fs::remove_file(root.join("work/WIP.txt")).unwrap();
        let out2 = push_snapshot(
            &git,
            &plan,
            Some((tree.as_str(), head.as_str())),
            rec_pending.as_deref(),
            &leases,
        )
        .await;
        assert!(
            matches!(out2, TickOutcome::Pushed { .. }),
            "discard must publish a superseding snapshot"
        );
        let superseded = observe_remote_ref_sha(&git, &own, "origin").await;
        assert_ne!(
            superseded, wip_remote,
            "the discarded WIP must be superseded on the remote, not left to reappear"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression (review round 9): an ambiguous push failure (the server applied
    /// the update but the client lost the response) leaves the lease pinned to the
    /// pre-push `expect` while the remote has actually moved to our attempted sha.
    /// The next push must RECONCILE — observe that the remote holds OUR attempted
    /// sha and retry against it — rather than treating the stale-lease rejection as
    /// a sibling takeover and halting checkpointing for the rest of the run.
    #[tokio::test]
    async fn ambiguous_push_reconciles_against_our_own_landed_sha() {
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
        let root =
            std::env::temp_dir().join(format!("nano-ambig-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let root_git = runner_at(&root);
        assert!(root_git.run(&["init", "--bare", "remote.git"]).await.ok());
        assert!(root_git.run(&["clone", "remote.git", "work"]).await.ok());
        let git = runner_at(&root.join("work"));
        assert!(git
            .run(&["symbolic-ref", "HEAD", "refs/heads/main"])
            .await
            .ok());
        std::fs::write(root.join("work/README.md"), "base\n").unwrap();
        assert!(git.run(&["add", "-A"]).await.ok());
        assert!(git
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
        assert!(git.run(&["push", "origin", "main"]).await.ok());
        let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

        let elem = "ambig-elem";
        let own = checkpoint_ref(elem).unwrap();

        // S1: our FIRST snapshot. Publish it to the own ref — this models the
        // ambiguous push that LANDED on the remote.
        std::fs::write(root.join("work/WIP.txt"), "first\n").unwrap();
        let s1 = match snapshot_worktree(
            &git,
            &base_sha,
            "main",
            "run",
            None,
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_eq!(
            push_checkpoint(&git, &own, &s1, "", "origin").await,
            PushResult::Ok
        );

        // S2: our NEXT snapshot (not yet pushed).
        std::fs::write(root.join("work/WIP.txt"), "second\n").unwrap();
        let s2 = match snapshot_worktree(
            &git,
            &base_sha,
            "main",
            "run",
            Some((s1.as_str(), base_sha.as_str())),
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_ne!(s1, s2, "second snapshot must differ");

        // The ambiguous state: `expect` is still the pre-S1 create-only baseline
        // ("" demands absence), but we remember S1 as our last attempt — while the
        // remote actually holds S1.
        let mut own_lease = RefLease::new(own.clone(), None);
        own_lease.attempted = vec![s1.clone()];
        let leases = LeaseState {
            own: std::sync::Mutex::new(own_lease),
            recovered: std::sync::Mutex::new(RefLease::new(
                recovered_checkpoint_ref(elem).unwrap(),
                None,
            )),
        };

        // Pushing S2 first fails the create-only lease (the ref exists at S1), but
        // reconciliation observes remote == our attempted S1 and retries — landing
        // S2 and KEEPING ownership instead of halting.
        let res = lease_push_shared(&git, "origin", &leases.own, &s2).await;
        assert_eq!(
            res,
            PushResult::Ok,
            "ambiguous push must reconcile, not halt"
        );
        assert_eq!(
            observe_remote_ref_sha(&git, &own, "origin").await,
            s2,
            "the remote own ref must advance to our retried sha"
        );
        {
            let l = leases.own.lock().unwrap();
            assert!(l.owned, "ownership must be retained after reconciliation");
            assert_eq!(l.expect, s2, "lease must be re-based on the landed sha");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression (nanobpm/nano-supervisor#82, review round 10): a FIRST push can
    /// land ambiguously (transient error, but the server applied it) and a SECOND
    /// push then fail outright before reaching the server (so the remote still
    /// holds the first). A single-slot `attempted` would overwrite the first sha
    /// with the second, so the later stale-lease reconciliation would compare the
    /// remote (still at the first) against the second and conclude a sibling stole
    /// the ref — halting checkpointing. The accumulated attempt set must let the
    /// reconciliation match the remote against EITHER attempt and retry.
    #[tokio::test]
    async fn reconcile_survives_a_second_failed_attempt_overwriting_the_landed_sha() {
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
        let root =
            std::env::temp_dir().join(format!("nano-ambig2-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let root_git = runner_at(&root);
        assert!(root_git.run(&["init", "--bare", "remote.git"]).await.ok());
        assert!(root_git.run(&["clone", "remote.git", "work"]).await.ok());
        let git = runner_at(&root.join("work"));
        assert!(git
            .run(&["symbolic-ref", "HEAD", "refs/heads/main"])
            .await
            .ok());
        std::fs::write(root.join("work/README.md"), "base\n").unwrap();
        assert!(git.run(&["add", "-A"]).await.ok());
        assert!(git
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
        assert!(git.run(&["push", "origin", "main"]).await.ok());
        let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

        let elem = "ambig2-elem";
        let own = checkpoint_ref(elem).unwrap();

        // S1: lands on the remote (models the first ambiguous push that applied).
        std::fs::write(root.join("work/WIP.txt"), "first\n").unwrap();
        let s1 = match snapshot_worktree(
            &git,
            &base_sha,
            "main",
            "run",
            None,
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_eq!(
            push_checkpoint(&git, &own, &s1, "", "origin").await,
            PushResult::Ok
        );

        // S2: committed locally but NEVER pushed (models the second push failing to
        // connect — the remote still holds S1, not S2).
        std::fs::write(root.join("work/WIP.txt"), "second\n").unwrap();
        let s2 = match snapshot_worktree(
            &git,
            &base_sha,
            "main",
            "run",
            Some((s1.as_str(), base_sha.as_str())),
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };

        // S3: the push we now retry once the connection recovers.
        std::fs::write(root.join("work/WIP.txt"), "third\n").unwrap();
        let s3 = match snapshot_worktree(
            &git,
            &base_sha,
            "main",
            "run",
            Some((s2.as_str(), base_sha.as_str())),
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };

        // The ambiguous state after two failed pushes: expect is still the
        // create-only baseline, and BOTH S1 (landed) and S2 (never landed) are
        // unresolved attempts — in that order, so the single-slot bug would keep
        // only S2.
        let mut own_lease = RefLease::new(own.clone(), None);
        own_lease.attempted = vec![s1.clone(), s2.clone()];
        let leases = LeaseState {
            own: std::sync::Mutex::new(own_lease),
            recovered: std::sync::Mutex::new(RefLease::new(
                recovered_checkpoint_ref(elem).unwrap(),
                None,
            )),
        };

        // Pushing S3 fails the create-only lease (ref exists at S1); reconciliation
        // must find the remote (S1) among our attempts and retry — landing S3 and
        // KEEPING ownership instead of halting on the overwritten S2.
        let res = lease_push_shared(&git, "origin", &leases.own, &s3).await;
        assert_eq!(
            res,
            PushResult::Ok,
            "reconciliation must match the remote against an earlier attempt, not halt"
        );
        assert_eq!(
            observe_remote_ref_sha(&git, &own, "origin").await,
            s3,
            "the remote own ref must advance to our retried sha"
        );
        {
            let l = leases.own.lock().unwrap();
            assert!(l.owned, "ownership must be retained after reconciliation");
            assert_eq!(l.expect, s3, "lease must be re-based on the landed sha");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression (nanobpm/nano-supervisor#82, review round 10): a WIP push can
    /// land on the remote but report a transient error, so the tick leaves
    /// `last_tree` unadvanced. If the agent then DISCARDS back to base, the clean
    /// snapshot alone has no baseline to supersede against, so the no-op tick never
    /// replaces the landed (now-unwanted) WIP — it reappears on resume. Reconciling
    /// the uncertain publication BEFORE the snapshot restores the supersession
    /// baseline so the discard publishes a superseding snapshot.
    #[tokio::test]
    async fn uncertain_wip_publication_is_reconciled_so_discard_supersedes() {
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
        let root =
            std::env::temp_dir().join(format!("nano-uncwip-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let root_git = runner_at(&root);
        assert!(root_git.run(&["init", "--bare", "remote.git"]).await.ok());
        assert!(root_git.run(&["clone", "remote.git", "work"]).await.ok());
        let git = runner_at(&root.join("work"));
        assert!(git
            .run(&["symbolic-ref", "HEAD", "refs/heads/main"])
            .await
            .ok());
        std::fs::write(root.join("work/README.md"), "base\n").unwrap();
        assert!(git.run(&["add", "-A"]).await.ok());
        assert!(git
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
        assert!(git.run(&["push", "origin", "main"]).await.ok());
        let base_sha = git.run(&["rev-parse", "HEAD"]).await.out();

        let elem = "uncwip-elem";
        let own = checkpoint_ref(elem).unwrap();
        let plan = Plan {
            config: CheckpointConfig::from_env(),
            own_ref: own.clone(),
            recovered_ref: recovered_checkpoint_ref(elem).unwrap(),
            working_branch: "main".to_string(),
            base_sha: base_sha.clone(),
            base_ref: "main".to_string(),
            run_id: "run-uncwip".to_string(),
            remote: "origin".to_string(),
            secret_values: Vec::new(),
        };

        // Model the landed-but-reported-failed WIP push: snapshot S1, push it so it
        // is ON the remote, but leave the lease in the ambiguous state (expect at
        // the create-only baseline, S1 only an unresolved attempt) and `last_tree`
        // unadvanced — exactly what `push_snapshot` leaves behind on a WIP-push
        // Error that actually landed.
        std::fs::write(root.join("work/WIP.txt"), "in progress\n").unwrap();
        let s1 = match snapshot_worktree(
            &git,
            &base_sha,
            "main",
            "run-uncwip",
            None,
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_eq!(
            push_checkpoint(&git, &own, &s1, "", "origin").await,
            PushResult::Ok
        );
        let mut own_lease = RefLease::new(own.clone(), None);
        own_lease.attempted = vec![s1.clone()];
        let leases = LeaseState {
            own: std::sync::Mutex::new(own_lease),
            recovered: std::sync::Mutex::new(RefLease::new(
                recovered_checkpoint_ref(elem).unwrap(),
                None,
            )),
        };

        // The agent DISCARDS the work back to base.
        std::fs::remove_file(root.join("work/WIP.txt")).unwrap();

        // A no-op tick with `last_tree = None` would normally report `clean` and
        // leave S1 on the remote. Reconciliation restores the supersession baseline
        // from the landed sha first.
        let last_tree = reconcile_landed_wip(&git, &plan, &leases, None).await;
        assert!(
            last_tree.is_some(),
            "a landed-but-uncertain WIP push must restore the supersession baseline"
        );
        {
            let l = leases.own.lock().unwrap();
            assert_eq!(l.expect, s1, "lease must be re-based on the landed WIP sha");
            assert!(
                l.attempted.is_empty(),
                "the reconciled attempt must be cleared"
            );
        }

        // With the baseline restored, the discard now publishes a SUPERSEDING
        // snapshot that replaces S1 on the remote.
        let out = push_snapshot(
            &git,
            &plan,
            last_tree.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
            None,
            &leases,
        )
        .await;
        assert!(
            matches!(out, TickOutcome::Pushed { .. }),
            "the discard must publish a superseding snapshot after reconciliation"
        );
        let remote_now = observe_remote_ref_sha(&git, &own, "origin").await;
        assert_ne!(
            remote_now, s1,
            "the discarded WIP must be superseded on the remote, not left to reappear"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression (nanobpm/nano-supervisor#82, review round 10): on a REDELIVERY
    /// after an explicit adoption, the `resumeFromCheckpoint` pointer still names
    /// the predecessor even though our OWN ref now holds newer progress. Restore
    /// tries the predecessor first, its create-only adoption onto our own ref fails
    /// (the ref already exists), and the old code bowed out — leaving `seed_own`
    /// empty so the periodic loop's first push was rejected as a stale lease and
    /// checkpointing stopped. Restore must instead fall through to resume our own
    /// newer checkpoint.
    #[tokio::test]
    async fn redelivery_after_adoption_resumes_own_newer_progress() {
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
        let root =
            std::env::temp_dir().join(format!("nano-redeliv-{}-{}", std::process::id(), now_ms()));
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
        let base_sha = seed.run(&["rev-parse", "HEAD"]).await.out();

        let pred_elem = "redeliv-pred";
        let own_elem = "redeliv-own";
        let pred_ref = checkpoint_ref(pred_elem).unwrap();
        let own_ref = checkpoint_ref(own_elem).unwrap();

        // Predecessor snapshot (the adopted source).
        std::fs::write(root.join("seed/WORK.txt"), "adopted work\n").unwrap();
        let pred_sha = match snapshot_worktree(
            &seed,
            &base_sha,
            "main",
            "run-pred",
            None,
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_eq!(
            push_checkpoint(&seed, &pred_ref, &pred_sha, "", "origin").await,
            PushResult::Ok
        );

        // Our OWN ref already holds NEWER progress (what the first delivery produced
        // after adopting the predecessor).
        std::fs::write(root.join("seed/WORK.txt"), "newer own progress\n").unwrap();
        let own_sha = match snapshot_worktree(
            &seed,
            &base_sha,
            "main",
            "run-own",
            None,
            5_000_000,
            &[],
            "nano: WIP",
        )
        .await
        {
            Snapshot::Committed { sha, .. } => sha,
            Snapshot::Skipped { reason } => panic!("snapshot skipped: {reason}"),
        };
        assert_ne!(
            own_sha, pred_sha,
            "own progress must differ from predecessor"
        );
        assert_eq!(
            push_checkpoint(&seed, &own_ref, &own_sha, "", "origin").await,
            PushResult::Ok
        );

        // Fresh redelivery checkout on main, still pointed at the predecessor.
        assert!(root_git.run(&["clone", "remote.git", "redeliv"]).await.ok());
        let git = runner_at(&root.join("redeliv"));
        let plan = Plan {
            config: CheckpointConfig::from_env(),
            own_ref: own_ref.clone(),
            recovered_ref: recovered_checkpoint_ref(own_elem).unwrap(),
            working_branch: "main".to_string(),
            base_sha: base_sha.clone(),
            base_ref: "main".to_string(),
            run_id: "run-redeliv".to_string(),
            remote: "origin".to_string(),
            secret_values: Vec::new(),
        };
        let variables = serde_json::json!({ "resumeFromCheckpoint": pred_ref });
        let outcome = restore(&git, &plan, &variables, "task").await;

        assert_eq!(
            outcome.seed_own.as_deref(),
            Some(own_sha.as_str()),
            "redelivery must resume our own newer progress, not bow out after a \
             failed re-adoption"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("redeliv/WORK.txt")).unwrap(),
            "newer own progress\n",
            "the worktree must restore our own newer checkpoint"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
