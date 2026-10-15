//! Keep the worker's `gh auth token` fresh for its whole lifetime
//! (nanobpm/nano-supervisor#67, porting jwulf/c8ctl-plugin-nano#294 / #293).
//!
//! A long-lived worker that falls back to `gh auth token` for its GitHub
//! credential would otherwise memoize the first read for the whole process
//! lifetime, so a `gh auth login` / `gh auth refresh` the operator runs while
//! the fleet is up never reaches an in-flight worker and every subsequent job
//! is handed a **stale** token. This module ports the plugin's fix: the token
//! is cached as a record (`{ token, fingerprint, scopes, since, last_check }`)
//! with a TTL and re-read on a worker-lifetime cadence **off the job path**, so
//! a rotated login is adopted within an interval without ever blocking a job.
//!
//! The cache keeps the **FD / no-env-leak** guarantees of the credential
//! delivery from #24/#62: the token value never rides argv (the scopes probe
//! passes it to `gh` via `GH_TOKEN` in the child env, exactly like
//! [`crate::provision`]'s delivery) and is never logged — only its
//! non-reversible **fingerprint** and OAuth **scopes** appear in logs and the
//! supervisor activity marker.
//!
//! The design mirrors the plugin so the parity ledger (#57) can cite it:
//!
//! - [`GhTokenCache::token_for_cli`] is the per-job hot path: it serves the **primed**
//!   cache verbatim, never a blocking TTL re-read, so a job is never stalled on
//!   a `gh` spawn.
//! - [`GhTokenCache::prime`] warms the cache once at worker startup (off the job
//!   path) and logs the token identity.
//! - [`GhTokenCache::maintenance_tick`] is the worker-lifetime refresh: it
//!   **defers** while a job is active (so no `gh` read happens mid-job) but that
//!   defer is **bounded** (`NANO_GH_TOKEN_MAX_DEFER_MS`) so a saturated worker
//!   that is never idle at a tick still re-reads once the primed cache is stale
//!   beyond the bound, capping staleness at a few intervals.
//! - [`GhTokenCache::recover_after_auth_failure`] force-re-reads after a
//!   clone/push auth failure and returns a token **iff** it differs from the one
//!   that just failed — a non-destructive recovery that never erases a
//!   still-valid (possibly newer) cached credential.
//! - [`is_git_auth_failure`] classifies the (already-redacted) git/gh failure
//!   detail so only a real auth/OAuth-scope failure triggers that recovery.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};

/// `NANO_GH_TOKEN_TTL_MS` default: 5 minutes. A warm cache younger than this is
/// served without re-spawning `gh`.
const DEFAULT_TTL_MS: u64 = 5 * 60_000;

/// Monotonic clock in milliseconds, anchored to the UNIX epoch — the production
/// clock for the cache. Tests inject their own.
///
/// The clock MUST be monotonic: TTL expiry, the busy-defer bound, and the
/// credential age are all computed as `now.saturating_sub(earlier)`, so a clock
/// that can move backward would clamp those deltas to zero and indefinitely
/// stall a refresh (or freeze the reported age) for the whole duration of a
/// backward wall-clock adjustment. `SystemTime` is a wall clock and can jump
/// backward (NTP step, manual set, leap-second smear), so it must NOT drive
/// these deltas directly. Instead we anchor the UNIX wall-clock reading ONCE at
/// first use and advance it with a monotonic [`Instant`]: later wall-clock
/// changes can't rewind the cache's sense of elapsed time, while the values
/// stay in the existing "millis since the UNIX epoch" representation.
fn now_ms() -> u64 {
    static ANCHOR: OnceLock<(Instant, u64)> = OnceLock::new();
    let (mono0, unix0) = *ANCHOR.get_or_init(|| {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        (Instant::now(), unix)
    });
    unix0.saturating_add(mono0.elapsed().as_millis() as u64)
}

fn coerce_env_ms(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(v) => v
            .trim()
            .parse::<i64>()
            .ok()
            .map(|n| n.max(0) as u64)
            .unwrap_or(default),
        Err(_) => default,
    }
}

/// `NANO_GH_TOKEN_TTL_MS` (default 5m). `0` means "re-read on every lookup",
/// honouring the spawn cost.
pub fn ttl_ms() -> u64 {
    coerce_env_ms("NANO_GH_TOKEN_TTL_MS", DEFAULT_TTL_MS)
}

/// `NANO_GH_TOKEN_MAX_DEFER_MS` (default 4 intervals): the ceiling on how long
/// the maintenance tick may keep deferring a refresh while a job is active.
pub fn max_defer_ms() -> u64 {
    coerce_env_ms("NANO_GH_TOKEN_MAX_DEFER_MS", 4 * ttl_ms())
}

/// The outcome of one `gh auth token` read, distinguishing a definitive logout
/// from a transient failure (porting the plugin's `GH_AUTH_READ_FAILED`
/// sentinel). A transient failure must **preserve** the prior cached token
/// rather than drop the worker to anonymous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhAuthRead {
    /// A trimmed, non-empty token — the worker is logged in.
    Token(String),
    /// The read definitively established no login (a clean exit with empty
    /// output, or a nonzero exit whose stderr carries gh's logged-out message).
    LoggedOut,
    /// The read could not be completed (spawn error, timeout, or a nonzero exit
    /// with no logged-out signal). The caller must preserve any prior token.
    ReadFailed,
}

/// Map one completed (or failed) `gh auth token` invocation to a [`GhAuthRead`].
/// `status` is the process exit code (`None` = killed/no code). `output_failed`
/// marks an invocation whose captured output could NOT be fully collected (a
/// descendant held a pipe open past the drain bound): the output is then
/// incomplete, so an empty buffer must NOT be read as a definitive logout —
/// treat the read as a transient failure and preserve any cached credential.
pub fn classify_gh_auth_read(
    spawn_errored: bool,
    status: Option<i32>,
    stdout: &str,
    stderr: &str,
    output_failed: bool,
) -> GhAuthRead {
    if spawn_errored || output_failed {
        return GhAuthRead::ReadFailed;
    }
    if status == Some(0) {
        let tok = stdout.trim();
        if tok.is_empty() {
            return GhAuthRead::LoggedOut;
        }
        return GhAuthRead::Token(tok.to_string());
    }
    let lo = stderr.to_ascii_lowercase();
    if lo.contains("no oauth token")
        || lo.contains("no token found")
        || lo.contains("not logged in")
    {
        return GhAuthRead::LoggedOut;
    }
    GhAuthRead::ReadFailed
}

/// A short, non-reversible identity for a token so logs/status can show *when*
/// the credential changed (and that two workers hold the same one) without ever
/// printing a usable fragment of the secret. 12 hex chars of a cryptographic
/// digest. `None` for an empty/absent token.
///
/// The plugin uses sha256; the Rust worker already ships `sha1` (for the
/// control-socket path), and the fingerprint only needs to be short, stable and
/// non-reversible — never compared across the two implementations — so sha1 is
/// used here to avoid a new dependency. The externally observable contract
/// (12 lowercase hex chars, stable, distinct, never the value) is identical.
pub fn gh_token_fingerprint(token: &str) -> Option<String> {
    use std::fmt::Write as _;
    if token.is_empty() {
        return None;
    }
    let digest = Sha1::digest(token.as_bytes());
    let mut s = String::with_capacity(12);
    for b in digest.iter().take(6) {
        let _ = write!(s, "{b:02x}");
    }
    Some(s)
}

/// The cached credential record. `token == None` is a *populated* cache with no
/// login (distinct from a never-primed cache, which is [`GhTokenCache`] holding
/// `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    token: Option<String>,
    fingerprint: Option<String>,
    scopes: Option<String>,
    /// When THIS token value was first seen (the credential's age).
    since: u64,
    /// When `gh` was last consulted (TTL freshness).
    last_check: u64,
}

/// The result of folding a read into the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // `changed`/`superseded` are part of the port's public cache
                    // contract (and asserted by the unit tests); not every field
                    // is read by the lifetime-refresh wiring yet.
pub struct AdoptOutcome {
    pub token: Option<String>,
    /// The token VALUE differs from what the cache previously held (incl.
    /// `None -> token` and `token -> None`) — the credential actually rotated.
    pub changed: bool,
    /// The OBSERVABLE snapshot (fingerprint + scopes) moved: `changed` OR a
    /// same-token scopes self-repair. Log/republish paths gate on this.
    pub snapshot_changed: bool,
    /// A newer definitive write landed while this read was in flight, so it was
    /// not committed (the generation fence).
    pub superseded: bool,
}

/// A token-free snapshot of the cached credential's observable identity for logs
/// and the supervisor activity marker. Never carries the token value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // `since`/`last_check_ago_ms` ride the port's status snapshot;
                    // the current wiring logs via `describe_gh_auth_token`.
pub struct GhAuthTokenInfo {
    pub present: bool,
    pub fingerprint: Option<String>,
    pub scopes: Option<String>,
    pub since: u64,
    /// The token's age (since this value was first seen).
    pub age_ms: u64,
    /// How long ago `gh` was last consulted (TTL freshness).
    pub last_check_ago_ms: u64,
}

struct Inner {
    /// `None` = never primed (the plugin's `GH_AUTH_TOKEN_UNSET`).
    cache: Option<Record>,
    /// Bumped on EVERY write so an in-flight read can detect (and refuse to
    /// clobber) a newer definitive write that landed while it was reading.
    generation: u64,
}

type Reader = Box<dyn Fn() -> GhAuthRead + Send + Sync>;
type ScopesProbe = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;
type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

/// The worker's lifetime gh-auth-token cache. Thread-safe: the per-job hot path
/// ([`token_for_cli`](Self::token_for_cli)) and the background maintenance refresh
/// ([`maintenance_tick`](Self::maintenance_tick)) share one instance. The
/// potentially slow `gh` subprocesses (the token read and the scopes probe) run
/// **outside** the lock, so a refresh never blocks a concurrent hot-path lookup;
/// a generation fence (snapshotted before the read, re-checked at commit) keeps
/// a slow read from resurrecting a credential a newer write already superseded.
pub struct GhTokenCache {
    inner: Mutex<Inner>,
    ttl_ms: u64,
    max_defer_ms: u64,
    reader: Reader,
    scopes: ScopesProbe,
    clock: Clock,
}

impl GhTokenCache {
    /// Build a cache with the production `gh auth token` reader and `gh api`
    /// scopes probe, and the env-configured TTL / defer bound.
    pub fn production() -> Self {
        Self {
            inner: Mutex::new(Inner {
                cache: None,
                generation: 0,
            }),
            ttl_ms: ttl_ms(),
            max_defer_ms: max_defer_ms(),
            reader: Box::new(read_gh_auth_token_default),
            scopes: Box::new(|t| gh_token_scopes(t, Duration::from_secs(5))),
            clock: Box::new(now_ms),
        }
    }

    /// Build a cache with injected seams for hermetic tests.
    #[cfg(test)]
    fn with_seams(
        ttl_ms: u64,
        max_defer_ms: u64,
        reader: Reader,
        scopes: ScopesProbe,
        clock: Clock,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                cache: None,
                generation: 0,
            }),
            ttl_ms,
            max_defer_ms,
            reader,
            scopes,
            clock,
        }
    }

    /// Fold a read result into the cache. The read has already happened (outside
    /// the lock); `scopes` probes are run here only when needed, also outside the
    /// lock, then the record is committed under a generation fence. `prev` and
    /// `start_gen` are the record and generation the CALLER snapshotted **before
    /// invoking the reader** — the fence must bracket the token read, so the
    /// generation cannot be captured here (after the read) without reopening the
    /// overlapping-read race this guards against.
    fn adopt(&self, read: GhAuthRead, prev: Option<Record>, start_gen: u64) -> AdoptOutcome {
        let now = (self.clock)();

        // Transient read failure: never discard a usable cached credential.
        if read == GhAuthRead::ReadFailed {
            if let Some(p) = prev.as_ref() {
                if p.token.is_some() {
                    let mut g = self.inner.lock().unwrap();
                    if g.generation != start_gen {
                        return self.superseded(&g);
                    }
                    let mut updated = p.clone();
                    updated.last_check = now;
                    g.cache = Some(updated);
                    g.generation += 1;
                    return AdoptOutcome {
                        token: p.token.clone(),
                        changed: false,
                        snapshot_changed: false,
                        superseded: false,
                    };
                }
            }
            // No usable prior token: fall through as a definitive logout.
            return self.commit(None, &prev, start_gen, now);
        }

        let token = match read {
            GhAuthRead::Token(t) => Some(t),
            GhAuthRead::LoggedOut => None,
            GhAuthRead::ReadFailed => unreachable!(),
        };
        self.commit(token, &prev, start_gen, now)
    }

    /// Compute scopes (probing outside the lock when needed) and commit the new
    /// record under the generation fence.
    fn commit(
        &self,
        token: Option<String>,
        prev: &Option<Record>,
        start_gen: u64,
        now: u64,
    ) -> AdoptOutcome {
        let changed = match prev {
            None => true,
            Some(p) => p.token != token,
        };
        // Re-probe scopes on a change, on first populate, or when the cached
        // reading was MISSING (a prior transient probe failure self-repairs);
        // otherwise carry a successful prior reading forward (no extra ping).
        let scopes: Option<String> = match &token {
            None => None,
            Some(t) => {
                let reuse = !changed && prev.as_ref().map(|p| p.scopes.is_some()).unwrap_or(false);
                if reuse {
                    prev.as_ref().and_then(|p| p.scopes.clone())
                } else {
                    (self.scopes)(t)
                }
            }
        };

        let snapshot_changed =
            changed || prev.as_ref().map(|p| p.scopes != scopes).unwrap_or(false);

        let since = match prev {
            Some(p) if p.token == token && token.is_some() => p.since,
            _ => now,
        };
        let fingerprint = token.as_deref().and_then(gh_token_fingerprint);

        let mut g = self.inner.lock().unwrap();
        if g.generation != start_gen {
            return self.superseded(&g);
        }
        g.cache = Some(Record {
            token: token.clone(),
            fingerprint,
            scopes,
            since,
            last_check: now,
        });
        g.generation += 1;
        AdoptOutcome {
            token,
            changed,
            snapshot_changed,
            superseded: false,
        }
    }

    fn superseded(&self, g: &std::sync::MutexGuard<'_, Inner>) -> AdoptOutcome {
        AdoptOutcome {
            token: g.cache.as_ref().and_then(|c| c.token.clone()),
            changed: false,
            snapshot_changed: false,
            superseded: true,
        }
    }

    /// One (re)read of `gh auth token`, folding the result into the cache. Honours
    /// the TTL unless `force`. SYNCHRONOUS (the reader spawns `gh`) — safe OFF the
    /// job path (the startup prime, the auth-failure recovery where the caller is
    /// already blocked on git, and the background maintenance tick).
    pub fn refresh(&self, force: bool) -> AdoptOutcome {
        // Snapshot the previous record AND the generation BEFORE spawning the
        // (slow) reader, so the generation fence brackets the token READ, not
        // only the later scopes probe. Capturing the generation after the read
        // (as `adopt` used to) let a stale read that STARTED before a newer
        // committed write still snapshot the post-write generation, pass the
        // fence, and silently overwrite the newer token without reporting
        // `superseded`. Snapshotting here makes that stale read observe the
        // bumped generation at commit and report `superseded` instead.
        let (prev, start_gen) = {
            let g = self.inner.lock().unwrap();
            if !force {
                if let Some(p) = g.cache.as_ref() {
                    let now = (self.clock)();
                    if now.saturating_sub(p.last_check) < self.ttl_ms {
                        return AdoptOutcome {
                            token: p.token.clone(),
                            changed: false,
                            snapshot_changed: false,
                            superseded: false,
                        };
                    }
                }
            }
            (g.cache.clone(), g.generation)
        };
        let read = (self.reader)();
        self.adopt(read, prev, start_gen)
    }

    /// The per-job hot path. Serve the PRIMED cache verbatim — NEVER a blocking
    /// TTL-triggered re-read here (that is the event-loop/lease stall the off-path
    /// refresh exists to avoid). A not-yet-primed cache force-reads once (the same
    /// unavoidable first read the plugin pays), then is served from cache.
    ///
    /// This is the credential-*consumption* seam a gh-token-sourced clone/push
    /// uses; the current Rust worker sources the job token from the envelope, so
    /// this is exercised by the unit tests and wired by the broader fallback port.
    #[allow(dead_code)]
    pub fn token_for_cli(&self) -> Option<String> {
        {
            let g = self.inner.lock().unwrap();
            if let Some(c) = g.cache.as_ref() {
                return c.token.clone();
            }
        }
        self.refresh(true).token
    }

    /// Warm the cache at worker startup, off the job path. Logs the token's
    /// fingerprint + scopes on the first populate and whenever the observable
    /// snapshot moves (a rotation OR a scopes self-repair). Returns `true` once
    /// the cache is populated.
    pub fn prime(&self, log: impl Fn(&str)) -> bool {
        let out = self.refresh(false);
        if out.snapshot_changed {
            log(&describe_gh_auth_token(self.info().as_ref()));
        }
        self.inner.lock().unwrap().cache.is_some()
    }

    /// One maintenance tick of the worker-lifetime refresh. `is_idle` is whether
    /// the worker currently has no job in flight. Returns `Some(snapshot_changed)`
    /// when a refresh ran, or `None` when the tick deferred (a job is active and
    /// the primed cache is not yet stale beyond the bound).
    ///
    /// The defer-while-busy rule keeps a `gh` read off the job path; the bound
    /// (`max_defer_ms`) stops a perpetually-busy worker from serving an expired
    /// non-null cache to every job for its whole busy lifetime. An UNSET cache is
    /// never primed mid-job (a logged-out worker stays anonymous until idle).
    pub fn maintenance_tick(&self, is_idle: bool) -> Option<bool> {
        if !is_idle {
            let now = (self.clock)();
            let stale_beyond_bound = {
                let g = self.inner.lock().unwrap();
                match g.cache.as_ref() {
                    // UNSET cache: never primed mid-job.
                    None => false,
                    Some(c) => now.saturating_sub(c.last_check) >= self.max_defer_ms,
                }
            };
            if !stale_beyond_bound {
                return None; // defer to the next idle tick
            }
        }
        Some(self.refresh(false).snapshot_changed)
    }

    /// Recover from a git/gh auth failure on a cache-derived credential: force a
    /// fresh read and return it **iff** it differs from the credential that just
    /// failed. Deliberately non-destructive — it never drops the cache first, so a
    /// transiently-failing re-read can't erase a still-valid (possibly newer,
    /// from a reload) cached credential.
    ///
    /// Wired by the broader clone/push credential-recovery port; exercised here
    /// by the unit tests.
    #[allow(dead_code)]
    pub fn recover_after_auth_failure(&self, failing_token: &str) -> Option<String> {
        let fresh = self.refresh(true).token?;
        if fresh != failing_token {
            Some(fresh)
        } else {
            None
        }
    }

    /// Drop the cached token so the next lookup re-reads `gh`. A reset primitive;
    /// the production recovery paths are deliberately non-destructive and never
    /// call this.
    #[allow(dead_code)]
    pub fn invalidate(&self) {
        let mut g = self.inner.lock().unwrap();
        g.cache = None;
        g.generation += 1;
    }

    /// A token-free snapshot of the cached credential for logs / the activity
    /// marker. `None` when the cache has never been primed.
    pub fn info(&self) -> Option<GhAuthTokenInfo> {
        let g = self.inner.lock().unwrap();
        let c = g.cache.as_ref()?;
        let now = (self.clock)();
        Some(GhAuthTokenInfo {
            present: c.token.is_some(),
            fingerprint: c.fingerprint.clone(),
            scopes: c.scopes.clone(),
            since: c.since,
            age_ms: now.saturating_sub(c.since),
            last_check_ago_ms: now.saturating_sub(c.last_check),
        })
    }
}

/// One-line, token-free description for logs, e.g.
/// `gh auth token: fingerprint ab12cd34ef56 (scopes: repo, workflow; age 2m)`.
pub fn describe_gh_auth_token(info: Option<&GhAuthTokenInfo>) -> String {
    let info = match info {
        None => return "gh auth token: (not yet read)".to_string(),
        Some(i) => i,
    };
    if !info.present {
        return "gh auth token: none (gh missing or not logged in)".to_string();
    }
    let mut bits = Vec::new();
    bits.push(format!(
        "fingerprint {}",
        info.fingerprint.as_deref().unwrap_or("unknown")
    ));
    match info.scopes.as_deref() {
        Some(s) => bits.push(format!("scopes: {s}")),
        None => bits.push("scopes: unknown".to_string()),
    }
    bits.push(format!("age {}", format_duration(info.age_ms)));
    format!("gh auth token: {}", bits.join("; "))
}

fn format_duration(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h");
    }
    format!("{}d", hours / 24)
}

/// Classify a git/gh failure as an AUTH (or auth-scope) failure — the cases where
/// the cached credential, not the request, is the problem: a 401/403, git's
/// credential prompts on an anonymous/rejected clone, or GitHub's OAuth-scope
/// refusal. Matched on the ALREADY-REDACTED detail string, so the token value is
/// never inspected. Deliberately conservative: a non-fast-forward reject, a 404,
/// or a network timeout are NOT auth failures.
#[allow(dead_code)]
pub fn is_git_auth_failure(detail: &str) -> bool {
    if detail.is_empty() {
        return false;
    }
    let s = detail.to_ascii_lowercase();
    s.contains("http 401")
        || s.contains("http 403")
        || s.contains("401 (unauthorized)")
        || s.contains("403 (forbidden)")
        || s.contains("returned error: 401")
        || s.contains("returned error: 403")
        || s.contains("could not read username")
        || s.contains("could not read password")
        || s.contains("authentication failed")
        || s.contains("authentication required")
        || (s.contains("permission to ") && s.contains(" denied"))
        || s.contains("refusing to allow an oauth app")
        || s.contains("without `workflow` scope")
        || s.contains("without 'workflow' scope")
        || s.contains("without workflow scope")
        || s.contains("bad credentials")
        || s.contains("resource not accessible by integration")
        || s.contains("resource not accessible by personal access token")
}

/// Non-interactive environment for every `gh` child: no prompts, no pager.
fn gh_noninteractive_env() -> Vec<(&'static str, String)> {
    vec![
        ("GH_PROMPT_DISABLED", "1".to_string()),
        ("GH_NO_UPDATE_NOTIFIER", "1".to_string()),
        ("GH_PAGER", String::new()),
        ("CLICOLOR", "0".to_string()),
        ("NO_COLOR", "1".to_string()),
    ]
}

/// Scrub the daemon's engine-connection secrets from a `gh` child before it is
/// spawned — the same strip every other `gh` launch applies
/// (`src/provision.rs`). This worker's own environment carries
/// `CAMUNDA_CLIENT_SECRET` / `NANO_AGENTIC_TOKEN` / the ZEEBE client secrets,
/// and a spawned `gh` inherits them; on Linux a same-UID agent on the host can
/// then read them out of the child's `/proc/<pid>/environ`. `gh` needs none of
/// them to read a token or probe scopes, so remove the whole
/// [`crate::slot::SENSITIVE_DAEMON_ENV`] set while retaining the GitHub auth
/// variables (`GH_TOKEN` and friends) the reader relies on.
fn scrub_sensitive_env(cmd: &mut std::process::Command) {
    for k in crate::slot::SENSITIVE_DAEMON_ENV {
        cmd.env_remove(k);
    }
}

/// Spawn `cmd`, capture its stdout/stderr, and enforce `timeout`. Returns
/// `Some((exit_code, stdout, stderr, output_failed))` when the child exits
/// within the deadline, or `None` when it could not be spawned OR exceeded the
/// deadline. On expiry the child is killed and reaped — on unix the WHOLE
/// process group is signalled
/// (the child is spawned as its own group leader, so a `gh` wrapper or helper
/// that backgrounded a descendant holding our pipes cannot keep those pipes
/// open past the deadline), and the drain-thread joins are themselves bounded
/// ([`bounded_join`]) so even a surviving descendant (e.g. one that escaped the
/// group on a platform without group signalling) can never hang `prime()` or a
/// maintenance refresh: the join gives up, the stuck reader thread is left to
/// finish (or leak) on its own, and its buffer is reaped by a detached thread.
/// Both pipes are drained on their own threads so a child that fills a pipe
/// buffer can never wedge the wait, and so whatever it wrote before a kill is
/// still collected. `output_failed` is `true` when a drain could not be
/// collected within its bound (a descendant held the pipe open) — the captured
/// output is then INCOMPLETE, so a caller must treat the read as failed rather
/// than trust an empty/partial buffer. This is the shared, bounded spawn for
/// every `gh` child here — neither the token read nor the scopes probe may
/// block `prime()` / the maintenance refresh indefinitely.
fn run_capped(
    mut cmd: std::process::Command,
    timeout: Duration,
) -> Option<(Option<i32>, String, String, bool)> {
    use std::io::Read;
    use std::process::Stdio;
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Own process group (unix) so a timed-out child cannot leave a descendant
    // holding stdout/stderr open: killing only the direct child would not close
    // those pipes, and the drain threads below would block past the deadline.
    // `arm` (Linux) + `watch` (macOS/Linux) are the same parent-death backstops
    // the other spawn sites use, so a daemon death cannot orphan the child.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
        crate::pdeath::arm_std(&mut cmd);
    }
    let mut child = cmd.spawn().ok()?;
    // Install the child's cleanup guard BEFORE `watch()`: the watchdog spawn is
    // best-effort and its reaper thread is created fallibly, but if that
    // fallible path (or any later one) ever unwinds, the guard must already be
    // armed so the child group is torn down rather than orphaned.
    #[cfg(unix)]
    let mut group_guard = {
        let pid = child.id();
        let guard = crate::pdeath::GroupGuard::new(Some(pid));
        crate::pdeath::watch(pid);
        guard
    };
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    // Spawn the two drain threads FALLIBLY (`Builder::spawn`, not the panicking
    // `thread::spawn`): under a process/thread limit the OS can refuse to create
    // a thread, and a panic here would abort `prime()` / the refresh loop instead
    // of reporting a best-effort read failure. On a spawn failure, kill + reap
    // the child (and its group) and join any drain already started so nothing
    // leaks, then return `None` so the read is reported as failed.
    let out_t = match std::thread::Builder::new().spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = out.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    }) {
        Ok(t) => t,
        Err(_) => {
            #[cfg(unix)]
            group_guard.kill_group_if_ours();
            let _ = child.kill();
            let _ = child.wait();
            #[cfg(unix)]
            group_guard.disarm();
            return None;
        }
    };
    let err_t = match std::thread::Builder::new().spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = err.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    }) {
        Ok(t) => t,
        Err(_) => {
            // The stdout drain already started: kill + reap the child (closing
            // its pipes so that drain sees EOF), join the started drain so its
            // thread does not leak, then report the read as failed. The join is
            // BOUNDED (`bounded_join`, not a bare `join`): a descendant that
            // escaped the killed group and still holds stdout would otherwise
            // keep the drain blocked indefinitely, hanging `prime()` / the
            // refresh loop — thread-creation failure must not bypass bounded
            // output collection. A give-up detaches the stuck drain to finish
            // (or leak) on its own, exactly like the normal path below.
            #[cfg(unix)]
            group_guard.kill_group_if_ours();
            let _ = child.kill();
            let _ = child.wait();
            let _ = bounded_join(out_t, Instant::now() + Duration::from_secs(2));
            #[cfg(unix)]
            group_guard.disarm();
            return None;
        }
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Kill the WHOLE group first (identity-gated, so a recycled
                    // pgid is never signalled): a descendant still holding our
                    // pipes dies too, which is what lets the drain threads see
                    // EOF. Then kill + reap the direct child (a no-op if the
                    // group kill already got it) so it can't become a zombie.
                    #[cfg(unix)]
                    group_guard.kill_group_if_ours();
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                #[cfg(unix)]
                group_guard.kill_group_if_ours();
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    // The direct child is reaped by here on every path, but do NOT disarm yet.
    // On the normal-exit path (the child exited 0, so the timeout branch above
    // never fired and nothing tore the group down) a descendant can have
    // inherited our pipes and outlived the wrapper — the `printf gho_x; sleep
    // 30 & exit 0` case. Keep the spawn-time guard armed THROUGH output
    // collection so that, if a drain cannot complete, we can still tear that
    // descendant down below instead of leaking it (and its blocked
    // reader/joiner threads) across every refresh tick.
    //
    // Join the drain threads, but BOUNDED: once the child (and, on unix, its
    // whole group) is gone the pipes close and these return promptly — yet a
    // descendant that survived (non-unix, or a re-parented escapee) would keep
    // a pipe open forever, so never let that hang the caller. On a stuck drain
    // the buffer is dropped for THIS result and reaped by a detached thread,
    // and `output_failed` is set so the caller treats the read as failed
    // (incomplete output) rather than trusting an empty/partial buffer.
    let join_deadline = deadline + Duration::from_secs(2);
    let out_r = bounded_join(out_t, join_deadline);
    let err_r = bounded_join(err_t, join_deadline);
    let output_failed = out_r.is_none() || err_r.is_none();
    // Tear the whole group down now, UNCONDITIONALLY — on BOTH the failed-drain
    // and the successful-collection path. Successful output collection does NOT
    // mean the group has exited: a wrapper such as `printf gho_x; sleep 30
    // >/dev/null 2>&1 & exit 0` finishes both drains (the descendant's
    // redirected output does not hold our pipes), so `output_failed` is false —
    // yet the descendant is still alive and would otherwise survive,
    // accumulating one process (plus its watchdog/reaper resources) per refresh
    // tick. `kill_group_if_ours()` is itself a no-op when the group holds
    // nothing live, so calling it on the success path costs only a gated,
    // harmless SIGKILL to the pgid.
    //
    // Do NOT gate this kill on a `group_has_live_member()` scan: that scan is
    // best-effort and explicitly fails open (a descendant that forks mid-scan
    // can be missed — see `pdeath::group_has_live_member`'s contract). A false
    // negative would skip the kill AND the unconditional `disarm()` below would
    // then disable the guard's Drop fallback, leaking exactly the descendant the
    // scan missed. Signalling first and disarming second keeps the kill
    // unconditional while retaining the identity check (`still_ours()`), so a
    // recycled pgid is never signalled, yet nothing survives a false-negative
    // scan.
    #[cfg(unix)]
    group_guard.kill_group_if_ours();
    // The child is reaped and any surviving descendant has now been signalled;
    // disarm so the guard's Drop never signals a recycled pgid.
    #[cfg(unix)]
    group_guard.disarm();
    let stdout = String::from_utf8_lossy(&out_r.unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_r.unwrap_or_default()).into_owned();
    status.map(|st| (st.code(), stdout, stderr, output_failed))
}

/// Join a drain thread, bounded by `deadline`. A finished thread is joined and
/// its buffer returned as `Some`. A thread still blocked at the deadline (its
/// pipe is held open by a surviving descendant) is NOT awaited: it is handed to
/// a detached reaper that joins it whenever it eventually finishes, so no
/// thread or buffer leaks — and `None` is returned now so the caller knows the
/// output was NOT collected (rather than mistaking an empty buffer for a
/// completed, empty read). This is what keeps a descendant-held pipe from
/// hanging the caller past the deadline while still surfacing the failure.
fn bounded_join(t: std::thread::JoinHandle<Vec<u8>>, deadline: Instant) -> Option<Vec<u8>> {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    // Spawn the joiner FALLIBLY: under a process/thread limit the OS can refuse
    // to create it, and a panicking `thread::spawn` would abort the caller
    // instead of reporting the output as not collected. On failure, return
    // `None` (output collection incomplete) — the drain thread `t` is dropped
    // here, detaching it to finish (or leak) on its own exactly like the
    // stuck-drain give-up path below.
    if std::thread::Builder::new()
        .spawn(move || {
            let out = t.join();
            // If the caller already timed out and walked away, `send` fails — the
            // buffer is then dropped here, which is the intended give-up path.
            let _ = tx.send(out);
        })
        .is_err()
    {
        return None;
    }
    // Poll rather than `recv_deadline` (which is still unstable): a finished
    // drain is observed within one poll tick, and a stuck one gives up at the
    // deadline instead of blocking the caller.
    loop {
        match rx.try_recv() {
            Ok(Ok(v)) => return Some(v),
            // The drain thread panicked: there is no output for this result.
            Ok(Err(_)) => return None,
            Err(mpsc::TryRecvError::Empty) => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(mpsc::TryRecvError::Disconnected) => return None,
        }
    }
}

/// Production `gh auth token` reader (synchronous spawn), bounded by a 10s wait.
/// A timeout (or any spawn failure) is a transient [`GhAuthRead::ReadFailed`] so
/// the caller PRESERVES any prior cached credential rather than dropping to
/// anonymous on a stalled keychain/token read.
fn read_gh_auth_token_default() -> GhAuthRead {
    read_gh_auth_token(Duration::from_secs(10))
}

fn read_gh_auth_token(timeout: Duration) -> GhAuthRead {
    use std::process::Command;
    let mut cmd = Command::new("gh");
    cmd.args(["auth", "token"]);
    for (k, v) in gh_noninteractive_env() {
        cmd.env(k, v);
    }
    scrub_sensitive_env(&mut cmd);
    match run_capped(cmd, timeout) {
        Some((code, stdout, stderr, output_failed)) => {
            classify_gh_auth_read(false, code, &stdout, &stderr, output_failed)
        }
        None => GhAuthRead::ReadFailed,
    }
}

/// Deliver `token` to a spawned `gh` child so the API validates EXACTLY the
/// token we just read — never gh's stored credentials for some other login.
/// `gh` honours `GH_TOKEN` on github.com but IGNORES it on a self-hosted
/// GitHub Enterprise host, where it reads `GH_ENTERPRISE_TOKEN` (or falls back
/// to stored credentials) instead — see `src/provision.rs`, which selects the
/// variable by host. We do not resolve the active host here, so set BOTH to the
/// same value: whichever variable the configured host honours, it is OUR token,
/// so the probe can never pair this token's fingerprint with a DIFFERENT (e.g.
/// a stored-login rotation's) token's scopes. The unused variable is harmless —
/// gh ignores `GH_ENTERPRISE_TOKEN` on github.com and `GH_TOKEN` on Enterprise.
/// The token rides the child env, NEVER argv, so it can't leak via `ps` — the
/// same no-env-leak-to-argv guarantee as [`crate::provision`].
fn apply_probe_token(cmd: &mut std::process::Command, token: &str) {
    cmd.env("GH_TOKEN", token);
    cmd.env("GH_ENTERPRISE_TOKEN", token);
}

/// Read the token's OAuth scopes from the live `X-OAuth-Scopes` response header.
/// Best-effort and BOUNDED by `timeout`: a spawn failure, a timeout, or a missing
/// header all yield `None` (scopes simply go unreported) so a stalled or slow API
/// probe never blocks adoption of a rotated token. The token rides the child env
/// (`GH_TOKEN` / `GH_ENTERPRISE_TOKEN`, see [`apply_probe_token`]), NEVER argv,
/// so it can't leak via `ps` — the same no-env-leak-to-argv guarantee as the
/// credential delivery in [`crate::provision`].
fn gh_token_scopes(token: &str, timeout: Duration) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    use std::process::Command;
    let mut cmd = Command::new("gh");
    cmd.args(["api", "-i", "--include", "user"]);
    for (k, v) in gh_noninteractive_env() {
        cmd.env(k, v);
    }
    // Scrub BEFORE delivering the token: the strip removes the daemon's
    // engine secrets but must not clear the `GH_*` token vars we set next.
    scrub_sensitive_env(&mut cmd);
    apply_probe_token(&mut cmd, token);
    let (_code, stdout, stderr, _output_failed) = run_capped(cmd, timeout)?;
    let mut combined = stdout;
    combined.push('\n');
    combined.push_str(&stderr);
    for line in combined.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("x-oauth-scopes:") {
            let _ = rest;
            // Re-slice the ORIGINAL line to preserve case of the scopes value.
            if let Some(idx) = line.find(':') {
                let val = line[idx + 1..].trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// A controllable clock for deterministic TTL / age tests.
    #[derive(Clone)]
    struct FakeClock(Arc<AtomicU64>);
    impl FakeClock {
        fn new() -> Self {
            FakeClock(Arc::new(AtomicU64::new(1_000_000)))
        }
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
        fn clock(&self) -> Clock {
            let a = self.0.clone();
            Box::new(move || a.load(Ordering::SeqCst))
        }
    }

    fn reader_from(slot: Arc<Mutex<GhAuthRead>>) -> Reader {
        Box::new(move || slot.lock().unwrap().clone())
    }

    #[test]
    fn fingerprint_is_short_non_reversible_and_stable() {
        let fp = gh_token_fingerprint("gho_secret_value_123").unwrap();
        assert_eq!(fp.len(), 12);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(fp, "gho_secret_value_123");
        assert_eq!(gh_token_fingerprint(""), None);
        // Stable + distinct.
        assert_eq!(gh_token_fingerprint("gho_secret_value_123").unwrap(), fp);
        assert_ne!(gh_token_fingerprint("gho_other").unwrap(), fp);
    }

    #[test]
    fn refresh_honours_the_ttl() {
        let clock = FakeClock::new();
        let reads = Arc::new(AtomicU64::new(0));
        let r2 = reads.clone();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            Box::new(move || {
                r2.fetch_add(1, Ordering::SeqCst);
                GhAuthRead::Token("gho_one".into())
            }),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        let first = cache.refresh(true);
        assert_eq!(first.token.as_deref(), Some("gho_one"));
        assert!(first.changed);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        // Within the TTL: a non-forced refresh is a cache hit, no new read.
        clock.advance(10_000);
        let second = cache.refresh(false);
        assert_eq!(second.token.as_deref(), Some("gho_one"));
        assert!(!second.changed);
        assert_eq!(reads.load(Ordering::SeqCst), 1, "no re-read inside the TTL");
        // Past the TTL: a non-forced refresh re-reads.
        clock.advance(60_000);
        cache.refresh(false);
        assert_eq!(reads.load(Ordering::SeqCst), 2, "re-read past the TTL");
    }

    #[test]
    fn refresh_reports_change_and_reprobes_scopes_only_on_change() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_old".into())));
        let scope_reads = Arc::new(AtomicU64::new(0));
        let sr = scope_reads.clone();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            reader_from(served.clone()),
            Box::new(move |_| {
                sr.fetch_add(1, Ordering::SeqCst);
                Some("repo".into())
            }),
            clock.clock(),
        );
        cache.refresh(true);
        assert_eq!(
            scope_reads.load(Ordering::SeqCst),
            1,
            "scopes read on first populate"
        );
        *served.lock().unwrap() = GhAuthRead::Token("gho_new".into());
        let r = cache.refresh(true);
        assert_eq!(r.token.as_deref(), Some("gho_new"));
        assert!(r.changed);
        assert_eq!(
            scope_reads.load(Ordering::SeqCst),
            2,
            "scopes re-read when token rotates"
        );
        // A forced re-read of the SAME token is not a change and keeps scopes.
        let r2 = cache.refresh(true);
        assert!(!r2.changed);
        assert_eq!(
            scope_reads.load(Ordering::SeqCst),
            2,
            "same token does not re-ping scopes"
        );
        assert_eq!(cache.info().unwrap().scopes.as_deref(), Some("repo"));
    }

    #[test]
    fn reprobes_scopes_when_cached_reading_is_missing() {
        let clock = FakeClock::new();
        let scope_val = Arc::new(Mutex::new(None::<String>));
        let sv = scope_val.clone();
        let scope_reads = Arc::new(AtomicU64::new(0));
        let sr = scope_reads.clone();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            Box::new(|| GhAuthRead::Token("gho_scope".into())),
            Box::new(move |_| {
                sr.fetch_add(1, Ordering::SeqCst);
                sv.lock().unwrap().clone()
            }),
            clock.clock(),
        );
        cache.refresh(true);
        assert_eq!(scope_reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            cache.info().unwrap().scopes,
            None,
            "transient probe failure caches scopes:null"
        );
        // Same token, probe now heals → must re-probe.
        *scope_val.lock().unwrap() = Some("repo, workflow".into());
        let r = cache.refresh(true);
        assert!(!r.changed);
        assert!(
            r.snapshot_changed,
            "a scopes self-repair reports snapshot_changed"
        );
        assert_eq!(
            scope_reads.load(Ordering::SeqCst),
            2,
            "re-probed because cached scope was missing"
        );
        assert_eq!(
            cache.info().unwrap().scopes.as_deref(),
            Some("repo, workflow")
        );
        // Now a successful reading is cached: a same-token refresh reuses it.
        let r2 = cache.refresh(true);
        assert!(!r2.changed);
        assert_eq!(
            scope_reads.load(Ordering::SeqCst),
            2,
            "successful cached reading reused"
        );
    }

    #[test]
    fn transient_read_failure_preserves_the_cached_token() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_live".into())));
        let cache = GhTokenCache::with_seams(
            0, // TTL 0 → every non-forced lookup re-reads
            240_000,
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.refresh(true);
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_live"));
        // gh momentarily unavailable: the cached token must survive.
        *served.lock().unwrap() = GhAuthRead::ReadFailed;
        let out = cache.refresh(true);
        assert_eq!(
            out.token.as_deref(),
            Some("gho_live"),
            "transient failure preserves the token"
        );
        assert!(!out.changed);
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_live"));
    }

    #[test]
    fn transient_failure_with_no_prior_token_is_anonymous() {
        let clock = FakeClock::new();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            Box::new(|| GhAuthRead::ReadFailed),
            Box::new(|_| None),
            clock.clock(),
        );
        let out = cache.refresh(true);
        assert_eq!(out.token, None);
        assert!(
            cache.info().is_some(),
            "the cache is populated (logged out)"
        );
        assert!(!cache.info().unwrap().present);
    }

    #[test]
    fn classify_distinguishes_token_logout_and_transient() {
        assert_eq!(
            classify_gh_auth_read(false, Some(0), "gho_abc\n", "", false),
            GhAuthRead::Token("gho_abc".into())
        );
        assert_eq!(
            classify_gh_auth_read(false, Some(0), "   \n", "", false),
            GhAuthRead::LoggedOut
        );
        assert_eq!(
            classify_gh_auth_read(
                false,
                Some(1),
                "",
                "no oauth token found for github.com",
                false
            ),
            GhAuthRead::LoggedOut
        );
        assert_eq!(
            classify_gh_auth_read(false, Some(1), "", "keychain error", false),
            GhAuthRead::ReadFailed
        );
        assert_eq!(
            classify_gh_auth_read(true, None, "", "", false),
            GhAuthRead::ReadFailed
        );
    }

    /// Round-4 regression: a clean exit-0 whose captured output could NOT be
    /// fully collected (a descendant held the pipe open past the drain bound)
    /// is a transient failure, NOT a definitive logout — an incomplete/empty
    /// buffer must never clear a valid cached credential.
    #[test]
    fn classify_treads_uncollected_output_as_transient_not_logout() {
        // exit 0 + empty stdout would normally read as LoggedOut …
        assert_eq!(
            classify_gh_auth_read(false, Some(0), "", "", false),
            GhAuthRead::LoggedOut
        );
        // … but with output_failed set it is a transient ReadFailed.
        assert_eq!(
            classify_gh_auth_read(false, Some(0), "", "", true),
            GhAuthRead::ReadFailed
        );
        // output_failed dominates even a would-be token and a logged-out stderr.
        assert_eq!(
            classify_gh_auth_read(false, Some(0), "gho_abc\n", "", true),
            GhAuthRead::ReadFailed
        );
        assert_eq!(
            classify_gh_auth_read(false, Some(1), "", "no oauth token", true),
            GhAuthRead::ReadFailed
        );
    }

    #[test]
    fn from_cli_serves_primed_cache_without_reread_even_past_ttl() {
        let clock = FakeClock::new();
        let reads = Arc::new(AtomicU64::new(0));
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_primed".into())));
        let s2 = served.clone();
        let r2 = reads.clone();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            Box::new(move || {
                r2.fetch_add(1, Ordering::SeqCst);
                s2.lock().unwrap().clone()
            }),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.refresh(true); // prime
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        // Even well past the TTL, the hot path serves the cache without re-reading.
        clock.advance(10 * 60_000);
        *served.lock().unwrap() = GhAuthRead::Token("gho_rotated".into());
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_primed"));
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "the hot path never blocks on a re-read"
        );
    }

    #[test]
    fn recover_returns_rotated_token_and_declines_a_genuine_denial() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_stale".into())));
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.refresh(true);
        // A re-read yields a DIFFERENT token → recovery returns it for the retry.
        *served.lock().unwrap() = GhAuthRead::Token("gho_fresh".into());
        assert_eq!(
            cache.recover_after_auth_failure("gho_stale").as_deref(),
            Some("gho_fresh")
        );
        // A genuine denial: the re-read returns the SAME failing token → no retry.
        *served.lock().unwrap() = GhAuthRead::Token("gho_fresh".into());
        assert_eq!(cache.recover_after_auth_failure("gho_fresh"), None);
    }

    #[test]
    fn recover_preserves_a_newer_cached_token_when_the_reread_fails_transiently() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_new".into())));
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.refresh(true); // cache holds the NEWER token (e.g. a reload swap)
                             // The clone failed on the OLD token; the re-read fails transiently, so the
                             // cache preserves the newer token and recovery retries with it.
        *served.lock().unwrap() = GhAuthRead::ReadFailed;
        assert_eq!(
            cache.recover_after_auth_failure("gho_old").as_deref(),
            Some("gho_new")
        );
    }

    #[test]
    fn recover_heals_a_logged_out_cache() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::LoggedOut));
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.refresh(true); // logged out (token None)
        *served.lock().unwrap() = GhAuthRead::Token("gho_after_login".into());
        assert_eq!(
            cache.recover_after_auth_failure("").as_deref(),
            Some("gho_after_login")
        );
    }

    #[test]
    fn maintenance_tick_defers_while_busy_and_refreshes_when_idle() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_one".into())));
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        // Cache starts UNSET: a busy tick must NOT populate it.
        *served.lock().unwrap() = GhAuthRead::Token("gho_two".into());
        assert_eq!(cache.maintenance_tick(false), None, "deferred while busy");
        assert!(cache.info().is_none(), "no refresh while a job is active");
        // Idle: the tick adopts the token.
        let changed = cache.maintenance_tick(true);
        assert_eq!(changed, Some(true));
        assert_eq!(
            cache.info().unwrap().fingerprint,
            gh_token_fingerprint("gho_two")
        );
    }

    #[test]
    fn maintenance_tick_bounds_the_busy_defer() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_one".into())));
        let cache = GhTokenCache::with_seams(
            1_000,  // tiny TTL so the non-forced re-read isn't short-circuited
            10_000, // max defer
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.refresh(true); // prime with gho_one
        *served.lock().unwrap() = GhAuthRead::Token("gho_two".into());
        // Still within the bound while busy: defer.
        clock.advance(5_000);
        assert_eq!(cache.maintenance_tick(false), None);
        assert_eq!(
            cache.info().unwrap().fingerprint,
            gh_token_fingerprint("gho_one")
        );
        // Past the bound while STILL busy: refresh anyway.
        clock.advance(6_000);
        let changed = cache.maintenance_tick(false);
        assert_eq!(changed, Some(true));
        assert_eq!(
            cache.info().unwrap().fingerprint,
            gh_token_fingerprint("gho_two")
        );
    }

    /// The headline scenario for #67: a token rotates during a worker's
    /// lifetime and the worker adopts it once idle, having served the old token
    /// from the hot path (never blocking) until then.
    #[test]
    fn token_rotation_during_worker_lifetime_is_adopted() {
        let clock = FakeClock::new();
        let served = Arc::new(Mutex::new(GhAuthRead::Token("gho_login_v1".into())));
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            reader_from(served.clone()),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        // Startup prime adopts v1.
        cache.refresh(true);
        let v1_fp = gh_token_fingerprint("gho_login_v1");
        assert_eq!(cache.info().unwrap().fingerprint, v1_fp);
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_login_v1"));

        // Operator runs `gh auth login`; the login rotates mid-lifetime.
        *served.lock().unwrap() = GhAuthRead::Token("gho_login_v2".into());

        // A job is in flight: the hot path keeps serving v1 (no stale-mid-job
        // block) and the busy tick defers the read.
        assert_eq!(cache.maintenance_tick(false), None);
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_login_v1"));

        // The worker goes idle: the next tick adopts v2 and reports the change.
        clock.advance(61_000);
        assert_eq!(cache.maintenance_tick(true), Some(true));
        let v2_fp = gh_token_fingerprint("gho_login_v2");
        assert_eq!(cache.info().unwrap().fingerprint, v2_fp);
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_login_v2"));
        assert_ne!(v1_fp, v2_fp);
    }

    #[test]
    fn info_exposes_identity_but_never_the_token_value() {
        let clock = FakeClock::new();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            Box::new(|| GhAuthRead::Token("gho_secret".into())),
            Box::new(|_| Some("repo, workflow".into())),
            clock.clock(),
        );
        cache.refresh(true);
        clock.advance(120_000);
        let info = cache.info().unwrap();
        assert!(info.present);
        assert_eq!(info.fingerprint, gh_token_fingerprint("gho_secret"));
        assert_eq!(info.scopes.as_deref(), Some("repo, workflow"));
        assert_eq!(info.age_ms, 120_000);
        // The rendered description never carries the token value.
        let desc = describe_gh_auth_token(Some(&info));
        assert!(desc.contains("fingerprint"));
        assert!(desc.contains("scopes: repo, workflow"));
        assert!(!desc.contains("gho_secret"));
    }

    #[test]
    fn describe_renders_token_free_states() {
        assert_eq!(
            describe_gh_auth_token(None),
            "gh auth token: (not yet read)"
        );
        let logged_out = GhAuthTokenInfo {
            present: false,
            fingerprint: None,
            scopes: None,
            since: 0,
            age_ms: 0,
            last_check_ago_ms: 0,
        };
        assert_eq!(
            describe_gh_auth_token(Some(&logged_out)),
            "gh auth token: none (gh missing or not logged in)"
        );
    }

    #[test]
    fn is_git_auth_failure_matches_auth_not_ordinary_failures() {
        assert!(is_git_auth_failure(
            "fatal: unable to access: The requested URL returned error: 403"
        ));
        assert!(is_git_auth_failure("remote: HTTP 401"));
        assert!(is_git_auth_failure(
            "fatal: Authentication failed for 'https://github.com/o/r'"
        ));
        assert!(is_git_auth_failure(
            "remote: Permission to o/r.git denied to user"
        ));
        assert!(is_git_auth_failure(
            "refusing to allow an OAuth App to create or update workflow without `workflow` scope"
        ));
        assert!(is_git_auth_failure("Bad credentials"));
        // Not auth failures:
        assert!(!is_git_auth_failure(
            "! [rejected] main -> main (non-fast-forward)"
        ));
        assert!(!is_git_auth_failure("fatal: repository not found (404)"));
        assert!(!is_git_auth_failure(
            "fatal: unable to access: Connection timed out"
        ));
        assert!(!is_git_auth_failure(""));
    }

    #[test]
    fn invalidate_forces_the_next_lookup_to_reread() {
        let clock = FakeClock::new();
        let reads = Arc::new(AtomicU64::new(0));
        let r2 = reads.clone();
        let cache = GhTokenCache::with_seams(
            60_000,
            240_000,
            Box::new(move || {
                r2.fetch_add(1, Ordering::SeqCst);
                GhAuthRead::Token("gho_x".into())
            }),
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        );
        cache.prime(|_| {});
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(cache.info().is_some());
        cache.invalidate();
        assert!(cache.info().is_none(), "the cache is reset to UNSET");
        // The next hot-path lookup re-reads the CLI.
        assert_eq!(cache.token_for_cli().as_deref(), Some("gho_x"));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    /// Finding-1 regression (the generation fence must bracket the token READ,
    /// not only the scopes probe). A reads the OLD token; while A's read is in
    /// flight, B commits a NEWER token. A must observe the bumped generation and
    /// report `superseded` rather than overwrite B's newer credential.
    #[test]
    fn overlapping_read_does_not_overwrite_a_newer_committed_token() {
        use std::sync::mpsc;
        let clock = FakeClock::new();
        let calls = Arc::new(AtomicU64::new(0));
        let (a_reading_tx, a_reading_rx) = mpsc::channel::<()>();
        let (b_done_tx, b_done_rx) = mpsc::channel::<()>();
        // mpsc endpoints are Send but not Sync; a `Reader` must be Send + Sync,
        // so wrap the ones the reader closure uses in a Mutex.
        let a_reading_tx = Mutex::new(a_reading_tx);
        let b_done_rx = Mutex::new(b_done_rx);
        let c = calls.clone();
        let reader: Reader = Box::new(move || {
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // A: announce it is mid-read, then block until B has committed.
                a_reading_tx.lock().unwrap().send(()).unwrap();
                b_done_rx.lock().unwrap().recv().unwrap();
                GhAuthRead::Token("gho_old".into())
            } else {
                // B: commit immediately with the newer token.
                GhAuthRead::Token("gho_new".into())
            }
        });
        let cache = Arc::new(GhTokenCache::with_seams(
            60_000,
            240_000,
            reader,
            Box::new(|_| Some("repo".into())),
            clock.clock(),
        ));
        let ca = cache.clone();
        let a = std::thread::spawn(move || ca.refresh(true));
        a_reading_rx.recv().unwrap(); // A has snapshotted gen and is mid-read
        let b_out = cache.refresh(true); // B reads + commits gho_new (gen bumps)
        assert_eq!(b_out.token.as_deref(), Some("gho_new"));
        assert!(b_out.changed);
        b_done_tx.send(()).unwrap(); // release A to finish its stale read
        let a_out = a.join().unwrap();
        assert!(
            a_out.superseded,
            "A's stale read must not clobber B's newer commit"
        );
        assert!(!a_out.changed);
        assert_eq!(
            cache.token_for_cli().as_deref(),
            Some("gho_new"),
            "the newer token survives the overlapping stale read"
        );
    }

    /// Finding-4 regression: the production clock never moves backward and stays
    /// anchored to UNIX-epoch millis (so a wall-clock step can't stall refreshes
    /// by clamping `now.saturating_sub(last_check)` to zero).
    #[test]
    fn production_clock_is_monotonic_and_epoch_anchored() {
        let a = now_ms();
        let b = now_ms();
        assert!(b >= a, "the production clock never goes backward");
        assert!(
            a > 1_600_000_000_000,
            "anchored to UNIX-epoch millis, not a monotonic-only base"
        );
    }

    /// Finding-2 regression: a child that outlives the deadline is killed, reaped,
    /// and reported as a failure promptly — not after its own runtime.
    #[cfg(unix)]
    #[test]
    fn run_capped_kills_a_child_that_exceeds_the_timeout() {
        use std::process::Command;
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let out = run_capped(cmd, Duration::from_millis(150));
        assert!(
            out.is_none(),
            "a child past the deadline is killed and reported as a failure"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "returns promptly on timeout, not after the child's full runtime"
        );
    }

    /// Finding-2 companion: a prompt command still returns its captured output
    /// and exit code through the bounded spawn.
    #[cfg(unix)]
    #[test]
    fn run_capped_returns_output_for_a_prompt_command() {
        use std::process::Command;
        let mut cmd = Command::new("printf");
        cmd.arg("hello");
        let (code, stdout, _stderr, output_failed) =
            run_capped(cmd, Duration::from_secs(5)).expect("a fast command completes in time");
        assert_eq!(code, Some(0));
        assert_eq!(stdout, "hello");
        assert!(
            !output_failed,
            "a prompt command's output is fully collected"
        );
    }

    /// Round-4 regression (a descendant-held pipe must fail the read, not fake a
    /// logout): a wrapper that prints its token, exits 0 immediately, and leaves
    /// a background descendant holding stdout open. The wrapper's own output is
    /// collected, but the drain thread stays blocked on the descendant's
    /// inherited pipe past the join bound, so `run_capped` reports
    /// `output_failed` — which `classify_gh_auth_read` maps to a transient
    /// `ReadFailed`, never a `LoggedOut` that would clear a valid cached token.
    /// (The round-3 test's `wait` keeps the wrapper alive until the deadline;
    /// here the wrapper exits at once so the exit code is real and only the
    /// OUTPUT collection fails.)
    #[cfg(unix)]
    #[test]
    fn run_capped_flags_output_failed_when_a_descendant_outlives_the_wrapper() {
        use std::process::Command;
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf gho_x; sleep 30 & exit 0"]);
        let start = Instant::now();
        let (code, _stdout, _stderr, output_failed) =
            run_capped(cmd, Duration::from_millis(150)).expect("the wrapper exits promptly");
        assert_eq!(code, Some(0), "the wrapper itself exits 0");
        assert!(
            output_failed,
            "a descendant holding the pipe past the join bound fails output collection"
        );
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "bounded by deadline + join bound, not the descendant's runtime"
        );
        // The classification contract: never a false logout on uncollected output.
        assert_eq!(
            classify_gh_auth_read(false, code, "", "", output_failed),
            GhAuthRead::ReadFailed
        );
    }

    /// Round-3 regression (descendant-held pipes must not outlive the deadline):
    /// a shell that backgrounds a long-lived child and waits on it inherits our
    /// stdout/stderr into that child, so killing only the direct shell would
    /// leave the pipes open and the drain threads blocked. The whole process
    /// group must be killed so the pipes close, and the call must return
    /// promptly — not after the descendant's own runtime.
    #[cfg(unix)]
    #[test]
    fn run_capped_kills_descendants_holding_the_pipes() {
        use std::process::Command;
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & wait"]);
        let start = Instant::now();
        let out = run_capped(cmd, Duration::from_millis(150));
        assert!(
            out.is_none(),
            "a child whose descendant holds the pipes is still a timeout"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "returns promptly: killing the direct child alone would leave the \
             descendant holding the pipes and the drain joins blocked"
        );
    }

    /// Round-5 regression (advisory: *preserve cleanup guard until descendant
    /// output collection completes*). The round-4 test above proved the read is
    /// reported as `output_failed`; this proves the surviving descendant is also
    /// KILLED, not merely reported. A wrapper exits 0 while a backgrounded
    /// descendant records its own pid and then holds stdout open. Because the
    /// direct child exited cleanly, the timeout branch never fired, so the ONLY
    /// thing that tears the descendant down is the post-collection group kill
    /// `run_capped` now performs when a drain can't complete. Without it the
    /// descendant (and its blocked reader/joiner threads) would accumulate on
    /// every refresh tick. We assert the recorded pid is dead afterwards.
    #[cfg(unix)]
    #[test]
    fn run_capped_kills_a_descendant_that_outlives_a_successful_wrapper() {
        use std::process::Command;
        let pidfile = std::env::temp_dir().join(format!(
            "nano_gh_desc_{}_{}.pid",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&pidfile);
        // Background `sleep` (it inherits stdout and holds the pipe open), record
        // ITS pid via `$!` — not `$$`, which in a subshell is the parent sh's pid
        // and would make this pass trivially once sh is reaped — then exit 0.
        let script = format!(
            "printf gho_x; sleep 30 & echo $! > '{p}'; exit 0",
            p = pidfile.display()
        );
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script.as_str()]);
        let (code, _stdout, _stderr, output_failed) =
            run_capped(cmd, Duration::from_millis(150)).expect("the wrapper exits promptly");
        assert_eq!(code, Some(0), "the wrapper itself exits 0");
        assert!(
            output_failed,
            "a descendant holding the pipe fails output collection"
        );
        // Read the pid the backgrounded sleep recorded.
        let mut pid: Option<i32> = None;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pidfile) {
                if let Ok(p) = s.trim().parse::<i32>() {
                    pid = Some(p);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = pid.expect("the descendant recorded its pid before sleeping");
        // `kill(pid, 0)` succeeds for a ZOMBIE too: once the wrapper exits, its
        // killed descendant is reparented and must be reaped by its NEW parent,
        // not by `run_capped` — so in a container without prompt orphan reaping
        // the pid can linger as a zombie even though cleanup succeeded. Assert on
        // the zombie-aware group-liveness check instead: the descendant shares
        // the wrapper's process group (pgid == the wrapper's pid, since the
        // wrapper leads the group), so `group_has_live_member` reports `false`
        // once no LIVE member remains, ignoring a held zombie anchor.
        //
        // `getpgid` itself can also legitimately fail with ESRCH here: if the
        // descendant's new parent reaps it PROMPTLY, the pid is already gone —
        // which IS successful cleanup, so accept ESRCH as done. Any other lookup
        // error is a real failure; when the pid still exists, retain the
        // zombie-aware group-liveness check.
        let pgid = unsafe { libc::getpgid(pid) };
        if pgid < 0 {
            let err = std::io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ESRCH),
                "getpgid(descendant pid {pid}) failed with an error other than ESRCH: {err}"
            );
            let _ = std::fs::remove_file(&pidfile);
            // ESRCH: the descendant is already reaped — cleanup succeeded.
            return;
        }
        let mut live = true;
        for _ in 0..200 {
            if !crate::pdeath::group_has_live_member(pgid as u32) {
                live = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            !live,
            "the surviving descendant must be killed by the post-collection group \
             cleanup, not leaked across refresh ticks (pid {pid}, pgid {pgid})"
        );
    }

    /// Round-8 regression ("Previously missed" advisory: *clean up surviving
    /// descendants after successful output collection*). The round-5 test above
    /// proves the descendant is killed when its inherited pipe keeps a drain
    /// blocked (`output_failed`). This proves the OTHER hole is closed too: a
    /// wrapper such as `printf gho_x; sleep 30 >/dev/null 2>&1 & exit 0` exits
    /// 0 and the descendant's redirected output never holds our pipes, so BOTH
    /// drains finish and `output_failed` is false — yet the descendant is still
    /// alive and, before the fix, was disarmed and leaked (one process plus its
    /// watchdog/reaper resources per refresh tick). `run_capped` now issues an
    /// UNCONDITIONAL identity-gated group SIGKILL after successful collection —
    /// no longer gated on a best-effort `group_has_live_member()` scan, whose
    /// fail-open false negative would skip the kill and then be defeated by the
    /// unconditional `disarm()` (the "Unconditional disarm" advisory). We assert
    /// the recorded
    /// descendant pid is dead afterwards — with the same ESRCH/zombie-aware
    /// handling as the round-5 test: once the wrapper exits, the killed
    /// descendant is reparented and reaped by its NEW parent, so a prompt
    /// reaper makes `getpgid` fail with ESRCH (successful cleanup), and a
    /// lingering zombie is not a live member.
    #[cfg(unix)]
    #[test]
    fn run_capped_kills_a_descendant_after_successful_output_collection() {
        use std::process::Command;
        let pidfile = std::env::temp_dir().join(format!(
            "nano_gh_desc_ok_{}_{}.pid",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_file(&pidfile);
        // Background `sleep` with its output REDIRECTED (so it never holds our
        // pipes and both drains complete), record ITS pid via `$!` — not `$$`,
        // which in a subshell is the parent sh's pid and would make this pass
        // trivially once sh is reaped — then exit 0.
        let script = format!(
            "printf gho_x; sleep 30 >/dev/null 2>&1 & echo $! > '{p}'; exit 0",
            p = pidfile.display()
        );
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script.as_str()]);
        let (code, stdout, _stderr, output_failed) =
            run_capped(cmd, Duration::from_millis(150)).expect("the wrapper exits promptly");
        assert_eq!(code, Some(0), "the wrapper itself exits 0");
        assert_eq!(stdout, "gho_x", "the wrapper's own output is collected");
        assert!(
            !output_failed,
            "the descendant's redirected output never holds our pipes, so collection succeeds"
        );
        // Read the pid the backgrounded sleep recorded.
        let mut pid: Option<i32> = None;
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&pidfile) {
                if let Ok(p) = s.trim().parse::<i32>() {
                    pid = Some(p);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = pid.expect("the descendant recorded its pid before sleeping");
        // Same liveness contract as the round-5 test: accept ESRCH (already
        // reaped by its new parent) as successful cleanup; reject other lookup
        // errors; when the pid still exists, assert the group has no LIVE
        // member (a held zombie anchor is not one).
        let pgid = unsafe { libc::getpgid(pid) };
        if pgid < 0 {
            let err = std::io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ESRCH),
                "getpgid(descendant pid {pid}) failed with an error other than ESRCH: {err}"
            );
            let _ = std::fs::remove_file(&pidfile);
            // ESRCH: the descendant is already reaped — cleanup succeeded.
            return;
        }
        let mut live = true;
        for _ in 0..200 {
            if !crate::pdeath::group_has_live_member(pgid as u32) {
                live = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(&pidfile);
        assert!(
            !live,
            "the surviving descendant must be killed after successful output \
             collection, not leaked across refresh ticks (pid {pid}, pgid {pgid})"
        );
    }

    /// Round-5 regression (advisory: *pin Enterprise host and token source*).
    /// The scopes probe must deliver OUR exact token in whichever variable the
    /// active host honours — `GH_TOKEN` on github.com, `GH_ENTERPRISE_TOKEN` on
    /// a self-hosted Enterprise host, where `gh` IGNORES `GH_TOKEN` and would
    /// otherwise fall back to stored credentials (pairing this token's
    /// fingerprint with a different login's scopes). Setting BOTH to the same
    /// value makes the probe host-agnostic: whichever var the host uses, it is
    /// our token.
    #[test]
    fn apply_probe_token_feeds_both_github_and_enterprise_token_vars() {
        let mut cmd = std::process::Command::new("gh");
        apply_probe_token(&mut cmd, "gho_secret");
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                v.map(|v| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect();
        assert!(
            envs.iter()
                .any(|(k, v)| k == "GH_TOKEN" && v == "gho_secret"),
            "the github.com token var must carry our exact token"
        );
        assert!(
            envs.iter()
                .any(|(k, v)| k == "GH_ENTERPRISE_TOKEN" && v == "gho_secret"),
            "the Enterprise token var must carry the SAME token so the probe never \
             falls back to stored creds on a self-hosted host"
        );
    }
}
