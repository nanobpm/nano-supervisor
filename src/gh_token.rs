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

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};

/// `NANO_GH_TOKEN_TTL_MS` default: 5 minutes. A warm cache younger than this is
/// served without re-spawning `gh`.
const DEFAULT_TTL_MS: u64 = 5 * 60_000;

/// Monotonic clock in milliseconds since the UNIX epoch — the production clock
/// for the cache. Tests inject their own.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
/// `status` is the process exit code (`None` = killed/no code).
pub fn classify_gh_auth_read(
    spawn_errored: bool,
    status: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> GhAuthRead {
    if spawn_errored {
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
    /// lock, then the record is committed under a generation fence.
    fn adopt(&self, read: GhAuthRead) -> AdoptOutcome {
        // Snapshot prev + generation under the lock, then release it for the
        // (possibly slow) scopes probe.
        let (prev, start_gen) = {
            let g = self.inner.lock().unwrap();
            (g.cache.clone(), g.generation)
        };
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
        {
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
        }
        let read = (self.reader)();
        self.adopt(read)
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

/// Production `gh auth token` reader (synchronous spawn). Bounded by a 10s wait.
fn read_gh_auth_token_default() -> GhAuthRead {
    use std::process::Command;
    let mut cmd = Command::new("gh");
    cmd.args(["auth", "token"]);
    for (k, v) in gh_noninteractive_env() {
        cmd.env(k, v);
    }
    match cmd.output() {
        Ok(out) => classify_gh_auth_read(
            false,
            out.status.code(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(_) => GhAuthRead::ReadFailed,
    }
}

/// Read the token's OAuth scopes from the live `X-OAuth-Scopes` response header.
/// Best-effort: failure -> `None` (scopes simply go unreported). The token rides
/// the child env (`GH_TOKEN`), NEVER argv, so it can't leak via `ps` — the same
/// no-env-leak-to-argv guarantee as the credential delivery in [`crate::provision`].
fn gh_token_scopes(token: &str, _timeout: Duration) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    use std::process::Command;
    let mut cmd = Command::new("gh");
    cmd.args(["api", "-i", "--include", "user"]);
    for (k, v) in gh_noninteractive_env() {
        cmd.env(k, v);
    }
    cmd.env("GH_TOKEN", token);
    let out = cmd.output().ok()?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push('\n');
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
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
            classify_gh_auth_read(false, Some(0), "gho_abc\n", ""),
            GhAuthRead::Token("gho_abc".into())
        );
        assert_eq!(
            classify_gh_auth_read(false, Some(0), "   \n", ""),
            GhAuthRead::LoggedOut
        );
        assert_eq!(
            classify_gh_auth_read(false, Some(1), "", "no oauth token found for github.com"),
            GhAuthRead::LoggedOut
        );
        assert_eq!(
            classify_gh_auth_read(false, Some(1), "", "keychain error"),
            GhAuthRead::ReadFailed
        );
        assert_eq!(
            classify_gh_auth_read(true, None, "", ""),
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
}
