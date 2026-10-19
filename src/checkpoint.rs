//! WIP checkpoints for ephemeral agent workers (parity port of the Node plugin's
//! `agent-checkpoint.mjs`, nanobpm/nano-supervisor#66; JS issues #264 + #295/#296).
//!
//! A host-provisioned agent job runs in a throwaway clone. If the worker dies
//! mid-run (crash, OOM, preemption, `stop --force`, SLA cancel) every UNCOMMITTED
//! change and every unpushed local commit dies with it, and the re-activation can
//! only replay the transcript. This module lets the worker periodically snapshot
//! the workspace to a deterministic remote ref WITHOUT touching the agent's HEAD,
//! index, or branch, and restore that snapshot on the next activation.
//!
//!   - **Snapshot**: a "shadow commit" built through a TEMPORARY index
//!     (`GIT_INDEX_FILE`): `read-tree HEAD` (or the empty tree on an UNBORN HEAD) →
//!     `add -A` (honours `.gitignore`) → drop deny-listed / oversized / secret
//!     paths → `write-tree` → `commit-tree -p HEAD` (parentless when unborn). The
//!     agent's own index and refs are never written.
//!   - **Push**: `refs/nano/wip/<elementInstanceKey>` with `--force-with-lease`
//!     against the last sha WE pushed, so a zombie prior owner can't clobber a
//!     newer run. The snapshot's ancestry carries any unpushed local commits too.
//!   - **Restore**: fetch the ref; if the fresh clone's HEAD is an ancestor of the
//!     snapshot's parent, move the branch to that parent (recovering local commits)
//!     and lay the snapshot tree down as UNCOMMITTED changes. Otherwise apply the
//!     prior run's base→snapshot diff onto the new HEAD (`--3way`), else skip.
//!   - **Delete**: drop the ref after a successful finalize.
//!   - **Recovery refs** (#295): on an SLA-cancel / force-stop / failed run the
//!     last snapshot is promoted to `refs/nano/recovered/<eik>`, OUTSIDE the
//!     per-checkpoint WIP reap, so a human escalation can be answered and resumed.
//!   - **Orphan GC** (#295/#296): a throttled sweep deletes WIP / recovered refs
//!     past a TTL, or whose element instance is terminal AND whose PROCESS instance
//!     is also finished — an element terminated by an SLA boundary timer inside a
//!     STILL-ACTIVE process is pending human escalation and is SPARED.
//!
//! Mode (`NANO_AGENT_CHECKPOINT`): `auto` (default) runs only for provisioned jobs
//! that already push an authenticated working branch; `on` forces it for any
//! provisioned job; `off` disables. Everything is BEST-EFFORT: any failure is
//! logged and degrades to transcript-only resume.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::safecwd::CwdHandle;

/// Namespace of per-checkpoint WIP refs.
pub const CHECKPOINT_REF_PREFIX: &str = "refs/nano/wip/";
/// Namespace of GC-proof recovery refs (#295).
pub const RECOVERED_REF_PREFIX: &str = "refs/nano/recovered/";
/// Shared root of every nano-managed ref namespace.
pub const NANO_REF_ROOT: &str = "refs/nano/";

const CHECKPOINT_BASE_TRAILER: &str = "Nano-Checkpoint-Base";
const CHECKPOINT_RUN_TRAILER: &str = "Nano-Checkpoint-Run";
const CHECKPOINT_BASEREF_TRAILER: &str = "Nano-Checkpoint-BaseRef";
const CHECKPOINT_BRANCH_TRAILER: &str = "Nano-Checkpoint-Branch";
/// Explicit "HEAD was detached" identity. The `:` makes it an impossible git
/// branch name so it can never equal a real expected branch.
const CHECKPOINT_DETACHED_MARKER: &str = "HEAD:detached";

const MIN_INTERVAL_FLOOR_MS: u64 = 5_000;

/// The full set of ref prefixes the orphan GC reaps.
pub fn swept_ref_prefixes() -> [&'static str; 2] {
    [CHECKPOINT_REF_PREFIX, RECOVERED_REF_PREFIX]
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Checkpoint mode parsed from `NANO_AGENT_CHECKPOINT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointMode {
    /// Only checkpoint provisioned jobs that already push an authenticated branch.
    Auto,
    /// Force checkpointing for any provisioned job.
    On,
    /// Disable checkpointing.
    Off,
}

/// Parse the `NANO_AGENT_CHECKPOINT` value (defaulting to `auto`).
pub fn checkpoint_mode(value: &str) -> CheckpointMode {
    let v = value.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "auto" => CheckpointMode::Auto,
        "on" => CheckpointMode::On,
        "off" => CheckpointMode::Off,
        "1" | "true" | "yes" => CheckpointMode::On,
        "0" | "false" | "no" | "disable" | "disabled" => CheckpointMode::Off,
        _ => CheckpointMode::Auto,
    }
}

/// Resolved checkpoint configuration.
#[derive(Clone, Debug)]
pub struct CheckpointConfig {
    pub mode: CheckpointMode,
    pub min_interval_ms: u64,
    pub interval_ms: u64,
    pub max_file_bytes: u64,
    pub ttl_ms: u64,
    pub gc_grace_ms: u64,
    pub gc_every_ms: u64,
    pub git_timeout_ms: u64,
}

impl CheckpointConfig {
    /// Read configuration from the process environment.
    pub fn from_env() -> Self {
        Self::build(|k| std::env::var(k).ok())
    }

    /// Build configuration from an arbitrary getter (seam for tests).
    pub fn build<F: Fn(&str) -> Option<String>>(get: F) -> Self {
        let mode = checkpoint_mode(&get("NANO_AGENT_CHECKPOINT").unwrap_or_default());
        let int_or = |key: &str, dflt: u64| -> u64 {
            get(key)
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|&n| n >= 0)
                .map(|n| n as u64)
                .unwrap_or(dflt)
        };
        CheckpointConfig {
            mode,
            min_interval_ms: int_or("NANO_AGENT_CHECKPOINT_MIN_INTERVAL_MS", 60_000)
                .max(MIN_INTERVAL_FLOOR_MS),
            interval_ms: int_or("NANO_AGENT_CHECKPOINT_INTERVAL_MS", 300_000),
            max_file_bytes: int_or("NANO_AGENT_CHECKPOINT_MAX_FILE_BYTES", 5 * 1024 * 1024),
            ttl_ms: int_or("NANO_AGENT_CHECKPOINT_TTL_MS", 7 * 24 * 60 * 60 * 1000),
            gc_grace_ms: 60 * 60 * 1000,
            gc_every_ms: 60 * 60 * 1000,
            git_timeout_ms: 60_000,
        }
    }

    pub fn enabled(&self) -> bool {
        self.mode != CheckpointMode::Off
    }

    pub fn git_timeout(&self) -> Duration {
        Duration::from_millis(self.git_timeout_ms)
    }
}

/// Outcome of the eligibility decision for `auto`/`on`/`off`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eligibility {
    pub enabled: bool,
    pub reason: String,
}

/// Does this job checkpoint? `auto` only when the job already publishes its work:
/// a provisioned, authenticated clone on a symbolic working branch that pushes.
pub fn checkpoint_eligibility(
    mode: CheckpointMode,
    has_workspace: bool,
    branch_push: Option<bool>,
    authenticated: bool,
    working_branch: Option<&str>,
) -> Eligibility {
    let no = |reason: &str| Eligibility {
        enabled: false,
        reason: reason.to_string(),
    };
    let yes = |reason: &str| Eligibility {
        enabled: true,
        reason: reason.to_string(),
    };
    if mode == CheckpointMode::Off {
        return no("NANO_AGENT_CHECKPOINT=off");
    }
    if !has_workspace {
        return no("no provisioned workspace");
    }
    if mode == CheckpointMode::On {
        return yes("NANO_AGENT_CHECKPOINT=on");
    }
    if branch_push == Some(false) {
        return no("job does not push (branch.push=false)");
    }
    if !authenticated {
        return no("anonymous clone (no push credentials)");
    }
    match working_branch {
        Some(b) if !b.is_empty() => yes("auto: job pushes an authenticated working branch"),
        _ => no("detached checkout (no working branch)"),
    }
}

/// Does this remote URL carry its OWN push authentication (SSH, or HTTPS userinfo)?
pub fn is_authenticated_remote(url: &str) -> bool {
    let s = url.trim();
    if s.is_empty() {
        return false;
    }
    // scp-like SSH syntax `[user@]host:path` (no URL scheme).
    if let Some(at) = s.find('@') {
        let (user, rest) = s.split_at(at);
        let rest = &rest[1..];
        if !user.contains('/')
            && !rest.is_empty()
            && rest.contains(':')
            && !rest.split(':').next().unwrap_or("").contains('/')
        {
            return true;
        }
    }
    if let Some((scheme, rest)) = s.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if scheme == "ssh" {
            return true;
        }
        if scheme == "https" || scheme == "http" {
            // userinfo present iff the authority (before the first '/') has an '@'.
            let authority = rest.split('/').next().unwrap_or("");
            if authority.contains('@') {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Ref naming
// ---------------------------------------------------------------------------

fn valid_key(key: &str) -> bool {
    let key = key.trim();
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The WIP ref for an element instance key, or `None` when the key is malformed.
pub fn checkpoint_ref(element_instance_key: &str) -> Option<String> {
    let key = element_instance_key.trim();
    valid_key(key).then(|| format!("{CHECKPOINT_REF_PREFIX}{key}"))
}

/// The GC-proof recovery ref for an element instance key.
pub fn recovered_checkpoint_ref(element_instance_key: &str) -> Option<String> {
    let key = element_instance_key.trim();
    valid_key(key).then(|| format!("{RECOVERED_REF_PREFIX}{key}"))
}

/// The namespace prefix a ref belongs to, if any.
fn ref_prefix(s: &str) -> Option<&'static str> {
    if s.starts_with(CHECKPOINT_REF_PREFIX) {
        Some(CHECKPOINT_REF_PREFIX)
    } else if s.starts_with(RECOVERED_REF_PREFIX) {
        Some(RECOVERED_REF_PREFIX)
    } else {
        None
    }
}

/// Read a well-formed predecessor checkpoint ref out of the process-scoped
/// `resumeFromCheckpoint` variable, correlated to this task's `element_id` when
/// supplied. Returns `None` when absent/malformed/self/mismatched.
pub fn predecessor_checkpoint_ref(
    variables: &Value,
    self_ref: Option<&str>,
    element_id: Option<&str>,
) -> Option<String> {
    let v = variables.get("resumeFromCheckpoint")?;
    let (ref_str, recorded_element) = match v {
        Value::String(s) => (s.as_str(), None),
        Value::Object(_) => (
            v.get("ref").and_then(Value::as_str).unwrap_or(""),
            v.get("elementId").and_then(Value::as_str),
        ),
        _ => return None,
    };
    let s = ref_str.trim();
    let prefix = ref_prefix(s)?;
    let key = &s[prefix.len()..];
    if !valid_key(key) {
        return None;
    }
    if Some(s) == self_ref {
        return None;
    }
    // Correlation gate: only a POSITIVE mismatch on a present recorded elementId refuses.
    if let (Some(caller), Some(recorded)) = (element_id, recorded_element) {
        if recorded != caller {
            return None;
        }
    }
    Some(s.to_string())
}

/// Is the resume slot an EXPLICIT, occurrence-authoritative bare-string ref?
pub fn resume_ref_is_explicit(variables: &Value) -> bool {
    match variables.get("resumeFromCheckpoint") {
        Some(Value::String(s)) => {
            let s = s.trim();
            match ref_prefix(s) {
                Some(prefix) => valid_key(&s[prefix.len()..]),
                None => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Deny-list and secret-content filtering
// ---------------------------------------------------------------------------

/// Paths that must never leave the worker even if the agent forgot to gitignore
/// them. Matched against the repo-relative path (any directory depth).
pub fn is_denied_path(path: &str) -> bool {
    let p = path;
    let base = p.rsplit('/').next().unwrap_or(p);
    let lower = base.to_ascii_lowercase();

    // `.env*` family, `.npmrc`, `.netrc`, `.pypirc`, `.git-credentials`.
    if lower.starts_with(".env") {
        return true;
    }
    if matches!(
        lower.as_str(),
        ".npmrc" | ".netrc" | ".pypirc" | ".git-credentials"
    ) {
        return true;
    }
    // `id_*` basename family.
    if lower.starts_with("id_") {
        return true;
    }
    // Key material by extension.
    if let Some(ext) = lower.rsplit_once('.').map(|(_, e)| e) {
        if matches!(ext, "pem" | "key" | "p12" | "pfx" | "jks" | "keystore") {
            return true;
        }
    }
    // `credentials` / `credentials.json`.
    if lower == "credentials" || lower == "credentials.json" {
        return true;
    }
    // `secret(s).(json|yaml|yml|toml)`.
    if let Some((stem, ext)) = lower.rsplit_once('.') {
        if (stem == "secret" || stem == "secrets")
            && matches!(ext, "json" | "yaml" | "yml" | "toml")
        {
            return true;
        }
    }
    // Any path component in a sensitive dot-directory.
    p.split('/')
        .any(|c| matches!(c.to_ascii_lowercase().as_str(), ".aws" | ".ssh" | ".gnupg"))
}

/// Normalize injected secret values: trim, drop empties, dedupe.
pub fn normalize_secret_values(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        let s = v.trim();
        if !s.is_empty() && !out.iter().any(|e| e == s) {
            out.push(s.to_string());
        }
    }
    out
}

/// Extract credentials embedded in a remote URL's userinfo (`user:pass@host`),
/// in both raw and percent-decoded forms. Non-HTTP(S) / userinfo-less URLs → [].
pub fn credentials_from_url(url: &str) -> Vec<String> {
    let s = url.trim();
    let Some((scheme, rest)) = s.split_once("://") else {
        return Vec::new();
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Vec::new();
    }
    let authority = rest.split('/').next().unwrap_or("");
    let Some((userinfo, _host)) = authority.rsplit_once('@') else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    let (user, pass) = match userinfo.split_once(':') {
        Some((u, p)) => (u, Some(p)),
        None => (userinfo, None),
    };
    for raw in [pass, Some(user)].into_iter().flatten() {
        if raw.is_empty() {
            continue;
        }
        if !out.iter().any(|e| e == raw) {
            out.push(raw.to_string());
        }
        if let Some(dec) = percent_decode(raw) {
            if !dec.is_empty() && !out.iter().any(|e| e == &dec) {
                out.push(dec);
            }
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return Some(s.to_string());
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Does `text` contain a known-credential format or one of the injected secrets?
pub fn contains_secret(text: &str, secret_values: &[String]) -> bool {
    if text.is_empty() {
        return false;
    }
    if secret_values
        .iter()
        .any(|v| !v.is_empty() && text.contains(v.as_str()))
    {
        return true;
    }
    // PEM private key block. Scan EVERY `-----BEGIN ` marker, not just the first:
    // a file whose first block is a certificate or public key followed by a
    // private-key block would otherwise slip through and publish the private key.
    let mut search = text;
    while let Some(i) = search.find("-----BEGIN ") {
        let tail = &search[i + "-----BEGIN ".len()..];
        if let Some(j) = tail.find("-----") {
            let label = &tail[..j];
            if label.ends_with("PRIVATE KEY")
                && label.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
            {
                return true;
            }
            // Advance past this marker's closing dashes so the next iteration
            // inspects subsequent blocks.
            search = &tail[j + "-----".len()..];
        } else {
            search = tail;
        }
    }
    // Token prefixes with a minimum run of allowed characters.
    let alnum = |b: u8| b.is_ascii_alphanumeric();
    let alnum_us = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let alnum_dash = |b: u8| b.is_ascii_alphanumeric() || b == b'-';
    let alnum_us_dash = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let upper_digit = |b: u8| b.is_ascii_digit() || b.is_ascii_uppercase();
    let alnum_us_dash_proj = alnum_us_dash;

    for pfx in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if token_after(text, pfx, 36, alnum) {
            return true;
        }
    }
    if token_after(text, "github_pat_", 60, alnum_us) {
        return true;
    }
    for pfx in ["AKIA", "ASIA"] {
        if token_exact(text, pfx, 16, upper_digit) {
            return true;
        }
    }
    for pfx in ["xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"] {
        if token_after(text, pfx, 10, alnum_dash) {
            return true;
        }
    }
    for pfx in ["sk-proj-", "sk-ant-", "sk-"] {
        if token_after(text, pfx, 32, alnum_us_dash_proj) {
            return true;
        }
    }
    if token_exact(text, "AIza", 35, alnum_us_dash) {
        return true;
    }
    if token_exact(text, "npm_", 36, alnum) {
        return true;
    }
    false
}

/// `prefix` followed by AT LEAST `min` chars matching `allow`.
fn token_after(text: &str, prefix: &str, min: usize, allow: impl Fn(u8) -> bool) -> bool {
    let bytes = text.as_bytes();
    let pb = prefix.as_bytes();
    let mut i = 0;
    while let Some(off) = find_from(bytes, pb, i) {
        let mut run = 0;
        let mut j = off + pb.len();
        while j < bytes.len() && allow(bytes[j]) {
            run += 1;
            j += 1;
        }
        if run >= min {
            return true;
        }
        i = off + 1;
    }
    false
}

/// `prefix` followed by EXACTLY `n` chars matching `allow` (not more).
fn token_exact(text: &str, prefix: &str, n: usize, allow: impl Fn(u8) -> bool) -> bool {
    let bytes = text.as_bytes();
    let pb = prefix.as_bytes();
    let mut i = 0;
    while let Some(off) = find_from(bytes, pb, i) {
        let mut run = 0;
        let mut j = off + pb.len();
        while j < bytes.len() && allow(bytes[j]) {
            run += 1;
            j += 1;
        }
        if run >= n {
            return true;
        }
        i = off + 1;
    }
    false
}

fn find_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

// ---------------------------------------------------------------------------
// Push-failure classification
// ---------------------------------------------------------------------------

/// Why a push failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushFailure {
    /// `--force-with-lease` expectation was stale (another writer moved the ref).
    Lease,
    /// The remote refused it (rules, push protection, hooks).
    Policy,
    /// No permission / bad credentials.
    Auth,
    /// Network / timeout / anything else — worth retrying.
    Transient,
}

/// Classify a push failure from git's combined stderr/stdout.
pub fn classify_push_failure(text: &str) -> PushFailure {
    let t = text.to_ascii_lowercase();
    if t.contains("(stale info)") {
        return PushFailure::Lease;
    }
    for m in [
        "remote rejected",
        "push protection",
        "repository rule",
        "pre-receive hook",
        "protected ref",
        "declined",
    ] {
        if t.contains(m) {
            return PushFailure::Policy;
        }
    }
    // "GH0NN" codes (secret-scanning / policy).
    if let Some(i) = t.find("gh0") {
        let tail = &t.as_bytes()[i + 3..];
        if tail.len() >= 2 && tail[0].is_ascii_digit() && tail[1].is_ascii_digit() {
            return PushFailure::Policy;
        }
    }
    for m in [
        "permission denied",
        "permission to",
        "403",
        "authentication failed",
        "could not read username",
        "invalid username or password",
        "access denied",
        "not authorized",
    ] {
        if t.contains(m) {
            return PushFailure::Auth;
        }
    }
    if t.contains("! [rejected]") {
        return PushFailure::Lease;
    }
    PushFailure::Transient
}

// ---------------------------------------------------------------------------
// Orphan probe (#295/#296)
// ---------------------------------------------------------------------------

/// Is a terminal element inside a terminal process? The pure decision behind the
/// orphan probe: an element must be COMPLETED/TERMINATED; with a process reader it
/// must ALSO be finished (COMPLETED/TERMINATED/CANCELED). Any `None` (unknown /
/// unreachable) spares the ref (returns `false`) so only the TTL reclaims it.
pub fn orphan_decision(
    element_state: Option<&str>,
    has_process_reader: bool,
    process_state: Option<&str>,
) -> bool {
    let terminal_element = matches!(element_state, Some("COMPLETED") | Some("TERMINATED"));
    if !terminal_element {
        return false;
    }
    if !has_process_reader {
        return true;
    }
    matches!(
        process_state,
        Some("COMPLETED") | Some("TERMINATED") | Some("CANCELED")
    )
}

/// Async predicate the GC sweep consults: given an element-instance key, is its
/// checkpoint an orphan (safe to reclaim)? Implementations fail CLOSED on any
/// error (return `false`) so a recoverable checkpoint is never eagerly deleted.
pub trait OrphanProbe: Send + Sync {
    fn is_orphan<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Git runner
// ---------------------------------------------------------------------------

/// Captured result of one git invocation.
#[derive(Clone, Debug)]
pub struct GitOut {
    pub status: Option<i32>,
    /// Lossy-decoded stdout for TEXTUAL consumers (ref listings, shas,
    /// diagnostics). Binary payloads must use [`GitOut::stdout_bytes`].
    pub stdout: String,
    pub stderr: String,
    /// Raw stdout bytes, BEFORE the lossy UTF-8 decode. A `git diff --binary`
    /// restore patch can carry non-UTF-8 hunk content (e.g. Latin-1 without NUL
    /// bytes); the lossy decode would replace those bytes and corrupt the patch
    /// handed to `git apply`, so patch transport reads this field instead.
    pub stdout_bytes: Vec<u8>,
}

impl GitOut {
    fn ok(&self) -> bool {
        self.status == Some(0)
    }
    fn out(&self) -> String {
        self.stdout.trim().to_string()
    }
    /// Raw stdout bytes for binary-safe transport (e.g. a patch piped to
    /// `git apply`). Never lossy-decoded.
    fn stdout_bytes(&self) -> &[u8] {
        &self.stdout_bytes
    }
    fn err_text(&self) -> String {
        let t = if !self.stderr.trim().is_empty() {
            self.stderr.trim()
        } else {
            self.stdout.trim()
        };
        let tail: Vec<&str> = t.lines().rev().take(3).collect();
        let joined: Vec<&str> = tail.into_iter().rev().collect();
        let mut s = joined.join(" | ");
        truncate_on_char_boundary(&mut s, 400);
        redact_url_userinfo(&s)
    }
}

/// Truncate `s` in place to at most `max` bytes WITHOUT splitting a UTF-8
/// character. `String::truncate` panics when `max` falls inside a multi-byte
/// char (e.g. 399 ASCII bytes followed by `é`); a job-controlled git diagnostic
/// must never panic the checkpointer, so back the cut up to the nearest char
/// boundary at or below `max`.
fn truncate_on_char_boundary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut boundary = max;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s.truncate(boundary);
}

/// Redact `scheme://user:pass@` userinfo from a diagnostic string.
pub fn redact_url_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &s[i..];
        let matched = ["https://", "http://"]
            .iter()
            .find(|p| rest.starts_with(**p));
        if let Some(p) = matched {
            // find the authority up to '/', '@' or whitespace
            let after = &rest[p.len()..];
            if let Some(at) = after.find('@') {
                let seg = &after[..at];
                if !seg.contains('/') && !seg.chars().any(|c| c.is_whitespace()) {
                    out.push_str(p);
                    out.push_str("***@");
                    i += p.len() + at + 1;
                    continue;
                }
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Async git runner bound to one workspace directory. Every invocation suppresses
/// the host credential helper (`-c credential.helper=`) and disables terminal
/// prompts, so a remote checkpoint op never blocks on, reuses, or persists a
/// credential.
pub struct GitRunner {
    cwd: CwdHandle,
    timeout: Duration,
    /// Out-of-band push/fetch credential (HTTPS userinfo lifted from the clone
    /// URL), delivered to git via the same secret-file credential helper the
    /// provisioning path uses. `None` for an anonymous or SSH remote (SSH auth
    /// rides the agent/transport) and for the local-remote tests.
    cred: Option<crate::provision::GitCredential>,
    /// Isolate global/system git config to `/dev/null` for authenticated remote
    /// ops, mirroring `provision::git_isolated`: the agent shares the daemon's
    /// `HOME`, so its global config (`insteadOf`, proxies) is untrusted.
    isolate_config: bool,
    /// Hard cap on retained stdout bytes per invocation. Every pipe is still
    /// drained to EOF (so git never blocks on a full buffer), but a
    /// job-controlled remote/helper flooding stdout — or a pathological ref
    /// listing — can never grow unbounded and exhaust the long-lived daemon's
    /// memory. On overflow the invocation FAILS CLOSED (`status = None`) so a
    /// caller never parses a silently truncated ref listing / blob / patch.
    /// Must exceed the largest legitimate stdout (a `cat-file blob` of a file up
    /// to `max_file_bytes`); `run_in` callers that read blobs size it from the
    /// config (see `with_max_stdout`).
    max_stdout: usize,
    /// When set, every git invocation runs against THIS repository directory
    /// (`--git-dir`) instead of the checkout the runner's cwd is pinned to. The
    /// orphan-GC sweep uses it to operate on a dedicated scratch repo that
    /// outlives any single job's checkout, so reaping a job's `.git` mid-sweep
    /// cannot fail the sweep's git operations.
    git_dir: Option<std::path::PathBuf>,
}

/// Default retained-stdout cap: comfortably over the 5 MiB default
/// `max_file_bytes` blob read plus `cat-file` headers, while still bounding a
/// flooded pipe far below daemon-exhausting sizes. Authenticated runners raise
/// it from config via [`GitRunner::with_max_stdout`].
const DEFAULT_MAX_STDOUT: usize = 16 * 1024 * 1024;

impl GitRunner {
    pub fn new(cwd: CwdHandle, timeout: Duration) -> Self {
        GitRunner {
            cwd,
            timeout,
            cred: None,
            isolate_config: false,
            max_stdout: DEFAULT_MAX_STDOUT,
            git_dir: None,
        }
    }

    /// Point every git invocation at a SPECIFIC repository directory
    /// (`--git-dir`), decoupling the operation from the checkout the runner's cwd
    /// is pinned to. Used by the orphan-GC sweep so it runs against a dedicated
    /// scratch repo that survives the job checkout's teardown.
    pub fn with_git_dir(mut self, git_dir: std::path::PathBuf) -> Self {
        self.git_dir = Some(git_dir);
        self
    }

    /// Raise the retained-stdout cap so a legitimate `cat-file blob` of a file up
    /// to `max_file_bytes` is never truncated/rejected, while still bounding a
    /// flooded pipe. Floors at [`DEFAULT_MAX_STDOUT`] so a tiny configured file
    /// cap can never shrink the bound below normal ref-listing output.
    pub fn with_max_stdout(mut self, max_file_bytes: u64) -> Self {
        let want = usize::try_from(max_file_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(8 * 1024 * 1024);
        self.max_stdout = want.max(DEFAULT_MAX_STDOUT);
        self
    }

    /// Attach an out-of-band push credential and isolate untrusted config for
    /// authenticated remote operations. A `None` credential leaves the runner
    /// anonymous (unchanged).
    pub fn with_credential(
        mut self,
        cred: Option<crate::provision::GitCredential>,
        isolate_config: bool,
    ) -> Self {
        self.cred = cred;
        self.isolate_config = isolate_config;
        self
    }

    /// Run `git <args>` with no extra env and no stdin.
    pub async fn run(&self, args: &[&str]) -> GitOut {
        self.run_in(args, &[], None).await
    }

    /// Run `git <args>` with `env` overrides and optional stdin `input`.
    pub async fn run_in(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        input: Option<&[u8]>,
    ) -> GitOut {
        // Resolve `git` to a trusted ABSOLUTE path on a sanitized PATH, exactly as
        // the provisioning launcher does (provision.rs): the child `fchdir`s into
        // the agent-controlled checkout, so a bare `git` lookup (empty/`.`/relative
        // PATH entry) could otherwise resolve an agent-planted binary that then
        // receives this run's credential-file location. The sanitized PATH also
        // constrains git's own transport/credential-helper subprocesses.
        let (git_exe, safe_path) = match crate::provision::trusted_cli("git") {
            Ok(v) => v,
            Err(e) => {
                return GitOut {
                    status: None,
                    stdout: String::new(),
                    stdout_bytes: Vec::new(),
                    stderr: format!("git resolution failed: {e}"),
                }
            }
        };
        let mut cmd = Command::new(git_exe);
        cmd.env("PATH", &safe_path);
        // A dedicated `--git-dir` (the orphan-GC scratch repo) redirects every
        // operation away from the pinned checkout, so reaping that checkout
        // mid-sweep cannot fail the sweep. It must precede the subcommand args.
        if let Some(gd) = &self.git_dir {
            cmd.arg("--git-dir").arg(gd);
        }
        cmd.arg("-c").arg("credential.helper=");
        // Out-of-band credential (if any) must be configured with its `-c` flags
        // BEFORE the git subcommand args. The returned guard owns the 0600 secret
        // file and must stay alive until the child exits, so bind it for the whole
        // function.
        let _cred_guard = match &self.cred {
            Some(c) => match crate::provision::apply_git_credential(&mut cmd, c) {
                Ok(g) => Some(g),
                Err(e) => {
                    return GitOut {
                        status: None,
                        stdout: String::new(),
                        stdout_bytes: Vec::new(),
                        stderr: format!("credential setup failed: {e}"),
                    }
                }
            },
            None => None,
        };
        for a in args {
            cmd.arg(a);
        }
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        if self.isolate_config {
            cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
            cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
            cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        // Strip the daemon's engine-connection secrets (CAMUNDA_*/ZEEBE_*) from
        // every git child, matching provision.rs: git runs job-controlled remote
        // URLs plus remote/credential helpers, so a hostile repo config or helper
        // could otherwise read those secrets straight out of the inherited env.
        for k in crate::slot::SENSITIVE_DAEMON_ENV {
            cmd.env_remove(k);
        }
        // Strip git's environment-based config-injection channels
        // (GIT_CONFIG_COUNT/KEY_<n>/VALUE_<n>, …): git applies them ABOVE every
        // on-disk file, bypassing the GIT_CONFIG_GLOBAL/SYSTEM=/dev/null isolation,
        // so a tainted daemon environment could inject `url.*.insteadOf` config for
        // an authenticated checkpoint push/fetch.
        for k in crate::provision::GIT_CONFIG_INJECTION_ENV {
            cmd.env_remove(k);
        }
        for (k, _) in std::env::vars_os() {
            if k.to_str().is_some_and(|s| {
                s.starts_with("GIT_CONFIG_KEY_") || s.starts_with("GIT_CONFIG_VALUE_")
            }) {
                cmd.env_remove(&k);
            }
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        // Give the git child its own process group + parent-death signal so a hard
        // daemon crash (kill -9, which never runs `kill_on_drop`) tears the whole
        // git tree — transports, remote/credential helpers — down with the daemon
        // instead of leaving it mutating the checkout.
        #[cfg(unix)]
        cmd.process_group(0);
        #[cfg(unix)]
        crate::pdeath::arm(&mut cmd);
        if let Err(e) = self.cwd.apply(&mut cmd) {
            return GitOut {
                status: None,
                stdout: String::new(),
                stdout_bytes: Vec::new(),
                stderr: format!("cwd bind failed: {e}"),
            };
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return GitOut {
                    status: None,
                    stdout: String::new(),
                    stdout_bytes: Vec::new(),
                    stderr: format!("spawn failed: {e}"),
                }
            }
        };
        // Capture the spawn-time process-group identity so a timeout/cancel can
        // SIGKILL the WHOLE git tree (not just the leader `kill_on_drop` reaps):
        // SSH transports, remote helpers and filters git spawned share its group
        // and would otherwise keep running after teardown. The guard verifies the
        // group's identity, so it never signals a recycled pgid (issue #27).
        #[cfg(unix)]
        let gpid = child.id();
        #[cfg(unix)]
        if let Some(pid) = gpid {
            crate::pdeath::watch(pid);
        }
        #[cfg(unix)]
        let mut group_guard = crate::pdeath::GroupGuard::new(gpid);
        if let Some(mut si) = child.stdin.take() {
            if let Some(data) = input {
                let _ = si.write_all(data).await;
            }
            let _ = si.shutdown().await;
        }
        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();
        let max_stdout = self.max_stdout;
        let wait = async {
            // Drain BOTH pipes to EOF so git never blocks on a full buffer, but
            // retain only a bounded amount: unbounded `read_to_end` here let a
            // large restore diff or a noisy remote/helper grow the buffer without
            // limit and exhaust the long-lived daemon's memory. stdout fails
            // closed on overflow (its caller parses ref listings / blobs / patches
            // and must never act on a silently truncated capture); stderr keeps
            // only a short diagnostic tail.
            let read_out = async {
                match stdout_pipe.as_mut() {
                    Some(o) => crate::provision::drain_capped(o, max_stdout).await,
                    None => (Vec::new(), false),
                }
            };
            let read_err = async {
                match stderr_pipe.as_mut() {
                    Some(e) => {
                        crate::provision::drain_capped(e, crate::provision::GIT_STDERR_TAIL)
                            .await
                            .0
                    }
                    None => Vec::new(),
                }
            };
            let (status, out, err) = tokio::join!(child.wait(), read_out, read_err);
            (status, out, err)
        };
        match tokio::time::timeout(self.timeout, wait).await {
            Ok((status, (out, out_overflow), err)) => {
                // git finished within the timeout, but a helper it spawned can
                // outlive the leader while sharing its group. Tear the whole group
                // down before disarming, mirroring the provisioning path.
                #[cfg(unix)]
                {
                    crate::pdeath::terminate_group_and_reap(
                        &mut child,
                        group_guard.guard(),
                        Duration::from_secs(3),
                    )
                    .await;
                    group_guard.disarm();
                }
                // stdout exceeded its cap: leading bytes were DROPPED, so the
                // capture is a partial tail. Fail closed rather than let the
                // caller parse an incomplete ref listing / blob / patch as if it
                // were the whole stream.
                if out_overflow {
                    return GitOut {
                        status: None,
                        stdout: String::new(),
                        stdout_bytes: Vec::new(),
                        stderr: format!(
                            "git stdout exceeded the {max_stdout}-byte capture cap; \
                             refusing to act on a truncated result"
                        ),
                    };
                }
                let (code, stderr) = match status {
                    Ok(s) => (s.code(), String::from_utf8_lossy(&err).into_owned()),
                    Err(e) => (None, format!("wait failed: {e}")),
                };
                GitOut {
                    status: code,
                    stdout: String::from_utf8_lossy(&out).into_owned(),
                    stdout_bytes: out,
                    stderr,
                }
            }
            Err(_) => {
                // Timed out: SIGKILL the whole group (not just the leader) using
                // the spawn-time identity, then reap the leader (bounded) so the
                // long-lived daemon never accumulates zombie git leaders.
                #[cfg(unix)]
                {
                    group_guard.kill_group_if_ours();
                    group_guard.disarm();
                }
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                GitOut {
                    status: None,
                    stdout: String::new(),
                    stdout_bytes: Vec::new(),
                    stderr: "git timed out".to_string(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// Result of a snapshot attempt.
#[derive(Clone, Debug)]
pub enum Snapshot {
    /// Nothing worth a WIP ref, or a recoverable failure.
    Skipped { reason: String },
    /// A shadow commit was written.
    Committed {
        sha: String,
        tree: String,
        head: String,
        excluded: Vec<(String, String)>,
    },
}

const EMPTY_TREE_SHA1: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// Build a parented (or parentless, on an unborn HEAD) shadow commit of the
/// working tree through a temporary index, excluding deny-listed / oversized /
/// secret-bearing paths. Never touches the agent's index, HEAD, or branches.
#[allow(clippy::too_many_arguments)]
pub async fn snapshot_worktree(
    git: &GitRunner,
    base_sha: &str,
    base_ref_name: &str,
    run_id: &str,
    last_tree: Option<(&str, &str)>, // (tree, head)
    max_file_bytes: u64,
    secret_values: &[String],
    message: &str,
) -> Snapshot {
    let tmp = match make_temp_index_dir() {
        Some(d) => d,
        None => {
            return Snapshot::Skipped {
                reason: "could not create temp index dir".into(),
            }
        }
    };
    let _guard = TempDirGuard(tmp.clone());
    let index_path = tmp.join("index");
    let index_str = index_path.to_string_lossy().into_owned();
    let env: Vec<(&str, &str)> = vec![("GIT_INDEX_FILE", index_str.as_str())];

    let head = git.run(&["rev-parse", "--verify", "-q", "HEAD"]).await;
    let unborn = !head.ok();
    let head_sha = if unborn { String::new() } else { head.out() };
    let symbolic = git
        .run(&["symbolic-ref", "--short", "-q", "HEAD"])
        .await
        .out();
    let symbolic_branch = if symbolic.is_empty() {
        CHECKPOINT_DETACHED_MARKER.to_string()
    } else {
        symbolic
    };

    let base_ref = if unborn { EMPTY_TREE_SHA1 } else { "HEAD" };

    let r = git.run_in(&["read-tree", base_ref], &env, None).await;
    if !r.ok() {
        return Snapshot::Skipped {
            reason: format!("read-tree failed: {}", r.err_text()),
        };
    }
    let r = git.run_in(&["add", "-A"], &env, None).await;
    if !r.ok() {
        return Snapshot::Skipped {
            reason: format!("add failed: {}", r.err_text()),
        };
    }
    let changed = git
        .run_in(
            &[
                "diff",
                "--cached",
                "--name-only",
                "--no-renames",
                "-z",
                "--diff-filter=AMT",
                base_ref,
            ],
            &env,
            None,
        )
        .await;
    if !changed.ok() {
        return Snapshot::Skipped {
            reason: format!("diff failed: {}", changed.err_text()),
        };
    }
    let mut excluded: Vec<(String, String)> = Vec::new();
    for path in changed.stdout.split('\0').filter(|s| !s.is_empty()) {
        let mut why: Option<&str> = if is_denied_path(path) {
            Some("denied")
        } else {
            None
        };
        if why.is_none() {
            let spec = format!(":{path}");
            let size = git.run_in(&["cat-file", "-s", &spec], &env, None).await;
            if max_file_bytes > 0
                && size.ok()
                && size
                    .out()
                    .parse::<u64>()
                    .map(|n| n > max_file_bytes)
                    .unwrap_or(false)
            {
                why = Some("too-large");
            } else {
                let blob = git.run_in(&["cat-file", "blob", &spec], &env, None).await;
                if !blob.ok() {
                    why = Some("unreadable");
                } else if contains_secret(&blob.stdout, secret_values) {
                    why = Some("secret-content");
                }
            }
        }
        if let Some(w) = why {
            excluded.push((path.to_string(), w.to_string()));
        }
    }
    if !excluded.is_empty() {
        let mut args: Vec<&str> = vec!["reset", "-q", base_ref, "--"];
        for (p, _) in &excluded {
            args.push(p.as_str());
        }
        let r = git.run_in(&args, &env, None).await;
        if !r.ok() {
            return Snapshot::Skipped {
                reason: format!("exclude failed: {}", r.err_text()),
            };
        }
    }

    let tree = git.run_in(&["write-tree"], &env, None).await;
    if !tree.ok() {
        return Snapshot::Skipped {
            reason: format!("write-tree failed: {}", tree.err_text()),
        };
    }
    let tree_sha = tree.out();
    if let Some((lt, lh)) = last_tree {
        if tree_sha == lt && head_sha == lh {
            return Snapshot::Skipped {
                reason: "unchanged".into(),
            };
        }
    }
    let head_tree = if unborn {
        EMPTY_TREE_SHA1.to_string()
    } else {
        git.run(&["rev-parse", "HEAD^{tree}"]).await.out()
    };
    let clean = tree_sha == head_tree
        && if !base_sha.is_empty() {
            head_sha == base_sha
        } else {
            unborn
        };
    if clean {
        // A clean worktree still needs a fresh snapshot when we ALREADY pushed a
        // DIFFERENT checkpoint this session: an earlier interval may have snapshot
        // a WIP file the agent has since deleted, and simply skipping here leaves
        // the remote WIP ref holding that superseded content — which an
        // interrupted run would then wrongly restore. Publish the clean snapshot
        // (just the base tree) to supersede it. Only truly skip when nothing stale
        // needs replacing: no prior push this session, or the last push already
        // matches this clean tree (the common idle-interval no-op).
        let supersedes_prior = matches!(last_tree, Some((lt, _)) if lt != tree_sha);
        if !supersedes_prior {
            return Snapshot::Skipped {
                reason: "clean".into(),
            };
        }
    }

    let mut trailers: Vec<String> = Vec::new();
    if !base_sha.is_empty() {
        trailers.push(format!("{CHECKPOINT_BASE_TRAILER}: {base_sha}"));
    }
    if !base_ref_name.is_empty() && !base_ref_name.chars().any(|c| c.is_whitespace()) {
        trailers.push(format!("{CHECKPOINT_BASEREF_TRAILER}: {base_ref_name}"));
    }
    if !run_id.is_empty() {
        trailers.push(format!("{CHECKPOINT_RUN_TRAILER}: {run_id}"));
    }
    trailers.push(format!("{CHECKPOINT_BRANCH_TRAILER}: {symbolic_branch}"));
    let body = format!("{message}\n\n{}\n", trailers.join("\n"));

    let commit_env: Vec<(&str, &str)> = vec![
        ("GIT_AUTHOR_NAME", "nano-supervisor"),
        ("GIT_AUTHOR_EMAIL", "nano-supervisor@localhost"),
        ("GIT_COMMITTER_NAME", "nano-supervisor"),
        ("GIT_COMMITTER_EMAIL", "nano-supervisor@localhost"),
    ];
    let commit = if unborn {
        git.run_in(
            &["commit-tree", &tree_sha],
            &commit_env,
            Some(body.as_bytes()),
        )
        .await
    } else {
        git.run_in(
            &["commit-tree", &tree_sha, "-p", &head_sha],
            &commit_env,
            Some(body.as_bytes()),
        )
        .await
    };
    if !commit.ok() {
        return Snapshot::Skipped {
            reason: format!("commit-tree failed: {}", commit.err_text()),
        };
    }
    Snapshot::Committed {
        sha: commit.out(),
        tree: tree_sha,
        head: head_sha,
        excluded,
    }
}

fn make_temp_index_dir() -> Option<PathBuf> {
    let base = std::env::temp_dir();
    let unique = format!(
        "nano-ckpt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let dir = base.join(unique);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Push / fetch / delete
// ---------------------------------------------------------------------------

/// Outcome of a leased push / delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushResult {
    Ok,
    /// Lease mismatch — another writer moved the ref first; theirs is intact.
    StaleLease {
        error: String,
    },
    Error {
        error: String,
    },
}

/// Push `sha` to `ref`, leased against `expect_sha` (`""` = must not exist).
pub async fn push_checkpoint(
    git: &GitRunner,
    reference: &str,
    sha: &str,
    expect_sha: &str,
    remote: &str,
) -> PushResult {
    let lease = format!("--force-with-lease={reference}:{expect_sha}");
    let refspec = format!("{sha}:{reference}");
    let r = git
        .run(&["push", "--quiet", "--no-verify", &lease, remote, &refspec])
        .await;
    if r.ok() {
        return PushResult::Ok;
    }
    let text = format!("{}\n{}", r.stderr, r.stdout);
    if classify_push_failure(&text) == PushFailure::Lease {
        return PushResult::StaleLease {
            error: r.err_text(),
        };
    }
    PushResult::Error {
        error: r.err_text(),
    }
}

/// Observe the sha `ref` currently holds on `remote` (`""` when absent/unreadable).
pub async fn observe_remote_ref_sha(git: &GitRunner, reference: &str, remote: &str) -> String {
    let r = git.run(&["ls-remote", "--quiet", remote, reference]).await;
    if !r.ok() {
        return String::new();
    }
    let first = r.stdout.split_whitespace().next().unwrap_or("").to_string();
    if !first.is_empty()
        && first.len() >= 7
        && first.len() <= 64
        && first.bytes().all(|b| b.is_ascii_hexdigit())
    {
        first
    } else {
        String::new()
    }
}

/// Delete `ref`, leased against `expect_sha` (`None` = unconditional, `Some("")`
/// demands absence, `Some(sha)` only deletes while the ref still holds `sha`).
pub async fn delete_checkpoint_ref(
    git: &GitRunner,
    reference: &str,
    remote: &str,
    expect_sha: Option<&str>,
) -> PushResult {
    let lease;
    let refspec = format!(":{reference}");
    let r = match expect_sha {
        Some(e) => {
            lease = format!("--force-with-lease={reference}:{e}");
            git.run(&["push", "--quiet", "--no-verify", &lease, remote, &refspec])
                .await
        }
        None => {
            git.run(&["push", "--quiet", "--no-verify", remote, &refspec])
                .await
        }
    };
    if r.ok() {
        return PushResult::Ok;
    }
    let text = format!("{}{}", r.stderr, r.stdout).to_ascii_lowercase();
    if text.contains("remote ref does not exist") || text.contains("unable to delete") {
        return PushResult::Ok;
    }
    if expect_sha.is_some() && classify_push_failure(&text) == PushFailure::Lease {
        return PushResult::StaleLease {
            error: r.err_text(),
        };
    }
    PushResult::Error {
        error: r.err_text(),
    }
}
/// Delete a LOCAL ref (`git update-ref -d`), best-effort. Fetching a checkpoint
/// materialises a local copy of `refs/nano/...`; those local refs must be removed
/// after restore so finalization's stranded-work scan does not mistake the
/// snapshot commit they pin for unpublished agent work (and refuse to push).
pub async fn delete_local_ref(git: &GitRunner, reference: &str) {
    if reference.is_empty() {
        return;
    }
    let _ = git.run(&["update-ref", "-d", reference]).await;
}

/// A fetched checkpoint and the metadata read from its trailers.
#[derive(Clone, Debug, Default)]
pub struct FetchedCheckpoint {
    pub sha: String,
    pub parent: String,
    pub base: String,
    pub base_ref: String,
    pub branch: String,
}

/// Fetch `ref` and read its metadata, or `None` when the remote has no such ref.
pub async fn fetch_checkpoint(
    git: &GitRunner,
    reference: &str,
    remote: &str,
) -> anyhow::Result<Option<FetchedCheckpoint>> {
    let spec = format!("+{reference}:{reference}");
    let r = git
        .run(&["fetch", "--quiet", "--no-tags", remote, &spec])
        .await;
    if !r.ok() {
        let t = format!("{}{}", r.stderr, r.stdout).to_ascii_lowercase();
        if t.contains("couldn't find remote ref")
            || t.contains("no such ref")
            || t.contains("not our ref")
        {
            return Ok(None);
        }
        anyhow::bail!("fetch {reference} failed: {}", r.err_text());
    }
    let commitish = format!("{reference}^{{commit}}");
    let sha = git
        .run(&["rev-parse", "--verify", "-q", &commitish])
        .await
        .out();
    if sha.is_empty() {
        return Ok(None);
    }
    let parent_ref = format!("{sha}^1");
    let parent = git
        .run(&["rev-parse", "--verify", "-q", &parent_ref])
        .await
        .out();
    let msg = git.run(&["log", "-1", "--format=%B", &sha]).await.stdout;
    let base = trailer(&msg, CHECKPOINT_BASE_TRAILER);
    let base_ok = !base.is_empty()
        && base.len() >= 7
        && base.len() <= 64
        && base.bytes().all(|b| b.is_ascii_hexdigit());
    Ok(Some(FetchedCheckpoint {
        sha,
        parent,
        base: if base_ok { base } else { String::new() },
        base_ref: trailer(&msg, CHECKPOINT_BASEREF_TRAILER),
        branch: trailer(&msg, CHECKPOINT_BRANCH_TRAILER),
    }))
}

/// Read a single-token trailer value (`Name: value`) from a commit message.
fn trailer(msg: &str, name: &str) -> String {
    for line in msg.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix(name) {
            if let Some(rest) = rest.strip_prefix(':') {
                let v = rest.trim();
                if !v.is_empty() && !v.chars().any(|c| c.is_whitespace()) {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

/// Outcome of a restore attempt.
#[derive(Clone, Debug, Default)]
pub struct RestoreResult {
    pub restored: bool,
    pub reason: String,
    pub mode: String,
    pub commits_recovered: bool,
    pub branch_mismatch: bool,
}

/// Parse a generated per-run fallback branch `nano/agent-work/<base>-<uniq>`,
/// returning `(base, uniq)`.
///
/// Provisioning composes the fallback as `<base>-<uniq>` where the per-activation
/// `<uniq>` is EXACTLY `<rand>-<pid>-<nanos>-<seq>`: four dash-separated
/// components, none of which itself contains a dash (`rand` is hex, the rest are
/// decimal; see `slot::process_rand_token` and the activation suffix). Peel those
/// four components off the RIGHT; everything before them is the (possibly
/// dash-bearing) `<base>` segment.
///
/// The previous implementation split on only the LAST dash, which left
/// `<rand>-<pid>-<nanos>` glued onto the returned base. Two production-shaped
/// activations of the SAME base therefore never compared equal, so every default
/// fallback retry rejected its own checkpoint (the branch-rename recognition in
/// `restore_checkpoint` below could never fire).
fn fallback_branch_parts(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("nano/agent-work/")?;
    let mut it = rest.rsplitn(5, '-');
    let seq = it.next()?;
    let nanos = it.next()?;
    let pid = it.next()?;
    let rand = it.next()?;
    let base = it.next()?;
    let is_hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    let is_dec = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if base.is_empty() || !(is_hex(rand) && is_dec(pid) && is_dec(nanos) && is_dec(seq)) {
        return None;
    }
    Some((base.to_string(), format!("{rand}-{pid}-{nanos}-{seq}")))
}

/// Lay a fetched checkpoint down onto the fresh clone as UNCOMMITTED changes,
/// recovering unpushed local commits when the ancestry allows. HEAD stays on the
/// current branch. Refuses to publish off-branch/detached work onto a mismatched
/// working branch.
pub async fn restore_checkpoint(
    git: &GitRunner,
    checkpoint: &FetchedCheckpoint,
    expected_branch: Option<&str>,
    expected_branch_ephemeral: bool,
    expected_base_ref: &str,
) -> RestoreResult {
    let refuse = |reason: &str, mismatch: bool| RestoreResult {
        restored: false,
        reason: reason.to_string(),
        branch_mismatch: mismatch,
        ..Default::default()
    };
    if checkpoint.sha.is_empty() {
        return refuse("no-sha", false);
    }
    let head = git
        .run(&["rev-parse", "--verify", "-q", "HEAD"])
        .await
        .out();
    let status = git.run(&["status", "--porcelain"]).await;
    if !status.ok() || !status.out().is_empty() {
        return refuse("workspace-dirty", false);
    }

    let branch = &checkpoint.branch;
    let branch_mismatch = !branch.is_empty()
        && expected_branch.map(|e| !e.is_empty()).unwrap_or(false)
        && Some(branch.as_str()) != expected_branch;

    let fallback_rename = branch_mismatch && expected_branch_ephemeral && {
        // A benign per-activation rename: BOTH the snapshot's branch and this
        // run's expected branch are generated fallback branches
        // (`nano/agent-work/<base>-<uniq>`) cut from the SAME base. The `<uniq>`
        // suffix is minted fresh per activation, so recognition turns on the
        // shared base SEGMENT plus the shared configured base ref the snapshot
        // recorded — NOT on the activation-specific suffix (which differs by
        // design). `expected_base_ref` is the configured base and
        // `checkpoint.base_ref` is the base ref the snapshot recorded; requiring
        // a non-empty exact match keeps an unrelated base from cross-restoring.
        let snap = fallback_branch_parts(branch);
        let exp = expected_branch.and_then(fallback_branch_parts);
        match (snap, exp) {
            (Some((sb, _)), Some((eb, _))) => {
                sb == eb
                    && !expected_base_ref.is_empty()
                    && checkpoint.base_ref == expected_base_ref
            }
            _ => false,
        }
    };
    let branch_guard_refused = branch_mismatch && !fallback_rename;
    let where_str = || -> String {
        if branch == CHECKPOINT_DETACHED_MARKER {
            "a detached HEAD".to_string()
        } else {
            format!("'{branch}'")
        }
    };
    let mismatch_reason = || -> String {
        format!(
            "branch-mismatch (snapshot on {}, expected '{}')",
            where_str(),
            expected_branch.unwrap_or("")
        )
    };

    // Parentless (unborn) snapshot.
    if checkpoint.parent.is_empty() {
        if !head.is_empty() {
            return refuse("unborn snapshot but clone already has commits", false);
        }
        if branch_guard_refused {
            return refuse(&mismatch_reason(), true);
        }
        let r = git
            .run(&["read-tree", "-u", "--reset", &checkpoint.sha])
            .await;
        if !r.ok() {
            return refuse(&format!("read-tree failed: {}", r.err_text()), false);
        }
        let r = git.run(&["read-tree", "--empty"]).await;
        if !r.ok() {
            return refuse(&format!("unstage failed: {}", r.err_text()), false);
        }
        return RestoreResult {
            restored: true,
            mode: "unborn".into(),
            ..Default::default()
        };
    }

    // Parentful snapshot on an unborn clone.
    if head.is_empty() {
        if branch_guard_refused {
            return refuse(&mismatch_reason(), true);
        }
        let unborn_ref = git.run(&["symbolic-ref", "-q", "HEAD"]).await.out();
        let rollback = |reason: String| async move {
            if !unborn_ref.is_empty() {
                let _ = git.run(&["update-ref", "-d", &unborn_ref]).await;
            }
            let _ = git.run(&["read-tree", "--empty"]).await;
            let _ = git.run(&["clean", "-fdq"]).await;
            refuse(&reason, false)
        };
        let r = git
            .run(&["reset", "-q", "--hard", &checkpoint.parent])
            .await;
        if !r.ok() {
            return rollback(format!("reset failed: {}", r.err_text())).await;
        }
        let r = git
            .run(&["read-tree", "-u", "--reset", &checkpoint.sha])
            .await;
        if !r.ok() {
            return rollback(format!("read-tree failed: {}", r.err_text())).await;
        }
        let r = git.run(&["reset", "-q", &checkpoint.parent]).await;
        if !r.ok() {
            return rollback(format!("unstage failed: {}", r.err_text())).await;
        }
        return RestoreResult {
            restored: true,
            mode: "unborn-parentful".into(),
            commits_recovered: true,
            ..Default::default()
        };
    }

    // Fast-forward restore: HEAD is an ancestor of the snapshot's parent.
    let is_ancestor = !branch_mismatch
        && git
            .run(&["merge-base", "--is-ancestor", &head, &checkpoint.parent])
            .await
            .ok();
    if is_ancestor {
        let r = git
            .run(&["reset", "-q", "--hard", &checkpoint.parent])
            .await;
        if !r.ok() {
            return refuse(&format!("reset failed: {}", r.err_text()), false);
        }
        let r = git
            .run(&["read-tree", "-u", "--reset", &checkpoint.sha])
            .await;
        if !r.ok() {
            let _ = git.run(&["reset", "-q", "--hard", &head]).await;
            return refuse(&format!("read-tree failed: {}", r.err_text()), false);
        }
        let r = git.run(&["reset", "-q", &checkpoint.parent]).await;
        if !r.ok() {
            let _ = git.run(&["reset", "-q", "--hard", &head]).await;
            return refuse(&format!("unstage failed: {}", r.err_text()), false);
        }
        return RestoreResult {
            restored: true,
            mode: "fast-forward".into(),
            commits_recovered: head != checkpoint.parent,
            ..Default::default()
        };
    }

    if branch_mismatch && !fallback_rename {
        return refuse(&mismatch_reason(), true);
    }

    // Diverged: replay base→snapshot as a 3-way patch.
    let patch_base = if !checkpoint.base.is_empty() {
        checkpoint.base.clone()
    } else {
        let mk = git.run_in(&["mktree"], &[], Some(b"")).await;
        let out = mk.out();
        if !mk.ok() || !(out.len() >= 7 && out.bytes().all(|b| b.is_ascii_hexdigit())) {
            return refuse("diverged (no base trailer; empty-tree unavailable)", false);
        }
        out
    };
    let diff = git
        .run(&[
            "diff",
            "--binary",
            "--full-index",
            &patch_base,
            &checkpoint.sha,
        ])
        .await;
    if !diff.ok() {
        return refuse(&format!("diff failed: {}", diff.err_text()), false);
    }
    if diff.stdout_bytes().is_empty() {
        return refuse("empty diff", false);
    }
    // Feed git apply the RAW diff bytes, not the lossy UTF-8 decode: a
    // `--binary` diff can carry non-UTF-8 hunk content (e.g. Latin-1 without NUL
    // bytes), and the lossy decode would replace those bytes and corrupt the
    // patch before it ever reaches the worktree.
    let apply = git
        .run_in(
            &["apply", "--3way", "--whitespace=nowarn"],
            &[],
            Some(diff.stdout_bytes()),
        )
        .await;
    // Detect apply failure by EXIT STATUS, never by diagnostic text: a clean
    // `--3way` apply prints `Applied patch to 'conflict.rs' cleanly.` — a
    // substring match on "conflict" would misread that filename as a conflict
    // and reset away work that applied cleanly.
    if !apply.ok() {
        let _ = git.run(&["reset", "-q", "--hard", &head]).await;
        let _ = git.run(&["clean", "-fdq"]).await;
        return refuse(
            &format!("patch did not apply cleanly: {}", apply.err_text()),
            false,
        );
    }
    let _ = git.run(&["reset", "-q"]).await;
    RestoreResult {
        restored: true,
        mode: if checkpoint.base.is_empty() {
            "patch-empty-base".into()
        } else {
            "patch".into()
        },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Orphan GC sweep
// ---------------------------------------------------------------------------

/// A ref the sweep decided to reclaim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deletion {
    pub reference: String,
    pub sha: String,
    pub why: String,
}

/// Result of one sweep.
#[derive(Clone, Debug, Default)]
pub struct SweepResult {
    pub scanned: usize,
    pub deleted: Vec<Deletion>,
    pub error: Option<String>,
}

/// Select a bounded, ROTATING window of at most `batch` entries from `entries`,
/// keyed off `now_ms` so successive sweeps cover different refs. Entries are
/// sorted by ref name for a deterministic order, then a `batch`-sized window
/// starting at `now_ms % len` is taken (wrapping), so every ref is eventually
/// considered instead of being starved behind a stable prefix. Returns all
/// entries unchanged when the set already fits in `batch`.
fn rotating_batch(
    mut entries: Vec<(String, String)>,
    batch: usize,
    now_ms: u64,
) -> Vec<(String, String)> {
    let batch = batch.max(1);
    if entries.len() <= batch {
        return entries;
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let total = entries.len();
    let offset = (now_ms as usize) % total;
    (0..batch)
        .map(|k| entries[(offset + k) % total].clone())
        .collect()
}

/// Reclaim stale / orphaned nano refs across both swept namespaces. A ref is
/// reclaimed when it ages past the TTL, OR — past a grace window — when the
/// `probe` reports it an orphan (its element terminal AND its process finished).
/// A ref whose process is still ACTIVE (an SLA-cancelled escalation pending a
/// human) is SPARED until the TTL backstop.
#[allow(clippy::too_many_arguments)]
pub async fn sweep_stale_checkpoints(
    git: &GitRunner,
    own_ref: Option<&str>,
    ttl_ms: u64,
    grace_ms: u64,
    probe: Option<&dyn OrphanProbe>,
    now_ms: u64,
    max_deletes: usize,
    max_lookups: usize,
    remote: &str,
) -> SweepResult {
    let prefixes = swept_ref_prefixes();
    let prefix_of =
        |r: &str| -> Option<&'static str> { prefixes.iter().copied().find(|p| r.starts_with(p)) };

    let mut ls_args: Vec<String> = vec!["ls-remote".into(), "--refs".into(), remote.into()];
    for p in prefixes {
        ls_args.push(format!("{p}*"));
    }
    let ls_refs: Vec<&str> = ls_args.iter().map(|s| s.as_str()).collect();
    let ls = git.run(&ls_refs).await;
    if !ls.ok() {
        return SweepResult {
            error: Some(ls.err_text()),
            ..Default::default()
        };
    }

    let mut entries: Vec<(String, String)> = Vec::new(); // (ref, sha)
    for line in ls.stdout.lines().filter(|l| !l.trim().is_empty()) {
        let mut it = line.split_whitespace();
        let sha = it.next().unwrap_or("").to_string();
        let reference = it.next().unwrap_or("").to_string();
        if reference.is_empty() || Some(reference.as_str()) == own_ref {
            continue;
        }
        if prefix_of(&reference).is_some() {
            entries.push((reference, sha));
        }
    }
    if entries.is_empty() {
        return SweepResult::default();
    }

    // Bound the EXPENSIVE part of the sweep. Every selected ref is fetched (one
    // refspec apiece) and then has its history/timestamp read and possibly
    // cleaned up, so an unbounded `entries` would grow fetch argv and cleanup
    // work with the TOTAL accumulated ref count — eventually exceeding the
    // command-line argument limit and consuming ever more disk/time. Select a
    // bounded, ROTATING batch here, BEFORE building the fetch refspecs, so each
    // sweep does O(batch) work and the rotating window ensures later refs are
    // eventually considered rather than being starved behind a stable prefix.
    entries = rotating_batch(entries, max_lookups.max(max_deletes), now_ms);

    let local = |r: &str| -> String {
        let suffix = r
            .strip_prefix(NANO_REF_ROOT)
            .map(|s| s.to_string())
            .unwrap_or_else(|| r.strip_prefix("refs/").unwrap_or(r).to_string());
        format!("refs/nano-gc/{suffix}")
    };
    let key_of = |r: &str| -> String {
        match prefix_of(r) {
            Some(p) => r[p.len()..].to_string(),
            None => r.to_string(),
        }
    };

    let mut fetch_args: Vec<String> = vec![
        "fetch".into(),
        "--quiet".into(),
        "--no-tags".into(),
        "--no-write-fetch-head".into(),
        remote.into(),
    ];
    for (r, _) in &entries {
        fetch_args.push(format!("+{r}:{}", local(r)));
    }
    let fetch_refs: Vec<&str> = fetch_args.iter().map(|s| s.as_str()).collect();
    let fetch = git.run(&fetch_refs).await;
    if !fetch.ok() {
        return SweepResult {
            error: Some(fetch.err_text()),
            ..Default::default()
        };
    }

    let scanned = entries.len();
    let mut doomed: Vec<Deletion> = Vec::new();
    let mut lookups = 0usize;
    for (reference, sha) in &entries {
        if doomed.len() >= max_deletes {
            break;
        }
        let lr = local(reference);
        let ct = git.run(&["log", "-1", "--format=%ct", &lr]).await.out();
        let at_ms = ct.parse::<u64>().map(|s| s * 1000).unwrap_or(0);
        if at_ms == 0 {
            continue;
        }
        let age = now_ms.saturating_sub(at_ms);
        if ttl_ms > 0 && age > ttl_ms {
            doomed.push(Deletion {
                reference: reference.clone(),
                sha: sha.clone(),
                why: "ttl".into(),
            });
            continue;
        }
        if let Some(p) = probe {
            if age > grace_ms && lookups < max_lookups {
                lookups += 1;
                if p.is_orphan(&key_of(reference)).await {
                    doomed.push(Deletion {
                        reference: reference.clone(),
                        sha: sha.clone(),
                        why: "element-terminal".into(),
                    });
                }
            }
        }
    }

    // Clean up local temp refs regardless of outcome.
    if doomed.is_empty() {
        for (r, _) in &entries {
            let _ = git.run(&["update-ref", "-d", &local(r)]).await;
        }
        return SweepResult {
            scanned,
            ..Default::default()
        };
    }

    let mut deleted: Vec<Deletion> = Vec::new();
    let mut last_error: Option<String> = None;
    for d in &doomed {
        match delete_checkpoint_ref(git, &d.reference, remote, Some(&d.sha)).await {
            PushResult::Ok => deleted.push(d.clone()),
            PushResult::StaleLease { error } | PushResult::Error { error } => {
                last_error = Some(error)
            }
        }
    }
    for (r, _) in &entries {
        let _ = git.run(&["update-ref", "-d", &local(r)]).await;
    }

    SweepResult {
        scanned,
        error: if deleted.is_empty() { last_error } else { None },
        deleted,
    }
}

// ---------------------------------------------------------------------------
// Restored-note for the agent prompt
// ---------------------------------------------------------------------------

/// The note appended to the agent prompt when a checkpoint was restored.
pub fn checkpoint_restored_note(info: &RestoreResult) -> String {
    if !info.restored {
        return String::new();
    }
    let recovered = if info.commits_recovered {
        "(its local commits were recovered too — they are on the current branch)."
    } else {
        "(on top of the current branch)."
    };
    [
        "",
        "---",
        "WORKSPACE RESTORED FROM A WIP CHECKPOINT: a previous attempt at this task was interrupted.",
        "Its in-progress working tree has been restored into this workspace as UNCOMMITTED changes",
        recovered,
        "Before doing anything else, run `git status` and `git diff` to see what was already done,",
        "then continue from there rather than redoing it. The restored state may include a",
        "partially written file if the interruption happened mid-edit — verify before relying on it.",
        "This supersedes any statement above that uncommitted work from the prior run was lost.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests;

pub mod integration;
