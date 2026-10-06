//! Pin the supervisor's engine connection in `connection.json` (issue #41).
//!
//! The failure this guards against: the supervisor and its workers used to
//! resolve their connection from c8ctl's **mutable active profile at the moment
//! each process started**. One agent's `c8 use profile local` rewrote the
//! operator's global `~/.config/c8ctl/session.json`, and the next supervisor
//! restart silently re-pointed the whole fleet at a stray test engine — which
//! then burned real agent tokens serving `probe-*`/`ct-*` test jobs while the
//! production engine had no workers.
//!
//! The fix has the supervisor resolve its connection **once** — from an
//! explicit `--profile`, else the active profile at that moment — and record
//! the choice (profile name plus the resolved baseUrl as a fingerprint) in
//! `<state home>/connection.json`. Every later start of the same state home
//! reuses the pinned profile instead of re-reading the ambient session, so a
//! moved `activeProfile` can never silently retarget the fleet. A drift between
//! the pin and the current session is surfaced loudly on every startup banner
//! instead of being obeyed.
//!
//! The pin has its **own dedicated file**, `connection.json`, owned solely by
//! this Rust supervisor — deliberately NOT the shared `supervisor.json` the
//! external Node supervisor (`c8ctl-plugin-nano`) rewrites on every worker
//! persist and deletes on stop. That Node writer does not merge foreign keys,
//! so a pin kept in `supervisor.json` would be clobbered on the next Node
//! persist and erased on the next Node stop — re-exposing the exact ambient
//! re-resolution incident this pin exists to prevent (issue #41). A private
//! file the Node supervisor never touches makes the pin durable regardless of
//! the Node side's state lifecycle, with no cross-repo coordination required.
//! `connection.json` is new to this feature, so there is no legacy pin in
//! `supervisor.json` to migrate: a home that has never pinned simply pins on
//! its next start.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::profile::{self, Profile};
use crate::runtime::log;

/// The pinned connection, persisted in `connection.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionPin {
    /// The c8ctl profile every worker of this supervisor connects with. `None`
    /// means "no c8ctl profile — the `CAMUNDA_*` environment" (the pin still
    /// records the baseUrl fingerprint so an env change is just as visible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The engine baseUrl the pin was taken against (normalized: no trailing
    /// `/`, no `/v2` suffix), as a fingerprint. A worker that resolves the
    /// pinned profile to a *different* baseUrl warns loudly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

impl ConnectionPin {
    /// `engine: <profile> (<baseUrl>)` for banners and status output.
    ///
    /// The baseUrl is run through [`crate::slot::redact_url`] first: an engine
    /// URL may embed HTTP(S) userinfo (`https://user:secret@host`), and this
    /// string is interpolated into startup banners and drift warnings that land
    /// on stdout/journald — logging it verbatim would leak the credential. The
    /// redaction is display-only; the un-redacted URL is retained in the pin
    /// for connection setup.
    pub fn describe(&self) -> String {
        let url = |u: &String| crate::slot::redact_url(u);
        match (&self.profile, &self.base_url) {
            (Some(p), Some(u)) => format!("{p} ({})", url(u)),
            (Some(p), None) => format!("{p} (no baseUrl recorded)"),
            (None, Some(u)) => format!("CAMUNDA_* env ({})", url(u)),
            (None, None) => "CAMUNDA_* env (no baseUrl recorded)".to_string(),
        }
    }
}

/// The on-disk shape of `<state home>/connection.json`. Only the connection
/// pin is modeled explicitly; any other keys are preserved verbatim on rewrite
/// so a field written by a NEWER supervisor binary is not dropped when an older
/// one on the same state home does a read-modify-write (forward compatibility).
/// This file is owned solely by this Rust supervisor — the external Node
/// supervisor never reads or writes it — so the preserved keys are future Rust
/// fields, not another process's state.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PinState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection: Option<ConnectionPin>,
    /// Everything else the file carries, preserved verbatim on rewrite.
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// Where the pin lives: `connection.json` directly under the c8ctl-nano state
/// home. This is a dedicated, Rust-owned file — deliberately separate from the
/// shared `supervisor.json` the external Node supervisor rewrites and deletes —
/// so the pin's durability never depends on the Node side's state lifecycle
/// (issue #41).
pub fn state_file(state_home: &Path) -> PathBuf {
    state_home.join("connection.json")
}

/// Read the pinned connection. `Ok(None)` means `connection.json` does not
/// exist — genuinely unpinned, so the next start resolves and pins. A file that
/// exists but is unreadable or malformed is a HARD ERROR ([`Err`]), never
/// silently treated as unpinned: a truncated or externally corrupted
/// `connection.json` would otherwise fall back to resolving the mutable ambient
/// profile and recreate the exact fleet-retargeting incident this pin exists to
/// prevent (issue #41). The operator must repair or deliberately delete the
/// file to re-pin.
pub fn read(state_home: &Path) -> Result<Option<ConnectionPin>> {
    Ok(read_state(state_home)?.and_then(|s| s.connection))
}

/// Read and parse `connection.json`, distinguishing "absent" (`Ok(None)`) from
/// "present but corrupt" ([`Err`]). Only a `NotFound` means unpinned; every
/// other read error and every parse error fails closed, so no corrupt state can
/// be mistaken for a clean, unpinned home.
fn read_state(state_home: &Path) -> Result<Option<PinState>> {
    let path = state_file(state_home);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("reading {}", path.display()));
        }
    };
    let state = serde_json::from_slice::<PinState>(&bytes).with_context(|| {
        format!(
            "{} exists but is not valid connection-pin JSON; refusing to start with a corrupt \
             connection pin (an unpinned fallback would re-resolve the mutable ambient profile \
             and could silently retarget the fleet — issue #41). Repair the file, or delete it \
             to deliberately re-pin",
            path.display()
        )
    })?;
    Ok(Some(state))
}

/// Persist the pin, preserving any other fields already in the file. The state
/// home is created owner-only if needed; the file is written `0600` because it
/// names the engine the fleet talks to.
///
/// The write is **atomic**: the new state goes to a `0600` temporary file in the
/// same directory, is flushed + `fsync`ed, then `rename(2)`d over
/// `connection.json`. A plain `std::fs::write` truncates the live file in place,
/// so a crash, cancellation, or short write could leave malformed JSON behind —
/// and because a corrupt pin deliberately fails closed (issue #41), that would
/// wedge every later worker start until manual repair. The rename is atomic, so
/// a concurrent reader sees either the old pin or the new one, never a torn
/// half-write. Permission-setting failures are propagated, not ignored.
///
/// The whole read-modify-write runs under `lock` (the home's [`PinLock`]). The
/// pin is merged into the file's other (forward-compat) keys, so the merge must
/// be serialized against every other pin writer on the home: without it, two
/// processes could each read the file, merge their pin into their own stale
/// copy, and the last rename would clobber the other's update. Because
/// `connection.json` is owned solely by this Rust supervisor — the external
/// Node supervisor never writes it — this advisory Rust-only lock serializes
/// EVERY writer of the file, so it fully removes the read-modify-write race
/// (unlike the old shared `supervisor.json`, which the Node side could still
/// rewrite outside any lock we hold).
fn write(state_home: &Path, pin: &ConnectionPin, lock: &PinLock) -> Result<()> {
    std::fs::create_dir_all(state_home)
        .with_context(|| format!("creating state home {}", state_home.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_home, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting state home {}", state_home.display()))?;
    }
    let path = state_file(state_home);
    // Preserve any forward-compat keys on rewrite — but fail closed on a corrupt
    // existing file rather than silently discarding it (which would drop those
    // keys AND any pin). `read_state` already turned a `NotFound` into
    // `Ok(None)`, so a fresh home starts from the default. This read and the
    // `write_atomic` below are one critical section under `lock`.
    let _ = lock; // held by the caller across this whole read-modify-write
    let mut state: PinState = read_state(state_home)?.unwrap_or_default();
    state.connection = Some(pin.clone());
    let json = serde_json::to_string_pretty(&state).context("serializing connection.json")?;
    write_atomic(&path, format!("{json}\n").as_bytes())
}

/// Write `bytes` to `path` atomically and owner-only: create a `0600` temp file
/// in the same directory, flush + `fsync` it, then `rename` it over `path`. The
/// temp file is unlinked on any failure so a crash never leaves a stray
/// `*.tmp` beside the state file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .context("state file has no parent directory")?;
    // A unique temp name: pid + a process-local counter disambiguate concurrent
    // writers and repeated writes within one process (the cross-process pin
    // lock serializes pin writers, but use a unique name anyway so a stale temp
    // left by a crashed process can never make `create_new` trip on a fixed
    // name). `create_new` would otherwise fail a second write that reused a
    // name a prior crash left behind.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("connection.json"),
        std::process::id(),
        seq
    ));
    // Remove any stale temp file of this exact name (e.g. left by a killed
    // process that got the same pid) so `create_new` below cannot trip on it.
    let _ = std::fs::remove_file(&tmp);
    let write_result = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("creating temporary state file {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing temporary state file {}", tmp.display()))?;
        // Flush + fsync so the renamed file is durable, not a torn page.
        f.sync_all()
            .with_context(|| format!("syncing temporary state file {}", tmp.display()))?;
        drop(f);
        std::fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} over {}", tmp.display(), path.display()))?;
        // Durability (issue #41): syncing the temp file makes its CONTENT
        // durable, but the rename itself only updates the containing
        // directory's entry — and that update can still be lost on a power
        // loss unless the DIRECTORY is fsynced too. On a first pin that could
        // make `connection.json` vanish and the next start would re-resolve
        // the mutable ambient profile. fsync the parent dir so the rename is
        // durable before reporting success (Unix only; elsewhere the rename is
        // the best available guarantee).
        //
        // This directory fsync is BEST-EFFORT: the pin is already written and
        // atomically renamed into place, so a failure here only weakens the
        // crash-durability of that rename — it does not corrupt or lose the
        // live file. Some platforms/filesystems reject `fsync` on a directory
        // descriptor (e.g. macOS can return `EINVAL`/`ENOTSUP` depending on the
        // filesystem), and propagating that would fail the whole pin write and
        // break startup over a non-fatal durability nicety. So warn and carry
        // on rather than failing closed on it.
        #[cfg(unix)]
        {
            sync_dir_best_effort(dir);
        }
        Ok(())
    })();
    if write_result.is_err() {
        // Never leave a stray temp file behind on failure.
        let _ = std::fs::remove_file(&tmp);
    }
    write_result?;
    // `create_new` + `mode(0o600)` already made the temp file owner-only, and
    // the rename preserves that. Re-assert it so a pre-existing `path` with
    // looser permissions (left by an older version) is tightened too — and
    // propagate a failure rather than ignoring it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }
    Ok(())
}

/// Best-effort fsync of the containing directory `dir` after the atomic rename.
///
/// Extracted from `write_atomic` so the swallowed-error path is testable: the
/// real directory fsync can fail on some platforms/filesystems (e.g. macOS can
/// reject `fsync` on a directory descriptor with `EINVAL`/`ENOTSUP`), and that
/// failure must NOT fail the pin write — the file is already written and
/// atomically renamed into place. Tests override this via [`SYNC_DIR_HOOK`] to
/// force an error and assert the write still succeeds.
#[cfg(unix)]
fn sync_dir_best_effort(dir: &Path) {
    let result = {
        #[cfg(test)]
        if let Some(hook) = SYNC_DIR_HOOK.with(|h| *h.borrow()) {
            hook(dir)
        } else {
            real_sync_dir(dir)
        }
        #[cfg(not(test))]
        real_sync_dir(dir)
    };
    if let Err(e) = result {
        log(&format!(
            "warning: could not fsync state directory {} ({e}); \
             the pin is written but its on-disk rename may be less \
             durable across a power loss",
            dir.display()
        ));
    }
}

/// The production directory fsync, kept separate so tests can bypass it.
#[cfg(unix)]
fn real_sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir).and_then(|d| d.sync_all())
}

// Test-only hook to force the directory fsync to fail (or otherwise observe
// it) so the swallowed-error path in `write_atomic` can be exercised without
// relying on a filesystem that actually rejects directory fsync.
#[cfg(all(unix, test))]
type SyncDirHook = fn(&Path) -> std::io::Result<()>;

#[cfg(all(unix, test))]
thread_local! {
    static SYNC_DIR_HOOK: std::cell::RefCell<Option<SyncDirHook>> =
        const { std::cell::RefCell::new(None) };
}

/// An interprocess (advisory `flock`) lock serializing the pin's
/// read/resolve/write across every `work`/`daemon` process that shares a state
/// home. Without it, two concurrent first starts on a fresh home could both
/// read "no pin", resolve different profiles, and overwrite each other's
/// `connection.json` — then keep running connected to different engines, the
/// exact split-fleet condition the pin exists to prevent (issue #41). The lock
/// is held from the first read to the final write, so exactly one process pins
/// and the rest follow the pin they read while holding it.
///
/// Unix-only: on non-Unix hosts there is no `flock`, so this is a best-effort
/// no-op (the race window remains, as it did before this hardening). The lock
/// file itself is never deleted — it is a stable inode every process agrees on;
/// the lock is released simply by dropping the file handle.
struct PinLock {
    #[cfg(unix)]
    _file: std::fs::File,
}

impl PinLock {
    fn acquire(state_home: &Path) -> Result<PinLock> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            std::fs::create_dir_all(state_home)
                .with_context(|| format!("creating state home {}", state_home.display()))?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                // The lock file is a pure lock token — its content is never
                // read or written, only the flock on its inode matters. State
                // the truncation intent explicitly (clippy::suspicious_open_options).
                .truncate(false)
                .open(state_home.join(".pin.lock"))
                .with_context(|| {
                    format!(
                        "opening the connection-pin lock in {}",
                        state_home.display()
                    )
                })?;
            // LOCK_EX blocks until every other holder releases; the fd's Drop
            // (or process exit) releases it, so a crash can never wedge the
            // home. This is an advisory lock — it serializes only the processes
            // that take it, which is every supervisor/worker start on the home.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "locking the connection-pin lock in {}",
                        state_home.display()
                    )
                });
            }
            Ok(PinLock { _file: file })
        }
        #[cfg(not(unix))]
        {
            let _ = state_home;
            Ok(PinLock {})
        }
    }
}

/// The outcome of resolving the connection for this start.
pub struct PinDecision {
    /// The pin this start will run with (read from disk or just written). Its
    /// `base_url` is the URL the client actually connects to: for an existing
    /// env-only pin it is the *stored* fingerprint (enforced), and for a
    /// profile pin / fresh pin it is the currently resolved URL.
    pub pin: ConnectionPin,
    /// The fully resolved profile for the pin, when it names one — already
    /// loaded once, so the caller does not re-resolve it.
    pub profile: Option<Profile>,
    /// True when this start *created* the pin (first start of this home).
    pub created: bool,
    /// The session's current active profile at resolve time, for drift
    /// warnings. `None` when no session names one.
    pub active_profile: Option<String>,
    /// The baseUrl fingerprint **stored on disk** in the pre-existing pin, when
    /// this start followed one (`created == false`). Kept separate from
    /// `pin.base_url` so the profile-URL drift check compares the *recorded*
    /// fingerprint against what the pinned profile resolves to NOW — for a
    /// profile pin `pin.base_url` is rebuilt from the profile's current value,
    /// so without this the check would compare the current URL with itself and
    /// a re-pointed profile (engine A → B under the same name) would warn about
    /// nothing.
    pub stored_base_url: Option<String>,
}

/// Does an engine base URL embed HTTP(S) userinfo (`user:pass@host`)? Such a
/// URL would carry a credential into the persisted pin, so the pin rejects it
/// (issue #41). The authority is everything between `://` and the first
/// `/`, `?` or `#`; a `@` there is userinfo. Scheme-relative or opaque strings
/// are treated as their own authority so a `user@host`-style value is caught.
fn base_url_has_userinfo(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    authority.contains('@')
}

/// Resolve the connection for this start, honouring and maintaining the pin:
///
/// * An explicit `--profile` (re)pins: the operator is deliberately choosing a
///   connection, so it is recorded and used.
/// * Otherwise an existing pin wins over the ambient session — this is the
///   whole point of issue #41: a moved `activeProfile` must not retarget the
///   fleet.
/// * With no pin and no explicit flag, the active profile (or `CAMUNDA_*` env)
///   is resolved once and pinned for every later start.
pub fn resolve_or_pin(state_home: &Path, explicit: Option<&str>) -> Result<PinDecision> {
    // Serialize the whole read/resolve/write across every `work`/`daemon`
    // process sharing this state home. Two concurrent first starts on a fresh
    // home could both observe "no pin", resolve different profiles, and
    // overwrite each other's state — then keep running connected to different
    // engines, precisely the split-fleet condition the pin exists to prevent
    // (issue #41). Hold an interprocess lock from the first read to the final
    // write so exactly one process pins and the rest follow the pin they read.
    let _pin_lock = PinLock::acquire(state_home)?;
    let active_profile = profile::active_profile_name();
    let existing = read(state_home)?;

    // Choose the profile NAME this start connects with, then resolve it once.
    let (name, created) = match (explicit, &existing) {
        (Some(x), _) => (Some(x.to_string()), true),
        (None, Some(pin)) => (pin.profile.clone(), false),
        (None, None) => (active_profile.clone(), true),
    };
    // Fail CLOSED on an existing pin that carries NO baseUrl fingerprint. A
    // structurally valid but empty state such as `{"connection":{"profile":null}}`
    // (or a profile pin whose `baseUrl` was dropped) would otherwise be followed
    // as a real pin: the env-only branch falls back to the ambient env/session
    // and a profile pin follows the profile's CURRENT url with no drift
    // comparison — either silently restores the exact retargeting the pin exists
    // to prevent (issue #41). An explicit `--profile` sets `created` (it repairs
    // the pin), so this never blocks the operator's deliberate re-pin.
    if !created {
        let has_fingerprint = existing
            .as_ref()
            .and_then(|p| p.base_url.as_deref())
            .is_some_and(|u| !u.trim().is_empty());
        if !has_fingerprint {
            anyhow::bail!(
                "the pinned connection in connection.json has no recorded engine \
                 baseUrl fingerprint, so it cannot be enforced and would fall back \
                 to the ambient connection — silently retargetable. Setting an \
                 engine address alone will NOT repair this pin (this check runs \
                 before the environment is consulted): delete/reset the pin in \
                 connection.json first, or re-pin with --profile (issue #41)."
            );
        }
    }
    // An existing ENV-ONLY pin (`profile: None`) must stay env-only: `name` is
    // `None` here, and if `CAMUNDA_REST_ADDRESS` was later removed,
    // `profile::resolve(None)` would fall through to the session's active
    // profile and silently retarget the fleet onto it — the exact incident the
    // pin prevents (issue #41). Force the env fallback (never the session) and
    // enforce the recorded baseUrl fingerprint over the (possibly drifted or
    // absent) environment.
    let existing_env_only = !created && matches!(&existing, Some(p) if p.profile.is_none());
    let env_override: Option<String> = if existing_env_only {
        existing
            .as_ref()
            .and_then(|p| p.base_url.clone())
            .or_else(|| profile::resolved_base_url(None))
    } else {
        None
    };
    let resolved = if existing_env_only {
        profile::resolve_with_base_override(None, env_override.as_deref())?
    } else {
        profile::resolve(name.as_deref())?
    };
    let mut base_url = profile::resolved_base_url(resolved.as_ref());
    // The fingerprint recorded on disk by the pin this start followed (if any).
    // Tracked separately from `base_url` so the profile-URL drift check can
    // compare "what the pin recorded THEN" against "what the profile resolves
    // to NOW" (see `PinDecision::stored_base_url`).
    let mut stored_base_url: Option<String> = None;
    if !created {
        if let Some(pin) = &existing {
            stored_base_url = pin.base_url.clone();
            if resolved.is_none() {
                // An env-only pin has no profile to re-resolve, so its baseUrl
                // fingerprint is the RECORDED one: keep it stable across
                // restarts (and ENFORCE it as the connection URL). Re-reading
                // the current `CAMUNDA_REST_ADDRESS` here would rewrite the pin
                // to wherever the env drifted and the drift check below could
                // never fire — the pin would ratify the very retarget it exists
                // to catch.
                if pin.base_url.is_some() {
                    base_url = pin.base_url.clone();
                }
            }
            // A profile pin leaves `base_url` as the profile's CURRENT resolved
            // URL (the client connects there); the recorded fingerprint stays
            // in `stored_base_url` purely for the drift comparison.
        }
    }
    // Fail CLOSED when the connection cannot be faithfully and safely pinned
    // (issue #41). A pin that misrepresents, leaks, or cannot fingerprint the
    // connection is worse than refusing to start: it either retargets the
    // fleet silently or writes a credential a same-user agent can read.
    //
    // 1. A requested/pinned profile NAME that did not resolve (e.g. no c8ctl
    //    config directory is locatable because `C8CTL_NANO_HOME` is set but
    //    `HOME`/`XDG_CONFIG_HOME` is not) would otherwise be recorded verbatim
    //    while the client connects from the ambient environment — the banner
    //    and pin would claim a profile that is not actually in effect.
    if resolved.is_none() {
        if let Some(wanted) = &name {
            anyhow::bail!(
                "cannot resolve c8ctl profile {wanted:?}: no c8ctl config directory \
                 was found (set HOME/XDG_CONFIG_HOME, or C8CTL_DATA_DIR). Refusing \
                 to start with an ambient connection masquerading as this profile \
                 (issue #41)."
            );
        }
    }
    // 2. An engine URL that embeds HTTP(S) userinfo (`user:pass@host`) would be
    //    persisted into `<state home>/connection.json` in cleartext. The agent
    //    runs as the same OS user and inherits the state-home context, so
    //    `0600`/`0700` does not stop it reading that secret, and display/seed
    //    redaction happens too late. Reject it and require dedicated auth
    //    settings rather than carrying credentials in the URL.
    if let Some(u) = &base_url {
        if base_url_has_userinfo(u) {
            anyhow::bail!(
                "engine base URL embeds userinfo credentials, which would be \
                 persisted to connection.json in cleartext and readable by \
                 same-user agents. Remove the `user:pass@` from the engine URL \
                 and supply authentication via a c8ctl profile or the \
                 CAMUNDA_* auth environment instead (issue #41)."
            );
        }
    }
    // 3. A first pin with no resolvable base URL would persist `connection: {}`
    //    — no fingerprint at all. The SDK then falls back to its ambient/default
    //    endpoint, and a later restart with a freshly set address silently
    //    follows it because there is nothing stored to restore or compare. That
    //    is a pinned home that is still retargetable without an explicit re-pin.
    //    Require a resolvable engine URL so the pin can record a fingerprint.
    //    `resolved_base_url` never yields an empty string, but guard against one
    //    defensively so a self-invalid `Some("")` pin is never written.
    if created && base_url.as_deref().is_none_or(|u| u.trim().is_empty()) {
        anyhow::bail!(
            "cannot pin the supervisor connection: no engine base URL could be \
             resolved from a c8ctl profile or CAMUNDA_REST_ADDRESS/\
             ZEEBE_REST_ADDRESS. Set an explicit engine address (or pass \
             --profile) so the pin records a fingerprint instead of leaving the \
             home retargetable (issue #41)."
        );
    }
    let pin = ConnectionPin {
        profile: resolved.as_ref().map(|p| p.name.clone()).or(name),
        base_url,
    };
    if created {
        write(state_home, &pin, &_pin_lock)?;
    }
    Ok(PinDecision {
        pin,
        profile: resolved,
        created,
        active_profile,
        stored_base_url,
    })
}

/// The startup banner's drift warnings (issue #41, proposal 2). Three drift
/// signals, all loud:
///
/// * the pinned profile differs from the session's current active profile —
///   the classic `c8 use profile` retarget; the supervisor keeps following the
///   PIN, and says so;
/// * the pinned profile now resolves to a different baseUrl than the pin's
///   fingerprint — the profile itself was re-pointed under the same name (the
///   worker connects to the profile's CURRENT baseUrl and warns);
/// * an env-only pin's recorded baseUrl differs from the CURRENT
///   `CAMUNDA_REST_ADDRESS`/`ZEEBE_REST_ADDRESS` — the env drifted after
///   pinning; the worker keeps
///   connecting to the PINNED baseUrl (the fingerprint is enforced, not just
///   recorded) and warns.
pub fn warn_if_drifted(decision: &PinDecision) {
    for warning in drift_warnings(decision) {
        log(&warning);
    }
}

/// The pure core of [`warn_if_drifted`]: compute the drift warnings for this
/// start without emitting them, so every branch is unit-testable. Every URL
/// interpolated into a warning is redacted first: an engine URL may embed
/// HTTP(S) userinfo, and these lines land on stdout/journald.
fn drift_warnings(decision: &PinDecision) -> Vec<String> {
    let redact = |u: &str| crate::slot::redact_url(u);
    let mut out = Vec::new();
    match (&decision.pin.profile, &decision.active_profile) {
        (Some(pinned), Some(active)) if pinned != active => {
            out.push(format!(
                "WARNING: the pinned connection is profile {pinned:?} but c8ctl's active profile \
                 is now {active:?} — this supervisor keeps following the PIN; the active profile \
                 is IGNORED (an agent's `c8 use profile` cannot retarget this fleet). Restart with \
                 --profile to re-pin, or edit {}",
                state_file_display(decision)
            ));
        }
        // A named pin whose session has NO active profile now (session.json was
        // deleted or `activeProfile` cleared) is drift too — the classic
        // retarget's sibling, symmetric with the env-only unset branch below —
        // and must warn as loudly as a *changed* active profile rather than be
        // silently swallowed by the `Some/Some`-only arm above. Only an
        // *existing* pin being followed can drift: a freshly created pin
        // (`created`) is being established from the current state now, so a
        // first `--profile` start with no session must not warn here.
        (Some(pinned), None) if !decision.created => {
            out.push(format!(
                "WARNING: the pinned connection is profile {pinned:?} but c8ctl now has NO active \
                 profile (session.json was removed or its activeProfile cleared) — this supervisor \
                 keeps following the PIN and connects to profile {pinned:?}; the unset session is \
                 IGNORED (clearing the active profile cannot retarget this fleet). Restart with \
                 --profile to re-pin, or edit {}",
                state_file_display(decision)
            ));
        }
        // An ENV-ONLY pin (`pin.profile` is None — pinned via
        // `CAMUNDA_REST_ADDRESS`/`ZEEBE_REST_ADDRESS`/`--base-url`, no c8ctl
        // profile) whose session has GAINED an active profile since pinning is
        // drift too — the mirror image of the `(Some, None)` unset case above,
        // and the exact fingerprint of an agent's `c8 use profile` creating an
        // operator session the fleet must keep ignoring. Without this arm the
        // `_ =>` below silently swallows it, so the promised session-drift
        // signal never fires on the env-only path. Only an *existing* pin being
        // followed can drift: a freshly created env pin (`created`) is being
        // established from the current state now, so it must not warn.
        (None, Some(active)) if !decision.created => {
            out.push(format!(
                "WARNING: the pinned connection is env-only (CAMUNDA_REST_ADDRESS/\
                 ZEEBE_REST_ADDRESS, no c8ctl profile) but c8ctl now has active profile \
                 {active:?} — this supervisor keeps following the PINNED engine URL; the newly \
                 active profile is IGNORED (an agent's `c8 use profile` cannot retarget this \
                 fleet). Restart with --profile to re-pin, or edit {}",
                state_file_display(decision)
            ));
        }
        _ => {}
    }
    // The baseUrl drift check compares the fingerprint recorded on disk THEN
    // (`stored_base_url`) against what the connection resolves to NOW — never
    // `pin.base_url` against itself. For a profile pin `pin.base_url` was
    // rebuilt from the profile's current value, so comparing it to `now` would
    // always be equal and a re-pointed profile (engine A → B under one name)
    // would warn about nothing; the stored fingerprint is the honest "then".
    let then = if decision.created {
        // A freshly created pin has no prior fingerprint to drift from.
        None
    } else {
        decision.stored_base_url.as_deref()
    };
    match (&decision.pin.profile, then) {
        // Profile pin: the recorded fingerprint is compared against what the
        // pinned profile resolves to NOW (the client connects to the profile's
        // CURRENT baseUrl and warns). A REMOVED baseUrl is drift too — the
        // profile dropped its address under the same name — and is the more
        // dangerous case: with no explicit address the client falls back to the
        // ambient/SDK-default endpoint, so an unset current value warns as
        // loudly as a changed one (symmetric with the env-only branch below).
        (Some(_), Some(then)) => match profile::resolved_base_url(decision.profile.as_ref()) {
            Some(now) if now == then => {}
            Some(now) => {
                out.push(format!(
                    "WARNING: the pinned profile resolves to {} but the pin was taken \
                     against {} — the profile's baseUrl changed under the same name; \
                     this supervisor connects to {}",
                    redact(&now),
                    redact(then),
                    redact(&now)
                ));
            }
            None => {
                out.push(format!(
                    "WARNING: the pinned profile no longer resolves a baseUrl (it was \
                     removed under the same name) but the pin was taken against {} — \
                     with no explicit engine address the client falls back to the \
                     ambient/SDK-default endpoint, NOT the pinned engine. Restore the \
                     profile's baseUrl, or re-pin with --profile / an explicit \
                     CAMUNDA_REST_ADDRESS, or delete the pin in {}",
                    redact(then),
                    state_file_display(decision)
                ));
            }
        },
        // Env-only pin: the recorded fingerprint is compared against the
        // CURRENT environment, and the client build keeps following the PIN
        // (see `engine::connect`'s `pinned_base_url`). A REMOVED
        // `CAMUNDA_REST_ADDRESS` is drift too — the deployment environment was
        // cleared after pinning — so an unset current value warns as loudly as
        // a changed one (the worker still connects to the pinned URL either
        // way).
        (None, Some(then)) => match profile::resolved_base_url(None) {
            Some(now) if now == then => {}
            Some(now) => {
                out.push(format!(
                    "WARNING: the CAMUNDA_REST_ADDRESS/ZEEBE_REST_ADDRESS environment now \
                     points at {} but this supervisor's connection was pinned against {} — the \
                     env drifted after pinning; this supervisor keeps connecting to the PINNED \
                     engine {}. To re-pin an env-only connection, delete the pin in {} and \
                     restart with the intended CAMUNDA_REST_ADDRESS/ZEEBE_REST_ADDRESS \
                     environment (an explicit --profile would select a named c8ctl profile \
                     instead of the changed environment)",
                    redact(&now),
                    redact(then),
                    redact(then),
                    state_file_display(decision)
                ));
            }
            None => {
                out.push(format!(
                    "WARNING: the CAMUNDA_REST_ADDRESS/ZEEBE_REST_ADDRESS environment is now \
                     UNSET (the engine address was removed) but this supervisor's connection \
                     was pinned against {} — the env drifted after pinning; this supervisor \
                     keeps connecting to the PINNED engine {}. To re-pin an env-only \
                     connection, delete the pin in {} and restart with the intended \
                     CAMUNDA_REST_ADDRESS/ZEEBE_REST_ADDRESS environment (an explicit \
                     --profile would select a named c8ctl profile instead of the changed \
                     environment)",
                    redact(then),
                    redact(then),
                    state_file_display(decision)
                ));
            }
        },
        _ => {}
    }
    out
}

/// Display path for the state file in warnings (the decision does not carry
/// the home, so recompute it for the message only).
fn state_file_display(_decision: &PinDecision) -> String {
    match crate::state::state_home() {
        Some(h) => state_file(&h).display().to_string(),
        None => "connection.json".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `resolve_or_pin` reads the process `CAMUNDA_*` environment, and cargo
    /// runs tests in threads sharing that environment — so the env-pin test
    /// below mutates `CAMUNDA_REST_ADDRESS` under a mutex and restores it on
    /// drop. No other test in this binary may depend on those variables.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        saved: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> EnvGuard {
            let saved = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            EnvGuard { key, saved }
        }
        fn unset(key: &'static str) -> EnvGuard {
            let saved = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            EnvGuard { key, saved }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.saved {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn temp_home(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nano-pin-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_preserves_unknown_forward_compat_fields() {
        // `connection.json` is Rust-owned, but a rewrite must still preserve any
        // keys it does not model — e.g. a field written by a NEWER supervisor
        // binary — so an older binary on the same home does not drop it. (This
        // file is NOT shared with the Node supervisor; the preserved keys are
        // future Rust fields, not another process's state.)
        let home = temp_home("roundtrip");
        std::fs::write(
            state_file(&home),
            r#"{"futureField":"keep-me","schemaVersion":2,"connection":{"profile":"merlin","baseUrl":"http://m:8080"}}"#,
        )
        .unwrap();
        let pin = read(&home).expect("pin read ok").expect("pin present");
        assert_eq!(pin.profile.as_deref(), Some("merlin"));
        assert_eq!(pin.base_url.as_deref(), Some("http://m:8080"));
        // Rewriting the pin must not drop the unmodeled forward-compat fields.
        let lock = PinLock::acquire(&home).unwrap();
        write(
            &home,
            &ConnectionPin {
                profile: Some("local".into()),
                base_url: Some("http://localhost:8080".into()),
            },
            &lock,
        )
        .unwrap();
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(state_file(&home)).unwrap()).unwrap();
        assert_eq!(raw["futureField"], serde_json::json!("keep-me"));
        assert_eq!(raw["schemaVersion"], serde_json::json!(2));
        assert_eq!(raw["connection"]["profile"], serde_json::json!("local"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn malformed_state_file_is_a_hard_error_not_unpinned() {
        // Issue #41: a corrupt `connection.json` must FAIL CLOSED. Treating it
        // as unpinned would re-resolve the mutable ambient profile on the next
        // start and could silently retarget the fleet — the very incident the
        // pin prevents. Only a MISSING file means unpinned.
        let home = temp_home("malformed");
        std::fs::write(state_file(&home), b"not json").unwrap();
        let err = read(&home).expect_err("malformed state must be a hard error");
        assert!(
            err.to_string().contains("corrupt connection pin")
                || err.chain().any(|c| c.to_string().contains("corrupt")),
            "the error must explain the corrupt pin: {err:#}"
        );
        // `resolve_or_pin` must surface the same failure rather than re-pinning
        // the ambient profile over a corrupt file.
        assert!(
            resolve_or_pin(&home, None).is_err(),
            "resolve_or_pin must refuse to run over corrupt state"
        );
        // A truncated/garbage file must also never be silently overwritten by a
        // rewrite that drops the operator's own fields and pin.
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn missing_state_file_reads_as_unpinned() {
        let home = temp_home("missing");
        assert!(read(&home).expect("missing reads ok").is_none());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn write_atomic_succeeds_on_every_unix_including_macos() {
        // Regression (PR #46): the parent-directory fsync that follows the
        // rename is only a best-effort durability nicety. Some platforms
        // (notably macOS, depending on the filesystem) can reject `fsync` on a
        // directory descriptor with `EINVAL`/`ENOTSUP`; that must NOT fail the
        // pin write and break startup, since the file is already written and
        // atomically renamed into place. Writing — and re-writing — a pin must
        // succeed on the host running this test, macOS included.
        //
        // This covers the happy path; the swallowed-error path is covered by
        // `write_atomic_survives_a_failing_directory_fsync` below, which forces
        // the directory fsync to fail via the SYNC_DIR_HOOK seam.
        let home = temp_home("write-atomic-durable");
        let path = state_file(&home);
        write_atomic(&path, b"{\"first\":true}\n").expect("first write must succeed");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"first\":true}\n"
        );
        // A re-pin over the existing file must also succeed (exercises the same
        // durability path a second time).
        write_atomic(&path, b"{\"second\":true}\n").expect("re-write must succeed");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"second\":true}\n"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Red-first regression for PR #46: when the parent-directory fsync FAILS
    /// (as macOS can on some filesystems), `write_atomic` must still succeed —
    /// the pin is already written and atomically renamed, so a failed directory
    /// fsync is only a durability nicety, not a fatal error. This forces the
    /// error through the SYNC_DIR_HOOK seam so it is genuinely red-before /
    /// green-after (unlike the happy-path test above, which passes on any host
    /// whose directory fsync succeeds).
    #[cfg(unix)]
    #[test]
    fn write_atomic_survives_a_failing_directory_fsync() {
        fn fail_sync(_dir: &Path) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "EINVAL: fsync not supported on directory (simulated macOS)",
            ))
        }
        SYNC_DIR_HOOK.with(|h| *h.borrow_mut() = Some(fail_sync));
        // Ensure the hook is cleared even if the test panics.
        struct HookGuard;
        impl Drop for HookGuard {
            fn drop(&mut self) {
                SYNC_DIR_HOOK.with(|h| *h.borrow_mut() = None);
            }
        }
        let _guard = HookGuard;

        let home = temp_home("write-atomic-dirfsync-fails");
        let path = state_file(&home);
        // The write must SUCCEED despite the directory fsync failing.
        write_atomic(&path, b"{\"pinned\":true}\n")
            .expect("write must succeed even when the directory fsync fails");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"pinned\":true}\n"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn describe_covers_profile_and_env_pins() {
        assert_eq!(
            ConnectionPin {
                profile: Some("merlin".into()),
                base_url: Some("http://m:8080".into()),
            }
            .describe(),
            "merlin (http://m:8080)"
        );
        assert_eq!(
            ConnectionPin {
                profile: None,
                base_url: Some("http://localhost:8080".into()),
            }
            .describe(),
            "CAMUNDA_* env (http://localhost:8080)"
        );
    }

    /// Issue #41: `describe()` feeds startup banners and drift warnings that
    /// land on stdout/journald, so a baseUrl carrying HTTP(S) userinfo
    /// (`https://user:secret@host`) must be redacted — never logged verbatim.
    #[test]
    fn describe_redacts_url_userinfo() {
        let d = ConnectionPin {
            profile: Some("merlin".into()),
            base_url: Some("https://user:secret@m.example:8443".into()),
        }
        .describe();
        assert_eq!(d, "merlin (https://m.example:8443)");
        assert!(!d.contains("secret"), "describe leaked a credential: {d}");
        // …and the env-only form redacts too.
        let d = ConnectionPin {
            profile: None,
            base_url: Some("https://user:secret@m.example:8443".into()),
        }
        .describe();
        assert_eq!(d, "CAMUNDA_* env (https://m.example:8443)");
    }

    /// Issue #41: the pin is persisted atomically — a crash mid-write must never
    /// leave a torn `connection.json` (which would then fail closed on every
    /// later start). The write goes through a temp file + rename, and the temp
    /// file is cleaned up.
    #[test]
    fn write_is_atomic_and_leaves_no_temp_file() {
        let home = temp_home("atomic");
        let lock = PinLock::acquire(&home).unwrap();
        write(
            &home,
            &ConnectionPin {
                profile: Some("local".into()),
                base_url: Some("http://localhost:8080".into()),
            },
            &lock,
        )
        .unwrap();
        // The state file is valid JSON with the pin…
        let pin = read(&home).expect("read ok").expect("pin present");
        assert_eq!(pin.profile.as_deref(), Some("local"));
        // …and no stray temp file is left beside it.
        let entries: Vec<_> = std::fs::read_dir(&home)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.iter().all(|n| !n.ends_with(".tmp")),
            "no temp file may survive the atomic write: {entries:?}"
        );
        // …and on Unix the state file is owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(state_file(&home))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "connection.json must be 0600");
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Issue #41: for an existing PROFILE pin, the drift check must compare the
    /// fingerprint recorded on disk THEN against what the profile resolves to
    /// NOW. `pin.base_url` is rebuilt from the profile's current value, so the
    /// recorded fingerprint is carried separately in `stored_base_url` —
    /// otherwise a re-pointed profile (engine A → B under one name) would warn
    /// about nothing.
    #[test]
    fn profile_pin_preserves_stored_fingerprint_for_drift() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("profiledrift");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        // A profile that initially points at engine A…
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-a:8080"}]}"#,
        )
        .unwrap();
        std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();
        let first = resolve_or_pin(&home, None).expect("first start pins");
        assert!(first.created);
        assert_eq!(first.pin.base_url.as_deref(), Some("http://engine-a:8080"));
        assert_eq!(
            first.stored_base_url, None,
            "a fresh pin has no prior fingerprint"
        );

        // …then the profile is re-pointed at engine B under the SAME name.
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-b:8080"}]}"#,
        )
        .unwrap();
        let second = resolve_or_pin(&home, None).expect("second start follows the pin");
        assert!(!second.created);
        // The client connects to the profile's CURRENT URL (engine B)…
        assert_eq!(second.pin.base_url.as_deref(), Some("http://engine-b:8080"));
        // …but the recorded fingerprint (engine A) is preserved separately so
        // `warn_if_drifted` can compare A-vs-B instead of B-vs-B.
        assert_eq!(
            second.stored_base_url.as_deref(),
            Some("http://engine-a:8080"),
            "the stored fingerprint must survive so profile-URL drift is detectable"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Issue #41, the profile-URL-REMOVAL drift gap (review round 6): when a
    /// pinned profile drops its `baseUrl` under the same name, the profile
    /// still resolves (so the created-time fail-closed guard never fires) but
    /// `resolved_base_url(Some(profile))` is now `None` and the client falls
    /// back to the ambient/SDK-default endpoint. The symmetric env-only branch
    /// already warned on a removed address; the profile branch must too, rather
    /// than silently skipping the `None` case.
    #[test]
    fn profile_pin_warns_when_its_base_url_is_removed() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("profileurlremoved");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        // Ensure no ambient CAMUNDA_* address masks the removed profile URL —
        // otherwise `resolved_base_url(Some(profile))` would fall through to it
        // and the removal would read as a plain URL *change* instead.
        let _addr = EnvGuard::unset("CAMUNDA_REST_ADDRESS");
        let _zaddr = EnvGuard::unset("ZEEBE_REST_ADDRESS");
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-a:8080"}]}"#,
        )
        .unwrap();
        std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();
        let first = resolve_or_pin(&home, None).expect("first start pins");
        assert!(first.created);
        // No drift warning on the creating start.
        assert!(
            drift_warnings(&first).is_empty(),
            "a freshly created pin has nothing to drift from"
        );

        // The profile drops its baseUrl under the SAME name.
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin"}]}"#,
        )
        .unwrap();
        let second = resolve_or_pin(&home, None).expect("second start follows the pin");
        assert!(!second.created);
        assert_eq!(
            second.stored_base_url.as_deref(),
            Some("http://engine-a:8080"),
            "the recorded fingerprint must survive so removal is detectable"
        );
        let warnings = drift_warnings(&second);
        assert!(
            warnings.iter().any(|w| w.contains("no longer resolves a baseUrl")),
            "a removed profile baseUrl must warn about drift, not be silently skipped: {warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// "Previously missed" (review round 9): a profile/env URL that normalizes
    /// to the empty string (e.g. `/` or `/v2`) must NOT persist a self-invalid
    /// `Some("")` pin. The first start would write an unenforceable fingerprint
    /// that the next start's non-empty-fingerprint guard then rejects. Fail
    /// closed on creation instead.
    #[test]
    fn empty_normalized_base_url_fails_closed_instead_of_persisting() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _addr = EnvGuard::unset("CAMUNDA_REST_ADDRESS");
        let _zaddr = EnvGuard::unset("ZEEBE_REST_ADDRESS");
        for empty_url in ["/", "/v2", "/v2/", "   "] {
            let home = temp_home("emptybaseurl");
            let c8ctl = home.join("c8ctl-config");
            std::fs::create_dir_all(&c8ctl).unwrap();
            let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
            std::fs::write(
                c8ctl.join("profiles.json"),
                format!(r#"{{"profiles":[{{"name":"merlin","baseUrl":"{empty_url}"}}]}}"#),
            )
            .unwrap();
            std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();
            let err = resolve_or_pin(&home, Some("merlin"))
                .err()
                .unwrap_or_else(|| {
                    panic!("baseUrl {empty_url:?} normalizes to empty and must fail closed")
                });
            assert!(
                format!("{err:#}").contains("no engine base URL"),
                "baseUrl {empty_url:?}: unexpected error: {err:#}"
            );
            // Nothing self-invalid may have been persisted.
            assert!(
                read(&home).unwrap().is_none(),
                "baseUrl {empty_url:?} must not persist a pin"
            );
            let _ = std::fs::remove_dir_all(&home);
        }
    }
    /// structurally valid but empty `{"connection":{"profile":null}}`, or a
    /// profile pin whose URL was dropped) must FAIL CLOSED rather than fall back
    /// to the ambient env/session — otherwise it silently restores the
    /// retargeting the pin exists to prevent. An explicit `--profile` still
    /// repairs it.
    #[test]
    fn fingerprintless_pin_fails_closed_but_explicit_profile_repairs() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("nofingerprint");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-a:8080"}]}"#,
        )
        .unwrap();
        // A fingerprint-less existing pin, plus an ambient address it must NOT
        // silently adopt.
        std::fs::write(state_file(&home), r#"{"connection":{"profile":null}}"#).unwrap();
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://ambient:8080");

        let err = resolve_or_pin(&home, None)
            .err()
            .expect("a fingerprint-less pin must fail closed, never adopt the ambient env");
        assert!(
            format!("{err:#}").contains("no recorded engine"),
            "unexpected error: {err:#}"
        );

        // The operator's explicit --profile repairs the pin and records a
        // fingerprint.
        let repaired = resolve_or_pin(&home, Some("merlin")).expect("explicit --profile repairs");
        assert!(repaired.created);
        assert_eq!(
            repaired.pin.base_url.as_deref(),
            Some("http://engine-a:8080")
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A changed profile baseUrl (engine A → B under one name) warns, and the
    /// warning names the drift — the sibling of the removal case above.
    #[test]
    fn profile_pin_warns_when_its_base_url_changes() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("profileurlchanged");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-a:8080"}]}"#,
        )
        .unwrap();
        std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();
        let first = resolve_or_pin(&home, None).expect("first start pins");
        assert!(first.created);
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-b:8080"}]}"#,
        )
        .unwrap();
        let second = resolve_or_pin(&home, None).expect("second start follows the pin");
        let warnings = drift_warnings(&second);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("baseUrl changed under the same name")),
            "a changed profile baseUrl must warn: {warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A named pin whose session becomes UNSET (session.json deleted or its
    /// `activeProfile` cleared) is drift too: the `Some/None` sibling of the
    /// active-profile retarget, and it must warn rather than be silently
    /// swallowed by the `Some/Some`-only arm.
    #[test]
    fn named_pin_warns_when_active_profile_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("activeprofileunset");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-a:8080"}]}"#,
        )
        .unwrap();
        std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();
        let first = resolve_or_pin(&home, None).expect("first start pins");
        assert!(first.created);
        // Clear the active profile: session.json removed entirely.
        std::fs::remove_file(c8ctl.join("session.json")).unwrap();
        let second = resolve_or_pin(&home, None).expect("second start follows the pin");
        assert!(second.active_profile.is_none());
        let warnings = drift_warnings(&second);
        assert!(
            warnings.iter().any(|w| w.contains("NO active profile")),
            "an unset active profile under a named pin must warn: {warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The sibling of the case above: a FRESH named pin created with an
    /// explicit `--profile` while there is no session must NOT emit the
    /// unset-active-profile drift warning — a pin being established now has
    /// nothing to drift from.
    #[test]
    fn fresh_named_pin_without_session_does_not_warn_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("freshnamednosession");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-a:8080"}]}"#,
        )
        .unwrap();
        // No session.json at all: active_profile resolves to None.
        let first = resolve_or_pin(&home, Some("merlin")).expect("explicit --profile pins");
        assert!(first.created);
        assert!(first.active_profile.is_none());
        assert!(
            !drift_warnings(&first)
                .iter()
                .any(|w| w.contains("NO active profile")),
            "a freshly created pin must not warn about an unset active profile"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The env-only mirror of `named_pin_warns_when_active_profile_unset`: an
    /// existing ENV-only pin (no c8ctl profile) whose session has GAINED an
    /// active profile since pinning must warn — that new active profile is the
    /// exact evidence an agent ran `c8 use profile`, and the fleet keeps
    /// following the env URL and says so.
    #[test]
    fn env_pin_warns_when_active_profile_appears() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("envactiveprofileappears");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://engine-a:8080");
        // First start: no session, so the pin is env-only (profile None).
        let first = resolve_or_pin(&home, None).expect("first start pins env-only");
        assert!(first.created);
        assert_eq!(first.pin.profile, None);
        // A profile becomes active (an agent's `c8 use profile`, or the operator).
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-b:8080"}]}"#,
        )
        .unwrap();
        std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();
        let second = resolve_or_pin(&home, None).expect("second start follows the env pin");
        assert!(!second.created);
        assert_eq!(second.pin.profile, None);
        assert_eq!(second.active_profile.as_deref(), Some("merlin"));
        let warnings = drift_warnings(&second);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("env-only") && w.contains("merlin")),
            "an active profile appearing under an env-only pin must warn: {warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The sibling of the case above: a FRESH env-only pin created while a
    /// profile is already active must NOT warn — a pin being established now
    /// has nothing to drift from. (A created pin with an active profile is
    /// normally a NAMED pin, so this guards the `created` gate on the new arm.)
    #[test]
    fn fresh_env_pin_does_not_warn_on_first_start() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("freshenvpin");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://engine-a:8080");
        let first = resolve_or_pin(&home, None).expect("first start pins env-only");
        assert!(first.created);
        assert!(
            !drift_warnings(&first)
                .iter()
                .any(|w| w.contains("env-only")),
            "a freshly created env pin must not warn: {:?}",
            drift_warnings(&first)
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn env_pin_keeps_its_base_url_fingerprint_across_env_drift() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("envdrift");
        // Isolate from the host's real c8ctl session: an ambient active
        // profile would be picked up as the pin's profile, and the test is
        // about the profile-LESS (env) path.
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://engine-a:8080");
        let first = resolve_or_pin(&home, None).expect("first start pins");
        assert!(first.created);
        assert_eq!(first.pin.profile, None);
        assert_eq!(first.pin.base_url.as_deref(), Some("http://engine-a:8080"));

        // The environment drifts (a stray export, a systemd unit edit)…
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://engine-b:8080");
        let second = resolve_or_pin(&home, None).expect("second start follows the pin");
        assert!(!second.created);
        assert_eq!(second.pin.profile, None);
        // …but the pin's fingerprint is NOT rewritten to the drifted address…
        assert_eq!(
            second.pin.base_url.as_deref(),
            Some("http://engine-a:8080"),
            "the env pin must keep its recorded fingerprint across env drift"
        );
        // …and the on-disk pin is untouched either.
        let on_disk = read(&home).expect("read ok").expect("pin on disk");
        assert_eq!(on_disk.base_url.as_deref(), Some("http://engine-a:8080"));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Issue #41, the env-only retarget gap: an existing env-only pin
    /// (`profile: None`) must NOT fall through to the session's active profile
    /// when `CAMUNDA_REST_ADDRESS` is later removed. `profile::resolve(None)`
    /// would otherwise read `session.json` and silently retarget the fleet onto
    /// the ambient profile — the exact incident the pin prevents. The pin must
    /// keep enforcing its recorded baseUrl and stay profile-less.
    #[test]
    fn env_pin_is_not_retargeted_to_the_ambient_profile_when_env_is_removed() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("envretarget");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        // Pin against an env-only connection (no profile)…
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://engine-a:8080");
        let first = resolve_or_pin(&home, None).expect("first start pins env-only");
        assert!(first.created);
        assert_eq!(first.pin.profile, None);
        assert_eq!(first.pin.base_url.as_deref(), Some("http://engine-a:8080"));

        // …then the env var is REMOVED and an ambient active profile appears.
        // A naive `resolve(None)` would now fall through to the session and
        // retarget onto "merlin" — the pin must not.
        let _addr = EnvGuard::unset("CAMUNDA_REST_ADDRESS");
        std::fs::write(
            c8ctl.join("profiles.json"),
            r#"{"profiles":[{"name":"merlin","baseUrl":"http://engine-b:8080"}]}"#,
        )
        .unwrap();
        std::fs::write(c8ctl.join("session.json"), r#"{"activeProfile":"merlin"}"#).unwrap();

        let second = resolve_or_pin(&home, None).expect("second start follows the env pin");
        assert!(!second.created);
        // The pin stays env-only (no profile is picked up)…
        assert_eq!(
            second.pin.profile, None,
            "an env-only pin must not be retargeted to the ambient active profile"
        );
        assert!(second.profile.is_none(), "no profile may be resolved");
        // …and keeps enforcing the recorded engine-A fingerprint, not engine B.
        assert_eq!(second.pin.base_url.as_deref(), Some("http://engine-a:8080"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn base_url_userinfo_is_detected() {
        assert!(base_url_has_userinfo("http://user:pass@engine:8080"));
        assert!(base_url_has_userinfo("https://user:pass@engine:8080/v2"));
        assert!(base_url_has_userinfo("https://token@engine:8080"));
        assert!(base_url_has_userinfo("user:pass@engine:8080"));
        assert!(!base_url_has_userinfo("http://engine:8080"));
        assert!(!base_url_has_userinfo("https://engine:8080/v2"));
        // A `@` only in the path/query is not userinfo.
        assert!(!base_url_has_userinfo("http://engine:8080/a@b"));
        assert!(!base_url_has_userinfo("http://engine:8080/p?u=a@b"));
    }

    /// Issue #41, credential-in-pin: an engine URL that embeds `user:pass@host`
    /// must NOT be persisted to `connection.json`, where a same-user agent could
    /// read it. The pin fails closed and tells the operator to use dedicated
    /// auth settings instead.
    #[test]
    fn env_pin_rejects_userinfo_bearing_engine_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("userinfo");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://admin:s3cr3t@engine:8080");
        let err = match resolve_or_pin(&home, None) {
            Ok(_) => panic!("userinfo URL must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("userinfo"),
            "error must explain the credential leak: {err:#}"
        );
        // Nothing may have been persisted.
        assert!(
            read(&home).expect("read ok").is_none(),
            "a rejected pin must not write any state"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Issue #41, empty-fingerprint pin: a first start with neither a profile
    /// nor a `CAMUNDA_*` engine address must NOT persist `connection: {}` — an
    /// empty pin leaves the home retargetable by a later restart with a freshly
    /// set address, with no fingerprint to compare. The pin fails closed.
    #[test]
    fn initial_pin_without_resolvable_base_url_is_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("nobaseurl");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        let _a = EnvGuard::unset("CAMUNDA_REST_ADDRESS");
        let _z = EnvGuard::unset("ZEEBE_REST_ADDRESS");
        let err = match resolve_or_pin(&home, None) {
            Ok(_) => panic!("a fingerprint-less pin must be rejected"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("no engine base URL could be resolved"),
            "error must explain the missing fingerprint: {err:#}"
        );
        assert!(
            read(&home).expect("read ok").is_none(),
            "a rejected initial pin must not write any state"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Issue #41, unresolved-profile masquerade: when a profile NAME is
    /// requested/pinned but no c8ctl config directory can be located,
    /// `profile::resolve` returns `Ok(None)`. The pin must NOT record that name
    /// while silently connecting from the ambient environment — it fails closed.
    #[test]
    fn explicit_profile_that_cannot_be_resolved_is_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("ghostprofile");
        // Make `c8ctl_data_dir()` return None: no override and no HOME/XDG.
        let _cfg = EnvGuard::unset("C8CTL_DATA_DIR");
        let _home_env = EnvGuard::unset("HOME");
        let _xdg = EnvGuard::unset("XDG_CONFIG_HOME");
        let err = match resolve_or_pin(&home, Some("ghost")) {
            Ok(_) => panic!("an unresolvable named profile must be rejected"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("ghost") && msg.contains("config directory"),
            "error must name the unresolved profile and the cause: {err:#}"
        );
        assert!(
            read(&home).expect("read ok").is_none(),
            "a rejected profile pin must not write any state"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Issue #41, env-drift warning wording: the drifted address may come from
    /// `ZEEBE_REST_ADDRESS` (not only `CAMUNDA_REST_ADDRESS`), so the warning must
    /// name BOTH variables — a `CAMUNDA_*`-only message misleads a ZEEBE-only
    /// deployment. This pins the drift-via-ZEEBE path and the message wording.
    #[test]
    fn env_drift_via_zeebe_address_warns_and_names_both_variables() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("zeebedrift");
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_DATA_DIR", &c8ctl.to_string_lossy());
        // Pin against an env-only connection via CAMUNDA_REST_ADDRESS…
        let _addr = EnvGuard::set("CAMUNDA_REST_ADDRESS", "http://engine-a:8080");
        let _zaddr = EnvGuard::unset("ZEEBE_REST_ADDRESS");
        let first = resolve_or_pin(&home, None).expect("first start pins env-only");
        assert!(first.created);
        assert_eq!(first.pin.base_url.as_deref(), Some("http://engine-a:8080"));

        // …then the drift arrives via ZEEBE_REST_ADDRESS only (CAMUNDA_ removed).
        let _addr = EnvGuard::unset("CAMUNDA_REST_ADDRESS");
        let _zaddr = EnvGuard::set("ZEEBE_REST_ADDRESS", "http://engine-b:8080");
        let second = resolve_or_pin(&home, None).expect("second start follows the pin");
        let warnings = drift_warnings(&second);
        assert!(
            warnings.iter().any(|w| w.contains("points at")),
            "drift via ZEEBE_REST_ADDRESS must warn: {warnings:?}"
        );
        // The warning must name BOTH candidate source variables, not mislead a
        // ZEEBE-only deployment with a CAMUNDA_*-only message.
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("CAMUNDA_REST_ADDRESS") && w.contains("ZEEBE_REST_ADDRESS")),
            "the env-drift warning must name both CAMUNDA_REST_ADDRESS and ZEEBE_REST_ADDRESS: {warnings:?}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
