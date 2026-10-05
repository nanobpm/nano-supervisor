//! Pin the supervisor's engine connection in `supervisor.json` (issue #41).
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
//! `<state home>/supervisor.json`. Every later start of the same state home
//! reuses the pinned profile instead of re-reading the ambient session, so a
//! moved `activeProfile` can never silently retarget the fleet. A drift between
//! the pin and the current session is surfaced loudly on every startup banner
//! instead of being obeyed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::profile::{self, Profile};
use crate::runtime::log;

/// The pinned connection, persisted in `supervisor.json`.
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

/// The on-disk shape of `<state home>/supervisor.json`. Only the connection
/// pin is modeled here; the file is otherwise free-form so the Node
/// supervisor's own fields (socket path, pid, …) survive a round-trip.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SupervisorState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection: Option<ConnectionPin>,
    /// Everything else the file carries, preserved verbatim on rewrite.
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// Where the pin lives: `supervisor.json` directly under the c8ctl-nano state
/// home — the same file the Node supervisor records its socket path in, so
/// there is exactly one supervisor state file per home.
pub fn state_file(state_home: &Path) -> PathBuf {
    state_home.join("supervisor.json")
}

/// Read the pinned connection. `Ok(None)` means `supervisor.json` does not
/// exist — genuinely unpinned, so the next start resolves and pins. A file that
/// exists but is unreadable or malformed is a HARD ERROR ([`Err`]), never
/// silently treated as unpinned: a truncated or externally corrupted
/// `supervisor.json` would otherwise fall back to resolving the mutable ambient
/// profile and recreate the exact fleet-retargeting incident this pin exists to
/// prevent (issue #41). The operator must repair or deliberately delete the
/// file to re-pin.
pub fn read(state_home: &Path) -> Result<Option<ConnectionPin>> {
    Ok(read_state(state_home)?.and_then(|s| s.connection))
}

/// Read and parse `supervisor.json`, distinguishing "absent" (`Ok(None)`) from
/// "present but corrupt" ([`Err`]). Only a `NotFound` means unpinned; every
/// other read error and every parse error fails closed, so no corrupt state can
/// be mistaken for a clean, unpinned home.
fn read_state(state_home: &Path) -> Result<Option<SupervisorState>> {
    let path = state_file(state_home);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("reading {}", path.display()));
        }
    };
    let state = serde_json::from_slice::<SupervisorState>(&bytes).with_context(|| {
        format!(
            "{} exists but is not valid supervisor state JSON; refusing to start with a corrupt \
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
/// `supervisor.json`. A plain `std::fs::write` truncates the live file in place,
/// so a crash, cancellation, or short write could leave malformed JSON behind —
/// and because a corrupt pin deliberately fails closed (issue #41), that would
/// wedge every later worker start until manual repair. The rename is atomic, so
/// a concurrent reader sees either the old pin or the new one, never a torn
/// half-write. Permission-setting failures are propagated, not ignored.
fn write(state_home: &Path, pin: &ConnectionPin) -> Result<()> {
    std::fs::create_dir_all(state_home)
        .with_context(|| format!("creating state home {}", state_home.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state_home, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting state home {}", state_home.display()))?;
    }
    let path = state_file(state_home);
    // Preserve the Node supervisor's own fields on rewrite — but fail closed on
    // a corrupt existing file rather than silently discarding it (which would
    // drop those fields AND any pin). `read_state` already turned a `NotFound`
    // into `Ok(None)`, so a fresh home starts from the default.
    let mut state: SupervisorState = read_state(state_home)?.unwrap_or_default();
    state.connection = Some(pin.clone());
    let json = serde_json::to_string_pretty(&state).context("serializing supervisor.json")?;
    write_atomic(&path, format!("{json}\n").as_bytes())
}

/// Write `bytes` to `path` atomically and owner-only: create a `0600` temp file
/// in the same directory, flush + `fsync` it, then `rename` it over `path`. The
/// temp file is unlinked on any failure so a crash never leaves a stray
/// `*.tmp` beside the state file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().context("state file has no parent directory")?;
    // A unique temp name: pid + a process-local counter disambiguate concurrent
    // writers and repeated writes within one process (the cross-process pin
    // lock serializes pin writers anyway, but the state file is also rewritten
    // outside that lock by the Node supervisor's own updates, so never collide
    // on a fixed name). `create_new` would otherwise fail a second write that
    // reused a name a prior crash left behind.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("supervisor.json"),
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
        std::fs::rename(&tmp, path).with_context(|| {
            format!("renaming {} over {}", tmp.display(), path.display())
        })?;
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

/// An interprocess (advisory `flock`) lock serializing the pin's
/// read/resolve/write across every `work`/`daemon` process that shares a state
/// home. Without it, two concurrent first starts on a fresh home could both
/// read "no pin", resolve different profiles, and overwrite each other's
/// `supervisor.json` — then keep running connected to different engines, the
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
                    format!("opening the connection-pin lock in {}", state_home.display())
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
    let resolved = profile::resolve(name.as_deref())?;
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
    let pin = ConnectionPin {
        profile: resolved.as_ref().map(|p| p.name.clone()).or(name),
        base_url,
    };
    if created {
        write(state_home, &pin)?;
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
///   `CAMUNDA_REST_ADDRESS` — the env drifted after pinning; the worker keeps
///   connecting to the PINNED baseUrl (the fingerprint is enforced, not just
///   recorded) and warns.
pub fn warn_if_drifted(decision: &PinDecision) {
    // Every URL interpolated into a warning is redacted first: an engine URL
    // may embed HTTP(S) userinfo, and these lines land on stdout/journald.
    let redact = |u: &str| crate::slot::redact_url(u);
    if let (Some(pinned), Some(active)) = (&decision.pin.profile, &decision.active_profile) {
        if pinned != active {
            log(&format!(
                "WARNING: the pinned connection is profile {pinned:?} but c8ctl's active profile \
                 is now {active:?} — this supervisor keeps following the PIN; the active profile \
                 is IGNORED (an agent's `c8 use profile` cannot retarget this fleet). Restart with \
                 --profile to re-pin, or edit {}",
                state_file_display(decision)
            ));
        }
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
        // CURRENT baseUrl and warns).
        (Some(_), Some(then)) => {
            if let Some(now) = profile::resolved_base_url(decision.profile.as_ref()) {
                if then != now {
                    log(&format!(
                        "WARNING: the pinned profile resolves to {} but the pin was taken \
                         against {} — the profile's baseUrl changed under the same name; \
                         this supervisor connects to {}",
                        redact(&now),
                        redact(then),
                        redact(&now)
                    ));
                }
            }
        }
        // Env-only pin: the recorded fingerprint is compared against the
        // CURRENT environment, and the client build keeps following the PIN
        // (see `engine::connect`'s `pinned_base_url`).
        (None, Some(then)) => {
            if let Some(now) = profile::resolved_base_url(None) {
                if then != now {
                    log(&format!(
                        "WARNING: the CAMUNDA_* environment now points at {} but this \
                         supervisor's connection was pinned against {} — the env drifted \
                         after pinning; this supervisor keeps connecting to the PINNED engine \
                         {}. To re-pin an env-only connection, delete the pin in {} and restart \
                         with the intended CAMUNDA_* environment (an explicit --profile would \
                         select a named c8ctl profile instead of the changed environment)",
                        redact(&now),
                        redact(then),
                        redact(then),
                        state_file_display(decision)
                    ));
                }
            }
        }
        _ => {}
    }
}

/// Display path for the state file in warnings (the decision does not carry
/// the home, so recompute it for the message only).
fn state_file_display(_decision: &PinDecision) -> String {
    match crate::state::state_home() {
        Some(h) => state_file(&h).display().to_string(),
        None => "supervisor.json".to_string(),
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
    fn round_trip_preserves_foreign_fields() {
        let home = temp_home("roundtrip");
        std::fs::write(
            state_file(&home),
            r#"{"socket":"/tmp/x.sock","pid":1234,"connection":{"profile":"merlin","baseUrl":"http://m:8080"}}"#,
        )
        .unwrap();
        let pin = read(&home).expect("pin read ok").expect("pin present");
        assert_eq!(pin.profile.as_deref(), Some("merlin"));
        assert_eq!(pin.base_url.as_deref(), Some("http://m:8080"));
        // Rewriting the pin must not drop the Node supervisor's own fields.
        write(
            &home,
            &ConnectionPin {
                profile: Some("local".into()),
                base_url: Some("http://localhost:8080".into()),
            },
        )
        .unwrap();
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(state_file(&home)).unwrap()).unwrap();
        assert_eq!(raw["socket"], serde_json::json!("/tmp/x.sock"));
        assert_eq!(raw["pid"], serde_json::json!(1234));
        assert_eq!(raw["connection"]["profile"], serde_json::json!("local"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn malformed_state_file_is_a_hard_error_not_unpinned() {
        // Issue #41: a corrupt `supervisor.json` must FAIL CLOSED. Treating it
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
    /// leave a torn `supervisor.json` (which would then fail closed on every
    /// later start). The write goes through a temp file + rename, and the temp
    /// file is cleaned up.
    #[test]
    fn write_is_atomic_and_leaves_no_temp_file() {
        let home = temp_home("atomic");
        write(
            &home,
            &ConnectionPin {
                profile: Some("local".into()),
                base_url: Some("http://localhost:8080".into()),
            },
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
            let mode = std::fs::metadata(state_file(&home)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "supervisor.json must be 0600");
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
        let _cfg = EnvGuard::set("C8CTL_CONFIG_DIR", &c8ctl.to_string_lossy());
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
        assert_eq!(first.stored_base_url, None, "a fresh pin has no prior fingerprint");

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

    /// Issue #41, the env-only gap: an env pin's baseUrl fingerprint must
    /// survive a restart whose `CAMUNDA_REST_ADDRESS` drifted. Re-resolving the
    /// current env would silently rewrite the pin to the drifted engine and the
    /// drift warning could never fire — the pin would ratify the very retarget
    /// it exists to catch.
    #[test]
    fn env_pin_keeps_its_base_url_fingerprint_across_env_drift() {
        let _lock = ENV_LOCK.lock().unwrap();
        let home = temp_home("envdrift");
        // Isolate from the host's real c8ctl session: an ambient active
        // profile would be picked up as the pin's profile, and the test is
        // about the profile-LESS (env) path.
        let c8ctl = home.join("c8ctl-config");
        std::fs::create_dir_all(&c8ctl).unwrap();
        let _cfg = EnvGuard::set("C8CTL_CONFIG_DIR", &c8ctl.to_string_lossy());
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
}
