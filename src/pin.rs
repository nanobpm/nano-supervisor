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
    pub fn describe(&self) -> String {
        match (&self.profile, &self.base_url) {
            (Some(p), Some(u)) => format!("{p} ({u})"),
            (Some(p), None) => format!("{p} (no baseUrl recorded)"),
            (None, Some(u)) => format!("CAMUNDA_* env ({u})"),
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

/// Read the pinned connection, if `supervisor.json` exists and carries one.
/// A malformed file is treated as unpinned (and reported) rather than fatal:
/// the supervisor must still start, and the next successful start re-pins.
pub fn read(state_home: &Path) -> Option<ConnectionPin> {
    let path = state_file(state_home);
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice::<SupervisorState>(&bytes) {
        Ok(s) => s.connection,
        Err(e) => {
            log(&format!(
                "warning: {} is not valid JSON ({e}); ignoring it and re-pinning the connection",
                path.display()
            ));
            None
        }
    }
}

/// Persist the pin, preserving any other fields already in the file. The state
/// home is created owner-only if needed; the file is written `0600` because it
/// names the engine the fleet talks to.
fn write(state_home: &Path, pin: &ConnectionPin) -> Result<()> {
    std::fs::create_dir_all(state_home)
        .with_context(|| format!("creating state home {}", state_home.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(state_home, std::fs::Permissions::from_mode(0o700));
    }
    let path = state_file(state_home);
    let mut state: SupervisorState = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    state.connection = Some(pin.clone());
    let json = serde_json::to_string_pretty(&state).context("serializing supervisor.json")?;
    std::fs::write(&path, format!("{json}\n"))
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// The outcome of resolving the connection for this start.
pub struct PinDecision {
    /// The pin this start will run with (read from disk or just written).
    pub pin: ConnectionPin,
    /// The fully resolved profile for the pin, when it names one — already
    /// loaded once, so the caller does not re-resolve it.
    pub profile: Option<Profile>,
    /// True when this start *created* the pin (first start of this home).
    pub created: bool,
    /// The session's current active profile at resolve time, for drift
    /// warnings. `None` when no session names one.
    pub active_profile: Option<String>,
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
    let active_profile = profile::active_profile_name();
    let existing = read(state_home);

    // Choose the profile NAME this start connects with, then resolve it once.
    let (name, created) = match (explicit, &existing) {
        (Some(x), _) => (Some(x.to_string()), true),
        (None, Some(pin)) => (pin.profile.clone(), false),
        (None, None) => (active_profile.clone(), true),
    };
    let resolved = profile::resolve(name.as_deref())?;
    let base_url = profile::resolved_base_url(resolved.as_ref());
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
    })
}

/// The startup banner's drift warnings (issue #41, proposal 2). Two drift
/// signals, both loud:
///
/// * the pinned profile differs from the session's current active profile —
///   the classic `c8 use profile` retarget; the supervisor keeps following the
///   PIN, and says so;
/// * the pinned profile now resolves to a different baseUrl than the pin's
///   fingerprint — the profile itself was re-pointed under the same name.
pub fn warn_if_drifted(decision: &PinDecision) {
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
    let now_url = profile::resolved_base_url(decision.profile.as_ref());
    match (&decision.pin.base_url, &now_url) {
        (Some(then), Some(now)) if then != now => {
            log(&format!(
                "WARNING: the pinned profile resolves to {now} but the pin was taken against \
                 {then} — the profile's baseUrl changed under the same name; this supervisor \
                 connects to {now}"
            ));
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

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nano-pin-test-{}-{}",
            tag,
            std::process::id()
        ));
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
        let pin = read(&home).expect("pin read back");
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
    fn malformed_state_file_reads_as_unpinned() {
        let home = temp_home("malformed");
        std::fs::write(state_file(&home), b"not json").unwrap();
        assert!(read(&home).is_none());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn missing_state_file_reads_as_unpinned() {
        let home = temp_home("missing");
        assert!(read(&home).is_none());
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
}
