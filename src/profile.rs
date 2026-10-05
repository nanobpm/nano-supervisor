//! Resolve a c8ctl connection profile and turn it into SDK configuration.
//!
//! c8ctl keeps profiles in `<config>/c8ctl/profiles.json` (`{"profiles": [...]}`)
//! and the active profile in `<config>/c8ctl/session.json` (`activeProfile`).
//! `<config>` is `$XDG_CONFIG_HOME` or `~/.config` on Linux, and
//! `~/Library/Application Support` on macOS.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use camunda_orchestration_sdk::{CamundaClient, CamundaOptions};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub name: String,
    pub base_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub audience: Option<String>,
    pub o_auth_url: Option<String>,
    pub scope: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub default_tenant_id: Option<String>,
}

impl Profile {
    /// A copy carrying only the **non-secret connection identity** — `name`,
    /// `baseUrl`, and `defaultTenantId` — with every credential field cleared
    /// (`clientId`/`clientSecret`, the OAuth coordinates, and the basic-auth
    /// `username`/`password`).
    ///
    /// Issue #41: the worker seeds this into the agent's isolated c8ctl
    /// `profiles.json`. The agent runs as the **same OS user** as the daemon,
    /// so a `0600` file does not hide its contents from the agent — serializing
    /// the full profile would copy the daemon's engine `clientSecret` / basic
    /// auth `password` into an agent-readable file and bypass the credential
    /// boundary the launchers enforce elsewhere. The agent only needs to know
    /// *which engine* the job is pinned to, so only the connection identity is
    /// seeded; authenticated `c8` access, if ever required, must come from a
    /// deliberately scoped agent credential, never the daemon's.
    pub fn connection_identity(&self) -> Profile {
        Profile {
            name: self.name.clone(),
            base_url: self.base_url.clone(),
            default_tenant_id: self.default_tenant_id.clone(),
            ..Default::default()
        }
    }
}

#[derive(Deserialize)]
struct ProfilesFile {
    #[serde(default)]
    profiles: Vec<Profile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionFile {
    active_profile: Option<String>,
}

pub fn c8ctl_config_dir() -> Option<PathBuf> {
    // Issue #41: an explicit override wins first. The worker seeds every agent
    // with an isolated per-run `C8CTL_CONFIG_DIR` so an agent's
    // `c8 use profile` / `c8 profile add` lands inside its own run directory
    // and can never rewrite the operator's global c8ctl session — which every
    // supervisor/worker on the host would otherwise follow on its next start.
    if let Some(dir) = std::env::var_os("C8CTL_CONFIG_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME")?;
        return Some(PathBuf::from(home).join("Library/Application Support/c8ctl"));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("c8ctl"))
}

/// The name of c8ctl's currently active profile, if a session names one.
/// Compared against the pinned connection to detect drift (issue #41): an
/// agent's `c8 use profile` rewrites exactly this, so a mismatch after the
/// fact is the observable signal that the ambient session moved.
pub fn active_profile_name() -> Option<String> {
    let dir = c8ctl_config_dir()?;
    std::fs::read(dir.join("session.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<SessionFile>(&b).ok())
        .and_then(|s| s.active_profile)
}

/// Pick the profile named `wanted`, else the session's active profile.
/// Returns `None` when neither is set (the caller falls back to `CAMUNDA_*` env).
pub fn resolve(wanted: Option<&str>) -> Result<Option<Profile>> {
    resolve_with_base_override(wanted, None)
}

/// [`resolve`], plus an explicit base URL that beats the environment when the
/// connection comes from the `CAMUNDA_*` env (no profile). This is how an
/// env-only connection pin (issue #41) is ENFORCED rather than just recorded:
/// the pin's baseUrl fingerprint is passed here, so a later start whose
/// `CAMUNDA_REST_ADDRESS` drifted still builds its client for the PINNED
/// engine. A resolved profile always keeps its own `baseUrl` — the override
/// only ever applies to the env fallback.
pub fn resolve_with_base_override(
    wanted: Option<&str>,
    base_url_override: Option<&str>,
) -> Result<Option<Profile>> {
    let Some(dir) = c8ctl_config_dir() else {
        return Ok(None);
    };
    // An explicit engine address in the environment beats c8ctl's remembered
    // active profile (but not an explicit --profile). A pinned baseUrl counts
    // as such an address: the pin IS the recorded connection decision.
    let env_address = base_url_override.is_some()
        || ["CAMUNDA_REST_ADDRESS", "ZEEBE_REST_ADDRESS"]
            .iter()
            .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()));
    let name = match wanted {
        Some(n) => Some(n.to_string()),
        None if env_address => None,
        None => std::fs::read(dir.join("session.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<SessionFile>(&b).ok())
            .and_then(|s| s.active_profile),
    };
    let Some(name) = name else { return Ok(None) };
    let path = dir.join("profiles.json");
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let file: ProfilesFile =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    match file.profiles.into_iter().find(|p| p.name == name) {
        Some(p) => Ok(Some(p)),
        None => bail!("no c8ctl profile named {name:?} in {}", path.display()),
    }
}

/// Map a c8ctl profile onto the SDK's `CAMUNDA_*` configuration keys.
pub fn sdk_settings(p: &Profile) -> BTreeMap<&'static str, String> {
    let mut m = BTreeMap::new();
    if let Some(url) = &p.base_url {
        // c8ctl profiles may carry the `/v2` suffix; the SDK appends it itself.
        let url = url.trim_end_matches('/');
        let url = url.strip_suffix("/v2").unwrap_or(url);
        m.insert("CAMUNDA_REST_ADDRESS", url.to_string());
    }
    let oauth = p.client_id.is_some() && p.client_secret.is_some();
    let basic = p.username.is_some() && p.password.is_some();
    if oauth {
        m.insert("CAMUNDA_AUTH_STRATEGY", "OAUTH".into());
        let pairs = [
            ("CAMUNDA_CLIENT_ID", &p.client_id),
            ("CAMUNDA_CLIENT_SECRET", &p.client_secret),
            ("CAMUNDA_OAUTH_URL", &p.o_auth_url),
            ("CAMUNDA_TOKEN_AUDIENCE", &p.audience),
            ("CAMUNDA_OAUTH_SCOPE", &p.scope),
        ];
        for (k, v) in pairs {
            if let Some(v) = v {
                m.insert(k, v.clone());
            }
        }
    } else if basic {
        m.insert("CAMUNDA_AUTH_STRATEGY", "BASIC".into());
        m.insert(
            "CAMUNDA_BASIC_AUTH_USERNAME",
            p.username.clone().unwrap_or_default(),
        );
        m.insert(
            "CAMUNDA_BASIC_AUTH_PASSWORD",
            p.password.clone().unwrap_or_default(),
        );
    } else {
        m.insert("CAMUNDA_AUTH_STRATEGY", "NONE".into());
    }
    if let Some(t) = &p.default_tenant_id {
        m.insert("CAMUNDA_DEFAULT_TENANT_ID", t.clone());
    }
    m
}

/// Build an SDK client from the profile (if any) layered over the environment,
/// plus an explicit base URL applied only when the connection has no profile
/// of its own — the env-only connection pin's fingerprint (issue #41). Setting
/// `CAMUNDA_REST_ADDRESS` on the options beats the process environment, so a
/// drifted `CAMUNDA_*` env cannot retarget a pinned worker; a resolved
/// profile's own `baseUrl` still wins over the override.
pub fn client_with_base_override(
    profile: Option<&Profile>,
    base_url_override: Option<&str>,
) -> Result<CamundaClient> {
    let mut opts = CamundaOptions::new();
    if let Some(p) = profile {
        for (k, v) in sdk_settings(p) {
            opts = opts.with(k, v);
        }
    } else if let Some(url) = base_url_override {
        opts = opts.with("CAMUNDA_REST_ADDRESS", url.to_string());
    }
    CamundaClient::new(opts).map_err(|e| anyhow::anyhow!("creating engine client: {e}"))
}

/// The engine base URL a connection resolved to, normalized the same way
/// [`sdk_settings`] normalizes it for the SDK (trailing `/` and `/v2` stripped).
/// Used as the connection *fingerprint* in the pinned state (issue #41): the
/// supervisor records it next to the profile name so a later start can tell
/// "same profile name, different engine" apart from "same engine". With no
/// profile this is the ambient `CAMUNDA_REST_ADDRESS`/`ZEEBE_REST_ADDRESS`.
pub fn resolved_base_url(profile: Option<&Profile>) -> Option<String> {
    if let Some(p) = profile {
        if let Some(url) = &p.base_url {
            let url = url.trim_end_matches('/');
            let url = url.strip_suffix("/v2").unwrap_or(url);
            return Some(url.to_string());
        }
    }
    for key in ["CAMUNDA_REST_ADDRESS", "ZEEBE_REST_ADDRESS"] {
        if let Some(v) = std::env::var_os(key) {
            let v = v.to_string_lossy().trim().trim_end_matches('/').to_string();
            if !v.is_empty() {
                let v = v.strip_suffix("/v2").unwrap_or(&v).to_string();
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(json: &str) -> Profile {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn strips_v2_and_picks_basic() {
        let p = profile(
            r#"{"name":"local","baseUrl":"http://localhost:8080/v2/","username":"demo","password":"x"}"#,
        );
        let m = sdk_settings(&p);
        assert_eq!(m["CAMUNDA_REST_ADDRESS"], "http://localhost:8080");
        assert_eq!(m["CAMUNDA_AUTH_STRATEGY"], "BASIC");
        assert_eq!(m["CAMUNDA_BASIC_AUTH_USERNAME"], "demo");
    }

    #[test]
    fn oauth_wins_and_maps_fields() {
        let p = profile(
            r#"{"name":"saas","baseUrl":"https://x.camunda.io","clientId":"id","clientSecret":"s",
                "oAuthUrl":"https://login/oauth/token","audience":"zeebe.camunda.io","username":"u","password":"p",
                "defaultTenantId":"t1"}"#,
        );
        let m = sdk_settings(&p);
        assert_eq!(m["CAMUNDA_AUTH_STRATEGY"], "OAUTH");
        assert_eq!(m["CAMUNDA_OAUTH_URL"], "https://login/oauth/token");
        assert_eq!(m["CAMUNDA_TOKEN_AUDIENCE"], "zeebe.camunda.io");
        assert_eq!(m["CAMUNDA_DEFAULT_TENANT_ID"], "t1");
        assert!(!m.contains_key("CAMUNDA_BASIC_AUTH_USERNAME"));
    }

    #[test]
    fn no_credentials_means_none() {
        let p = profile(r#"{"name":"merlin","baseUrl":"http://192.168.0.21:8080"}"#);
        let m = sdk_settings(&p);
        assert_eq!(m["CAMUNDA_REST_ADDRESS"], "http://192.168.0.21:8080");
        assert_eq!(m["CAMUNDA_AUTH_STRATEGY"], "NONE");
    }

    /// Issue #41: the identity seeded into the agent's isolated c8ctl dir must
    /// carry ONLY non-secret connection identity. Serializing the stripped
    /// profile must not leak the daemon's engine `clientSecret`/`password` (or
    /// any other credential) into an agent-readable file.
    #[test]
    fn connection_identity_strips_every_credential() {
        let p = profile(
            r#"{"name":"saas","baseUrl":"https://x.camunda.io","clientId":"id","clientSecret":"SECRET",
                "oAuthUrl":"https://login/oauth/token","audience":"zeebe.camunda.io","scope":"sc",
                "username":"u","password":"PASSWORD","defaultTenantId":"t1"}"#,
        );
        let id = p.connection_identity();
        // Non-secret identity is preserved…
        assert_eq!(id.name, "saas");
        assert_eq!(id.base_url.as_deref(), Some("https://x.camunda.io"));
        assert_eq!(id.default_tenant_id.as_deref(), Some("t1"));
        // …and every credential field is cleared.
        assert!(id.client_id.is_none());
        assert!(id.client_secret.is_none());
        assert!(id.o_auth_url.is_none());
        assert!(id.audience.is_none());
        assert!(id.scope.is_none());
        assert!(id.username.is_none());
        assert!(id.password.is_none());
        // The serialized form (what the worker writes to profiles.json) leaks
        // no secret substring.
        let json = serde_json::to_string(&id).unwrap();
        assert!(!json.contains("SECRET"), "clientSecret leaked: {json}");
        assert!(!json.contains("PASSWORD"), "password leaked: {json}");
    }
}
