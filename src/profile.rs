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
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
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

/// Pick the profile named `wanted`, else the session's active profile.
/// Returns `None` when neither is set (the caller falls back to `CAMUNDA_*` env).
pub fn resolve(wanted: Option<&str>) -> Result<Option<Profile>> {
    let Some(dir) = c8ctl_config_dir() else {
        return Ok(None);
    };
    // An explicit engine address in the environment beats c8ctl's remembered
    // active profile (but not an explicit --profile).
    let env_address = ["CAMUNDA_REST_ADDRESS", "ZEEBE_REST_ADDRESS"]
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

/// Build an SDK client from the profile (if any) layered over the environment.
pub fn client(profile: Option<&Profile>) -> Result<CamundaClient> {
    let mut opts = CamundaOptions::new();
    if let Some(p) = profile {
        for (k, v) in sdk_settings(p) {
            opts = opts.with(k, v);
        }
    }
    CamundaClient::new(opts).map_err(|e| anyhow::anyhow!("creating engine client: {e}"))
}

/// Engine address and basic-auth credentials for the raw Nano job client:
/// the profile's settings, else the `CAMUNDA_*` environment, else localhost.
/// (OAuth is not supported on this path; the spike only needs none/basic.)
pub fn rest_address_and_basic(profile: Option<&Profile>) -> (String, Option<(String, String)>) {
    let settings = profile.map(sdk_settings).unwrap_or_default();
    let get = |k: &str| {
        settings
            .get(k)
            .cloned()
            .or_else(|| std::env::var(k).ok().filter(|v| !v.is_empty()))
    };
    let address = get("CAMUNDA_REST_ADDRESS")
        .or_else(|| get("ZEEBE_REST_ADDRESS"))
        .unwrap_or_else(|| "http://localhost:8080".into());
    let basic = match (
        get("CAMUNDA_BASIC_AUTH_USERNAME"),
        get("CAMUNDA_BASIC_AUTH_PASSWORD"),
    ) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };
    (address, basic)
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
}
