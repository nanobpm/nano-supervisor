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

/// Whether this profile carries OAuth client-credentials (which the raw Nano
/// job client cannot use — it only speaks none/basic).
pub fn has_oauth(p: &Profile) -> bool {
    p.client_id.is_some() && p.client_secret.is_some()
}

/// Whether the ambient `CAMUNDA_*`/`ZEEBE_*` environment configures OAuth. Used
/// when no c8ctl profile resolved and the connection comes from the environment
/// instead — the raw Nano client would otherwise send unauthenticated requests.
pub fn env_has_oauth() -> bool {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    let strategy_is_oauth = |k: &str| {
        std::env::var(k)
            .map(|s| s.eq_ignore_ascii_case("oauth"))
            .unwrap_or(false)
    };
    // Honour *both* the `CAMUNDA_*` and `ZEEBE_*` strategy variables: the SDK
    // accepts either, so a connection configured with `ZEEBE_AUTH_STRATEGY=OAUTH`
    // must be refused here too rather than falling through to unauthenticated
    // none/basic requests.
    if strategy_is_oauth("CAMUNDA_AUTH_STRATEGY") || strategy_is_oauth("ZEEBE_AUTH_STRATEGY") {
        return true;
    }
    (set("CAMUNDA_CLIENT_ID") && set("CAMUNDA_CLIENT_SECRET"))
        || (set("ZEEBE_CLIENT_ID") && set("ZEEBE_CLIENT_SECRET"))
}

/// Whether the ambient `CAMUNDA_*`/`ZEEBE_*` environment explicitly selects the
/// `NONE` auth strategy. The `CAMUNDA_*` variable wins when both are set (SDK
/// precedence); `None`/empty means "unspecified" (not `NONE`), so a bare set of
/// basic-auth vars still authenticates. Used by [`rest_address_and_basic`] to
/// honour an explicit `AUTH_STRATEGY=NONE` on the no-profile path, exactly as a
/// profile that resolves to `NONE` is honoured.
fn env_auth_strategy_is_none() -> bool {
    ["CAMUNDA_AUTH_STRATEGY", "ZEEBE_AUTH_STRATEGY"]
        .iter()
        .find_map(|k| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .is_some_and(|s| s.eq_ignore_ascii_case("none"))
}

/// Engine address and basic-auth credentials for the raw Nano job client.
///
/// The **address** comes from the profile's settings, else the
/// `CAMUNDA_*`/`ZEEBE_*` environment, else localhost, honouring the `ZEEBE_*`
/// aliases (the SDK accepts either prefix).
///
/// The **basic-auth** username/password honour the *selected* profile's auth
/// mode: when a profile is chosen they are taken from its resolved settings
/// only and never fall back to the ambient `CAMUNDA_*`/`ZEEBE_*` basic-auth
/// variables, so a `--profile` connection to a `NONE`/`OAUTH` engine cannot be
/// silently authenticated with unrelated environment credentials. Ambient
/// basic-auth is consulted only when no profile is selected — and even then
/// only when the ambient configuration does not explicitly select
/// `AUTH_STRATEGY=NONE`, so an environment that disables auth is honoured just
/// as a profile-derived `NONE` mode is. The `ZEEBE_*` aliases are honoured on
/// both paths.
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
    // Basic-auth credentials must honour the *selected* profile's auth mode.
    // When a profile is chosen we read basic-auth only from its own resolved
    // settings and never fall back to the ambient `CAMUNDA_*`/`ZEEBE_*`
    // basic-auth variables: otherwise a `--profile` connection whose profile
    // carries no basic credentials (e.g. it maps to `CAMUNDA_AUTH_STRATEGY=NONE`
    // or `OAUTH`) would be silently authenticated with unrelated environment
    // credentials, unlike the SDK path and the profile's explicit auth setting.
    // Ambient basic-auth is consulted only when no profile is selected — and
    // even then an explicit ambient `AUTH_STRATEGY=NONE` disables it, so an
    // environment that turns auth off is not silently re-authenticated by stray
    // basic-auth vars (the profile path honours its `NONE` mode the same way).
    let ambient_auth_disabled = profile.is_none() && env_auth_strategy_is_none();
    let basic_get = |k: &str| -> Option<String> {
        if profile.is_some() {
            settings.get(k).cloned()
        } else if ambient_auth_disabled {
            None
        } else {
            std::env::var(k).ok().filter(|v| !v.is_empty())
        }
    };
    let basic = match (
        basic_get("CAMUNDA_BASIC_AUTH_USERNAME").or_else(|| basic_get("ZEEBE_BASIC_AUTH_USERNAME")),
        basic_get("CAMUNDA_BASIC_AUTH_PASSWORD").or_else(|| basic_get("ZEEBE_BASIC_AUTH_PASSWORD")),
    ) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    };
    (address, basic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Serialize tests that mutate process-global environment variables. Rust
    /// runs unit tests in parallel threads that share one process environment,
    /// so without this lock the env-mutating auth tests race over the same
    /// `*_AUTH_*` / `*_BASIC_AUTH_*` keys and observe (or clobber) each other's
    /// writes. Every such test holds this lock for its whole body, so the
    /// save/restore each test already performs nests safely inside the
    /// serialized section. A panicking test poisons the mutex; we recover the
    /// guard (`into_inner`) so one failure does not cascade into the rest.
    fn env_guard() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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

    #[test]
    fn env_oauth_detected_via_zeebe_strategy() {
        // The raw Nano client speaks only none/basic, so OAuth configured through
        // *either* the CAMUNDA_* or ZEEBE_* strategy variable must be detected —
        // previously only CAMUNDA_AUTH_STRATEGY was checked, so a
        // ZEEBE_AUTH_STRATEGY=OAUTH connection slipped through unauthenticated.
        let _env = env_guard();
        let keys = [
            "CAMUNDA_AUTH_STRATEGY",
            "ZEEBE_AUTH_STRATEGY",
            "CAMUNDA_CLIENT_ID",
            "CAMUNDA_CLIENT_SECRET",
            "ZEEBE_CLIENT_ID",
            "ZEEBE_CLIENT_SECRET",
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        assert!(!env_has_oauth());
        std::env::set_var("ZEEBE_AUTH_STRATEGY", "OAUTH");
        assert!(env_has_oauth());
        // Restore prior environment so parallel tests are unaffected.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn nano_client_reads_zeebe_basic_auth_aliases() {
        // The raw Nano client honours the ZEEBE_* basic-auth aliases the same way
        // it honours ZEEBE_REST_ADDRESS: a ZEEBE_BASIC_AUTH_* setup must still send
        // an Authorization header instead of going out unauthenticated.
        let _env = env_guard();
        let keys = [
            "CAMUNDA_BASIC_AUTH_USERNAME",
            "CAMUNDA_BASIC_AUTH_PASSWORD",
            "ZEEBE_BASIC_AUTH_USERNAME",
            "ZEEBE_BASIC_AUTH_PASSWORD",
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        std::env::set_var("ZEEBE_BASIC_AUTH_USERNAME", "zuser");
        std::env::set_var("ZEEBE_BASIC_AUTH_PASSWORD", "zpass");
        let (_addr, basic) = rest_address_and_basic(None);
        assert_eq!(basic, Some(("zuser".to_string(), "zpass".to_string())));
        // Restore prior environment so parallel tests are unaffected.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn selected_profile_ignores_ambient_basic_auth() {
        // A selected profile must honour its own auth mode. A profile with no
        // credentials resolves to `CAMUNDA_AUTH_STRATEGY=NONE`, so the raw Nano
        // client must go out unauthenticated even when ambient CAMUNDA_*/ZEEBE_*
        // basic-auth variables are set — otherwise a `--profile` connection would
        // authenticate with unrelated environment credentials.
        let _env = env_guard();
        let keys = [
            "CAMUNDA_BASIC_AUTH_USERNAME",
            "CAMUNDA_BASIC_AUTH_PASSWORD",
            "ZEEBE_BASIC_AUTH_USERNAME",
            "ZEEBE_BASIC_AUTH_PASSWORD",
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        std::env::set_var("CAMUNDA_BASIC_AUTH_USERNAME", "ambient");
        std::env::set_var("CAMUNDA_BASIC_AUTH_PASSWORD", "secret");
        let none_profile = profile(r#"{"name":"prod","baseUrl":"http://engine:8080"}"#);
        let (_addr, basic) = rest_address_and_basic(Some(&none_profile));
        assert_eq!(basic, None, "NONE-mode profile must not use ambient basic-auth");
        // A profile that *does* carry basic credentials still authenticates.
        let basic_profile =
            profile(r#"{"name":"prod","baseUrl":"http://engine:8080","username":"pu","password":"pp"}"#);
        let (_addr, basic) = rest_address_and_basic(Some(&basic_profile));
        assert_eq!(basic, Some(("pu".to_string(), "pp".to_string())));
        // Restore prior environment so parallel tests are unaffected.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn ambient_auth_strategy_none_suppresses_basic() {
        // On the no-profile path, an explicit ambient `AUTH_STRATEGY=NONE` must
        // disable basic-auth even when stray `*_BASIC_AUTH_*` vars are present —
        // otherwise an environment that deliberately turns auth off is silently
        // re-authenticated with leftover credentials.
        let _env = env_guard();
        let keys = [
            "CAMUNDA_AUTH_STRATEGY",
            "ZEEBE_AUTH_STRATEGY",
            "CAMUNDA_BASIC_AUTH_USERNAME",
            "CAMUNDA_BASIC_AUTH_PASSWORD",
            "ZEEBE_BASIC_AUTH_USERNAME",
            "ZEEBE_BASIC_AUTH_PASSWORD",
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        std::env::set_var("CAMUNDA_BASIC_AUTH_USERNAME", "ambient");
        std::env::set_var("CAMUNDA_BASIC_AUTH_PASSWORD", "secret");
        // Without a strategy, ambient basic-auth is honoured (unchanged).
        let (_addr, basic) = rest_address_and_basic(None);
        assert_eq!(basic, Some(("ambient".to_string(), "secret".to_string())));
        // An explicit NONE disables it (case-insensitive), even on the ZEEBE alias.
        std::env::set_var("ZEEBE_AUTH_STRATEGY", "none");
        let (_addr, basic) = rest_address_and_basic(None);
        assert_eq!(basic, None, "explicit ambient NONE must suppress basic-auth");
        // A non-NONE strategy still authenticates.
        std::env::remove_var("ZEEBE_AUTH_STRATEGY");
        std::env::set_var("CAMUNDA_AUTH_STRATEGY", "BASIC");
        let (_addr, basic) = rest_address_and_basic(None);
        assert_eq!(basic, Some(("ambient".to_string(), "secret".to_string())));
        // Restore prior environment so parallel tests are unaffected.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
