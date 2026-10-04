//! Resolve a c8ctl connection profile and turn it into SDK configuration.
//!
//! c8ctl keeps profiles in `<config>/c8ctl/profiles.json` (`{"profiles": [...]}`)
//! and the active profile in `<config>/c8ctl/session.json` (`activeProfile`).
//! `<config>` is `$XDG_CONFIG_HOME` or `~/.config` on Linux, and
//! `~/Library/Application Support` on macOS.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use camunda_orchestration_sdk::{CamundaClient, CamundaConfig, CamundaOptions, TlsConfig};
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
    // One pooled HTTP client for the whole process (the SDK shares it across
    // every slot's activate/extend/complete/fail). reqwest already pools and
    // reuses keep-alive connections by default; these settings bound the pool's
    // CHURN instead:
    //
    // - `pool_idle_timeout(30s)`: the engine's own keep-alive timeout can be
    //   shorter than reqwest's 90s default, in which case a pooled connection
    //   goes stale and the next request opens a fresh socket — each abandoned
    //   one held by the kernel in `TIME_WAIT`. Dropping idle pool entries after
    //   30s (the default long-poll window, so a poll response's connection is
    //   reused for the immediately following poll) keeps the pool from
    //   accumulating dead sockets between polls.
    // - `tcp_keepalive(60s)`: keep long-lived idle connections (a 30s+ long
    //   poll, a quiet fleet) fresh through NATs/LBs instead of discovering a
    //   half-dead socket on the next request and reconnecting.
    //
    // The storm guard itself is the activation backoff in `slot::run`
    // (nanobpm/nano-supervisor#23); this keeps the steady-state connection count
    // low so a fleet of slots shares a handful of sockets rather than churning
    // the ephemeral port range.
    let builder = reqwest::Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .tcp_keepalive(std::time::Duration::from_secs(60));
    // The SDK skips its own `tls::apply_tls` whenever a caller supplies a
    // pre-built client (`runtime/client.rs`: `Some(client) => client`), so a
    // hand-built client would silently drop CAMUNDA_MTLS_* material — private-CA
    // trust and the mTLS identity — and every engine call would fail TLS
    // verification. Resolve the same TLS config the SDK would and apply it to
    // our tuned builder before handing the client over.
    let tls = CamundaConfig::from_env_with_overrides(&opts.config)
        .map_err(|e| anyhow::anyhow!("resolving engine TLS configuration: {e}"))?
        .tls;
    let http = apply_tls(builder, &tls)?
        .build()
        .map_err(|e| anyhow::anyhow!("creating engine HTTP client: {e}"))?;
    CamundaClient::new(opts.with_http_client(http))
        .map_err(|e| anyhow::anyhow!("creating engine client: {e}"))
}

/// Apply the configured `CAMUNDA_MTLS_*` material to a [`reqwest::ClientBuilder`].
///
/// Mirrors the SDK's own (crate-private) `tls::apply_tls`: a CA certificate
/// enables trusting a private certificate authority, and a client certificate +
/// key enable mutual TLS. Inline PEM values take precedence over `*_PATH` file
/// locations. When no TLS material is configured the builder is returned
/// unchanged.
fn apply_tls(
    mut builder: reqwest::ClientBuilder,
    tls: &TlsConfig,
) -> Result<reqwest::ClientBuilder> {
    if !tls.is_configured() {
        return Ok(builder);
    }

    if let Some(ca_pem) = read_pem(&tls.ca, &tls.ca_path, "CA certificate")? {
        let cert = reqwest::Certificate::from_pem(&ca_pem)
            .context("invalid CAMUNDA_MTLS_CA certificate")?;
        builder = builder.add_root_certificate(cert);
    }

    let cert_pem = read_pem(&tls.cert, &tls.cert_path, "client certificate")?;
    let key_pem = read_pem(&tls.key, &tls.key_path, "client key")?;
    match (cert_pem, key_pem) {
        (Some(cert), Some(key)) => {
            let identity = build_identity(&cert, &key, tls.key_passphrase.as_deref())?;
            builder = builder.identity(identity);
        }
        (None, None) => {}
        _ => {
            bail!(
                "mutual TLS requires both a client certificate (CAMUNDA_MTLS_CERT[_PATH]) and key (CAMUNDA_MTLS_KEY[_PATH])"
            );
        }
    }

    Ok(builder)
}

/// Resolve PEM bytes from an inline value (preferred) or a file path.
fn read_pem(inline: &Option<String>, path: &Option<String>, what: &str) -> Result<Option<Vec<u8>>> {
    if let Some(pem) = inline {
        return Ok(Some(pem.clone().into_bytes()));
    }
    if let Some(p) = path {
        let bytes = std::fs::read(p).with_context(|| format!("failed to read {what} from {p:?}"))?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

/// Build an mTLS identity from a client certificate and key.
///
/// This crate builds reqwest with the `rustls` backend only, which expects the
/// certificate chain and private key concatenated in one PEM buffer. Encrypted
/// keys are not supported; provide an unencrypted PEM key.
fn build_identity(cert: &[u8], key: &[u8], passphrase: Option<&str>) -> Result<reqwest::Identity> {
    if passphrase.is_some() {
        bail!(
            "CAMUNDA_MTLS_KEY_PASSPHRASE (encrypted client keys) is not supported; provide an unencrypted PEM key"
        );
    }
    let mut pem = Vec::with_capacity(cert.len() + key.len() + 1);
    pem.extend_from_slice(cert);
    pem.push(b'\n');
    pem.extend_from_slice(key);
    reqwest::Identity::from_pem(&pem).context("invalid client certificate/key")
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

    // Regression tests for nanobpm/nano-supervisor#37: a caller-supplied
    // `reqwest::Client` makes the SDK skip its own `tls::apply_tls`, so
    // `profile::client` must apply the `CAMUNDA_MTLS_*` material to its tuned
    // builder itself. These exercise `apply_tls`/`build_identity` directly.

    // A throwaway self-signed certificate + key generated for these tests
    // (`openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=nano-test`). Only
    // used to prove the PEM parsing/wiring path runs; never leaves the test.
    const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDCTCCAfGgAwIBAgIUTHeH+jhBjOPler27Mv4vRoOTU0kwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbmFuby10ZXN0MB4XDTI2MTAwNDE3NTAwMFoXDTI2MTAw\n\
NTE3NTAwMFowFDESMBAGA1UEAwwJbmFuby10ZXN0MIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEAmwUHGxHlP13bfkYJhzL4EloXjSwIlHzxZl72Oe3g48M7\n\
Z/D5+2wgo6BqzTKCjXrn2vxPCYjvKeY9XJudE6X3JiTc0UHTP4Kv0qSzPugbx7/v\n\
ghAo6Y9rH2JZKZehWpA8UClg8PKWtZa+DFSjKAWhUT9gB8+WumjdxXW1mKB92tJe\n\
RoN5+4GXp1Yu1r3aMvApMmwggA+ohClakTcgGNvInnJiyiIp425Fx0mY+CslMLZf\n\
cUpOA437lGQg6H0q/+qoMJupg1x8dIVhq4xlu7yiUjx3CaFKwi/ArxBlMu5MuMNC\n\
zANtW0STHaaafj4XvUlChS5Hlq2dO/mj0h+4yQGXSwIDAQABo1MwUTAdBgNVHQ4E\n\
FgQUXasWEYJokygDxdkSq7VpZvk1Ul4wHwYDVR0jBBgwFoAUXasWEYJokygDxdkS\n\
q7VpZvk1Ul4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAgGtI\n\
dUJA9B65HOR79HrK0aOVemOOKQL+5Flp9ZWhbkTiX4gO0nxAcKrrh5q6p77fwo2Z\n\
3zHYPPhDCWeiiKyMrnvmyckFtakOIQKo9NLbjYUrig5Plr25sOLamdDygerotN27\n\
xShiEBQS1qFkYQEdKIwaOIap969G9p+Z8XbcF/1O0YlZP9eNox2i8vlHl3wePq24\n\
NOee8TWhPMQ6AVjhrLZAZywmEkH23bs4Lg8l+n6DL9epAE4c4qG01RRyQ2US1way\n\
tZulKk8Fy1zJs8JBWDcHmx/v/6h0spvMo/8pAj7ArCPv+dlIN7FC8/gfNEHzKTBj\n\
vxOuZuKIGBUZYlj5KA==\n\
-----END CERTIFICATE-----\n";

    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbBQcbEeU/Xdt+\n\
RgmHMvgSWheNLAiUfPFmXvY57eDjwztn8Pn7bCCjoGrNMoKNeufa/E8JiO8p5j1c\n\
m50TpfcmJNzRQdM/gq/SpLM+6BvHv++CECjpj2sfYlkpl6FakDxQKWDw8pa1lr4M\n\
VKMoBaFRP2AHz5a6aN3FdbWYoH3a0l5Gg3n7gZenVi7Wvdoy8CkybCCAD6iEKVqR\n\
NyAY28iecmLKIinjbkXHSZj4KyUwtl9xSk4DjfuUZCDofSr/6qgwm6mDXHx0hWGr\n\
jGW7vKJSPHcJoUrCL8CvEGUy7ky4w0LMA21bRJMdppp+Phe9SUKFLkeWrZ07+aPS\n\
H7jJAZdLAgMBAAECggEAGEaeST/xLY4uLEUdgt2ZeY5AN+xYX6B9UTG3z3SQDjrp\n\
l6pmC1hweA9MClxJk4xWuLVgTzbxdRdILrNz0rrfzEpjhiWPxldZ31vJciV5DDvj\n\
bvPG5GSAOwb0vY2wR/VkbI0+UB09OqyjkFzEvCS9kXKiQDbi/MglSqHXUVJ4wwaG\n\
JSe0n5dagiFWNCTKE/UJ+6Y+2XXt2wMKbCqTtZf+hJ2Se9g9vhSRg3OCOiMUuv7X\n\
9QqDF3J1sOEGQuEkyZNrgln4TZ8tljV1VsO9Rpp5mmu4W2dStsfISVFWxbLk63Zv\n\
2s9ywq4kd2ZKRKcDsisUCXh476CtcjB2fApYqBECOQKBgQDQp124BOBi/XMJRJB9\n\
bUR5DEXMuPyFnhFUo0gYUYC3fLhJhdSsB9WLExFPKM6/HapVEXkYwXDn6LpifW+W\n\
E1h8+1Vb0to/P5v5BAcshw5y+CQC5PZh2cXjJ5WPJwd5SLbew4BVuJIy9Cf2GNMg\n\
Eidk+xguJgpcwubDzPEfVn7vtwKBgQC+MhI7aH/gyjfyrF5YyZV9S8jTJh3ne9XJ\n\
PE7EuZ52dsI6W2hd2L7HbMef2cFAIfliNHPwcFiQlN8SDsZzKC6QvFv2pSwT0KLH\n\
XG/lNfvUlVq13hWK13By6oqsXToyvV2melLpSVMvjsX3HJ/Qpswz4boLxKic6ytz\n\
+a/kPnXtDQKBgDxFjFHivrp5gehUcPR6QsRAokz/xpoGTfVH8URtDqRyF33NdeB3\n\
pty0llRqckZMmG5YTMW04xtqY6SdnUUZs37uzvpmTvrkMfbdjgDzxl25hhV79BvR\n\
31K9lXszh/ol4gU5LfIVDc5ALubsxtfFxrFpwtNZ07Z16lj281PdFW/DAoGACPM6\n\
QGluexmJAHZ0CiGSU08ZqDYG+jmtmcaovkEt380+3pgmlSP59lB8JF2O5oGyxphJ\n\
TGs8/7DBvovLcufVKSJ0AWtMY7JRtqf27AZaT2qn1h8ZTGtO81luJSZN8s1OduMS\n\
u7+jln1Ve4dxTdRLj7Vzl9ItTRUT+mUpjcgSrJECgYEAzRRb/PaV8E2vC09P36mS\n\
OzGl3wAf1UpQrRmoUZ+GMDfSHrA+nvUpuEjHmUlOkFFzKcQ0CoS+EIKj8LxCU32n\n\
UN1CCiHPvqDsiGUoCf+ajydjBPrOo+S8rBIR1HlMUnLMojMp7kExWF0rXdkjvyic\n\
1EovIIMApTRTLo3WbMkoa4I=\n\
-----END PRIVATE KEY-----\n";

    fn tls() -> TlsConfig {
        TlsConfig::default()
    }

    #[test]
    fn apply_tls_unconfigured_is_passthrough() {
        // No CAMUNDA_MTLS_* material: the builder must come back untouched
        // (and must still build).
        let b = apply_tls(reqwest::Client::builder(), &tls()).unwrap();
        b.build().unwrap();
    }

    #[test]
    fn apply_tls_ca_only_builds() {
        let t = TlsConfig {
            ca: Some(TEST_CERT.into()),
            ..tls()
        };
        let b = apply_tls(reqwest::Client::builder(), &t).unwrap();
        b.build().unwrap();
    }

    #[test]
    fn apply_tls_mtls_identity_builds() {
        let t = TlsConfig {
            ca: Some(TEST_CERT.into()),
            cert: Some(TEST_CERT.into()),
            key: Some(TEST_KEY.into()),
            ..tls()
        };
        let b = apply_tls(reqwest::Client::builder(), &t).unwrap();
        b.build().unwrap();
    }

    #[test]
    fn apply_tls_cert_without_key_errors() {
        let t = TlsConfig {
            cert: Some(TEST_CERT.into()),
            ..tls()
        };
        let err = apply_tls(reqwest::Client::builder(), &t).unwrap_err();
        assert!(
            err.to_string().contains("requires both a client certificate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn apply_tls_rejects_encrypted_key() {
        let err = build_identity(TEST_CERT.as_bytes(), TEST_KEY.as_bytes(), Some("pw"))
            .unwrap_err();
        assert!(
            err.to_string().contains("PASSPHRASE"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn apply_tls_rejects_invalid_identity_pem() {
        // Unlike the CA cert (parsed lazily at connection time under rustls),
        // `Identity::from_pem` parses eagerly, so a malformed client key/cert
        // must be rejected here rather than silently trusted.
        let t = TlsConfig {
            cert: Some("not a pem".into()),
            key: Some("also not a pem".into()),
            ..tls()
        };
        let err = apply_tls(reqwest::Client::builder(), &t).unwrap_err();
        assert!(
            err.to_string().contains("invalid client certificate/key"),
            "unexpected error: {err}"
        );
    }
}
