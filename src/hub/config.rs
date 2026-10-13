//! Worker-side agentic-hub configuration, read from the `NANO_AGENTIC*`
//! environment the launcher exports — the same variable names the Node plugin
//! (jwulf/c8ctl-plugin-nano) reads, so a Rust-run daemon and a Node-run worker
//! are configured identically.
//!
//! Local-first: the hub is ON BY DEFAULT and `NANO_AGENTIC` is an OPT-OUT — only
//! an explicit off value (`off`/`0`/`false`/`no`) disables it. With no secure
//! identity configured the worker joins in LOCAL mode (the well-known
//! [`LOCAL_AGENTIC_TOKEN`]); `NANO_AGENTIC_URL` names the app's HTTP(S) base and
//! is normalised to the `ws(s)://…/agentic` channel endpoint.

use std::env;

/// How many buffered outbound frames to retain while the hub is unreachable
/// before dropping the OLDEST (so a long outage cannot grow daemon memory
/// without bound). Overridable with `NANO_AGENTIC_BUFFER_CAPACITY`.
pub const DEFAULT_BUFFER_CAPACITY: usize = 1024;

/// Total byte budget for the outbound buffer's retained payloads. A count cap
/// alone does not bound *memory*: a transcript `produce` chunk may be up to
/// ~1 MiB (`MAX_ACP_FRAME`), so `DEFAULT_BUFFER_CAPACITY` frames could retain
/// ~1 GiB per session and multiple slots multiply that. This caps the summed
/// payload bytes the buffer holds regardless of frame count; a frame that would
/// exceed it sheds lower-priority traffic first and is otherwise dropped.
/// Overridable with `NANO_AGENTIC_BUFFER_BYTES`.
pub const DEFAULT_BUFFER_BYTE_BUDGET: usize = 64 * 1024 * 1024;

/// The well-known identity token for LOCAL agentic visibility (security
/// opt-in). Nano is local-first: a worker with no `NANO_AGENTIC_SECRET` joins
/// the visibility channel with zero configuration by presenting this constant,
/// well-known LOCAL token — NOT a secret. Kept in lock-step with the reference
/// Node plugin (`c8ctl-plugin.js` `LOCAL_AGENTIC_TOKEN`) and the hub
/// (`nano-workforce` `app/agentic/channel.ts`), which honours this token from
/// any origin on a trusted LAN. Never used in SECURE mode (a real
/// `NANO_AGENTIC_SECRET`).
pub const LOCAL_AGENTIC_TOKEN: &str = "nano-local";

/// The default app base URL when `NANO_AGENTIC_URL` is unset. The reference
/// worker defers to the engine its jobs run on (profile `restAddress` →
/// localhost); this worker has no persisted engine profile here, so it falls
/// back to the same localhost default.
pub const DEFAULT_AGENTIC_BASE: &str = "http://localhost:8080";

/// Resolved hub configuration. Absent (`from_env` → `None`) means the hub is
/// disabled and the daemon runs without any hub connection.
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// The WebSocket channel endpoint, normalised from the `NANO_AGENTIC_URL`
    /// HTTP(S) base by [`HubConfig::from_env`] (e.g. `http://localhost:8080` →
    /// `ws://localhost:8080/agentic`).
    pub url: String,
    /// The deprecated identity-token alias (`NANO_AGENTIC_TOKEN`). The current
    /// shared identity is `secret` (`NANO_AGENTIC_SECRET`); this is used only
    /// when `secret` is unset. Whichever resolves is carried as the `?token=`
    /// query param on the upgrade URL (see `authenticated_url`/`identity_token`).
    pub token: Option<String>,
    /// The shared-secret identity this worker presents (`NANO_AGENTIC_SECRET`).
    /// It is the current, preferred identity and is sent as the `?token=` query
    /// param on the upgrade URL — the same slot the hub's shared-secret
    /// authenticator reads — NOT as an `Authorization` header. `token`
    /// (`NANO_AGENTIC_TOKEN`) is only a deprecated fallback when this is unset.
    pub secret: Option<String>,
    /// An opaque credential (`NANO_AGENTIC_CREDENTIAL`) sent as the `capability`
    /// query parameter on the WebSocket upgrade URL (see `authenticated_url`).
    /// It is NOT included in the REGISTER/presence `capability` payload
    /// (`capability_payload` never adds it), so operators should not expect it
    /// in presence frames.
    pub credential: Option<String>,
    /// The permission policy the worker advertises (`NANO_AGENTIC_PERMISSION`).
    pub permission: Option<String>,
    /// Whether the terminal relay (PTY agents) is enabled
    /// (`NANO_AGENTIC_TERMINAL`).
    pub terminal: bool,
    /// Attribution string recorded in presence (`NANO_AGENT_ATTRIBUTION`).
    pub attribution: Option<String>,
    /// Bounded outbound buffer depth while disconnected
    /// (`NANO_AGENTIC_BUFFER_CAPACITY`, default [`DEFAULT_BUFFER_CAPACITY`]).
    pub buffer_capacity: usize,
    /// Total byte budget for retained outbound payloads
    /// (`NANO_AGENTIC_BUFFER_BYTES`, default [`DEFAULT_BUFFER_BYTE_BUDGET`]). A
    /// count cap alone cannot bound memory because a single transcript chunk may
    /// be ~1 MiB; this caps the summed bytes the buffer holds.
    pub buffer_byte_budget: usize,
}

/// Is `NANO_AGENTIC` an explicit OFF value? The reference worker treats it as an
/// opt-OUT, not a required on-switch: visibility is on by default and only
/// `off`/`0`/`false`/`no` (case-insensitive) disable it. Any other value —
/// including a truthy one or a typo — leaves it enabled.
fn env_off(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "off" | "false" | "no"
    )
}

/// Normalise the `NANO_AGENTIC_URL` app base to the WebSocket channel endpoint,
/// mirroring the reference worker's `buildAgenticUrl`: `http`→`ws`,
/// `https`→`wss`, any base path preserved, and the same-port channel path
/// `/agentic` appended. A value already on `ws`/`wss` is re-anchored to
/// `/agentic` the same way; any other scheme is returned unchanged so the
/// connector surfaces a clear unsupported-scheme error rather than a silently
/// mangled URL.
fn agentic_channel_url(base: &str) -> String {
    let trimmed = base.trim();
    let (rest, scheme_ws) = if let Some(r) = trimmed.strip_prefix("http://") {
        (r, "ws://")
    } else if let Some(r) = trimmed.strip_prefix("https://") {
        (r, "wss://")
    } else if let Some(r) = trimmed.strip_prefix("ws://") {
        (r, "ws://")
    } else if let Some(r) = trimmed.strip_prefix("wss://") {
        (r, "wss://")
    } else {
        return trimmed.to_string();
    };
    // Split off any query/fragment so the path join does not corrupt them; the
    // channel carries its own auth query params, so they are dropped here.
    let host_path = rest.split(['?', '#']).next().unwrap_or(rest);
    let joined = format!("{scheme_ws}{host_path}");
    format!("{}/agentic", joined.trim_end_matches('/'))
}

fn non_empty(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// The permission policies a worker may advertise. The source of truth is the
/// hire vocabulary (`fleet::VALID_PERMISSIONS`); an override outside this closed
/// set is a typo and must fall through to the hire/default policy rather than be
/// advertised verbatim.
const VALID_PERMISSIONS: [&str; 3] = ["yolo", "escalate", "filter"];

/// The terminal transports a worker may declare. The source of truth is the hire
/// vocabulary (`fleet::VALID_TERMINALS`). `NANO_AGENTIC_TERMINAL` names a MODE
/// (`pty`/`pipe`), not a truthy flag, so only `pty` enables the terminal relay.
const VALID_TERMINALS: [&str; 2] = ["pty", "pipe"];

/// Read `key` and return its trimmed, lower-cased value only when it is one of
/// `allowed`. An unset, empty, or out-of-vocabulary value yields `None`, so a
/// typo (`YOLOO`, `ptyy`) falls through to the caller's default instead of being
/// advertised as a real policy/mode. Normalising to lower-case keeps parity with
/// the hire-side parse, which is case-insensitive.
fn validated_mode(key: &str, allowed: &[&str]) -> Option<String> {
    validate_mode(env::var(key).ok(), allowed)
}

/// Pure core of [`validated_mode`]: normalise a raw value (trim + lower-case)
/// and keep it only when it is in the closed `allowed` vocabulary.
fn validate_mode(raw: Option<String>, allowed: &[&str]) -> Option<String> {
    let norm = raw?.trim().to_ascii_lowercase();
    allowed.contains(&norm.as_str()).then_some(norm)
}

impl HubConfig {
    /// Resolve the hub configuration from the process environment. Local-first:
    /// the hub is ON BY DEFAULT and `NANO_AGENTIC` is an OPT-OUT — this returns
    /// `None` (hub disabled) only when `NANO_AGENTIC` is an explicit off value
    /// (`off`/`0`/`false`/`no`). With no secure identity configured the worker
    /// joins in LOCAL mode (the well-known [`LOCAL_AGENTIC_TOKEN`]); a credential
    /// set without a secret is meaningless and is ignored (LOCAL mode).
    pub fn from_env() -> Option<HubConfig> {
        // Opt-out, not opt-in: only an explicit off value disables visibility.
        if let Some(v) = env::var("NANO_AGENTIC").ok().as_deref() {
            if env_off(v) {
                return None;
            }
        }
        // `NANO_AGENTIC_URL` is the app's HTTP(S) base; normalise it to the
        // `ws(s)://…/agentic` channel endpoint. Unset defers to the localhost
        // default (the reference worker defers to its engine's profile base).
        let url = agentic_channel_url(
            &non_empty("NANO_AGENTIC_URL").unwrap_or_else(|| DEFAULT_AGENTIC_BASE.to_string()),
        );
        let buffer_capacity = env::var("NANO_AGENTIC_BUFFER_CAPACITY")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_BUFFER_CAPACITY);
        let buffer_byte_budget = env::var("NANO_AGENTIC_BUFFER_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_BUFFER_BYTE_BUDGET);
        let secret = non_empty("NANO_AGENTIC_SECRET");
        let token = non_empty("NANO_AGENTIC_TOKEN");
        let credential = non_empty("NANO_AGENTIC_CREDENTIAL");
        // SECURE mode: a real shared secret (or its deprecated TOKEN alias) is
        // the identity. LOCAL mode (default): no secure identity, so present the
        // well-known LOCAL token; a credential set without a secret is ignored.
        let secure = secret.is_some() || token.is_some();
        let (token, credential) = if secure {
            (token, credential)
        } else {
            (Some(LOCAL_AGENTIC_TOKEN.to_string()), None)
        };
        Some(HubConfig {
            url,
            token,
            secret,
            credential,
            // Validate against the closed permission vocabulary: an invalid
            // override (a typo like `YOLOO`) must fall through to the
            // hire/default policy, not be advertised verbatim as a real policy.
            permission: validated_mode("NANO_AGENTIC_PERMISSION", &VALID_PERMISSIONS),
            // `NANO_AGENTIC_TERMINAL` is a MODE (`pty`/`pipe`), not a truthy
            // flag: only `pty` enables/advertises the terminal relay. An invalid
            // or unset value falls through to the default (relay off).
            terminal: validated_mode("NANO_AGENTIC_TERMINAL", &VALID_TERMINALS)
                .is_some_and(|mode| mode == "pty"),
            attribution: non_empty("NANO_AGENT_ATTRIBUTION"),
            buffer_capacity,
            buffer_byte_budget,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_switch_matches_the_reference_opt_out_vocabulary() {
        // Only the explicit off values disable visibility (opt-OUT).
        for v in ["0", "off", "false", "no", "OFF", " False ", "No"] {
            assert!(env_off(v), "{v:?} should disable the hub");
        }
        // Anything else — truthy values, typos, empty — leaves it enabled.
        for v in ["", "1", "true", "yes", "on", "enable", "offf", "garbage"] {
            assert!(!env_off(v), "{v:?} should NOT disable the hub");
        }
    }

    #[test]
    fn agentic_channel_url_normalises_http_base_to_ws_endpoint() {
        // http→ws, /agentic appended (the documented config).
        assert_eq!(
            agentic_channel_url("http://localhost:8080"),
            "ws://localhost:8080/agentic"
        );
        // https→wss, base path preserved, trailing slashes collapsed.
        assert_eq!(
            agentic_channel_url("https://app.example.com/base/"),
            "wss://app.example.com/base/agentic"
        );
        // An already-ws base is re-anchored to /agentic.
        assert_eq!(
            agentic_channel_url("ws://127.0.0.1:8787"),
            "ws://127.0.0.1:8787/agentic"
        );
        // A base query/fragment is dropped (the channel carries its own auth).
        assert_eq!(
            agentic_channel_url("http://h:1/base?x=1#frag"),
            "ws://h:1/base/agentic"
        );
        // An unsupported scheme is returned unchanged so the connector surfaces
        // a clear unsupported-scheme error rather than a mangled URL.
        assert_eq!(agentic_channel_url("ftp://x/y"), "ftp://x/y");
    }

    #[test]
    fn permission_override_validates_against_the_closed_vocabulary() {
        // Every supported policy is accepted, normalised to lower-case.
        for v in ["yolo", "escalate", "filter", "YOLO", " Filter "] {
            assert_eq!(
                validate_mode(Some(v.to_string()), &VALID_PERMISSIONS),
                Some(v.trim().to_ascii_lowercase()),
                "{v:?} should be an accepted permission policy"
            );
        }
        // A typo or any out-of-vocabulary value falls through to the default
        // (None) rather than being advertised verbatim as a real policy.
        for v in ["", "yoloo", "YOLOO", "allow", "deny", "garbage"] {
            assert_eq!(
                validate_mode(Some(v.to_string()), &VALID_PERMISSIONS),
                None,
                "{v:?} must not be advertised as a permission policy"
            );
        }
        assert_eq!(validate_mode(None, &VALID_PERMISSIONS), None);
    }

    #[test]
    fn terminal_override_is_a_mode_not_a_truthy_flag() {
        // The documented modes are parsed as a mode: only `pty` enables relay.
        let pty = |v: &str| {
            validate_mode(Some(v.to_string()), &VALID_TERMINALS).is_some_and(|m| m == "pty")
        };
        for v in ["pty", "PTY", " Pty "] {
            assert!(pty(v), "{v:?} should enable the terminal relay");
        }
        // `pipe` is a valid mode but disables the relay; the old truthy parse
        // (regression under test) wrongly treated BOTH documented values as
        // false, and any truthy-looking value as true.
        for v in [
            "pipe", "PIPE", "", "true", "1", "yes", "on", "ptyy", "garbage",
        ] {
            assert!(!pty(v), "{v:?} should NOT enable the terminal relay");
        }
    }
}
