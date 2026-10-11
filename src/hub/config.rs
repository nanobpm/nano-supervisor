//! Worker-side agentic-hub configuration, read from the `NANO_AGENTIC*`
//! environment the launcher exports — the same variable names the Node plugin
//! (jwulf/c8ctl-plugin-nano) reads, so a Rust-run daemon and a Node-run worker
//! are configured identically.
//!
//! The hub is OFF unless `NANO_AGENTIC` is truthy AND `NANO_AGENTIC_URL` names
//! an endpoint: a daemon with neither set behaves exactly as before (no socket,
//! no presence), so enabling the hub is purely additive.

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

/// Resolved hub configuration. Absent (`from_env` → `None`) means the hub is
/// disabled and the daemon runs without any hub connection.
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// The WebSocket endpoint, e.g. `ws://127.0.0.1:8787/agentic`.
    pub url: String,
    /// The routing token this worker presents (`NANO_AGENTIC_TOKEN`), e.g.
    /// `implementation.ci.fix#red`. Optional: an endpoint may assign one.
    pub token: Option<String>,
    /// A bearer secret sent as `Authorization: Bearer …` on the upgrade
    /// (`NANO_AGENTIC_SECRET`).
    pub secret: Option<String>,
    /// An opaque credential echoed in the presence payload
    /// (`NANO_AGENTIC_CREDENTIAL`).
    pub credential: Option<String>,
    /// The worker's harness-protocol override (`NANO_AGENTIC_PROTOCOL`), e.g.
    /// `pipe` or `acp`. This is NOT a WebSocket subprotocol: it is applied when
    /// resolving the hire protocol (see [`HubConfig::hire_protocol_override`])
    /// and is never sent on the wire.
    pub protocol: Option<String>,
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

/// Is an environment flag truthy the way the Node launcher treats it? `1`,
/// `true`, `yes`, `on` (case-insensitive) enable; everything else (including
/// unset, empty, `0`, `false`) disables.
pub fn env_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn non_empty(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

impl HubConfig {
    /// Resolve the hub configuration from the process environment. Returns
    /// `None` (hub disabled) unless `NANO_AGENTIC` is truthy and
    /// `NANO_AGENTIC_URL` is a non-empty endpoint.
    pub fn from_env() -> Option<HubConfig> {
        let enabled = env::var("NANO_AGENTIC")
            .ok()
            .is_some_and(|v| env_truthy(&v));
        if !enabled {
            return None;
        }
        let url = non_empty("NANO_AGENTIC_URL")?;
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
        Some(HubConfig {
            url,
            token: non_empty("NANO_AGENTIC_TOKEN"),
            secret: non_empty("NANO_AGENTIC_SECRET"),
            credential: non_empty("NANO_AGENTIC_CREDENTIAL"),
            protocol: non_empty("NANO_AGENTIC_PROTOCOL"),
            permission: non_empty("NANO_AGENTIC_PERMISSION"),
            terminal: env::var("NANO_AGENTIC_TERMINAL")
                .ok()
                .is_some_and(|v| env_truthy(&v)),
            attribution: non_empty("NANO_AGENT_ATTRIBUTION"),
            buffer_capacity,
            buffer_byte_budget,
        })
    }

    /// The harness-protocol override named by `NANO_AGENTIC_PROTOCOL`, if any.
    /// This is the referenced worker's override for the hire protocol (`pipe` or
    /// `acp`) — distinct from a WebSocket subprotocol, so it is applied when
    /// resolving the hire protocol and never sent as a `Sec-WebSocket-Protocol`
    /// header. Returns the trimmed override, or `None` when unset/empty.
    pub fn hire_protocol_override(&self) -> Option<&str> {
        self.protocol.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthy_matches_the_node_launcher_vocabulary() {
        for v in ["1", "true", "TRUE", "Yes", "on", " on "] {
            assert!(env_truthy(v), "{v:?} should be truthy");
        }
        for v in ["", "0", "false", "no", "off", "enable"] {
            assert!(!env_truthy(v), "{v:?} should be falsy");
        }
    }
}
