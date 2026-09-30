//! Daemon state read from disk: the c8ctl-nano state home and the `config.json`
//! hires map, plus the rank×capability job-type matrix each hire subscribes to.
//!
//! This mirrors the Node plugin (`c8ctl-plugin.js`): the state home is
//! `$C8CTL_NANO_HOME`, else the platform data dir (`~/.local/share/c8ctl-nano`
//! on Linux, `~/Library/Application Support/c8ctl-nano` on macOS), and hires
//! live under `config.json`'s `hires` object keyed by name.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The transport a hire's harness speaks. `pipe` feeds the agent a JSON job
/// payload on stdin; `acp` drives it over the Agent Client Protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Pipe,
    Acp,
}

impl Protocol {
    fn parse(raw: &str) -> Protocol {
        match raw.trim().to_ascii_lowercase().as_str() {
            "acp" => Protocol::Acp,
            // Tolerant like the Node plugin: an unknown/legacy value falls back
            // to the safe `pipe` default rather than failing the whole hire.
            _ => Protocol::Pipe,
        }
    }
}

/// One hire (persisted agent profile) from `config.json`.
#[derive(Debug, Clone)]
pub struct Hire {
    pub name: String,
    pub rank: String,
    pub command: String,
    pub args: Vec<String>,
    pub model: String,
    pub capabilities: Vec<String>,
    pub protocol: Protocol,
    /// Sandbox mode. The MVP daemon only runs the `none` (host) sandbox; a
    /// container sandbox is refused up front.
    pub sandbox: String,
    pub env: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawHire {
    #[serde(default)]
    rank: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    args: Option<Vec<String>>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    capabilities: Option<Vec<String>>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    sandbox: Option<String>,
    #[serde(default)]
    env: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    hires: std::collections::BTreeMap<String, RawHire>,
}

/// The c8ctl-nano state home (`$C8CTL_NANO_HOME` or the platform default).
pub fn state_home() -> Option<PathBuf> {
    if let Some(env) = std::env::var_os("C8CTL_NANO_HOME") {
        if !env.is_empty() {
            return Some(PathBuf::from(env));
        }
    }
    let home = std::env::var_os("HOME")?;
    if cfg!(target_os = "macos") {
        return Some(PathBuf::from(home).join("Library/Application Support/c8ctl-nano"));
    }
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(home).join(".local/share"),
    };
    Some(base.join("c8ctl-nano"))
}

/// Path to `config.json` under the state home.
pub fn config_file() -> Option<PathBuf> {
    state_home().map(|d| d.join("config.json"))
}

/// Read and normalize the hires map from a specific `config.json` path. A
/// missing file yields an empty list; a malformed file is an error the caller
/// surfaces. The daemon composes this with [`config_file`].
pub fn read_hires_from(path: &std::path::Path) -> Result<Vec<Hire>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    let mut hires = Vec::new();
    for (name, raw) in cfg.hires {
        hires.push(normalize(name, raw));
    }
    hires.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(hires)
}

fn normalize(name: String, raw: RawHire) -> Hire {
    Hire {
        rank: raw.rank.trim().to_ascii_lowercase(),
        command: raw.command.trim().to_string(),
        args: raw.args.unwrap_or_default(),
        model: raw.model.unwrap_or_default().trim().to_string(),
        capabilities: normalize_capabilities(raw.capabilities.unwrap_or_default()),
        protocol: Protocol::parse(raw.protocol.as_deref().unwrap_or("pipe")),
        sandbox: raw
            .sandbox
            .unwrap_or_else(|| "none".into())
            .trim()
            .to_ascii_lowercase(),
        env: raw.env.unwrap_or_default(),
        name,
    }
}

/// Deduplicate, trim, lowercase and sort capability tokens (canonical order so
/// the combined job type is predictable), matching the Node plugin.
pub fn normalize_capabilities(caps: Vec<String>) -> Vec<String> {
    let set: BTreeSet<String> = caps
        .into_iter()
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    set.into_iter().collect()
}

/// The job-type matrix a hire subscribes to, from its rank and sorted
/// capabilities `[c1, c2, ...]`:
///   - `rank`                  (rank alone)
///   - `rank:c1`, `rank:c2`    (rank + a single capability, "spread")
///   - `rank:c1+c2+...`        (rank + all capabilities combined; only when >1)
pub fn job_type_matrix(rank: &str, capabilities: &[String]) -> Vec<String> {
    let mut tokens = vec![rank.to_string()];
    for c in capabilities {
        tokens.push(format!("{rank}:{c}"));
    }
    if capabilities.len() > 1 {
        tokens.push(format!("{rank}:{}", capabilities.join("+")));
    }
    // Dedup while preserving order.
    let mut seen = BTreeSet::new();
    tokens
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_rank_only() {
        assert_eq!(job_type_matrix("senior", &[]), vec!["senior"]);
    }

    #[test]
    fn matrix_spread_and_combined() {
        let caps = normalize_capabilities(vec!["Review".into(), "feature".into()]);
        // Normalized/sorted: ["feature", "review"].
        assert_eq!(
            job_type_matrix("senior", &caps),
            vec![
                "senior",
                "senior:feature",
                "senior:review",
                "senior:feature+review",
            ]
        );
    }

    #[test]
    fn matrix_single_cap_has_no_combined() {
        let caps = normalize_capabilities(vec!["pr-review".into()]);
        assert_eq!(
            job_type_matrix("senior", &caps),
            vec!["senior", "senior:pr-review"]
        );
    }

    #[test]
    fn protocol_defaults_to_pipe() {
        assert_eq!(Protocol::parse("weird"), Protocol::Pipe);
        assert_eq!(Protocol::parse("ACP"), Protocol::Acp);
        assert_eq!(Protocol::parse(" pipe "), Protocol::Pipe);
    }

    #[test]
    fn reads_hires_from_config() {
        let dir = std::env::temp_dir().join(format!("nano-state-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"hires":{"coder":{"rank":"Senior","command":"nano-coder","capabilities":["pr-review"],"protocol":"acp"}}}"#,
        )
        .unwrap();
        let hires = read_hires_from(&path).unwrap();
        assert_eq!(hires.len(), 1);
        let h = &hires[0];
        assert_eq!(h.name, "coder");
        assert_eq!(h.rank, "senior");
        assert_eq!(h.protocol, Protocol::Acp);
        assert_eq!(h.capabilities, vec!["pr-review"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_config_is_empty() {
        let path = std::env::temp_dir().join("nano-state-does-not-exist.json");
        assert!(read_hires_from(&path).unwrap().is_empty());
    }
}
