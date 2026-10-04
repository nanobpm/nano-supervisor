//! Fleet-management CLI surface — `hire`, `assign`, `supervisor` and
//! `workforce` — the Rust counterparts of the Node plugin's `c8 nano` fleet
//! commands.
//!
//! These commands own the on-disk state the #3 contract suite pins: the
//! `config.json` hires map, the `workforce/<name>.json` manifests, and the
//! human / `--json` output of `hire --list`, `hire`, `assign`, `supervisor
//! status`/`add` and `workforce list`/`add`/`status`. Everything here reads and
//! writes under `C8CTL_NANO_HOME` only (the control socket lives in the system
//! temp dir, like the Node plugin), and the JSON shapes and key order match the
//! golden snapshots exactly so the very same black-box suite stays green for
//! both targets.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::{job_type_matrix, normalize_capabilities, state_home};

/// The ranks a hire may hold, in the order the Node plugin lists them in its
/// rejection message.
const VALID_RANKS: [&str; 4] = ["principal", "senior", "junior", "decider"];

/// The transport protocols a hire may declare. Anything else is rejected at
/// hire time: `state::Protocol::parse` deliberately maps an unknown stored
/// value to `pipe` (tolerant read of legacy configs), so a typo accepted here
/// would silently run an ACP harness over pipe instead of failing.
const VALID_PROTOCOLS: [&str; 2] = ["acp", "pipe"];

/// One persisted hire in `config.json`. The field order is the golden order the
/// `config_after_hire` snapshot pins; a `#[derive(Serialize)]` struct always
/// emits its fields in declaration order (independent of serde_json's
/// `preserve_order` feature), so writing through this type keeps the on-disk
/// key order stable.
#[derive(Clone, Serialize, Deserialize)]
struct StoredHire {
    name: String,
    rank: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    model: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default = "default_sandbox")]
    sandbox: String,
    #[serde(default)]
    image: String,
    #[serde(default = "default_terminal")]
    terminal: String,
    #[serde(default = "default_protocol")]
    protocol: String,
    #[serde(default = "default_permission")]
    permission: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(rename = "createdAt", default)]
    created_at: serde_json::Value,
}

fn default_sandbox() -> String {
    "none".into()
}
fn default_terminal() -> String {
    "pipe".into()
}
fn default_protocol() -> String {
    "pipe".into()
}
fn default_permission() -> String {
    "ask".into()
}

/// `config.json` — the hires map plus any other top-level keys we don't model,
/// kept so a rewrite never drops fields a future plugin version added.
#[derive(Default, Serialize, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    hires: BTreeMap<String, StoredHire>,
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
}

/// The state home or a configuration error (the home is required for every
/// fleet command).
fn home_dir() -> Result<PathBuf> {
    state_home().context("cannot locate the c8ctl-nano state home (set HOME or C8CTL_NANO_HOME)")
}

fn config_path() -> Result<PathBuf> {
    Ok(home_dir()?.join("config.json"))
}

fn read_config() -> Result<ConfigFile> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(ConfigFile::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn write_config(cfg: &ConfigFile) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut json = serde_json::to_string_pretty(cfg)?;
    json.push('\n');
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
}

/// An ISO-8601 UTC timestamp (`YYYY-MM-DDThh:mm:ss.sssZ`), matching the Node
/// plugin's `new Date().toISOString()` for `createdAt`. Computed without a date
/// crate via the civil-from-days algorithm.
fn now_iso8601() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ms = dur.as_millis() as i64;
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

// --- hire -------------------------------------------------------------------

/// Flags accepted by `hire` (both the `--list` view and a new hire).
pub struct HireArgs {
    pub list: bool,
    pub json: bool,
    pub name: Option<String>,
    pub rank: Option<String>,
    pub command: Option<String>,
    pub capabilities: Option<String>,
    pub model: Option<String>,
    pub protocol: Option<String>,
    pub permission: Option<String>,
    pub sandbox: Option<String>,
    pub image: Option<String>,
    pub terminal: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<String>,
}

/// An NDJSON info record, as the Node plugin's `--json` mode emits on its
/// structured (stderr) channel: `{"status":"info","message":"<line>"}`.
#[derive(Serialize)]
struct InfoLine<'a> {
    status: &'a str,
    message: &'a str,
}

/// Emit human-readable `lines` either to stdout (default) or, under `--json`, as
/// one `{"status":"info","message":…}` record per line on stderr (stdout stays
/// empty — the recorded Node quirk).
fn emit_lines(lines: &[String], json: bool) {
    if json {
        for line in lines {
            if let Ok(s) = serde_json::to_string(&InfoLine {
                status: "info",
                message: line,
            }) {
                eprintln!("{s}");
            }
        }
    } else {
        for line in lines {
            println!("{line}");
        }
    }
}

fn split_caps(raw: Option<&str>) -> Vec<String> {
    match raw {
        Some(s) => normalize_capabilities(s.split(',').map(|c| c.to_string()).collect()),
        None => Vec::new(),
    }
}

pub fn hire(args: HireArgs) -> Result<()> {
    if args.list {
        return hire_list(args.json);
    }

    let name = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("hire requires --name")?
        .to_string();
    let rank_raw = args
        .rank
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("hire requires --rank")?;
    let command = args
        .command
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("hire requires --command")?
        .to_string();

    let rank = rank_raw.to_ascii_lowercase();
    if !VALID_RANKS.contains(&rank.as_str()) {
        bail!(
            "Invalid rank \"{rank_raw}\". Valid ranks: {}",
            VALID_RANKS.join(", ")
        );
    }

    let capabilities = split_caps(args.capabilities.as_deref());
    let mut env = BTreeMap::new();
    for pair in &args.env {
        match pair.split_once('=') {
            Some(("", _)) => {
                bail!("invalid --env entry \"{pair}\": expected KEY=VALUE with a non-empty key")
            }
            Some((k, v)) => {
                env.insert(k.to_string(), v.to_string());
            }
            None => bail!("invalid --env entry \"{pair}\": expected KEY=VALUE"),
        }
    }

    let protocol = args
        .protocol
        .as_deref()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(default_protocol);
    if !VALID_PROTOCOLS.contains(&protocol.as_str()) {
        bail!(
            "Invalid protocol \"{}\". Valid protocols: {}",
            args.protocol.as_deref().unwrap_or_default(),
            VALID_PROTOCOLS.join(", ")
        );
    }

    let hire = StoredHire {
        name: name.clone(),
        rank: rank.clone(),
        command: command.clone(),
        args: args.args.clone(),
        model: args.model.clone().unwrap_or_default().trim().to_string(),
        capabilities: capabilities.clone(),
        sandbox: args
            .sandbox
            .clone()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_sandbox),
        image: args.image.clone().unwrap_or_default(),
        terminal: args
            .terminal
            .clone()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .unwrap_or_else(default_terminal),
        protocol: protocol.clone(),
        permission: args
            .permission
            .clone()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(default_permission),
        env,
        created_at: serde_json::Value::String(now_iso8601()),
    };

    let mut cfg = read_config()?;
    cfg.hires.insert(name.clone(), hire.clone());
    write_config(&cfg)?;

    let caps_display = if capabilities.is_empty() {
        "(none)".to_string()
    } else {
        capabilities.join(", ")
    };
    let job_types = job_type_matrix(&rank, &capabilities).join(", ");
    println!("Hired {name} [{rank}] {command}");
    println!("  capabilities: {caps_display}");
    println!("  job types: {job_types}");
    println!("  protocol: {protocol}");
    println!("  permission: {}", hire.permission);
    Ok(())
}

fn hire_line(h: &StoredHire) -> String {
    let caps = if h.capabilities.is_empty() {
        "(none)".to_string()
    } else {
        h.capabilities.join(", ")
    };
    format!(
        "  {}  [{}]  {}  (model: {}; caps: {}; protocol: {})",
        h.name, h.rank, h.command, h.model, caps, h.protocol
    )
}

fn hire_list(json: bool) -> Result<()> {
    let cfg = read_config()?;
    let lines = if cfg.hires.is_empty() {
        vec!["No hires yet. Create one with: c8ctl nano hire".to_string()]
    } else {
        let mut lines = vec!["Hired agent profiles:".to_string()];
        for h in cfg.hires.values() {
            lines.push(hire_line(h));
        }
        lines.push(String::new());
        lines.push("Put one to work with: c8ctl nano work <name>".to_string());
        lines
    };
    emit_lines(&lines, json);
    Ok(())
}

// --- assign -----------------------------------------------------------------

pub fn assign(profile: &str, capabilities: &str) -> Result<()> {
    let mut cfg = read_config()?;
    let hire = cfg
        .hires
        .get_mut(profile)
        .with_context(|| format!("no hire named \"{profile}\""))?;
    let mut merged = hire.capabilities.clone();
    merged.extend(capabilities.split(',').map(|c| c.to_string()));
    let merged = normalize_capabilities(merged);
    hire.capabilities = merged.clone();
    write_config(&cfg)?;
    println!("Reassigned {profile} — capabilities: {}", merged.join(", "));
    Ok(())
}

// --- supervisor control socket ---------------------------------------------

/// Whether a supervisor daemon is listening on this home's control socket.
/// Mirrors the Node derivation (`<tmp>/c8ctl-nano-sup-<sha1(home)[:8]>.sock`)
/// and treats a successful connect as "running".
#[cfg(unix)]
fn supervisor_running(home: &std::path::Path) -> bool {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(home.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let sock = std::env::temp_dir().join(format!("c8ctl-nano-sup-{}.sock", &hex[..8]));
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

#[cfg(not(unix))]
fn supervisor_running(_home: &std::path::Path) -> bool {
    false
}

/// `supervisor` subcommands this target implements.
pub enum SupervisorOp {
    Status,
    Add { profile: String },
}

pub fn supervisor(op: SupervisorOp) -> Result<()> {
    let home = home_dir()?;
    match op {
        SupervisorOp::Status => {
            if supervisor_running(&home) {
                println!("Supervisor running");
            } else {
                println!("Supervisor not running");
            }
            Ok(())
        }
        SupervisorOp::Add { profile } => {
            let cfg = read_config()?;
            if !cfg.hires.contains_key(&profile) {
                bail!("no hire named \"{profile}\"");
            }
            if !supervisor_running(&home) {
                bail!("Supervisor not running; start it with: nano-supervisor supervisor start");
            }
            // A live daemon would take the add over the control socket; that
            // path lands with the daemon itself (#8).
            bail!("supervisor add against a live daemon is not yet implemented on the Rust target");
        }
    }
}

// --- workforce manifests ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct ManifestWorker {
    profile: String,
    instances: u32,
    #[serde(default = "default_roles")]
    roles: String,
}

fn default_roles() -> String {
    "auto".into()
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    name: String,
    #[serde(default)]
    workers: Vec<ManifestWorker>,
}

fn manifest_path(name: &str) -> Result<PathBuf> {
    // The manifest name becomes a filename under the home's `workforce/`
    // directory, so it must be exactly one plain path component. `Path::join`
    // silently DISCARDS the base when the argument is absolute, and a `..`
    // (or separator) component climbs out of `workforce/` — either way a
    // crafted name would read/write state files outside the home. Fail closed:
    // reject anything that is not a single normal component.
    let bad = || {
        anyhow::anyhow!(
            "invalid workforce name \"{name}\": expected a plain name (no path separators or `..`)"
        )
    };
    let trimmed = name.trim();
    // Reject both platforms' separators explicitly: on Unix a backslash is a
    // valid filename character, so the component check below passes `a\b`,
    // but the same manifest read on Windows would traverse into `b`.
    if trimmed.is_empty() || trimmed.contains(['/', '\\']) {
        return Err(bad());
    }
    let as_path = std::path::Path::new(trimmed);
    match as_path.components().collect::<Vec<_>>().as_slice() {
        [std::path::Component::Normal(_)] => {}
        _ => return Err(bad()),
    }
    Ok(home_dir()?
        .join("workforce")
        .join(format!("{trimmed}.json")))
}

fn read_manifest(name: &str) -> Result<Option<Manifest>> {
    let path = manifest_path(name)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let m =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(m))
}

fn write_manifest(m: &Manifest) -> Result<()> {
    let path = manifest_path(&m.name)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut json = serde_json::to_string_pretty(m)?;
    json.push('\n');
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
}

pub fn workforce_list(name: &str) -> Result<()> {
    match read_manifest(name)? {
        None => println!("Workforce \"{name}\" does not exist"),
        Some(m) => {
            println!("Workforce \"{name}\":");
            for w in &m.workers {
                println!("  {} × {} (roles: {})", w.profile, w.instances, w.roles);
            }
        }
    }
    Ok(())
}

pub fn workforce_add(name: &str, profile: &str, instances: u32, roles: &str) -> Result<()> {
    // Like `assign` and `supervisor add`, refuse to persist state for a profile
    // that can never run.
    let cfg = read_config()?;
    if !cfg.hires.contains_key(profile) {
        bail!("no hire named \"{profile}\"");
    }
    // A desired-zero worker entry is meaningless (the Node CLI floors instances
    // at 1); clamp rather than persist an empty workers list.
    let instances = instances.max(1);
    let mut manifest = read_manifest(name)?.unwrap_or(Manifest {
        version: 1,
        name: name.to_string(),
        workers: Vec::new(),
    });
    match manifest.workers.iter_mut().find(|w| w.profile == profile) {
        Some(existing) => {
            existing.instances = instances;
            existing.roles = roles.to_string();
        }
        None => manifest.workers.push(ManifestWorker {
            profile: profile.to_string(),
            instances,
            roles: roles.to_string(),
        }),
    }
    write_manifest(&manifest)?;
    println!("Added {profile} × {instances} to workforce \"{name}\"");
    Ok(())
}

#[derive(Serialize)]
struct StatusWorker {
    name: String,
    present: bool,
    state: &'static str,
    pid: Option<u32>,
    #[serde(rename = "uptimeMs")]
    uptime_ms: Option<u64>,
    restarts: u32,
    collision: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct StatusEntry {
    profile: String,
    roles: String,
    #[serde(rename = "autoScope")]
    auto_scope: Option<String>,
    desired: u32,
    running: u32,
    workers: Vec<StatusWorker>,
}

#[derive(Serialize)]
struct WorkforceStatus {
    name: String,
    exists: bool,
    #[serde(rename = "supervisorRunning")]
    supervisor_running: bool,
    entries: Vec<StatusEntry>,
    extra: Vec<serde_json::Value>,
}

pub fn workforce_status(name: &str, json: bool) -> Result<()> {
    let home = home_dir()?;
    let manifest = read_manifest(name)?;
    let supervisor_running = supervisor_running(&home);

    let mut entries = Vec::new();
    if let Some(m) = &manifest {
        for w in &m.workers {
            let workers = (1..=w.instances)
                .map(|i| StatusWorker {
                    name: format!("wf-{name}-{}-{i}", w.profile),
                    present: false,
                    state: "absent",
                    pid: None,
                    uptime_ms: None,
                    restarts: 0,
                    collision: None,
                })
                .collect();
            entries.push(StatusEntry {
                profile: w.profile.clone(),
                roles: w.roles.clone(),
                auto_scope: None,
                desired: w.instances,
                running: 0,
                workers,
            });
        }
    }

    let status = WorkforceStatus {
        name: name.to_string(),
        exists: manifest.is_some(),
        supervisor_running,
        entries,
        extra: Vec::new(),
    };

    if json {
        println!("{}", serde_json::to_string(&status)?);
    } else if !status.exists {
        println!("Workforce \"{name}\" does not exist");
    } else {
        println!(
            "Workforce \"{name}\" — supervisor {}",
            if supervisor_running {
                "running"
            } else {
                "not running"
            }
        );
        for e in &status.entries {
            println!(
                "  {} desired {} running {} (roles: {})",
                e.profile, e.desired, e.running, e.roles
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hire_args(name: &str) -> HireArgs {
        HireArgs {
            list: false,
            json: false,
            name: Some(name.to_string()),
            rank: Some("senior".to_string()),
            command: Some("nano-coder".to_string()),
            capabilities: None,
            model: None,
            protocol: None,
            permission: None,
            sandbox: None,
            image: None,
            terminal: None,
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    /// The manifest name becomes a filename, so anything that is not a single
    /// plain path component must be rejected: an absolute name would make
    /// `Path::join` discard the home, and a `..`/separator component would
    /// climb out of `workforce/`. Fail closed on every variant.
    #[test]
    fn manifest_path_rejects_escaping_names() {
        for bad in [
            "",
            "   ",
            "/tmp/x",
            "/",
            "..",
            "../escape",
            "a/b",
            "a\\b",
            ".",
            "./x",
            "x/",
            "x//y",
        ] {
            assert!(
                manifest_path(bad).is_err(),
                "name {bad:?} must be rejected, not turned into a path"
            );
        }
    }

    #[test]
    fn manifest_path_accepts_plain_names() {
        for good in ["default", "my-fleet", "fleet_2", "x.y"] {
            let p = manifest_path(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
            assert_eq!(
                p.file_name().unwrap().to_string_lossy(),
                format!("{good}.json").as_str()
            );
            assert_eq!(p.parent().unwrap().file_name().unwrap(), "workforce");
        }
    }

    /// `state::Protocol::parse` maps an unknown stored value to `pipe`
    /// (tolerant read), so hire must reject an unknown --protocol at write
    /// time — a typo like `--protocol acpp` must fail, not silently degrade.
    #[test]
    fn hire_rejects_unknown_protocol() {
        let mut args = hire_args("coder");
        args.protocol = Some("bogus".to_string());
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("Invalid protocol \"bogus\""), "{err}");
        assert!(err.contains("acp, pipe"), "{err}");
    }

    /// A malformed repeatable --env entry must error like every other malformed
    /// hire input, not be silently dropped.
    #[test]
    fn hire_rejects_malformed_env_entries() {
        let mut args = hire_args("coder");
        args.env = vec!["NOVAL".to_string()];
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("expected KEY=VALUE"), "{err}");

        let mut args = hire_args("coder");
        args.env = vec!["=orphan".to_string()];
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("expected KEY=VALUE"), "{err}");
    }
}
