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
use std::io::Write;
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

/// The sandbox modes a hire may declare. Anything else is rejected at hire
/// time: the daemon refuses every sandbox but `none` (host), so a typo like
/// `dokcer` accepted here would persist a profile that can never run.
const VALID_SANDBOXES: [&str; 3] = ["none", "docker", "podman"];

/// The terminal transports a hire may declare. Anything else is rejected at
/// hire time, exactly as `--protocol`/`--sandbox` are: the value is persisted
/// verbatim, so a typo such as `--terminal typo` would create state no runtime
/// can interpret and the Node-compatible CLI would reject.
const VALID_TERMINALS: [&str; 2] = ["pty", "pipe"];

/// The permission policies a hire may declare. The CLI contract currently
/// implements only `yolo` — the Rust ACP client unconditionally applies the
/// yolo allow policy (`src/acp.rs`), and `escalate`/`filter` are reserved and
/// not yet enforced — so any other value (including the historical `ask`
/// default) is rejected rather than persisted as a policy that is silently not
/// honoured.
const VALID_PERMISSIONS: [&str; 1] = ["yolo"];

/// The largest supported `--instances` value for a workforce worker. `instances`
/// is a `u32`, so an unbounded value (e.g. `--instances 4294967295`) makes
/// `workforce status` eagerly construct billions of `StatusWorker` values and
/// exhaust memory. This bound is enforced both when a manifest is written
/// (`workforce add`) and when one is read for status expansion, so a hand-edited
/// or legacy manifest cannot trigger the blow-up either. 1024 is far above any
/// real fleet and matches the snapshot fixtures (which use 1–2).
const MAX_WORKER_INSTANCES: u32 = 1024;

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
    "yolo".into()
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

/// Serialize `value` to pretty JSON and commit it to `path` atomically: write a
/// deterministic sibling temp file, `fsync` it, then `rename` over `path`.
/// A same-directory rename is atomic on every supported OS, so a concurrent
/// `work`/daemon read observes either the old file or the new one — never a
/// truncated or partial `config.json` — and a crash mid-write leaves the
/// previous copy intact.
///
/// The temp name is **deterministic** (`.<file>.tmp`), not unique per
/// (pid, nanos): every writer of a given state file first takes that file's
/// `StateLock` (see `update_config`/`workforce_add`), so two writers never race
/// on this path, and a crash between `create` and `rename` leaves *at most this
/// one* temp — which the next write to the same file reuses (truncates) and
/// renames away — instead of a unique orphan per crash that would accumulate
/// forever under the state home. On the success path the temp is renamed away,
/// never left behind: the contract test `state_writes_stay_under_home` asserts
/// the exact set of files under the home, so nothing extra may persist.
fn write_json_atomic(path: &std::path::Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("state path has no valid file name")?;
    // Deterministic, lock-protected temp sibling: callers hold this file's
    // `StateLock`, so there is no cross-writer collision, and a crashed temp is
    // overwritten (not accumulated) by the next write rather than orphaned.
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp"));

    let write_result = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        f.write_all(json.as_bytes())
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        // Flush user-space buffers and fsync so the bytes are durable before
        // the rename publishes them.
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("renaming {} over {}", tmp_path.display(), path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        // Best-effort cleanup so a failed write never leaks a temp file under
        // the home (the contract asserts the exact written-file set).
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

fn write_config(cfg: &ConfigFile) -> Result<()> {
    let path = config_path()?;
    write_json_atomic(&path, cfg)
}

/// A cross-process mutual-exclusion guard for a state file's read-modify-write
/// cycle, built on an advisory `flock` (via `fs2`).
///
/// `acquire` opens a dedicated lock file and takes an exclusive `flock` on it
/// for the guard's lifetime; dropping the guard closes the file descriptor,
/// which the kernel treats as releasing the lock. This is an **OS-released**
/// lock, and that property is the whole point: if the holder crashes or is
/// killed, the kernel drops its `flock` immediately, so a contender never has
/// to decide whether an abandoned on-disk marker's owner is still alive. The
/// previous design reclaimed a marker purely by age, which could steal the lock
/// from a merely-slow owner (paused, or blocked on a slow `fsync`) and admit a
/// third writer into the same critical section — a mutual-exclusion break. With
/// `flock`, a live-but-slow holder simply makes contenders *block* until it
/// finishes (correct serialization), and a dead holder's lock is already gone.
///
/// The lock file lives in the system temp dir, keyed by a hash of the guarded
/// path — *not* under the state home — so it leaves no residue there: the
/// contract test `state_writes_stay_under_home` asserts the home's file set
/// exhaustively. This mirrors the control socket, the one other state artifact
/// the plugin keeps in the temp dir. The empty lock file itself may persist in
/// the temp dir between runs; it is reused, never a source of corruption,
/// because exclusion comes from the `flock`, not the file's existence.
struct StateLock {
    // Held for the guard's lifetime; dropping it closes the fd and releases the
    // advisory `flock`. Never read directly.
    _file: std::fs::File,
}

impl StateLock {
    /// Acquire the exclusive lock guarding `path`, blocking until any current
    /// holder — in this or another process — releases it. `path` is the guarded
    /// state file (e.g. `config.json`); the lock file is derived from it.
    fn acquire(path: &std::path::Path) -> Result<StateLock> {
        use fs2::FileExt;
        let lock_path = Self::lock_file_for(path)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The lock file lives in a shared temp dir; keep it owner-only.
            opts.mode(0o600);
        }
        let file = opts
            .open(&lock_path)
            .with_context(|| format!("opening lock {}", lock_path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("locking {}", lock_path.display()))?;
        Ok(StateLock { _file: file })
    }

    /// The lock file for `path`: `<tmp>/c8ctl-nano-fleet-<sha1(path)>.lock`.
    /// Keyed by the full guarded path, so distinct state files (and distinct
    /// state homes) never share a lock, while every writer of the *same* file
    /// contends on the *same* lock.
    fn lock_file_for(path: &std::path::Path) -> Result<PathBuf> {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(path.to_string_lossy().as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        Ok(std::env::temp_dir().join(format!("c8ctl-nano-fleet-{}.lock", &hex[..16])))
    }
}

/// Run `mutate` against the current config while holding an exclusive
/// interprocess lock, then commit the result atomically.
///
/// `hire`/`assign` are a read-modify-write over `config.json`; without
/// serialization two concurrent commands each read the pre-image and the second
/// commit silently overwrites the first's change. A `StateLock` keyed on
/// `config.json` serializes the whole read→mutate→write cycle across processes
/// (an OS-released `flock`, dropped automatically on return — including the
/// error path — and kept outside the home so the documented file set is
/// unchanged).
fn update_config<F>(mutate: F) -> Result<()>
where
    F: FnOnce(&mut ConfigFile) -> Result<()>,
{
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let _guard = StateLock::acquire(&path)?;

    // Critical section: read the latest config, mutate, commit atomically.
    let mut cfg = read_config()?;
    mutate(&mut cfg)?;
    write_config(&cfg)
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

    let sandbox = args
        .sandbox
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_sandbox);
    if !VALID_SANDBOXES.contains(&sandbox.as_str()) {
        bail!(
            "Invalid sandbox \"{}\". Valid sandboxes: {}",
            args.sandbox.as_deref().unwrap_or_default(),
            VALID_SANDBOXES.join(", ")
        );
    }

    let terminal = args
        .terminal
        .as_deref()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(default_terminal);
    if !VALID_TERMINALS.contains(&terminal.as_str()) {
        bail!(
            "Invalid terminal \"{}\". Valid terminals: {}",
            args.terminal.as_deref().unwrap_or_default(),
            VALID_TERMINALS.join(", ")
        );
    }

    let permission = args
        .permission
        .as_deref()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(default_permission);
    if !VALID_PERMISSIONS.contains(&permission.as_str()) {
        bail!(
            "Invalid permission \"{}\". Valid permissions: {}",
            args.permission.as_deref().unwrap_or_default(),
            VALID_PERMISSIONS.join(", ")
        );
    }

    let hire = StoredHire {
        name: name.clone(),
        rank: rank.clone(),
        command: command.clone(),
        args: args.args.clone(),
        model: args.model.clone().unwrap_or_default().trim().to_string(),
        capabilities: capabilities.clone(),
        sandbox,
        image: args.image.clone().unwrap_or_default(),
        terminal,
        protocol: protocol.clone(),
        permission,
        env,
        created_at: serde_json::Value::String(now_iso8601()),
    };

    // Serialize the read-modify-write against concurrent fleet commands and
    // commit atomically (see `update_config`).
    let name_for_insert = name.clone();
    let hire_for_insert = hire.clone();
    update_config(move |cfg| {
        cfg.hires.insert(name_for_insert, hire_for_insert);
        Ok(())
    })?;

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
    // `assign` SETS the capability list: starting from the old set would make a
    // stale capability impossible to remove, and the profile would keep
    // subscribing to its job types. Normalize the supplied list directly.
    let caps = normalize_capabilities(capabilities.split(',').map(|c| c.to_string()).collect());
    // Serialize the read-modify-write against concurrent fleet commands and
    // commit atomically (see `update_config`).
    let caps_for_set = caps.clone();
    let profile_owned = profile.to_string();
    update_config(move |cfg| {
        let hire = cfg
            .hires
            .get_mut(profile_owned.as_str())
            .with_context(|| format!("no hire named \"{profile_owned}\""))?;
        hire.capabilities = caps_for_set;
        Ok(())
    })?;
    println!("Reassigned {profile} — capabilities: {}", caps.join(", "));
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
    // Reject surrounding whitespace rather than silently trimming: the path is
    // derived from the trimmed name, but the manifest's stored `name`, status
    // object, worker IDs, and output all use the original string — so
    // `--name " default "` would alias `default.json` while persisting and
    // reporting a *different* name. Rejecting it prevents the ambiguous alias.
    if trimmed != name {
        return Err(bad());
    }
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
    // Same atomic commit as `config.json`: a concurrent `workforce status` /
    // daemon read must never observe a truncated manifest, and a crash mid-write
    // must not corrupt the only copy.
    write_json_atomic(&path, m)
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
    // at 1); clamp rather than persist an empty workers list. An unbounded
    // `u32`, on the other hand, lets `workforce status` allocate billions of
    // worker slots, so reject anything above the supported ceiling outright.
    if instances > MAX_WORKER_INSTANCES {
        bail!("invalid --instances {instances}: supported maximum is {MAX_WORKER_INSTANCES}");
    }
    let instances = instances.max(1);
    // The read-modify-write below is the same lost-update class as `config.json`:
    // two concurrent `workforce add <name> <a>` / `<b>` on the *same* manifest
    // each read the pre-image and the second atomic rename silently drops the
    // first's worker. `write_manifest` is atomic (a reader never sees a partial
    // file) but atomicity alone does not serialize the mutate, so guard the whole
    // read→mutate→write behind a per-manifest lock, exactly like `update_config`.
    let manifest_file = manifest_path(name)?;
    let _guard = StateLock::acquire(&manifest_file)?;
    let mut manifest = read_manifest(name)?.unwrap_or(Manifest {
        version: 1,
        name: name.to_string(),
        workers: Vec::new(),
    });
    // The write destination comes from the requested (validated) name, so bind
    // the loaded manifest to it: a manifest file whose internal `name` disagrees
    // with its filename would otherwise redirect the write to a *different*
    // file, silently leaving the requested one unchanged.
    manifest.name = name.to_string();
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
    // Test-only: widen the read→write window so the concurrency test reliably
    // overlaps two critical sections. With the lock this just serializes them
    // (green); without it the second read observes the pre-image and its rename
    // drops the first's worker (red). Compiled out of non-test builds.
    #[cfg(test)]
    std::thread::sleep(std::time::Duration::from_millis(30));
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
            // A manifest on disk may predate the `workforce add` bound or have
            // been hand-edited, so re-validate before expanding slots: an
            // out-of-range `instances` must fail here rather than allocate
            // billions of `StatusWorker` values.
            if w.instances > MAX_WORKER_INSTANCES {
                bail!(
                    "workforce \"{name}\" worker \"{}\" declares {} instances, above the supported maximum of {MAX_WORKER_INSTANCES}",
                    w.profile,
                    w.instances
                );
            }
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

    /// The daemon refuses every sandbox but `none` (host), so hire must reject
    /// an unknown --sandbox at write time — a typo like `dokcer` must fail, not
    /// persist a profile that can never run.
    #[test]
    fn hire_rejects_unknown_sandbox() {
        let cfg = TempCfg::new();
        let mut args = hire_args("coder");
        args.sandbox = Some("dokcer".to_string());
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("Invalid sandbox \"dokcer\""), "{err}");
        assert!(err.contains("none, docker, podman"), "{err}");

        for ok in ["none", "docker", "podman", " Docker "] {
            let mut args = hire_args("coder");
            args.sandbox = Some(ok.to_string());
            hire(args).unwrap_or_else(|e| panic!("sandbox {ok:?}: {e}"));
        }
        drop(cfg);
    }

    /// `--terminal` is persisted verbatim and no runtime can interpret an
    /// unknown transport, so hire must reject a typo like `--terminal typo`
    /// (normalizing case/whitespace), exactly as it does for protocol/sandbox.
    #[test]
    fn hire_rejects_unknown_terminal() {
        let cfg = TempCfg::new();
        let mut args = hire_args("coder");
        args.terminal = Some("typo".to_string());
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("Invalid terminal \"typo\""), "{err}");
        assert!(err.contains("pty, pipe"), "{err}");

        for ok in ["pty", "pipe", " PIPE "] {
            let mut args = hire_args("coder");
            args.terminal = Some(ok.to_string());
            hire(args).unwrap_or_else(|e| panic!("terminal {ok:?}: {e}"));
        }
        drop(cfg);
    }

    /// Only `yolo` is implemented (the ACP client unconditionally auto-allows);
    /// a reserved-but-unenforced value like `ask`/`escalate` must be rejected,
    /// not persisted as a policy that is silently not honoured. The default
    /// (no `--permission`) must also resolve to `yolo`, never `ask`.
    #[test]
    fn hire_rejects_unsupported_permission() {
        let cfg = TempCfg::new();
        for bad in ["ask", "escalate", "filter", "typo"] {
            let mut args = hire_args("coder");
            args.permission = Some(bad.to_string());
            let err = hire(args).unwrap_err().to_string();
            assert!(err.contains("Invalid permission"), "{bad}: {err}");
            assert!(err.contains("yolo"), "{bad}: {err}");
        }

        for ok in ["yolo", " YOLO "] {
            let mut args = hire_args("coder");
            args.permission = Some(ok.to_string());
            hire(args).unwrap_or_else(|e| panic!("permission {ok:?}: {e}"));
        }

        // Omitting --permission defaults to the only implemented policy, yolo.
        hire(hire_args("defaulted")).unwrap();
        let stored = read_config().unwrap();
        assert_eq!(stored.hires["defaulted"].permission, "yolo");
        drop(cfg);
    }

    /// `assign` SETS the capability list: a stale capability must be removable,
    /// not merged back in from the old set.
    #[test]
    fn assign_replaces_capabilities() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        assign("coder", "feature,pr-review").unwrap();
        assign("coder", "fix").unwrap();
        let cfg = read_config().unwrap();
        assert_eq!(
            cfg.hires["coder"].capabilities,
            vec!["fix".to_string()],
            "assign must replace, not merge with, the old set"
        );
    }

    /// The write destination comes from the requested name: a manifest whose
    /// internal `name` disagrees with its filename must not redirect the write.
    #[test]
    fn workforce_add_binds_manifest_to_requested_name() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        let dir = home_dir().unwrap().join("workforce");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("default.json"),
            "{\"version\":1,\"name\":\"other\",\"workers\":[]}",
        )
        .unwrap();
        workforce_add("default", "coder", 1, "auto").unwrap();
        let m = read_manifest("default").unwrap().unwrap();
        assert_eq!(m.name, "default");
        assert_eq!(m.workers.len(), 1);
        assert!(
            !dir.join("other.json").exists(),
            "the internal name must not redirect the write to other.json"
        );
    }

    /// A workforce name with surrounding whitespace must be rejected, not
    /// trimmed for the path while persisted/reported untrimmed — otherwise
    /// `--name " default "` aliases `default.json` under a different name.
    #[test]
    fn manifest_path_rejects_surrounding_whitespace() {
        for bad in [
            " default",
            "default ",
            " default ",
            "\tdefault",
            "default\n",
        ] {
            assert!(
                manifest_path(bad).is_err(),
                "name {bad:?} must be rejected, not aliased to a trimmed path"
            );
        }
        // Interior whitespace is a single normal component and stays allowed.
        assert!(manifest_path("my fleet").is_ok());
    }

    /// `workforce add` must reject an `instances` value above the supported
    /// ceiling rather than persist a manifest whose status expansion would
    /// exhaust memory.
    #[test]
    fn workforce_add_rejects_unbounded_instances() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        let err = workforce_add("default", "coder", u32::MAX, "auto")
            .unwrap_err()
            .to_string();
        assert!(err.contains("supported maximum"), "{err}");
        assert!(
            read_manifest("default").unwrap().is_none(),
            "an over-large instances value must not persist a manifest"
        );
        // The ceiling itself is accepted.
        workforce_add("default", "coder", MAX_WORKER_INSTANCES, "auto").unwrap();
        let m = read_manifest("default").unwrap().unwrap();
        assert_eq!(m.workers[0].instances, MAX_WORKER_INSTANCES);
    }

    /// A manifest that already holds an out-of-range `instances` (hand-edited or
    /// written before the bound existed) must make `workforce status` fail, not
    /// allocate billions of worker slots.
    #[test]
    fn workforce_status_rejects_over_large_manifest() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        let dir = home_dir().unwrap().join("workforce");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("default.json"),
            "{\"version\":1,\"name\":\"default\",\"workers\":[{\"profile\":\"coder\",\"instances\":4294967295,\"roles\":\"auto\"}]}",
        )
        .unwrap();
        let err = workforce_status("default", false).unwrap_err().to_string();
        assert!(err.contains("supported maximum"), "{err}");
    }

    /// `hire` must commit `config.json` atomically and leave no temp or lock
    /// file behind: the home keeps exactly the documented file set. The
    /// `StateLock` is an `flock` on a temp-dir file (not under the home), and
    /// the atomic write renames its deterministic temp away, so after the
    /// command returns nothing but `config.json` may remain under the home.
    #[test]
    fn hire_writes_config_atomically_without_residue() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        let home = home_dir().unwrap();
        assert!(home.join("config.json").is_file());
        let mut leftover: Vec<_> = std::fs::read_dir(&home)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "config.json")
            .collect();
        leftover.sort();
        assert!(
            leftover.is_empty(),
            "no temp/lock file may persist under the home, found: {leftover:?}"
        );
        // The committed config parses and holds the hire.
        let cfg = read_config().unwrap();
        assert!(cfg.hires.contains_key("coder"));
    }

    /// Two `update_config` mutations running on *concurrent* threads both
    /// survive: the lock serializes them, so the second observes the first's
    /// committed change rather than overwriting it from a stale pre-image. A
    /// sequential pair would pass even against the old unlocked code, so this
    /// spawns real threads (red before the lock, green after).
    #[test]
    fn update_config_serializes_read_modify_write() {
        let _cfg = TempCfg::new();
        // Release both hires together so their read-modify-write cycles overlap
        // as much as the scheduler allows; without the lock one is lost.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for name in ["a", "b"] {
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                hire(hire_args(name))
            }));
        }
        for h in handles {
            h.join().unwrap().unwrap();
        }
        let cfg = read_config().unwrap();
        assert!(
            cfg.hires.contains_key("a") && cfg.hires.contains_key("b"),
            "both concurrent hires must survive; a lost update would drop one"
        );
    }

    /// Concurrent `workforce add` of *different* profiles onto the *same*
    /// manifest both survive: the per-manifest lock serializes the
    /// read-modify-write, so the second add observes the first's committed
    /// worker instead of renaming over it. This is the manifest half of the
    /// lost-update class (Copilot's "also appears on line 499"); a sequential
    /// pair would not exercise the lock, so this spawns real threads.
    #[test]
    fn workforce_add_serializes_concurrent_manifest_updates() {
        let _cfg = TempCfg::new();
        // Both profiles must exist so `workforce_add` passes its hire check.
        hire(hire_args("a")).unwrap();
        hire(hire_args("b")).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for profile in ["a", "b"] {
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                workforce_add("default", profile, 1, "auto")
            }));
        }
        for h in handles {
            h.join().unwrap().unwrap();
        }
        let manifest = read_manifest("default").unwrap().unwrap();
        let mut profiles: Vec<_> = manifest.workers.iter().map(|w| w.profile.as_str()).collect();
        profiles.sort();
        assert_eq!(
            profiles,
            vec!["a", "b"],
            "both concurrent adds must survive; a lost update would drop one worker"
        );
    }

    /// A minimal `C8CTL_NANO_HOME` guard: points the state home at a fresh temp
    /// dir for the duration of a state-mutating test. Tests mutate the process
    /// environment, so they must not run concurrently — a process-wide mutex
    /// held for the guard's lifetime serializes them.
    struct TempCfg {
        home: std::path::PathBuf,
        prev: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    impl TempCfg {
        fn new() -> Self {
            let guard = env_lock().lock().unwrap();
            let home = std::env::temp_dir().join(format!(
                "fleet-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&home).unwrap();
            let prev = std::env::var_os("C8CTL_NANO_HOME");
            std::env::set_var("C8CTL_NANO_HOME", &home);
            Self {
                home,
                prev,
                _guard: guard,
            }
        }
    }

    impl Drop for TempCfg {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("C8CTL_NANO_HOME", v),
                None => std::env::remove_var("C8CTL_NANO_HOME"),
            }
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }
}
