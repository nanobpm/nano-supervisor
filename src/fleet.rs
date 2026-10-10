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
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::control;
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

/// The permission policies a hire may declare. The Node 1.70.1 surface accepts
/// and persists all three; only `yolo` is *enforced* today (the Rust ACP client
/// unconditionally applies the yolo allow policy, `src/acp.rs`), while
/// `escalate`/`filter` are RESERVED (pending nano-workforce#559) and behave like
/// `yolo`. They are still accepted and persisted verbatim for forward- and
/// drop-in-compatibility — rejecting them would make existing valid Node hire
/// commands fail — so the caller warns that a reserved mode is not yet enforced.
const VALID_PERMISSIONS: [&str; 3] = ["yolo", "escalate", "filter"];

/// The largest supported `--instances` value for a workforce worker, matching
/// the Node `MAX_ADD_INSTANCES` per-entry cap. `instances` is a `u32`, so an
/// unbounded value (e.g. `--instances 4294967295`) makes `workforce status`
/// eagerly construct billions of `StatusWorker` values and exhaust memory. This
/// bound is enforced both when a manifest is written (`workforce add`) and when
/// one is read for status expansion, so a hand-edited or legacy manifest cannot
/// trigger the blow-up either. 64 matches the Node target exactly, so a manifest
/// written here is one the Node target accepts (and vice versa).
const MAX_WORKER_INSTANCES: u32 = 64;

/// The established character set for a profile (hire) name and a workforce
/// manifest name: `[A-Za-z0-9][A-Za-z0-9._-]*` (Node's `isValidProfileName` /
/// `isValidManifestName`). The name rides in worker IDs and the manifest
/// filename, so a space, separator, or control character would either fail later
/// or (for a manifest) climb out of `workforce/`. Matched case-insensitively.
fn is_valid_name_charset(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The established character set for an environment variable name:
/// `[A-Za-z_][A-Za-z0-9_]*` (Node's `ENV_NAME_RE`). Persisting an invalid name
/// would make Rust state differ from Node and fail only later when the agent is
/// spawned.
fn is_valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One persisted hire in `config.json`. The field order is the golden order the
/// `config_after_hire` snapshot pins; a `#[derive(Serialize)]` struct always
/// emits its fields in declaration order (independent of serde_json's
/// `preserve_order` feature), so writing through this type keeps the on-disk
/// key order stable.
///
/// The trailing `other` map captures every field this struct does NOT model
/// (e.g. the `updatedAt` an `assign` stamps, or a field a future plugin version
/// adds). Without it, deserializing a hire into this closed struct and rewriting
/// the config would silently drop those fields from *every* hire on any
/// unrelated `hire`/`assign` — violating in-place compatibility with Node. The
/// map is empty for a freshly created hire, so the golden `config_after_hire`
/// shape (exactly the modelled fields) is unchanged.
#[derive(Clone, Serialize, Deserialize)]
struct StoredHire {
    name: String,
    rank: String,
    command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sandbox: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    env: Option<BTreeMap<String, String>>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    created_at: Option<serde_json::Value>,
    /// Unmodelled per-profile fields, preserved verbatim across a rewrite.
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
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
    match read_confined(&path)? {
        None => Ok(ConfigFile::default()),
        Some(bytes) => {
            serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
        }
    }
}

/// Serialize `value` to pretty JSON and commit it to `path` atomically: write a
/// deterministic sibling temp file, `fsync` it, then `rename` over `path`.
/// A same-directory rename is atomic on every supported OS, so a concurrent
/// `work`/daemon read observes either the old file or the new one — never a
/// truncated or partial `config.json` — and a crash mid-write leaves the
/// previous copy intact.
///
/// On Unix, the configured state home is the **trusted anchor**: it is opened
/// *following* symlinks (the operator may legitimately point `C8CTL_NANO_HOME`
/// at a symlink — e.g. macOS's `/var` -> `/private/var` — and `hire`/`assign`
/// already read through such a home), and then every path component *below* the
/// home is opened with `O_NOFOLLOW` via that pinned directory fd (`openat`,
/// `renameat`, `unlinkat`). So a symlinked state home no longer makes every
/// write fail with `ELOOP`/`ENOTDIR` while reads succeed, yet a planted symlink
/// anywhere in the operator-controlled tail (a symlinked descendant directory or
/// a `.<file>.tmp` entry) is still refused and a parent-dir swap after the walk
/// cannot redirect the write. The lock identity (control-socket hash) keeps the
/// caller's original path spelling, not the resolved anchor. Non-Unix builds keep
/// the plain filesystem fallback.
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
fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');

    #[cfg(unix)]
    {
        write_json_atomic_unix(path, json.as_bytes())
    }
    #[cfg(not(unix))]
    {
        write_json_atomic_fallback(path, json.as_bytes())
    }
}

#[cfg(unix)]
struct RawFdGuard(libc::c_int);

#[cfg(unix)]
impl Drop for RawFdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

#[cfg(unix)]
impl RawFdGuard {
    fn into_file(mut self) -> std::fs::File {
        use std::os::fd::FromRawFd;
        let fd = self.0;
        self.0 = -1;
        unsafe { std::fs::File::from_raw_fd(fd) }
    }
}

#[cfg(unix)]
fn cstring_from_path(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains NUL byte: {}", path.display()))
}

#[cfg(unix)]
fn cstring_from_component(name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).context("state path component contains NUL byte")
}

#[cfg(unix)]
fn temp_component_for(file_name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = Vec::with_capacity(file_name.as_bytes().len() + 5);
    bytes.push(b'.');
    bytes.extend_from_slice(file_name.as_bytes());
    bytes.extend_from_slice(b".tmp");
    std::ffi::CString::new(bytes).context("state temp path component contains NUL byte")
}

/// Open the directory that holds `path`, confined to the trusted state home.
///
/// The configured state home is the TRUSTED ANCHOR: open it *following* symlinks
/// (a symlinked home is operator-controlled trust, not an attacker-plantable
/// tail component), then walk every component BELOW it with `O_NOFOLLOW` so a
/// planted symlink in the operator-controlled tail cannot redirect an access out
/// of the home. For `config.json` the parent IS the anchor, so there is no tail
/// to walk and a symlinked home is simply resolved; for `workforce/<name>.json`
/// the `workforce` component is opened no-follow. Paths outside the home fail
/// closed. Both the read and the write path pin their target through this same
/// handle, so reads honour the exact same confinement invariant as writes.
#[cfg(unix)]
fn open_confined_parent(path: &Path) -> Result<RawFdGuard> {
    let parent = path
        .parent()
        .context("state path has no parent directory")?;
    let anchor = home_dir()?;
    let tail = parent.strip_prefix(&anchor).map_err(|_| {
        anyhow::anyhow!(
            "state path {} is not under the trusted state home {}",
            path.display(),
            anchor.display()
        )
    })?;

    let anchor_c = cstring_from_path(&anchor)?;
    let anchor_fd = unsafe {
        libc::open(
            anchor_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if anchor_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening trusted state home: {}", anchor.display()));
    }
    let mut dirfd = RawFdGuard(anchor_fd);

    for component in tail.components() {
        let name = match component {
            std::path::Component::Normal(name) => name,
            std::path::Component::CurDir => continue,
            other => bail!(
                "state path {} escapes the trusted state home via {:?}",
                path.display(),
                other
            ),
        };
        let name_c = cstring_from_component(name)?;
        let fd = unsafe {
            libc::openat(
                dirfd.0,
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "opening state directory without following symlinks: {}",
                    parent.display()
                )
            });
        }
        dirfd = RawFdGuard(fd);
    }

    Ok(dirfd)
}

/// True if any link in the error chain is an OS `NotFound` (`ENOENT`). Used by
/// the confined read to map "the file (or a directory above it) does not exist"
/// to `None` while still surfacing a symlinked/foreign tail (`ELOOP`/`ENOTDIR`)
/// as a hard error.
#[cfg(unix)]
fn chain_is_not_found(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    })
}

/// Read a state file confined to the trusted home: the home is the trusted
/// anchor (opened following symlinks), every component below it — INCLUDING the
/// file itself — is opened `O_NOFOLLOW`, and the opened file is verified to be a
/// regular file before its bytes are returned. So a symlinked `config.json`,
/// a symlinked `workforce/` tail, or a symlinked manifest can no longer make a
/// read escape the home — the exact confinement invariant the write path
/// enforces. `Ok(None)` means the file is simply absent (missing file, or a
/// missing directory above it); `Err` means a planted symlink/foreign entry or
/// a real I/O failure.
#[cfg(unix)]
fn read_confined(path: &Path) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file_name = path.file_name().context("state path has no file name")?;
    let final_c = cstring_from_component(file_name)?;

    let dirfd = match open_confined_parent(path) {
        Ok(fd) => fd,
        // A missing anchor or tail directory means the file cannot exist; mirror
        // the previous `path.exists()` check and report it absent rather than an
        // error. A symlinked/foreign tail surfaces as a non-`NotFound` error.
        Err(e) if chain_is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };

    let fd = unsafe {
        libc::openat(
            dirfd.0,
            final_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err).with_context(|| {
            format!(
                "opening state file without following symlinks: {}",
                path.display()
            )
        });
    }
    let fd = RawFdGuard(fd);

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.0, &mut st) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("statting state file {}", path.display()));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        bail!("state path is not a regular file: {}", path.display());
    }

    let mut f = fd.into_file();
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn read_confined(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(unix)]
fn write_json_atomic_unix(path: &Path, json: &[u8]) -> Result<()> {
    let file_name = path.file_name().context("state path has no file name")?;
    let final_c = cstring_from_component(file_name)?;
    let tmp_c = temp_component_for(file_name)?;

    let dirfd = open_confined_parent(path)?;

    let write_result = (|| -> Result<()> {
        let fd = unsafe {
            libc::openat(
                dirfd.0,
                tmp_c.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("creating temp state file next to {}", path.display()));
        }
        let fd = RawFdGuard(fd);

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.0, &mut st) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("statting temp state file next to {}", path.display()));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            bail!(
                "temp state path is not a regular file: .{}.tmp",
                file_name.to_string_lossy()
            );
        }
        if unsafe { libc::fchmod(fd.0, 0o600) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("restricting temp state file next to {}", path.display())
            });
        }

        let mut f = fd.into_file();
        f.write_all(json)
            .with_context(|| format!("writing temp state file next to {}", path.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing temp state file next to {}", path.display()))?;
        drop(f);

        if unsafe { libc::renameat(dirfd.0, tmp_c.as_ptr(), dirfd.0, final_c.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("renaming temp state file over {}", path.display()));
        }
        Ok(())
    })();

    if write_result.is_err() {
        unsafe {
            libc::unlinkat(dirfd.0, tmp_c.as_ptr(), 0);
        }
    }
    write_result
}

#[cfg(not(unix))]
fn write_json_atomic_fallback(path: &Path, json: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("state path has no valid file name")?;
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp"));
    let write_result = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        f.write_all(json)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("renaming {} over {}", tmp_path.display(), path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

fn write_config(cfg: &ConfigFile) -> Result<()> {
    let path = config_path()?;
    write_json_atomic(&path, cfg)
}

fn normalized_identity(path: &Path) -> PathBuf {
    let mut suffix = Vec::new();
    if let Some(file_name) = path.file_name() {
        suffix.push(file_name.to_os_string());
    }

    let mut anchor = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    while !anchor.exists() {
        match anchor.file_name() {
            Some(name) => {
                suffix.push(name.to_os_string());
                anchor = anchor
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
            }
            None => break,
        }
    }

    let mut identity = std::fs::canonicalize(anchor).unwrap_or_else(|_| {
        if anchor.is_absolute() {
            anchor.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(anchor)
        }
    });
    for component in suffix.iter().rev() {
        identity.push(component);
    }
    identity
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
/// The lock file lives in an **owner-private per-user directory**
/// (`<base>/c8ctl-nano-fleet-<uid>/`, where `<base>` is the single stable
/// per-user anchor derived from the UID's passwd home — see `lock_base_dir` for
/// why it is derived from the UID, *not* from `$HOME` or an environment-dependent
/// precedence chain), keyed by a hash of the
/// guarded path — *not* under the state home, so it
/// leaves no residue there: the contract test `state_writes_stay_under_home`
/// asserts the home's file set exhaustively. Preferring a user-private base
/// means another local user cannot even pre-create the lock subdir; the
/// directory is additionally created `0700` and verified to be a real directory
/// (not a symlink) owned by the current user with no group/other access, and
/// each lock file is opened `O_NOFOLLOW` and verified to be a regular file we
/// own. A predictable name *directly* under world-writable `/tmp` would
/// otherwise let another local user pre-create the path (as a mode-000 file or a
/// symlink), wedging every `hire`/`assign`/`workforce add` for the known home
/// with `EACCES`/`ELOOP` — the same pre-creation threat `default_runs_dir`
/// avoids with the same precedence. The empty lock file itself may persist
/// between runs; it is reused, never a source of corruption, because exclusion
/// comes from the `flock`, not the file's existence.
struct StateLock {
    // Held for the guard's lifetime; dropping it closes the fd and releases the
    // advisory `flock`. Never read directly.
    _file: std::fs::File,
}

/// The owner-private directory that holds the fleet lock files. Created `0700`
/// if absent, then verified to be a real directory (not a symlink), owned by the
/// current user, with no group/other permission bits — so no other local user
/// can have pre-created it to plant or redirect our lock files. Returns the
/// verified path.
#[cfg(unix)]
fn fleet_lock_dir() -> Result<PathBuf> {
    fleet_lock_dir_in(&lock_base_dir())
}

/// Base directory under which the owner-private lock directory is created.
///
/// This is a **single stable per-user anchor**, derived purely from the process
/// UID via the system account database (`getpwuid`) — deliberately *not* read
/// from the environment at all. The lock's job is to serialize the
/// read-modify-write of one guarded state file across *every* process that
/// targets it; that only works if those processes all derive the *same* lock
/// path. Environment variables cannot provide that guarantee: an earlier design
/// preferred `$XDG_RUNTIME_DIR` / `$XDG_STATE_HOME` before `$HOME`, but those
/// vary independently of the guarded path, and even `$HOME` alone is not safe —
/// a service (cron, systemd with a reduced environment) frequently runs with
/// `$HOME` *unset*, while an interactive shell for the same user has it set, so
/// two processes targeting the *same* `C8CTL_NANO_HOME` would resolve
/// *different* lock files and never serialize — a silent mutual-exclusion break.
///
/// Keying the anchor on the UID's passwd home (`<pw_dir>/.local/state/c8ctl-nano`)
/// removes the environment from the equation entirely: the same user resolves
/// the same home regardless of `$HOME`/XDG state, and the location stays
/// user-private (no other local user can pre-create entries under our home, so
/// the pre-creation DoS the owner/mode checks guard against cannot even be
/// staged). Only when the UID has *no* account entry at all (e.g. an anonymous
/// container UID) do we fall back to the shared system temp dir — and even then
/// the fallback is UID-only, so two such processes still converge on the same
/// path, where `fleet_lock_dir_in`'s ownership/permission verification still
/// fails closed on a foreign pre-created directory.
#[cfg(unix)]
fn lock_base_dir() -> PathBuf {
    if let Some(home) = passwd_home_dir() {
        return home.join(".local/state/c8ctl-nano");
    }
    std::env::temp_dir()
}

/// The current user's home directory as recorded in the system account database
/// (`getpwuid_r`), resolved from the UID alone and therefore **independent of
/// the `$HOME` environment variable**. This is the stable per-user anchor the
/// lock base needs so that processes with differing environments (e.g. a login
/// shell vs. a reduced-environment service) still agree on one lock path.
/// Returns `None` only when the UID has no account entry, or that entry records
/// no home directory — a degenerate case the caller handles with a UID-only
/// temp-dir fallback.
#[cfg(unix)]
fn passwd_home_dir() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let uid = unsafe { libc::getuid() };
    let mut bufsize = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n > 0 => n as usize,
        _ => 1024,
    };
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; bufsize];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd`, `buf` and `result` all outlive the call; `buf` is
        // `bufsize` bytes long. On success `result` is either null ("no entry
        // for this UID") or points at `pwd`, whose `pw_dir` borrows from `buf`
        // — we copy it out before `buf` is dropped.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), bufsize, &mut result) };
        if rc == libc::ERANGE && bufsize < (1usize << 20) {
            // Entry larger than the buffer; grow (bounded) and retry.
            bufsize *= 2;
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
        let bytes = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }.to_bytes();
        if bytes.is_empty() {
            return None;
        }
        return Some(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())));
    }
}

#[cfg(unix)]
fn fleet_lock_dir_in(base: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let dir = base.join(format!("c8ctl-nano-fleet-{}", crate::current_user_id()));
    // Create any missing parent of the lock directory (e.g. `~/.local/state`),
    // then create the lock directory itself `0700`. The parent's own mode is not
    // our trust root — the lock directory below is verified owner-only next.
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating lock directory parent {}", parent.display()))?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(e).with_context(|| format!("creating lock directory {}", dir.display()))
        }
    }
    // `symlink_metadata` does NOT follow a final symlink, so a pre-planted
    // symlink named like our dir is caught here instead of being trusted.
    let meta = std::fs::symlink_metadata(&dir)
        .with_context(|| format!("statting lock directory {}", dir.display()))?;
    if !meta.file_type().is_dir() {
        bail!(
            "lock directory {} is not a directory (possible pre-creation attack)",
            dir.display()
        );
    }
    let uid = unsafe { libc::getuid() };
    if meta.uid() != uid {
        bail!(
            "lock directory {} is not owned by the current user (possible pre-creation attack)",
            dir.display()
        );
    }
    if meta.mode() & 0o077 != 0 {
        bail!(
            "lock directory {} is accessible to other users; refusing to use it",
            dir.display()
        );
    }
    Ok(dir)
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
            // Keep it owner-only, and never follow a symlink in the lock file's
            // place: inside the verified owner-private directory no other user
            // can plant one, but refuse rather than follow if one somehow exists.
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts
            .open(&lock_path)
            .with_context(|| format!("opening lock {}", lock_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file
                .metadata()
                .with_context(|| format!("statting lock {}", lock_path.display()))?;
            if !meta.file_type().is_file() {
                bail!("lock {} is not a regular file", lock_path.display());
            }
            if meta.uid() != unsafe { libc::getuid() } {
                bail!(
                    "lock {} is not owned by the current user; refusing to use it",
                    lock_path.display()
                );
            }
        }
        file.lock_exclusive()
            .with_context(|| format!("locking {}", lock_path.display()))?;
        Ok(StateLock { _file: file })
    }

    /// The lock file for `path`:
    /// `<base>/c8ctl-nano-fleet-<uid>/c8ctl-nano-fleet-<sha1(identity)>.lock`.
    /// Keyed by a normalized absolute identity for the guarded file, so distinct
    /// state files (and distinct state homes) never share a lock, while relative
    /// and absolute spellings of the *same* file contend on the *same* lock. The
    /// containing directory is owner-private and verified (see `fleet_lock_dir`).
    fn lock_file_for(path: &std::path::Path) -> Result<PathBuf> {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        let identity = normalized_identity(path);
        hasher.update(identity.to_string_lossy().as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        #[cfg(unix)]
        {
            Ok(fleet_lock_dir()?.join(format!("c8ctl-nano-fleet-{}.lock", &hex[..16])))
        }
        #[cfg(not(unix))]
        {
            Ok(std::env::temp_dir().join(format!("c8ctl-nano-fleet-{}.lock", &hex[..16])))
        }
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
    // The profile name participates in worker IDs (`wf-<manifest>-<name>-<i>`),
    // so it must match the established character set, not merely be non-empty.
    if !is_valid_name_charset(&name) {
        bail!("Invalid profile name \"{name}\". Use letters, digits, dot, dash or underscore.");
    }
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
            // Never echo the VALUE in a diagnostic — a user may pass a secret
            // via `--env` (e.g. `--env =SECRET`), and printing it would leak it
            // to stderr / CI logs. Report only that the name is empty, matching
            // the reference parser's deliberate value-hiding.
            Some(("", _)) => {
                bail!("invalid --env entry: expected KEY=VALUE with a non-empty key (value hidden)")
            }
            Some((k, v)) => {
                if !is_valid_env_name(k) {
                    bail!(
                        "invalid --env name \"{k}\": must match [A-Za-z_][A-Za-z0-9_]* (value hidden)"
                    );
                }
                env.insert(k.to_string(), v.to_string());
            }
            None => bail!("invalid --env entry: expected KEY=VALUE (value hidden)"),
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

    let image = args.image.clone().unwrap_or_default().trim().to_string();
    // A container sandbox is unlaunchable without an image; the reference CLI
    // rejects `docker`/`podman` unless `--image` is non-empty, rather than
    // persisting a profile that can never run.
    if matches!(sandbox.as_str(), "docker" | "podman") && image.is_empty() {
        bail!(
            "--sandbox {sandbox} requires --image <ref> (the container image the agent runs in)."
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
    // escalate/filter are accepted and persisted for forward-compatibility, but
    // not yet enforced (pending nano-workforce#559) — warn so a hire is never
    // misread as gating destructive ops today. The value is kept as given.
    if permission == "escalate" || permission == "filter" {
        eprintln!(
            "warning: permission policy \"{permission}\" is RESERVED and not yet enforced in this build (pending nano-workforce#559); it effectively behaves like yolo (auto-allow all) and is persisted as-is."
        );
    }

    let hire = StoredHire {
        name: name.clone(),
        rank: rank.clone(),
        command: command.clone(),
        args: Some(args.args.clone()),
        model: Some(args.model.clone().unwrap_or_default().trim().to_string()),
        capabilities: Some(capabilities.clone()),
        sandbox: Some(sandbox),
        image: Some(image),
        terminal: Some(terminal),
        protocol: Some(protocol.clone()),
        permission: Some(permission),
        env: Some(env),
        created_at: Some(serde_json::Value::String(now_iso8601())),
        // A freshly created hire has no unmodelled fields to preserve.
        other: BTreeMap::new(),
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
    println!(
        "  permission: {}",
        hire.permission.as_deref().unwrap_or("yolo")
    );
    Ok(())
}

/// POSIX single-quote a token so it survives `sh -c` as one literal argv token,
/// matching the Node `shQuote` (`'` → `'\''`, empty → `''`).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Build the harness command line exactly like the Node `buildAgentCommandLine`:
/// with no structured args the command is used verbatim (preserving hires that
/// baked switches into the command); otherwise the command followed by each
/// arg shell-quoted.
fn build_agent_command_line(command: &str, args: &[String]) -> String {
    if args.is_empty() {
        return command.to_string();
    }
    let quoted: Vec<String> = args.iter().map(|a| sh_quote(a)).collect();
    format!("{} {}", command, quoted.join(" "))
}

/// One `hire --list` line, reproducing the Node 1.70.1 surface exactly (scripts
/// parse it): the command line includes any persisted `--arg`s; empty model and
/// capabilities print as `-`; and the optional `terminal`/`protocol`/`permission`
/// fields are appended only when they hold a non-default value (`pty`, `acp`, or
/// a recognized non-`yolo` permission respectively).
fn hire_line(h: &StoredHire) -> String {
    let model_value = h.model.as_deref().unwrap_or("");
    let model = if model_value.is_empty() {
        "-"
    } else {
        model_value
    };
    let caps_value = h.capabilities.as_deref().unwrap_or(&[]);
    let caps = if caps_value.is_empty() {
        "-".to_string()
    } else {
        caps_value.join(", ")
    };
    let mut optional = String::new();
    if h.terminal
        .as_deref()
        .unwrap_or("pipe")
        .trim()
        .eq_ignore_ascii_case("pty")
    {
        optional.push_str("; terminal: pty");
    }
    if h.protocol
        .as_deref()
        .unwrap_or("pipe")
        .trim()
        .eq_ignore_ascii_case("acp")
    {
        optional.push_str("; protocol: acp");
    }
    // Only surface recognized non-default permission modes; unknown/legacy
    // values are coerced back to yolo at runtime, so showing them here would
    // make --list disagree with actual behavior.
    let perm = h
        .permission
        .as_deref()
        .unwrap_or("yolo")
        .trim()
        .to_ascii_lowercase();
    if perm != "yolo" && VALID_PERMISSIONS.contains(&perm.as_str()) {
        optional.push_str(&format!("; permission: {perm}"));
    }
    format!(
        "  {}  [{}]  {}  (model: {}; caps: {}{})",
        h.name,
        h.rank,
        build_agent_command_line(&h.command, h.args.as_deref().unwrap_or(&[])),
        model,
        caps,
        optional
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
        hire.capabilities = Some(caps_for_set);
        hire.other.insert(
            "updatedAt".to_string(),
            serde_json::Value::String(now_iso8601()),
        );
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
    let sock = control::socket_path(home);
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

#[cfg(not(unix))]
fn supervisor_running(_home: &std::path::Path) -> bool {
    false
}

/// `supervisor` subcommands this target implements.
pub enum SupervisorOp {
    Status,
    Start { workers: Vec<String>, attach: bool },
    Stop { force: bool },
    Add { profile: String },
}

pub fn supervisor(op: SupervisorOp) -> Result<()> {
    let home = home_dir()?;
    match op {
        SupervisorOp::Status => supervisor_status(&home),
        SupervisorOp::Start { workers, attach } => supervisor_start(&home, &workers, attach),
        SupervisorOp::Stop { force } => supervisor_stop(&home, force),
        SupervisorOp::Add { profile } => {
            let cfg = read_config()?;
            if !cfg.hires.contains_key(&profile) {
                bail!("no hire named \"{profile}\"");
            }
            if !supervisor_running(&home) {
                bail!("Supervisor not running; start it with: nano-supervisor supervisor start");
            }
            // Dynamic worker management over the live socket (`add`/`remove`/
            // `restart`/`reload`) lands with the daemon's worker manager
            // (nanobpm/nano-supervisor#8); the daemon currently answers `add`
            // with a clean "not yet implemented" frame.
            bail!("supervisor add against a live daemon is not yet implemented on the Rust target");
        }
    }
}

/// `supervisor status`: print "not running" when no daemon is bound, else query
/// the control socket and render the live daemon descriptor and worker roster.
fn supervisor_status(home: &std::path::Path) -> Result<()> {
    if !supervisor_running(home) {
        println!("Supervisor not running");
        return Ok(());
    }
    let sock = control::socket_path(home);
    match control::request(&sock, &serde_json::json!({ "op": "status" })) {
        Ok(frames) => {
            let frame = frames
                .iter()
                .find(|f| f.get("final").and_then(|v| v.as_bool()).unwrap_or(false))
                .or_else(|| frames.last());
            match frame {
                Some(f) => {
                    let pid = f["daemon"]["pid"].as_u64();
                    let workers = f["workers"].as_array().map(|w| w.len()).unwrap_or(0);
                    match pid {
                        Some(pid) => println!("Supervisor running (pid {pid}); {workers} worker(s)"),
                        None => println!("Supervisor running; {workers} worker(s)"),
                    }
                    if let Some(ws) = f["workers"].as_array() {
                        for w in ws {
                            let id = w["id"].as_str().unwrap_or("?");
                            let profile = w["profile"].as_str().unwrap_or("?");
                            let state = w["state"].as_str().unwrap_or("?");
                            println!("  {id} [{profile}] {state}");
                        }
                    }
                }
                None => println!("Supervisor running"),
            }
            Ok(())
        }
        // Socket vanished between the probe and the request (a race with
        // shutdown): report the honest "not running" rather than an error.
        Err(_) => {
            println!("Supervisor not running");
            Ok(())
        }
    }
}

/// `supervisor stop [--force]`: ask a running daemon to drain and exit.
fn supervisor_stop(home: &std::path::Path, force: bool) -> Result<()> {
    if !supervisor_running(home) {
        println!("Supervisor not running");
        return Ok(());
    }
    let sock = control::socket_path(home);
    match control::request(&sock, &serde_json::json!({ "op": "stop", "force": force })) {
        Ok(_) => {
            println!("Supervisor stopping");
            Ok(())
        }
        Err(_) => {
            println!("Supervisor not running");
            Ok(())
        }
    }
}

/// `supervisor start --worker <p>… [--attach]`: launch the daemon for the named
/// hires. Without `--attach` the daemon is detached into its own session and
/// this command returns once the control socket is bound; with `--attach` it
/// runs the daemon in the foreground (Ctrl-C drains it).
#[cfg(unix)]
fn supervisor_start(home: &std::path::Path, workers: &[String], attach: bool) -> Result<()> {
    use std::os::unix::process::CommandExt;

    if supervisor_running(home) {
        println!("Supervisor already running");
        return Ok(());
    }
    let exe = std::env::current_exe().context("locating the nano-supervisor executable")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("daemon");
    for w in workers {
        cmd.arg("--hire").arg(w);
    }

    if attach {
        // Foreground: replace the usual detach with a direct run so Ctrl-C and
        // the daemon's console output reach the operator.
        let status = cmd.status().context("running the supervisor daemon")?;
        std::process::exit(status.code().unwrap_or(1));
    }

    // Detached: a new session so the daemon outlives this short-lived launcher.
    unsafe {
        cmd.pre_exec(|| {
            // Detach from the controlling terminal / parent session.
            if libc::setsid() == -1 {
                // Already a session leader is fine; any other failure is
                // non-fatal for the detach intent.
            }
            Ok(())
        });
    }
    let child = cmd.spawn().context("spawning the supervisor daemon")?;

    // Wait (bounded) for the daemon to bind its control socket so a follow-up
    // `status`/`add` sees it, then return.
    let sock = control::socket_path(home);
    for _ in 0..100 {
        if sock.exists() && supervisor_running(home) {
            println!("Supervisor started (pid {})", child.id());
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!(
        "supervisor daemon (pid {}) did not bind its control socket within 10s",
        child.id()
    );
}

#[cfg(not(unix))]
fn supervisor_start(_home: &std::path::Path, _workers: &[String], _attach: bool) -> Result<()> {
    bail!("supervisor start is only supported on Unix");
}

// --- workforce manifests ----------------------------------------------------

/// A workforce entry's role routing. In the Node manifest format `roles` is
/// either the string `"auto"` (serve every deployed agent job type) or a
/// non-empty array of normalized role names (`["pr-review","fix"]`). Modelling
/// it as an enum lets Rust both *read* a Node-created manifest that carries an
/// explicit role list and *write* the compatible shape — `--roles a,b` must
/// persist `["a","b"]`, not the incompatible string `"a,b"`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum Roles {
    Auto(AutoRoles),
    List(Vec<String>),
}

/// The `roles: "auto"` marker. A newtype over a unit-validated string so an
/// untagged enum round-trips the literal `"auto"` (and only it) distinctly from
/// a role list.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AutoRoles;

impl serde::Serialize for AutoRoles {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("auto")
    }
}

impl<'de> serde::Deserialize<'de> for AutoRoles {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == "auto" {
            Ok(AutoRoles)
        } else {
            Err(serde::de::Error::custom(
                "roles must be \"auto\" or an array of role names",
            ))
        }
    }
}

impl Default for Roles {
    fn default() -> Self {
        Roles::Auto(AutoRoles)
    }
}

impl Roles {
    /// Human-readable form for `workforce list`/`status`, matching Node's
    /// `describeEntryRoles`: a list joins with `, `; `auto` prints as `auto`.
    fn describe(&self) -> String {
        match self {
            Roles::Auto(_) => "auto".to_string(),
            Roles::List(rs) => rs.join(", "),
        }
    }
}

/// A workforce role name (a capability token): starts with a letter/digit, then
/// letters/digits/`. _ + -` (Node's `WORKFORCE_ROLE_RE`). No `:` — that delimits
/// rank↔role in the mapped job type. Matched case-insensitively.
fn is_valid_role(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Parse a `--roles a,b,c` value into a deduped, validated, lowercased,
/// sorted list of role names, mirroring Node's `parseRolesList`. Every element
/// may itself be comma-separated. Returns an error string on an invalid role.
fn parse_roles_list(raw: &str) -> Result<Vec<String>, String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut errors = Vec::new();
    for item in raw.split(',') {
        let r = item.trim().to_ascii_lowercase();
        if r.is_empty() {
            continue;
        }
        if !is_valid_role(&r) {
            errors.push(format!(
                "invalid role \"{}\" (use letters, digits, and . _ + -)",
                item.trim()
            ));
            continue;
        }
        seen.insert(r);
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(seen.into_iter().collect())
}

#[derive(Serialize, Deserialize, Clone)]
struct ManifestWorker {
    profile: String,
    instances: u32,
    #[serde(default)]
    roles: Roles,
    /// Unmodelled per-worker fields, preserved verbatim across a rewrite — the
    /// same preservation `StoredHire` gives a hire. `workforce add` is a
    /// read-modify-write of the whole manifest, so without this a mutation of
    /// one worker would silently drop a sibling worker's fields a future plugin
    /// version added. Empty for a freshly created worker, so the golden
    /// manifest shape (exactly the modelled fields) is unchanged.
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    name: String,
    #[serde(default)]
    workers: Vec<ManifestWorker>,
    /// Unmodelled top-level manifest fields, preserved verbatim across a
    /// rewrite — mirrors `ConfigFile`. The `version` field signals schema
    /// evolution, so a newer manifest may carry keys this struct does not
    /// model; `workforce add` must not drop them when it rewrites the file.
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported manifest version {}", self.version);
        }
        let mut seen = std::collections::BTreeSet::new();
        for worker in &self.workers {
            if !is_valid_name_charset(&worker.profile) {
                bail!(
                    "invalid worker profile \"{}\": use letters, digits, dot, dash or underscore",
                    worker.profile
                );
            }
            if !seen.insert(worker.profile.as_str()) {
                bail!("duplicate worker profile \"{}\"", worker.profile);
            }
            if worker.instances == 0 {
                bail!(
                    "invalid instances 0 for worker \"{}\": use a whole number between 1 and {MAX_WORKER_INSTANCES}",
                    worker.profile
                );
            }
            if worker.instances > MAX_WORKER_INSTANCES {
                bail!(
                    "invalid instances {} for worker \"{}\": supported maximum is {MAX_WORKER_INSTANCES}",
                    worker.instances,
                    worker.profile
                );
            }
            if let Roles::List(roles) = &worker.roles {
                if roles.is_empty() {
                    bail!("worker \"{}\" roles list must not be empty", worker.profile);
                }
                // A stored role list must satisfy the same v1 contract the CLI
                // enforces on input (`parse_roles_list`): `read_manifest` feeds
                // `workforce add`'s read-modify-write, so an invalid token (e.g.
                // `"bad:role"`) or a case-insensitive duplicate loaded from disk
                // would otherwise be silently rewritten as valid state.
                let mut seen_roles = std::collections::BTreeSet::new();
                for role in roles {
                    if !is_valid_role(role) {
                        bail!(
                            "worker \"{}\" has invalid role \"{}\": use letters, digits, and . _ + -",
                            worker.profile,
                            role
                        );
                    }
                    if !seen_roles.insert(role.to_ascii_lowercase()) {
                        bail!(
                            "worker \"{}\" has duplicate role \"{}\"",
                            worker.profile,
                            role
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

fn manifest_path(name: &str) -> Result<PathBuf> {
    // The manifest name becomes a filename under the home's `workforce/`
    // directory AND rides in the deterministic `wf-<name>-` worker-id prefix, so
    // it must satisfy the established manifest-name contract — the same
    // character set as a profile name, `[A-Za-z0-9][A-Za-z0-9._-]*`. That is
    // stricter than "a single normal path component": it also rejects spaces,
    // separators, control characters and a leading `.`/`_`/`-`, any of which
    // would either climb out of `workforce/` or produce an invalid worker id.
    let bad = || {
        anyhow::anyhow!(
            "invalid workforce name \"{name}\": use letters, digits, dot, dash or underscore (leading character must be a letter or digit)"
        )
    };
    // Reject surrounding whitespace rather than silently trimming: the path is
    // derived from the name, and the manifest's stored `name`, status object,
    // worker IDs, and output all use the original string — so `--name
    // " default "` would alias `default.json` while reporting a *different*
    // name. (A name with surrounding whitespace also fails the charset below;
    // this branch only exists to keep the rejection precise.)
    if !is_valid_name_charset(name) {
        return Err(bad());
    }
    Ok(home_dir()?.join("workforce").join(format!("{name}.json")))
}

fn read_manifest(name: &str) -> Result<Option<Manifest>> {
    let path = manifest_path(name)?;
    let bytes = match read_confined(&path)? {
        None => return Ok(None),
        Some(bytes) => bytes,
    };
    let m: Manifest =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    m.validate()?;
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
                println!(
                    "  {} × {} (roles: {})",
                    w.profile,
                    w.instances,
                    w.roles.describe()
                );
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
    // Match the pinned Node behavior (`parseInstancesCount`, MAX_ADD_INSTANCES
    // = 64) in both directions: `--instances 0` is REJECTED (not silently
    // floored to 1 — a command must not report success with a different count
    // than requested), and the per-entry maximum is 64, so a manifest written
    // here is one the Node target accepts during a rollback.
    if instances == 0 {
        bail!("invalid --instances 0: use a whole number between 1 and {MAX_WORKER_INSTANCES}");
    }
    if instances > MAX_WORKER_INSTANCES {
        bail!("invalid --instances {instances}: supported maximum is {MAX_WORKER_INSTANCES}");
    }
    // Parse `--roles` into the Node manifest shape: the literal `auto` stays the
    // string `"auto"`; any other value is a comma-separated role list persisted
    // as a normalized array (`["a","b"]`), never the incompatible string `"a,b"`.
    // The CLI defaults `--roles` to `auto` when the flag is absent, matching
    // Node's "neither --auto nor --roles → auto". The marker check is on the
    // EXACT value — case-SENSITIVE and un-trimmed (`auto`, not `" auto "`):
    // Node's `parseRolesList` lowercases a `--roles AUTO` and trims a
    // `--roles " auto "` into the *role* `auto` and persists the list `["auto"]`,
    // so only the exact literal `auto` selects the auto marker here; padded or
    // cased spellings fall through to the role list and stay distinguishable.
    let roles_value = if roles == "auto" {
        Roles::default()
    } else {
        match parse_roles_list(roles) {
            Ok(rs) if !rs.is_empty() => Roles::List(rs),
            Ok(_) => bail!("--roles must name at least one role (or use \"auto\")"),
            Err(e) => bail!("{e}"),
        }
    };
    // The read-modify-write below is the same lost-update class as `config.json`:
    // two concurrent `workforce add <name> <a>` / `<b>` on the *same* manifest
    // each read the pre-image and the second atomic rename silently drops the
    // first's worker. `write_manifest` is atomic (a reader never sees a partial
    // file) but atomicity alone does not serialize the mutate, so guard the whole
    // read→mutate→write behind a per-manifest lock, exactly like `update_config`.
    let manifest_file = manifest_path(name)?;
    if let Some(parent) = manifest_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let _guard = StateLock::acquire(&manifest_file)?;
    let mut manifest = read_manifest(name)?.unwrap_or(Manifest {
        version: 1,
        name: name.to_string(),
        workers: Vec::new(),
        other: BTreeMap::new(),
    });
    // The write destination comes from the requested (validated) name, so bind
    // the loaded manifest to it: a manifest file whose internal `name` disagrees
    // with its filename would otherwise redirect the write to a *different*
    // file, silently leaving the requested one unchanged.
    manifest.name = name.to_string();
    match manifest.workers.iter_mut().find(|w| w.profile == profile) {
        Some(existing) => {
            existing.instances = instances;
            existing.roles = roles_value.clone();
        }
        None => manifest.workers.push(ManifestWorker {
            profile: profile.to_string(),
            instances,
            roles: roles_value,
            other: BTreeMap::new(),
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
    /// The entry's `roles` in its persisted shape — the string `"auto"` or an
    /// array of role names — matching Node's `buildWorkforceStatus`, which
    /// passes `e.roles` through verbatim (it does NOT join a list into a string).
    roles: Roles,
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
                e.profile,
                e.desired,
                e.running,
                e.roles.describe()
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
    /// persist a profile that can never run. A *container* sandbox additionally
    /// requires a non-empty `--image` (the reference CLI rejects `docker`/
    /// `podman` with no usable image rather than persist an unlaunchable profile).
    #[test]
    fn hire_rejects_unknown_sandbox() {
        let cfg = TempCfg::new();
        let mut args = hire_args("coder");
        args.sandbox = Some("dokcer".to_string());
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("Invalid sandbox \"dokcer\""), "{err}");
        assert!(err.contains("none, docker, podman"), "{err}");

        // `none` (host) needs no image.
        for ok in ["none", " None "] {
            let mut args = hire_args("coder");
            args.sandbox = Some(ok.to_string());
            hire(args).unwrap_or_else(|e| panic!("sandbox {ok:?}: {e}"));
        }
        // A container sandbox WITH an image is accepted.
        for ok in ["docker", "podman"] {
            let mut args = hire_args("coder");
            args.sandbox = Some(ok.to_string());
            args.image = Some("registry.example/agent:1".to_string());
            hire(args).unwrap_or_else(|e| panic!("sandbox {ok:?} + image: {e}"));
        }
        drop(cfg);
    }

    /// A container sandbox (`docker`/`podman`) with no usable `--image` persists
    /// a profile that can never launch; the reference CLI rejects it up front.
    #[test]
    fn hire_rejects_container_sandbox_without_image() {
        let _cfg = TempCfg::new();
        for sandbox in ["docker", "podman"] {
            // Missing image entirely.
            let mut args = hire_args("coder");
            args.sandbox = Some(sandbox.to_string());
            let err = hire(args).unwrap_err().to_string();
            assert!(
                err.contains(&format!("--sandbox {sandbox} requires --image")),
                "{sandbox} (no image): {err}"
            );
            // Blank/whitespace image is still no image.
            let mut args = hire_args("coder");
            args.sandbox = Some(sandbox.to_string());
            args.image = Some("   ".to_string());
            let err = hire(args).unwrap_err().to_string();
            assert!(
                err.contains(&format!("--sandbox {sandbox} requires --image")),
                "{sandbox} (blank image): {err}"
            );
            // Nothing was persisted for the rejected hires.
            assert!(
                read_config().unwrap().hires.is_empty(),
                "a rejected container hire must not persist a profile"
            );
        }
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

    /// The Node surface accepts and persists all three permission policies
    /// (`yolo`, `escalate`, `filter`); only `yolo` is enforced today, with
    /// `escalate`/`filter` RESERVED-but-persisted for forward compatibility. So
    /// hire must reject only a genuinely unknown value (or the historical `ask`
    /// default), while accepting the reserved modes verbatim. The default (no
    /// `--permission`) resolves to `yolo`, never `ask`.
    #[test]
    fn hire_permission_accepts_reserved_modes() {
        let cfg = TempCfg::new();
        for bad in ["ask", "typo"] {
            let mut args = hire_args("coder");
            args.permission = Some(bad.to_string());
            let err = hire(args).unwrap_err().to_string();
            assert!(err.contains("Invalid permission"), "{bad}: {err}");
            assert!(err.contains("yolo"), "{bad}: {err}");
        }

        // Reserved modes are accepted and persisted verbatim (never downgraded).
        for ok in ["yolo", " YOLO ", "escalate", "filter", " ESCALATE "] {
            let mut args = hire_args("coder");
            args.permission = Some(ok.to_string());
            hire(args).unwrap_or_else(|e| panic!("permission {ok:?}: {e}"));
        }
        let stored = read_config().unwrap();
        assert_eq!(
            stored.hires["coder"].permission.as_deref(),
            Some("escalate")
        );

        // Omitting --permission defaults to the only enforced policy, yolo.
        hire(hire_args("defaulted")).unwrap();
        let stored = read_config().unwrap();
        assert_eq!(
            stored.hires["defaulted"].permission.as_deref(),
            Some("yolo")
        );
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
        let expected = vec!["fix".to_string()];
        assert_eq!(
            cfg.hires["coder"].capabilities.as_deref(),
            Some(expected.as_slice())
        );
    }

    #[test]
    fn assign_stamps_updated_at_and_leaves_other_profiles_untouched() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        hire(hire_args("other")).unwrap();
        let dir = home_dir().unwrap();
        let before: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        let other_before = before["hires"]["other"].clone();

        assign("coder", "fix").unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        assert!(
            after["hires"]["coder"]["updatedAt"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "assign must stamp a non-empty updatedAt"
        );
        assert_eq!(
            after["hires"]["other"], other_before,
            "assigning one profile must not rewrite an unrelated profile"
        );
    }

    #[test]
    fn config_rewrite_does_not_inject_optional_defaults_into_legacy_hires() {
        let _cfg = TempCfg::new();
        let dir = home_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = serde_json::json!({"name":"legacy","rank":"senior","command":"nano-legacy"});
        std::fs::write(
            dir.join("config.json"),
            serde_json::json!({"hires":{"legacy":legacy.clone()}}).to_string(),
        )
        .unwrap();

        hire(hire_args("other")).unwrap();

        let raw = std::fs::read_to_string(dir.join("config.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["hires"]["legacy"], legacy);
        for injected in ["args", "model", "capabilities", "sandbox", "createdAt"] {
            assert!(
                value["hires"]["legacy"].get(injected).is_none(),
                "legacy hire must not gain {injected}"
            );
        }
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

    /// A Node-written manifest may carry top-level keys and per-worker fields
    /// this struct does not model (schema evolution — the `version` field
    /// signals exactly that). `workforce add` is a read-modify-write of the
    /// whole manifest, so rewriting it must PRESERVE those fields — the same
    /// unknown-field preservation `config.json` gives a hire, not drop them off
    /// the manifest or a sibling worker.
    #[test]
    fn workforce_add_preserves_unknown_manifest_fields() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        hire(hire_args("other")).unwrap();
        let dir = home_dir().unwrap().join("workforce");
        std::fs::create_dir_all(&dir).unwrap();
        // Seed a manifest with an unmodelled top-level key and an unmodelled
        // field on an existing (sibling) worker that the add won't touch.
        std::fs::write(
            dir.join("default.json"),
            r#"{"version":1,"name":"default","generation":7,"workers":[{"profile":"other","instances":2,"roles":"auto","lastSeen":"2026-01-01T00:00:00.000Z"}]}"#,
        )
        .unwrap();
        // Add a different worker — a read-modify-write of the whole manifest.
        workforce_add("default", "coder", 1, "auto").unwrap();
        let raw = std::fs::read_to_string(dir.join("default.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            value["generation"],
            serde_json::json!(7),
            "an unmodelled top-level manifest field must survive a rewrite"
        );
        let sibling = value["workers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["profile"] == serde_json::json!("other"))
            .expect("the untouched sibling worker must still be present");
        assert_eq!(
            sibling["lastSeen"],
            serde_json::json!("2026-01-01T00:00:00.000Z"),
            "an unmodelled field on a sibling worker must survive a rewrite"
        );
    }

    /// A freshly created manifest/worker writes exactly the modelled fields (no
    /// stray `other` keys), so the golden manifest shape is unchanged.
    #[test]
    fn fresh_workforce_add_writes_only_modelled_fields() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        workforce_add("default", "coder", 1, "auto").unwrap();
        let raw =
            std::fs::read_to_string(home_dir().unwrap().join("workforce").join("default.json"))
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let top: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        for k in &top {
            assert!(
                matches!(*k, "version" | "name" | "workers"),
                "fresh manifest leaked an unmodelled top-level key: {k}"
            );
        }
        let worker: Vec<&str> = value["workers"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        for k in &worker {
            assert!(
                matches!(*k, "profile" | "instances" | "roles"),
                "fresh worker leaked an unmodelled key: {k}"
            );
        }
    }

    /// A workforce name with surrounding whitespace must be rejected, not
    /// trimmed for the path while persisted/reported untrimmed — otherwise
    /// `--name " default "` aliases `default.json` under a different name. And
    /// because the name rides in the `wf-<name>-` worker-id prefix, interior
    /// whitespace and other off-charset characters are rejected too (the Node
    /// manifest-name contract is `[A-Za-z0-9][A-Za-z0-9._-]*`).
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
    }

    /// The manifest name follows the same character set as a profile name
    /// (`[A-Za-z0-9][A-Za-z0-9._-]*`): spaces, separators, control characters
    /// and a leading `.`/`_`/`-` are all rejected, since the name flows into the
    /// deterministic `wf-<name>-` worker ids and the on-disk filename.
    #[test]
    fn manifest_path_enforces_name_charset() {
        for bad in [
            "my fleet",   // interior space
            "my\tfleet",  // control char
            "-lead",      // leading dash
            "_lead",      // leading underscore
            ".hidden",    // leading dot
            "fleet name", // space
            "café",       // non-ASCII
        ] {
            assert!(
                manifest_path(bad).is_err(),
                "name {bad:?} must be rejected by the character-set contract"
            );
        }
        // The full accepted charset round-trips.
        for good in ["default", "A", "a1", "my-fleet", "fleet_2", "x.y", "Z9.-_"] {
            assert!(
                manifest_path(good).is_ok(),
                "name {good:?} must be accepted by the character-set contract"
            );
        }
    }

    /// `workforce add` must match the pinned Node `parseInstancesCount` in both
    /// directions: `--instances 0` is REJECTED (not silently floored to 1 — a
    /// command must not report success with a count different from what was
    /// requested), and the per-entry maximum is 64 (not higher), so a manifest
    /// written here is one the Node target accepts during a rollback.
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
        // One above the Node per-entry cap (64) is also rejected.
        let err = workforce_add("default", "coder", MAX_WORKER_INSTANCES + 1, "auto")
            .unwrap_err()
            .to_string();
        assert!(err.contains("supported maximum"), "{err}");
        // The ceiling itself is accepted.
        workforce_add("default", "coder", MAX_WORKER_INSTANCES, "auto").unwrap();
        let m = read_manifest("default").unwrap().unwrap();
        assert_eq!(m.workers[0].instances, MAX_WORKER_INSTANCES);
    }

    /// `--instances 0` must be rejected outright, not silently changed to 1:
    /// reporting success with a different count than requested breaks drop-in
    /// compatibility with the Node CLI.
    #[test]
    fn workforce_add_rejects_zero_instances() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        let err = workforce_add("default", "coder", 0, "auto")
            .unwrap_err()
            .to_string();
        assert!(err.contains("between 1 and"), "{err}");
        assert!(
            read_manifest("default").unwrap().is_none(),
            "a zero instances value must not persist a manifest"
        );
    }

    /// `workforce status --json` must emit `roles` in its persisted shape — the
    /// string `"auto"` or an array of role names — matching Node's
    /// `buildWorkforceStatus`, which passes `e.roles` through verbatim rather
    /// than joining a list into a string.
    #[test]
    fn workforce_status_json_preserves_roles_shape() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        workforce_add("default", "coder", 1, "pr-review,fix").unwrap();
        let m = read_manifest("default").unwrap().unwrap();
        let entry = &m.workers[0];
        // Build the status entry exactly as workforce_status does and check the
        // serialized roles field is the array, not a joined string.
        let se = StatusEntry {
            profile: entry.profile.clone(),
            roles: entry.roles.clone(),
            auto_scope: None,
            desired: entry.instances,
            running: 0,
            workers: Vec::new(),
        };
        let v = serde_json::to_value(&se).unwrap();
        assert_eq!(v["roles"], serde_json::json!(["fix", "pr-review"]));
        // And the auto form stays the string "auto".
        workforce_add("default", "coder", 1, "auto").unwrap();
        let m = read_manifest("default").unwrap().unwrap();
        let se = StatusEntry {
            profile: m.workers[0].profile.clone(),
            roles: m.workers[0].roles.clone(),
            auto_scope: None,
            desired: m.workers[0].instances,
            running: 0,
            workers: Vec::new(),
        };
        let v = serde_json::to_value(&se).unwrap();
        assert_eq!(v["roles"], serde_json::json!("auto"));
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

    #[test]
    fn read_manifest_validates_v1_schema() {
        let _cfg = TempCfg::new();
        let dir = home_dir().unwrap().join("workforce");
        std::fs::create_dir_all(&dir).unwrap();

        let cases = [
            (
                "bad-version",
                r#"{"version":2,"name":"bad-version","workers":[]}"#,
                "unsupported manifest version 2",
            ),
            (
                "zero",
                r#"{"version":1,"name":"zero","workers":[{"profile":"coder","instances":0,"roles":"auto"}]}"#,
                "invalid instances 0",
            ),
            (
                "too-many",
                r#"{"version":1,"name":"too-many","workers":[{"profile":"coder","instances":65,"roles":"auto"}]}"#,
                "supported maximum is 64",
            ),
            (
                "empty-roles",
                r#"{"version":1,"name":"empty-roles","workers":[{"profile":"coder","instances":1,"roles":[]}]}"#,
                "roles list must not be empty",
            ),
            (
                "bad-profile",
                r#"{"version":1,"name":"bad-profile","workers":[{"profile":"bad profile","instances":1,"roles":"auto"}]}"#,
                "invalid worker profile",
            ),
            (
                "dupe",
                r#"{"version":1,"name":"dupe","workers":[{"profile":"coder","instances":1,"roles":"auto"},{"profile":"coder","instances":1,"roles":"auto"}]}"#,
                "duplicate worker profile",
            ),
        ];
        for (name, json, needle) in cases {
            std::fs::write(dir.join(format!("{name}.json")), json).unwrap();
            let err = match read_manifest(name) {
                Ok(_) => panic!("{name}: manifest should have failed validation"),
                Err(err) => err.to_string(),
            };
            assert!(err.contains(needle), "{name}: {err}");
        }

        std::fs::write(
            dir.join("valid.json"),
            r#"{"version":1,"name":"valid","workers":[{"profile":"coder","instances":64,"roles":["fix"]}]}"#,
        )
        .unwrap();
        let manifest = read_manifest("valid").unwrap().unwrap();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.workers[0].profile, "coder");
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

    /// Regression (confined reads — findings `r4181391477`/`r4181391593`):
    /// a symlinked `config.json` must NOT let a read escape the trusted home.
    /// The write path already refuses a symlinked tail; the read path must honour
    /// the same invariant, opening the file `O_NOFOLLOW` through the pinned home.
    #[cfg(unix)]
    #[test]
    fn read_config_refuses_symlinked_config_file() {
        let _cfg = TempCfg::new();
        let home = home_dir().unwrap();
        let outside = home.join("outside-secret.json");
        std::fs::write(
            &outside,
            serde_json::json!({"hires": {"leaked": {}}}).to_string(),
        )
        .unwrap();
        // A symlinked `config.json` pointing outside must be refused, not read.
        std::os::unix::fs::symlink(&outside, home.join("config.json")).unwrap();

        let err = match read_config() {
            Ok(_) => panic!("symlinked config.json must be refused, not read"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("opening state file without following symlinks")
                || err.contains("Too many levels of symbolic links"),
            "{err}"
        );
    }

    /// Regression (confined reads — finding `r4181391593`): a symlinked
    /// `workforce/` tail must NOT let `read_manifest` consume state outside the
    /// home, matching the write path's refusal of the same symlinked tail.
    #[cfg(unix)]
    #[test]
    fn read_manifest_refuses_symlinked_workforce_tail() {
        let _cfg = TempCfg::new();
        let home = home_dir().unwrap();
        let elsewhere = home.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(
            elsewhere.join("demo.json"),
            serde_json::json!({"version": 1, "name": "demo", "workers": []}).to_string(),
        )
        .unwrap();
        // `<home>/workforce -> <home>/elsewhere`: the hardened write path rejects
        // this tail, so the read path must too.
        std::os::unix::fs::symlink(&elsewhere, home.join("workforce")).unwrap();

        let err = match read_manifest("demo") {
            Ok(_) => panic!("symlinked workforce/ tail must be refused, not read"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("opening state directory without following symlinks")
                || err.contains("Too many levels of symbolic links"),
            "{err}"
        );
    }

    /// A confined read of an absent file (or absent directory above it) reports
    /// absence, not an error, so a fresh home still reads as an empty config /
    /// a missing manifest.
    #[cfg(unix)]
    #[test]
    fn read_confined_reports_absence_and_round_trips() {
        let _cfg = TempCfg::new();
        // Fresh home: config is default-empty, manifest is absent.
        assert!(read_config().unwrap().hires.is_empty());
        assert!(read_manifest("demo").unwrap().is_none());

        // After a normal write, the confined read sees the committed bytes.
        let man_path = manifest_path("demo").unwrap();
        write_json_atomic(
            &man_path,
            &serde_json::json!({"version": 1, "name": "demo", "workers": []}),
        )
        .unwrap();
        let m = read_manifest("demo").unwrap().expect("manifest present");
        assert_eq!(m.name, "demo");
    }

    /// The owner-private lock directory must fail closed on a pre-planted
    /// foreign entry: a symlink (or any non-directory) in its place, or a
    /// group/other-accessible directory, is a pre-creation attack and must be
    /// refused rather than used to plant or redirect our lock files.
    #[cfg(unix)]
    #[test]
    fn fleet_lock_dir_rejects_foreign_entries() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "fleet-lockdir-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join(format!("c8ctl-nano-fleet-{}", crate::current_user_id()));

        // 1. A symlink in the directory's place is refused (not followed).
        let target = base.join("real");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &dir).unwrap();
        let err = fleet_lock_dir_in(&base).unwrap_err().to_string();
        assert!(err.contains("not a directory"), "{err}");
        std::fs::remove_file(&dir).unwrap();

        // 2. A group/other-accessible directory is refused.
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = fleet_lock_dir_in(&base).unwrap_err().to_string();
        assert!(err.contains("accessible to other users"), "{err}");

        // 3. A fresh, owner-only directory is accepted and is 0700.
        std::fs::remove_dir(&dir).unwrap();
        let made = fleet_lock_dir_in(&base).unwrap();
        assert_eq!(made, dir);
        let mode = std::fs::symlink_metadata(&dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "lock dir must be owner-only");

        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_json_atomic_refuses_symlinked_parent() {
        let _cfg = TempCfg::new();
        let home = home_dir().unwrap();
        let real = home.join("real-parent");
        let link = home.join("linked-parent");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = write_json_atomic(&link.join("config.json"), &serde_json::json!({"ok":true}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("opening state directory"), "{err}");
        assert!(
            !real.join("config.json").exists(),
            "a symlinked parent must not redirect the state write"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_json_atomic_refuses_preplanted_temp_symlink() {
        let _cfg = TempCfg::new();
        let home = home_dir().unwrap();
        let state = home.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let victim = home.join("victim.txt");
        std::fs::write(&victim, "do not touch").unwrap();
        std::os::unix::fs::symlink(&victim, state.join(".config.json.tmp")).unwrap();

        let err = write_json_atomic(&state.join("config.json"), &serde_json::json!({"ok":true}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("creating temp state file"), "{err}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "do not touch");
        assert!(
            !state.join("config.json").exists(),
            "a planted temp symlink must not publish a state file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_json_atomic_round_trips_and_reuses_regular_temp() {
        let _cfg = TempCfg::new();
        let home = home_dir().unwrap();
        let path = home.join("state").join("config.json");
        write_json_atomic(&path, &serde_json::json!({"a":1})).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!({"a":1}));

        std::fs::write(path.with_file_name(".config.json.tmp"), "leftover").unwrap();
        write_json_atomic(&path, &serde_json::json!({"b":2})).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!({"b":2}));
        assert!(!path.with_file_name(".config.json.tmp").exists());
    }

    /// Regression (symlinked trusted anchor): pointing `C8CTL_NANO_HOME` at a
    /// symlink must NOT make state writes fail — the home is the trusted anchor,
    /// opened following symlinks, while only components below it are no-follow.
    /// Before the fix, `config.json` (whose parent IS the home) and every other
    /// write failed with `ELOOP`/`ENOTDIR` even though `hire`/`assign` could read
    /// through the same home.
    #[cfg(unix)]
    #[test]
    fn write_json_atomic_allows_symlinked_state_home() {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("C8CTL_NANO_HOME");
        let base = std::env::temp_dir().join(format!(
            "fleet-symhome-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let real = base.join("real-home");
        let link = base.join("home-link");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        std::env::set_var("C8CTL_NANO_HOME", &link);

        // config.json: the parent IS the symlinked home (the anchor).
        let cfg_path = config_path().unwrap();
        write_json_atomic(&cfg_path, &serde_json::json!({"ok": true})).unwrap();
        // A descendant path: the home symlink is followed, the created
        // `workforce` tail component is opened no-follow.
        let man_path = manifest_path("demo").unwrap();
        write_json_atomic(&man_path, &serde_json::json!({"version": 1})).unwrap();

        // Both land in the REAL target through the symlinked home.
        let cfg: serde_json::Value =
            serde_json::from_slice(&std::fs::read(real.join("config.json")).unwrap()).unwrap();
        assert_eq!(cfg, serde_json::json!({"ok": true}));
        assert!(real.join("workforce").join("demo.json").is_file());

        match prev {
            Some(v) => std::env::set_var("C8CTL_NANO_HOME", v),
            None => std::env::remove_var("C8CTL_NANO_HOME"),
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// Regression (stored-role validation): a manifest loaded from disk must
    /// satisfy the same v1 role contract the CLI enforces on input, so
    /// `workforce add`'s read-modify-write cannot silently rewrite invalid or
    /// duplicate role tokens as valid state.
    #[test]
    fn manifest_validate_rejects_invalid_and_duplicate_roles() {
        let worker = |roles: Vec<&str>| ManifestWorker {
            profile: "coder".to_string(),
            instances: 1,
            roles: Roles::List(roles.into_iter().map(String::from).collect()),
            other: BTreeMap::new(),
        };
        let manifest = |w: ManifestWorker| Manifest {
            version: 1,
            name: "wf".to_string(),
            workers: vec![w],
            other: BTreeMap::new(),
        };

        let bad = manifest(worker(vec!["bad:role"]))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(bad.contains("invalid role"), "{bad}");

        let dup = manifest(worker(vec!["Build", "build"]))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(dup.contains("duplicate role"), "{dup}");

        assert!(manifest(worker(vec!["build", "review"])).validate().is_ok());
    }

    /// Regression (exact `auto` marker): only the un-trimmed, case-sensitive
    /// literal `auto` selects the auto marker. A padded `--roles " auto "` is an
    /// explicit role list `["auto"]`, matching Node's `parseRolesList`, so the
    /// two valid shapes stay distinguishable in the persisted manifest.
    #[test]
    fn workforce_add_marker_is_exact_not_trimmed() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();

        workforce_add("wfa", "coder", 1, "auto").unwrap();
        let m = read_manifest("wfa").unwrap().unwrap();
        assert!(
            matches!(m.workers[0].roles, Roles::Auto(_)),
            "exact `auto` must be the auto marker"
        );

        workforce_add("wfb", "coder", 1, " auto ").unwrap();
        let m = read_manifest("wfb").unwrap().unwrap();
        match &m.workers[0].roles {
            Roles::List(rs) => assert_eq!(rs, &vec!["auto".to_string()]),
            other => panic!("padded ` auto ` must persist as a role list, got {other:?}"),
        }
    }

    #[test]
    fn state_lock_normalizes_relative_and_absolute_identity() {
        // Derive the relative/absolute identity from the EXISTING working
        // directory rather than `set_current_dir`: mutating the process-wide cwd
        // races other parallel tests that also touch it (e.g. the saferoot cwd
        // test) and can leave a later test in the wrong directory.
        // `normalized_identity` resolves a relative path against the current dir,
        // so the same file spelled relatively and absolutely must hash to one
        // lock. Hold the shared cwd guard so a concurrent `set_current_dir`
        // cannot shift the cwd between the two resolutions.
        let _cwd = crate::cwd_test_guard();
        let cwd = std::env::current_dir().unwrap();
        let relative = Path::new("state").join("config.json");
        let absolute = cwd.join("state").join("config.json");
        let rel_lock = StateLock::lock_file_for(&relative).unwrap();
        let abs_lock = StateLock::lock_file_for(&absolute).unwrap();
        assert_eq!(rel_lock, abs_lock);
    }

    /// Regression (finding `r4182128486`): the lock base must be a single
    /// stable per-user anchor, invariant to the *entire* environment —
    /// `XDG_RUNTIME_DIR` / `XDG_STATE_HOME` **and** `HOME` (present or absent).
    /// Two processes targeting the SAME guarded file but running with different
    /// environments — an interactive shell (HOME + XDG set) vs. a service with a
    /// reduced environment that has neither (the very scenario `lock_base_dir`
    /// cites) — must derive the SAME lock base, or the `flock` lands on different
    /// files and silently fails to serialize them (a mutual-exclusion break).
    /// Because the base is keyed on the UID's passwd home, it is invariant to
    /// all of these by construction. Asserts on the pure `lock_base_dir()` (no
    /// filesystem writes) so it neither races sibling tests nor leaves a lock
    /// dir behind.
    #[cfg(unix)]
    #[test]
    fn lock_base_is_invariant_to_environment() {
        // Restores the perturbed env on any exit (including a panicking assert),
        // so this test never leaks a stale var into the next one.
        struct EnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }

        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _restore = EnvRestore(
            ["XDG_RUNTIME_DIR", "XDG_STATE_HOME", "HOME"]
                .iter()
                .map(|k| (*k, std::env::var_os(k)))
                .collect(),
        );

        // "Interactive shell": HOME and both XDG vars set.
        std::env::set_var("HOME", "/home/interactive-shell");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/31415");
        std::env::set_var("XDG_STATE_HOME", "/some/xdg/state");
        let interactive = lock_base_dir();

        // "Service with a reduced environment": a *different* HOME and neither
        // XDG var — the exact split that silently broke serialization before.
        std::env::set_var("HOME", "/home/some-other-value");
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::remove_var("XDG_STATE_HOME");
        let other_home = lock_base_dir();

        // "Service with no HOME at all": the cited cron/systemd reduced env.
        std::env::remove_var("HOME");
        let no_home = lock_base_dir();

        assert_eq!(
            interactive, other_home,
            "lock base must not vary with HOME/XDG, or same-home processes with \
             different environments fail to serialize"
        );
        assert_eq!(
            interactive, no_home,
            "lock base must be identical whether HOME is set or absent, or a \
             reduced-environment service fails to serialize with a login shell"
        );
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
        let mut profiles: Vec<_> = manifest
            .workers
            .iter()
            .map(|w| w.profile.as_str())
            .collect();
        profiles.sort();
        assert_eq!(
            profiles,
            vec!["a", "b"],
            "both concurrent adds must survive; a lost update would drop one worker"
        );
    }

    /// A hire may carry fields this struct does not model (`updatedAt`, or a
    /// field a future plugin adds). Deserializing into the closed struct and
    /// rewriting the config must PRESERVE those fields, not drop them — Node's
    /// `assign` spreads the existing profile, so an unrelated `hire`/`assign`
    /// must not strip them.
    #[test]
    fn config_rewrite_preserves_unknown_hire_fields() {
        let _cfg = TempCfg::new();
        // Seed a config with an unmodelled field on an existing hire.
        let dir = home_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.json"),
            r#"{"hires":{"coder":{"name":"coder","rank":"senior","command":"nano-coder","updatedAt":"2026-01-01T00:00:00.000Z","customField":{"nested":1}}}}"#,
        )
        .unwrap();
        // An unrelated hire rewrites the whole config.
        hire(hire_args("other")).unwrap();
        let raw = std::fs::read_to_string(dir.join("config.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            value["hires"]["coder"]["updatedAt"],
            serde_json::json!("2026-01-01T00:00:00.000Z"),
            "an unrelated hire must not drop the coder's unmodelled updatedAt"
        );
        assert_eq!(
            value["hires"]["coder"]["customField"],
            serde_json::json!({"nested": 1}),
            "arbitrary unmodelled fields must survive a rewrite"
        );
        // And `assign` (which mutates the coder in place) preserves them too.
        assign("coder", "fix").unwrap();
        let raw = std::fs::read_to_string(dir.join("config.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(value["hires"]["coder"]["updatedAt"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        assert_eq!(
            value["hires"]["coder"]["customField"],
            serde_json::json!({"nested": 1})
        );
        assert_eq!(
            value["hires"]["coder"]["capabilities"],
            serde_json::json!(["fix"])
        );
    }

    /// A freshly created hire writes exactly the modelled fields (no stray
    /// `other` keys), so the golden `config_after_hire` shape is unchanged.
    #[test]
    fn fresh_hire_writes_only_modelled_fields() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        let raw = std::fs::read_to_string(home_dir().unwrap().join("config.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let keys: Vec<&str> = value["hires"]["coder"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        for k in &keys {
            assert!(
                matches!(
                    *k,
                    "name"
                        | "rank"
                        | "command"
                        | "args"
                        | "model"
                        | "capabilities"
                        | "sandbox"
                        | "image"
                        | "terminal"
                        | "protocol"
                        | "permission"
                        | "env"
                        | "createdAt"
                ),
                "fresh hire must not write unmodelled field {k:?}"
            );
        }
    }

    /// The profile name participates in worker IDs, so it must match the
    /// established character set `[A-Za-z0-9][A-Za-z0-9._-]*` — spaces,
    /// separators and control characters are rejected before any state write.
    #[test]
    fn hire_rejects_invalid_profile_name() {
        let _cfg = TempCfg::new();
        for bad in ["my agent", "a/b", "-lead", ".hidden", "café", "a b"] {
            let mut args = hire_args("coder");
            args.name = Some(bad.to_string());
            let err = hire(args).unwrap_err().to_string();
            assert!(err.contains("Invalid profile name"), "{bad:?}: {err}");
        }
        assert!(
            read_config().unwrap().hires.is_empty(),
            "an invalid profile name must not persist a hire"
        );
        // The accepted charset round-trips.
        for good in ["coder", "A", "a1", "my-agent", "agent_2", "x.y"] {
            let mut args = hire_args("coder");
            args.name = Some(good.to_string());
            hire(args).unwrap_or_else(|e| panic!("name {good:?}: {e}"));
        }
    }

    /// `--env` keys must match `[A-Za-z_][A-Za-z0-9_]*`; an invalid name is
    /// rejected before insertion, and a malformed entry's VALUE is never echoed
    /// in the diagnostic (it may be a secret).
    #[test]
    fn hire_validates_env_names_and_hides_values() {
        let _cfg = TempCfg::new();
        for bad in ["1TOKEN", "A-B", "A B"] {
            let mut args = hire_args("coder");
            args.env = vec![format!("{bad}=x")];
            let err = hire(args).unwrap_err().to_string();
            assert!(err.contains("invalid --env name"), "{bad}: {err}");
        }
        // The empty-name error must not leak the value.
        let mut args = hire_args("coder");
        args.env = vec!["=SECRET".to_string()];
        let err = hire(args).unwrap_err().to_string();
        assert!(err.contains("non-empty key"), "{err}");
        assert!(!err.contains("SECRET"), "value must be hidden: {err}");
        // A no-`=` entry must not leak either.
        let mut args = hire_args("coder");
        args.env = vec!["SECRET".to_string()];
        let err = hire(args).unwrap_err().to_string();
        assert!(!err.contains("SECRET"), "value must be hidden: {err}");
        // Valid names are accepted.
        let mut args = hire_args("coder");
        args.env = vec!["_OK=1".to_string(), "A1_B=2".to_string()];
        hire(args).unwrap_or_else(|e| panic!("valid env: {e}"));
    }

    /// `roles` is `"auto"` or a non-empty array of normalized role names. The
    /// manifest must round-trip both: read a Node-written explicit list, and
    /// write `--roles a,b` as `["a","b"]` (never the string `"a,b"`).
    #[test]
    fn workforce_roles_roundtrip_auto_and_list() {
        let _cfg = TempCfg::new();
        hire(hire_args("coder")).unwrap();
        // Default (auto) persists the string "auto".
        workforce_add("default", "coder", 1, "auto").unwrap();
        let raw =
            std::fs::read_to_string(home_dir().unwrap().join("workforce/default.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["workers"][0]["roles"], serde_json::json!("auto"));

        // An explicit `--roles a,b` persists a normalized array, not a string.
        workforce_add("default", "coder", 1, "Pr-Review, Fix ,pr-review").unwrap();
        let raw =
            std::fs::read_to_string(home_dir().unwrap().join("workforce/default.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            value["workers"][0]["roles"],
            serde_json::json!(["fix", "pr-review"]),
            "--roles a,b must persist a normalized array"
        );

        // A Node-written manifest with an explicit list deserializes.
        std::fs::write(
            home_dir().unwrap().join("workforce/node.json"),
            r#"{"version":1,"name":"node","workers":[{"profile":"coder","instances":1,"roles":["pr-review","fix"]}]}"#,
        )
        .unwrap();
        let m = read_manifest("node").unwrap().unwrap();
        assert_eq!(
            m.workers[0].roles,
            Roles::List(vec!["pr-review".to_string(), "fix".to_string()])
        );
        // An invalid role is rejected.
        let err = workforce_add("default", "coder", 1, "bad:role")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid role"), "{err}");
    }

    /// `hire --list` must reproduce the Node surface: persisted `--arg`s are
    /// shell-quoted into the command line, empty model/caps print as `-`, and
    /// the `protocol`/`terminal`/`permission` fields appear only when non-default.
    #[test]
    fn hire_list_matches_node_format() {
        let _cfg = TempCfg::new();
        // Default pipe hire with an --arg: protocol/terminal omitted (defaults).
        let mut args = hire_args("coder");
        args.args = vec!["--allow-all".to_string()];
        hire(args).unwrap();
        let cfg = read_config().unwrap();
        let line = hire_line(&cfg.hires["coder"]);
        assert_eq!(
            line, "  coder  [senior]  nano-coder '--allow-all'  (model: -; caps: -)",
            "default pipe hire with --arg: {line}"
        );

        // Non-default protocol/terminal/permission are appended in order.
        let mut args = hire_args("reviewer");
        args.protocol = Some("acp".to_string());
        args.terminal = Some("pty".to_string());
        args.permission = Some("escalate".to_string());
        args.model = Some("gpt5".to_string());
        args.capabilities = Some("fix,pr-review".to_string());
        hire(args).unwrap();
        let cfg = read_config().unwrap();
        let line = hire_line(&cfg.hires["reviewer"]);
        assert_eq!(
            line,
            "  reviewer  [senior]  nano-coder  (model: gpt5; caps: fix, pr-review; terminal: pty; protocol: acp; permission: escalate)",
            "non-default modes appended: {line}"
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
            // `unwrap_or_else(|e| e.into_inner())` recovers from a poisoned
            // mutex: a test that panics while holding the lock (e.g. a failed
            // assertion) must not cascade PoisonError failures into every later
            // state-mutating test — the guard still serializes access, which is
            // its only job.
            let guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
