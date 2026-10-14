//! Host-wide supervisor discovery and phantom flagging (nanobpm/nano-supervisor#42).
//!
//! Observability/hygiene on top of the structural nested-supervisor containment
//! in #40. A misbehaving agent run could leave a stray supervisor daemon running
//! on the host — one whose working directory is a now-deleted agent run dir, or
//! whose state home sits in throwaway `/tmp` — polling with a live worker
//! identity and misleading triage. #40 stops agents from *creating* such
//! phantoms; this module lets `supervisor status` *surface* the ones already
//! there.
//!
//! Discovery is deliberately host-wide and derivation-free: the control sockets
//! all live in the shared system temp dir under the Node-compatible name
//! `c8ctl-nano-sup-<sha1(home)[:8]>.sock` (see [`crate::control::socket_path`]),
//! so enumerating that directory finds every supervisor on the host regardless
//! of which state home launched it. For each live socket we read the daemon's
//! own `status` reply (pid + `logFile`), recover its state home from the log
//! path, and inspect the process's working directory. The classification of what
//! counts as a phantom is a pure function ([`classify`]) so it is unit-testable
//! without a live daemon.

use std::path::{Path, PathBuf};

/// Why a discovered supervisor is flagged as a phantom. Each variant carries the
/// offending path so `supervisor status` can show the operator exactly what
/// tripped the flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhantomReason {
    /// The process's working directory no longer exists on disk — the classic
    /// signature of a daemon left behind by a torn-down agent run whose run dir
    /// was deleted out from under it (#40).
    DeletedCwd(PathBuf),
    /// The daemon's state home is under the system temp dir (the `/tmp` family):
    /// a throwaway home an agent run exported (`C8CTL_NANO_HOME=/tmp/nshome-…`),
    /// never a durable operator fleet.
    HomeUnderTmp(PathBuf),
}

impl PhantomReason {
    /// A short operator-facing phrase for the status rendering.
    pub fn describe(&self) -> String {
        match self {
            PhantomReason::DeletedCwd(p) => format!("cwd is a deleted dir ({})", escape_display(p)),
            PhantomReason::HomeUnderTmp(p) => {
                format!("home under temp dir ({})", escape_display(p))
            }
        }
    }
}

/// A discovered supervisor's working directory and whether it still exists on
/// disk. A non-existent cwd is the deleted-run-dir phantom signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cwd {
    pub path: PathBuf,
    /// Whether the directory still exists on disk.
    pub exists: bool,
}

/// One other supervisor found on the host.
#[derive(Debug, Clone)]
pub struct DiscoveredSupervisor {
    /// The control-socket path it was discovered at.
    pub socket: PathBuf,
    /// The daemon pid, if a `status` reply was obtained.
    pub pid: Option<u32>,
    /// The daemon's state home, recovered from its `status` `logFile`.
    pub home: Option<PathBuf>,
    /// The daemon process's working directory, when it could be read.
    pub cwd: Option<Cwd>,
    /// The phantom flags that applied (empty for a healthy supervisor).
    pub reasons: Vec<PhantomReason>,
    /// Whether the daemon answered the `status` probe. A live socket that could
    /// not be queried is reported as unresponsive rather than silently dropped.
    pub responsive: bool,
}

impl DiscoveredSupervisor {
    pub fn is_phantom(&self) -> bool {
        !self.reasons.is_empty()
    }
}

/// Classify a supervisor as a phantom. Pure so the policy is unit-testable
/// without a live daemon:
///
/// * a working directory that no longer exists → [`PhantomReason::DeletedCwd`];
/// * a state home under any throwaway temp root → [`PhantomReason::HomeUnderTmp`].
///
/// `temp_roots` is the set of throwaway roots a home is matched against (see
/// [`temp_roots`]): the socket dir alone is not enough, because on macOS it is a
/// per-user `/var/folders/...` path while the incident signature parks a home at
/// the platform-canonical `/tmp`. Both signals can apply at once (a `/tmp` home
/// whose run dir was also wiped), so every matching reason is returned rather
/// than the first.
pub fn classify(
    home: Option<&Path>,
    temp_roots: &[PathBuf],
    cwd: Option<&Cwd>,
) -> Vec<PhantomReason> {
    let mut reasons = Vec::new();
    if let Some(cwd) = cwd {
        if !cwd.exists {
            reasons.push(PhantomReason::DeletedCwd(cwd.path.clone()));
        }
    }
    if let Some(home) = home {
        if path_under_any(home, temp_roots) {
            reasons.push(PhantomReason::HomeUnderTmp(home.to_path_buf()));
        }
    }
    reasons
}

/// The normalized absolute identity of `path` used for containment.
/// `Path::starts_with` is purely lexical, so an unnormalized `/tmp/../home/x`
/// would spuriously match `/tmp` and a symlinked alias into the temp tree would
/// evade it. We therefore compare the *resolved* identity: the canonical path
/// when it exists on disk (resolving `..` and every symlink). The lexical
/// normalization (resolving `.`/`..` without touching the filesystem) is only a
/// *fallback* for a path that has since disappeared — and then it is anchored at
/// the canonical form of the longest ancestor that still exists, so a vanished
/// descendant of a symlinked directory still resolves to its real location.
///
/// Crucially the lexical form is NOT retained alongside the canonical one: an
/// existing `/tmp/state-link` that points at `/srv/state` has the canonical
/// identity `/srv/state`, and keeping its lexical `/tmp/...` spelling as a
/// second identity would falsely flag it as a temp-backed phantom. One path has
/// one identity. A non-absolute or empty result yields `None` so a misread can
/// never match a root.
fn normalized_identity(path: &Path) -> Option<PathBuf> {
    // Reject non-absolute (or empty) input *before* touching the filesystem.
    // `canonicalize` (and the ancestor walk below) resolve a relative path
    // against the *status command's* own cwd, not the peer's — so a relative
    // home left unresolved (e.g. the peer cwd was unreadable) could be
    // canonicalized against our cwd and spuriously match a temp root. A path
    // we cannot anchor to the peer has no absolute identity: yield `None`.
    if !path.is_absolute() {
        return None;
    }
    if let Ok(canon) = std::fs::canonicalize(path) {
        return Some(canon);
    }
    // The path itself is gone (or unstatable). Canonicalize the longest ancestor
    // that still exists so any symlinked prefix is resolved to its real target,
    // then re-attach the lexically-normalized missing tail.
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path;
    loop {
        match cursor.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                // Capture the *real* final component of `cursor`. `file_name()`
                // returns `None` when `cursor` ends in `..` (or `.`), so using
                // it would push an empty component and silently drop that
                // traversal — e.g. `/tmp/missing/../../srv/state` would lose the
                // `..`s and reconstruct `/tmp/missing/srv/state`, falsely
                // temp-flagging a home that actually resolves to `/srv/state`.
                // Pushing the raw component lets `lexical_normalize` below apply
                // the `..` pop correctly.
                if let Some(last) = cursor.components().next_back() {
                    missing.push(last.as_os_str().to_os_string());
                }
                cursor = parent;
                if let Ok(canon) = std::fs::canonicalize(cursor) {
                    let mut out = canon;
                    for comp in missing.iter().rev() {
                        out.push(comp);
                    }
                    let out = lexical_normalize(&out);
                    return if out.is_absolute() && !out.as_os_str().is_empty() {
                        Some(out)
                    } else {
                        None
                    };
                }
            }
            _ => {
                // No statable ancestor: fall back to a purely lexical resolution.
                let out = lexical_normalize(path);
                return if out.is_absolute() && !out.as_os_str().is_empty() {
                    Some(out)
                } else {
                    None
                };
            }
        }
    }
}

/// Resolve `.` and `..` components purely lexically, without consulting the
/// filesystem (so it still works for a path that no longer exists). `..` pops the
/// accumulated tail; a leading root is preserved.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Whether `path` resolves to the same as, or nested under, any of `roots`,
/// comparing normalized filesystem identities ([`normalized_identity`]) rather
/// than raw lexical prefixes. A relative or empty root (or candidate) matches
/// nothing, so a misread never flags a legitimate home.
fn path_under_any(path: &Path, roots: &[PathBuf]) -> bool {
    let Some(path) = normalized_identity(path) else {
        return false;
    };
    roots
        .iter()
        .any(|root| normalized_identity(root).is_some_and(|r| path.starts_with(r)))
}

/// Whether a discovered peer's recovered `peer_home` is the SAME filesystem
/// identity as the caller's already-normalized `current_identity`. Two
/// equivalent spellings or a symlink alias of one home hash to different control
/// socket names, so the socket-path filter cannot exclude the caller's own
/// daemon when `status` is invoked through an alias — comparing normalized
/// identities can. Returns `false` unless BOTH identities resolve: a peer with
/// no recoverable home (or an unstatable caller home) cannot be proven to be the
/// caller, so it is kept rather than silently dropped.
#[cfg(unix)]
fn is_same_home_identity(peer_home: Option<&Path>, current_identity: Option<&Path>) -> bool {
    match (peer_home.and_then(normalized_identity), current_identity) {
        (Some(peer), Some(current)) => peer == current,
        _ => false,
    }
}

/// The throwaway temp roots a daemon's state home is matched against. The socket
/// directory (`std::env::temp_dir()`) alone is insufficient: on macOS it is a
/// per-user `/var/folders/...` path, so a home an agent run parked at the
/// platform-canonical `/tmp/nshome` — the exact incident signature #42 targets —
/// would go unflagged. Enumerate every well-known throwaway root so a home under
/// any of them is classified regardless of which the launching run used;
/// [`path_under_any`] additionally folds in each root's canonical alias (e.g.
/// `/tmp` → `/private/tmp` on macOS).
#[cfg(unix)]
fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    for p in ["/tmp", "/private/tmp", "/var/tmp"] {
        let p = PathBuf::from(p);
        if !roots.contains(&p) {
            roots.push(p);
        }
    }
    roots
}

/// Recover a daemon's state home from its `status` `logFile`, which the daemon
/// publishes as `<home>/logs/supervisor/daemon.log` (see
/// [`crate::daemon`] descriptor construction). Returns `None` when the path does
/// not carry that trailing shape, so a Node daemon logging elsewhere is simply
/// reported without a home rather than mis-derived.
pub fn home_from_log_file(log_file: &Path) -> Option<PathBuf> {
    let tail = [
        std::ffi::OsStr::new("daemon.log"),
        std::ffi::OsStr::new("supervisor"),
        std::ffi::OsStr::new("logs"),
    ];
    let mut cur = log_file;
    for expected in tail {
        if cur.file_name() != Some(expected) {
            return None;
        }
        cur = cur.parent()?;
    }
    if cur.as_os_str().is_empty() {
        None
    } else {
        Some(cur.to_path_buf())
    }
}

/// Whether a temp-dir entry name is a supervisor control socket
/// (`c8ctl-nano-sup-<hash>.sock`). [`crate::control::socket_path`] derives the
/// `<hash>` as exactly eight lowercase hex characters (`sha1(home)[:8]`), so the
/// shape is pinned, not a loose prefix/suffix: an unrelated live socket such as
/// `c8ctl-nano-sup-debug.sock` must fail closed here rather than be probed and
/// reported as a supervisor.
fn is_supervisor_socket_name(name: &str) -> bool {
    let Some(hash) = name
        .strip_prefix("c8ctl-nano-sup-")
        .and_then(|n| n.strip_suffix(".sock"))
    else {
        return false;
    };
    hash.len() == 8
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Discover the *other* supervisors running on this host (every one except the
/// caller's own `current_home`), each classified for phantom flags. Returns an
/// empty vec on any discovery error (a best-effort hygiene overlay must never
/// make `supervisor status` fail).
#[cfg(unix)]
pub fn discover_other_supervisors(current_home: &Path) -> Vec<DiscoveredSupervisor> {
    use std::time::{Duration, Instant};

    // One overall discovery deadline. Each candidate costs a liveness probe plus
    // a status request, so N wedged/phantom sockets would otherwise stack into
    // ~N × (probe + status) of serial blocking — precisely when an operator runs
    // `supervisor status` for fleet hygiene. Cap the whole sweep so a host
    // littered with stale sockets cannot stall status; on exhaustion we stop the
    // best-effort sweep rather than reporting unprobed candidates.
    const DISCOVERY_BUDGET: Duration = Duration::from_secs(5);
    const PROBE_BUDGET: Duration = Duration::from_millis(500);
    const STATUS_BUDGET: Duration = Duration::from_secs(2);
    let deadline = Instant::now() + DISCOVERY_BUDGET;
    let remaining = |deadline: Instant| deadline.saturating_duration_since(Instant::now());

    let temp = std::env::temp_dir();
    let roots = temp_roots();
    let current_sock = crate::control::socket_path(current_home);
    // The caller's own home canonical filesystem identity. `socket_path` hashes
    // the raw home *spelling*, so an equivalent spelling or symlink alias of the
    // same home derives a DIFFERENT socket name and is therefore NOT excluded by
    // the `path == current_sock` filter below — yet it is the same daemon, which
    // would then be discovered and rendered as an "other" (potentially phantom)
    // supervisor. Capture the normalized identity once so each inspected peer can
    // be discarded when its recovered home resolves to the same identity.
    let current_home_identity = normalized_identity(current_home);
    let mut out = Vec::new();

    let entries = match std::fs::read_dir(&temp) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        // Check the overall deadline at the TOP of every iteration, before the
        // socket-name filter. The filter `continue`s past every non-socket entry,
        // so a deadline check placed after it would never run while a large temp
        // directory of unrelated entries is drained — the sweep would then exceed
        // its advertised bound precisely on the littered host it exists to bound.
        if remaining(deadline).is_zero() {
            // Deadline exhausted. We cannot distinguish a live supervisor from a
            // stale leftover socket (or even a same-named regular file) without a
            // probe, and the budget forbids probing — so reporting these as
            // running "unresponsive" supervisors would fabricate results that
            // contradict the stale-socket filtering below. Stop the sweep instead:
            // a best-effort hygiene overlay under-reports rather than invents a
            // phantom. Remaining candidates share the exhausted deadline, so
            // `break` (not `continue`) is correct.
            break;
        }

        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !is_supervisor_socket_name(name) || path == current_sock {
            continue;
        }

        let budget = remaining(deadline);
        if budget.is_zero() {
            // Unreachable: the top-of-loop check above already broke out on an
            // exhausted deadline. Kept as a defensive guard so the probe below
            // can never be handed a zero (or negative-saturated) budget.
            break;
        }

        // A stale leftover socket (connect refused / absent) belongs to a dead
        // owner — not a running supervisor — so it is not a phantom to report.
        // Anything else (live, or an indeterminate backlogged peer) is a running
        // supervisor we must surface. Each probe is capped by the time still left
        // on the overall deadline, so a slow peer cannot overrun the sweep.
        match crate::control::probe_liveness(&path, budget.min(PROBE_BUDGET)) {
            crate::control::Liveness::Absent => continue,
            crate::control::Liveness::Live | crate::control::Liveness::Indeterminate(_) => {}
        }

        let inspected = inspect_supervisor(path, &roots, remaining(deadline).min(STATUS_BUDGET));

        // Self-exclusion by home identity, not just socket path. The socket-path
        // filter above misses an equivalent spelling/symlink alias of the caller's
        // own home (it hashes the raw spelling), so after inspection also discard
        // a peer whose recovered home has the same normalized filesystem identity
        // as `current_home` — that peer IS this daemon, not an "other" supervisor.
        if is_same_home_identity(inspected.home.as_deref(), current_home_identity.as_deref()) {
            continue;
        }

        out.push(inspected);
    }

    // Deterministic order (phantoms first, then by socket path) so the rendering
    // is stable across runs regardless of directory-iteration order.
    out.sort_by(|a, b| {
        b.is_phantom()
            .cmp(&a.is_phantom())
            .then_with(|| a.socket.cmp(&b.socket))
    });
    out
}

/// Non-Unix stub: the control socket is a Unix-domain transport, so there is no
/// host-wide supervisor discovery to offer off-Unix.
#[cfg(not(unix))]
pub fn discover_other_supervisors(_current_home: &Path) -> Vec<DiscoveredSupervisor> {
    Vec::new()
}

/// Query one live control socket for its `status`, recover its home and cwd, and
/// classify it. `status_budget` bounds the status request so the caller's overall
/// discovery deadline is honoured across candidates.
#[cfg(unix)]
fn inspect_supervisor(
    socket: PathBuf,
    temp_roots: &[PathBuf],
    status_budget: std::time::Duration,
) -> DiscoveredSupervisor {
    let reply = crate::control::request_with_timeout(
        &socket,
        &serde_json::json!({ "op": "status" }),
        status_budget,
    );
    let frame = reply.ok().and_then(|frames| {
        frames
            .iter()
            .find(|f| f.get("final").and_then(|v| v.as_bool()).unwrap_or(false))
            .or_else(|| frames.last())
            .cloned()
    });

    // The terminal frame only counts as a healthy status answer when it has the
    // *positive* documented shape — `ok:true`, `type:"status"`, and a `daemon`
    // descriptor object. A merely "not an explicit error" test (`ok != false`)
    // would accept any other terminal JSON: a response for a different op, a
    // malformed descriptor, or a peer that answered with something unrecognised
    // would all be parsed and rendered as a healthy/phantom supervisor. Validate
    // the positive shape before extracting peer data or marking the endpoint
    // responsive, so only a genuine status reply counts.
    let is_status_frame = frame.as_ref().is_some_and(is_status_frame_shape);

    let (pid, home) = match &frame {
        Some(f) if is_status_frame => {
            // A peer-reported pid that does not fit in u32 must not wrap to an
            // unrelated local pid (`as u32` truncates); treat it as absent.
            let pid = status_frame_pid(f);
            let home = f["daemon"]["logFile"]
                .as_str()
                .and_then(|lf| home_from_log_file(Path::new(lf)));
            (pid, home)
        }
        _ => (None, None),
    };
    let responsive = is_status_frame;
    let cwd = pid.and_then(process_cwd);
    // A relative `logFile` (a daemon launched with a relative `C8CTL_NANO_HOME`)
    // yields a relative home that `path_under` would never flag. Resolve it
    // against the daemon's own working directory — the base the daemon itself
    // resolved it against — so a temp-backed relative home is still classified.
    let home = home.map(|h| resolve_home(h, cwd.as_ref()));
    let reasons = classify(home.as_deref(), temp_roots, cwd.as_ref());

    DiscoveredSupervisor {
        socket,
        pid,
        home,
        cwd,
        reasons,
        responsive,
    }
}

/// Whether a terminal control frame is a genuine `status` answer. Positive
/// shape only: `ok:true`, `type:"status"`, and a `daemon` descriptor object.
/// Anything else — an explicit error, a reply for another op, or a malformed
/// descriptor — is not a healthy status answer and must not mark the endpoint
/// responsive or supply peer data.
#[cfg(unix)]
fn is_status_frame_shape(f: &serde_json::Value) -> bool {
    f.get("ok").and_then(|v| v.as_bool()) == Some(true)
        && f.get("type").and_then(|v| v.as_str()) == Some("status")
        && f.get("daemon").map(|d| d.is_object()).unwrap_or(false)
}

/// The peer-reported daemon pid from a validated status frame, or `None` when
/// it is absent or does not fit in `u32`. A checked conversion is used so an
/// out-of-range value cannot wrap (via `as u32` truncation) onto an unrelated
/// local pid.
#[cfg(unix)]
fn status_frame_pid(f: &serde_json::Value) -> Option<u32> {
    f["daemon"]["pid"]
        .as_u64()
        .and_then(|p| u32::try_from(p).ok())
}

/// Resolve a daemon's recovered state home to an absolute path. A daemon that
/// published a relative `logFile` (relative `C8CTL_NANO_HOME`) built it from its
/// own working directory, so anchor the relative home at that cwd; an absolute
/// home (or an unreadable cwd) is returned unchanged.
#[cfg(unix)]
fn resolve_home(home: PathBuf, cwd: Option<&Cwd>) -> PathBuf {
    if home.is_absolute() {
        return home;
    }
    match cwd {
        Some(c) if !c.path.as_os_str().is_empty() => c.path.join(&home),
        _ => home,
    }
}

/// Read a process's working directory and whether it still exists on disk.
/// Returns `None` when it cannot be determined (the process vanished, or the
/// platform offers no probe) — the home-under-temp check still applies without
/// it.
#[cfg(target_os = "linux")]
fn process_cwd(pid: u32) -> Option<Cwd> {
    // Linux exposes the live cwd as the `/proc/<pid>/cwd` symlink, and appends a
    // literal " (deleted)" suffix to the target when that directory has been
    // unlinked — the exact deleted-run-dir signature #40 leaves behind.
    let target = std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
    // Check the FULL kernel-reported path first. If it exists verbatim it is a
    // live directory — even one whose real name literally ends in " (deleted)".
    if target.exists() {
        return Some(Cwd {
            path: target,
            exists: true,
        });
    }
    // The verbatim target is absent. Only the kernel's literal " (deleted)"
    // marker proves the cwd was unlinked; strip it to recover the real (now-gone)
    // directory name and flag it. An UNMARKED target that fails `exists()` is NOT
    // proof of deletion: `exists()` is also false on a permission error, and the
    // target may live outside this process's mount namespace. Treat that case as
    // unknown (None) rather than fabricating a deleted-cwd phantom flag.
    let s = target.to_string_lossy();
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        return Some(Cwd {
            path: PathBuf::from(stripped),
            exists: false,
        });
    }
    None
}

#[cfg(target_os = "macos")]
fn process_cwd(pid: u32) -> Option<Cwd> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // macOS has no `/proc`; `proc_pidinfo(PROC_PIDVNODEPATHINFO)` fills the
    // process's current-directory vnode path (`pvi_cdir.vip_path`).
    unsafe {
        let mut info: libc::proc_vnodepathinfo = std::mem::zeroed();
        let n = libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int,
        );
        if n <= 0 {
            return None;
        }
        let raw = &info.pvi_cdir.vip_path;
        // `vip_path` is really a 1024-byte buffer that libc models as
        // `[[c_char; 32]; 32]` for old-rustc compatibility; flatten it and stop
        // at the NUL terminator.
        let bytes: Vec<u8> = raw
            .iter()
            .flat_map(|chunk| chunk.iter())
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        if bytes.is_empty() {
            return None;
        }
        let path = PathBuf::from(OsString::from_vec(bytes));
        // Distinguish a confirmed absence from a probe failure. `Path::exists()`
        // maps EVERY metadata error to `false`, so an existing cwd that cannot be
        // traversed or statted (a permission error, or a transient I/O error)
        // would be misclassified as `DeletedCwd`. Only a `NotFound` error is a
        // confirmed deletion; any other error preserves this function's
        // "unknown on probe failure" contract by returning `None`.
        match std::fs::metadata(&path) {
            Ok(_) => Some(Cwd { path, exists: true }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Cwd {
                path,
                exists: false,
            }),
            Err(_) => None,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_cwd(_pid: u32) -> Option<Cwd> {
    None
}

/// Escape a peer-derived path for terminal display. The home, socket, cwd, and
/// reason paths rendered by [`render`] ultimately come from whatever peer bound
/// a hash-shaped socket in the shared temp directory, and `Path::display()`
/// preserves control characters and newlines verbatim. A hostile local process
/// could therefore answer `status` with a crafted `logFile` that injects ANSI
/// escapes or spoofs extra status lines on the operator's terminal. Render every
/// control character (and DEL) as a visible `\u{XX}` escape so a peer-derived
/// path can never emit a terminal control sequence or a line break.
fn escape_display(path: &Path) -> String {
    path.display()
        .to_string()
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                format!("\\u{{{:02x}}}", c as u32)
                    .chars()
                    .collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Render the "other supervisors on this host" section of `supervisor status`.
/// Returns the lines to print (empty when none were found) so the caller owns
/// the I/O and the formatting is testable.
pub fn render(supervisors: &[DiscoveredSupervisor]) -> Vec<String> {
    let mut lines = Vec::new();
    if supervisors.is_empty() {
        return lines;
    }
    let phantoms = supervisors.iter().filter(|s| s.is_phantom()).count();
    if phantoms > 0 {
        lines.push(format!(
            "Other supervisors on this host: {} ({phantoms} flagged as phantom)",
            supervisors.len()
        ));
    } else {
        lines.push(format!(
            "Other supervisors on this host: {}",
            supervisors.len()
        ));
    }
    for s in supervisors {
        let pid = s
            .pid
            .map(|p| format!("pid {p}"))
            .unwrap_or_else(|| "pid ?".to_string());
        let home = s
            .home
            .as_ref()
            .map(|h| escape_display(h))
            .unwrap_or_else(|| escape_display(&s.socket));
        if s.is_phantom() {
            let why = s
                .reasons
                .iter()
                .map(|r| r.describe())
                .collect::<Vec<_>>()
                .join("; ");
            lines.push(format!("  ⚠ PHANTOM {home} ({pid}): {why}"));
        } else if !s.responsive {
            lines.push(format!("  {home} ({pid}) [unresponsive]"));
        } else {
            // A healthy supervisor: show its cwd when we could read it, so an
            // operator can see at a glance where it is running from.
            match &s.cwd {
                Some(cwd) => lines.push(format!(
                    "  {home} ({pid}) cwd {}",
                    escape_display(&cwd.path)
                )),
                None => lines.push(format!("  {home} ({pid})")),
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The throwaway temp roots used by the pure-`classify` unit tests. Mirrors
    /// what `temp_roots()` supplies in production, pinned to `/tmp` so the tests
    /// are platform-independent.
    fn tmp_roots() -> Vec<PathBuf> {
        vec![PathBuf::from("/tmp")]
    }

    #[test]
    fn classify_flags_deleted_cwd() {
        let cwd = Cwd {
            path: PathBuf::from("/home/u/.local/state/nano-supervisor/runs/run-123"),
            exists: false,
        };
        let reasons = classify(
            Some(Path::new("/home/u/.local/state/c8ctl-nano")),
            &tmp_roots(),
            Some(&cwd),
        );
        assert_eq!(
            reasons,
            vec![PhantomReason::DeletedCwd(cwd.path.clone())],
            "a deleted cwd must flag the supervisor as a phantom"
        );
    }

    #[test]
    fn classify_flags_home_under_tmp() {
        let cwd = Cwd {
            path: PathBuf::from("/some/live/dir"),
            exists: true,
        };
        let reasons = classify(
            Some(Path::new("/tmp/nshome-Elnn")),
            &tmp_roots(),
            Some(&cwd),
        );
        assert_eq!(
            reasons,
            vec![PhantomReason::HomeUnderTmp(PathBuf::from(
                "/tmp/nshome-Elnn"
            ))],
            "a /tmp home must flag the supervisor as a phantom even with a live cwd"
        );
    }

    #[test]
    fn classify_flags_both_signals() {
        let cwd = Cwd {
            path: PathBuf::from("/tmp/nano-probe2/runs/run-9"),
            exists: false,
        };
        let reasons = classify(
            Some(Path::new("/tmp/nano-probe2")),
            &tmp_roots(),
            Some(&cwd),
        );
        assert_eq!(
            reasons.len(),
            2,
            "a /tmp home with a deleted cwd flags both"
        );
        assert!(matches!(reasons[0], PhantomReason::DeletedCwd(_)));
        assert!(matches!(reasons[1], PhantomReason::HomeUnderTmp(_)));
    }

    #[test]
    fn classify_passes_a_healthy_supervisor() {
        let cwd = Cwd {
            path: PathBuf::from("/home/u/work"),
            exists: true,
        };
        let reasons = classify(
            Some(Path::new("/home/u/.local/state/c8ctl-nano")),
            &tmp_roots(),
            Some(&cwd),
        );
        assert!(
            reasons.is_empty(),
            "a durable home with a live cwd is not a phantom: {reasons:?}"
        );
    }

    #[test]
    fn classify_without_cwd_still_checks_home() {
        let reasons = classify(Some(Path::new("/tmp/nshome-nbQk")), &tmp_roots(), None);
        assert_eq!(
            reasons,
            vec![PhantomReason::HomeUnderTmp(PathBuf::from(
                "/tmp/nshome-nbQk"
            ))],
            "an unreadable cwd must not hide a /tmp home"
        );
    }

    #[test]
    fn classify_without_home_still_checks_cwd() {
        let cwd = Cwd {
            path: PathBuf::from("/gone"),
            exists: false,
        };
        let reasons = classify(None, &tmp_roots(), Some(&cwd));
        assert_eq!(
            reasons,
            vec![PhantomReason::DeletedCwd(PathBuf::from("/gone"))]
        );
    }

    #[test]
    fn home_recovered_from_log_file() {
        let home = home_from_log_file(Path::new(
            "/home/u/.local/state/c8ctl-nano/logs/supervisor/daemon.log",
        ));
        assert_eq!(
            home,
            Some(PathBuf::from("/home/u/.local/state/c8ctl-nano")),
            "the home is the log path minus logs/supervisor/daemon.log"
        );
    }

    #[test]
    fn home_from_log_file_rejects_unexpected_shape() {
        assert_eq!(
            home_from_log_file(Path::new("/var/log/other/daemon.log")),
            None,
            "a log path that is not <home>/logs/supervisor/daemon.log yields no home"
        );
        assert_eq!(home_from_log_file(Path::new("daemon.log")), None);
        // A home-less log (the tail is the whole path) must not yield an empty home.
        assert_eq!(
            home_from_log_file(Path::new("logs/supervisor/daemon.log")),
            None
        );
    }

    #[test]
    fn socket_name_filter() {
        assert!(is_supervisor_socket_name("c8ctl-nano-sup-57425ec9.sock"));
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-57425ec9.lock"));
        assert!(!is_supervisor_socket_name("other.sock"));
        assert!(!is_supervisor_socket_name("c8ctl-nano-fleet-abc.lock"));
    }

    #[test]
    fn socket_name_filter_requires_the_exact_hash_shape() {
        // `control::socket_path` emits exactly eight lowercase hex chars; anything
        // else between the prefix and suffix is an unrelated socket that must fail
        // closed (not be probed and reported as a supervisor).
        // Wrong length.
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-57425ec.sock")); // 7
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-57425ec9aa.sock")); // 10
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-.sock")); // empty
                                                                     // Non-hex / uppercase.
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-57425EC9.sock"));
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-57425ecg.sock"));
        // An arbitrary live socket that merely shares the prefix/suffix.
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-debug.sock"));
        assert!(!is_supervisor_socket_name("c8ctl-nano-sup-debug.sock.sock"));
        // The genuine shape still passes (digits and a-f).
        assert!(is_supervisor_socket_name("c8ctl-nano-sup-01234567.sock"));
        assert!(is_supervisor_socket_name("c8ctl-nano-sup-abcdefab.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_home_anchors_a_relative_home_at_the_daemon_cwd() {
        let cwd = Cwd {
            path: PathBuf::from("/tmp"),
            exists: true,
        };
        // A daemon launched from /tmp with a relative home resolves under /tmp.
        assert_eq!(
            resolve_home(PathBuf::from("nshome"), Some(&cwd)),
            PathBuf::from("/tmp/nshome"),
            "a relative home must resolve against the daemon's cwd"
        );
        // An absolute home is returned unchanged.
        assert_eq!(
            resolve_home(PathBuf::from("/var/lib/nshome"), Some(&cwd)),
            PathBuf::from("/var/lib/nshome")
        );
        // No cwd to anchor against: the relative home is returned unchanged (the
        // classifier then simply cannot flag it rather than guessing a base).
        assert_eq!(
            resolve_home(PathBuf::from("nshome"), None),
            PathBuf::from("nshome")
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_home_resolved_against_tmp_cwd_is_flagged() {
        // The classification half of the relative-home fix: once `resolve_home`
        // anchors a relative home at a /tmp cwd, `classify` must flag it.
        let cwd = Cwd {
            path: PathBuf::from("/tmp"),
            exists: true,
        };
        let home = resolve_home(PathBuf::from("nshome"), Some(&cwd));
        let reasons = classify(Some(&home), &tmp_roots(), Some(&cwd));
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, PhantomReason::HomeUnderTmp(_))),
            "a relative home resolved under /tmp must flag: {reasons:?}"
        );
    }

    #[test]
    fn path_under_any_handles_edges() {
        let tmp = tmp_roots();
        assert!(path_under_any(Path::new("/tmp/x"), &tmp));
        assert!(path_under_any(Path::new("/tmp"), &tmp));
        assert!(!path_under_any(Path::new("/home/u"), &tmp));
        // A relative or empty root never matches, so a misread cannot flag a home.
        assert!(!path_under_any(Path::new("/tmp/x"), &[PathBuf::from("")]));
        assert!(!path_under_any(
            Path::new("/tmp/x"),
            &[PathBuf::from("relative")]
        ));
        // A relative candidate path never matches either.
        assert!(!path_under_any(Path::new("relative/x"), &tmp));
    }

    #[test]
    fn path_under_any_is_not_fooled_by_dotdot() {
        // `starts_with` is lexical: an un-normalized `/tmp/../home/...` textually
        // begins with `/tmp` but resolves OUTSIDE it, so it must NOT be flagged.
        assert!(!path_under_any(
            Path::new("/tmp/../home/user/state"),
            &tmp_roots()
        ));
        // ...while a genuinely nested (but `.`/`..`-laden) path still matches.
        assert!(path_under_any(Path::new("/tmp/./a/../b"), &tmp_roots()));
    }

    #[test]
    fn normalized_identity_rejects_relative_input_before_touching_disk() {
        // A relative candidate must yield `None` rather than being canonicalized
        // against the *status command's* cwd: `.` and `..` both exist relative to
        // our cwd and would otherwise resolve to real absolute paths that could
        // spuriously match a temp root.
        assert_eq!(normalized_identity(Path::new(".")), None);
        assert_eq!(normalized_identity(Path::new("..")), None);
        assert_eq!(normalized_identity(Path::new("nshome")), None);
        assert_eq!(normalized_identity(Path::new("")), None);
    }

    #[test]
    fn normalized_identity_preserves_trailing_parent_traversal_in_missing_tail() {
        // A vanished descendant whose missing tail contains `..` must keep that
        // traversal: the longest existing ancestor is canonicalized and the tail
        // re-applied lexically, so `<tmp>/missing/../sibling` resolves to
        // `<tmp>/sibling`, NOT `<tmp>/missing/sibling`. Dropping the `..` (the old
        // `file_name()` bug) would falsely place it under the missing subtree.
        let base = std::env::temp_dir().join(format!("c8ctl-nano-normid-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("create base");
        let real = std::fs::canonicalize(&base).expect("canonicalize base");
        // `missing` does not exist, so the tail `missing/../sibling` is resolved
        // lexically against the canonical base.
        let candidate = base.join("missing").join("..").join("sibling");
        let got = normalized_identity(&candidate);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(
            got,
            Some(real.join("sibling")),
            "the `..` in the missing tail must collapse `missing`"
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_flags_home_via_symlink_into_tmp() {
        // A home that is a symlink whose target resolves under a temp root must be
        // flagged: `normalized_forms` canonicalizes the live path, so the alias
        // cannot evade the classifier.
        let _guard = crate::cwd_test_guard();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let real =
            std::env::temp_dir().join(format!("c8ctl-nano-symreal-{}-{nanos}", std::process::id()));
        let link =
            std::env::temp_dir().join(format!("c8ctl-nano-symlink-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&real).expect("create real home");
        let _ = std::fs::remove_file(&link);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).expect("create symlink home");
        // Classify against a root that does NOT lexically contain the link path,
        // but whose canonical identity does (the system temp dir itself).
        let roots = vec![std::env::temp_dir()];
        let reasons = classify(Some(&link), &roots, None);
        let flagged = reasons
            .iter()
            .any(|r| matches!(r, PhantomReason::HomeUnderTmp(_)));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&real);
        assert!(
            flagged,
            "a symlinked home resolving under the temp dir must flag: {reasons:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_does_not_flag_a_symlink_that_escapes_tmp() {
        // Regression for the retained-lexical-form false positive: an EXISTING
        // symlink that lives under a temp root but points OUTSIDE it must not be
        // flagged. Its canonical identity is the target (`/srv/state`-like), so
        // keeping the lexical `/tmp/...` spelling as a second identity would
        // falsely match the temp root. One path has one identity.
        let _guard = crate::cwd_test_guard();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // A real target OUTSIDE every temp root, under a unique non-temp dir.
        let real = std::env::current_dir().expect("cwd").join(format!(
            "c8ctl-nano-escape-real-{}-{nanos}",
            std::process::id()
        ));
        // A symlink to it parked under the system temp dir.
        let link = std::env::temp_dir().join(format!(
            "c8ctl-nano-escape-link-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&real).expect("create real dir outside temp");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).expect("create escaping symlink");
        // Classify against the temp roots: the link's lexical spelling is under
        // temp, but its canonical identity (the real dir) is not.
        let roots = temp_roots();
        let reasons = classify(Some(&link), &roots, None);
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&real);
        assert!(
            !reasons
                .iter()
                .any(|r| matches!(r, PhantomReason::HomeUnderTmp(_))),
            "a symlink whose canonical target escapes temp must NOT flag: {reasons:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn is_same_home_identity_matches_a_symlink_alias() {
        // Regression (self-exclusion via alias): `socket_path` hashes the raw home
        // spelling, so invoking `status` through a symlink alias of the daemon's
        // home derives a DIFFERENT socket name and escapes the `path ==
        // current_sock` filter — the daemon would then list itself as an "other"
        // (potentially phantom) supervisor. The identity comparison must recognise
        // the alias as the same home.
        let _guard = crate::cwd_test_guard();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let real = std::env::temp_dir().join(format!(
            "c8ctl-nano-selfid-real-{}-{nanos}",
            std::process::id()
        ));
        let link = std::env::temp_dir().join(format!(
            "c8ctl-nano-selfid-link-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&real).expect("create real home");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).expect("create symlink alias");

        let current_identity = normalized_identity(&link);
        // The peer reports its home via the canonical spelling; the caller came in
        // through the alias. They must compare equal.
        let matched = is_same_home_identity(Some(&real), current_identity.as_deref());

        // A genuinely different home must NOT match.
        let other = std::env::temp_dir().join(format!(
            "c8ctl-nano-selfid-other-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&other).expect("create other home");
        let other_matched = is_same_home_identity(Some(&other), current_identity.as_deref());

        // A peer with no recoverable home cannot be proven to be the caller.
        let none_matched = is_same_home_identity(None, current_identity.as_deref());

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_dir_all(&other);

        assert!(matched, "a symlink alias of the same home must match");
        assert!(!other_matched, "a different home must not match");
        assert!(!none_matched, "an unrecoverable peer home must not match");
    }

    #[test]
    fn classify_flags_literal_tmp_home_regardless_of_socket_dir() {
        // Finding: on macOS the socket dir is `/var/folders/...`, so classifying
        // against it alone would miss a home literally under `/tmp`. The root set
        // must include the platform throwaway roots so `/tmp/nshome` is flagged
        // even when the socket dir is elsewhere.
        let roots = vec![
            PathBuf::from("/var/folders/ab/cd/T"),
            PathBuf::from("/tmp"),
            PathBuf::from("/private/tmp"),
        ];
        let reasons = classify(Some(Path::new("/tmp/nshome")), &roots, None);
        assert_eq!(
            reasons,
            vec![PhantomReason::HomeUnderTmp(PathBuf::from("/tmp/nshome"))],
            "a literal /tmp home must flag even when the socket dir is a /var/folders path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn temp_roots_includes_the_platform_throwaway_roots() {
        let roots = temp_roots();
        assert!(
            roots.contains(&std::env::temp_dir()),
            "the socket dir must be a root: {roots:?}"
        );
        assert!(
            roots.contains(&PathBuf::from("/tmp")),
            "the canonical /tmp must be a root: {roots:?}"
        );
    }

    #[test]
    fn render_marks_phantoms_and_counts() {
        let supers = vec![
            DiscoveredSupervisor {
                socket: PathBuf::from("/tmp/c8ctl-nano-sup-aaaaaaaa.sock"),
                pid: Some(3132592),
                home: Some(PathBuf::from("/tmp/nshome-nbQk")),
                cwd: None,
                reasons: vec![PhantomReason::HomeUnderTmp(PathBuf::from(
                    "/tmp/nshome-nbQk",
                ))],
                responsive: true,
            },
            DiscoveredSupervisor {
                socket: PathBuf::from("/tmp/c8ctl-nano-sup-bbbbbbbb.sock"),
                pid: Some(42),
                home: Some(PathBuf::from("/home/u/.local/state/c8ctl-nano")),
                cwd: Some(Cwd {
                    path: PathBuf::from("/home/u/work"),
                    exists: true,
                }),
                reasons: vec![],
                responsive: true,
            },
        ];
        let lines = render(&supers);
        assert_eq!(
            lines[0],
            "Other supervisors on this host: 2 (1 flagged as phantom)"
        );
        assert!(lines[1].contains("PHANTOM"), "line: {}", lines[1]);
        assert!(lines[1].contains("/tmp/nshome-nbQk"));
        assert!(!lines[2].contains("PHANTOM"), "line: {}", lines[2]);
    }

    #[test]
    fn render_empty_when_no_others() {
        assert!(render(&[]).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn status_frame_shape_requires_the_positive_documented_form() {
        // A genuine status answer is accepted.
        assert!(is_status_frame_shape(
            &serde_json::json!({"ok": true, "type": "status", "daemon": {"pid": 1}})
        ));
        // An explicit protocol error is not a healthy status answer.
        assert!(!is_status_frame_shape(
            &serde_json::json!({"ok": false, "error": "boom", "final": true})
        ));
        // A reply for a different op (no `type:"status"`) must not be treated as
        // a healthy status answer even though it is not an explicit error.
        assert!(!is_status_frame_shape(
            &serde_json::json!({"ok": true, "type": "stopped", "final": true})
        ));
        // A well-formed status shape missing the daemon descriptor is rejected.
        assert!(!is_status_frame_shape(
            &serde_json::json!({"ok": true, "type": "status"})
        ));
        // A `daemon` that is not an object is rejected.
        assert!(!is_status_frame_shape(
            &serde_json::json!({"ok": true, "type": "status", "daemon": "x"})
        ));
    }

    #[cfg(unix)]
    #[test]
    fn status_frame_pid_rejects_an_out_of_range_value() {
        // An in-range pid is recovered.
        assert_eq!(
            status_frame_pid(&serde_json::json!({"daemon": {"pid": 4242}})),
            Some(4242)
        );
        // A pid beyond u32::MAX must not wrap onto an unrelated local pid.
        assert_eq!(
            status_frame_pid(&serde_json::json!({"daemon": {"pid": 4294967296u64}})),
            None
        );
        // A missing pid is absent, not a crash.
        assert_eq!(status_frame_pid(&serde_json::json!({"daemon": {}})), None);
    }

    #[test]
    fn render_escapes_control_characters_in_peer_paths() {
        // Peer-derived paths (home, cwd, and the reason paths they feed) must
        // never reach the terminal bearing control characters or newlines: a
        // hostile local process could otherwise spoof status lines or emit ANSI
        // escapes. Every control char is rendered as a visible \u{XX} escape.
        let evil_home = PathBuf::from("/tmp/nshome-\u{1b}[31m\nspoofed");
        let evil_cwd = PathBuf::from("/home/u/work\u{1b}[2j");
        let supers = vec![DiscoveredSupervisor {
            socket: PathBuf::from("/tmp/c8ctl-nano-sup-aaaaaaaa.sock"),
            pid: Some(7),
            home: Some(evil_home.clone()),
            cwd: Some(Cwd {
                path: evil_cwd.clone(),
                exists: true,
            }),
            reasons: vec![PhantomReason::HomeUnderTmp(evil_home.clone())],
            responsive: true,
        }];
        let out = render(&supers).join("\n");
        assert!(
            !out.contains('\u{1b}'),
            "no raw ESC may reach the terminal: {out:?}"
        );
        // The only newline is the one we joined with; the peer's `\n` is escaped.
        assert!(
            !out.contains("spoofed\n") && out.contains("\\u{0a}"),
            "the embedded newline is escaped: {out:?}"
        );
        assert!(
            out.contains("\\u{1b}"),
            "the escape char itself is rendered visibly: {out:?}"
        );
    }

    /// A genuinely deleted cwd IS flagged: chdir into a dir, remove it, and
    /// `/proc/self/cwd` reports `<path> (deleted)` with the full marked path gone.
    /// This is the regression for the deletion-marker handling: the full target no
    /// longer exists, so the suffix is the kernel's marker and the supervisor is
    /// flagged. Holds the repository-wide [`crate::cwd_test_guard`] (not a private
    /// mutex) so it serializes against every other cwd-sensitive test in the crate
    /// — including `fleet.rs` and the live-marker converse below — which all read
    /// or mutate the single process-wide cwd.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_cwd_flags_a_genuinely_deleted_dir() {
        let _guard = crate::cwd_test_guard();
        let base = std::env::temp_dir().join(format!(
            "c8ctl-nano-gone-cwd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("create dir to delete");
        let original = std::env::current_dir().expect("current dir");

        std::env::set_current_dir(&base).expect("chdir into dir");
        std::fs::remove_dir_all(&base).expect("delete the cwd out from under the process");
        let cwd = process_cwd(std::process::id());
        std::env::set_current_dir(&original).expect("restore cwd");

        let cwd = cwd.expect("read own deleted cwd");
        assert!(!cwd.exists, "a deleted cwd must be flagged: {cwd:?}");
        assert_eq!(cwd.path, base, "the stripped (original) path is reported");
    }

    /// The converse of the deletion-marker handling: a LIVE directory whose real
    /// name literally ends in ` (deleted)` must NOT be flagged. Because the full
    /// `/proc/self/cwd` target still exists on disk, `process_cwd` must report it
    /// as live rather than stripping the suffix and misreading it as a deleted
    /// cwd. Sharing [`crate::cwd_test_guard`] with the deletion test above makes
    /// this deterministic: the two cwd mutations can no longer interleave through
    /// the shared `/proc/self`.
    #[cfg(target_os = "linux")]
    #[test]
    fn process_cwd_keeps_a_live_dir_named_like_the_marker() {
        let _guard = crate::cwd_test_guard();
        let base = std::env::temp_dir().join(format!(
            "c8ctl-nano-live-{}-{} (deleted)",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("create live dir ending in the marker");
        let original = std::env::current_dir().expect("current dir");

        std::env::set_current_dir(&base).expect("chdir into the live marker dir");
        let cwd = process_cwd(std::process::id());
        std::env::set_current_dir(&original).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&base);

        let cwd = cwd.expect("read own live cwd");
        assert!(
            cwd.exists,
            "a live dir whose name ends in ' (deleted)' must not be flagged: {cwd:?}"
        );
        assert_eq!(
            cwd.path, base,
            "the full (un-stripped) path is reported for a live marker-named dir"
        );
    }

    /// Socket-level tests for `inspect_supervisor` against a scripted fake peer.
    #[cfg(unix)]
    mod inspect {
        use super::*;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        /// Serve one connection that replies with `frame`, returning the socket
        /// path. The server thread is detached (the test asserts on the reply,
        /// not on a clean shutdown).
        fn serve_frame(tag: &str, frame: serde_json::Value) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let sock = std::env::temp_dir()
                .join(format!("nst-inspect-{tag}-{}-{nanos}", std::process::id()));
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(&sock).expect("bind inspect test socket");
            let path = sock.clone();
            let body = frame.to_string();
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    // Drain the request line, then answer with the scripted frame.
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let _ = stream.write_all(body.as_bytes());
                    let _ = stream.write_all(b"\n");
                    let _ = stream.flush();
                }
                let _ = std::fs::remove_file(&path);
            });
            sock
        }

        /// A terminal PROTOCOL ERROR frame (`{ok:false,error,…,final:true}`) must
        /// NOT mark the endpoint responsive: the daemon answered but rejected the
        /// op, exactly as `fleet.rs::terminal_frame_error` surfaces it as a
        /// failure. Rendering must show `[unresponsive]`, never a healthy `pid ?`.
        #[test]
        fn protocol_error_frame_is_not_responsive() {
            let sock = serve_frame(
                "err",
                serde_json::json!({"ok": false, "error": "unknown op", "final": true}),
            );
            let sup = inspect_supervisor(
                sock,
                &[PathBuf::from("/tmp")],
                std::time::Duration::from_secs(2),
            );
            assert!(
                !sup.responsive,
                "a protocol error frame must not mark the supervisor responsive: {sup:?}"
            );
            assert_eq!(
                sup.pid, None,
                "no daemon descriptor is read from an error frame"
            );
            assert_eq!(sup.home, None);
            let lines = render(&[sup]);
            assert!(
                lines.iter().any(|l| l.contains("[unresponsive]")),
                "an erroring endpoint must render unresponsive: {lines:?}"
            );
        }

        /// A clean terminal status frame IS responsive and reads pid + home.
        #[test]
        fn ok_status_frame_is_responsive() {
            let sock = serve_frame(
                "ok",
                serde_json::json!({
                    "ok": true,
                    "type": "status",
                    "daemon": {
                        "pid": 424242,
                        "logFile": "/tmp/nshome-x/logs/supervisor/daemon.log"
                    },
                    "final": true
                }),
            );
            let sup = inspect_supervisor(
                sock,
                &[PathBuf::from("/tmp")],
                std::time::Duration::from_secs(2),
            );
            assert!(
                sup.responsive,
                "a clean status frame is responsive: {sup:?}"
            );
            assert_eq!(sup.pid, Some(424242));
            assert_eq!(sup.home, Some(PathBuf::from("/tmp/nshome-x")));
            // The /tmp home flags it as a phantom.
            assert!(sup.is_phantom(), "a /tmp home must flag: {sup:?}");
        }

        /// A terminal frame for a DIFFERENT op (`ok:true, type:"stopped"`) is not
        /// an explicit error, but it is not a status answer either: the stricter
        /// positive-shape gate must not mark the endpoint responsive from it.
        #[test]
        fn wrong_op_frame_is_not_responsive() {
            let sock = serve_frame(
                "stop",
                serde_json::json!({"ok": true, "type": "stopped", "final": true}),
            );
            let sup = inspect_supervisor(
                sock,
                &[PathBuf::from("/tmp")],
                std::time::Duration::from_secs(2),
            );
            assert!(
                !sup.responsive,
                "a non-status terminal frame must not mark the supervisor responsive: {sup:?}"
            );
            assert_eq!(sup.pid, None);
            assert_eq!(sup.home, None);
        }
    }
}
