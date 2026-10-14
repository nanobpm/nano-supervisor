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
            PhantomReason::DeletedCwd(p) => format!("cwd is a deleted dir ({})", p.display()),
            PhantomReason::HomeUnderTmp(p) => format!("home under temp dir ({})", p.display()),
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
/// * a state home under `temp_dir` → [`PhantomReason::HomeUnderTmp`].
///
/// Both signals can apply at once (a `/tmp` home whose run dir was also wiped),
/// so every matching reason is returned rather than the first.
pub fn classify(home: Option<&Path>, temp_dir: &Path, cwd: Option<&Cwd>) -> Vec<PhantomReason> {
    let mut reasons = Vec::new();
    if let Some(cwd) = cwd {
        if !cwd.exists {
            reasons.push(PhantomReason::DeletedCwd(cwd.path.clone()));
        }
    }
    if let Some(home) = home {
        if path_under(home, temp_dir) {
            reasons.push(PhantomReason::HomeUnderTmp(home.to_path_buf()));
        }
    }
    reasons
}

/// Whether `path` is the same as, or nested under, `root`. Both are expected to
/// be absolute (the control-socket temp dir and a daemon's recovered state home
/// always are); a relative or empty `root` matches nothing so a misread never
/// flags a legitimate home.
fn path_under(path: &Path, root: &Path) -> bool {
    if root.as_os_str().is_empty() || !root.is_absolute() {
        return false;
    }
    path.starts_with(root)
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
/// (`c8ctl-nano-sup-<hash>.sock`).
fn is_supervisor_socket_name(name: &str) -> bool {
    name.starts_with("c8ctl-nano-sup-") && name.ends_with(".sock")
}

/// Discover the *other* supervisors running on this host (every one except the
/// caller's own `current_home`), each classified for phantom flags. Returns an
/// empty vec on any discovery error (a best-effort hygiene overlay must never
/// make `supervisor status` fail).
#[cfg(unix)]
pub fn discover_other_supervisors(current_home: &Path) -> Vec<DiscoveredSupervisor> {
    use std::time::Duration;

    let temp = std::env::temp_dir();
    let current_sock = crate::control::socket_path(current_home);
    let mut out = Vec::new();

    let entries = match std::fs::read_dir(&temp) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !is_supervisor_socket_name(name) || path == current_sock {
            continue;
        }

        // A stale leftover socket (connect refused / absent) belongs to a dead
        // owner — not a running supervisor — so it is not a phantom to report.
        // Anything else (live, or an indeterminate backlogged peer) is a running
        // supervisor we must surface.
        match crate::control::probe_liveness(&path, Duration::from_millis(500)) {
            crate::control::Liveness::Absent => continue,
            crate::control::Liveness::Live | crate::control::Liveness::Indeterminate(_) => {}
        }

        out.push(inspect_supervisor(path, &temp));
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
/// classify it.
#[cfg(unix)]
fn inspect_supervisor(socket: PathBuf, temp_dir: &Path) -> DiscoveredSupervisor {
    use std::time::Duration;

    let reply = crate::control::request_with_timeout(
        &socket,
        &serde_json::json!({ "op": "status" }),
        Duration::from_secs(2),
    );
    let frame = reply.ok().and_then(|frames| {
        frames
            .iter()
            .find(|f| f.get("final").and_then(|v| v.as_bool()).unwrap_or(false))
            .or_else(|| frames.last())
            .cloned()
    });

    let (pid, home) = match &frame {
        Some(f) => {
            let pid = f["daemon"]["pid"].as_u64().map(|p| p as u32);
            let home = f["daemon"]["logFile"]
                .as_str()
                .and_then(|lf| home_from_log_file(Path::new(lf)));
            (pid, home)
        }
        None => (None, None),
    };
    let responsive = frame.is_some();
    let cwd = pid.and_then(process_cwd);
    let reasons = classify(home.as_deref(), temp_dir, cwd.as_ref());

    DiscoveredSupervisor {
        socket,
        pid,
        home,
        cwd,
        reasons,
        responsive,
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
    let s = target.to_string_lossy();
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        return Some(Cwd {
            path: PathBuf::from(stripped),
            exists: false,
        });
    }
    let exists = target.exists();
    Some(Cwd {
        path: target,
        exists,
    })
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
        let exists = path.exists();
        Some(Cwd { path, exists })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_cwd(_pid: u32) -> Option<Cwd> {
    None
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
            .map(|h| h.display().to_string())
            .unwrap_or_else(|| s.socket.display().to_string());
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
                Some(cwd) => lines.push(format!("  {home} ({pid}) cwd {}", cwd.path.display())),
                None => lines.push(format!("  {home} ({pid})")),
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_flags_deleted_cwd() {
        let cwd = Cwd {
            path: PathBuf::from("/home/u/.local/state/nano-supervisor/runs/run-123"),
            exists: false,
        };
        let reasons = classify(
            Some(Path::new("/home/u/.local/state/c8ctl-nano")),
            Path::new("/tmp"),
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
            Path::new("/tmp"),
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
            Path::new("/tmp"),
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
            Path::new("/tmp"),
            Some(&cwd),
        );
        assert!(
            reasons.is_empty(),
            "a durable home with a live cwd is not a phantom: {reasons:?}"
        );
    }

    #[test]
    fn classify_without_cwd_still_checks_home() {
        let reasons = classify(Some(Path::new("/tmp/nshome-nbQk")), Path::new("/tmp"), None);
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
        let reasons = classify(None, Path::new("/tmp"), Some(&cwd));
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
    fn path_under_handles_edges() {
        assert!(path_under(Path::new("/tmp/x"), Path::new("/tmp")));
        assert!(path_under(Path::new("/tmp"), Path::new("/tmp")));
        assert!(!path_under(Path::new("/home/u"), Path::new("/tmp")));
        // A relative or empty root never matches, so a misread cannot flag a home.
        assert!(!path_under(Path::new("/tmp/x"), Path::new("")));
        assert!(!path_under(Path::new("/tmp/x"), Path::new("relative")));
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
}
