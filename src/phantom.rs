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
    // littered with stale sockets cannot stall status; on exhaustion the
    // remaining candidates are reported unresponsive rather than probed.
    const DISCOVERY_BUDGET: Duration = Duration::from_secs(5);
    const PROBE_BUDGET: Duration = Duration::from_millis(500);
    const STATUS_BUDGET: Duration = Duration::from_secs(2);
    let deadline = Instant::now() + DISCOVERY_BUDGET;
    let remaining = |deadline: Instant| deadline.saturating_duration_since(Instant::now());

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

        let budget = remaining(deadline);
        if budget.is_zero() {
            // Deadline exhausted: still surface the socket (a live entry must not
            // silently vanish) but skip the network probes, marking it
            // unresponsive so status stays within its latency budget.
            out.push(DiscoveredSupervisor {
                socket: path,
                pid: None,
                home: None,
                cwd: None,
                reasons: Vec::new(),
                responsive: false,
            });
            continue;
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

        out.push(inspect_supervisor(
            path,
            &temp,
            remaining(deadline).min(STATUS_BUDGET),
        ));
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
    temp_dir: &Path,
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

    // A protocol-level error frame (`{ok:false,error,…,final:true}`) is NOT a
    // healthy status answer: the daemon answered but rejected the op. The normal
    // status path surfaces the same frame as a failure (`fleet.rs`
    // `terminal_frame_error`), so it must not mark the endpoint responsive here —
    // otherwise an erroring daemon renders as a healthy-looking `pid ?`
    // supervisor. Only a non-error terminal frame counts as responsive.
    let is_protocol_error = frame
        .as_ref()
        .and_then(|f| f.get("ok"))
        .and_then(|v| v.as_bool())
        == Some(false);

    let (pid, home) = match &frame {
        Some(f) if !is_protocol_error => {
            let pid = f["daemon"]["pid"].as_u64().map(|p| p as u32);
            let home = f["daemon"]["logFile"]
                .as_str()
                .and_then(|lf| home_from_log_file(Path::new(lf)));
            (pid, home)
        }
        _ => (None, None),
    };
    let responsive = frame.is_some() && !is_protocol_error;
    let cwd = pid.and_then(process_cwd);
    // A relative `logFile` (a daemon launched with a relative `C8CTL_NANO_HOME`)
    // yields a relative home that `path_under` would never flag. Resolve it
    // against the daemon's own working directory — the base the daemon itself
    // resolved it against — so a temp-backed relative home is still classified.
    let home = home.map(|h| resolve_home(h, cwd.as_ref()));
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
    let s = target.to_string_lossy();
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        // Linux appends the literal " (deleted)" marker to an unlinked cwd, but a
        // LIVE directory whose real name ends in " (deleted)" is reported with
        // the same literal text. Distinguish them: only when the stripped path is
        // actually gone is this the kernel's deletion marker; if it still exists,
        // the suffix is part of the real (live) name and must not flag the
        // supervisor.
        if !Path::new(stripped).exists() {
            return Some(Cwd {
                path: PathBuf::from(stripped),
                exists: false,
            });
        }
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

    #[test]
    fn relative_home_resolved_against_tmp_cwd_is_flagged() {
        // The classification half of the relative-home fix: once `resolve_home`
        // anchors a relative home at a /tmp cwd, `classify` must flag it.
        let cwd = Cwd {
            path: PathBuf::from("/tmp"),
            exists: true,
        };
        let home = resolve_home(PathBuf::from("nshome"), Some(&cwd));
        let reasons = classify(Some(&home), Path::new("/tmp"), Some(&cwd));
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, PhantomReason::HomeUnderTmp(_))),
            "a relative home resolved under /tmp must flag: {reasons:?}"
        );
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

    /// Serialize the cwd-manipulating test: `std::env::set_current_dir` is
    /// process-wide, so it must not run concurrently with any other test that
    /// reads `/proc/self/cwd`.
    #[cfg(target_os = "linux")]
    fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// A genuinely deleted cwd IS flagged: chdir into a dir, remove it, and
    /// `/proc/self/cwd` reports `<path> (deleted)` with the stripped path gone.
    /// This is the regression for the deletion-marker handling: the stripped path
    /// no longer exists, so the suffix is the kernel's marker and the supervisor
    /// is flagged. (The converse — a *live* dir whose name ends in the marker —
    /// cannot be exercised deterministically here: pointing this process's cwd at
    /// a real " (deleted)" dir races the parallel test below, which momentarily
    /// deletes its own cwd and would be misread through the shared `/proc/self`.)
    #[cfg(target_os = "linux")]
    #[test]
    fn process_cwd_flags_a_genuinely_deleted_dir() {
        let _guard = cwd_lock();
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
            let sup =
                inspect_supervisor(sock, Path::new("/tmp"), std::time::Duration::from_secs(2));
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
            let sup =
                inspect_supervisor(sock, Path::new("/tmp"), std::time::Duration::from_secs(2));
            assert!(
                sup.responsive,
                "a clean status frame is responsive: {sup:?}"
            );
            assert_eq!(sup.pid, Some(424242));
            assert_eq!(sup.home, Some(PathBuf::from("/tmp/nshome-x")));
            // The /tmp home flags it as a phantom.
            assert!(sup.is_phantom(), "a /tmp home must flag: {sup:?}");
        }
    }
}
