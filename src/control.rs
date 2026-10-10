//! The supervisor control socket (`supervisor.sock`) — the NDJSON request /
//! response protocol the Node daemon speaks, so a Node client can drive a Rust
//! daemon and a Rust client can drive a Node daemon (the switch-over in
//! nanobpm/nano-supervisor#8).
//!
//! The wire contract is recorded in `contract-tests/fixtures/socket-protocol.md`:
//!
//! * Transport: a Unix domain socket at
//!   `join(tmpdir(), "c8ctl-nano-sup-<sha1(home)[:8]>.sock")`.
//! * Framing: newline-delimited JSON — one `JSON + "\n"` per frame, both ways.
//!   Blank lines are ignored; malformed lines are skipped.
//! * Request: a single JSON object with an `op` field.
//! * Response: one or more frames; the client reads until the first frame whose
//!   `final` is `true`. Streaming ops (`stop`) emit interim frames first.
//!
//! This module owns the pure protocol layer (path derivation, frame shapes and
//! the request dispatcher) plus a small blocking client. The daemon's async
//! accept loop lives in [`crate::daemon`]; it calls [`handle_request`] per line.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

/// Derive the control-socket path exactly like the Node plugin:
/// `join(tmpdir(), "c8ctl-nano-sup-<sha1(home)[:8]>.sock")`. It lives in the
/// system temp dir, **not** under the home (a recorded quirk).
pub fn socket_path(home: &Path) -> PathBuf {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(home.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    std::env::temp_dir().join(format!("c8ctl-nano-sup-{}.sock", &hex[..8]))
}

/// The `daemon` descriptor reported inside a `status` reply.
#[derive(Clone, Debug, Serialize)]
pub struct DaemonDescriptor {
    pub pid: u32,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    pub version: String,
    pub socket: String,
    #[serde(rename = "logFile")]
    pub log_file: String,
}

/// A supervised worker as reported in `status.workers[]`. The Rust daemon runs
/// a fixed set of in-process slots, so `pid` is the daemon's own pid and the
/// per-slot activity is reported as `unknown` until live slot state is wired in
/// (tracked on nanobpm/nano-supervisor#8).
#[derive(Clone, Debug, Serialize)]
pub struct WorkerStatus {
    pub id: String,
    pub profile: String,
    pub pid: u32,
    pub state: String,
    pub restarts: u32,
    #[serde(rename = "uptimeMs")]
    pub uptime_ms: u64,
    #[serde(rename = "startedAtMs")]
    pub started_at_ms: u64,
    #[serde(rename = "lastExit")]
    pub last_exit: Value,
    pub args: Vec<String>,
    #[serde(rename = "logFile")]
    pub log_file: String,
    pub activity: Value,
    pub engine: String,
    pub agentic: Value,
}

impl WorkerStatus {
    /// A worker running an in-process slot of this daemon. `engine` is the
    /// pinned engine the daemon serves; activity/agentic are reported with the
    /// honest `unknown` placeholder the schema accepts (string / object).
    pub fn in_process(
        id: String,
        profile: String,
        pid: u32,
        started_at_ms: u64,
        uptime_ms: u64,
        log_file: String,
        engine: String,
    ) -> Self {
        WorkerStatus {
            id,
            profile,
            pid,
            state: "running".to_string(),
            restarts: 0,
            uptime_ms,
            started_at_ms,
            last_exit: Value::Null,
            args: Vec::new(),
            log_file,
            activity: json!({ "state": "unknown", "jobs": [] }),
            engine,
            agentic: json!({
                "status": "unknown",
                "mode": "local",
                "url": "",
                "discovered": {},
                "message": Value::Null,
            }),
        }
    }
}

/// Everything a `status` reply renders: the daemon descriptor, the plugin
/// version string and the current worker list.
#[derive(Clone, Debug)]
pub struct StatusSnapshot {
    pub daemon: DaemonDescriptor,
    pub plugin_version: String,
    pub workers: Vec<WorkerStatus>,
}

impl StatusSnapshot {
    /// The `status` frame body. `fin` controls the terminal `final:true` marker
    /// — a `status` op sends it `true`; a `stop` op streams an interim status
    /// frame with it `false` before its terminal `stopped` frame.
    fn status_frame(&self, fin: bool) -> Value {
        json!({
            "ok": true,
            "type": "status",
            "daemon": self.daemon,
            "pluginVersion": self.plugin_version,
            "workers": self.workers,
            "final": fin,
        })
    }
}

/// A terminal error frame — `{ ok:false, error, final:true }`.
fn error_frame(message: &str) -> Value {
    json!({ "ok": false, "error": message, "final": true })
}

/// The daemon's reply to one request line: the frames to write, and whether the
/// daemon should begin a graceful shutdown afterwards.
pub struct Response {
    pub frames: Vec<Value>,
    pub stop: bool,
    /// When `stop` is set, whether the operator asked for a **forced** shutdown
    /// (`stop --force`): the daemon cancels in-flight work immediately instead
    /// of waiting out the drain grace. `false` for a graceful stop and for
    /// every non-`stop` reply, so the force mode is carried end-to-end rather
    /// than only appearing in the interim frame (nanobpm/nano-supervisor#8).
    pub force: bool,
}

/// Dispatch one request line against the live [`StatusSnapshot`]. Blank and
/// malformed lines yield `None` (the accept loop skips them, as the protocol
/// requires). A recognized object yields the frames to stream back.
pub fn handle_request(line: &str, snapshot: &StatusSnapshot) -> Option<Response> {
    let raw = line.trim();
    if raw.is_empty() {
        return None;
    }
    let req: Value = serde_json::from_str(raw).ok()?;
    let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let response = match op {
        "status" => Response {
            frames: vec![snapshot.status_frame(true)],
            stop: false,
            force: false,
        },
        "stop" => {
            let force = req.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            let interim = if force {
                json!({ "type": "stopping", "force": true })
            } else {
                json!({ "type": "draining" })
            };
            Response {
                frames: vec![
                    interim,
                    snapshot.status_frame(false),
                    json!({ "ok": true, "type": "stopped", "final": true }),
                ],
                stop: true,
                force,
            }
        }
        // Ops the Node protocol defines but the Rust daemon does not yet drive
        // (dynamic worker management / live reload — nanobpm/nano-supervisor#8).
        // Answered with a clean error frame rather than the unknown-op reply so
        // a Node client can tell "not here yet" from "no such op".
        "add" | "remove" | "restart" | "reload" | "attach" => Response {
            frames: vec![error_frame(&format!(
                "op \"{op}\" is not yet implemented on the Rust supervisor"
            ))],
            stop: false,
            force: false,
        },
        "" => Response {
            frames: vec![error_frame("request is missing an \"op\" field")],
            stop: false,
            force: false,
        },
        other => Response {
            frames: vec![json!({
                "ok": false,
                "error": format!("unknown op \"{other}\""),
                "final": true,
            })],
            stop: false,
            force: false,
        },
    };
    Some(response)
}

/// Serialize a frame as one NDJSON line (`JSON + "\n"`).
pub fn encode_frame(frame: &Value) -> String {
    let mut line = frame.to_string();
    line.push('\n');
    line
}

/// A blocking control-socket client: send one request object and read frames
/// until the first `final:true`. Mirrors the Node client and the contract
/// harness's `control_request`.
///
/// Framing is handled byte-accurately: bytes are buffered until a newline and
/// only a **complete** line is decoded as UTF-8, so a multi-byte code point
/// split across two socket reads is never corrupted by a per-chunk lossy decode
/// (nanobpm/nano-supervisor#8). The exchange is only well-formed when it ends
/// with a terminal `final:true` frame: a read timeout OR the peer closing the
/// connection (EOF) before that frame means the daemon crashed or was cut off
/// mid-reply, so both surface as an error rather than letting a caller mistake
/// a partial reply for success.
#[cfg(unix)]
pub fn request(socket: &Path, req: &Value) -> std::io::Result<Vec<Value>> {
    request_with_timeout(socket, req, std::time::Duration::from_secs(5))
}

/// Like [`request`], but bounds the WHOLE exchange by an absolute `timeout`
/// deadline so a caller with an overall budget (e.g. the bounded
/// supervisor-start readiness poll) keeps each probe within its remaining time
/// instead of blocking for the fixed 5-second default. The deadline is enforced
/// across every blocking step (write + each read), so a peer dripping blank or
/// non-final lines cannot reset a per-read clock and hang the call. A
/// zero/elapsed budget fails fast as a timeout rather than being passed to
/// `set_read_timeout`, where `Some(0)` means "block forever" and would defeat
/// the deadline.
#[cfg(unix)]
pub fn request_with_timeout(
    socket: &Path,
    req: &Value,
    timeout: std::time::Duration,
) -> std::io::Result<Vec<Value>> {
    use std::io::{BufRead, BufReader, Write};
    use std::time::Instant;

    if timeout.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "control request budget exhausted before contacting the daemon",
        ));
    }

    // Enforce ONE absolute deadline across the whole exchange. `set_read_timeout`
    // bounds a SINGLE blocking read, so re-arming it with the full `timeout`
    // before every `read_until` would reset the clock on each read: a peer that
    // drips a blank or non-final line just before each timeout fires could keep
    // this call blocked indefinitely, defeating the caller's overall budget (e.g.
    // the bounded supervisor-start readiness poll). Instead, pin a fixed deadline
    // and hand each blocking step only the budget still remaining, failing fast
    // once it is exhausted.
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control request timeout overflows the monotonic clock",
        )
    })?;
    fn remaining(deadline: Instant) -> std::io::Result<std::time::Duration> {
        let now = Instant::now();
        if now >= deadline {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control request exceeded its overall deadline before a final frame",
            ))
        } else {
            Ok(deadline - now)
        }
    }

    let stream = connect_within_deadline(socket, deadline)?;
    // Bound the request write by the remaining budget too, so a peer whose
    // receive buffer is full cannot wedge the write past the overall deadline.
    let budget = remaining(deadline)?;
    stream.set_write_timeout(Some(budget))?;
    stream.set_read_timeout(Some(budget))?;
    (&stream).write_all(encode_frame(req).as_bytes())?;
    (&stream).flush()?;

    let mut reader = BufReader::new(&stream);
    let mut frames = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    loop {
        // Re-arm the read timeout with only the budget still left on the fixed
        // deadline, so total blocking time cannot exceed `timeout` no matter how
        // many partial/blank frames the peer emits.
        let budget = remaining(deadline)?;
        stream.set_read_timeout(Some(budget))?;
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            // Peer closed before a terminal `final:true` frame: the reply is
            // incomplete (the daemon crashed or was cut off mid-response), so
            // surface it as an error rather than returning partial frames that a
            // caller could mistake for a successful answer.
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control socket closed before a final frame (incomplete response)",
                ));
            }
            Ok(_) => {
                // `line` is one whole NDJSON frame (through the newline), so a
                // UTF-8 code point is never split across reads here.
                let text = String::from_utf8_lossy(&line);
                let raw = text.trim();
                if raw.is_empty() {
                    continue;
                }
                if let Ok(frame) = serde_json::from_str::<Value>(raw) {
                    let is_final = frame
                        .get("final")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    frames.push(frame);
                    // The terminal frame ends the exchange immediately, so a
                    // later read timeout or EOF can only ever occur before it —
                    // which the arms above correctly surface as a failure.
                    if is_final {
                        return Ok(frames);
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No terminal frame has been parsed (we would have returned
                // above otherwise), so the response is incomplete: surface the
                // timeout rather than letting the caller mistake a partial reply
                // for success.
                return Err(e);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Connect to the Unix-domain control socket without letting a blocking
/// `connect(2)` overrun the caller's overall deadline.
///
/// `UnixStream::connect` blocks until the peer accepts, and a *live* daemon
/// whose listen backlog is full (wedged, not draining its accept queue) can
/// stall that blocking connect for an unbounded time — before any
/// `set_read_timeout`/`set_write_timeout` is installed. A readiness probe or
/// `status`/`stop` call would then hang past its advertised budget. So drive the
/// connect ourselves on a NON-blocking socket and bound the whole attempt by the
/// absolute `deadline`:
///   * an immediate success returns at once;
///   * a connect left in progress (`EINPROGRESS`) is awaited with `poll(2)` for
///     only the remaining budget;
///   * a full-backlog refusal on a *live* peer (`EAGAIN`/`EWOULDBLOCK`, how a
///     nonblocking AF_UNIX connect reports "try again") is retried with a fresh
///     socket after a bounded backoff, still only until the deadline;
///   * a hard failure (`ENOENT`/`ECONNREFUSED`/…, i.e. no live daemon) fails
///     fast, so "not running" is never turned into a deadline-long wait.
///
/// Blocking mode is then restored so the caller's `SO_RCVTIMEO`/`SO_SNDTIMEO`
/// timeouts govern the rest of the exchange.
#[cfg(unix)]
fn connect_within_deadline(
    socket: &Path,
    deadline: std::time::Instant,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;
    use std::time::Instant;

    fn remaining(deadline: Instant) -> std::io::Result<std::time::Duration> {
        let now = Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control request budget exhausted before the daemon accepted the connection",
            ));
        }
        Ok(deadline - now)
    }
    // `poll(2)` wants an i32 millisecond timeout; clamp and never hand it 0,
    // which it treats as "return immediately".
    fn remaining_ms(deadline: Instant) -> std::io::Result<libc::c_int> {
        Ok((remaining(deadline)?.as_millis().min(i32::MAX as u128)).max(1) as libc::c_int)
    }

    let path_bytes = socket.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    // Need room for the path plus a terminating NUL within the fixed buffer.
    if path_bytes.len() >= std::mem::size_of_val(&addr.sun_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control socket path is too long for sockaddr_un",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &src) in addr.sun_path.iter_mut().zip(path_bytes.iter()) {
        *dst = src as libc::c_char;
    }
    // Portable sockaddr length: offset of sun_path (handles the BSD `sun_len`
    // prefix) + path bytes + the trailing NUL.
    let sun_path_offset =
        addr.sun_path.as_ptr() as usize - (&addr as *const libc::sockaddr_un as usize);
    let addr_len = (sun_path_offset + path_bytes.len() + 1) as libc::socklen_t;

    let mut backoff = std::time::Duration::from_millis(2);
    let backoff_cap = std::time::Duration::from_millis(50);
    loop {
        // Fail fast if the budget is already spent, mirroring the read/write paths.
        remaining(deadline)?;

        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Own the fd immediately so every early return (and the `?` below) closes
        // it rather than leaking a descriptor.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        // Close-on-exec so a concurrently spawned child can never inherit this
        // client socket (std's own `connect` sets this; our manual socket must too).
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;

        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                addr_len,
            )
        };
        if rc == 0 {
            // Restore blocking mode so the caller's read/write timeouts apply.
            stream.set_nonblocking(false)?;
            return Ok(stream);
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // Connect started but not yet complete: wait for writability within
            // the remaining budget, then read the pending socket error.
            Some(code) if code == libc::EINPROGRESS => {
                let completed = poll_connect_complete(fd, deadline, remaining_ms)?;
                if completed {
                    stream.set_nonblocking(false)?;
                    return Ok(stream);
                }
                // A full backlog can surface as a post-poll ECONNREFUSED on a live
                // peer; fall through to a bounded retry rather than failing the
                // whole call on a transient refusal.
            }
            // Nonblocking AF_UNIX connect against a full listen backlog: the peer
            // is alive but cannot enqueue us yet. Retry within the deadline.
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {}
            // Interrupted before the connect was initiated: retry immediately.
            Some(code) if code == libc::EINTR => {
                continue;
            }
            // No live daemon (ENOENT/ECONNREFUSED/EACCES/…): fail fast so callers
            // can detect "not running" without waiting out the whole budget.
            _ => return Err(err),
        }

        // Bounded backoff before the next attempt, never past the deadline.
        drop(stream);
        let budget = remaining(deadline)?;
        std::thread::sleep(backoff.min(budget));
        backoff = (backoff * 2).min(backoff_cap);
    }
}

/// Wait for a nonblocking connect on `fd` to finish within `deadline`. Returns
/// `Ok(true)` when the connection completed cleanly, `Ok(false)` when the peer
/// refused us (e.g. a transiently full backlog — the caller may retry), and
/// `Err` on timeout or an unexpected poll/socket failure.
#[cfg(unix)]
fn poll_connect_complete(
    fd: libc::c_int,
    deadline: std::time::Instant,
    remaining_ms: fn(std::time::Instant) -> std::io::Result<libc::c_int>,
) -> std::io::Result<bool> {
    loop {
        let timeout_ms = remaining_ms(deadline)?;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "control connect exceeded its overall deadline before the daemon accepted",
            ));
        }
        // Writable: read the pending socket error to distinguish a completed
        // connect from a refused/failed one.
        let mut so_error: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let g = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if g < 0 {
            return Err(std::io::Error::last_os_error());
        }
        return match so_error {
            0 => Ok(true),
            // A refused connect on an otherwise-live socket (full backlog) is
            // retryable; hard failures are surfaced to fail the call fast.
            code if code == libc::ECONNREFUSED => Ok(false),
            code => Err(std::io::Error::from_raw_os_error(code)),
        };
    }
}

/// Non-Unix stub: the control socket is a Unix-domain transport, so there is no
/// client to offer off-Unix. Returns `Unsupported` rather than failing to
/// compile, mirroring the daemon's `cfg(not(unix))` fallbacks.
#[cfg(not(unix))]
pub fn request(_socket: &Path, _req: &Value) -> std::io::Result<Vec<Value>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the supervisor control-socket client is only supported on Unix",
    ))
}

/// ISO-8601 UTC timestamp (millisecond precision), matching the Node daemon's
/// `startedAt`. Howard Hinnant's `civil_from_days`, no external calendar crate.
pub fn iso8601_now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
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

/// Epoch milliseconds now — the `startedAtMs` worker field.
pub fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> StatusSnapshot {
        StatusSnapshot {
            daemon: DaemonDescriptor {
                pid: 4242,
                started_at: "2026-01-02T03:04:05.006Z".into(),
                version: "0.0.1".into(),
                socket: "/tmp/c8ctl-nano-sup-57425ec9.sock".into(),
                log_file: "/home/logs/supervisor/daemon.log".into(),
            },
            plugin_version: "0.0.1".into(),
            workers: vec![WorkerStatus::in_process(
                "host-coder-0".into(),
                "coder".into(),
                4242,
                1_700_000_000_000,
                1234,
                "/home/logs/supervisor/worker-host-coder-0.log".into(),
                "http://localhost:8080".into(),
            )],
        }
    }

    #[test]
    fn socket_path_matches_node_derivation() {
        // sha1("/tmp/ct-b")[:8] == "57425ec9" — the exact value the Node plugin
        // emits and `contract-tests/tests/socket.rs` pins.
        let p = socket_path(Path::new("/tmp/ct-b"));
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            "c8ctl-nano-sup-57425ec9.sock"
        );
        // Deterministic, and distinct per home.
        assert_eq!(p, socket_path(Path::new("/tmp/ct-b")));
        assert_ne!(p, socket_path(Path::new("/tmp/ct-c")));
    }

    #[test]
    fn status_op_returns_a_final_status_frame() {
        let snap = snapshot();
        let resp = handle_request(r#"{"op":"status"}"#, &snap).expect("a response");
        assert!(!resp.stop);
        assert_eq!(resp.frames.len(), 1);
        let f = &resp.frames[0];
        assert_eq!(f["ok"], json!(true));
        assert_eq!(f["type"], json!("status"));
        assert_eq!(f["final"], json!(true));
        assert_eq!(f["daemon"]["pid"], json!(4242));
        assert!(f["daemon"]["socket"].is_string());
        assert!(f["pluginVersion"].is_string());
        let workers = f["workers"].as_array().expect("workers array");
        assert_eq!(workers.len(), 1);
        for key in [
            "id",
            "profile",
            "pid",
            "state",
            "restarts",
            "uptimeMs",
            "startedAtMs",
            "lastExit",
            "args",
            "logFile",
            "activity",
            "engine",
            "agentic",
        ] {
            assert!(workers[0].get(key).is_some(), "worker.{key} missing");
        }
        assert!(workers[0]["args"].is_array());
        assert!(workers[0]["activity"]["jobs"].is_array());
        for key in ["status", "mode", "url", "discovered", "message"] {
            assert!(workers[0]["agentic"].get(key).is_some());
        }
    }

    #[test]
    fn stop_op_streams_interim_then_final_and_requests_shutdown() {
        let snap = snapshot();
        let resp = handle_request(r#"{"op":"stop"}"#, &snap).expect("a response");
        assert!(resp.stop, "stop must request a graceful shutdown");
        assert!(!resp.force, "a plain stop is graceful, not forced");
        assert_eq!(resp.frames[0]["type"], json!("draining"));
        assert_eq!(resp.frames[1]["type"], json!("status"));
        assert_eq!(resp.frames[1]["final"], json!(false), "interim status");
        let last = resp.frames.last().unwrap();
        assert_eq!(last["type"], json!("stopped"));
        assert_eq!(last["final"], json!(true));
    }

    #[test]
    fn stop_force_reports_stopping() {
        let snap = snapshot();
        let resp = handle_request(r#"{"op":"stop","force":true}"#, &snap).expect("a response");
        assert_eq!(resp.frames[0]["type"], json!("stopping"));
        assert_eq!(resp.frames[0]["force"], json!(true));
        assert!(resp.stop);
        assert!(
            resp.force,
            "force must be carried end-to-end, not only in the interim frame"
        );
    }

    #[test]
    fn unknown_op_is_rejected_uniformly() {
        let snap = snapshot();
        let resp = handle_request(r#"{"op":"nope"}"#, &snap).expect("a response");
        assert!(!resp.stop);
        let f = &resp.frames[0];
        assert_eq!(f["ok"], json!(false));
        assert_eq!(f["final"], json!(true));
        assert!(f["error"].as_str().unwrap().contains("unknown op"));
    }

    #[test]
    fn defined_but_unimplemented_ops_do_not_claim_unknown() {
        let snap = snapshot();
        for op in ["add", "remove", "restart", "reload", "attach"] {
            let line = format!(r#"{{"op":"{op}"}}"#);
            let resp = handle_request(&line, &snap).expect("a response");
            let err = resp.frames[0]["error"].as_str().unwrap();
            assert!(err.contains(op), "error names the op: {err}");
            assert!(
                !err.contains("unknown op"),
                "a defined op must not be reported as unknown: {err}"
            );
            assert_eq!(resp.frames[0]["final"], json!(true));
        }
    }

    #[test]
    fn missing_op_is_an_error_frame() {
        let snap = snapshot();
        let resp = handle_request(r#"{"profile":"coder"}"#, &snap).expect("a response");
        assert_eq!(resp.frames[0]["ok"], json!(false));
        assert!(resp.frames[0]["error"].as_str().unwrap().contains("op"));
    }

    #[test]
    fn blank_and_malformed_lines_are_skipped() {
        let snap = snapshot();
        assert!(handle_request("", &snap).is_none());
        assert!(handle_request("   ", &snap).is_none());
        assert!(handle_request("{not json", &snap).is_none());
    }

    #[test]
    fn frames_encode_as_ndjson_lines() {
        let line = encode_frame(&json!({ "a": 1 }));
        assert!(line.ends_with('\n'));
        assert!(!line[..line.len() - 1].contains('\n'));
    }

    #[test]
    fn iso8601_is_well_formed() {
        let s = iso8601_now();
        assert_eq!(s.len(), "2026-01-02T03:04:05.006Z".len());
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }

    // The control-socket client's framing/timeout contract. Each test stands up a
    // throwaway `UnixListener`, scripts one connection's bytes, and asserts how
    // `request` decodes them.
    #[cfg(unix)]
    mod client {
        use super::*;
        use std::io::Write;
        use std::os::unix::net::UnixListener;

        fn temp_sock(tag: &str) -> PathBuf {
            let pid = std::process::id();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            std::env::temp_dir().join(format!("c8ctl-nano-test-{tag}-{pid}-{nanos}.sock"))
        }

        /// Serve exactly one connection: read (and discard) the request line, then
        /// write `script` back in the supplied byte chunks with a small pause
        /// between them, so the client is forced to read across chunk boundaries.
        fn serve_once(path: &Path, chunks: Vec<Vec<u8>>) -> std::thread::JoinHandle<()> {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).expect("bind test socket");
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    // Drain the single request line so the client's write unblocks.
                    use std::io::Read;
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    for chunk in chunks {
                        if stream.write_all(&chunk).is_err() {
                            return;
                        }
                        let _ = stream.flush();
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    // Leave the connection to close, signalling EOF to the client.
                }
            })
        }

        // A daemon that has bound the socket but is NOT replying (accepts the
        // connection, reads the request, then goes silent) must not let a probe
        // block for the fixed 5-second default: `request_with_timeout` caps the
        // read wait at the caller's remaining budget, so a bounded readiness poll
        // (`supervisor_start`) honours its advertised 10s window instead of
        // stacking 100 × 5s probes into ~500s.
        #[test]
        fn request_with_timeout_bounds_a_silent_daemon() {
            let sock = temp_sock("silent");
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(&sock).expect("bind test socket");
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    use std::io::Read;
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    // Never reply; hold the connection until the client has timed
                    // out so the silence is what ends the exchange.
                    let _ = release_rx.recv();
                }
            });

            let start = std::time::Instant::now();
            let err = request_with_timeout(
                &sock,
                &json!({ "op": "status" }),
                std::time::Duration::from_millis(200),
            )
            .expect_err("a silent daemon must time out");
            let elapsed = start.elapsed();

            let _ = release_tx.send(());
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);

            assert!(
                err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock,
                "expected a timeout error, got {err:?}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "the probe must be bounded by the 200ms budget, not the 5s default; took {elapsed:?}"
            );
        }

        // A fully-consumed budget must fail fast as a timeout rather than being
        // handed to `set_read_timeout`, where `Some(0)` means "block forever" and
        // would defeat the overall readiness deadline.
        #[test]
        fn request_with_timeout_zero_budget_fails_fast() {
            let err = request_with_timeout(
                Path::new("/nonexistent/c8ctl-nano-zero-budget.sock"),
                &json!({ "op": "status" }),
                std::time::Duration::ZERO,
            )
            .expect_err("a zero budget must not connect or block");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::TimedOut,
                "an exhausted budget must surface as a timeout, got {err:?}"
            );
        }

        // A peer that drip-feeds blank/non-final lines just before each per-read
        // timeout must NOT be able to hold the call open past the caller's overall
        // budget. Re-arming the full `timeout` on every `read_until` (the bug)
        // would reset the clock per line and let this block for the server's whole
        // send window; one absolute deadline bounds the exchange regardless.
        #[test]
        fn request_with_timeout_bounds_a_drip_feeding_daemon() {
            let sock = temp_sock("drip");
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(&sock).expect("bind test socket");
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    use std::io::Read;
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    // Emit a blank line every 50ms for ~3s but never a terminal
                    // frame: each line keeps a per-read timer from firing, so only
                    // an absolute deadline can end the exchange.
                    for _ in 0..60 {
                        if stream.write_all(b"\n").is_err() {
                            return;
                        }
                        let _ = stream.flush();
                        if release_rx
                            .recv_timeout(std::time::Duration::from_millis(50))
                            .is_ok()
                        {
                            return;
                        }
                    }
                }
            });

            let start = std::time::Instant::now();
            let err = request_with_timeout(
                &sock,
                &json!({ "op": "status" }),
                std::time::Duration::from_millis(300),
            )
            .expect_err("a drip-feeding daemon must still hit the overall deadline");
            let elapsed = start.elapsed();

            let _ = release_tx.send(());
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);

            assert!(
                err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock,
                "the overall deadline must surface as a timeout, got {err:?}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "the 300ms overall budget must bound the exchange, not the server's ~3s \
                 drip window; took {elapsed:?}"
            );
        }

        // The new non-blocking connect must still complete the normal exchange:
        // a listener that accepts and replies a terminal frame returns Ok. This
        // guards the connect helper's happy path (socket creation, connect, and
        // the restore-to-blocking so SO_RCVTIMEO still governs the reads).
        #[test]
        fn request_with_timeout_connects_and_completes_normally() {
            let sock = temp_sock("cok");
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(&sock).expect("bind test socket");
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    use std::io::{Read, Write};
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let _ = stream.write_all(b"{\"ok\":true,\"final\":true}\n");
                    let _ = stream.flush();
                }
            });

            let frames = request_with_timeout(
                &sock,
                &json!({ "op": "status" }),
                std::time::Duration::from_secs(2),
            )
            .expect("a replying daemon must complete the exchange");
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);

            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0]["final"], json!(true));
        }

        // Regression (blocking connect unbounded by the deadline): a live listener
        // whose backlog is full can stall a *blocking* `connect(2)` indefinitely,
        // before any socket timeout is installed. The non-blocking connect + poll
        // must keep the WHOLE call bounded by the caller's budget regardless of
        // how the connect resolves. We best-effort fill the backlog; the connect
        // then either blocks (Linux: EINPROGRESS → poll times out within budget)
        // or fails fast (macOS: a full Unix backlog yields ECONNREFUSED) — both
        // are bounded, which is the property under test. Either way the overall
        // call must return well within the budget rather than hanging.
        #[test]
        fn request_with_timeout_bounds_a_backlogged_listener() {
            use std::os::unix::net::UnixStream as StdUnixStream;
            let sock = temp_sock("bkl");
            let _ = std::fs::remove_file(&sock);
            // A listener that NEVER accepts, so pending connects pile up in the
            // kernel backlog and are never serviced.
            let listener = UnixListener::bind(&sock).expect("bind test socket");

            // Pile up pending connections to try to saturate the accept backlog.
            let mut pending = Vec::new();
            for _ in 0..512 {
                match StdUnixStream::connect(&sock) {
                    Ok(s) => pending.push(s),
                    Err(_) => break,
                }
            }

            let start = std::time::Instant::now();
            let err = request_with_timeout(
                &sock,
                &json!({ "op": "status" }),
                std::time::Duration::from_millis(300),
            )
            .expect_err("a backlogged, never-accepting listener must not complete");
            let elapsed = start.elapsed();

            drop(pending);
            drop(listener);
            let _ = std::fs::remove_file(&sock);

            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::ConnectionRefused
                ),
                "expected a bounded connect failure, got {err:?}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "the 300ms budget must bound connect+read even with a full backlog; took {elapsed:?}"
            );
        }

        #[test]
        fn utf8_split_across_reads_is_not_corrupted() {
            // A status frame carrying a non-ASCII profile name ("café"), whose
            // multi-byte 'é' (0xC3 0xA9) is split across two socket reads. A
            // per-chunk lossy decode would insert replacement characters; framing
            // on whole lines keeps the name intact.
            let sock = temp_sock("utf8");
            let frame = br#"{"ok":true,"type":"status","name":"caf"#.to_vec();
            let e_bytes = vec![0xC3u8]; // first byte of 'é'
            let rest = {
                let mut v = vec![0xA9u8]; // second byte of 'é'
                v.extend_from_slice(br#"","final":true}"#);
                v.push(b'\n');
                v
            };
            let mut first = frame;
            first.extend_from_slice(&e_bytes);
            let handle = serve_once(&sock, vec![first, rest]);

            let frames = request(&sock, &json!({ "op": "status" })).expect("ok response");
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);

            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0]["name"], json!("café"));
        }

        #[test]
        fn timeout_without_terminal_frame_is_an_error() {
            // The server sends a single non-terminal frame then holds the
            // connection open (neither sending more nor closing) until the
            // client has timed out. The client must return the read-timeout
            // error rather than report a successful (incomplete) response. Using
            // a release channel instead of a fixed sleep keeps the socket open
            // past the client's 5s timeout deterministically, with no wall-clock
            // race between the server's close and the client's timeout.
            let sock = temp_sock("timeout");
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let path = sock.clone();
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind test socket");
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    use std::io::Read;
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    let mut chunk = br#"{"type":"draining","final":false}"#.to_vec();
                    chunk.push(b'\n');
                    let _ = stream.write_all(&chunk);
                    let _ = stream.flush();
                    // Hold the connection open until the client has finished
                    // (timed out); only then drop the stream.
                    let _ = release_rx.recv();
                }
            });

            let err = request(&sock, &json!({ "op": "stop" })).expect_err("timeout is an error");
            assert!(
                err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock,
                "expected a timeout error, got {err:?}"
            );
            let _ = release_tx.send(());
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);
        }

        #[test]
        fn terminal_frame_before_timeout_succeeds() {
            // When a terminal frame does arrive, a subsequent quiet period must
            // not turn the already-complete response into an error.
            let sock = temp_sock("final");
            let mut chunk = br#"{"ok":true,"type":"status","final":true}"#.to_vec();
            chunk.push(b'\n');
            let handle = serve_once(&sock, vec![chunk]);
            let frames = request(&sock, &json!({ "op": "status" })).expect("ok response");
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0]["final"], json!(true));
        }

        #[test]
        fn eof_before_terminal_frame_is_unexpected_eof() {
            // The server sends a single non-terminal frame then CLOSES the
            // connection without ever sending `final:true` (a daemon that crashed
            // or was cut off mid-reply). The client must surface this as an
            // `UnexpectedEof` error rather than return the partial frame as a
            // successful response (nanobpm/nano-supervisor#8).
            let sock = temp_sock("eof");
            let mut chunk = br#"{"type":"draining","final":false}"#.to_vec();
            chunk.push(b'\n');
            // `serve_once` drops the stream after its chunks, producing EOF.
            let handle = serve_once(&sock, vec![chunk]);

            let err = request(&sock, &json!({ "op": "stop" })).expect_err("EOF is an error");
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "expected UnexpectedEof, got {err:?}"
            );
        }

        #[test]
        fn eof_with_no_frames_is_unexpected_eof() {
            // The peer accepts then immediately closes without writing anything:
            // an empty reply is still incomplete (no `final:true`), so it errors.
            let sock = temp_sock("eof-empty");
            let handle = serve_once(&sock, vec![]);

            let err = request(&sock, &json!({ "op": "status" })).expect_err("EOF is an error");
            handle.join().ok();
            let _ = std::fs::remove_file(&sock);
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        }
    }
}
