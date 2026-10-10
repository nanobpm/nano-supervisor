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
/// until the first `final:true` (or the peer closes). Mirrors the Node client
/// and the contract harness's `control_request`.
///
/// Framing is handled byte-accurately: bytes are buffered until a newline and
/// only a **complete** line is decoded as UTF-8, so a multi-byte code point
/// split across two socket reads is never corrupted by a per-chunk lossy decode
/// (nanobpm/nano-supervisor#8). A read timeout is an error unless a terminal
/// `final:true` frame has already been parsed — a timed-out, partial response is
/// surfaced rather than reported as a successful empty reply.
#[cfg(unix)]
pub fn request(socket: &Path, req: &Value) -> std::io::Result<Vec<Value>> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    (&stream).write_all(encode_frame(req).as_bytes())?;
    (&stream).flush()?;

    let mut reader = BufReader::new(&stream);
    let mut frames = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            // Peer closed: return whatever complete frames we parsed.
            Ok(0) => break,
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
                    // later read timeout can only ever occur before it — which
                    // the error arm below correctly surfaces as a failure.
                    if is_final {
                        break;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No terminal frame has been parsed (we would have broken out
                // above otherwise), so the response is incomplete: surface the
                // timeout rather than letting the caller mistake a partial reply
                // for success.
                return Err(e);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(frames)
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
    }
}
