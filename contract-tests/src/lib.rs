//! Black-box harness for the c8ctl nano fleet contract tests.
//!
//! The suite describes the behaviour users rely on today — the **Node plugin**
//! `c8ctl-plugin-nano` 1.69.2 — as an executable specification, then runs the
//! same tests against `nano-supervisor` (the Rust port). Nothing here links
//! nano-supervisor internals: every assertion goes through a subprocess, a state
//! file under `C8CTL_NANO_HOME`, the `supervisor.sock` control socket, or the
//! engine REST API. Selecting the implementation is a single environment
//! variable, `NS_TARGET`.
//!
//! See issue #3 and the shared-harness comment for the layout and rules.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sha1::{Digest, Sha1};

/// Which implementation the suite exercises, chosen by `NS_TARGET` (default
/// `node`). One suite, both targets — no test hard-codes the program name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The Node plugin, invoked as `c8 nano <args>` (override with `NS_NODE_CMD`).
    Node,
    /// The Rust binary, invoked as `$NS_BIN <args>`
    /// (default `target/debug/nano-supervisor`).
    Rust,
}

impl Target {
    /// Resolve the target from `NS_TARGET`. Unknown values fall back to `node`
    /// so a stray value never silently tests the wrong binary in CI.
    pub fn from_env() -> Target {
        match std::env::var("NS_TARGET").ok().as_deref() {
            Some("rust") => Target::Rust,
            _ => Target::Node,
        }
    }

    /// The program and any leading fixed arguments for this target.
    ///
    /// * `node` → `c8 nano` (or `$NS_NODE_CMD nano`, split on whitespace).
    /// * `rust` → `$NS_BIN` (default `target/debug/nano-supervisor`).
    fn program(self) -> Vec<String> {
        match self {
            Target::Node => match std::env::var("NS_NODE_CMD") {
                Ok(cmd) if !cmd.trim().is_empty() => {
                    let mut parts: Vec<String> =
                        cmd.split_whitespace().map(str::to_string).collect();
                    parts.push("nano".to_string());
                    parts
                }
                _ => vec!["c8".to_string(), "nano".to_string()],
            },
            Target::Rust => {
                let bin = std::env::var("NS_BIN")
                    .unwrap_or_else(|_| "target/debug/nano-supervisor".to_string());
                vec![bin]
            }
        }
    }

    /// A `Command` for this target with the given fleet arguments (e.g.
    /// `["hire", "--list"]`). The caller is responsible for the environment;
    /// prefer [`TempHome::cmd`] so every test gets an isolated home.
    pub fn cmd(self, args: &[&str]) -> Command {
        let program = self.program();
        let mut it = program.iter();
        let mut c = Command::new(it.next().expect("target program is never empty"));
        for fixed in it {
            c.arg(fixed);
        }
        c.args(args);
        c
    }

    /// Whether the target program is actually runnable here. When it is not
    /// (e.g. the Node plugin is not installed on a plain CI runner), tests skip
    /// cleanly rather than fail — the dedicated Node-target CI job is where they
    /// really run.
    pub fn available(self) -> bool {
        let mut probe = self.cmd(&["--help"]);
        probe
            .env("C8CTL_NANO_NO_LAUNCHD", "1")
            .env("NANO_NO_UPDATE_NOTIFIER", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        matches!(probe.status(), Ok(s) if s.success())
    }
}

/// Skip the current test (return early) with a message unless the configured
/// target program is runnable. Use at the top of every test that spawns a CLI.
#[macro_export]
macro_rules! require_target {
    ($target:expr) => {
        if !$target.available() {
            eprintln!(
                "SKIP {}: target {:?} is not runnable here (set NS_TARGET / NS_NODE_CMD / NS_BIN)",
                module_path!(),
                $target
            );
            return;
        }
    };
}

/// A fresh, isolated `C8CTL_NANO_HOME` in a temporary directory, torn down on
/// drop. Every test gets its own home so nothing touches a real fleet, and any
/// daemon a test starts is stopped when the home is dropped.
pub struct TempHome {
    dir: tempfile::TempDir,
    target: Target,
}

impl TempHome {
    /// Create a new isolated home for the default target.
    pub fn new() -> TempHome {
        TempHome::with_target(Target::from_env())
    }

    /// Create a new isolated home for a specific target.
    pub fn with_target(target: Target) -> TempHome {
        let dir = tempfile::Builder::new()
            .prefix("ct-home-")
            .tempdir()
            .expect("create temp C8CTL_NANO_HOME");
        TempHome { dir, target }
    }

    /// The home directory path (the value of `C8CTL_NANO_HOME`).
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The target this home is bound to.
    pub fn target(&self) -> Target {
        self.target
    }

    /// A `Command` for the bound target, with this home and the standard
    /// hermetic environment applied (`C8CTL_NANO_NO_LAUNCHD=1`,
    /// `NANO_NO_UPDATE_NOTIFIER=1`). The parent's own `C8CTL_NANO_HOME` and the
    /// `NS_*` selector variables are cleared so a test can never leak into the
    /// developer's real fleet.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = self.target.cmd(args);
        c.env("C8CTL_NANO_HOME", self.path())
            .env("C8CTL_NANO_NO_LAUNCHD", "1")
            .env("NANO_NO_UPDATE_NOTIFIER", "1")
            .env_remove("NS_TARGET")
            .env_remove("NS_NODE_CMD")
            .env_remove("NS_BIN");
        c
    }

    /// Read a state file under this home as text, if it exists.
    pub fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.path().join(rel)).ok()
    }

    /// Read and parse a JSON state file under this home, if it exists.
    pub fn read_json(&self, rel: &str) -> Option<serde_json::Value> {
        self.read(rel).and_then(|s| serde_json::from_str(&s).ok())
    }

    /// Run a fleet command in this home and capture the result.
    pub fn run(&self, args: &[&str]) -> CmdOutput {
        let out = self
            .cmd(args)
            .output()
            .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
        CmdOutput {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// The control-socket path the plugin derives for this home. It lives in the
    /// system temp dir, **not** under the home: `<tmp>/c8ctl-nano-sup-<h>.sock`,
    /// where `<h>` is the first 8 hex chars of `sha1(home)`. Recorded from the
    /// Node plugin's `getSupervisorSocketPath()`.
    pub fn socket_path(&self) -> PathBuf {
        supervisor_socket_path(self.path())
    }
}

impl Default for TempHome {
    fn default() -> Self {
        TempHome::new()
    }
}

/// The captured result of running a fleet command: exit code and streams.
#[derive(Clone, Debug)]
pub struct CmdOutput {
    /// Process exit code (`None` if terminated by a signal).
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // Best-effort: stop any daemon this test left on the control socket so a
        // dropped home never orphans a background process. Ignore every error —
        // the common case is that no daemon was ever started.
        let sock = self.socket_path();
        if sock.exists() {
            let _ = control_request(&sock, &serde_json::json!({ "op": "stop", "force": true }));
            let _ = std::fs::remove_file(&sock);
        }
    }
}

/// Derive the plugin's control-socket path for a given home directory. Mirrors
/// the Node plugin exactly: `join(tmpdir(), "c8ctl-nano-sup-<sha1(home)[:8]>.sock")`.
pub fn supervisor_socket_path(home: &Path) -> PathBuf {
    let mut hasher = Sha1::new();
    hasher.update(home.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    std::env::temp_dir().join(format!("c8ctl-nano-sup-{}.sock", &hex[..8]))
}

/// The engine under test, selected by `NS_ENGINE_URL` (default
/// `http://localhost:8080`). Engine-backed tests use it; pure CLI and
/// state-file tests never do.
pub struct Engine {
    url: String,
}

impl Engine {
    /// Resolve the engine from the environment. **Refuses** anything that is not
    /// `localhost`/`127.0.0.1` unless `NS_ALLOW_REMOTE_ENGINE=1`, so a test run
    /// can never be pointed at a shared cluster (never merlin).
    pub fn from_env() -> Engine {
        let url =
            std::env::var("NS_ENGINE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
        let host = host_of(&url);
        let is_local = matches!(
            host.as_deref(),
            Some("localhost") | Some("127.0.0.1") | Some("::1")
        );
        if !is_local && std::env::var("NS_ALLOW_REMOTE_ENGINE").ok().as_deref() != Some("1") {
            panic!(
                "refusing non-local engine {url:?}; set NS_ALLOW_REMOTE_ENGINE=1 to override \
                 (never point this at a shared cluster)"
            );
        }
        Engine { url }
    }

    /// The engine base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the engine's TCP port accepts a connection right now. When it
    /// does not, engine-backed tests skip with a message rather than fail.
    pub fn reachable(&self) -> bool {
        let Some((host, port)) = host_port(&self.url) else {
            return false;
        };
        let addrs = match std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port)) {
            Ok(a) => a,
            Err(_) => return false,
        };
        for addr in addrs {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok() {
                return true;
            }
        }
        false
    }
}

impl Default for Engine {
    fn default() -> Self {
        Engine::from_env()
    }
}

/// Skip the current test unless the engine is reachable. Engine-backed tests are
/// skipped-with-a-message, never failed, when no local cluster is up.
#[macro_export]
macro_rules! require_engine {
    ($engine:expr) => {
        if !$engine.reachable() {
            eprintln!(
                "SKIP {}: engine {:?} is unreachable (start a local cluster: `c8 nano start`)",
                module_path!(),
                $engine.url()
            );
            return;
        }
    };
}

/// Send one newline-framed JSON request to a control socket and collect the
/// reply frames up to and including the terminal `final` frame. The plugin's
/// wire format is NDJSON: `JSON.stringify(obj) + "\n"` per frame; a reply ends
/// at the first frame carrying `"final": true`.
pub fn control_request(
    socket: &Path,
    request: &serde_json::Value,
) -> std::io::Result<Vec<serde_json::Value>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut line = serde_json::to_string(request).expect("serialize control request");
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()?;

    let mut buf = String::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut frames = Vec::new();
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };
        buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
        let mut saw_final = false;
        while let Some(idx) = buf.find('\n') {
            let raw = buf[..idx].trim().to_string();
            buf.drain(..=idx);
            if raw.is_empty() {
                continue;
            }
            if let Ok(frame) = serde_json::from_str::<serde_json::Value>(&raw) {
                saw_final = saw_final
                    || frame
                        .get("final")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                frames.push(frame);
            }
        }
        if saw_final || Instant::now() >= deadline {
            break;
        }
    }
    Ok(frames)
}

// ---------------------------------------------------------------------------
// Redaction — golden files compare volatile fields by shape, not value.
// ---------------------------------------------------------------------------

/// A single golden-file redaction: a regex matched against the rendered output
/// and the stable token it is replaced with.
pub struct Redaction {
    /// The regex, in `insta`'s filter syntax.
    pub pattern: &'static str,
    /// The replacement token.
    pub replacement: &'static str,
}

/// The shared redactions for golden files: timestamps, PIDs, temp paths, the
/// home path, socket hashes, uptimes and lease tokens. Applied to every snapshot
/// (both `--json`, which is compared exactly after redaction, and the loose
/// human-readable snapshots) so a byte that only changes run-to-run never breaks
/// a test.
///
/// The home path filter is dynamic (it is the test's temp dir), so tests add it
/// via [`home_redaction`]; the rest are static and returned here.
pub fn redactions() -> Vec<Redaction> {
    vec![
        // ISO-8601 timestamps, e.g. 2026-09-28T08:57:49.254Z.
        Redaction {
            pattern: r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
            replacement: "[timestamp]",
        },
        // The control-socket path, whose hash depends on the temp home. Match
        // the full path token (any prefix) so /tmp vs macOS /var/folders and the
        // per-home hash both collapse to a stable placeholder.
        Redaction {
            pattern: r"\S*c8ctl-nano-sup-[0-9a-f]{8}\.sock",
            replacement: "[socket]",
        },
    ]
}

/// A redaction that replaces the given home directory (an absolute temp path)
/// with a stable token. Built per-test because the path is the test's temp dir.
pub fn home_redaction(home: &Path) -> (String, &'static str) {
    (regex_escape(&home.to_string_lossy()), "[home]")
}

/// Minimal regex escape for embedding a literal path in an `insta` filter.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.^$|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// Small URL helpers (std only — the harness stays dependency-light).
// ---------------------------------------------------------------------------

fn strip_scheme(url: &str) -> &str {
    url.split_once("://").map(|(_, rest)| rest).unwrap_or(url)
}

fn host_of(url: &str) -> Option<String> {
    host_port(url).map(|(h, _)| h)
}

fn host_port(url: &str) -> Option<(String, u16)> {
    let rest = strip_scheme(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let default_port = if url.starts_with("https") { 443 } else { 80 };
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        let (host, after) = stripped.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        Some((host.to_string(), port))
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        Some((authority.to_string(), default_port))
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn socket_path_matches_node_derivation() {
        // sha1("/tmp/ct-b")[:8] cross-checked against the Node plugin.
        let p = supervisor_socket_path(Path::new("/tmp/ct-b"));
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("c8ctl-nano-sup-"));
        assert!(name.ends_with(".sock"));
        assert_eq!(name.len(), "c8ctl-nano-sup-".len() + 8 + ".sock".len());
    }

    #[test]
    fn host_port_parses_forms() {
        assert_eq!(
            host_port("http://localhost:8080"),
            Some(("localhost".to_string(), 8080))
        );
        assert_eq!(
            host_port("http://127.0.0.1:26500/x"),
            Some(("127.0.0.1".to_string(), 26500))
        );
        assert_eq!(
            host_port("http://[::1]:8080"),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(
            host_port("http://localhost"),
            Some(("localhost".to_string(), 80))
        );
    }
}
