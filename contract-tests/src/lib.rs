//! Black-box contract-test harness for the c8ctl nano fleet.
//!
//! The suite describes the behaviour users rely on today — the **Node plugin**
//! `c8ctl-plugin-nano` — as an executable specification, then runs the same
//! tests against `nano-supervisor` (the Rust port). Nothing here links
//! nano-supervisor internals: every assertion goes through a subprocess, a state
//! file under `C8CTL_NANO_HOME`, the `supervisor.sock` control socket, or the
//! engine REST API. Selecting the implementation is a single environment
//! variable, `NS_TARGET` (`node` | `rust`, default `node`).
//!
//! This is the shared harness described on issue #3 (`Target`, `TempHome`,
//! `Engine`, redaction), extended by issue #5 (the agentic-hub conformance
//! module `hub`) and issue #4 (the job-worker harness: the scripted `fake-agent`
//! stand-in, `FakeAgent`/`FakeRecord`, `run_worker_job` and `JobOutcome`).
//! Everything here is additive — do not rename API another issue's tests depend
//! on.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use sha1::{Digest, Sha1};

pub mod bpmn;
pub mod fake;
pub mod redact;

/// Worker-side agentic-hub protocol suite (issue #5), held to the shared
/// `@nanobpm/agentic` conformance corpus in `fixtures/hub/`.
pub mod hub;

pub use fake::{FakeAgent, FakeRecord};

/// Absolute path to the crate's `fixtures/` directory, independent of the
/// working directory a test runs from.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Environment-variable prefixes that identify the caller's real fleet
/// configuration (base URL, agentic hub, supervisor, entry point, and the
/// harness's own `NS_*` selectors) plus the ambient engine endpoint and
/// credentials (`CAMUNDA_*`/`ZEEBE_*`: address, auth strategy, OAuth, and basic
/// credentials) and the caller's agent-invocation environment (`AGENT_*`). Any
/// inherited variable under one of these is cleared before a subprocess runs so
/// a test can never contact, authenticate against, or mutate the caller's
/// configured fleet — the harness's hermetic, no-real-fleet guarantee. Clearing
/// the `CAMUNDA_*`/`ZEEBE_*` set is what stops a developer or CI shell that
/// exports `CAMUNDA_AUTH_STRATEGY`/OAuth/basic credentials from leaking them
/// into a supposedly local, unauthenticated test engine. Clearing `AGENT_*`
/// stops an inherited `AGENT_API_KEY`/`AGENT_RESULT_FILE`/etc from the caller's
/// own agent run from bleeding into the worker-under-test (which allocates its
/// own `AGENT_*` for the fake agent) and being copied verbatim into
/// `NS_FAKE_RECORD` test artifacts and failure output. Callers may still re-add
/// a specific variable with `.env(...)` after `TempHome::cmd` (e.g. the local
/// `CAMUNDA_REST_ADDRESS`), since a later set on the same key wins.
fn is_fleet_var(key: &str) -> bool {
    key.starts_with("NANO_")
        || key.starts_with("C8CTL_NANO_")
        || key.starts_with("NS_")
        || key.starts_with("CAMUNDA_")
        || key.starts_with("ZEEBE_")
        || key.starts_with("AGENT_")
}

/// Apply the standard hermetic environment to `c`: drop every inherited
/// fleet-related variable (see [`is_fleet_var`]), then set the isolated
/// `C8CTL_NANO_HOME` and the launchd/update-notifier suppressors. Shared by
/// [`Target::available`] and [`TempHome`] so both isolate identically.
fn apply_hermetic_env(c: &mut Command, home: &Path) {
    for (key, _) in std::env::vars_os() {
        if let Some(k) = key.to_str() {
            if is_fleet_var(k) {
                c.env_remove(k);
            }
        }
    }
    c.env("C8CTL_NANO_HOME", home)
        .env("C8CTL_NANO_NO_LAUNCHD", "1")
        .env("NANO_NO_UPDATE_NOTIFIER", "1");
}

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
    /// Resolve the target from `NS_TARGET` (default `node` when unset or empty).
    ///
    /// An **unknown** value is rejected with a panic rather than falling back to
    /// `node`: silently coercing e.g. `NS_TARGET=typo` to Node lets a run that
    /// meant to exercise the Rust port report green while testing the wrong
    /// binary. Failing loud keeps the selector contract honest.
    pub fn from_env() -> Target {
        match std::env::var("NS_TARGET").ok().as_deref() {
            None | Some("") | Some("node") => Target::Node,
            Some("rust") => Target::Rust,
            Some(other) => panic!(
                "unknown NS_TARGET {other:?}; expected \"node\" or \"rust\" \
                 (leave unset for the default \"node\")"
            ),
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

    /// `node` or `rust`, for skip messages and golden-file names.
    pub fn label(self) -> &'static str {
        match self {
            Target::Node => "node",
            Target::Rust => "rust",
        }
    }

    /// The **Rust**-target worker command for one job type, running `agent` for
    /// at most `max_jobs` jobs:
    /// `<bin> work --job-type <t> --agent <agent> --max-jobs <n>`. Tests add the
    /// flags their area needs (`--with-lease`, `--recovery-window`, …). The
    /// caller applies the per-test home (see [`TempHome::apply`]).
    ///
    /// This standalone flag-driven form is Rust-only: the Node plugin's `work`
    /// takes a positional *hired profile* (`work <profile>`) and has no
    /// `--agent`/`--max-jobs`, so it cannot be driven this way. The Node target
    /// instead `hire`s an isolated profile pointing at the same fake-agent binary
    /// and runs `work <profile>` with the flag-driven config translated to the
    /// Node CLI's shapes — see [`run_worker_job`] (`node_hire` /
    /// `node_work_command` / `translate_node_flags`). Calling this for
    /// [`Target::Node`] would emit a command the Node plugin rejects, so it is
    /// gated to the Rust target.
    pub fn worker(self, job_type: &str, agent: &str, max_jobs: usize) -> Command {
        debug_assert_eq!(
            self,
            Target::Rust,
            "Target::worker builds the Rust standalone --job-type form; the Node \
             target must go through the hired-profile path in run_worker_job"
        );
        let mj = max_jobs.to_string();
        let mut c = self.cmd(&[
            "work",
            "--job-type",
            job_type,
            "--agent",
            agent,
            "--max-jobs",
            &mj,
        ]);
        c.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        c
    }

    /// Whether the target program is actually runnable here. When it is not
    /// (e.g. the Node plugin is not installed on a plain CI runner), tests skip
    /// cleanly rather than fail — the dedicated Node-target CI job is where they
    /// really run.
    pub fn available(self) -> bool {
        // Probe through a throwaway isolated home so loading the command for the
        // availability check can never read or initialize a real fleet under the
        // caller's `C8CTL_NANO_HOME`. Apply `apply_hermetic_env` (isolated home,
        // no launchd/update-notifier, and every inherited fleet variable
        // cleared). The temp dir is removed when `probe_home` drops.
        let probe_home = match tempfile::Builder::new().prefix("ct-probe-").tempdir() {
            Ok(dir) => dir,
            Err(_) => return false,
        };
        let mut probe = self.cmd(&["--help"]);
        apply_hermetic_env(&mut probe, probe_home.path());
        probe
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

    /// Apply the per-test hermetic environment to an already-built command: the
    /// private home, no launchd, no update notifier, and every inherited fleet
    /// variable cleared. Used by the worker harness, which builds its command
    /// from [`Target::worker`] and then layers this home on top.
    pub fn apply(&self, cmd: &mut Command) {
        apply_hermetic_env(cmd, self.path());
    }

    /// A `Command` for the bound target, with this home and the standard
    /// hermetic environment applied (`C8CTL_NANO_NO_LAUNCHD=1`,
    /// `NANO_NO_UPDATE_NOTIFIER=1`). The parent's own `C8CTL_NANO_HOME`, the
    /// `NS_*` selector variables, and every inherited fleet variable (see
    /// [`is_fleet_var`]) are cleared so a test can never leak into or mutate the
    /// developer's real fleet. Callers may re-add a specific variable with
    /// `.env(...)` on the returned `Command` (a later set on the same key wins).
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = self.target.cmd(args);
        apply_hermetic_env(&mut c, self.path());
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

/// The reason an engine-dependent test cannot run. Print it and return early —
/// engine tests **skip**, never fail, when no local engine is reachable.
#[derive(Debug)]
pub struct Skip(pub String);

/// Print a skip line for the current test and return. Use via [`skip!`].
pub fn note_skip(test: &str, why: impl AsRef<str>) {
    eprintln!("SKIP {test}: {}", why.as_ref());
}

/// `skip!(reason)` — print a `SKIP` line and `return` from the test.
#[macro_export]
macro_rules! skip {
    ($why:expr) => {{
        $crate::note_skip(module_path!(), $why);
        return;
    }};
}

/// The engine under test, from `NS_ENGINE_URL` (default `http://localhost:8080`).
///
/// It refuses anything that is not localhost / 127.0.0.1 unless
/// `NS_ALLOW_REMOTE_ENGINE=1`, and **never** merlin. Two constructors:
/// [`Engine::from_env`] panics on a misconfigured (non-local) engine — used by
/// tests that select the engine directly and gate reachability with
/// [`require_engine!`]; [`Engine::try_from_env`] instead returns a [`Skip`] both
/// for a non-local engine and for an unreachable local one — used by the worker
/// harness so those tests skip cleanly.
pub struct Engine {
    url: String,
    http: reqwest::blocking::Client,
}

impl Engine {
    /// Resolve the engine from the environment, panicking on a non-local URL.
    /// The reachability check is left to [`Engine::reachable`] /
    /// [`require_engine!`].
    pub fn from_env() -> Engine {
        Self::resolve().unwrap_or_else(|Skip(why)| panic!("{why}"))
    }

    /// Resolve **and** reachability-check the engine, or return a [`Skip`]
    /// reason. Engine-dependent worker tests start with this so they skip
    /// (never fail) when no local engine is up.
    pub fn try_from_env() -> Result<Engine, Skip> {
        let engine = Self::resolve()?;
        engine.probe_http()?;
        Ok(engine)
    }

    /// Shared resolution + safety rails, without the reachability probe.
    fn resolve() -> Result<Engine, Skip> {
        let url = std::env::var("NS_ENGINE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".into())
            .trim_end_matches('/')
            .to_string();
        // Hard safety rail: never target merlin, even if someone sets
        // NS_ALLOW_REMOTE_ENGINE=1. Deploying test BPMN/jobs to the shared
        // merlin engine would pollute a live cluster, so a merlin host is
        // rejected unconditionally, ahead of the remote-override escape hatch —
        // an accidental opt-in can never deploy the contract suite to merlin.
        if host_of(&url).to_ascii_lowercase().contains("merlin") {
            return Err(Skip(format!(
                "engine {url} targets merlin; refusing unconditionally (the contract suite must never touch merlin)"
            )));
        }
        if !is_local(&url) && std::env::var("NS_ALLOW_REMOTE_ENGINE").as_deref() != Ok("1") {
            return Err(Skip(format!(
                "engine {url} is not localhost and NS_ALLOW_REMOTE_ENGINE!=1 (never point at merlin)"
            )));
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Skip(format!("http client: {e}")))?;
        Ok(Engine { url, http })
    }

    /// Reachability probe used by the worker harness: hit the engine's REST
    /// topology endpoint, returning a [`Skip`] when it cannot be reached.
    fn probe_http(&self) -> Result<(), Skip> {
        let probe = format!("{}/v2/topology", self.url);
        match self.http.get(&probe).timeout(Duration::from_secs(2)).send() {
            Ok(_) => Ok(()),
            Err(e) => Err(Skip(format!("engine {} unreachable: {e}", self.url))),
        }
    }

    /// The engine base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the configured engine host is loopback (`localhost`/`127.0.0.1`/
    /// `::1`).
    pub fn is_local(&self) -> bool {
        is_local(&self.url)
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

    /// A unique job/process type for this test, so parallel tests on one cluster
    /// never take each other's jobs: `ct-<test>-<random>`.
    pub fn unique_type(&self, test: &str) -> String {
        format!("ct-{}-{}", sanitize(test), rand_suffix())
    }

    /// Deploy BPMN XML; returns the parsed deployment response.
    pub fn deploy_bpmn(&self, name: &str, xml: &str) -> reqwest::Result<serde_json::Value> {
        let part = reqwest::blocking::multipart::Part::text(xml.to_string())
            .file_name(format!("{name}.bpmn"))
            .mime_str("application/xml")
            .expect("mime");
        let form = reqwest::blocking::multipart::Form::new().part("resources", part);
        self.http
            .post(format!("{}/v2/deployments", self.url))
            .multipart(form)
            .send()?
            .error_for_status()?
            .json()
    }

    /// Create a process instance by BPMN process id, with `variables`.
    pub fn create_instance(
        &self,
        process_id: &str,
        variables: serde_json::Value,
    ) -> reqwest::Result<serde_json::Value> {
        self.http
            .post(format!("{}/v2/process-instances", self.url))
            .json(&serde_json::json!({
                "processDefinitionId": process_id,
                "variables": variables,
            }))
            .send()?
            .error_for_status()?
            .json()
    }

    /// Raw REST client and base URL, for tests needing an endpoint not wrapped here.
    pub fn http(&self) -> &reqwest::blocking::Client {
        &self.http
    }

    /// Number of jobs of `job_type` the engine will hand out right now (capped
    /// at one). Tests use this as a black-box probe that an unrelated job is
    /// still *waiting* — i.e. was never activated by a worker under test.
    ///
    /// Activation is **not** read-only: `POST /v2/jobs/activation` leases each
    /// job it returns. So any job this probe claims is immediately restored to
    /// the waiting state (retries preserved, no backoff) before returning —
    /// otherwise the probe would itself strand the unrelated job's activation
    /// for a later test, the very state it is trying to observe.
    pub fn activatable_count(&self, job_type: &str) -> usize {
        let v: serde_json::Value = self
            .http
            .post(format!("{}/v2/jobs/activation", self.url))
            .json(&serde_json::json!({
                "type": job_type,
                "timeout": 5000,
                "maxJobsToActivate": 1,
                "worker": "contract-test-probe",
                "requestTimeout": 0,
            }))
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json())
            .unwrap_or_else(|_| serde_json::json!({ "jobs": [] }));
        let jobs = v["jobs"].as_array().cloned().unwrap_or_default();
        for job in &jobs {
            // Release the lease we just took so the job returns to waiting.
            // Preserve its retries and use zero backoff so it is immediately
            // activatable again — the probe must observe engine state without
            // mutating it.
            if let Some(key) = job["jobKey"].as_str().or_else(|| job["key"].as_str()) {
                let retries = job["retries"].as_i64().unwrap_or(1);
                let _ = self
                    .http
                    .post(format!("{}/v2/jobs/{key}/failure", self.url))
                    .json(&serde_json::json!({
                        "retries": retries,
                        "retryBackOff": 0,
                        "errorMessage": "contract-test probe: releasing activation",
                    }))
                    .send()
                    .and_then(|r| r.error_for_status());
            }
        }
        jobs.len()
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

fn host_of(url: &str) -> &str {
    // The authority is everything after `://` and before the first `/`.
    let authority = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");
    // Drop any `user:pass@` userinfo — the host is what follows the last `@`.
    // Without this, `http://localhost:pw@merlin:8080` would parse its host as
    // `localhost` and wrongly pass the guard while actually targeting merlin.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // Extract the host, honouring bracketed IPv6 literals (`[::1]:8080`); a
    // plain `split(':')` would yield `[` for those and reject loopback.
    if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    }
}

/// `true` when `url`'s host is a loopback address the contract suite may touch.
fn is_local(url: &str) -> bool {
    let host = host_of(url);
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn strip_scheme(url: &str) -> &str {
    url.split_once("://").map(|(_, rest)| rest).unwrap_or(url)
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

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// A short random suffix from the OS clock and pid; enough to keep parallel job
/// types apart without a random-number crate.
pub fn rand_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// The compiled `fake-agent` binary. Tests set `CARGO_BIN_EXE_fake-agent` for
/// their own crate, but the library is compiled separately, so resolve it at
/// runtime: honour `NS_FAKE_AGENT_BIN`, else the Cargo env var if present, else
/// derive it from the test binary's location (`target/<profile>/fake-agent`).
pub fn fake_agent_path() -> PathBuf {
    if let Some(p) = std::env::var_os("NS_FAKE_AGENT_BIN") {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_fake-agent") {
        return PathBuf::from(p);
    }
    let exe_name = if cfg!(windows) {
        "fake-agent.exe"
    } else {
        "fake-agent"
    };
    if let Ok(cur) = std::env::current_exe() {
        // .../target/<profile>/deps/<test>  ->  .../target/<profile>/fake-agent
        if let Some(deps) = cur.parent() {
            let candidate = deps.join(exe_name);
            if candidate.exists() {
                return candidate;
            }
            if let Some(profile) = deps.parent() {
                let candidate = profile.join(exe_name);
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from(exe_name)
}

/// The `--agent` argument that runs the bundled `fake-agent` over ACP. The
/// executable path is shell-quoted so a checkout path containing spaces (the
/// `--agent` value is parsed with shell-style quoting) is preserved intact
/// rather than split into a bogus program plus arguments.
pub fn fake_agent_acp_arg() -> String {
    let path = fake_agent_path();
    let quoted = shlex::try_quote(&path.to_string_lossy())
        .expect("fake-agent path is not shell-quotable")
        .into_owned();
    format!("{quoted} --acp")
}

/// Resolve the target CLI and a reachable local engine together, or a [`Skip`]
/// reason. Engine-dependent worker tests start with this.
pub fn require_engine_and_target() -> Result<(Engine, Target), Skip> {
    let target = Target::from_env();
    if !target.available() {
        return Err(Skip(format!(
            "target `{}` CLI is not available (set NS_TARGET / NS_NODE_CMD / NS_BIN)",
            target.label()
        )));
    }
    let engine = Engine::try_from_env()?;
    Ok((engine, target))
}

/// The result of running the worker-under-test over one job: the fake agent's
/// recording and the worker's own output. Temp dirs are held alive by the value.
pub struct JobOutcome {
    pub job_type: String,
    record_path: PathBuf,
    pub output: std::process::Output,
    _home: TempHome,
    _work: tempfile::TempDir,
}

impl JobOutcome {
    /// What the fake agent recorded (prompt, env, cwd, permissions, …).
    pub fn record(&self) -> fake::FakeRecord {
        fake::FakeRecord::read(&self.record_path)
    }

    /// Whether the fake agent ran at all — its recording only exists if the
    /// worker actually launched it. Used to prove the worker did **not** run the
    /// agent (e.g. when work is gated by a disk-space floor).
    pub fn record_exists(&self) -> bool {
        self.record_path.exists()
    }

    /// Whether the agent wrote its result file, and its parsed contents. The
    /// worker allocates `AGENT_RESULT_FILE` inside its per-job run directory and
    /// hands the path to the agent, so we discover that *worker-generated* path
    /// from the agent's recorded environment and read the file it wrote there.
    /// This asserts the worker's own result channel — the harness never injects
    /// the variable itself.
    pub fn result_file(&self) -> Option<serde_json::Value> {
        let path = self.record().env.get("AGENT_RESULT_FILE")?.clone();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).to_string()
    }

    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).to_string()
    }
}

/// Deploy a one-task process with a unique job type, start an instance carrying
/// `vars`, then run the worker-under-test for one job with the bundled fake agent
/// scripted by `script`. `worker_flags` and `extra_env` are appended to the
/// worker invocation and its (inherited-by-the-agent) environment.
#[allow(clippy::too_many_arguments)]
pub fn run_worker_job(
    engine: &Engine,
    target: &Target,
    test: &str,
    script: &[serde_json::Value],
    vars: serde_json::Value,
    worker_flags: &[&str],
    extra_env: &[(&str, &str)],
) -> JobOutcome {
    let job_type = engine.unique_type(test);
    let process_id = format!("p-{job_type}");
    engine
        .deploy_bpmn(&process_id, &bpmn::single_task(&process_id, &job_type))
        .expect("deploy bpmn");
    engine
        .create_instance(&process_id, vars)
        .expect("create instance");

    let home = TempHome::new();
    let work = tempfile::Builder::new()
        .prefix("ns-run-")
        .tempdir()
        .unwrap();
    let record_path = work.path().join("record.json");
    let script_json = serde_json::to_string(&serde_json::Value::Array(script.to_vec())).unwrap();

    let agent = fake_agent_acp_arg();
    // Build the worker command for the selected target. The Rust worker takes its
    // whole configuration from flags (`--job-type`/`--agent`/`--max-jobs` …) in
    // one standalone process. The Node plugin instead runs a *hired profile*
    // (`work <profile>`) — it has no `--agent`/`--max-jobs` — so we first `hire`
    // an isolated profile that points at the same fake-agent binary over ACP,
    // then `work` it with the flag-driven config translated to the Node CLI's
    // shapes (see `node_hire` / `node_work_command` / `translate_node_flags`).
    let mut cmd = match target {
        Target::Rust => {
            let mut c = target.worker(&job_type, &agent, 1);
            c.args(worker_flags);
            c
        }
        Target::Node => {
            let profile = format!("ctfake{}", rand_suffix());
            node_hire(*target, &home, &profile);
            node_work_command(*target, &profile, &job_type, worker_flags)
        }
    };
    home.apply(&mut cmd);
    // NB: `AGENT_RESULT_FILE` is intentionally NOT set here — the worker itself
    // allocates it inside the per-job run dir and hands it to the agent. The
    // harness must not provide the very behavior these tests verify; read the
    // worker-generated file via `JobOutcome::result_file()` instead.
    cmd.env("NS_FAKE_SCRIPT", &script_json)
        .env("NS_FAKE_RECORD", &record_path)
        // Point the worker at the same engine the job was deployed to, so it
        // polls the local test engine rather than an inherited CAMUNDA_* endpoint
        // or an ambient c8ctl profile.
        .env("CAMUNDA_REST_ADDRESS", engine.url());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let output = match target {
        // The Rust worker self-exits after `--max-jobs 1`, so wait for it (and
        // fail fast if it wedges).
        Target::Rust => output_within(cmd, WORKER_TEST_TIMEOUT),
        // The Node worker never self-exits (it has no `--max-jobs`), so run it
        // until the job has been handled, then reap the tree (see
        // `run_node_worker`).
        Target::Node => run_node_worker(cmd, &record_path),
    };
    JobOutcome {
        job_type,
        record_path,
        output,
        _home: home,
        _work: work,
    }
}

/// Hire an isolated Node worker profile that runs the bundled `fake-agent` over
/// ACP. The profile is what `c8 nano work <profile>` drives — the Node plugin
/// has no flag-driven `--agent`, so the agent binary is bound here at hire time.
///
/// Rank `junior` with no extra capabilities yields the minimal job-type matrix
/// (`["junior"]`), so the profile never subscribes to unrelated job types on its
/// own; the caller adds the one test job type explicitly via `--job-type`. The
/// fake agent speaks ACP, so `--protocol acp` matches (a `pipe` protocol against
/// an ACP binary is rejected by the plugin's guard).
fn node_hire(target: Target, home: &TempHome, profile: &str) {
    let agent = fake_agent_path();
    let agent = agent.to_string_lossy();
    let mut cmd = target.cmd(&[
        "hire",
        "--name",
        profile,
        "--rank",
        "junior",
        "--command",
        &agent,
        "--arg",
        "--acp",
        "--protocol",
        "acp",
    ]);
    home.apply(&mut cmd);
    let out = cmd.output().expect("spawn node hire");
    assert!(
        out.status.success(),
        "node hire of profile {profile:?} failed: status={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Build the Node `work <profile>` command that services one test job type.
///
/// The positional profile (hired by [`node_hire`]) supplies the agent binding;
/// `--job-type <t>` adds the unique test job type on top of the profile's rank
/// matrix so the worker activates the deployed job. The remaining flags are the
/// per-test knobs, translated from the Rust CLI's shapes by
/// [`translate_node_flags`]. The caller applies the per-test home and env.
fn node_work_command(target: Target, profile: &str, job_type: &str, worker_flags: &[&str]) -> Command {
    let mut c = target.cmd(&["work", profile, "--job-type", job_type]);
    for arg in translate_node_flags(worker_flags) {
        c.arg(arg);
    }
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    c
}

/// Translate the flag-driven worker knobs the tests express in the Rust CLI's
/// vocabulary into the Node plugin's `work` flags. Most flags share their name,
/// units, and shape across both targets and pass straight through; the few that
/// differ are adapted here:
///
/// - `--with-lease` — Rust-only boolean; the Node worker manages leasing itself,
///   so it is dropped.
/// - `--reap-age` / `--reap-interval` — Rust takes a duration string (`"1s"`),
///   the Node CLI an integer millisecond count, so the value is converted via
///   [`duration_to_ms_string`].
/// - `--keep-runs` — Rust keeps the N most-recent runs (takes a count); the Node
///   flag is a boolean switch, so the count is consumed and the bare switch
///   emitted.
fn translate_node_flags(flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < flags.len() {
        let f = flags[i];
        match f {
            "--with-lease" => {
                i += 1;
            }
            "--reap-age" | "--reap-interval" => {
                let v = flags.get(i + 1).copied().unwrap_or("");
                out.push(f.to_string());
                out.push(duration_to_ms_string(v));
                i += 2;
            }
            "--keep-runs" => {
                out.push(f.to_string());
                i += 2; // consume (and drop) the Rust count value
            }
            _ => {
                out.push(f.to_string());
                if let Some(v) = flags.get(i + 1) {
                    out.push((*v).to_string());
                }
                i += 2;
            }
        }
    }
    out
}

/// Convert a Rust-CLI duration (`"500ms"`, `"30s"`, `"5m"`, `"2h"`, or a bare ms
/// count) to the integer millisecond string the Node CLI expects. Mirrors the
/// worker's own `parse_duration`. An unparseable value is passed through
/// unchanged so the Node CLI surfaces its own error rather than this masking it.
fn duration_to_ms_string(s: &str) -> String {
    let s = s.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1u64)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1_000)
    } else if let Some(v) = s.strip_suffix('m') {
        (v, 60_000)
    } else if let Some(v) = s.strip_suffix('h') {
        (v, 3_600_000)
    } else {
        (s, 1)
    };
    match num.trim().parse::<u64>() {
        Ok(n) => match n.checked_mul(mult) {
            Some(ms) => ms.to_string(),
            None => s.to_string(),
        },
        Err(_) => s.to_string(),
    }
}

/// Grace period after the fake agent records its run, giving the Node worker
/// time to finish logging the job's completion/nudge before we reap it. The
/// agent flushes `record.json` at exit, which happens once the worker closes the
/// ACP session — i.e. after the worker has handled the job — so a short settle
/// window captures the trailing "completed"/"nudge" log line.
const NODE_SETTLE_GRACE: Duration = Duration::from_secs(4);

/// How long to wait for the Node worker to handle the job before giving up.
/// The Node worker polls forever (no `--max-jobs`), so unlike the Rust path this
/// deadline is the *normal* exit for the one test where the agent never runs
/// (`min_free_mb_gates_work`); reaching it is not a failure.
const NODE_NO_WORK_DEADLINE: Duration = Duration::from_secs(45);

/// Run a Node `work <profile>` worker until it has handled the single test job,
/// then reap it and its agent subtree.
///
/// The Node worker never self-exits (it has no `--max-jobs`), so we cannot wait
/// for it like the Rust path. Instead we watch for the fake agent's
/// `record.json` — which it flushes at exit, after the worker has finished
/// handling the job — as the "job done" signal, wait a short settle window for
/// the worker to log the outcome, then kill the whole process tree. If the
/// record never appears within [`NODE_NO_WORK_DEADLINE`] (e.g. the worker gated
/// the job and never launched the agent, as in `min_free_mb_gates_work`) we reap
/// anyway and return whatever was logged; unlike [`output_within`] this is an
/// expected outcome, so it does NOT panic.
fn run_node_worker(mut cmd: Command, record_path: &Path) -> Output {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().expect("spawn node worker");
    let mut out = child.stdout.take().expect("node worker stdout");
    let mut err = child.stderr.take().expect("node worker stderr");
    let out_h = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let err_h = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });

    let start = Instant::now();
    let mut settle_until: Option<Instant> = None;
    let status = loop {
        // The worker may still crash/exit on its own — take that immediately.
        if let Some(status) = child.try_wait().expect("try_wait node worker") {
            break status;
        }
        // Agent recorded its run => the worker has handled the job. Start a short
        // settle window so the worker can log the outcome, then reap.
        if settle_until.is_none() && record_path.exists() {
            settle_until = Some(Instant::now() + NODE_SETTLE_GRACE);
        }
        let reap = match settle_until {
            Some(until) => Instant::now() >= until,
            None => start.elapsed() >= NODE_NO_WORK_DEADLINE,
        };
        if reap {
            #[cfg(unix)]
            kill_process_tree(child.id());
            let _ = child.kill();
            break child.wait().expect("wait killed node worker");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = out_h.join().unwrap_or_default();
    let stderr = err_h.join().unwrap_or_default();
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Cap on how long a single worker subprocess may run in a contract test.
/// The worker retries activation forever on errors and can also sit for its
/// idle timeout, so a bad endpoint, auth failure, or missing activation would
/// otherwise hang the whole CI run. Generous enough for a real single-job run.
const WORKER_TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Kill `pid` and all of its transitive descendants with `SIGKILL`.
///
/// The worker spawns agents in their *own* process groups, so signalling only
/// the worker's group leaves those agents alive holding the worker's inherited
/// stderr open — which wedges the reader-thread joins the watchdog depends on.
/// Walking the descendant tree (via `/proc` on Linux, or `ps` off Linux) reaps
/// them regardless of their group.
/// Shells out to `kill(1)` so no libc dependency is needed; failures are ignored
/// (a process may already be gone).
#[cfg(target_os = "linux")]
fn kill_process_tree(pid: u32) {
    use std::collections::HashMap;
    // Map ppid -> children, from every /proc/<pid>/stat (field 4 = ppid).
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Ok(cpid) = e.file_name().to_string_lossy().parse::<u32>() {
                if let Some(ppid) = read_ppid(cpid) {
                    children.entry(ppid).or_default().push(cpid);
                }
            }
        }
    }
    // Depth-first collect the worker and every descendant.
    let mut stack = vec![pid];
    let mut victims = Vec::new();
    while let Some(p) = stack.pop() {
        victims.push(p);
        if let Some(kids) = children.get(&p) {
            stack.extend(kids);
        }
    }
    for p in victims {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(p.to_string())
            .status();
    }
}

/// Parent PID of `pid` from `/proc/<pid>/stat`, or `None` if it can't be read.
#[cfg(target_os = "linux")]
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`; `comm` may contain spaces and parens, so
    // parse the fields *after* the final ')': state (skip) then ppid.
    let after = &stat[stat.rfind(')')? + 1..];
    let mut fields = after.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn kill_process_tree(pid: u32) {
    use std::collections::HashMap;
    // No /proc on macOS/BSD, so reconstruct the tree from `ps`. A plain
    // group-kill of the worker is NOT enough: the worker runs agents in their
    // *own* process groups (`acp::Agent::spawn` calls `process_group(0)`), so
    // signalling only `-pid` leaves a `go_silent` agent alive holding the
    // worker's inherited stderr open — the reader-thread joins in
    // `output_within` would then block forever, defeating the watchdog. Map
    // pid -> ppid across all processes and kill every descendant individually
    // so no agent survives regardless of its group.
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(out) = Command::new("ps").args(["-axo", "pid=,ppid="]).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut fields = line.split_whitespace();
            if let (Some(c), Some(p)) = (fields.next(), fields.next()) {
                if let (Ok(c), Ok(p)) = (c.parse::<u32>(), p.parse::<u32>()) {
                    children.entry(p).or_default().push(c);
                }
            }
        }
    }
    // Depth-first collect the worker and every descendant.
    let mut stack = vec![pid];
    let mut victims = Vec::new();
    while let Some(p) = stack.pop() {
        victims.push(p);
        if let Some(kids) = children.get(&p) {
            stack.extend(kids);
        }
    }
    for p in victims {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(p.to_string())
            .status();
    }
}

/// Run `cmd` to completion, but kill it and panic if it outstays `timeout`,
/// so a wedged worker fails the test fast instead of hanging CI forever.
/// Drains stdout/stderr on reader threads to avoid pipe-buffer deadlocks.
fn output_within(mut cmd: Command, timeout: Duration) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    // Put the worker in its own process group so the watchdog can reap the whole
    // subtree on timeout. The worker launches agents as separate processes;
    // killing only the worker would leave a descendant (e.g. a `go_silent`
    // agent) holding the stdout/stderr pipes open, so the reader-thread joins
    // below would block forever and defeat this very watchdog. With its own
    // group, a single signal to the group takes the worker and its agents down.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().expect("spawn worker");
    let mut out = child.stdout.take().expect("worker stdout");
    let mut err = child.stderr.take().expect("worker stderr");
    let out_h = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let err_h = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait worker") {
            break status;
        }
        if start.elapsed() >= timeout {
            // Reap the worker AND every descendant it spawned. The worker runs
            // agents in their *own* process groups (`acp::Agent::spawn` calls
            // `process_group(0)`) and passes them its inherited stderr, so a
            // single group-kill of the worker leaves a `go_silent` agent alive
            // holding that pipe open — and the reader-thread joins below would
            // block forever, defeating this very watchdog. Walking the process
            // tree kills those agents regardless of their group.
            #[cfg(unix)]
            kill_process_tree(child.id());
            let _ = child.kill();
            let status = child.wait().expect("wait killed worker");
            let stdout = out_h.join().unwrap_or_default();
            let stderr = err_h.join().unwrap_or_default();
            panic!(
                "worker did not finish within {timeout:?}; killed it. status={status:?}\n\
                 --- stdout ---\n{}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = out_h.join().unwrap_or_default();
    let stderr = err_h.join().unwrap_or_default();
    Output {
        status,
        stdout,
        stderr,
    }
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

#[cfg(test)]
mod is_local_tests {
    use super::is_local;

    #[test]
    fn plain_localhost_and_loopback_are_local() {
        assert!(is_local("http://localhost:8080"));
        assert!(is_local("http://127.0.0.1:8080"));
        assert!(is_local("http://[::1]:8080"));
        assert!(is_local("http://localhost/foo"));
    }

    #[test]
    fn remote_hosts_are_not_local() {
        assert!(!is_local("http://merlin:8080"));
        assert!(!is_local("https://example.com/v2"));
    }

    #[test]
    fn userinfo_does_not_spoof_the_host() {
        // The real host is `merlin`, even though the userinfo mentions localhost.
        assert!(!is_local("http://localhost:pw@merlin:8080"));
        assert!(!is_local("http://127.0.0.1@merlin:8080"));
        // Userinfo in front of a genuine loopback host stays local.
        assert!(is_local("http://user:pass@127.0.0.1:8080"));
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

    #[test]
    fn duration_to_ms_translates_suffixes() {
        assert_eq!(duration_to_ms_string("500ms"), "500");
        assert_eq!(duration_to_ms_string("1s"), "1000");
        assert_eq!(duration_to_ms_string("30s"), "30000");
        assert_eq!(duration_to_ms_string("5m"), "300000");
        assert_eq!(duration_to_ms_string("2h"), "7200000");
        // A bare number is already milliseconds.
        assert_eq!(duration_to_ms_string("250"), "250");
        // Surrounding whitespace is tolerated.
        assert_eq!(duration_to_ms_string(" 1s "), "1000");
    }

    #[test]
    fn duration_to_ms_passes_unparseable_through() {
        // Not a number: let the Node CLI report its own error rather than mask it.
        assert_eq!(duration_to_ms_string("soon"), "soon");
        assert_eq!(duration_to_ms_string("1x"), "1x");
    }

    #[test]
    fn translate_node_flags_drops_with_lease() {
        // Rust-only boolean; the Node worker manages leasing itself.
        assert_eq!(
            translate_node_flags(&["--with-lease", "--recovery-window", "3000"]),
            vec!["--recovery-window".to_string(), "3000".to_string()]
        );
    }

    #[test]
    fn translate_node_flags_converts_reap_durations() {
        assert_eq!(
            translate_node_flags(&["--reap-age", "1s", "--reap-interval", "500ms"]),
            vec![
                "--reap-age".to_string(),
                "1000".to_string(),
                "--reap-interval".to_string(),
                "500".to_string(),
            ]
        );
    }

    #[test]
    fn translate_node_flags_keep_runs_becomes_boolean() {
        // Rust `--keep-runs <n>` (a count) maps to the Node boolean switch: the
        // count is consumed and the bare flag emitted.
        assert_eq!(
            translate_node_flags(&["--keep-runs", "1"]),
            vec!["--keep-runs".to_string()]
        );
    }

    #[test]
    fn translate_node_flags_passes_shared_knobs_through() {
        assert_eq!(
            translate_node_flags(&[
                "--recovery-window",
                "9000",
                "--min-free-mb",
                "999999999",
            ]),
            vec![
                "--recovery-window".to_string(),
                "9000".to_string(),
                "--min-free-mb".to_string(),
                "999999999".to_string(),
            ]
        );
    }
}
