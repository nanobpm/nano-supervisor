//! Black-box contract-test harness for the Nano job worker.
//!
//! The suite runs the CLIs as subprocesses, reads and writes their state files,
//! and talks to the engine REST API. It never links to `nano-supervisor`
//! internals, so the same test runs against `c8 nano work` (Node) and
//! `nano-supervisor` (Rust).
//!
//! This module is the shared harness described on issue #3 (`Target`,
//! `TempHome`, `Engine`, redaction). Issue #3 lands the canonical skeleton;
//! until it does, issue #4's suite carries a faithful, additive copy so the
//! crate builds on its own. Everything here is additive — do not rename API
//! another issue's tests depend on.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub mod bpmn;
pub mod fake;
pub mod redact;

pub use fake::{FakeAgent, FakeRecord};

/// Which implementation is under test, selected by `NS_TARGET` (default `node`).
#[derive(Debug, Clone)]
pub enum Target {
    /// `c8 nano <args>`; `NS_NODE_CMD` overrides the `c8` program.
    Node { program: String },
    /// `$NS_BIN <args>` (default `target/debug/nano-supervisor`).
    Rust { bin: PathBuf },
}

impl Target {
    /// Read `NS_TARGET` (`node` | `rust`, default `node`).
    pub fn from_env() -> Target {
        match std::env::var("NS_TARGET")
            .unwrap_or_else(|_| "node".into())
            .as_str()
        {
            "rust" => Target::Rust {
                bin: std::env::var_os("NS_BIN")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("target/debug/nano-supervisor")),
            },
            _ => Target::Node {
                program: std::env::var("NS_NODE_CMD").unwrap_or_else(|_| "c8".into()),
            },
        }
    }

    /// A `Command` for the target with `args`, so tests never hard-code the
    /// program. For Node this is `c8 nano <args>`; for Rust `<bin> <args>`.
    pub fn cmd(&self, args: &[&str]) -> Command {
        match self {
            Target::Node { program } => {
                let mut c = Command::new(program);
                c.arg("nano").args(args);
                c
            }
            Target::Rust { bin } => {
                let mut c = Command::new(bin);
                c.args(args);
                c
            }
        }
    }

    /// `node` or `rust`, for skip messages and golden-file names.
    pub fn label(&self) -> &'static str {
        match self {
            Target::Node { .. } => "node",
            Target::Rust { .. } => "rust",
        }
    }

    /// A worker command for one job type, running `agent` for at most `max_jobs`
    /// jobs: `<cli> work --job-type <t> --agent <agent> --max-jobs <n>`. Tests add
    /// the flags their area needs (`--with-lease`, `--recovery-window`, …).
    pub fn worker(&self, job_type: &str, agent: &str, max_jobs: usize) -> Command {
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

    /// Whether the target program can actually be launched here. Node tests skip
    /// when `c8` is not on `PATH`; Rust tests skip when the binary is missing.
    pub fn available(&self) -> bool {
        match self {
            Target::Node { program } => which(program).is_some(),
            Target::Rust { bin } => bin.exists() || which(&bin.to_string_lossy()).is_some(),
        }
    }
}

/// A fresh `C8CTL_NANO_HOME` in a temporary directory for one test. Launchd and
/// the update notifier are disabled. The directory (and anything under it) is
/// removed on drop.
pub struct TempHome {
    dir: tempfile::TempDir,
}

impl TempHome {
    pub fn new() -> TempHome {
        let dir = tempfile::Builder::new()
            .prefix("ns-home-")
            .tempdir()
            .expect("create temp home");
        TempHome { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Apply the per-test environment to a command: a private home, no launchd,
    /// no update notifier.
    pub fn apply(&self, cmd: &mut Command) {
        cmd.env("C8CTL_NANO_HOME", self.path())
            .env("C8CTL_NANO_NO_LAUNCHD", "1")
            .env("NANO_NO_UPDATE_NOTIFIER", "1");
    }

    /// A `Command` for `target` with this home already applied.
    pub fn cmd(&self, target: &Target, args: &[&str]) -> Command {
        let mut c = target.cmd(args);
        self.apply(&mut c);
        c
    }
}

impl Default for TempHome {
    fn default() -> Self {
        Self::new()
    }
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
/// `NS_ALLOW_REMOTE_ENGINE=1`. **Never point it at merlin.** When the URL is
/// unreachable, [`Engine::from_env`] returns [`Skip`] so engine tests skip with
/// a message instead of failing.
pub struct Engine {
    url: String,
    http: reqwest::blocking::Client,
}

impl Engine {
    /// Resolve and reachability-check the engine, or return a [`Skip`] reason.
    pub fn from_env() -> Result<Engine, Skip> {
        let url = std::env::var("NS_ENGINE_URL")
            .unwrap_or_else(|_| "http://localhost:8080".into())
            .trim_end_matches('/')
            .to_string();
        // Hard safety rail: never target merlin, even if someone sets
        // NS_ALLOW_REMOTE_ENGINE=1. Deploying test BPMN/jobs to the shared
        // merlin engine would pollute a live cluster, so a merlin host is
        // rejected unconditionally, ahead of the remote-override escape hatch —
        // an accidental opt-in can never deploy the contract suite to merlin.
        if host_of(&url).contains("merlin") {
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
        let engine = Engine { url, http };
        engine.reachable()?;
        Ok(engine)
    }

    fn reachable(&self) -> Result<(), Skip> {
        let probe = format!("{}/v2/topology", self.url);
        match self.http.get(&probe).timeout(Duration::from_secs(2)).send() {
            Ok(_) => Ok(()),
            Err(e) => Err(Skip(format!("engine {} unreachable: {e}", self.url))),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
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

/// The `--agent` argument that runs the bundled `fake-agent` over ACP.
pub fn fake_agent_acp_arg() -> String {
    format!("{} --acp", fake_agent_path().display())
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
    let engine = Engine::from_env()?;
    Ok((engine, target))
}

/// The result of running the worker-under-test over one job: the fake agent's
/// recording and the worker's own output. Temp dirs are held alive by the value.
pub struct JobOutcome {
    pub job_type: String,
    record_path: PathBuf,
    result_path: PathBuf,
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

    /// Whether the agent wrote `AGENT_RESULT_FILE`, and its parsed contents.
    pub fn result_file(&self) -> Option<serde_json::Value> {
        std::fs::read_to_string(&self.result_path)
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
    let result_path = work.path().join("result.json");
    let script_json = serde_json::to_string(&serde_json::Value::Array(script.to_vec())).unwrap();

    let agent = fake_agent_acp_arg();
    let mut cmd = target.worker(&job_type, &agent, 1);
    home.apply(&mut cmd);
    cmd.args(worker_flags);
    cmd.env("NS_FAKE_SCRIPT", &script_json)
        .env("NS_FAKE_RECORD", &record_path)
        .env("AGENT_RESULT_FILE", &result_path)
        // Point the worker at the same engine the job was deployed to, so it
        // polls the local test engine rather than an inherited CAMUNDA_* endpoint
        // or an ambient c8ctl profile.
        .env("CAMUNDA_REST_ADDRESS", engine.url());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let output = output_within(cmd, WORKER_TEST_TIMEOUT);
    JobOutcome {
        job_type,
        record_path,
        result_path,
        output,
        _home: home,
        _work: work,
    }
}

/// Cap on how long a single worker subprocess may run in a contract test.
/// The worker retries activation forever on errors and can also sit for its
/// idle timeout, so a bad endpoint, auth failure, or missing activation would
/// otherwise hang the whole CI run. Generous enough for a real single-job run.
const WORKER_TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Best-effort kill of an entire process group by pid. Because the worker was
/// spawned with `process_group(0)`, its pgid equals its pid, so `kill -<pid>`
/// signals the worker and every descendant it started. Shells out to `kill(1)`
/// so no libc dependency is needed; failures are ignored (the group may already
/// be gone).
#[cfg(unix)]
fn kill_process_group(pid: u32) {
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(format!("-{pid}"))
        .status();
}

/// Run `cmd` to completion, but kill it and panic if it outstays `timeout`,
/// so a wedged worker fails the test fast instead of hanging CI forever.
/// Drains stdout/stderr on reader threads to avoid pipe-buffer deadlocks.
fn output_within(mut cmd: Command, timeout: Duration) -> Output {
    use std::io::Read;
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
            // Kill the entire process group (worker + agent descendants), not
            // just the worker, so nothing keeps the pipes open and wedges the
            // reader-thread joins below.
            #[cfg(unix)]
            kill_process_group(child.id());
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

fn which(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);
    if p.is_absolute() {
        return p.exists().then(|| p.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let cand = dir.join(program);
            cand.is_file().then_some(cand)
        })
    })
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
