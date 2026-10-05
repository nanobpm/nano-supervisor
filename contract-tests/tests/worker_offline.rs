//! **Offline connection storms** (nanobpm/nano-supervisor#23): when the engine
//! is unreachable, a worker's activation poll loop must NOT spin — every retry
//! is a fresh TCP connection the kernel holds in `TIME_WAIT`, and a fleet of
//! idle workers polling a dead gateway at a fixed cadence once churned the
//! host's whole ephemeral port range, making the gateway (and every other local
//! client) unreachable. The worker must bound its retry rate (backoff with
//! jitter) while the engine is down, then recover — reconnect and pick up jobs —
//! once the engine returns, without operator intervention.
//!
//! Engine-down is exercised against a closed loopback port (connection refused —
//! the same failure the incident's probes hit); engine-up recovery runs against
//! the live engine and asserts the job completes. Both are engine-observable /
//! process-observable, not log-text contracts (the one bounded log count is the
//! Rust worker's own retry instrumentation, gated Rust-only).

use std::process::Stdio;
use std::sync::mpsc::sync_channel;
use std::time::Duration;
// `Instant` is used only by the Linux-gated recovery test and `wait_for_settled`
// below, so its import is gated too — otherwise the `-D warnings` macOS build
// fails on an unused import.
#[cfg(target_os = "linux")]
use std::time::Instant;

use contract_tests::{require_engine_and_target, skip, Skip, Target, TempHome};
// `bpmn` / `json!` are used only by the Linux-gated recovery test below, so the
// imports are gated too — otherwise the `-D warnings` macOS build fails on them.
#[cfg(target_os = "linux")]
use contract_tests::bpmn;
#[cfg(target_os = "linux")]
use serde_json::json;

/// A loopback TCP port that is guaranteed CLOSED (nothing listening), so
/// connecting fails fast with `ECONNREFUSED` — the engine-down failure mode.
/// Binding port 0 and dropping the listener reserves-then-frees a port; a
/// follow-up connect is refused. (A listener that is never accepted would
/// instead let connections sit in its backlog and time out — a different,
/// slower failure.)
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
}

/// Register the fake-agent hire under `home` and spawn the worker-under-test
/// against `engine_url`, returning the live child. The caller owns the child's
/// lifecycle (kill/reap). `extra_env` (e.g. the fake-agent script/record paths)
/// is layered onto the worker's environment and inherited by the agent it runs.
fn spawn_worker(
    target: Target,
    home: &TempHome,
    engine_url: &str,
    job_type: &str,
    extra_flags: &[&str],
    extra_env: &[(&str, &str)],
) -> std::process::Child {
    let profile = format!("ctoff{}", contract_tests::rand_suffix());
    contract_tests::hire_fake_agent(target, home, &profile);

    let mut cmd = target.cmd(&["work", &profile, "--job-type", job_type]);
    cmd.args(extra_flags);
    home.apply(&mut cmd);
    cmd.env("CAMUNDA_REST_ADDRESS", engine_url)
        .env("NS_FAKE_SCRIPT", "[]")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().expect("spawn offline worker")
}

/// Pump a worker's stderr on a dedicated reader thread, returning a receiver
/// that yields the whole capture once the pipe closes (the worker exits).
///
/// `ChildStderr` is a BLOCKING pipe: reading it on the test's main thread can
/// wait for the next retry line (or EOF) instead of returning when an
/// observation window ends — once the backoff reaches 30s that would overrun the
/// window, and a regression that stops the worker logging would hang CI forever.
/// Draining on a reader thread lets the main thread enforce its own deadline and
/// then kill/reap the child; the reader reports the capture when the pipe
/// closes. The worker's agents are spawned into their own process groups
/// (`kill_on_drop`), so a `kill` of the worker closes this pipe even if an agent
/// outlives it. (This mirrors the harness's `output_within` reader threads.)
fn spawn_stderr_reader(child: &mut std::process::Child) -> std::sync::mpsc::Receiver<Vec<u8>> {
    use std::io::Read;
    let mut stderr = child.stderr.take().expect("worker stderr");
    let (tx, rx) = sync_channel::<Vec<u8>>(1);
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        // Ends at EOF (the worker exited / was killed); a read error ends it too.
        let _ = stderr.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// SIGSTOP / SIGCONT a process. The worker installs handlers only
/// for SIGINT/SIGTERM (graceful drain), so SIGSTOP freezes it silently — the
/// engine-observable "gateway went dark" of a real outage, with no FIN/RST and
/// no reconnect attempt while frozen. SIGCONT resumes it in place, exercising
/// the SAME worker's reconnect path. Linux-gated: only the Linux recovery test
/// uses it (see the note on `worker_recovers_…`).
#[cfg(target_os = "linux")]
fn signal_process(pid: u32, sig: i32) {
    // SAFETY: a plain libc `kill(2)` delivering SIGSTOP/SIGCONT to a child we own.
    unsafe { libc::kill(pid as libc::pid_t, sig) };
}

/// RAII guard that kills a spawned worker — and its whole agent subtree — on
/// drop unless explicitly disarmed.
///
/// Dropping a `std::process::Child` does NOT terminate the process, so a
/// panicking assertion (or a `wait_for_settled` timeout) would otherwise leak
/// the worker — and any agent descendants — still polling the shared engine
/// after the test ends. This guard installs the harness's panic-safe
/// process-tree cleanup; `kill()` performs the normal explicit reap and
/// disarms the drop.
struct WorkerKillGuard {
    child: Option<std::process::Child>,
}

impl WorkerKillGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    /// Borrow the child (liveness checks, stderr reader setup).
    fn child(&mut self) -> &mut std::process::Child {
        self.child.as_mut().expect("worker already reaped")
    }

    /// Normal-path reap: kill the worker's whole process tree, wait for it,
    /// and disarm so drop is a no-op.
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            contract_tests::kill_process_tree(child.id());
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for WorkerKillGuard {
    fn drop(&mut self) {
        // A panic unwound before the explicit reap — kill the worker and its
        // agents so they do not outlive the test against the shared engine.
        self.kill();
    }
}

/// Whether the worker's stderr capture shows it made at least one activation
/// (a job pickup or an empty poll) since it was last drained — i.e. it is
/// talking to the engine again after a freeze.
/// Linux-gated with the recovery test that is its only caller.
#[cfg(target_os = "linux")]
fn stderr_has_activity(text: &str) -> bool {
    text.contains("activated on") || text.contains("completed in")
}

/// While the engine is DOWN, a worker must keep retrying at a BOUNDED rate —
/// never a hot spin — and must still be alive (not crashed, not exited) when
/// the outage has lasted many backoff cycles.
#[test]
fn offline_worker_bounds_its_reconnect_rate_and_stays_up() {
    let (_engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    // The Node plugin is the predecessor this regression guards against; its
    // own retry behaviour is not the Rust worker's contract, so this test pins
    // the Rust target. (The Node-target CI job compiles and runs this whole
    // suite, but every engine-down/up case in this file — including the recovery
    // test below — skips Node; only the Rust-target job exercises them.)
    if target != Target::Rust {
        skip!("the bounded-reconnect backoff is the Rust worker's contract (#23)");
    }

    let home = TempHome::new();
    let engine_url = format!("http://127.0.0.1:{}", closed_port());
    let job_type = format!("ct-offline-{}", contract_tests::rand_suffix());
    // A short poll timeout so each failed activation cycle is quick; the
    // backoff (not the poll) is what must bound the retry rate. The guard
    // reaps the worker (and any agents) even if an assertion below panics.
    let mut child = WorkerKillGuard::new(spawn_worker(
        target,
        &home,
        &engine_url,
        &job_type,
        &["--poll-timeout", "500"],
        &[],
    ));
    // Drain stderr on a reader thread so the observation window below is owned
    // by the MAIN thread's deadline, never by a blocking pipe read (see
    // `spawn_stderr_reader`).
    let stderr_rx = spawn_stderr_reader(child.child());

    // Observe the worker through several backoff cycles. With the bounded
    // backoff (1s base doubling to a 30s ceiling, equal jitter with a `cap/2`
    // floor) a 12s outage yields on the order of 4–8 retry log lines; a hot
    // spin (the actual #23 defect — no backoff between failed activations)
    // would log thousands in the same window. The assertion that pins the
    // CONTRACT is the upper bound:
    // a worker that retries faster than the backoff allows fails here. (The
    // pre-#23 fixed-5s loop also passes this bound — it was never a hot spin —
    // so this test guards against a REGRESSION to unbounded retrying, while the
    // jittered-ceiling behaviour itself is pinned by the `runtime` unit tests.)
    let observe = Duration::from_secs(12);
    std::thread::sleep(observe);

    // The worker must still be RUNNING at the end of the outage: an offline
    // engine is transient, so the slot must not crash or give up. Reap it
    // BEFORE reading the capture so a failure never leaks the process (and so
    // the reader thread's pipe closes, ending its `read_to_end`).
    let alive = child
        .child()
        .try_wait()
        .map(|s| s.is_none())
        .unwrap_or(false);
    child.kill();
    // Collect the reader thread's capture (ready now that the child is reaped;
    // the short timeout just guards a wedged pipe).
    let buf = stderr_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    let stderr_text = String::from_utf8_lossy(&buf);
    let retries = stderr_text.matches("retrying in").count();

    assert!(
        alive,
        "an offline engine must not kill the worker; stderr:\n{stderr_text}"
    );
    assert!(
        retries >= 1,
        "the worker must log its bounded retry; stderr:\n{stderr_text}"
    );
    assert!(
        retries <= 16,
        "retry storm: {retries} retries in {observe:?} means the backoff is not bounding the \
         reconnect rate (a hot spin would produce thousands); stderr:\n{stderr_text}"
    );
}

/// Engine-down → engine-up: a job is waiting while the worker faces a DOWN
/// engine; once the worker can reach the live engine it must pick the job up
/// and complete it — no lost work. This is the recovery half of the #23
/// contract (and the fleet operator's real path: `workforce stop` → gateway
/// restart → `workforce start`). The bounded-backoff half above is what makes
/// that recovery safe for the host's ports.
///
/// The SAME worker is kept alive across the down→up transition: the live engine
/// is frozen with SIGSTOP (the engine-observable "gateway went dark" — the
/// worker's connections stall with no FIN/RST, exactly a dead gateway), then
/// resumed with SIGCONT, and the SAME child must reconnect and complete the
/// waiting job. Killing the worker and starting a fresh one (the previous
/// version) would pass even if an existing worker NEVER reconnects — the very
/// regression this test exists to catch.
///
/// A bare freeze is NOT enough to prove a reconnect, though: the frozen
/// engine's listening socket stays in the kernel, so the worker's in-flight
/// long-poll can simply pend through the freeze and complete after SIGCONT —
/// the test would pass without any activation ever failing. So while the
/// engine is frozen the worker's existing engine connections are reset
/// (`ss -K`, which makes the kernel RST them: the same teardown a gateway
/// restart delivers) so the next activation MUST establish a fresh connection.
/// The reset does not deterministically surface an error to the worker (its
/// HTTP stack may reconnect/retry internally and complete after SIGCONT), so
/// the test does NOT assert on a backoff log line. Instead it pins the
/// engine-observable contract: the job was genuinely WAITING before the outage,
/// and after the resume the SAME worker drives it to COMPLETED — which it can
/// only do via a post-resume activation — with stderr activity confirming it
/// reconnected and ran the job.
///
/// Gated to Linux: the freeze/resume uses SIGSTOP/SIGCONT and the reconnect is
/// forced with `ss -K` (kernel `SO_DESTROY`), both Linux-only here. Compiling
/// the body only for Linux keeps the unix-only helper set (`signal_process`,
/// `EngineResumeGuard`, `engine_process_pid`, `pids_listening_on`) referenced
/// on exactly the target that uses it, so the `-D warnings` macOS CI job does
/// not fail on dead code.
#[cfg(target_os = "linux")]
#[test]
fn worker_recovers_and_picks_up_jobs_when_the_engine_returns() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target != Target::Rust {
        skip!("recovery is asserted on the Rust worker (#23); the Node plugin's own retry loop is not this contract");
    }

    {
        // Deploy the job to the LIVE engine first so it is WAITING while the worker
        // is offline — the outage must not strand it.
        let job_type = engine.unique_type("offline-recovery");
        let process_id = format!("p-{job_type}");
        engine
            .deploy_bpmn(&process_id, &bpmn::single_task(&process_id, &job_type))
            .expect("deploy bpmn");
        let instance = engine
            .create_instance(&process_id, json!({ "prompt": "recover after outage" }))
            .expect("create instance");
        // The instance key is not needed beyond creating the waiting job: the
        // engine-observable settled state (queried by job type) is the assertion.
        let _process_instance_key = instance["processInstanceKey"]
            .as_str()
            .map(str::to_string)
            .or_else(|| {
                instance["processInstanceKey"]
                    .as_i64()
                    .map(|k| k.to_string())
            })
            .expect("create instance: no processInstanceKey");

        // Resolve the engine PID while it is still responsive, then freeze the
        // engine BEFORE the worker starts polling. Spawning the worker first
        // (against a LIVE engine) raced: it could activate and COMPLETE the
        // waiting job in the window before the freeze, so the later assertions
        // would pass on pre-outage work without ever exercising reconnection.
        let engine_pid = engine_process_pid(&engine);

        // The job must be genuinely WAITING before the outage: then the only way
        // it can reach COMPLETED is the post-resume reconnect this test asserts.
        // The job search is eventually consistent, so poll for it to appear
        // (bounded) rather than assuming it is indexed the instant the instance
        // is created.
        let pre = {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(job) = engine.job(&job_type) {
                    break job;
                }
                assert!(
                    Instant::now() < deadline,
                    "the waiting job never became visible before the outage"
                );
                std::thread::sleep(Duration::from_millis(250));
            }
        };
        assert!(
            !contract_tests::job_is_settled(&pre),
            "the job must still be pending before the outage; got {pre}"
        );

        // Phase 1 — engine DOWN. Freeze the engine and immediately arm an RAII
        // guard that resumes it on ANY unwind: a panicking assertion below must
        // never leave the shared test engine stopped (later contract tests would
        // then skip, time out, or hang).
        signal_process(engine_pid, libc::SIGSTOP);
        let mut resume_guard = EngineResumeGuard::arm(engine_pid);

        // Only now start the worker. Its very first poll hits the frozen engine
        // and stalls, so it cannot pick up — let alone complete — the job until
        // we resume. It must stay alive (not crash, not give up) for the
        // freeze. The kill guard reaps the worker (and any agents) even if an
        // assertion below panics.
        let home = TempHome::new();
        let work = tempfile::Builder::new()
            .prefix("ns-run-")
            .tempdir()
            .unwrap();
        let record_path = work.path().join("record.json");
        let script_json = serde_json::to_string(&serde_json::Value::Array(vec![
            json!({ "emit": "recovered" }),
            json!({ "write_result": { "ok": true } }),
        ]))
        .unwrap();
        let mut child = WorkerKillGuard::new(spawn_worker(
            target,
            &home,
            engine.url(),
            &job_type,
            // A short long-poll so the RST below is observed quickly: with
            // the 30s default a poll issued right at spawn could still be
            // in flight when the freeze ends, and the worker would not
            // touch the reset connection (and back off) inside the window.
            &["--poll-timeout", "2000"],
            &[
                ("NS_FAKE_SCRIPT", script_json.as_str()),
                ("NS_FAKE_RECORD", record_path.to_str().expect("record path")),
            ],
        ));
        let stderr_rx = spawn_stderr_reader(child.child());

        let freeze = Duration::from_secs(6);
        std::thread::sleep(freeze);
        let alive_down = child
            .child()
            .try_wait()
            .map(|s| s.is_none())
            .unwrap_or(false);
        assert!(
            alive_down,
            "the worker must stay up through an engine outage (it exits only when killed)"
        );

        // A bare freeze does NOT force a reconnect: the frozen engine's
        // listening socket stays in the kernel, so the worker's stalled
        // long-poll can simply complete after SIGCONT and the test would pass
        // without any activation ever failing. RST the worker's existing
        // engine connections while the engine is still frozen — the kernel
        // tears them down exactly as a gateway restart would — so the next
        // activation MUST establish a fresh connection. Note this still does
        // not deterministically surface an error to the worker (its HTTP stack
        // can reconnect/retry internally and complete after SIGCONT), so we do
        // not assert on a backoff log line — only on the engine-observable
        // recovery below.
        kill_worker_engine_connections(&engine);

        // Give the worker a moment inside the outage before the engine returns,
        // so the freeze window genuinely spans a worker poll cycle rather than
        // ending before the worker ever touched the engine.
        std::thread::sleep(Duration::from_secs(3));

        // Phase 2 — engine UP: resume the SAME engine (disarming the guard; the
        // explicit resume is the normal path). The SAME worker must reconnect,
        // activate the waiting job, run the agent, and settle it.
        resume_guard.resume();
        let outcome = wait_for_settled(&engine, &job_type, Duration::from_secs(60));

        // Reap the worker before asserting on its capture.
        child.kill();
        let buf = stderr_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
        let stderr_text = String::from_utf8_lossy(&buf);

        assert_eq!(
            outcome["state"].as_str().unwrap_or(""),
            "COMPLETED",
            "after the outage the SAME worker must reconnect and complete the waiting job; \
     engine job: {outcome}; worker stderr:\n{stderr_text}"
        );
        assert!(
            stderr_has_activity(&stderr_text),
            "the SAME worker must show it reconnected and ran the job after the freeze; stderr:\n{stderr_text}"
        );
        // The connection reset above tears down the worker's existing engine
        // connections so the next activation must establish a fresh one. We do
        // NOT assert on a `retrying in` log line here: that is not
        // deterministic. The frozen engine's listening socket stays in the
        // kernel, so the worker's HTTP stack can reconnect/retry internally
        // while the engine is frozen and complete the request after SIGCONT
        // without ever surfacing an error to the worker's own retry logic —
        // the `retrying in` line then never appears even though the worker
        // behaved correctly (this flaked in CI on 30d8202). What this test
        // pins is the engine-observable contract of #23: the job was genuinely
        // WAITING before the outage (asserted above), and after the resume the
        // SAME worker reconnects and drives it to COMPLETED (asserted above),
        // with stderr activity proving it reconnected and ran the job.
    }
}

/// RAII guard that resumes a frozen engine on drop unless explicitly disarmed.
///
/// The recovery test freezes the shared engine with `SIGSTOP`; if an assertion
/// between the freeze and the explicit `SIGCONT` panics, the unwinding stack
/// would otherwise leave the engine stopped for every later contract test. This
/// guard sends `SIGCONT` on any drop (including a panic unwind) so the engine is
/// always restored; `resume()` performs the normal explicit resume and disarms
/// it so the drop becomes a no-op.
#[cfg(target_os = "linux")]
struct EngineResumeGuard {
    pid: u32,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl EngineResumeGuard {
    fn arm(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    /// Normal-path resume: `SIGCONT` the engine and disarm so drop is a no-op.
    fn resume(&mut self) {
        if self.armed {
            signal_process(self.pid, libc::SIGCONT);
            self.armed = false;
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for EngineResumeGuard {
    fn drop(&mut self) {
        if self.armed {
            // A panic unwound before the explicit resume — restore the engine so
            // later tests are not stranded against a frozen gateway.
            signal_process(self.pid, libc::SIGCONT);
        }
    }
}

/// The PID of the local engine process, resolved by walking the listening
/// socket back to its owner. The engine under test is a local process the test
/// harness started (`start-nano-engine.sh`), so we can freeze it in place.
/// Linux-gated with the recovery test that uses it.
#[cfg(target_os = "linux")]
fn engine_process_pid(engine: &contract_tests::Engine) -> u32 {
    // The engine's PID is the owner of the loopback port it listens on. Find it
    // via `lsof` (available on the CI runners); fall back to `fuser`.
    let url = engine.url().to_string();
    let port = url.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
    if let Some(port) = port {
        if let Some(pid) = pids_listening_on(port).into_iter().next() {
            return pid;
        }
    }
    panic!("could not resolve the engine PID for {url}; the freeze/resume recovery test needs it");
}

/// RST every established loopback connection TO the engine's port, so a worker
/// whose long-poll pended through a SIGSTOP freeze cannot resume on that stale
/// connection — its next request/response touch fails and it must reconnect,
/// exactly as if the gateway had restarted. Uses `ss -K` (kernel
/// `SO_DESTROY`), which is Linux-only; the caller skips elsewhere.
///
/// Filters by the engine's dedicated port ALONE, not `dst 127.0.0.1`: the CI
/// engine URL is `http://localhost:8080`, and `localhost` can resolve to the
/// IPv6 loopback `::1` as readily as `127.0.0.1`. An IPv4-only filter would
/// leave a `[::1]`-bound long poll intact, the worker would never reconnect,
/// and the recovery assertion would fail. The port is engine-private, so
/// matching it across both address families resets exactly the right sockets.
///
/// Run this while the engine is still frozen: the RST is generated by the
/// LOCAL kernel, so the stopped engine process does not need to act, and no
/// NEW connection can complete its handshake until the engine is resumed.
#[cfg(target_os = "linux")]
fn kill_worker_engine_connections(engine: &contract_tests::Engine) {
    let url = engine.url().to_string();
    let port: u16 = url
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("engine url has a port");
    let out = std::process::Command::new("ss")
        .args(["-K", "dport", "=", &port.to_string()])
        .output()
        .expect("spawn `ss -K` to reset the worker's stalled engine connections");
    assert!(
        out.status.success(),
        "`ss -K dport = {port}` failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// PIDs of processes listening on loopback TCP `port` (via `lsof`, then `fuser`).
/// Linux-gated with the recovery test that uses it.
#[cfg(target_os = "linux")]
fn pids_listening_on(port: u16) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(o) = std::process::Command::new("lsof")
        .args(["-t", "-i", &format!("TCP:{port}"), "-s", "TCP:LISTEN"])
        .output()
    {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if let Ok(pid) = line.trim().parse::<u32>() {
                out.push(pid);
            }
        }
    }
    if out.is_empty() {
        if let Ok(o) = std::process::Command::new("fuser")
            .args([&format!("{port}/tcp")])
            .output()
        {
            for tok in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                if let Ok(pid) = tok.parse::<u32>() {
                    out.push(pid);
                }
            }
        }
    }
    out
}

/// Poll the engine until the job of `job_type` settles, returning it; panic if
/// it never does within `timeout`.
/// Linux-gated with the recovery test that is its only caller.
#[cfg(target_os = "linux")]
fn wait_for_settled(
    engine: &contract_tests::Engine,
    job_type: &str,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(job) = engine.job(job_type) {
            if contract_tests::job_is_settled(&job) {
                return job;
            }
        }
        if Instant::now() >= deadline {
            panic!("job {job_type} did not settle within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// **Fleet-level** outage (issue #23's regression criterion): a single worker's
/// bounded backoff is safe per slot, but the incident was a *fleet* of idle
/// workers whose combined retries churned the host's ephemeral ports into
/// `TIME_WAIT`. This test launches several workers against one DOWN gateway and
/// asserts the AGGREGATE retry/connection rate stays bounded — pool/concurrency
/// behaviour that is safe per slot but exhausts ports when many slots retry
/// together fails here even though the single-worker test above passes.
#[test]
fn offline_fleet_bounds_its_aggregate_reconnect_rate() {
    let (_engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target != Target::Rust {
        skip!("the bounded-reconnect backoff is the Rust worker's contract (#23)");
    }

    const FLEET: usize = 8;
    let engine_url = format!("http://127.0.0.1:{}", closed_port());
    let job_type = format!("ct-offline-fleet-{}", contract_tests::rand_suffix());

    // Launch the fleet against the DOWN gateway. Each worker gets its OWN
    // `TempHome`: `hire_fake_agent` writes the hired profile into the home's
    // `config.json`, so sharing one home would leave only the last-hired profile
    // and the other workers would fail to start. Keep the homes alive (the Vec)
    // for the whole test. Each worker's stderr drains on its own reader thread,
    // and each is wrapped in a kill guard so a panicking assertion below cannot
    // leak a worker (or its agents) against the shared engine.
    let mut homes = Vec::new();
    let mut children = Vec::new();
    let mut readers = Vec::new();
    for _ in 0..FLEET {
        let home = TempHome::new();
        let mut child = WorkerKillGuard::new(spawn_worker(
            target,
            &home,
            &engine_url,
            &job_type,
            &["--poll-timeout", "500"],
            &[],
        ));
        readers.push(spawn_stderr_reader(child.child()));
        children.push(child);
        homes.push(home);
    }

    // Observe the whole fleet through several backoff cycles.
    let observe = Duration::from_secs(12);
    std::thread::sleep(observe);

    // Reap the fleet, collecting each worker's capture and liveness.
    let mut total_retries = 0usize;
    let mut all_alive = true;
    let mut combined = String::new();
    for (mut child, rx) in children.into_iter().zip(readers) {
        all_alive &= child
            .child()
            .try_wait()
            .map(|s| s.is_none())
            .unwrap_or(false);
        child.kill();
        let buf = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        let text = String::from_utf8_lossy(&buf);
        total_retries += text.matches("retrying in").count();
        combined.push_str(&text);
    }

    assert!(
        all_alive,
        "every fleet worker must stay up through the outage; combined stderr:\n{combined}"
    );
    // The aggregate bound: with a 1s base / 30s ceiling equal-jitter backoff
    // (a nonzero `cap/2` floor), one worker retries ~4–8 times in 12s, so 8
    // workers retry on the order of 32–64 times in aggregate. A hot-spinning
    // fleet would log thousands. Cap the aggregate generously (8 × the
    // single-worker bound) so the test fails only when the fleet as a whole is
    // NOT bounded — the #23 storm.
    let aggregate_cap = 16 * FLEET;
    assert!(
        total_retries >= FLEET,
        "each fleet worker must log its bounded retry ({total_retries} total); combined stderr:\n{combined}"
    );
    assert!(
        total_retries <= aggregate_cap,
        "fleet retry storm: {total_retries} retries across {FLEET} workers in {observe:?} exceeds \
         the aggregate bound {aggregate_cap} — per-slot backoff is not bounding the FLEET's \
         reconnect rate (the #23 port-exhaustion storm); combined stderr:\n{combined}"
    );
}

/// Guard the helper: the closed port really is refused (so the tests above
/// exercise the engine-down path, not a slow timeout).
#[test]
fn a_closed_loopback_port_refuses_connections() {
    let port = closed_port();
    let addr = format!("127.0.0.1:{port}");
    let connect =
        std::net::TcpStream::connect(addr.parse::<std::net::SocketAddr>().expect("socket addr"));
    assert!(
        connect.is_err(),
        "port {port} should be closed; the offline tests rely on a fast refusal"
    );
}
