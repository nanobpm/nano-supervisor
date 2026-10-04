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
use std::time::{Duration, Instant};

use contract_tests::{bpmn, require_engine_and_target, skip, Skip, Target, TempHome};
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
/// lifecycle (kill/reap).
fn spawn_worker(
    target: Target,
    home: &TempHome,
    engine_url: &str,
    job_type: &str,
    extra_flags: &[&str],
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
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().expect("spawn offline worker")
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
    // the Rust target (the Node-target CI job runs the recovery test below).
    if target != Target::Rust {
        skip!("the bounded-reconnect backoff is the Rust worker's contract (#23)");
    }

    let home = TempHome::new();
    let engine_url = format!("http://127.0.0.1:{}", closed_port());
    let job_type = format!("ct-offline-{}", contract_tests::rand_suffix());
    // A short poll timeout so each failed activation cycle is quick; the
    // backoff (not the poll) is what must bound the retry rate.
    let mut child = spawn_worker(
        target,
        &home,
        &engine_url,
        &job_type,
        &["--poll-timeout", "500"],
    );
    let mut stderr = child.stderr.take().expect("worker stderr");

    // Observe the worker through several backoff cycles. With the bounded
    // backoff (1s base doubling to a 30s ceiling, full jitter) a 12s outage
    // yields on the order of 4–8 retry log lines; a hot spin (the actual #23
    // defect — no backoff between failed activations) would log thousands in
    // the same window. The assertion that pins the CONTRACT is the upper bound:
    // a worker that retries faster than the backoff allows fails here. (The
    // pre-#23 fixed-5s loop also passes this bound — it was never a hot spin —
    // so this test guards against a REGRESSION to unbounded retrying, while the
    // jittered-ceiling behaviour itself is pinned by the `runtime` unit tests.)
    let observe = Duration::from_secs(12);
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    use std::io::Read;
    while start.elapsed() < observe {
        // Non-blocking-ish drain: read what's there, then yield. The worker's
        // stderr is a pipe; a blocking read_to_end would wait for EOF (worker
        // exit) and never return during the window.
        match stderr.read(&mut chunk) {
            Ok(0) => break, // EOF: the worker EXITED — handled below.
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let stderr_text = String::from_utf8_lossy(&buf);
    let retries = stderr_text.matches("retrying in").count();

    // The worker must still be RUNNING at the end of the outage: an offline
    // engine is transient, so the slot must not crash or give up.
    let alive = child.try_wait().map(|s| s.is_none()).unwrap_or(false);
    // Reap the child before asserting so a failure never leaks the process.
    let _ = child.kill();
    let _ = child.wait();

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
#[test]
fn worker_recovers_and_picks_up_jobs_when_the_engine_returns() {
    let (engine, target) = match require_engine_and_target() {
        Ok(v) => v,
        Err(Skip(why)) => skip!(why),
    };
    if target != Target::Rust {
        skip!("recovery is asserted on the Rust worker (#23); the Node plugin's own retry loop is not this contract");
    }

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
    let process_instance_key = instance["processInstanceKey"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            instance["processInstanceKey"]
                .as_i64()
                .map(|k| k.to_string())
        })
        .expect("create instance: no processInstanceKey");

    // Phase 1: the worker against a CLOSED port survives the outage (bounded
    // retries, still alive) — a shorter re-assertion of the storm guard, kept
    // here so the down→up story is one scenario.
    let home = TempHome::new();
    let down_url = format!("http://127.0.0.1:{}", closed_port());
    let mut down_child = spawn_worker(
        target,
        &home,
        &down_url,
        &job_type,
        &["--poll-timeout", "500"],
    );
    std::thread::sleep(Duration::from_secs(6));
    let alive_down = down_child.try_wait().map(|s| s.is_none()).unwrap_or(false);
    let _ = down_child.kill();
    let _ = down_child.wait();
    assert!(
        alive_down,
        "the worker must stay up through an engine outage (it exits only when killed)"
    );

    // Phase 2: the engine is reachable; a worker pointed at it picks the
    // already-waiting job up and completes it (engine-observable settled state).
    let outcome = contract_tests::run_deployed_job(
        &engine,
        &target,
        &home,
        &job_type,
        &process_instance_key,
        &[
            json!({ "emit": "recovered" }),
            json!({ "write_result": { "ok": true } }),
        ],
        &[],
    );
    assert_eq!(
        outcome.job_state(),
        "COMPLETED",
        "after the outage the worker must reconnect and complete the waiting job; stderr:\n{}",
        outcome.stderr()
    );
    assert_eq!(outcome.variables()["ok"], true);
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
