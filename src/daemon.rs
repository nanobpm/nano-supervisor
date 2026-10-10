//! The daemon: the process manager. It reads the hires from `config.json`,
//! opens ONE shared engine connection, and runs N capacity-1 slots per hire as
//! tokio tasks. A slot task is resilient (it never returns an error), and each
//! job runs on its own task so a panic fails only that job.
//!
//! Shutdown is cooperative: on Ctrl-C / SIGTERM the daemon flips a watch channel
//! the slots observe, stops leasing new jobs, and drains within a grace period.
//! Agents are spawned in their own process group and armed to die with the
//! daemon ([`crate::pdeath`]), so even a `kill -9` leaves no orphans.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::watch;

use crate::control;
use crate::engine;
use crate::pin;
use crate::runtime::log;
use crate::slot::{self, SlotConfig};
use crate::state::{self, Hire, Protocol};

/// Host sandbox is the only mode the MVP daemon runs.
const HOST_SANDBOX: &str = "none";

/// How long slots are given to drain in-flight jobs after a shutdown signal
/// before the daemon exits (dropping the tasks; agents die via `kill_on_drop`
/// and parent-death cleanup).
const DRAIN_GRACE: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub profile: Option<String>,
    pub with_lease: bool,
    /// Capacity-1 slots to run per hire.
    pub slots: usize,
    /// Only run these hires (by name); empty = every hire in `config.json`.
    pub only: Vec<String>,
    pub recovery_window: Duration,
    pub idle_timeout: Duration,
    pub poll_timeout: Duration,
    pub clone_timeout: Duration,
    pub runs_dir: PathBuf,
    /// Override the `config.json` path (else the c8ctl-nano state home).
    pub config_path: Option<PathBuf>,
}

pub async fn run(opts: DaemonOptions) -> Result<()> {
    let config_path = match opts.config_path.clone() {
        Some(p) => p,
        None => state::config_file().ok_or_else(|| {
            anyhow::anyhow!("cannot locate the c8ctl-nano state home (set HOME or C8CTL_NANO_HOME)")
        })?,
    };

    // Issue #41: resolve & pin the connection BEFORE reading hires so the
    // daemon's VERY FIRST startup line names the engine it is about to serve
    // (the incident's only clue was buried in per-worker logs). Resolve the
    // profile ONCE (explicit `--profile`, else the pin this state home
    // recorded, else the current active profile) and persist the choice in
    // `connection.json`, so a later `c8 use profile` — by an agent or an
    // operator — can never silently retarget this daemon's fleet on its next
    // start.
    let state_home = state::state_home().ok_or_else(|| {
        anyhow::anyhow!("cannot locate the c8ctl-nano state home (set HOME or C8CTL_NANO_HOME)")
    })?;
    let decision = pin::resolve_or_pin(&state_home, opts.profile.as_deref())?;
    let engine_desc = decision.pin.describe();
    // The console header leads daemon startup output with the engine it is
    // about to serve: the incident's only clue was buried in per-worker logs,
    // so this banner must precede every other startup line (including the
    // config-path log below).
    log(&format!("engine: {engine_desc}"));
    if decision.created {
        log(&format!(
            "pinned the connection in {}: engine: {engine_desc}",
            pin::state_file(&state_home).display()
        ));
    }
    pin::warn_if_drifted(&decision);
    // Non-fatal pin-write warnings (e.g. a failed best-effort directory fsync)
    // were carried back in the decision rather than logged inside
    // `resolve_or_pin`, precisely so they land HERE — after the banner — and a
    // first start on a filesystem that rejects directory fsync still opens
    // with `engine: ...` (issue #41).
    pin::emit_deferred_warnings(&decision);

    log(&format!("reading hires from {}", config_path.display()));
    let all = state::read_hires_from(&config_path)?;
    if all.is_empty() {
        bail!(
            "no hires found in {} — hire an agent first (c8 nano hire …)",
            config_path.display()
        );
    }

    let selected: Vec<Hire> = all
        .into_iter()
        .filter(|h| opts.only.is_empty() || opts.only.iter().any(|n| n == &h.name))
        .collect();
    if selected.is_empty() {
        bail!("no hires matched --hire {:?}", opts.only);
    }

    // Normalize the runs root to the SAME absolute, parent-free lexical form
    // `slot::execute` registers in `active_runs` (via
    // `safecwd::normalize_run_path`). `execute` registers each in-flight run by
    // that normalized path, so a `SlotConfig.runs_dir` left relative (or
    // carrying a leading `..`) would make the retention sweep compare a
    // DIFFERENT key for the same directory (`std::path::absolute` keeps an
    // interior `..` that `normalize_run_path` resolves) and could reap a live
    // workspace. Normalizing here, once, keeps the registration key, the sweep
    // root, and the run-dir base identical (#36). This is purely lexical (the
    // no-follow hardening still inspects the real on-disk structure later).
    let runs_dir = crate::safecwd::normalize_run_path(&opts.runs_dir)
        .context("resolving absolute daemon runs-dir")?;

    // Every slot of this daemon connects through the PINNED profile — never
    // the ambient session — so a moved active profile cannot split the fleet.
    let pinned_base_url = decision.pin.base_url.clone();
    // The sanity guard's engine identity must be built from the hires this
    // daemon will ACTUALLY run — not every selected hire. A selected-but-invalid
    // hire (rejected by `validate` below) contributes no job types the daemon
    // serves; folding its production-looking matrix into the identity could make
    // `looks_like_test_engine` false even when every runnable hire is
    // `probe-*`/`ct-*`, suppressing the issue-#41 warning. So partition first.
    let mut runnable: Vec<&Hire> = Vec::new();
    for hire in &selected {
        if let Err(reason) = validate(hire) {
            log(&format!("skipping hire {:?}: {reason}", hire.name));
            continue;
        }
        runnable.push(hire);
    }
    if runnable.is_empty() {
        bail!("no runnable hires (all were skipped — see the warnings above)");
    }
    let all_types: Vec<String> = runnable
        .iter()
        .flat_map(|h| state::job_type_matrix(&h.rank, &h.capabilities))
        .collect();
    // Connect with the profile the pin already resolved (issue #41): passing the
    // pinned snapshot in rather than re-resolving `profiles.json` here closes
    // the window where a concurrent profile change could connect the client to
    // a different engine than the pin and banner.
    let jobs = engine::connect(
        decision.profile.as_ref(),
        &engine_desc,
        &all_types,
        pinned_base_url.as_deref(),
    )?;
    let host = short_hostname();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut handles = Vec::new();
    let mut running_hires = 0usize;
    // The in-process slots this daemon runs, as (worker id, profile) pairs — the
    // control socket's `status` reply reports each as a worker
    // (nanobpm/nano-supervisor#8).
    let mut worker_ids: Vec<(String, String)> = Vec::new();
    for hire in &runnable {
        let job_types = state::job_type_matrix(&hire.rank, &hire.capabilities);
        log(&format!(
            "hire {:?} [{}]: {} slot(s) over job types {:?}",
            hire.name, hire.rank, opts.slots, job_types
        ));
        running_hires += 1;
        for slot_idx in 0..opts.slots {
            let worker_name = format!("{host}-nanod-{}-{slot_idx}", hire.name);
            worker_ids.push((worker_name.clone(), hire.name.clone()));
            let cfg = Arc::new(SlotConfig {
                hire: (*hire).clone(),
                worker_name,
                job_types: job_types.clone(),
                recovery_window: opts.recovery_window,
                idle_timeout: opts.idle_timeout,
                poll_timeout: opts.poll_timeout,
                clone_timeout: opts.clone_timeout,
                runs_dir: runs_dir.clone(),
                with_lease: opts.with_lease,
                require_lease: opts.with_lease,
                max_jobs: None,
                propagate_job_panic: false,
                keep_runs: false,
                connection: decision.pin.clone(),
                connection_profile: decision.profile.clone(),
            });
            // Issue #41 sanity guard: judge each SLOT's own job-type matrix, not
            // the daemon-wide aggregate `all_types` the shared `jobs` was built
            // with. A daemon mixing a normal hire with a `ct-*`-only hire would
            // otherwise see the normal type in the aggregate and never warn for
            // the slot serving only test jobs. `for_slot` shares the client (and
            // its HTTP pool) but gives the slot its own matrix + warn-once latch.
            handles.push(tokio::spawn(slot::run(
                jobs.for_slot(job_types.clone()),
                cfg,
                shutdown_rx.clone(),
                shutdown_tx.clone(),
            )));
        }
    }

    if handles.is_empty() {
        bail!("no slots started (is --slots 0?)");
    }
    log(&format!(
        "daemon up: {} hire(s), {} slot(s) total; waiting for jobs. Ctrl-C to drain.",
        running_hires,
        handles.len()
    ));

    // --- control socket (nanobpm/nano-supervisor#8) -------------------------
    // Bind the supervisor control socket so a client (`supervisor status` /
    // `stop`, including the Node plugin's) can drive this daemon. A graceful
    // `stop` op flips `graceful` before the shutdown watch so the exit is a
    // clean drain, not the FATAL path a slot's watch flip signals.
    let graceful = Arc::new(AtomicBool::new(false));
    let log_file = state_home
        .join("logs")
        .join("supervisor")
        .join("daemon.log");
    let sock_path = control::socket_path(&state_home);
    let descriptor = control::DaemonDescriptor {
        pid: std::process::id(),
        started_at: control::iso8601_now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        socket: sock_path.to_string_lossy().into_owned(),
        log_file: log_file.to_string_lossy().into_owned(),
    };
    let engine_for_workers = pinned_base_url.clone().unwrap_or_else(|| engine_desc.clone());
    let control_handle = serve_control(
        sock_path.clone(),
        state_home.clone(),
        descriptor,
        worker_ids,
        engine_for_workers,
        control::epoch_millis(),
        shutdown_tx.clone(),
        graceful.clone(),
    )
    .await;

    // `wait_for_signal` reports whether a slot flipped the watch for a FATAL
    // misconfiguration (an unleased activation while leasing is enabled — the
    // default) versus an operator Ctrl-C/SIGTERM. We still drain either way, but
    // a fatal shutdown must surface as a non-zero exit (issue: default leasing is
    // documented to fail LOUDLY — returning `Ok(())` made the daemon look like a
    // clean drain).
    let mut fatal = wait_for_signal(&shutdown_tx).await;
    // A control-socket `stop` also flips the shutdown watch (via `graceful`), but
    // that is an operator-requested clean drain — never the fatal exit a slot's
    // own flip signals.
    if graceful.load(Ordering::SeqCst) {
        fatal = false;
    }
    if fatal {
        log("fatal: a slot could not fence its work while leasing is enabled (the default; engine not issuing leases); draining and exiting non-zero");
    } else {
        log("shutdown signal received; draining slots…");
    }
    let _ = shutdown_tx.send(true);

    // Give slots a bounded window to finish in-flight work; then exit (dropping
    // any stragglers — their agents die via kill_on_drop + parent-death).
    let drain = async {
        for h in handles {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(DRAIN_GRACE, drain).await.is_err() {
        log(&format!(
            "drain grace ({}s) elapsed; exiting and reaping remaining agents",
            DRAIN_GRACE.as_secs()
        ));
    } else {
        log("all slots drained; exiting");
    }

    // Tear the control socket down: stop accepting, remove the socket file and
    // the `supervisor.json` descriptor so a later `supervisor status` reports
    // "not running" rather than probing a stale socket.
    if let Some(handle) = control_handle {
        handle.abort();
    }
    let _ = std::fs::remove_file(&sock_path);
    let _ = std::fs::remove_file(state_home.join("supervisor.json"));

    if fatal {
        bail!(
            "daemon shut down because a slot received an unleased activation while leasing is \
             enabled (the default; opt out with --no-lease) — the engine is not issuing leases, so \
             the requested fencing is impossible"
        );
    }
    Ok(())
}

/// Bind and serve the supervisor control socket. Returns the accept-loop task
/// (aborted on daemon exit), or `None` if the socket could not be bound (the
/// daemon still runs its slots — it just cannot be driven over the socket).
#[allow(clippy::too_many_arguments)]
async fn serve_control(
    sock_path: PathBuf,
    state_home: PathBuf,
    descriptor: control::DaemonDescriptor,
    worker_ids: Vec<(String, String)>,
    engine: String,
    started_at_ms: u64,
    shutdown_tx: watch::Sender<bool>,
    graceful: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(unix)]
    {
        use tokio::net::UnixListener;

        // Clear a stale socket from a crashed predecessor so bind() succeeds; a
        // live predecessor would already hold the home lock elsewhere.
        let _ = std::fs::remove_file(&sock_path);
        if let Some(parent) = sock_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let listener = match UnixListener::bind(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                log(&format!(
                    "control socket unavailable ({}): {e}; status/stop clients cannot attach",
                    sock_path.display()
                ));
                return None;
            }
        };

        // Record the descriptor so clients that prefer `supervisor.json` (and
        // `supervisor status`) find the socket + pid without re-deriving them.
        let _ = std::fs::create_dir_all(&state_home);
        let sup_json = serde_json::json!({
            "pid": descriptor.pid,
            "startedAt": descriptor.started_at,
            "version": descriptor.version,
            "socket": descriptor.socket,
            "logFile": descriptor.log_file,
            "pluginVersion": descriptor.version,
        });
        if let Ok(bytes) = serde_json::to_vec_pretty(&sup_json) {
            let _ = std::fs::write(state_home.join("supervisor.json"), bytes);
        }
        log(&format!("control socket listening at {}", sock_path.display()));

        let handle = tokio::spawn(async move {
            let descriptor = Arc::new(descriptor);
            let worker_ids = Arc::new(worker_ids);
            let engine = Arc::new(engine);
            loop {
                let stream = match listener.accept().await {
                    Ok((stream, _addr)) => stream,
                    Err(_) => break,
                };
                let descriptor = descriptor.clone();
                let worker_ids = worker_ids.clone();
                let engine = engine.clone();
                let shutdown_tx = shutdown_tx.clone();
                let graceful = graceful.clone();
                tokio::spawn(async move {
                    handle_control_connection(
                        stream,
                        descriptor,
                        worker_ids,
                        engine,
                        started_at_ms,
                        shutdown_tx,
                        graceful,
                    )
                    .await;
                });
            }
        });
        Some(handle)
    }
    #[cfg(not(unix))]
    {
        let _ = (
            sock_path,
            state_home,
            descriptor,
            worker_ids,
            engine,
            started_at_ms,
            shutdown_tx,
            graceful,
        );
        None
    }
}

/// Serve one control connection: read NDJSON request lines, reply with frames,
/// and begin a graceful shutdown when a `stop` op is dispatched.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn handle_control_connection(
    stream: tokio::net::UnixStream,
    descriptor: Arc<control::DaemonDescriptor>,
    worker_ids: Arc<Vec<(String, String)>>,
    engine: Arc<String>,
    started_at_ms: u64,
    shutdown_tx: watch::Sender<bool>,
    graceful: Arc<AtomicBool>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let snapshot = control_snapshot(&descriptor, &worker_ids, &engine, started_at_ms);
        let Some(resp) = control::handle_request(&line, &snapshot) else {
            continue;
        };
        for frame in &resp.frames {
            if write_half
                .write_all(control::encode_frame(frame).as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = write_half.flush().await;
        if resp.stop {
            graceful.store(true, Ordering::SeqCst);
            let _ = shutdown_tx.send(true);
            return;
        }
    }
}

/// Build a fresh `status` snapshot (uptime recomputed per request) from the
/// daemon's fixed slot roster.
fn control_snapshot(
    descriptor: &control::DaemonDescriptor,
    worker_ids: &[(String, String)],
    engine: &str,
    started_at_ms: u64,
) -> control::StatusSnapshot {
    let uptime = control::epoch_millis().saturating_sub(started_at_ms);
    let log_dir = PathBuf::from(&descriptor.log_file)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    let workers = worker_ids
        .iter()
        .map(|(id, profile)| {
            let log_file = log_dir
                .join(format!("worker-{id}.log"))
                .to_string_lossy()
                .into_owned();
            control::WorkerStatus::in_process(
                id.clone(),
                profile.clone(),
                descriptor.pid,
                started_at_ms,
                uptime,
                log_file,
                engine.to_string(),
            )
        })
        .collect();
    control::StatusSnapshot {
        daemon: descriptor.clone(),
        plugin_version: descriptor.version.clone(),
        workers,
    }
}

/// Reject a hire the MVP daemon cannot run. Only the host sandbox is supported,
/// the command must be present, and a `pipe` hire whose command actually selects
/// ACP is refused (issue #275 — it would feed plain JSON to an ACP harness).
pub(crate) fn validate(hire: &Hire) -> Result<()> {
    if hire.command.trim().is_empty() {
        bail!("no command to run");
    }
    if hire.rank.is_empty() {
        bail!("no rank");
    }
    if hire.sandbox != HOST_SANDBOX {
        bail!(
            "sandbox {:?} is not supported by the MVP daemon (host sandbox only)",
            hire.sandbox
        );
    }
    if hire.protocol != Protocol::Acp && command_has_acp_selector(&hire.command, &hire.args) {
        bail!(
            "command selects ACP mode but protocol is not \"acp\" — the worker would pipe plain \
             JSON to an ACP harness that rejects it (issue #275); re-hire with --protocol acp"
        );
    }
    Ok(())
}

/// Does the command line select ACP mode (an `acp`/`--acp` token or a `*-acp`
/// adapter command)? A conservative port of the Node plugin's selector scan.
pub(crate) fn command_has_acp_selector(command: &str, args: &[String]) -> bool {
    let mut tokens: Vec<&str> = command.split_whitespace().collect();
    tokens.extend(args.iter().map(String::as_str));
    scan_acp_tokens(&tokens)
}

/// Does the basename of `name` identify a POSIX shell that reads its program
/// from a `-c <script>` string argument? Only these commands treat a short
/// `-…c` flag as a wrapped command line; a NON-shell agent's own `-c`/`-ec`
/// option (a config flag, a `--continue` alias, …) carries plain text, not a
/// script. Gating the `-c` shell-wrapper handling on this check stops a
/// non-shell `-c` from being mistaken for a shell wrapper — which would either
/// scan its argument for a selector (false-positive protocol mismatch) or
/// rewrite that argument as a script when injecting `--acp`. Mirrors the
/// reference worker, which descends only for actual shell wrappers.
fn is_shell_command(name: &str) -> bool {
    let base = name
        .trim_matches(|c| c == '"' || c == '\'')
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name);
    matches!(
        base,
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "mksh"
    )
}

/// Is `name` a short shell `-…c` flag (`-c`, `-ec`, `-lc`, …) — a single-dash
/// option ending in `c` that carries the shell's script as the next token?
fn is_short_c_flag(name: &str) -> bool {
    name.starts_with('-') && !name.starts_with("--") && name.len() >= 2 && name.ends_with('c')
}

/// `true` when a token only re-execs or decorates the real command (`exec`,
/// `command`, `builtin`, `env`, or a `VAR=value` assignment), so the command
/// name is the first token PAST any such prefix. The wrapper name is matched by
/// BASENAME, as [`is_shell_command`] already does for absolute shell paths: a
/// hire such as `command = "/usr/bin/env"`, `args = ["sh", "-c", "nano-coder"]`
/// runs `sh` as the real program, and matching only the bare `env` would stop at
/// the `/usr/bin/env` wrapper, gate the `-c` injection off, and append `--acp`
/// to the outer argv where POSIX `sh` swallows it as `$0`.
fn is_launch_prefix(t: &str) -> bool {
    let t = t.trim_matches(|c| c == '"' || c == '\'');
    let base = t.rsplit(['/', '\\']).next().unwrap_or(t);
    matches!(base, "exec" | "command" | "builtin" | "env")
        || (!t.starts_with('-')
            && t.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }))
}

/// Is `t` the `env` launch wrapper (matched by basename, so an absolute path
/// such as `/usr/bin/env` counts)? Only `env` carries its OWN option tokens
/// between the wrapper and the real command, so it is the one prefix whose
/// trailing options the effective-command scan must step over.
fn is_env_wrapper(t: &str) -> bool {
    let t = t.trim_matches(|c| c == '"' || c == '\'');
    t.rsplit(['/', '\\']).next().unwrap_or(t) == "env"
}

/// How many tokens an `env` option consumes INCLUDING the option token itself:
/// `0` for a nullary flag (`-i`), `1` when the value is glued on (`-uNAME`,
/// `-C/dir`, `-Sstr`), `2` when the value is the NEXT token (`-u NAME`,
/// `-C DIR`, BSD/macOS `-P ALTPATH`). Returns `None` when the token is not a
/// recognised `env` option, so the caller stops skipping. Only the options
/// that take a separate argument need a `2`; every other `env` flag is nullary
/// or carries its value inline.
///
/// The point is not to parse `env` fully but to step over the options a valid
/// hire can place between `env` and the real command (`env -i sh -c …`,
/// `env -u FOO bash -lc …`, `env -- sh …`), so the effective-command scan is
/// not fooled into naming `-i` the command. Stopping at `--` mirrors `env`
/// itself, which treats `--` as the end of its own options.
///
/// KNOWN LIMIT: `-S`/`--split-string` makes `env` split its string argument
/// into the command PLUS its own arguments (`env -S "sh -c nano-coder"` runs
/// `sh` with `-c nano-coder`), so the effective command lives INSIDE the `-S`
/// string token rather than at a top-level index. A positional scan cannot
/// point into that sub-token, so a `-S`-wrapped shell resolves non-shell and
/// the selector is appended to the outer argv (the safe failure — the agent
/// still boots, just possibly without ACP) rather than mis-injected. That case
/// is rare and shell-quoting-sensitive; the common wrapper options above are
/// resolved exactly.
fn env_option_arity(t: &str) -> Option<usize> {
    let t = t.trim_matches(|c| c == '"' || c == '\'');
    if t == "--" {
        return Some(1);
    }
    if !t.starts_with('-') || t == "-" {
        return None;
    }
    if let Some(long) = t.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or(long);
        // Only the long options that take a value consume a second token when
        // the value is not glued on with `=`; the rest (`--ignore-environment`,
        // `--null`, …) are nullary.
        return Some(match name {
            "unset"
            | "chdir"
            | "split-string"
            | "argv0"
            | "default-signal"
            | "block-signal"
            | "ignore-signal"
            | "list-signal-handling" => {
                if long.contains('=') {
                    1
                } else {
                    2
                }
            }
            _ => 1,
        });
    }
    // Short options. `-u`/`-C` take a separate-argument value; `-S` takes its
    // (possibly quoted, multi-word) string as the next token. BSD/macOS `env`
    // (the deployment OS) adds `-P altpath`, which also takes its value as the
    // NEXT token — treating it as nullary lands the scan on the altpath as the
    // effective command, so a `-P`-wrapped `*-acp` adapter fails the selector
    // scan OPEN and a `-P`-wrapped shell gets `--acp` appended to the outer
    // argv (swallowed as `$0`) instead of injected. A glued-on value (`-uNAME`,
    // `-C/dir`) or a bundled nullary flag (`-i`, `-iv`, `-0`) is one token. The
    // first byte after the dash decides, because `env` bundles nullary short
    // flags but never bundles a value-taking flag ahead of more letters (the
    // rest of the token IS the value).
    let rest = &t[1..];
    let first = rest.chars().next()?;
    Some(match first {
        'u' | 'C' | 'S' | 'P' | 'a' => {
            if rest.len() > 1 {
                1
            } else {
                2
            }
        }
        _ => 1,
    })
}

/// Index of the EFFECTIVE command token — the first token past every launch
/// prefix AND past any options belonging to an `env` prefix. This is the single
/// resolver every consumer (`scan_acp_tokens`, `effective_command_is_shell`,
/// `inject_selector_into_script`) uses, so the whole class of wrapper
/// (`exec`/`command`/`builtin`/`env`/`VAR=value`) plus wrapper-option
/// (`env -i`/`env -u NAME`/`env --`) indirection is resolved the same way
/// everywhere instead of each call site stopping at the first non-prefix —
/// which, for `env -i sh -c …`, is the `-i` flag, not the shell.
///
/// `T` is the token type (`&str` for an argv slice, `ScriptToken` for a
/// tokenized script); `as_text` extracts the comparable text so the same logic
/// serves both without forcing an artificial lifetime on the returned borrow.
fn effective_command_index<T>(tokens: &[T], as_text: impl Fn(&T) -> &str) -> Option<usize> {
    let mut i = 0;
    while i < tokens.len() {
        let tok = as_text(&tokens[i]);
        if !is_launch_prefix(tok) {
            return Some(i);
        }
        if is_env_wrapper(tok) {
            // Step over this `env` wrapper's own options before re-testing for
            // the command: `env -i sh`, `env -u FOO sh`, `env -- sh` all run
            // `sh`, so the option tokens must not be mistaken for it.
            i += 1;
            while i < tokens.len() {
                match env_option_arity(as_text(&tokens[i])) {
                    Some(arity) => i += arity,
                    None => break,
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Scan an argv token list for an ACP selector, recursing into shell `-c`
/// scripts.
///
/// A whole-token scan alone misses a shell-wrapped selector: a `pipe` hire with
/// command `sh` and args `["-c", "nano-coder --acp"]` keeps the script as ONE
/// opaque token, so `--acp` hides inside it and the validator would run the ACP
/// harness over the pipe path instead of exiting 78 (issue #275). Plugin 1.70.1
/// recursively inspects `-c` scripts, so do the same here: when a short option
/// ending in `c` (`-c`, `-ec`, `-lc`, …) is followed by a script token, split
/// that script on whitespace and scan it too. Recursion depth is bounded by the
/// finite nesting of quoted scripts.
fn scan_acp_tokens(tokens: &[&str]) -> bool {
    // The command token is the first token past every launch prefix AND past
    // any `env`-wrapper options: leading `exec`/`command`/`builtin`/`env`
    // wrappers, `VAR=value` env assignments, and an `env` wrapper's own options
    // (`env -i`, `env -u NAME`, `env --`) only re-exec or decorate the real
    // command (`sh -c "exec claude-code-acp"`, `env -i sh -c "nano-coder
    // --acp"`), so the `*-acp` suffix check must look past them instead of
    // gating on the literal first token — or on an `env` option it mistakes
    // for the command.
    let command_pos = effective_command_index(tokens, |t| t);
    // The `-…c` shell-wrapper recursion below must fire ONLY when this level's
    // command is an actual shell: a non-shell agent's own `-c` option (e.g.
    // `agent -c "config --acp"`) is config text, not a script, so recursing into
    // it would wrongly report a selector (a false protocol mismatch).
    let command_is_shell = command_pos
        .map(|p| is_shell_command(tokens[p].trim_matches(|c| c == '"' || c == '\'')))
        .unwrap_or(false);
    for (i, tok) in tokens.iter().enumerate() {
        let name = tok.trim_matches(|c| c == '"' || c == '\'');
        let (opt, inline_val) = match name.split_once('=') {
            Some((o, v)) => (o, Some(v)),
            None => (name, None),
        };
        if matches!(opt, "acp" | "-acp" | "--acp") {
            return true;
        }
        // An ACP-named SWITCH selects ACP too, not only an ACP-named command:
        // plugin 1.70.1 recognizes long options whose base name ends in `-acp`
        // (Qwen's `--experimental-acp`, `--experimental-acp=true`), so a hire
        // carrying one runs the agent in ACP mode. Match the option NAME (the
        // part before any `=value`) by basename, exactly as the command-token
        // suffix check below does — but do NOT match a VALUE that merely ends
        // in `-acp` (`--model=foo-acp`): the option name is `model`, not an ACP
        // switch. Single-dash shorts are excluded (`-c` is a shell flag, not an
        // ACP switch); only the `--long` form carries an ACP-mode switch name.
        if opt.starts_with("--") {
            let opt_base = opt.rsplit(['/', '\\']).next().unwrap_or(opt);
            if opt_base.ends_with("-acp") {
                return true;
            }
        }
        // `--protocol acp` / `--protocol=acp` selects the ACP harness too: the
        // value carries the selector, so inspect it (inline after `=`, else the
        // following token) rather than only matching bare `acp` tokens.
        if opt == "--protocol" {
            let value = inline_val
                .or_else(|| {
                    tokens
                        .get(i + 1)
                        .map(|t| t.trim_matches(|c| c == '"' || c == '\''))
                })
                .unwrap_or("");
            if value.eq_ignore_ascii_case("acp") {
                return true;
            }
        }
        // The `*-acp` adapter suffix identifies the command token only — the
        // first non-prefix token of this (sub)command, so it also catches a
        // wrapped inner command like `sh -c "exec claude-code-acp"` when
        // recursing.
        if Some(i) == command_pos {
            let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
            if base.ends_with("-acp") {
                return true;
            }
        }
        // Shell wrapper: a short `-…c` flag (e.g. `-c`, `-ec`) hides the real
        // agent invocation inside the following script token. Scan that script's
        // own tokens so a shell-wrapped ACP selector is not missed — but ONLY
        // when this level's command is a real shell, so a non-shell `-c` option
        // is not misread as a wrapper.
        if command_is_shell && is_short_c_flag(name) {
            if let Some(script) = tokens.get(i + 1).copied() {
                let script = script.trim_matches(|c| c == '"' || c == '\'');
                // Tokenize the script with the SAME quote-aware tokenizer the
                // selector-injection path uses (`tokenize_script`), not a bare
                // whitespace split: `sh -c "FOO='a b' claude-code-acp"` splits
                // `'a b'` into two words under whitespace, landing the command
                // scan on `b'` and missing the real `*-acp` adapter — a pipe
                // hire then bypasses the protocol-mismatch guard. One shared
                // tokenizer keeps detection and injection consistent.
                let sub_toks = tokenize_script(script);
                let sub: Vec<&str> = sub_toks.iter().map(|t| t.text.as_str()).collect();
                if scan_acp_tokens(&sub) {
                    return true;
                }
            }
        }
    }
    false
}

/// The argv an ACP hire is launched with (plugin 1.70.1 parity). The Node worker
/// accepts an ACP hire whose command carries no ACP selector and appends `--acp`
/// at spawn time, so a plain agent binary is started in ACP mode rather than its
/// default (non-ACP) mode — where the JSON-RPC handshake would fail. A hire that
/// already selects ACP (an `acp`/`--acp` token, `--protocol acp`, or a `*-acp`
/// adapter command) is returned unchanged, so the selector is never doubled.
///
/// A shell-wrapped hire (`sh -c "nano-coder"`) needs the selector injected INTO
/// the `-c` script, not appended to the outer argv: `sh -c nano-coder --acp`
/// lets POSIX `sh` swallow `--acp` as `$0`, so the inner agent never receives it
/// and the ACP handshake fails. Mirror the recursive `-c` scan in
/// [`scan_acp_tokens`]: when a short `-…c` flag carries the real command, inject
/// the selector INTO the INNERMOST wrapped command (so nested wrappers like
/// `sh -c "bash -c 'nano-coder'"` reach the real agent), re-quoting the inner
/// script so it stays a single argument. A non-shell command's `-c` option is
/// left alone and the selector appended to the outer argv instead.
pub(crate) fn acp_spawn_args(hire: &Hire) -> Vec<String> {
    let mut args = hire.args.clone();
    if command_has_acp_selector(&hire.command, &args) {
        return args;
    }
    if effective_command_is_shell(&hire.command, &args) {
        if let Some(i) = shell_script_arg_index(&args) {
            args[i] = inject_selector_into_script(&args[i]);
            return args;
        }
    }
    args.push("--acp".to_string());
    args
}

/// Does the hire's EFFECTIVE program (the first token past any launch prefix)
/// identify a POSIX shell? The outer argv a shell wrapper is spawned with can
/// carry launch prefixes just like a `-c` script does — a launch-prefixed form
/// such as `command = "env"`, `args = ["sh", "-c", "nano-coder"]` runs `sh` as
/// the real program. Gating the `-c` injection on only `hire.command` would miss
/// that: the selector would be appended to the OUTER argv (`env sh -c nano-coder
/// --acp`), and POSIX `sh` swallows the trailing `--acp` as `$0`, so the inner
/// agent never receives it and the ACP handshake fails. Mirror the launch-prefix
/// resolution [`scan_acp_tokens`] and [`inject_selector_into_script`] already do
/// so the whole class — prefixed outer argv AND prefixed inner script — is
/// handled, not just the inner one.
fn effective_command_is_shell(command: &str, args: &[String]) -> bool {
    // Tokenize `command` quote-aware (the same `tokenize_script` the `-c` script
    // scan and the injection path use), not with a bare whitespace split: a
    // command string carrying a quoted segment (`env FOO='a b' sh`) must resolve
    // to the same effective command here as everywhere else, or the `-c`
    // injection is gated on a different token than the selector scan used.
    let cmd_toks = tokenize_script(command);
    let tokens: Vec<&str> = cmd_toks
        .iter()
        .map(|t| t.text.as_str())
        .chain(args.iter().map(String::as_str))
        .collect();
    effective_command_index(&tokens, |t| t)
        .map(|p| is_shell_command(tokens[p]))
        .unwrap_or(false)
}

/// Index in `args` of the outer shell `-c` script token — the token following a
/// short `-…c` flag (`-c`, `-ec`, `-lc`, …). The caller has already confirmed
/// the command is a shell, so this only locates the wrapped script.
fn shell_script_arg_index(args: &[String]) -> Option<usize> {
    args.iter().enumerate().find_map(|(i, a)| {
        let name = a.trim_matches(|c| c == '"' || c == '\'');
        (is_short_c_flag(name) && i + 1 < args.len()).then_some(i + 1)
    })
}

/// Inject `--acp` into a shell `-c` script string, descending to the INNERMOST
/// wrapped command. For `bash -c 'nano-coder'` this rewrites the inner script to
/// `bash -c 'nano-coder --acp'`; for a plain command it appends `--acp`. The
/// inner script is re-quoted so the appended selector stays part of that inner
/// shell's single `-c` argument rather than leaking out as the next word (which
/// the inner shell would consume as `$0`, dropping the selector again).
fn inject_selector_into_script(script: &str) -> String {
    let toks = tokenize_script(script);
    let command_pos = effective_command_index(&toks, |t| t.text.as_str());
    let command_is_shell = command_pos
        .map(|p| is_shell_command(&toks[p].text))
        .unwrap_or(false);
    if command_is_shell {
        if let Some(c_idx) = command_pos {
            if let Some(script_tok) = toks
                .iter()
                .enumerate()
                .skip(c_idx + 1)
                .find_map(|(k, t)| {
                    (is_short_c_flag(&t.text) && k + 1 < toks.len()).then_some(k + 1)
                })
                .map(|k| &toks[k])
            {
                let inner = inject_selector_into_script(&script_tok.text);
                let requoted = requote_script_arg(&inner);
                return format!(
                    "{}{}{}",
                    &script[..script_tok.start],
                    requoted,
                    &script[script_tok.end..]
                );
            }
        }
    }
    format!("{} --acp", script.trim_end())
}

/// Re-quote an inner shell script so it is a single argument. A bare single word
/// needs no quoting; anything containing whitespace is single-quoted with POSIX
/// `'\''` escaping of embedded single quotes.
fn requote_script_arg(s: &str) -> String {
    if !s.is_empty() && !s.chars().any(char::is_whitespace) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// A single token of a shell script string with its byte span in the original
/// string. `text` is the unquoted content; a fully-quoted token records its
/// span (including the quotes) so it can be spliced back after rewriting.
struct ScriptToken {
    text: String,
    start: usize,
    end: usize,
}

/// Split a shell script string into whitespace-separated tokens, honoring
/// `'`/`"` quoting — including a quote that opens MID-token (`FOO='a b'` is one
/// word whose quoted part spans the space), since a shell joins adjacent
/// quoted/unquoted segments into a single word. A bare whitespace split would
/// break `FOO='a b' claude-code-acp` into `FOO='a`, `b'`, `claude-code-acp`,
/// landing the effective-command scan on `b'` and missing the real adapter.
/// `text` is the token with its quotes stripped; `start`/`end` span the token
/// (quotes included) in the original string so a rewritten token can be spliced
/// back. Good enough for the simple hire command lines this handles; it is not
/// a full shell parser (no `$()`/`\\` escapes).
fn tokenize_script(s: &str) -> Vec<ScriptToken> {
    let bytes = s.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < s.len() {
        while i < s.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let start = i;
        let mut text = String::new();
        // Consume one shell word: run to the next UNQUOTED whitespace, splicing
        // any quoted segment's content in without its quotes.
        while i < s.len() && !bytes[i].is_ascii_whitespace() {
            if bytes[i] == b'\'' || bytes[i] == b'"' {
                let q = bytes[i];
                i += 1;
                let content_start = i;
                while i < s.len() && bytes[i] != q {
                    i += 1;
                }
                text.push_str(&s[content_start..i]);
                if i < s.len() {
                    i += 1; // consume closing quote
                }
            } else {
                // Unquoted run: copy the raw substring so multi-byte UTF-8 is
                // preserved. Casting each `u8` to `char` would reinterpret a
                // continuation byte as its own Latin-1 code point and mojibake
                // any non-ASCII token.
                let seg_start = i;
                while i < s.len()
                    && !bytes[i].is_ascii_whitespace()
                    && bytes[i] != b'\''
                    && bytes[i] != b'"'
                {
                    i += 1;
                }
                text.push_str(&s[seg_start..i]);
            }
        }
        toks.push(ScriptToken {
            text,
            start,
            end: i,
        });
    }
    toks
}

/// This machine's short hostname (first dot-label, lowercased), for worker names.
pub(crate) fn short_hostname() -> String {
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "host".into());
    host.split('.')
        .next()
        .unwrap_or("host")
        .to_ascii_lowercase()
}

/// Block until a shutdown trigger fires. Returns `true` when a slot flipped the
/// `fatal` watch — an unrecoverable misconfiguration (e.g. an unleased
/// activation while leasing is enabled, the default) that must exit loudly — and
/// `false` for an operator Ctrl-C/SIGTERM drain. The caller distinguishes the two
/// so a fatal shutdown surfaces as a non-zero exit rather than a clean `Ok(())`.
pub(crate) async fn wait_for_signal(fatal: &watch::Sender<bool>) -> bool {
    // Also wake if a slot flips the shutdown watch (a fatal misconfiguration,
    // e.g. an unleased activation while leasing is enabled), so the daemon exits
    // loudly rather than lingering with the offending slot stopped.
    let mut fatal_rx = fatal.subscribe();
    // A second subscription used only to re-read the watch's *final* value after
    // the wait returns — `select!` reports whichever arm fired, not the channel's
    // settled state, so a fatal flip published in the same tick an operator
    // Ctrl-C/SIGTERM arrives could otherwise be masked by the signal arm winning.
    let recheck_rx = fatal.subscribe();
    let slot_requested = async {
        let _ = fatal_rx.wait_for(|stop| *stop).await;
    };
    let signal_was_fatal = {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut term) => tokio::select! {
                    _ = tokio::signal::ctrl_c() => false,
                    _ = term.recv() => false,
                    _ = slot_requested => true,
                },
                Err(_) => tokio::select! {
                    _ = tokio::signal::ctrl_c() => false,
                    _ = slot_requested => true,
                },
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => false,
                _ = slot_requested => true,
            }
        }
    };
    // Fatal always wins: if a slot has published a fatal state by now, surface it
    // even when an operator signal was the arm that woke us.
    signal_was_fatal || *recheck_rx.borrow()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hire(protocol: Protocol, command: &str, sandbox: &str) -> Hire {
        Hire {
            name: "coder".into(),
            rank: "senior".into(),
            command: command.into(),
            args: vec![],
            model: String::new(),
            capabilities: vec![],
            protocol,
            sandbox: sandbox.into(),
            env: Default::default(),
        }
    }

    #[test]
    fn rejects_container_sandbox() {
        assert!(validate(&hire(Protocol::Pipe, "copilot", "docker")).is_err());
    }

    #[test]
    fn rejects_empty_command() {
        assert!(validate(&hire(Protocol::Pipe, "  ", "none")).is_err());
    }

    #[test]
    fn rejects_acp_command_under_pipe() {
        assert!(validate(&hire(Protocol::Pipe, "nano-coder --acp", "none")).is_err());
        assert!(validate(&hire(Protocol::Acp, "nano-coder --acp", "none")).is_ok());
    }

    #[test]
    fn accepts_plain_host_pipe_hire() {
        assert!(validate(&hire(Protocol::Pipe, "copilot", "none")).is_ok());
    }

    #[test]
    fn acp_selector_detection() {
        assert!(command_has_acp_selector("nano-coder --acp", &[]));
        assert!(command_has_acp_selector("nano-coder", &["acp".into()]));
        assert!(command_has_acp_selector("claude-code-acp", &[]));
        assert!(command_has_acp_selector(
            "nano-coder",
            &["--protocol=acp".into()]
        ));
        assert!(command_has_acp_selector(
            "nano-coder",
            &["--protocol".into(), "acp".into()]
        ));
        assert!(command_has_acp_selector("nano-coder --protocol=ACP", &[]));
        assert!(!command_has_acp_selector(
            "nano-coder",
            &["--protocol=pipe".into()]
        ));
        assert!(!command_has_acp_selector(
            "copilot",
            &["--model=foo-acp".into()]
        ));
        assert!(!command_has_acp_selector(
            "copilot",
            &["--allow-all".into()]
        ));
    }

    #[test]
    fn acp_selector_detection_sees_acp_named_switch_options() {
        // Plugin 1.70.1 recognizes ACP switches whose NAME ends in `-acp`
        // (Qwen's `--experimental-acp`), so an agent invoked with one runs in
        // ACP mode: an ACP hire must not get a second `--acp`, and a pipe hire
        // carrying one must be rejected as a protocol mismatch.
        assert!(command_has_acp_selector(
            "qwen",
            &["--experimental-acp".into()]
        ));
        // The `=value` form still names the ACP switch (the value is not the
        // selector; the option name is).
        assert!(command_has_acp_selector(
            "qwen",
            &["--experimental-acp=true".into()]
        ));
        // …including when shell-wrapped.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "qwen --experimental-acp".into()]
        ));
        // A pipe hire with an ACP-named switch fails the protocol-mismatch guard.
        let mut h = hire(Protocol::Pipe, "qwen", "none");
        h.args = vec!["--experimental-acp".into()];
        assert!(validate(&h).is_err());
        // …while an ACP hire with the same switch is accepted and NOT doubled.
        let mut ok = hire(Protocol::Acp, "qwen", "none");
        ok.args = vec!["--experimental-acp".into()];
        assert!(validate(&ok).is_ok());
        assert_eq!(acp_spawn_args(&ok), vec!["--experimental-acp".to_string()]);
        // A VALUE that merely ends in `-acp` is not a switch: the option name
        // (`--model`) decides, so `--model=foo-acp` stays a non-ACP hire.
        assert!(!command_has_acp_selector(
            "copilot",
            &["--model=foo-acp".into()]
        ));
        // A non-ACP long option (`--allow-all`) is not an ACP switch either.
        assert!(!command_has_acp_selector(
            "copilot",
            &["--allow-all".into()]
        ));
    }

    #[test]
    fn acp_selector_detection_is_quote_aware() {
        // A bare whitespace split of `FOO='a b' claude-code-acp` breaks the
        // quoted assignment into `FOO='a` / `b'`, landing the effective-command
        // scan on `b'` and missing the real `*-acp` adapter — a pipe hire then
        // bypasses the protocol-mismatch guard. The scan must tokenize the `-c`
        // script quote-aware (mixed quoted/unquoted segments join into one word).
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "FOO='a b' claude-code-acp".into()]
        ));
        // …and a quoted non-ACP script still yields no selector (no false
        // positive from a mis-split token).
        assert!(!command_has_acp_selector(
            "sh",
            &["-c".into(), "FOO='a b' copilot".into()]
        ));
        // A mid-token quote around the selector itself still resolves.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "exec env X='1 2' claude-code-acp".into()]
        ));
    }

    #[test]
    fn tokenize_script_preserves_non_ascii_unquoted_tokens() {
        // Regression: the unquoted-run copy must not cast each byte to `char`,
        // which reinterprets a multi-byte UTF-8 sequence as separate Latin-1
        // code points (`café-acp` -> `cafÃ©-acp`) and corrupts a spawned command.
        let toks = tokenize_script("café-acp --flag");
        assert_eq!(toks[0].text, "café-acp");
        assert_eq!(toks[1].text, "--flag");
        // A word mixing unquoted and quoted non-ASCII segments joins intact.
        let mixed = tokenize_script("naïve'-wörld'-acp");
        assert_eq!(mixed[0].text, "naïve-wörld-acp");
        // The nested-shell injection path re-emits the inner script text, so a
        // non-ASCII unquoted command must survive the round-trip, not mojibake.
        assert_eq!(
            inject_selector_into_script("sh -c /café/nano-coder"),
            "sh -c '/café/nano-coder --acp'"
        );
    }

    #[test]
    fn acp_spawn_args_injects_when_command_string_is_quoted() {
        // The injection path resolves the effective shell from `command` with the
        // SAME quote-aware tokenizer as the selector scan, so a quoted command
        // string (`env FOO='a b' sh`) still names `sh` the shell and gets `--acp`
        // injected INTO the `-c` script — not appended to the outer argv where
        // POSIX `sh` would swallow it as `$0`.
        let mut h = hire(Protocol::Acp, "env FOO='a b' sh", "none");
        h.args = vec!["-c".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&h),
            vec!["-c".to_string(), "nano-coder --acp".to_string()]
        );
    }

    #[test]
    fn acp_selector_detection_sees_shell_wrapped_commands() {
        // A shell-wrapped selector keeps the script as one opaque arg token; the
        // scan must recurse into `-c <script>` to find it (issue #275).
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "nano-coder --acp".into()]
        ));
        assert!(command_has_acp_selector(
            "bash",
            &["-c".into(), "nano-coder acp".into()]
        ));
        // The inner command's `*-acp` adapter suffix counts when wrapped too.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "claude-code-acp --foo".into()]
        ));
        // `--protocol acp` inside the script is caught.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "nano-coder --protocol acp".into()]
        ));
        // Combined short flags (`-ec`) that still take a script also recurse.
        assert!(command_has_acp_selector(
            "bash",
            &["-ec".into(), "exec nano-coder --acp".into()]
        ));
        // Nested wrappers still resolve to the inner selector.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "sh -c 'nano-coder --acp'".into()]
        ));
        // A wrapped NON-ACP script is still accepted — no false positive.
        assert!(!command_has_acp_selector(
            "sh",
            &["-c".into(), "nano-coder --pipe".into()]
        ));
        // A launch prefix (`exec`, `env`, `VAR=value` assignments) shifts the
        // adapter off the literal first token; the suffix check must look past
        // it or a pipe hire like `sh -c "exec claude-code-acp"` fails open.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "exec claude-code-acp".into()]
        ));
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "env X=1 claude-code-acp".into()]
        ));
        assert!(command_has_acp_selector(
            "sh",
            &[
                "-c".into(),
                "exec env FOO=bar /opt/bin/claude-code-acp".into()
            ]
        ));
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "exec nano-coder --acp".into()]
        ));
        // …while a prefixed NON-ACP command is still accepted.
        assert!(!command_has_acp_selector(
            "sh",
            &["-c".into(), "exec nano-coder --pipe".into()]
        ));
        assert!(!command_has_acp_selector(
            "sh",
            &["-c".into(), "env X=1 copilot".into()]
        ));
    }

    #[test]
    fn rejects_shell_wrapped_acp_command_under_pipe() {
        // The validator must reject a `pipe` hire that hides an ACP selector in a
        // shell `-c` script, exactly as it rejects a bare `--acp` token.
        let mut h = hire(Protocol::Pipe, "sh", "none");
        h.args = vec!["-c".into(), "nano-coder --acp".into()];
        assert!(validate(&h).is_err());
        // An ACP hire with the same shell-wrapped selector is fine.
        let mut ok = hire(Protocol::Acp, "sh", "none");
        ok.args = vec!["-c".into(), "nano-coder --acp".into()];
        assert!(validate(&ok).is_ok());
    }

    #[test]
    fn acp_spawn_args_appends_selector_for_plain_acp_hire() {
        // Plugin 1.70.1 parity: an ACP hire whose command has no ACP selector is
        // launched with `--acp` appended, so the agent boots in ACP mode and the
        // JSON-RPC handshake succeeds.
        let h = hire(Protocol::Acp, "nano-coder", "none");
        assert_eq!(acp_spawn_args(&h), vec!["--acp".to_string()]);
    }

    #[test]
    fn acp_spawn_args_never_doubles_an_existing_selector() {
        // A hire that already selects ACP (a `--acp` token, `--protocol acp`, or
        // a `*-acp` adapter command) is spawned unchanged — the selector is not
        // appended again.
        let mut with_flag = hire(Protocol::Acp, "nano-coder", "none");
        with_flag.args = vec!["--acp".into()];
        assert_eq!(acp_spawn_args(&with_flag), vec!["--acp".to_string()]);

        let adapter = hire(Protocol::Acp, "claude-code-acp", "none");
        assert!(acp_spawn_args(&adapter).is_empty());

        let mut with_protocol = hire(Protocol::Acp, "nano-coder", "none");
        with_protocol.args = vec!["--protocol=acp".into()];
        assert_eq!(
            acp_spawn_args(&with_protocol),
            vec!["--protocol=acp".to_string()]
        );
    }

    #[test]
    fn acp_spawn_args_injects_selector_into_shell_wrapper_script() {
        // A shell-wrapped hire hides the real agent inside the `-c` script token.
        // Appending `--acp` to the OUTER argv (`sh -c nano-coder --acp`) lets the
        // shell swallow it as `$0`, so the inner agent never sees it. The selector
        // must be injected INTO the script instead.
        let mut wrapped = hire(Protocol::Acp, "sh", "none");
        wrapped.args = vec!["-c".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&wrapped),
            vec!["-c".to_string(), "nano-coder --acp".to_string()]
        );

        // Same for other short `-…c` shapes and prefixed inner commands — the
        // whole class the selector scan recurses into.
        let mut exec_prefixed = hire(Protocol::Acp, "bash", "none");
        exec_prefixed.args = vec!["-lc".into(), "exec nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&exec_prefixed),
            vec!["-lc".to_string(), "exec nano-coder --acp".to_string()]
        );

        let mut env_prefixed = hire(Protocol::Acp, "sh", "none");
        env_prefixed.args = vec!["-ec".into(), "env X=1 nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&env_prefixed),
            vec!["-ec".to_string(), "env X=1 nano-coder --acp".to_string()]
        );

        // A shell wrapper whose script ALREADY selects ACP is left untouched (the
        // recursive scan sees the inner selector, so nothing is appended/injected).
        let mut already = hire(Protocol::Acp, "sh", "none");
        already.args = vec!["-c".into(), "nano-coder --acp".into()];
        assert_eq!(
            acp_spawn_args(&already),
            vec!["-c".to_string(), "nano-coder --acp".to_string()]
        );
    }

    #[test]
    fn acp_spawn_args_appends_for_non_shell_c_option() {
        // A NON-shell agent whose own `-c` option carries config (not a script)
        // must NOT have the selector injected into that option; it is appended to
        // the outer argv so the agent still receives a top-level `--acp`.
        let mut h = hire(Protocol::Acp, "agent", "none");
        h.args = vec!["-c".into(), "config".into()];
        assert_eq!(
            acp_spawn_args(&h),
            vec!["-c".to_string(), "config".to_string(), "--acp".to_string()]
        );
    }

    #[test]
    fn acp_spawn_args_injects_when_shell_is_behind_a_launch_prefix() {
        // A launch-prefixed outer argv (`command = "env"`, `args = ["sh", "-c",
        // …]`) runs `sh` as the real program. The selector must still be injected
        // INTO the `-c` script, not appended to the outer argv — `env sh -c
        // nano-coder --acp` lets `sh` swallow `--acp` as `$0`, dropping it.
        let mut env_prefixed = hire(Protocol::Acp, "env", "none");
        env_prefixed.args = vec!["sh".into(), "-c".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&env_prefixed),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // `VAR=value` env assignments decorate the command the same way.
        let mut assign_prefixed = hire(Protocol::Acp, "FOO=bar", "none");
        assign_prefixed.args = vec!["bash".into(), "-lc".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&assign_prefixed),
            vec![
                "bash".to_string(),
                "-lc".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // A launch-prefixed NON-shell program is still just appended to — the
        // prefix resolution must not mistake a non-shell for a shell wrapper.
        let mut env_agent = hire(Protocol::Acp, "env", "none");
        env_agent.args = vec!["nano-coder".into(), "-c".into(), "config".into()];
        assert_eq!(
            acp_spawn_args(&env_agent),
            vec![
                "nano-coder".to_string(),
                "-c".to_string(),
                "config".to_string(),
                "--acp".to_string()
            ]
        );
    }

    #[test]
    fn acp_spawn_args_injects_when_shell_is_behind_an_absolute_launch_prefix() {
        // The launch wrapper may be invoked by ABSOLUTE path (`command =
        // "/usr/bin/env"`). Matching only the bare `env` stops at the wrapper, so
        // the `-c` injection is gated off and `--acp` is appended to the outer
        // argv, where POSIX `sh` swallows it as `$0` and the inner agent never
        // sees it. Match the wrapper by basename, as `is_shell_command` already
        // does for absolute shell paths.
        let mut abs_env = hire(Protocol::Acp, "/usr/bin/env", "none");
        abs_env.args = vec!["sh".into(), "-c".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&abs_env),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // Same for the other wrappers behind an absolute path.
        let mut abs_exec = hire(Protocol::Acp, "/usr/bin/exec", "none");
        abs_exec.args = vec!["bash".into(), "-lc".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&abs_exec),
            vec![
                "bash".to_string(),
                "-lc".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // An absolute-path wrapper in front of a NON-shell program is still just
        // appended to — basename matching must not mistake it for a shell.
        let mut abs_env_agent = hire(Protocol::Acp, "/usr/bin/env", "none");
        abs_env_agent.args = vec!["nano-coder".into(), "-c".into(), "config".into()];
        assert_eq!(
            acp_spawn_args(&abs_env_agent),
            vec![
                "nano-coder".to_string(),
                "-c".to_string(),
                "config".to_string(),
                "--acp".to_string()
            ]
        );
    }

    #[test]
    fn acp_spawn_args_injects_when_shell_is_behind_env_options() {
        // `env` carries its OWN options between the wrapper and the real command
        // (`env -i sh -c …`, `env -u FOO sh …`, `env -- sh …`). A scan that stops
        // at the first non-prefix token names `-i` the effective command, gates
        // the `-c` injection off, and appends `--acp` to the outer argv — where
        // POSIX `sh` swallows it as `$0` and the inner agent never sees it. The
        // effective command is the first token past the wrapper's options.
        let mut env_i = hire(Protocol::Acp, "env", "none");
        env_i.args = vec!["-i".into(), "sh".into(), "-c".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&env_i),
            vec![
                "-i".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // `-u` consumes its NAME argument as a separate token.
        let mut env_u = hire(Protocol::Acp, "/usr/bin/env", "none");
        env_u.args = vec![
            "-u".into(),
            "FOO".into(),
            "bash".into(),
            "-lc".into(),
            "nano-coder".into(),
        ];
        assert_eq!(
            acp_spawn_args(&env_u),
            vec![
                "-u".to_string(),
                "FOO".to_string(),
                "bash".to_string(),
                "-lc".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // BSD/macOS `env -P ALTPATH` (the deployment OS) consumes its altpath
        // as a separate token too: treating `-P` as nullary lands the scan on
        // the altpath as the effective command, so the shell is missed and
        // `--acp` is appended to the outer argv where `sh` swallows it as `$0`.
        let mut env_p = hire(Protocol::Acp, "env", "none");
        env_p.args = vec![
            "-P".into(),
            "/alt/bin".into(),
            "sh".into(),
            "-c".into(),
            "nano-coder".into(),
        ];
        assert_eq!(
            acp_spawn_args(&env_p),
            vec![
                "-P".to_string(),
                "/alt/bin".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // `--` ends `env`'s own options; the next token is the command.
        let mut env_ddash = hire(Protocol::Acp, "env", "none");
        env_ddash.args = vec!["--".into(), "sh".into(), "-c".into(), "nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&env_ddash),
            vec![
                "--".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // A glued-on value (`-uFOO`) and a nullary bundle (`-i0`) are one token.
        let mut env_glued = hire(Protocol::Acp, "env", "none");
        env_glued.args = vec![
            "-uFOO".into(),
            "sh".into(),
            "-c".into(),
            "nano-coder".into(),
        ];
        assert_eq!(
            acp_spawn_args(&env_glued),
            vec![
                "-uFOO".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "nano-coder --acp".to_string()
            ]
        );

        // `env` options in front of a NON-shell program still just append — the
        // option skip must not mistake a non-shell for a shell wrapper.
        let mut env_agent = hire(Protocol::Acp, "env", "none");
        env_agent.args = vec![
            "-i".into(),
            "nano-coder".into(),
            "-c".into(),
            "config".into(),
        ];
        assert_eq!(
            acp_spawn_args(&env_agent),
            vec![
                "-i".to_string(),
                "nano-coder".to_string(),
                "-c".to_string(),
                "config".to_string(),
                "--acp".to_string()
            ]
        );
    }

    #[test]
    fn acp_selector_detection_sees_past_env_options() {
        // The selector scan must look past an `env` wrapper's options too, or a
        // pipe hire that hides an ACP selector behind `env -i …` fails open.
        assert!(command_has_acp_selector(
            "env",
            &[
                "-i".into(),
                "sh".into(),
                "-c".into(),
                "nano-coder --acp".into()
            ]
        ));
        assert!(command_has_acp_selector(
            "/usr/bin/env",
            &[
                "-u".into(),
                "FOO".into(),
                "sh".into(),
                "-c".into(),
                "nano-coder --acp".into()
            ]
        ));
        assert!(command_has_acp_selector(
            "env",
            &["--".into(), "claude-code-acp".into()]
        ));
        // A wrapped NON-ACP script behind env options is still accepted.
        assert!(!command_has_acp_selector(
            "env",
            &[
                "-i".into(),
                "sh".into(),
                "-c".into(),
                "nano-coder --pipe".into()
            ]
        ));
        // An `env` option's own value is not a command: `env -u sh copilot` runs
        // `copilot` (the `-u` value `sh` is unset, not executed), so no `-acp`
        // suffix on the real command and no shell `-c` recursion.
        assert!(!command_has_acp_selector(
            "env",
            &["-u".into(), "sh".into(), "copilot".into()]
        ));
        // BSD/macOS `env -P ALTPATH` takes its value as a separate token, so a
        // `-P`-wrapped `*-acp` adapter must still be caught: treating `-P` as
        // nullary names the altpath the effective command and fails the
        // validator OPEN on the deployment OS (issue #275's class).
        assert!(command_has_acp_selector(
            "env",
            &["-P".into(), "/alt/bin".into(), "claude-code-acp".into()]
        ));
        assert!(command_has_acp_selector(
            "env",
            &[
                "-P".into(),
                "/alt/bin".into(),
                "sh".into(),
                "-c".into(),
                "nano-coder --acp".into()
            ]
        ));
        // The `-P` VALUE is not a command either: `env -P /alt/bin copilot`
        // runs `copilot`, so no `-acp` suffix and no shell `-c` recursion.
        assert!(!command_has_acp_selector(
            "env",
            &["-P".into(), "/alt/bin".into(), "copilot".into()]
        ));
        // A glued-on `-P` value (`-P/alt/bin`) is one token.
        assert!(command_has_acp_selector(
            "env",
            &["-P/alt/bin".into(), "claude-code-acp".into()]
        ));
    }

    #[test]
    fn acp_spawn_args_injects_into_innermost_script_behind_env_options() {
        // The inner `-c` script can itself begin with an `env` wrapper carrying
        // options; the injection must descend past them to the innermost command.
        let mut h = hire(Protocol::Acp, "sh", "none");
        h.args = vec!["-c".into(), "env -i bash -c 'nano-coder'".into()];
        assert_eq!(
            acp_spawn_args(&h),
            vec![
                "-c".to_string(),
                "env -i bash -c 'nano-coder --acp'".to_string()
            ]
        );
    }

    #[test]
    fn acp_spawn_args_injects_into_innermost_nested_wrapper() {
        // Nested shell wrappers must receive the selector in the INNERMOST
        // command, re-quoted so it stays one argument — appending to only the
        // outer script lets the inner shell consume `--acp` as `$0`.
        let mut quoted = hire(Protocol::Acp, "sh", "none");
        quoted.args = vec!["-c".into(), "bash -c 'nano-coder'".into()];
        assert_eq!(
            acp_spawn_args(&quoted),
            vec!["-c".to_string(), "bash -c 'nano-coder --acp'".to_string()]
        );

        // An unquoted inner command gains quoting so the appended selector does
        // not leak out as the inner shell's `$0`.
        let mut bare = hire(Protocol::Acp, "sh", "none");
        bare.args = vec!["-c".into(), "bash -c nano-coder".into()];
        assert_eq!(
            acp_spawn_args(&bare),
            vec!["-c".to_string(), "bash -c 'nano-coder --acp'".to_string()]
        );
    }

    #[test]
    fn acp_selector_scan_ignores_non_shell_c_option() {
        // A non-shell agent's `-c` config argument must not be scanned as a shell
        // script, or `agent -c "config --acp"` would be a false positive.
        assert!(!command_has_acp_selector(
            "agent",
            &["-c".into(), "config --acp".into()]
        ));
        // The real shell wrapper is still detected.
        assert!(command_has_acp_selector(
            "sh",
            &["-c".into(), "nano-coder --acp".into()]
        ));
    }

    // A slot that flips the fatal watch (an unleased activation while leasing is
    // enabled, the default) must be reported as fatal so `run` exits non-zero
    // rather than returning a clean drain `Ok(())`.
    #[tokio::test]
    async fn wait_for_signal_reports_slot_requested_fatal() {
        let (tx, _rx) = watch::channel(false);
        tx.send(true).expect("flip fatal watch");
        assert!(
            wait_for_signal(&tx).await,
            "a slot-flipped watch must be reported as a fatal shutdown"
        );
    }

    // A fatal state published *during* the wait — concurrently with (or racing)
    // an operator Ctrl-C/SIGTERM — must still be reported. `select!` returns
    // whichever arm fired, so the function rechecks the watch after waking; this
    // guards that a fatal flip is never masked by the signal arm winning.
    #[tokio::test]
    async fn wait_for_signal_reports_fatal_flipped_during_wait() {
        let (tx, _rx) = watch::channel(false);
        let flipper = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = flipper.send(true);
        });
        assert!(
            wait_for_signal(&tx).await,
            "a fatal state published during the wait must be reported as fatal"
        );
    }
}
