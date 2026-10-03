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
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::sync::watch;

use crate::engine::{self, JobApi};
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
    pub job_api: JobApi,
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
    log(&format!("reading hires from {}", config_path.display()));
    let all = state::read_hires_from(&config_path)?;
    if all.is_empty() {
        bail!(
            "no hires found in {} — hire an agent first (c8ctl nano hire …)",
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

    let (_profile, jobs) = engine::connect(opts.profile.as_deref(), opts.job_api)?;
    let host = short_hostname();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut handles = Vec::new();
    let mut running_hires = 0usize;
    for hire in &selected {
        if let Err(reason) = validate(hire) {
            log(&format!("skipping hire {:?}: {reason}", hire.name));
            continue;
        }
        let job_types = state::job_type_matrix(&hire.rank, &hire.capabilities);
        log(&format!(
            "hire {:?} [{}]: {} slot(s) over job types {:?}",
            hire.name, hire.rank, opts.slots, job_types
        ));
        running_hires += 1;
        for slot_idx in 0..opts.slots {
            let cfg = Arc::new(SlotConfig {
                hire: hire.clone(),
                worker_name: format!("{host}-nanod-{}-{slot_idx}", hire.name),
                job_types: job_types.clone(),
                recovery_window: opts.recovery_window,
                idle_timeout: opts.idle_timeout,
                poll_timeout: opts.poll_timeout,
                clone_timeout: opts.clone_timeout,
                runs_dir: opts.runs_dir.clone(),
                with_lease: opts.with_lease,
                require_lease: opts.with_lease,
                max_jobs: None,
                propagate_job_panic: false,
                keep_runs: false,
            });
            handles.push(tokio::spawn(slot::run(
                jobs.clone(),
                cfg,
                shutdown_rx.clone(),
                shutdown_tx.clone(),
            )));
        }
    }

    if handles.is_empty() {
        bail!("no runnable hires (all were skipped — see the warnings above)");
    }
    log(&format!(
        "daemon up: {} hire(s), {} slot(s) total; waiting for jobs. Ctrl-C to drain.",
        running_hires,
        handles.len()
    ));

    // `wait_for_signal` reports whether a slot flipped the watch for a FATAL
    // misconfiguration (an unleased activation under `--with-lease`) versus an
    // operator Ctrl-C/SIGTERM. We still drain either way, but a fatal shutdown
    // must surface as a non-zero exit (issue: `--with-lease` is documented to
    // fail LOUDLY — returning `Ok(())` made the daemon look like a clean drain).
    let fatal = wait_for_signal(&shutdown_tx).await;
    if fatal {
        log("fatal: a slot could not fence its work under --with-lease (engine not issuing leases); draining and exiting non-zero");
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
    if fatal {
        bail!(
            "daemon shut down because a slot received an unleased activation under --with-lease — \
             the engine is not issuing leases, so the requested fencing is impossible"
        );
    }
    Ok(())
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
    for (i, tok) in tokens.iter().enumerate() {
        let name = tok.trim_matches(|c| c == '"' || c == '\'');
        let (opt, inline_val) = match name.split_once('=') {
            Some((o, v)) => (o, Some(v)),
            None => (name, None),
        };
        if matches!(opt, "acp" | "-acp" | "--acp") {
            return true;
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
        // The `*-acp` adapter suffix identifies the command token only.
        if i == 0 {
            let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
            if base.ends_with("-acp") {
                return true;
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
pub(crate) fn acp_spawn_args(hire: &Hire) -> Vec<String> {
    let mut args = hire.args.clone();
    if !command_has_acp_selector(&hire.command, &args) {
        args.push("--acp".to_string());
    }
    args
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
/// `fatal` watch — an unrecoverable misconfiguration (e.g. an unleased activation
/// under `--with-lease`) that must exit loudly — and `false` for an operator
/// Ctrl-C/SIGTERM drain. The caller distinguishes the two so a fatal shutdown
/// surfaces as a non-zero exit rather than a clean `Ok(())`.
pub(crate) async fn wait_for_signal(fatal: &watch::Sender<bool>) -> bool {
    // Also wake if a slot flips the shutdown watch (a fatal misconfiguration,
    // e.g. an unleased activation under --with-lease), so the daemon exits loudly
    // rather than lingering with the offending slot stopped.
    let mut fatal_rx = fatal.subscribe();
    let slot_requested = async {
        let _ = fatal_rx.wait_for(|stop| *stop).await;
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                return tokio::select! {
                    _ = tokio::signal::ctrl_c() => false,
                    _ = slot_requested => true,
                };
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => false,
            _ = term.recv() => false,
            _ = slot_requested => true,
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => false,
            _ = slot_requested => true,
        }
    }
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

    // A slot that flips the fatal watch (an unleased activation under
    // `--with-lease`) must be reported as fatal so `run` exits non-zero rather
    // than returning a clean drain `Ok(())`.
    #[tokio::test]
    async fn wait_for_signal_reports_slot_requested_fatal() {
        let (tx, _rx) = watch::channel(false);
        tx.send(true).expect("flip fatal watch");
        assert!(
            wait_for_signal(&tx).await,
            "a slot-flipped watch must be reported as a fatal shutdown"
        );
    }
}
