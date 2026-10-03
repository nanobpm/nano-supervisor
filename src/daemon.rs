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
/// name is the first token PAST any such prefix.
fn is_launch_prefix(t: &str) -> bool {
    let t = t.trim_matches(|c| c == '"' || c == '\'');
    matches!(t, "exec" | "command" | "builtin" | "env")
        || (!t.starts_with('-')
            && t.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }))
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
    // The command token is the first token that is not a launch prefix: leading
    // `exec`/`command`/`builtin`/`env` wrappers and `VAR=value` env assignments
    // only re-exec or decorate the real command (`sh -c "exec claude-code-acp"`,
    // `sh -c "env X=1 claude-code-acp"`), so the `*-acp` suffix check must look
    // past them instead of gating on the literal first token.
    let command_pos = tokens.iter().position(|t| !is_launch_prefix(t));
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
                let sub: Vec<&str> = script
                    .trim_matches(|c| c == '"' || c == '\'')
                    .split_whitespace()
                    .collect();
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
    let command = hire.command.split_whitespace().next().unwrap_or("");
    if is_shell_command(command) {
        if let Some(i) = shell_script_arg_index(&args) {
            args[i] = inject_selector_into_script(&args[i]);
            return args;
        }
    }
    args.push("--acp".to_string());
    args
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
    let command_pos = toks.iter().position(|t| !is_launch_prefix(&t.text));
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

/// Split a shell script string into whitespace-separated tokens, treating a
/// leading `'`/`"` quote as spanning to its matching close quote (so a quoted
/// inner script with spaces stays one token). Good enough for the simple hire
/// command lines this handles; it is not a full shell parser.
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
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let q = bytes[i];
            i += 1;
            let content_start = i;
            while i < s.len() && bytes[i] != q {
                i += 1;
            }
            let content_end = i;
            if i < s.len() {
                i += 1; // consume closing quote
            }
            toks.push(ScriptToken {
                text: s[content_start..content_end].to_string(),
                start,
                end: i,
            });
        } else {
            while i < s.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            toks.push(ScriptToken {
                text: s[start..i].to_string(),
                start,
                end: i,
            });
        }
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
