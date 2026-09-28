//! Pipe-protocol agent runner: feed the agent a single JSON job payload on
//! stdin, let it work in `cwd`, and capture its stdout/stderr. The agent
//! reports its result by writing `$AGENT_RESULT_FILE` or by printing a
//! `::nano:result:: {json}` sentinel line (parsed by [`crate::result`]).
//!
//! Like the ACP client, the agent runs in its own process group (so a timeout
//! kills the whole tree) and dies with the daemon via [`crate::pdeath`].

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// What a pipe run produced.
#[derive(Debug, Default)]
pub struct PipeOutcome {
    pub stdout: String,
    pub exit_code: Option<i32>,
    /// True when the run was cut short because the agent produced no output for
    /// longer than the idle timeout.
    pub idle_timed_out: bool,
}

/// Spawn `program args…` in `cwd` with `env`, write `stdin_json` to its stdin,
/// and collect stdout until the agent exits or goes idle for `idle`.
pub async fn run(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    stdin_json: &str,
    idle: Duration,
) -> Result<PipeOutcome> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(unix)]
    crate::pdeath::arm(&mut cmd);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("starting agent {program:?}"))?;
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        crate::pdeath::watch(pid);
    }

    // Deliver the whole payload, then close stdin so the agent sees EOF.
    if let Some(mut stdin) = child.stdin.take() {
        let payload = stdin_json.to_string();
        tokio::spawn(async move {
            let _ = stdin.write_all(payload.as_bytes()).await;
            let _ = stdin.write_all(b"\n").await;
            let _ = stdin.shutdown().await;
        });
    }

    let stdout = child.stdout.take().context("agent stdout")?;
    // Read raw fixed-size chunks rather than whole lines: a line reader buffers
    // an entire line before yielding, so one very large unterminated line could
    // exhaust memory before the cap is applied. Chunked reads let `bound_capture`
    // run continuously and hold `collected` to `MAX_STDOUT` regardless of how the
    // agent frames (or fails to frame) its output.
    let mut reader = BufReader::new(stdout);
    let mut buf = [0u8; 64 * 1024];
    let mut collected = String::new();
    let mut last_activity = Instant::now();
    let mut idle_timed_out = false;

    let exit_code = loop {
        tokio::select! {
            n = reader.read(&mut buf) => match n {
                Ok(0) | Err(_) => {
                    // stdout closed (EOF) or errored: wait for the process to reap.
                    let status = child.wait().await.ok();
                    break status.and_then(|s| s.code());
                }
                Ok(n) => {
                    last_activity = Instant::now();
                    // Lossy is safe here: the `::nano:result::` sentinel is ASCII,
                    // so it survives chunk boundaries exactly; only split multibyte
                    // prose (a diagnostic fallback channel) may gain replacements.
                    collected.push_str(&String::from_utf8_lossy(&buf[..n]));
                    bound_capture(&mut collected);
                }
            },
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if last_activity.elapsed() > idle {
                    idle_timed_out = true;
                    break None;
                }
            }
        }
    };

    // Kill the whole process group (agent + any tools it started), then reap.
    kill_tree(&mut child).await;

    Ok(PipeOutcome {
        stdout: collected,
        exit_code,
        idle_timed_out,
    })
}

/// Upper bound on captured agent output. The result is delivered out-of-band via
/// `$AGENT_RESULT_FILE`; captured stdout / the ACP transcript is only a fallback
/// channel for the trailing `::nano:result::` sentinel, so a noisy or adversarial
/// agent must not be able to grow it without limit and exhaust the daemon's
/// memory. Shared with the ACP path ([`crate::acp`]).
pub(crate) const MAX_STDOUT: usize = 1 << 20; // 1 MiB

/// Keep `collected` within [`MAX_STDOUT`] by dropping from the front (oldest
/// output) once it overflows. Retaining the tail preserves a trailing
/// `::nano:result::` sentinel for result parsing.
pub(crate) fn bound_capture(collected: &mut String) {
    if collected.len() <= MAX_STDOUT {
        return;
    }
    let overflow = collected.len() - MAX_STDOUT;
    // Advance to a char boundary at or past the overflow so we never split a
    // UTF-8 code point.
    let mut cut = overflow;
    while cut < collected.len() && !collected.is_char_boundary(cut) {
        cut += 1;
    }
    collected.replace_range(..cut, "");
}

async fn kill_tree(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // Negative pid = the whole process group.
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &format!("-{pid}")])
            .status();
    }
    let _ = child.start_kill();
    // Best-effort reap so we don't leak a zombie.
    let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_capture_keeps_tail_within_limit() {
        let mut s = "x".repeat(MAX_STDOUT + 1000);
        s.push_str("::nano:result:: {}\n");
        bound_capture(&mut s);
        assert!(s.len() <= MAX_STDOUT);
        // The trailing sentinel (what result parsing needs) is retained.
        assert!(s.ends_with("::nano:result:: {}\n"));
    }

    #[test]
    fn bound_capture_leaves_small_output_untouched() {
        let mut s = "hello\nworld\n".to_string();
        bound_capture(&mut s);
        assert_eq!(s, "hello\nworld\n");
    }
}
