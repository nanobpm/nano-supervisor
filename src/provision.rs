//! Minimum repository provisioning: clone the envelope's repository into the
//! job's workspace so the agent runs inside a real checkout.
//!
//! This is the MVP slice — clone (honouring depth / single-branch / filter /
//! submodules / branch), optionally check out a pinned commit, and best-effort
//! fetch a base ref so `git diff base...HEAD` works. Push/finalize is a later
//! issue; the agent (or a future finalize step) owns committing and pushing.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use crate::envelope::Repository;

/// Clone `repo` into `<workdir>/repo` and return the checkout path. `default_timeout`
/// caps each git invocation (overridden per-repo by `cloneTimeoutMs`).
pub async fn provision(
    repo: &Repository,
    workdir: &Path,
    default_timeout: Duration,
) -> Result<PathBuf> {
    if repo.url.trim().is_empty() {
        bail!("repository has no url to clone");
    }
    if let Some(sha) = &repo.sha {
        if !is_hex_sha(sha) {
            bail!("invalid repository.sha {sha:?} — expected a 7–40 char hex commit id");
        }
    }
    let timeout = repo
        .clone_timeout_ms
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(default_timeout);

    let workspace = workdir.join("repo");
    let mut args: Vec<String> = vec!["clone".into(), "--no-tags".into()];
    if let Some(depth) = repo.depth.filter(|&d| d > 0) {
        args.push("--depth".into());
        args.push(depth.to_string());
    }
    if repo.single_branch {
        args.push("--single-branch".into());
    }
    if let Some(filter) = &repo.filter {
        args.push(format!("--filter={filter}"));
    }
    if repo.submodules {
        args.push("--recurse-submodules".into());
    }
    // `ref` is always a branch/tag name (there is no hex heuristic); a pinned
    // commit is checked out below via `sha`.
    if let Some(branch) = &repo.ref_ {
        args.push("--branch".into());
        args.push(branch.clone());
    }
    // `--` terminates git's option parsing so a job-supplied `repo.url` (or
    // workspace path) beginning with `-` can never be mistaken for a clone
    // option (e.g. `--upload-pack`).
    args.push("--".into());
    args.push(repo.url.clone());
    args.push(workspace.to_string_lossy().into_owned());

    git(&args, None, timeout)
        .await
        .context("git clone failed")?;

    if let Some(sha) = &repo.sha {
        // The commit may be absent under a shallow clone: fetch it, then check
        // it out detached.
        let _ = git(
            &[
                "fetch".into(),
                "--no-tags".into(),
                "origin".into(),
                "--".into(),
                sha.clone(),
            ],
            Some(&workspace),
            timeout,
        )
        .await;
        git(
            &["checkout".into(), "--detach".into(), sha.clone()],
            Some(&workspace),
            timeout,
        )
        .await
        .with_context(|| format!("git checkout {sha} failed"))?;
    }

    // Best-effort base fetch so a single-branch/shallow checkout can still diff
    // against its base. A failure here is not fatal — the head clone succeeded.
    if let Some(base) = repo.base_sha.as_ref().or(repo.base_ref.as_ref()) {
        let _ = git(
            &[
                "fetch".into(),
                "--no-tags".into(),
                "origin".into(),
                // `--` terminates option parsing so a job-supplied base ref
                // beginning with `-` (e.g. `--upload-pack=…`) can never be read
                // as a `git fetch` option, mirroring the `git clone` URL guard.
                "--".into(),
                base.clone(),
            ],
            Some(&workspace),
            timeout,
        )
        .await;
    }

    Ok(workspace)
}

fn is_hex_sha(s: &str) -> bool {
    let n = s.len();
    (7..=40).contains(&n) && s.chars().all(|c| c.is_ascii_hexdigit())
}

async fn git(args: &[String], cwd: Option<&Path>, timeout: Duration) -> Result<()> {
    use std::process::Stdio;
    let mut cmd = Command::new("git");
    cmd.args(args);
    // Kill (and reap) the git child if this future is dropped — e.g. when the
    // timeout below fires — so a timed-out clone/fetch can't keep running and
    // mutate the workspace while a retry starts.
    cmd.kill_on_drop(true);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    // Never prompt for credentials interactively (would hang the slot).
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Give git the same parent-death/process-group cleanup as agent children.
    // `kill_on_drop` only runs on a graceful daemon shutdown; a `kill -9` of the
    // daemon mid-clone would otherwise orphan git (and any transport/credential
    // helper it spawned), which could keep mutating the run directory while the
    // job is redelivered. Its own process group + PDEATHSIG/watchdog tears the
    // whole git tree down with the daemon.
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(unix)]
    crate::pdeath::arm(&mut cmd);
    let child = cmd.spawn().context("spawning git")?;
    #[cfg(unix)]
    let gpid = child.id();
    #[cfg(unix)]
    if let Some(pid) = gpid {
        crate::pdeath::watch(pid);
    }
    // Cancellation cleanup: if this future is dropped mid-clone/fetch (e.g. the
    // slot aborts `execute` on lease loss), the `wait_with_output` future — and
    // the `child` it owns — is dropped, but `kill_on_drop` reaps only the direct
    // git leader; transports / credential helpers it spawned share git's process
    // group and would leak, still mutating the run directory while the job is
    // redelivered. The guard SIGKILLs the whole git group on drop. Disarmed once
    // git has completed (or we have already killed the group on timeout), so a
    // recycled pid is never re-signalled.
    #[cfg(unix)]
    let mut group_guard = crate::pdeath::GroupGuard::new(gpid);
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(res) => {
            #[cfg(unix)]
            group_guard.disarm();
            res.context("collecting git output")?
        }
        Err(_) => {
            // Timed out: SIGKILL the whole group (not just the leader that
            // `kill_on_drop` reaps) so a helper git spawned cannot outlive it.
            #[cfg(unix)]
            if let Some(pid) = gpid {
                crate::pdeath::sigkill_group(pid);
            }
            #[cfg(unix)]
            group_guard.disarm();
            bail!(
                "git {} timed out after {}s",
                args.first().map(String::as_str).unwrap_or(""),
                timeout.as_secs()
            );
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git {} exited with {}: {}",
            args.first().map(String::as_str).unwrap_or(""),
            output.status,
            stderr.chars().take(500).collect::<String>()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_sha_validation() {
        assert!(is_hex_sha("deadbeef"));
        assert!(is_hex_sha("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_hex_sha("xyz"));
        assert!(!is_hex_sha("short"));
        assert!(!is_hex_sha("0123456789abcdef0123456789abcdef012345678")); // 41 chars
    }
}
