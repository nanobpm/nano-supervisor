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
    // Lift any `user:token@` credential out of the URL so it is delivered to git
    // out of band (via the credential helper in `git()`) instead of embedded in
    // argv, where it would sit in world-readable `/proc/<git-pid>/cmdline` for
    // the life of every clone/fetch. `fetch_url` (credential-free) is what goes
    // on the command line; the same handle authenticates the clone and both
    // fetches below.
    let (fetch_url, cred) = split_url_credential(&repo.url);
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
    args.push(fetch_url.clone());
    args.push(workspace.to_string_lossy().into_owned());

    if let Err(e) = git(&args, None, timeout, cred.as_ref()).await {
        // A failed clone can still leave a *partially populated* checkout — most
        // notably a `--recurse-submodules` clone whose submodule step failed
        // after the superproject was created — with the credential-bearing URL
        // already written into `<workspace>/.git/config` (and any nested
        // submodule configs). This early return would otherwise leave that token
        // on disk. Remove the whole partial checkout before propagating so no
        // failure path leaves credentials behind.
        remove_partial_checkout(&workspace).await;
        return Err(e).context("git clone failed");
    }

    // `git clone` now runs with a credential-free `fetch_url` in argv, so the
    // persisted `<workspace>/.git/config` origin already carries no `user:token@`
    // userinfo. This rewrite is kept as defense in depth — it re-canonicalises
    // the origin to the scrubbed URL right after the clone (a no-op when the URL
    // carried no credentials), so even if a future change reintroduced a
    // credential-bearing clone URL the agent could never read the PAT from the
    // persisted config. The clone and both fetches below authenticate via the
    // out-of-band credential helper (see `git()`), so the token is never written
    // to config or placed in argv.
    let scrubbed_origin = scrub_url_credentials(&repo.url);
    if let Err(e) = git(
        &[
            "remote".into(),
            "set-url".into(),
            "origin".into(),
            "--".into(),
            scrubbed_origin,
        ],
        Some(&workspace),
        timeout,
        None,
    )
    .await
    {
        // The scrub itself failed, so the credential-bearing origin is still
        // persisted in the checkout config. Remove the whole checkout rather
        // than leaving the token on disk.
        remove_partial_checkout(&workspace).await;
        return Err(e).context("scrubbing persisted clone credentials failed");
    }

    // A `--recurse-submodules` clone also persists each submodule's
    // (possibly credential-bearing) remote URL into `<workspace>/.git/modules/**/config`.
    // The top-level `origin` scrub above does not touch those nested configs, so
    // an agent with read access to the checkout could exfiltrate the PAT from
    // them even though `origin` is clean. Scrub every nested submodule config
    // before returning the workspace.
    if repo.submodules {
        if let Err(e) = scrub_submodule_config_credentials(&workspace) {
            remove_partial_checkout(&workspace).await;
            return Err(e).context("scrubbing submodule clone credentials failed");
        }
    }

    if let Some(sha) = &repo.sha {
        // The commit may be absent under a shallow clone: fetch it, then check
        // it out detached. Fetch against the credential-free `fetch_url` and let
        // the out-of-band credential helper (see `git()`) authenticate — so the
        // token never lands in argv or in the scrubbed-`origin` config. `--`
        // terminates option parsing so neither the URL nor the sha can be read
        // as a git option.
        let _ = git(
            &[
                "fetch".into(),
                "--no-tags".into(),
                "--".into(),
                fetch_url.clone(),
                sha.clone(),
            ],
            Some(&workspace),
            timeout,
            cred.as_ref(),
        )
        .await;
        // `git fetch` still records the (now credential-free) source URL in
        // `<workspace>/.git/FETCH_HEAD`; the scrub is retained as defense in
        // depth before the (fallible) checkout below can return.
        if let Err(e) = scrub_fetch_head(&workspace) {
            remove_partial_checkout(&workspace).await;
            return Err(e).context("scrubbing fetch metadata credentials failed");
        }
        git(
            &["checkout".into(), "--detach".into(), sha.clone()],
            Some(&workspace),
            timeout,
            None,
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
                // Fetch against the credential-free `fetch_url`; the out-of-band
                // credential helper (see `git()`) supplies the token so a private
                // base still authenticates without the secret ever reaching argv
                // (world-readable `/proc/<pid>/cmdline`) or the scrubbed origin.
                // `--` terminates option parsing so neither the URL nor a
                // job-supplied base ref beginning with `-` (e.g.
                // `--upload-pack=…`) can be read as a `git fetch` option,
                // mirroring the `git clone` URL guard.
                "--".into(),
                fetch_url.clone(),
                base.clone(),
            ],
            Some(&workspace),
            timeout,
            cred.as_ref(),
        )
        .await;
    }

    // The base fetch above (like the sha fetch) records its source URL in
    // `.git/FETCH_HEAD`. It is credential-free now that the token is delivered
    // out of band, but the scrub is kept as defense in depth before handing the
    // workspace to the agent so no fetch path can ever leave a token on disk.
    if let Err(e) = scrub_fetch_head(&workspace) {
        remove_partial_checkout(&workspace).await;
        return Err(e).context("scrubbing fetch metadata credentials failed");
    }

    Ok(workspace)
}

/// Best-effort removal of a partially provisioned checkout after a git step
/// failed. The checkout config may still hold a credential-bearing remote URL
/// (see the clone/scrub failure paths above), so it must not be left on disk. A
/// removal error is deliberately ignored — the checkout may not exist yet, and
/// there is nothing more to do about a filesystem failure here beyond the caller
/// already propagating the original git error.
async fn remove_partial_checkout(workspace: &Path) {
    if tokio::fs::try_exists(workspace).await.unwrap_or(false) {
        let _ = tokio::fs::remove_dir_all(workspace).await;
    }
}

/// Strip `user:token@` credentials from every submodule's persisted remote
/// config after a `--recurse-submodules` clone. Git writes each submodule's
/// remote URL (which, for a credential-bearing superproject, resolves to a
/// credential-bearing URL) into `<workspace>/.git/modules/**/config`; the
/// top-level `origin` scrub does not reach those nested configs. Walk every
/// `config` file under `.git/modules` and rewrite any embedded credential URL to
/// its credential-free form, so no token is left on disk for the agent to read.
/// The superproject's own top-level `<workspace>/.git/config` is scrubbed too,
/// since `submodule init` copies each submodule URL into a `submodule.<name>.url`
/// entry there that the `origin` scrub does not reach.
///
/// Directory recursion uses `file_type()` (which does not follow symlinks), so a
/// symlinked entry is never traversed into, and each `config` rewrite goes
/// through an atomic no-follow open (`scrub_file_credentials_in_place`) so a
/// symlink planted at the leaf between the `file_type()` check and the write
/// cannot redirect the scrub outside the checkout. Errors are propagated so the
/// caller can remove the whole checkout rather than return one that may still
/// hold a token.
fn scrub_submodule_config_credentials(workspace: &Path) -> Result<()> {
    let modules = workspace.join(".git").join("modules");
    // Resolve the root with `symlink_metadata` (which does NOT follow symlinks):
    // `exists()` follows links, so a symlink planted at `.git/modules` would be
    // traversed into and `read_dir` could walk — and rewrite — files outside the
    // checkout. A genuine `--recurse-submodules` clone always creates
    // `.git/modules` as a real directory, so treat anything else (a symlink, a
    // regular file, or an absent path) as "nothing to scrub" and never traverse
    // it. Descendants are already guarded by the per-entry `file_type()` checks
    // below, which are likewise symlink-safe.
    match std::fs::symlink_metadata(&modules) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", modules.display())),
    }
    // `git submodule init` (run by `--recurse-submodules`) also copies each
    // submodule's remote URL into a top-level `submodule.<name>.url` entry in the
    // superproject's own `<workspace>/.git/config`, which the `origin` set-url
    // scrub does not touch. Scrub it too so no persisted submodule URL source is
    // left behind (defense in depth — the token is supplied out of band and is
    // never written here, symmetric with the origin and nested-module scrubs).
    scrub_file_credentials_in_place(&workspace.join(".git").join("config"))?;
    let mut stack = vec![modules];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("reading an entry in {}", dir.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("stat {}", path.display()))?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && entry.file_name() == "config" {
                scrub_file_credentials_in_place(&path)?;
            }
        }
    }
    Ok(())
}

/// Strip `user:token@` credentials from `<workspace>/.git/FETCH_HEAD`, which git
/// populates with the (credential-bearing) source URL of every `git fetch`. The
/// top-level `origin` scrub leaves that file untouched, so a private-repo fetch
/// would leave the PAT readable in the checkout the agent receives. Rewrite any
/// embedded credential URL to its credential-free form in place.
///
/// Symlink-safe: the rewrite goes through an atomic no-follow open
/// (`scrub_file_credentials_in_place`), so a symlink planted at `.git/FETCH_HEAD`
/// between any check and the write is never followed and cannot redirect the
/// write outside the checkout. A missing or non-regular file is a no-op.
fn scrub_fetch_head(workspace: &Path) -> Result<()> {
    let fetch_head = workspace.join(".git").join("FETCH_HEAD");
    scrub_file_credentials_in_place(&fetch_head)
}

/// Rewrite `path` in place with any embedded git credentials scrubbed, holding
/// the checked inode open for the whole read-modify-write so a symlink planted at
/// `path` between an earlier `file_type()`/`symlink_metadata` check and this
/// rewrite cannot redirect the write outside the checkout (a TOCTOU that a
/// separate `symlink_metadata`-then-`std::fs::write` pair leaves open).
///
/// On unix the leaf is opened `O_NOFOLLOW` (a swapped-in symlink fails the open
/// with `ELOOP`) and `O_NONBLOCK` (the leaf is attacker-plantable, so it could be
/// a FIFO whose open would otherwise block the worker thread — special files are
/// then rejected by the regular-file guard). On other platforms a symlink is
/// rejected explicitly (best-effort; such targets are not supported daemon
/// hosts). A missing or non-regular file is a no-op.
fn scrub_file_credentials_in_place(path: &Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true);
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        match opts.open(path) {
            Ok(f) => f,
            // ENOENT: nothing to scrub. ELOOP: the leaf is a symlink (someone
            // planted one) — skip it rather than follow it outside the checkout.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ELOOP) =>
            {
                return Ok(());
            }
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        }
    };
    #[cfg(not(unix))]
    let mut file = {
        // No atomic no-follow open here: reject a symlink explicitly so the
        // documented no-symlink guarantee still holds.
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?
    };

    // Only rewrite a real regular file; a FIFO/device/dir opened above is skipped
    // so the read below can never block or misbehave on a special file.
    let meta = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.file_type().is_file() {
        return Ok(());
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("reading {}", path.display()))?;
    let scrubbed = scrub_url_credentials(&contents);
    if scrubbed != contents {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("seeking {}", path.display()))?;
        file.set_len(0)
            .with_context(|| format!("truncating {}", path.display()))?;
        file.write_all(scrubbed.as_bytes())
            .with_context(|| format!("rewriting {}", path.display()))?;
    }
    Ok(())
}

fn is_hex_sha(s: &str) -> bool {
    let n = s.len();
    (7..=40).contains(&n) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Credentials lifted out of a remote URL so they are handed to git *out of
/// band* rather than embedded in its argv. A `user:token@` URL passed on the
/// command line leaves the token in `/proc/<git-pid>/cmdline`, which is
/// world-readable on a default Linux host, so any local process can read the
/// PAT for the lifetime of the clone/fetch — scrubbing the on-disk
/// `origin`/`FETCH_HEAD` afterward does not close that live exposure. Supplying
/// the secret through git's credential-helper protocol keeps it in the child's
/// environment (`/proc/<pid>/environ`, readable only by the owning user)
/// instead.
struct GitCredential {
    /// Host (without port) the credential is scoped to, so the helper never
    /// hands the token to a differently-hosted submodule remote.
    host: String,
    username: String,
    password: String,
}

/// Split a remote URL into `(url_for_argv, credential)`: the returned URL has
/// any `user:secret@` userinfo removed (safe to place in argv), and the
/// credential — when the URL carried one — is returned separately for
/// out-of-band delivery via [`git`]'s credential helper.
///
/// The userinfo is split on its first `:` into username/password; a userinfo
/// with no `:` (the `https://<token>@host` token-as-username form) becomes the
/// username with an empty password, mirroring how git itself would interpret
/// the original URL. A credential-free URL yields `(url, None)` and is returned
/// byte-for-byte unchanged.
fn split_url_credential(url: &str) -> (String, Option<GitCredential>) {
    let sanitized = scrub_url_credentials(url);
    // Only the `scheme://[userinfo@]authority…` form carries an embeddable
    // credential; anything else (or a URL the scrub left untouched) has none.
    let Some(pos) = url.find("://") else {
        return (sanitized, None);
    };
    let after = pos + 3;
    let tail = &url[after..];
    let auth_end = tail
        .find(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace())
        .unwrap_or(tail.len());
    let authority = &tail[..auth_end];
    let Some(at) = authority.rfind('@') else {
        return (sanitized, None);
    };
    let userinfo = &authority[..at];
    let hostport = &authority[at + 1..];
    // `hostport` is already past the last `@`, so it is `host[:port]`; scope the
    // credential on the bare host (git's `host` request field omits a default
    // port, and we strip any explicit `:port` before comparing).
    let host = hostport.split(':').next().unwrap_or(hostport).to_string();
    let (username, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (userinfo.to_string(), String::new()),
    };
    if host.is_empty() || username.is_empty() {
        // Nothing usable to scope/authenticate with — fall back to the sanitized
        // URL alone (git will consult its own credential machinery as before).
        return (sanitized, None);
    }
    (
        sanitized,
        Some(GitCredential {
            host,
            username,
            password,
        }),
    )
}

/// Strip `user:secret@` userinfo from every `scheme://…@authority` occurrence in
/// arbitrary text (such as a git stderr tail). Git can echo a credential-bearing
/// remote URL in its diagnostics, and that text is propagated into job-failure
/// and daemon logs, so any embedded PAT must be removed before it is logged.
/// Non-URL text (and credential-free URLs) is returned unchanged.
fn scrub_url_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("://") {
        let after = pos + 3;
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        // The authority runs until the first character that cannot be part of it
        // (path/query/fragment separators or any whitespace/quoting that ends the
        // URL inside surrounding prose).
        let auth_end = tail
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '|' | '\\' | '`')
                    || c.is_whitespace()
            })
            .unwrap_or(tail.len());
        let authority = &tail[..auth_end];
        match authority.rfind('@') {
            Some(at) => out.push_str(&authority[at + 1..]),
            None => out.push_str(authority),
        }
        rest = &tail[auth_end..];
    }
    out.push_str(rest);
    out
}

async fn git(
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
    cred: Option<&GitCredential>,
) -> Result<()> {
    use std::process::Stdio;
    let mut cmd = Command::new("git");
    // A credential is delivered out of band via git's credential-helper
    // protocol so the secret never reaches argv (world-readable
    // `/proc/<pid>/cmdline`). The helper snippet itself is not secret — it only
    // names env vars — and is host-scoped so a `--recurse-submodules` fetch to a
    // different host is never handed this repo's token. The empty
    // `credential.helper=` first resets any host/global helper so ours is the
    // only one consulted. These `-c` flags must precede the git subcommand.
    if let Some(c) = cred {
        // Read the request on stdin (draining it), emit the credential only for
        // a `get` on the matching host, and ignore `store`/`erase`.
        let helper = "!f() { \
            test \"$1\" = get || exit 0; \
            h=; \
            while IFS='=' read -r k v; do test x\"$k\" = xhost && h=${v%%:*}; done; \
            test x\"$h\" = x\"$NANO_GIT_CRED_HOST\" || exit 0; \
            printf 'username=%s\\npassword=%s\\n' \"$NANO_GIT_CRED_USER\" \"$NANO_GIT_CRED_PASS\"; \
        }; f";
        cmd.arg("-c").arg("credential.helper=");
        cmd.arg("-c").arg(format!("credential.helper={helper}"));
        cmd.env("NANO_GIT_CRED_HOST", &c.host);
        cmd.env("NANO_GIT_CRED_USER", &c.username);
        cmd.env("NANO_GIT_CRED_PASS", &c.password);
    }
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
    // Strip the daemon's own engine-connection secrets from the inherited
    // environment before spawning git, exactly as the ACP/pipe launch sites do:
    // git runs job-controlled remote URLs and credential/remote helpers, so a
    // hostile repo config or helper could otherwise read `CAMUNDA_*`/`ZEEBE_*`
    // client secrets and basic-auth passwords straight out of the environment.
    for k in crate::slot::SENSITIVE_DAEMON_ENV {
        cmd.env_remove(k);
    }
    cmd.stdin(Stdio::null())
        // stdout is never consumed (git() returns `()`); discard it so a
        // job-controlled remote can't exhaust memory by flooding it.
        .stdout(Stdio::null())
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
    let mut child = cmd.spawn().context("spawning git")?;
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
    // Drain git's stderr to EOF while retaining only a bounded tail: the pipe is
    // always read so git never blocks on a full buffer, but a job-controlled
    // repository/remote helper emitting unbounded progress/diagnostics can't grow
    // this without limit and exhaust the daemon. stdout is discarded (`null`)
    // above; only a short stderr tail is ever needed for the error message.
    let stderr = child.stderr.take();
    let wait = async {
        let drain = async {
            match stderr {
                Some(e) => drain_capped(e, GIT_STDERR_TAIL).await,
                None => Vec::new(),
            }
        };
        tokio::join!(child.wait(), drain)
    };
    let (status, stderr_tail) = match tokio::time::timeout(timeout, wait).await {
        Ok(res) => {
            // git finished within the timeout, but a credential/remote helper it
            // spawned can outlive the leader while sharing git's process group
            // (`child.wait()` reaped only the direct git leader). Tear the whole
            // group down before disarming the guard — mirroring the ACP and pipe
            // paths — so a lingering helper can't keep mutating the run directory
            // after provisioning "succeeds". `terminate_group_and_reap` gates on
            // `group_alive`, so this is a no-op when git left nothing behind and
            // never re-signals a pid that may have been recycled.
            #[cfg(unix)]
            {
                crate::pdeath::terminate_group_and_reap(&mut child, gpid, Duration::from_secs(3))
                    .await;
                group_guard.disarm();
            }
            res
        }
        Err(_) => {
            // Timed out: SIGKILL the whole group (not just the leader that
            // `kill_on_drop` reaps) so a helper git spawned cannot outlive it.
            // Re-probe `group_alive` immediately before signalling — mirroring
            // `terminate_group_and_reap` and the success path above: the `wait`
            // future (and its `child.wait()`) is dropped when the timeout fires,
            // so if git and every descendant exited in that interval the pgid can
            // be released and recycled by an unrelated group before this call.
            // Only signal while the group is genuinely still present, so a timeout
            // never SIGKILLs a recycled pid — upholding the guard's guarantee.
            #[cfg(unix)]
            if let Some(pid) = gpid {
                if crate::pdeath::group_alive(pid) {
                    crate::pdeath::sigkill_group(pid);
                }
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
    let status = status.context("waiting for git")?;
    if !status.success() {
        // Show the *last* 500 chars of the retained tail — a git failure message
        // (e.g. `fatal: …`) lands at the very end of stderr.
        let stderr = String::from_utf8_lossy(&stderr_tail);
        let chars: Vec<char> = stderr.chars().collect();
        let start = chars.len().saturating_sub(500);
        let tail: String = chars[start..].iter().collect();
        // Git can echo a credential-bearing remote URL in its fatal diagnostics
        // (e.g. `unable to access 'https://user:pat@host/...'`); this tail is
        // propagated into the job-failure/daemon logs, so scrub any embedded
        // userinfo before including it.
        let tail = scrub_url_credentials(&tail);
        bail!(
            "git {} exited with {}: {}",
            args.first().map(String::as_str).unwrap_or(""),
            status,
            tail
        );
    }
    Ok(())
}

/// Bytes of a child stream's *tail* retained for diagnostics. The stream is
/// still drained fully; only the last `GIT_STDERR_TAIL` bytes are kept.
const GIT_STDERR_TAIL: usize = 8 * 1024;

/// Read `reader` to EOF, retaining only its last `cap` bytes. Always consumes the
/// whole stream (so the writer never blocks on a full pipe) while bounding memory
/// to `cap` regardless of how much a job-controlled process emits.
async fn drain_capped<R>(mut reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    let excess = buf.len() - cap;
                    buf.drain(..excess);
                }
            }
        }
    }
    buf
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

    #[test]
    fn scrub_credentials_from_git_stderr() {
        // A credential-bearing URL echoed in a git diagnostic is redacted.
        let line = "fatal: unable to access 'https://x-access-token:ghp_SECRET@github.com/org/repo.git/': The requested URL returned error: 403";
        let scrubbed = scrub_url_credentials(line);
        assert!(!scrubbed.contains("ghp_SECRET"));
        assert!(!scrubbed.contains("x-access-token"));
        assert!(scrubbed.contains("https://github.com/org/repo.git/"));
        assert!(scrubbed.contains("error: 403"));
        // Credential-free URLs and plain text are left untouched.
        assert_eq!(
            scrub_url_credentials("cloning https://github.com/org/repo.git now"),
            "cloning https://github.com/org/repo.git now"
        );
        assert_eq!(scrub_url_credentials("no url here"), "no url here");
    }

    #[test]
    fn origin_scrub_strips_clone_url_credentials() {
        // The URL rewritten into `remote.origin.url` after a credential-bearing
        // clone must never retain the PAT, while a credential-free URL is left
        // byte-for-byte unchanged (so the rewrite is a harmless no-op). Build the
        // userinfo at runtime so no credential-like literal is stored in source.
        let token = "x-access-token:s3cr3t";
        let with_creds = format!("https://{token}@github.com/org/repo.git");
        let scrubbed = scrub_url_credentials(&with_creds);
        assert!(!scrubbed.contains("s3cr3t"));
        assert!(!scrubbed.contains('@'));
        assert_eq!(scrubbed, "https://github.com/org/repo.git");
        assert_eq!(
            scrub_url_credentials("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
    }

    #[test]
    fn split_url_credential_lifts_secret_out_of_argv() {
        // A `user:token@` URL yields a credential-free URL for argv plus the
        // credential (host-scoped) for out-of-band delivery. Build the userinfo
        // at runtime so no credential-like literal is stored in source.
        let (user, pass) = ("x-access-token", "s3cr3tPAT");
        let url = format!("https://{user}:{pass}@github.com/org/repo.git");
        let (argv_url, cred) = split_url_credential(&url);
        assert_eq!(argv_url, "https://github.com/org/repo.git");
        assert!(!argv_url.contains(pass) && !argv_url.contains('@'));
        let cred = cred.expect("credential lifted from userinfo URL");
        assert_eq!(cred.host, "github.com");
        assert_eq!(cred.username, user);
        assert_eq!(cred.password, pass);

        // Token-as-username form (`https://<token>@host`) becomes username with
        // an empty password, mirroring git's own interpretation.
        let url = format!("https://{pass}@github.com/org/repo.git");
        let (argv_url, cred) = split_url_credential(&url);
        assert_eq!(argv_url, "https://github.com/org/repo.git");
        let cred = cred.expect("token-as-username credential lifted");
        assert_eq!(cred.username, pass);
        assert!(cred.password.is_empty());
        assert_eq!(cred.host, "github.com");

        // An explicit port is stripped from the scoped host (git sends `host`
        // without the default-port suffix; scope on the bare host).
        let url = format!("https://{user}:{pass}@example.com:8443/o/r.git");
        let cred = split_url_credential(&url).1.expect("credential expected");
        assert_eq!(cred.host, "example.com");

        // A credential-free URL is returned byte-for-byte with no credential.
        let plain = "https://github.com/org/repo.git";
        let (argv_url, cred) = split_url_credential(plain);
        assert_eq!(argv_url, plain);
        assert!(cred.is_none());

        // A non-URL (e.g. a local path) is passed through with no credential.
        let (argv_url, cred) = split_url_credential("/tmp/local/repo");
        assert_eq!(argv_url, "/tmp/local/repo");
        assert!(cred.is_none());
    }

    #[test]
    fn submodule_configs_are_scrubbed_of_credentials() {
        // A `--recurse-submodules` clone writes each submodule's remote URL into
        // `.git/modules/**/config`; the scrub must strip credentials from those
        // nested configs (recursively), leaving credential-free URLs behind.
        let tmp = std::env::temp_dir().join(format!("nano-sub-scrub-{}", std::process::id()));
        let nested = tmp.join(".git").join("modules").join("sub").join("modules").join("inner");
        std::fs::create_dir_all(&nested).unwrap();
        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");
        let outer_cfg = tmp.join(".git").join("modules").join("sub").join("config");
        let inner_cfg = nested.join("config");
        let body = |host: &str| {
            format!("[remote \"origin\"]\n\turl = https://{token}@{host}/o/r.git\n")
        };
        std::fs::write(&outer_cfg, body("h1")).unwrap();
        std::fs::write(&inner_cfg, body("h2")).unwrap();

        // The superproject's own top-level `.git/config` holds a
        // `submodule.<name>.url` entry that `submodule init` copied; it must be
        // scrubbed too.
        let top_cfg = tmp.join(".git").join("config");
        std::fs::write(
            &top_cfg,
            format!("[submodule \"sub\"]\n\turl = https://{token}@h3/o/r.git\n"),
        )
        .unwrap();

        scrub_submodule_config_credentials(&tmp).expect("scrub submodule configs");

        for (cfg, host) in [(&outer_cfg, "h1"), (&inner_cfg, "h2"), (&top_cfg, "h3")] {
            let got = std::fs::read_to_string(cfg).unwrap();
            assert!(!got.contains("s3cr3tPAT"), "credential left in {}: {got}", cfg.display());
            assert!(got.contains(&format!("https://{host}/o/r.git")));
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn submodule_scrub_is_noop_without_modules_dir() {
        // No `.git/modules` (the common no-submodules clone) is a clean no-op.
        let tmp = std::env::temp_dir().join(format!("nano-sub-none-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        scrub_submodule_config_credentials(&tmp).expect("no-op when no submodules");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn submodule_scrub_skips_symlinked_modules_root() {
        // A symlink planted at `.git/modules` must NOT be traversed: `exists()`
        // follows links, so the scrub would otherwise walk (and rewrite) a config
        // OUTSIDE the checkout. The `symlink_metadata` root guard treats the link
        // as "nothing to scrub" and leaves the target untouched.
        let tmp = std::env::temp_dir().join(format!("nano-sub-link-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("nano-sub-out-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");
        let outside_cfg = outside.join("config");
        std::fs::write(
            &outside_cfg,
            format!("[remote \"origin\"]\n\turl = https://{token}@h/o/r.git\n"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, tmp.join(".git").join("modules")).unwrap();

        scrub_submodule_config_credentials(&tmp).expect("symlinked root is a no-op");

        // The out-of-checkout config was left byte-for-byte untouched.
        let got = std::fs::read_to_string(&outside_cfg).unwrap();
        assert!(got.contains("s3cr3tPAT"), "scrub must not follow the symlinked root");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn fetch_head_scrub_strips_credentials() {
        // `git fetch <credential-URL>` records the source URL in
        // `.git/FETCH_HEAD`; the scrub must strip the PAT while leaving the rest
        // of the line intact. A missing file is a clean no-op.
        let tmp = std::env::temp_dir().join(format!("nano-fetchhead-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join(".git")).unwrap();
        // No FETCH_HEAD yet: no-op.
        scrub_fetch_head(&tmp).expect("no-op when FETCH_HEAD absent");

        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");
        let fetch_head = tmp.join(".git").join("FETCH_HEAD");
        std::fs::write(
            &fetch_head,
            format!("deadbeef\t\tbranch 'main' of https://{token}@github.com/o/r.git\n"),
        )
        .unwrap();

        scrub_fetch_head(&tmp).expect("scrub FETCH_HEAD");

        let got = std::fs::read_to_string(&fetch_head).unwrap();
        assert!(!got.contains("s3cr3tPAT"), "credential left in FETCH_HEAD: {got}");
        assert!(got.contains("https://github.com/o/r.git"));
        assert!(got.contains("branch 'main' of"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
