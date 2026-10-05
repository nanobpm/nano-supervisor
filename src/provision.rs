//! Minimum repository provisioning: clone the envelope's repository into the
//! job's workspace so the agent runs inside a real checkout.
//!
//! This is the MVP slice — clone (honouring depth / single-branch / filter /
//! submodules / branch), optionally check out a pinned commit, and best-effort
//! fetch a base ref so `git diff base...HEAD` works. Push/finalize is a later
//! issue; the agent (or a future finalize step) owns committing and pushing.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use crate::envelope::Repository;
use crate::safecwd::CwdHandle;

/// Upper bound on the size of a git metadata file (`config`, `FETCH_HEAD`, …)
/// the credential scrubber will read into memory. These files are influenced by
/// the remote repository, so an unbounded read is a remote/job-controlled
/// memory-exhaustion vector; 8 MiB is orders of magnitude above any legitimate
/// git config/FETCH_HEAD while still bounding a hostile one.
const MAX_SCRUB_BYTES: u64 = 8 * 1024 * 1024;

/// The checkout directory name, relative to the pinned run dir. A single
/// literal component: it is passed to git as a *relative* clone destination
/// (resolved against the pinned run-dir cwd) and to [`CwdHandle::open_child`]
/// (opened fd-relative), so it must never carry a separator or a parent
/// component.
const CHECKOUT_DIR: &str = "repo";

/// Clone `repo` into the `repo` child of the pinned run directory `workdir` and
/// return the pinned checkout handle. `default_timeout` caps each git
/// invocation (overridden per-repo by `cloneTimeoutMs`).
///
/// Every git step runs *through the capability*: the clone executes with its
/// cwd bound to the pinned run dir and a RELATIVE `repo` destination (an
/// absolute destination would be re-resolved by the kernel at spawn, so a
/// same-UID actor swapping an ancestor after preparation could redirect the
/// clone's writes outside the validated tree, #35), and the follow-on
/// `set-url`/fetch/checkout steps bind the checkout pinned fd-relative to that
/// same run dir — no path is ever re-resolved.
pub async fn provision(
    repo: &Repository,
    workdir: &CwdHandle,
    default_timeout: Duration,
) -> Result<CwdHandle> {
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

    // The checkout's path, for the scrub/removal helpers (which operate on
    // files, not cwds) and for messages. Recovered through the pinned fd so it
    // names the real prepared inode even after an ancestor rename; these
    // helpers re-validate each file no-follow before rewriting it.
    let workspace = workdir
        .path()
        .context("recovering the pinned run dir path")?
        .join(CHECKOUT_DIR);
    // `provision` binds every git step's cwd to the pinned run dir (#35), but a
    // relative *local* source (e.g. `./origin.git`) is interpreted by git
    // relative to *that* cwd — i.e. inside the still-empty run dir — so it would
    // no longer resolve to the path the envelope author meant (which, before
    // #35, was taken relative to the supervisor's own cwd). Re-anchor such
    // sources to the supervisor's cwd *once*, here, so the single resolved
    // `source` below drives clone, both fetches, AND the persisted origin
    // consistently. Remote URLs, scp-like SSH sources, and absolute local paths
    // are cwd-independent and pass through unchanged.
    let supervisor_cwd =
        std::env::current_dir().context("resolving the supervisor working directory")?;
    let source = resolve_local_source(&repo.url, &supervisor_cwd);

    // Lift any `user:token@` credential out of the URL so it is delivered to git
    // out of band (via the credential helper in `git()`) instead of embedded in
    // argv, where it would sit in world-readable `/proc/<git-pid>/cmdline` for
    // the life of every clone/fetch. `fetch_url` (credential-free) is what goes
    // on the command line; the same handle authenticates the clone and both
    // fetches below.
    let (fetch_url, cred) = split_url_credential(&source);
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
    // The destination is the RELATIVE `repo`, resolved by the clone child
    // against its pinned run-dir cwd — an absolute `<workdir>/repo` would be
    // re-resolved by the kernel at spawn, letting a same-UID actor redirect the
    // clone's writes by swapping an ancestor after preparation (#35).
    args.push(CHECKOUT_DIR.into());

    if let Err(e) = git(&args, Some(workdir), timeout, cred.as_ref()).await {
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

    // The clone wrote through the pinned run dir, so the checkout it created is
    // a direct child of that pinned inode; pin it fd-relative (never following
    // a symlink at the child) so every follow-on git step binds the same inode
    // the clone wrote, even if a path component is swapped afterwards.
    let checkout = workdir
        .open_child(std::ffi::OsStr::new(CHECKOUT_DIR))
        .context("pinning the freshly cloned checkout")?;

    // `git clone` now runs with a credential-free `fetch_url` in argv, so the
    // persisted `<workspace>/.git/config` origin already carries no `user:token@`
    // userinfo. This rewrite is kept as defense in depth — it re-canonicalises
    // the origin to the scrubbed URL right after the clone (a no-op when the URL
    // carried no credentials), so even if a future change reintroduced a
    // credential-bearing clone URL the agent could never read the PAT from the
    // persisted config. The clone and both fetches below authenticate via the
    // out-of-band credential helper (see `git()`), so the token is never written
    // to config or placed in argv.
    let scrubbed_origin = scrub_url_credentials(&source);
    if let Err(e) = git(
        &[
            "remote".into(),
            "set-url".into(),
            "origin".into(),
            "--".into(),
            scrubbed_origin,
        ],
        Some(&checkout),
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
            Some(&checkout),
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
            Some(&checkout),
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
            Some(&checkout),
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

    Ok(checkout)
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
    // These files (`config`, `FETCH_HEAD`, …) are influenced by the remote repo
    // and by `git fetch`, so their size is ultimately attacker/job-controlled.
    // An unbounded `read_to_string` would let a hostile repo (a giant
    // `FETCH_HEAD` or a pathologically nested config) make each slot buffer the
    // whole file, exhausting the daemon's memory. Read at most `MAX_SCRUB_BYTES`
    // and fail the checkout if the scrub input is larger — a credential-bearing
    // git metadata file this big is not legitimate.
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_SCRUB_BYTES + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("reading {}", path.display()))?;
    if raw.len() as u64 > MAX_SCRUB_BYTES {
        bail!(
            "{} exceeds the {}-byte credential-scrub cap — refusing to load it",
            path.display(),
            MAX_SCRUB_BYTES
        );
    }
    let contents = String::from_utf8(raw).with_context(|| format!("reading {}", path.display()))?;
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

/// Re-anchor a *relative local* clone source against the supervisor's working
/// directory.
///
/// `provision` runs every git step with its cwd bound to the pinned run dir
/// (#35). A relative local source such as `./origin.git` or `../mirror` is
/// interpreted by git relative to *that* cwd — i.e. inside the empty run dir —
/// so it would no longer resolve where the envelope author meant it (before #35
/// the clone ran from the supervisor's own cwd). Join such a source onto
/// `supervisor_cwd` so clone, fetch, and the persisted origin all keep
/// resolving it the same way they did before the run-dir binding.
///
/// Only genuinely *local relative* sources are rewritten. These pass through
/// byte-for-byte because their meaning is independent of the launching cwd:
///   * a remote URL (`scheme://…` — a colon before the first slash), and
///   * an scp-like SSH source (`host:path` — likewise a colon before any
///     slash, or a colon with no slash at all), and
///   * an already-absolute local path.
/// The "colon before the first slash" test mirrors git's own rule for telling a
/// URL / scp-like remote from a local path, so a path containing a colon *after*
/// a slash (e.g. `./weird:name`) is still treated as the local path it is.
fn resolve_local_source(url: &str, supervisor_cwd: &Path) -> String {
    let first_colon = url.find(':');
    let first_slash = url.find('/');
    let is_remote = match (first_colon, first_slash) {
        (Some(c), Some(s)) => c < s,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if is_remote || Path::new(url).is_absolute() {
        return url.to_string();
    }
    supervisor_cwd.join(url).to_string_lossy().into_owned()
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
    // Only lift a credential for the schemes whose userinfo `scrub_url_credentials`
    // actually strips — `http`/`https`. For other schemes (notably `ssh://git@host`,
    // where the userinfo is a *login*, not a secret) the sanitized URL still carries
    // the original userinfo verbatim, so extracting a credential here would both
    // leave that userinfo in the argv `fetch_url` AND additionally hand git a helper
    // credential — double-delivering a password-bearing non-HTTP URL into git's
    // argv/config. Leave such URLs untouched (no lifted credential), mirroring the
    // scrub's scheme scoping.
    let scheme = scheme_of(&url[..pos]);
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return (sanitized, None);
    }
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
        // Credentials are only lifted/scrubbed for the schemes where git's
        // credential helper injects a secret: http and https. Other schemes —
        // notably `ssh://git@host` — carry a *username* in the userinfo, not a
        // secret, so stripping it would corrupt an otherwise valid remote
        // (dropping the SSH login and silently breaking the fetch). Leave those
        // authorities untouched.
        let scheme = scheme_of(&rest[..pos]);
        let scrub = scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        // The authority runs until the first character that cannot be part of it
        // (path/query/fragment separators or any whitespace/quoting that ends the
        // URL inside surrounding prose).
        let auth_end = tail
            .find(|c: char| {
                matches!(
                    c,
                    '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ')' | ']' | '}' | '|' | '\\' | '`'
                ) || c.is_whitespace()
            })
            .unwrap_or(tail.len());
        let authority = &tail[..auth_end];
        match authority.rfind('@') {
            Some(at) if scrub => out.push_str(&authority[at + 1..]),
            _ => out.push_str(authority),
        }
        rest = &tail[auth_end..];
    }
    out.push_str(rest);
    out
}

/// The URL scheme = the trailing run of scheme characters (`[A-Za-z0-9+.-]`)
/// immediately preceding `"://"`. Returns `""` when no valid scheme precedes it
/// (e.g. a bare `://` embedded in prose), which leaves that authority untouched.
fn scheme_of(prefix: &str) -> &str {
    let mut start = prefix.len();
    for (i, c) in prefix.char_indices().rev() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') {
            start = i;
        } else {
            break;
        }
    }
    &prefix[start..]
}

async fn git(
    args: &[String],
    cwd: Option<&CwdHandle>,
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
        // Enter the working directory through the pinned, no-follow capability
        // (`fchdir` in the child's `pre_exec`) rather than re-resolving a path
        // at spawn time: the run dir can sit under a world-writable ancestor,
        // so a same-UID actor could otherwise swap a component for a symlink
        // between provisioning and this `clone`/`fetch`/`checkout`/`set-url`
        // and redirect git outside the validated tree (#35). The caller holds
        // the handle open from preparation, so the bind targets the prepared
        // inode even across a post-prepare replacement of the path.
        dir.apply(&mut cmd)
            .context("binding git working directory")?;
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
            // Reap the just-killed leader (bounded) before returning. The `wait`
            // future — which owns `child` — was dropped when the timeout fired,
            // and `kill_on_drop` signals a dropped child but does *not* guarantee
            // it is reaped; without an explicit wait, repeated clone/fetch
            // timeouts would accumulate zombie git leaders in the long-lived
            // daemon. The timeout bounds the wait so a wedged (uninterruptible)
            // child cannot hang the slot.
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
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
    fn resolve_local_source_reanchors_only_relative_local_paths() {
        let cwd = Path::new("/supervisor/cwd");
        let anchor = |u: &str| resolve_local_source(u, cwd);

        // Relative local sources are re-anchored to the supervisor cwd — the
        // bug: under the #35 run-dir binding these would otherwise resolve
        // inside the empty run dir and the clone would fail.
        assert_eq!(anchor("./origin.git"), "/supervisor/cwd/./origin.git");
        assert_eq!(anchor("../mirror"), "/supervisor/cwd/../mirror");
        assert_eq!(anchor("origin.git"), "/supervisor/cwd/origin.git");
        assert_eq!(anchor("sub/dir/repo"), "/supervisor/cwd/sub/dir/repo");
        // A colon *after* a slash is still a local path (git's own rule), so it
        // too is re-anchored rather than mistaken for an scp-like remote.
        assert_eq!(anchor("./weird:name"), "/supervisor/cwd/./weird:name");

        // Sources whose meaning is independent of the launching cwd pass through
        // byte-for-byte: absolute local paths, URLs, and scp-like SSH sources.
        for passthrough in [
            "/abs/local/path",
            "https://github.com/o/r.git",
            "http://example.com/r.git",
            "git://example.com/r.git",
            "ssh://git@example.com/o/r.git",
            "file:///srv/mirror.git",
            "git@github.com:o/r.git", // scp-like: colon before any slash
            "host:path",              // scp-like: colon, no slash
        ] {
            assert_eq!(anchor(passthrough), passthrough, "{passthrough} must pass through unchanged");
        }
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
    fn scrub_preserves_ssh_username() {
        // ssh:// userinfo is a login name, not a secret git delivers via a
        // credential helper — stripping it would corrupt the remote and break
        // the fetch, so it must be left intact.
        assert_eq!(
            scrub_url_credentials("ssh://git@example.com/org/repo.git"),
            "ssh://git@example.com/org/repo.git"
        );
        // git:// likewise carries no credential-helper secret in its userinfo.
        assert_eq!(
            scrub_url_credentials("git://user@host/org/repo.git"),
            "git://user@host/org/repo.git"
        );
        // …while an http(s) PAT is still scrubbed.
        let token = "x-access-token:s3cr3t";
        let with_creds = format!("https://{token}@github.com/org/repo.git");
        assert_eq!(
            scrub_url_credentials(&with_creds),
            "https://github.com/org/repo.git"
        );
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

        // A non-HTTP(S) scheme carries a *login*, not a secret: `scrub_url_credentials`
        // deliberately leaves its userinfo intact, so lifting a credential here would
        // double-deliver it (userinfo stays in the argv URL *and* a helper credential
        // is emitted). No credential is lifted and the URL is returned unchanged.
        let url = format!("ssh://{user}:{pass}@git.example.com/o/r.git");
        let (argv_url, cred) = split_url_credential(&url);
        assert_eq!(argv_url, url);
        assert!(
            cred.is_none(),
            "no credential must be lifted from a non-HTTP scheme"
        );
        // The canonical `ssh://git@host` login form is likewise preserved verbatim.
        let ssh = "ssh://git@git.example.com/o/r.git";
        let (argv_url, cred) = split_url_credential(ssh);
        assert_eq!(argv_url, ssh);
        assert!(cred.is_none());
    }

    #[test]
    fn submodule_configs_are_scrubbed_of_credentials() {
        // A `--recurse-submodules` clone writes each submodule's remote URL into
        // `.git/modules/**/config`; the scrub must strip credentials from those
        // nested configs (recursively), leaving credential-free URLs behind.
        let tmp = std::env::temp_dir().join(format!("nano-sub-scrub-{}", std::process::id()));
        let nested = tmp
            .join(".git")
            .join("modules")
            .join("sub")
            .join("modules")
            .join("inner");
        std::fs::create_dir_all(&nested).unwrap();
        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");
        let outer_cfg = tmp.join(".git").join("modules").join("sub").join("config");
        let inner_cfg = nested.join("config");
        let body =
            |host: &str| format!("[remote \"origin\"]\n\turl = https://{token}@{host}/o/r.git\n");
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
            assert!(
                !got.contains("s3cr3tPAT"),
                "credential left in {}: {got}",
                cfg.display()
            );
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
        assert!(
            got.contains("s3cr3tPAT"),
            "scrub must not follow the symlinked root"
        );
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
        assert!(
            !got.contains("s3cr3tPAT"),
            "credential left in FETCH_HEAD: {got}"
        );
        assert!(got.contains("https://github.com/o/r.git"));
        assert!(got.contains("branch 'main' of"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A `file://` source repo with one commit, for provisioning tests.
    #[cfg(unix)]
    fn make_source_repo(base: &std::path::Path) -> String {
        let src = base.join("src-repo");
        std::fs::create_dir_all(&src).unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&src)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        std::fs::write(src.join("f.txt"), b"hello").unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ]);
        format!("file://{}", src.display())
    }

    #[cfg(unix)]
    fn repo_envelope(url: String) -> Repository {
        Repository {
            provider: "github".into(),
            url,
            ref_: None,
            sha: None,
            depth: None,
            single_branch: false,
            filter: None,
            base_ref: None,
            base_sha: None,
            submodules: false,
            clone_timeout_ms: None,
        }
    }

    /// The clone must write into the PINNED run dir: it runs with its cwd bound
    /// to the pinned handle and a RELATIVE `repo` destination, so an ancestor
    /// swapped for a symlink after the pin cannot redirect the clone's writes
    /// into the attacker's tree — the checkout lands in the pinned inode (the
    /// moved-aside real dir), and the returned handle names that same inode
    /// (#35). Before the fix the clone ran with `cwd=None` and an ABSOLUTE
    /// `<workdir>/repo` destination, which the kernel re-resolved at spawn —
    /// straight into the swapped-in attacker path.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn clone_writes_into_the_pinned_run_dir_after_an_ancestor_swap() {
        let base = std::env::temp_dir().join(format!(
            "nano-provision-swap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor (macOS /var).
        let base = std::fs::canonicalize(&base).unwrap();
        let url = make_source_repo(&base);

        // The prepared run dir, pinned as at provisioning.
        let ancestor = base.join("ancestor");
        let run = ancestor.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let workdir = CwdHandle::open(&run).unwrap();

        // Attacker swaps the ancestor for a symlink to their tree AFTER the
        // pin, before the clone: an absolute destination path would now
        // resolve into the attacker tree; the pinned fd must not.
        let moved = base.join("ancestor-moved");
        std::fs::rename(&ancestor, &moved).unwrap();
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join("run")).unwrap();
        std::os::unix::fs::symlink(&evil, &ancestor).unwrap();

        let checkout = provision(&repo_envelope(url), &workdir, Duration::from_secs(60))
            .await
            .expect("provision through the pinned run dir");

        // The clone landed in the PINNED inode (now at `moved/run/repo`), not
        // the attacker tree the original path would resolve to.
        let real_checkout = moved.join("run").join(CHECKOUT_DIR);
        assert!(
            real_checkout.join("f.txt").exists(),
            "clone must land in the pinned run dir"
        );
        assert!(
            !evil.join("run").join(CHECKOUT_DIR).join("f.txt").exists(),
            "clone must not write into the swapped-in attacker tree"
        );
        // And the returned handle binds that same pinned checkout inode.
        let landed = checkout.path().expect("checkout path");
        assert_eq!(
            std::fs::canonicalize(landed).unwrap(),
            std::fs::canonicalize(real_checkout).unwrap(),
            "the returned checkout handle must name the pinned inode"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// A RELATIVE local source must still resolve against the supervisor's cwd,
    /// even though the clone now runs with its cwd bound to the pinned run dir
    /// (#35). Before the re-anchoring fix, git interpreted `./…`/`../…` relative
    /// to the empty run dir and provisioning failed. We avoid mutating the
    /// process cwd (racy under parallel tests) by computing a relative path from
    /// the *actual* current dir to the source repo and passing that — exactly
    /// what `provision` re-anchors via `std::env::current_dir()`.
    ///
    /// The red-before guard is the **persisted origin**, not merely that the
    /// clone produced a checkout: `relativize(cwd, temp_src)` can climb to `/`
    /// when the cwd is deeper than the temp base, and such an all-`..` path
    /// resolves to the *same* absolute location whether git anchors it at the
    /// run dir (the bug) or the supervisor cwd (the fix) — so a checkout-only
    /// assertion passes against the broken code too (it did, from a deep cwd).
    /// We therefore assert the stored `remote.origin.url` is the re-anchored
    /// **absolute** path: the fix persists `supervisor_cwd.join(url)` (absolute),
    /// whereas the pre-fix code would persist the raw **relative** input. That
    /// distinction is independent of cwd depth, so the test is reliably red
    /// before the fix wherever the test binary runs.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn provision_resolves_a_relative_local_source_from_supervisor_cwd() {
        fn relativize(from: &Path, to: &Path) -> std::path::PathBuf {
            let fc: Vec<_> = from.components().collect();
            let tc: Vec<_> = to.components().collect();
            let mut i = 0;
            while i < fc.len() && i < tc.len() && fc[i] == tc[i] {
                i += 1;
            }
            let mut rel = std::path::PathBuf::new();
            for _ in i..fc.len() {
                rel.push("..");
            }
            for c in &tc[i..] {
                rel.push(c.as_os_str());
            }
            rel
        }

        let base = std::env::temp_dir().join(format!(
            "nano-provision-relsrc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        let base = std::fs::canonicalize(&base).unwrap();
        let _ = make_source_repo(&base); // creates `base/src-repo`
        let src = base.join("src-repo");

        // A relative source spelled from the real supervisor cwd — never a URL,
        // never absolute — so only the re-anchoring makes it resolve.
        let cwd = std::env::current_dir().unwrap();
        let rel = relativize(&cwd, &src);
        assert!(!rel.is_absolute(), "test must exercise a RELATIVE source");
        let rel_url = rel.to_string_lossy().into_owned();

        let run = base.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let workdir = CwdHandle::open(&run).unwrap();

        let checkout = provision(&repo_envelope(rel_url.clone()), &workdir, Duration::from_secs(60))
            .await
            .expect("provision must resolve a relative local source from the supervisor cwd");

        let landed = checkout.path().expect("checkout path");
        assert!(
            landed.join("f.txt").exists(),
            "the relative-source clone must land a real checkout in the run dir"
        );

        // The real red-before guard (see the doc comment): the persisted origin
        // must be the re-anchored ABSOLUTE path, not the raw relative input. The
        // fix stores `supervisor_cwd.join(url)`; the pre-fix code would store the
        // relative string verbatim. This distinction holds regardless of how
        // deep the test binary's cwd is, so it catches a reintroduction of the
        // bug even when an all-`..` relative path happens to clone successfully.
        let origin = {
            let out = std::process::Command::new("git")
                .args(["config", "--get", "remote.origin.url"])
                .current_dir(landed)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "reading remote.origin.url failed");
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        let origin_path = Path::new(&origin);
        assert!(
            origin_path.is_absolute(),
            "persisted origin must be the re-anchored ABSOLUTE path, not the \
             relative input {rel_url:?}; got {origin:?}"
        );
        assert_eq!(
            std::fs::canonicalize(origin_path).unwrap(),
            std::fs::canonicalize(&src).unwrap(),
            "the re-anchored origin must resolve to the real source repo"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
