//! Minimum repository provisioning: clone the envelope's repository into the
//! job's workspace so the agent runs inside a real checkout.
//!
//! This is the MVP slice — clone (honouring depth / single-branch / filter /
//! submodules / branch), optionally check out a pinned commit, and best-effort
//! fetch a base ref so `git diff base...HEAD` works. Push/finalize is a later
//! issue; the agent (or a future finalize step) owns committing and pushing.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::process::Command;
use tokio::time::Instant;

use crate::envelope::Repository;
use crate::safecwd::CwdHandle;

/// Upper bound on the size of a git metadata file (`config`, `FETCH_HEAD`, …)
/// the credential scrubber will read into memory. These files are influenced by
/// the remote repository, so an unbounded read is a remote/job-controlled
use crate::runtime::log;
use std::path::PathBuf;
/// git config/FETCH_HEAD while still bounding a hostile one.
const MAX_SCRUB_BYTES: u64 = 8 * 1024 * 1024;

/// Process-local monotonically increasing sequence folded into the finalize
/// push-context directory name. All slots share the worker PID and two
/// concurrent finalizers can observe the SAME wall-clock tick (or the clock can
/// move backward), so `pid`+`nanos` alone is not unique — the second
/// `create_dir` would fail and incorrectly leave otherwise pushable work
/// retained. This counter guarantees two finalizers in one process never mint
/// the same context name (mirroring `slot.rs`'s `ACTIVATION_SEQ`). `Relaxed`
/// ordering suffices — only the fetch_add's atomicity/uniqueness matters.
static FINALIZE_CTX_SEQ: AtomicUsize = AtomicUsize::new(0);

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
    /// Set when finalize proved the repository is still in the UNBORN/no-ref
    /// state it was provisioned in (`start_sha` was `None` and HEAD still
    /// resolves to no commit): the agent created no commit anywhere, so the
    /// run dir holds NO agent work. Distinct from `retain` (an incomplete or
    /// stranded scan): the empty-scan retain that accompanies this state is
    /// only the fail-closed "cannot prove completeness" guard for a repo with
    /// no anchor — NOT evidence a commit exists — so the caller must NOT let
    /// it count as `has_commits` for the empty-result check (a quiet no-op
    /// agent on an unborn base would otherwise bypass the empty-result failure
    /// contract). Reaping is unaffected: `retain` still keeps the dir, and the
    /// stale-run sweep ages it out.
    pub unborn_no_ref: bool,
    /// Set when a safety-net enumeration could NOT be proven complete — a ref
    /// listing overflowed the capture cap, a per-ref probe failed, or the
    /// candidate/reflog set exceeded its scan cap — so finalize examined only a
    /// TRUNCATED view in which an agent commit could still be hiding beyond
    /// what it saw. Distinct from the fail-closed `retain` an unborn base
    /// ALWAYS carries (its HEAD has no anchor, so `rev-parse HEAD`/the HEAD
    /// reflog net fail closed even on a genuine no-op): those expected
    /// anchor-absent failures are NOT inconclusive scans and must NOT set this
    /// flag, or a legitimate no-op would never be recognised. `unborn_no_ref`
    /// requires this flag CLEAR: proving "no commit anywhere" demands that
    /// every net that could surface a parked/stranded commit actually ran to
    /// completion — a capped non-head-ref or reflog sweep (e.g. an agent that
    /// `commit-tree`s work, parks it under a non-HEAD ref, and pads the ref set
    /// past the cap) leaves `retain=true, work_found=false, commits=[]` yet is
    /// NOT a proven-empty repo, so it must not be marked unborn and failed as
    /// an empty run.
    pub scan_incomplete: bool,
}

/// Longest segment `sanitize_branch_segment` leaves in a composed fallback ref.
///
/// A git ref is stored loose as a file per component, so each component must
/// fit the filesystem's `NAME_MAX` (255 on ext4/overlayfs/APFS). The composed
/// fallback is `nano/agent-work/<base>-<uniq>`, whose last component is
/// `<base>-<uniq>`. The per-activation `<uniq>` is `<rand>-<pid>-<nanos>-<seq>`,
/// whose worst case stays under ~70 chars (16 hex + a `u32` pid + `u128` nanos +
/// a `usize` seq + separators), so capping the job-controlled `<base>` segment
/// at 180 keeps that component (`180 + 1 + ~70 ≈ 251`) — and the whole ref —
/// comfortably inside the 255 limit even at the extremes. Mirrors the plugin's
/// `sanitizeBranchSegment`, which likewise bounds its segment.
const MAX_FALLBACK_SEGMENT: usize = 180;

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
        &[
            "symbolic-ref".into(),
            "--short".into(),
            "-q".into(),
            "HEAD".into(),
        ],
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
            Err(e) => log(&format!(
                "finalize: detached-HEAD fallback branch cut failed — {e}"
            )),
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

/// The overall wall-clock budget for the WHOLE [`finalize_git`] stage, derived
/// from the per-command `timeout`. Finalize launches many git subprocesses
/// SERIALLY (a `rev-parse`/`rev-list` per side branch up to
/// `MAX_SIDE_BRANCH_SCAN`, a `for-each-ref`/`rev-list` per HEAD-reflog position
/// and per non-head candidate up to `MAX_REFLOG_SCAN`, …), so the per-command
/// timeout alone does not bound the stage: an agent-controlled repository could
/// stretch settlement to scan-cap × timeout (many hours at the default 120 s).
/// A real run finishes finalize in a handful of quick commands, so a small
/// multiple of the per-command timeout absorbs the legitimate serial chain
/// while still bounding the stage far below caps × timeout. A floor keeps a
/// tiny configured `clone_timeout` from making the deadline unusably tight.
fn finalize_deadline_budget(timeout: Duration) -> Duration {
    const MULTIPLIER: u32 = 8;
    const FLOOR: Duration = Duration::from_secs(60);
    timeout.saturating_mul(MULTIPLIER).max(FLOOR)
}

/// After the agent runs: enumerate the commits it made on the work branch and
/// (when `branch.push` is on and the branch has new commits) push it to the
/// origin, returning the `branch`/`commits`/`pushed`/`pr` the job's completion
/// variables carry. Mirrors the plugin's `finalizeGit`. Best-effort: a push
/// failure is reported as `pushed = false` (the run dir is then retained for
/// recovery by the caller) rather than failing the job.
///
/// The whole stage runs under ONE overall deadline (see
/// [`finalize_deadline_budget`]):
/// `timeout` bounds each individual git subprocess, but finalize launches many
/// of them serially, so without a stage-level budget an agent-controlled
/// repository could stretch settlement to scan-cap × timeout (hours).
pub async fn finalize_git(
    workspace: &CwdHandle,
    prep: &GitPrep,
    repo: &Repository,
    timeout: Duration,
) -> GitResult {
    // ONE overall finalize deadline. `timeout` bounds each INDIVIDUAL git
    // subprocess, but finalize launches many of them SERIALLY (a `rev-parse`/
    // `rev-list` per side branch up to `MAX_SIDE_BRANCH_SCAN`, a
    // `for-each-ref`/`rev-list` per HEAD-reflog position and per non-head
    // candidate up to `MAX_REFLOG_SCAN`, …), so a per-command budget alone lets
    // an agent-controlled repository stretch the stage to caps × timeout (many
    // hours at the default 120 s) and delay settlement. Bound the WHOLE stage
    // instead: the deadline is a small multiple of the per-command timeout (a
    // real run finishes in a handful of quick commands; the multiple absorbs
    // the legitimate serial chain without permitting caps×timeout), and every
    // git invocation below is handed the REMAINING budget so the stage cannot
    // overrun it. On expiry the scan is incomplete — fail CLOSED (`retain`) so
    // the run dir is kept rather than reaped on a half-finished sweep.
    let deadline = Instant::now() + finalize_deadline_budget(timeout);
    finalize_git_with_deadline(workspace, prep, repo, timeout, deadline).await
}

/// The body of [`finalize_git`] with the overall stage `deadline` supplied by
/// the caller, so tests can inject an already-expired deadline to drive the
/// genuine expiry branch of `remaining!()` (a past deadline, NOT merely a tiny
/// per-command `timeout`, is what makes `checked_duration_since` return `None`).
async fn finalize_git_with_deadline(
    workspace: &CwdHandle,
    prep: &GitPrep,
    repo: &Repository,
    timeout: Duration,
    deadline: Instant,
) -> GitResult {
    let mut out = GitResult {
        branch: prep.working_branch.clone(),
        commits: Vec::new(),
        pushed: false,
        pr: None,
        retain: false,
        work_found: false,
        unborn_no_ref: false,
        scan_incomplete: false,
    };

    // The timeout for the NEXT git subprocess: the smaller of the per-command
    // `timeout` and the time left to the overall deadline. Recomputed at each
    // call site so a stalled command cannot let the stage overrun the deadline
    // by another full per-command timeout. Once the deadline has expired this
    // yields a NEAR-ZERO duration, so the next `git()`/`git_untruncated()`/
    // `git_isolated()`/`git_raw_status()` times out immediately and surfaces
    // `Err`/`None` — which every call site already maps to "scan incomplete →
    // retain" (fail closed). The expiry log is emitted once, on the first
    // `remaining!()` that finds the deadline exhausted.
    #[allow(unused_mut)]
    let mut deadline_logged = false;
    macro_rules! remaining {
        () => {{
            // Hygiene note: this macro expands to an expression that may mutate
            // the caller's `deadline_logged`/`deadline`/`timeout` locals. The
            // final expansion's `deadline_logged = true` store is dead (nothing
            // reads it afterwards), so silence the per-expansion lint here.
            #[allow(unused_assignments)]
            match deadline.checked_duration_since(Instant::now()) {
                Some(r) if !r.is_zero() => r.min(timeout),
                _ => {
                    if !deadline_logged {
                        deadline_logged = true;
                        log(&format!(
                            "finalize: the overall finalize deadline ({:?}) expired — treating \
                             the scan as incomplete and retaining the run dir rather than \
                             sweeping on a half-finished/inconclusive scan",
                            finalize_deadline_budget(timeout)
                        ));
                    }
                    Duration::from_nanos(1)
                }
            }
        }};
    }

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
            remaining!(),
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
            remaining!(),
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
            remaining!(),
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
                    remaining!(),
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
        // Read via `git_untruncated`: the forward-sorted `for-each-ref` listing
        // keeps only the LAST bytes of stdout under the capture cap, so an
        // oversized ref pile would silently drop the FIRST (early-sorting) refs —
        // exactly where an agent's stranded side branch would hide. Endpoint
        // probes cannot rescue a truncated tail: the capture can cut in the
        // MIDDLE of a ref name, so an agent can pad the listing until the
        // surviving suffix of a late ref equals the true minimum name and passes
        // both the min and max anchors while earlier branches were dropped. Fail
        // CLOSED on overflow (propagated `Err`) instead, exactly as the
        // provision-time and non-head ref scans do.
        match git_untruncated(
            &[
                "for-each-ref".into(),
                "--format=%(refname:short)".into(),
                "refs/heads/".into(),
            ],
            Some(workspace),
            remaining!(),
            None,
        )
        .await
        {
            Ok(refs) => {
                let refs: Vec<&str> = refs
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                // An untruncated read proves the listing is COMPLETE, so the
                // parsed set is exactly the repo's `refs/heads/` branches with no
                // endpoint anchoring. A healthy finalize always has at least the
                // prepared work branch and/or the local base, so an empty parse
                // is still treated as an incomplete scan: fail closed and retain
                // rather than sweep an empty list.
                if refs.is_empty() {
                    log(
                        "finalize: side-branch enumeration parsed no branches; treating the \
                         scan as incomplete and retaining the run dir rather than trusting \
                         the empty list",
                    );
                    out.retain = true;
                    // An unborn/empty base LEGITIMATELY has no `refs/heads/`
                    // branches (a symbolic HEAD with no commit creates none),
                    // so the empty parse is the expected no-ref state there,
                    // not an inconclusive scan. The detached-HEAD reflog and
                    // non-head-ref nets below still run (they catch any commit
                    // the agent DID make off-branch), but the push block is
                    // unreachable — `branch_tip` is `None` on an unborn base,
                    // so `commits` is empty and the push is refused under
                    // `retain` regardless.
                    //
                    // `unborn_no_ref` is NOT decided here: the HEAD probe alone
                    // only proves HEAD resolves to no commit — it says nothing
                    // about a commit the agent stranded and then orphaned (e.g.
                    // commit on the only branch, then `update-ref -d` it: HEAD
                    // is unborn again and `refs/heads/` is empty, yet the
                    // commit still dangles in the HEAD reflog). Marking here
                    // would return before those nets run and let the caller
                    // fail the run as empty — and its retry wipes the run dir
                    // holding the only copy. Fall through so the nets classify
                    // whatever appeared; the end-of-function `mark_unborn_no_ref`
                    // marks the verdict only when they found nothing.
                    if prep.start_sha.is_none() && !out.work_found && out.commits.is_empty() {
                        // The empty-scan `retain` is only the fail-closed
                        // "cannot prove completeness" guard of a repo with no
                        // anchor, not evidence of work — clear it so the nets
                        // below run their classification loops (they skip while
                        // `retain` is set) and re-set it on any inconclusive
                        // step or stranded find.
                        out.retain = false;
                    } else {
                        return out;
                    }
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
                        remaining!(),
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
                            log("finalize: no provision-time ref snapshot (its enumeration \
                                 failed); cannot prove side branches pre-existed, so treating the \
                                 scan as incomplete and retaining the run dir");
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
                        remaining!(),
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
                // A failed branch sweep OR a listing that overflowed the capture
                // cap (`git_untruncated` fails closed on overflow) is an
                // incomplete scan: retain rather than risk missing a stranded
                // side branch dropped from a truncated tail.
                log(&format!(
                    "finalize: enumerating side branches failed or overflowed the capture cap \
                     — {e}; treating the scan as incomplete and retaining the run dir"
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
            remaining!(),
            None,
        )
        .await
        {
            Ok(entries) => {
                // De-duplicate with a HashSet and stop as soon as the distinct
                // count EXCEEDS the scan cap: the reflog is agent-controlled,
                // so a linear `Vec` membership probe per line is quadratic in
                // the reflog length and would burn CPU for the whole capture
                // before the `MAX_REFLOG_SCAN` guard ever fired — defeating the
                // CPU bound the cap exists to enforce. Iterating the positions
                // in their original (newest-first) order preserves the scan
                // order the loop below had when `distinct` was a Vec.
                let mut seen = std::collections::HashSet::new();
                let mut distinct: Vec<String> = Vec::new();
                let mut unbounded = false;
                for h in entries.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if seen.insert(h.to_string()) {
                        distinct.push(h.to_string());
                        if distinct.len() > MAX_REFLOG_SCAN {
                            unbounded = true;
                            break;
                        }
                    }
                }
                if unbounded {
                    log(&format!(
                        "finalize: HEAD reflog has more than {MAX_REFLOG_SCAN} distinct \
                         positions; treating the detached-commit scan as unbounded and retaining \
                         the run dir rather than sweeping an agent-controlled reflog"
                    ));
                    out.retain = true;
                    // Truncated view: a detached commit could hide past the cap,
                    // so this scan is NOT proof of "no work" — block any unborn
                    // verdict (see `GitResult::scan_incomplete`).
                    out.scan_incomplete = true;
                } else if let Some(start) = &prep.start_sha {
                    if !seen.contains(start.as_str()) {
                        log(&format!(
                            "finalize: HEAD reflog no longer contains the provision-time HEAD \
                             {start} (expired/rewritten); treating the detached-commit scan as \
                             incomplete and retaining the run dir"
                        ));
                        out.retain = true;
                        out.scan_incomplete = true;
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
                            remaining!(),
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
                                match git(&args, Some(workspace), remaining!(), None).await {
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
        // HashSet membership for the candidate de-dup below: the ref set is
        // agent-controlled, so a linear `Vec` probe per line is quadratic in
        // the ref count and would burn CPU for the whole capture before the
        // `MAX_REFLOG_SCAN` guard ever fired. `candidates` keeps insertion
        // order for the classification loop; `seen` makes membership O(1).
        let mut seen_candidates = std::collections::HashSet::new();
        match git_untruncated(
            &[
                "for-each-ref".into(),
                "--format=%(refname) %(objectname) %(*objectname)".into(),
                "refs/".into(),
            ],
            Some(workspace),
            remaining!(),
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
                    if !sha.is_empty() && seen_candidates.insert(sha.to_string()) {
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
                // A parked commit could hide in the refs this truncated/failed
                // listing did not surface — not proof of "no work" (see
                // `GitResult::scan_incomplete`).
                out.scan_incomplete = true;
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
                remaining!(),
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
                    remaining!(),
                    None,
                )
                .await
                {
                    Ok(list) => {
                        for h in list.lines().map(str::trim).filter(|l| !l.is_empty()) {
                            // Same O(1)-membership guard as the `for-each-ref`
                            // dedup above: the stash reflog is agent-controlled,
                            // so a linear `Vec` probe per entry is quadratic.
                            if seen_candidates.insert(h.to_string()) {
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
                        out.scan_incomplete = true;
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
            // The exact attack the unborn verdict must survive: an agent parks a
            // `commit-tree` commit under a non-HEAD ref and pads the ref set past
            // the cap. The sweep is truncated, so this is NOT proof of "no work".
            out.scan_incomplete = true;
        }
        // The classification loop below is gated on `!out.retain` (once the dir
        // is being retained there is no need to keep classifying FOR RETENTION).
        // But on an unborn base an earlier fail-closed net ALWAYS sets `retain`
        // (the HEAD-reflog net cannot enumerate an unborn HEAD's log), so that
        // short-circuit leaves these non-head candidates UNEXAMINED — and a
        // candidate here is a commit parked outside `refs/heads` (a tag, the
        // stash, a remote-tracking or arbitrary ref) that the agent may have
        // created. Unexamined parked candidates mean the "no commit anywhere"
        // scan is NOT conclusive, so block the unborn verdict (a genuine no-op
        // unborn base has ZERO non-head refs, so `candidates` is empty there and
        // this does not fire). See `GitResult::scan_incomplete`.
        if out.retain && !candidates.is_empty() {
            out.scan_incomplete = true;
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
                    remaining!(),
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
                        match git(&args, Some(workspace), remaining!(), None).await {
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
                //  - the LOCAL config is agent-mutable, so rather than scrub it
                //    in place and then spawn the push from the same checkout (a
                //    scrub-then-use race — a detached agent helper could rewrite
                //    `http.proxy`/TLS or `url.*` between the scrub and the spawn),
                //    the push runs from a CLEAN git administrative context that
                //    never reads the checkout's local/worktree config at all.
                //  - the GLOBAL config is NOT trusted host state either: agents
                //    inherit the daemon's `HOME` and run as the same account, so
                //    they can plant a `url.*.insteadOf`, an `http.proxy`, or a TLS
                //    loosening in `~/.gitconfig`. So the push runs with the GLOBAL
                //    and SYSTEM config isolated to `/dev/null` (no host
                //    insteadOf/proxy/TLS applies). The credential is still
                //    delivered out of band by `git()`'s host-matched helper, so
                //    the token never reaches argv.
                let push_ctx =
                    match finalize_push_context(workspace, branch, timeout, deadline).await {
                        Ok(ctx) => Some(ctx),
                        Err(e) => {
                            log(&format!(
                                "finalize: could not build a clean git admin context for the push \
                                 — {e}; skipping the push and retaining the run dir so work is not \
                                 pushed to a possibly rewritten/MITM'd destination"
                            ));
                            out.retain = true;
                            None
                        }
                    };
                if let Some(push_ctx) = push_ctx {
                    // Push to the SAME trusted source the clone used: a
                    // relative local `repo.url` (e.g. `./origin.git`) must be
                    // re-anchored to the supervisor cwd, not re-resolved
                    // against the checkout (which would target the wrong — or
                    // no — destination and report `pushed: false`).
                    let (fetch_url, cred) = trusted_fetch_source(&repo.url);
                    // The push runs from the clean context, so no agent-writable
                    // `url.*.insteadOf`/`http.proxy`/TLS/include setting is in its
                    // config search path. `--git-dir=<ctx>` points git at the clean
                    // context; `core.hooksPath=/dev/null` is belt-and braces (the
                    // clean context has no hooks, but the flag keeps the invariant
                    // explicit). This prefix (`cfg`) is reused for the post-error
                    // remote verification below, so that check runs over the SAME
                    // isolated/trusted channel.
                    let cfg: Vec<String> = vec![
                        format!("--git-dir={}", push_ctx.dir.display()),
                        "-c".into(),
                        "core.hooksPath=/dev/null".into(),
                    ];
                    let mut args = cfg.clone();
                    args.push("push".into());
                    args.push("--".into());
                    args.push(fetch_url.clone());
                    args.push(format!("refs/heads/{branch}:refs/heads/{branch}"));
                    // cwd is None: the clean `--git-dir` is absolute, so the push
                    // must NOT run from the agent-mutable checkout (which would
                    // re-introduce its local/worktree config into the search path).
                    match git_isolated(&args, None, remaining!(), cred.as_ref()).await {
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
                                &push_ctx,
                                &cfg,
                                &fetch_url,
                                branch,
                                cred.as_ref(),
                                timeout,
                                deadline,
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

    // UNBORN/NO-REF verdict (see the helper): a proven-still-unborn run's
    // `retain` is only the fail-closed guard of a repo with no anchor, not
    // evidence a commit exists — mark it so the caller's empty-result check
    // does not read that retain as `has_commits`.
    mark_unborn_no_ref(&mut out, prep, workspace, remaining!()).await;
    out
}

/// Set [`GitResult::unborn_no_ref`] when finalize PROVED the repository is
/// still in the unborn/no-ref state it was provisioned in: the base was empty
/// (`start_sha` is `None`), every scan found nothing (`commits` empty,
/// `work_found` clear), and HEAD STILL resolves to no commit. Every
/// commit-carrying path in `finalize_git` (work branch, side branch, detached
/// HEAD, stash/tag/remote-ref) sets `commits` or `work_found` when it finds
/// one, so all three conditions together prove the agent created no commit
/// anywhere. The `retain` such a run carries comes only from the fail-closed
/// empty-scan guards (an unborn repo has no anchor, so the nets cannot PROVE
/// completeness) — it is not evidence a commit exists. The caller must not let
/// that retain count as `has_commits` for the empty-result check (a quiet
/// no-op agent on an unborn base would otherwise bypass the empty-result
/// failure contract).
///
/// The still-unborn HEAD probe alone is not sufficient: an agent that committed
/// on the only branch and then deleted it leaves HEAD unborn with the commit
/// dangling in the HEAD reflog, and on an unborn HEAD the reflog net above
/// fails closed (it cannot enumerate the log). So the verdict additionally
/// requires the HEAD reflog to be ABSENT (see `head_reflog_is_absent`) — the
/// state of a genuine no-op. A present-but-unreadable reflog (the orphaned-
/// commit shape) keeps `unborn_no_ref` clear so the caller does not fail the
/// run as empty and wipe the run dir holding the only copy.
///
/// The probe uses `--verify --quiet`: a bare `rev-parse --verify HEAD` exits
/// 128 on an unborn HEAD, which `git()` surfaces as Err — indistinguishable
/// from a real scan failure. `--quiet` downgrades "no such ref" to exit 1 with
/// no stderr, so `Ok("")` is the definitive no-ref answer and `Err` is a
/// genuine failure. A read failure leaves `unborn_no_ref` false (the
/// conservative "may hold work" default).
async fn mark_unborn_no_ref(
    out: &mut GitResult,
    prep: &GitPrep,
    workspace: &CwdHandle,
    timeout: Duration,
) {
    if !(prep.start_sha.is_none() && !out.work_found && out.commits.is_empty()) {
        return;
    }
    // A TRUNCATED/capped/failed safety-net enumeration (see
    // `GitResult::scan_incomplete`) means finalize examined only a partial view
    // of the repo's refs/reflog, in which an agent commit could still be hiding
    // beyond what it saw. `commits`/`work_found` being empty then proves
    // nothing — the scan never reached the parked commit. Marking the run as
    // proven-unborn here would let the caller fail it as empty and wipe the run
    // dir holding that commit's only copy, so require every net to have run to
    // completion before claiming "no commit anywhere".
    if out.scan_incomplete {
        return;
    }
    // `git rev-parse --verify --quiet HEAD` exits 0 with the SHA when HEAD
    // resolves, 1 with empty stdout on an unborn HEAD (the expected no-ref
    // state), and 128 on a real error. `git()` maps ALL nonzero exits to Err,
    // which would conflate the legitimate unborn state (1) with a scan failure
    // (128), so read the RAW exit status: only the definitive `1` + empty
    // stdout proves "no commit anywhere". `0` (a commit exists) and any other
    // outcome leave `unborn_no_ref` false — the conservative "may hold work"
    // default.
    let status = git_raw_status(
        &[
            "rev-parse".into(),
            "--verify".into(),
            "--quiet".into(),
            "HEAD".into(),
        ],
        Some(workspace),
        timeout,
    )
    .await;
    // A still-unborn HEAD is necessary but NOT sufficient: the agent may have
    // committed and then orphaned the commit (deleted the only branch), leaving
    // HEAD unborn again with the commit dangling in the HEAD reflog. On an
    // unborn HEAD `git reflog show HEAD` exits 128, so the reflog net above
    // failed closed and set `retain` — which here means "a commit may dangle",
    // not "no work". Distinguish the genuine no-op (no HEAD reflog was ever
    // written) from an orphaned commit (a reflog exists but is unreadable on
    // the unborn HEAD): only the former proves the agent created no commit.
    //
    // Read `.git/logs/HEAD` through the pinned checkout handle (fd-relative,
    // no-follow) so a same-UID actor swapping a path component cannot redirect
    // the probe outside the validated tree. Any open/read error — missing git
    // dir, a symlinked component, I/O failure — is the conservative "may hold
    // work" default and leaves `unborn_no_ref` false.
    if !head_reflog_is_absent(workspace) {
        return;
    }
    if status == Some(1) {
        log(
            "finalize: repository is still unborn (no commit on any ref) — the run made no \
             commits; the retained run dir holds no agent work",
        );
        out.unborn_no_ref = true;
    }
}

/// Probe whether the checkout's HEAD reflog (`.git/logs/HEAD`) is ABSENT —
/// the state of a genuine no-op on an unborn base (no commit was ever made, so
/// no reflog entry exists). Returns `true` only when the file is definitively
/// not there; `false` when it exists (a commit was written, then possibly
/// orphaned) or cannot be read (the conservative "may hold work" answer).
///
/// The walk is fd-relative and no-follow through the pinned checkout handle:
/// `.git` and `logs` are opened as directories with `O_NOFOLLOW`, and the leaf
/// `HEAD` is matched by name from `logs`'s own `getdents` — so a symlinked
/// component or a swapped ancestor yields an open/read error (→ `false`),
/// never a redirect outside the validated tree.
fn head_reflog_is_absent(workspace: &CwdHandle) -> bool {
    use std::os::unix::ffi::OsStrExt;
    // `.git` must exist in a provisioned checkout; a missing/unopenable `.git`
    // is anomalous, so fail closed (false — "may hold work").
    let git = match workspace.open_child(std::ffi::OsStr::new(".git")) {
        Ok(d) => d,
        Err(_) => return false,
    };
    // A missing `logs/` directory is the genuine no-op: git creates it lazily on
    // the first reflog write, so no `logs/` means no commit was ever recorded.
    // Any OTHER open error (a symlinked component, I/O failure) fails closed.
    let logs = match git.open_child(std::ffi::OsStr::new("logs")) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    let logs_path = match logs.path() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let entries = match std::fs::read_dir(&logs_path) {
        Ok(rd) => rd,
        Err(_) => return false,
    };
    for e in entries.flatten() {
        if e.file_name().as_bytes() == b"HEAD" {
            return false; // a reflog exists — a commit was written
        }
    }
    true
}

/// Run git and return its RAW exit code (`Some(0)`/`Some(1)`/…), or `None` on
/// a spawn/wait/timeout failure. Unlike [`git`], a nonzero exit is NOT an
/// error — needed by probes like `rev-parse --verify --quiet`, whose exit `1`
/// is the definitive "no such ref" answer, not a failure. Stdout/stderr are
/// drained (bounded) so the child never blocks, but discarded: the caller
/// wants only the status. Same cwd-pinning, env-scrubbing, timeout, and
/// process-group cleanup as [`git_with_env_capture`].
async fn git_raw_status(
    args: &[String],
    cwd: Option<&CwdHandle>,
    timeout: Duration,
) -> Option<i32> {
    use std::process::Stdio;
    let mut cmd = Command::new("git");
    cmd.args(args);
    cmd.kill_on_drop(true);
    if let Some(dir) = cwd {
        dir.apply(&mut cmd).ok()?;
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    for k in crate::slot::SENSITIVE_DAEMON_ENV {
        cmd.env_remove(k);
    }
    for k in GIT_CONFIG_INJECTION_ENV {
        cmd.env_remove(k);
    }
    for (k, _) in std::env::vars_os() {
        if k.to_str()
            .is_some_and(|s| s.starts_with("GIT_CONFIG_KEY_") || s.starts_with("GIT_CONFIG_VALUE_"))
        {
            cmd.env_remove(&k);
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(unix)]
    crate::pdeath::arm(&mut cmd);
    let mut child = cmd.spawn().ok()?;
    #[cfg(unix)]
    let gpid = child.id();
    #[cfg(unix)]
    if let Some(pid) = gpid {
        crate::pdeath::watch(pid);
    }
    #[cfg(unix)]
    let mut group_guard = crate::pdeath::GroupGuard::new(gpid);
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
        let (status, _err, _out) = tokio::join!(child.wait(), drain_err, drain_out);
        status
    };
    let status = match tokio::time::timeout(timeout, wait).await {
        Ok(res) => {
            #[cfg(unix)]
            {
                crate::pdeath::terminate_group_and_reap(
                    &mut child,
                    group_guard.guard(),
                    Duration::from_secs(3),
                )
                .await;
                group_guard.disarm();
            }
            res.ok()?.code()
        }
        Err(_) => {
            // Reuse the spawn-time guard (never a fresh signal-time capture) so a
            // recycled pgid is declined (issue #27).
            #[cfg(unix)]
            {
                group_guard.kill_group_if_ours();
                group_guard.disarm();
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
            None
        }
    };
    status
}

/// A clean, self-contained git administrative context for the credentialed
/// finalize push and its post-error verification. It borrows the workspace's
/// object store (via `objects/info/alternates`) and pins the work-branch tip,
/// but carries its OWN empty `config`/`HEAD` — so no agent-writable
/// `.git/config` / `config.worktree` / `include` chain is in the push's config
/// search path. This removes the scrub-then-use race outright: there is no
/// mutable local config for a detached agent helper to rewrite between a scrub
/// and the spawn.
///
/// The context lives INSIDE the per-job run directory (a sibling of the
/// agent's checkout), not the shared system temp dir: the run dir is prepared
/// mode `0700` under a `0700` runs root and pinned no-follow, so it is not
/// readable or writable by *other* UIDs and a world-writable temp dir's
/// post-creation tamper window is closed. Dropping it removes the directory.
///
/// RESIDUAL RISK (accepted, see nano-supervisor#45): the daemon's documented
/// model is "host sandbox only" — the agent runs as the SAME UID as the daemon
/// (no setuid / namespace / chroot; only process-group + pdeath containment).
/// `0700` excludes only *other* UIDs, so a same-UID agent is NOT barred from
/// the run dir: it can traverse upward from its checkout (`cd ..`), watch for
/// the `.nano-finalize-push-*` context dir, and reopen/mutate its `config`,
/// refs, or `objects/info/alternates` before `git push` reads them. The clean
/// context removes the agent-writable *config search path* (the scrub-then-use
/// race), but it does NOT provide OS-level isolation of the context from a
/// same-UID agent. Real isolation (a different UID / sandbox / an unlinked
/// capability) is a deliberate, out-of-scope architectural change; do not read
/// this comment as asserting it exists.
struct FinalizePushContext {
    /// The context git-dir's absolute path (inside the run dir). The push and
    /// verification reference it via `--git-dir=<dir>`; `Drop` removes it.
    dir: PathBuf,
    /// The work-branch tip SHA pinned at build time (the trusted local state).
    branch_tip: String,
}

impl Drop for FinalizePushContext {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Build a clean git administrative context for the finalize push. Rather than
/// scrub the agent-mutable `.git/config` in place and then spawn the push from
/// the same checkout (a scrub-then-use race), finalize runs the credentialed
/// push from a temporary git-dir that:
///
///   * borrows the workspace's object store via `objects/info/alternates`, so
///     the branch's commits are visible without copying them;
///   * pins the work-branch tip as its own `refs/heads/<branch>` ref, so the
///     explicit-URL push resolves the source ref; and
///   * has an empty `config` and a `HEAD`, so git treats it as a valid
///     repository yet reads NO agent-writable local/worktree config (and no
///     `include`d file) — the entire class of local-config redirect/MITM is
///     absent from the search path, not merely scrubbed-then-raced.
///
/// The branch tip is read from the workspace BEFORE the context is built (the
/// workspace's refs/objects are trusted repo state; only its *config* is
/// agent-mutable). Any failure fails CLOSED: the caller skips the push and
/// retains the run dir rather than risk a redirect.
///
/// The context is created as a direct child of the run dir (the workspace's
/// parent), never the shared temp dir, so it inherits the run dir's `0700`
/// no-follow protection against *other* UIDs. It does NOT isolate the context
/// from a same-UID agent (see the `FinalizePushContext` docs for the accepted
/// residual risk). `workspace` is the pinned checkout handle; its parent is the
/// pinned run dir.
async fn finalize_push_context(
    workspace: &CwdHandle,
    branch: &str,
    timeout: Duration,
    deadline: Instant,
) -> Result<FinalizePushContext> {
    // The two git probes below share the finalize stage's overall `deadline`
    // with every other scan: a fixed per-probe timeout would let this helper
    // overrun the stage budget by up to two full timeouts after earlier scans
    // already consumed it. Recompute the remaining budget before EACH probe
    // (`remaining` = min(per-command `timeout`, time left to `deadline`)); once
    // the deadline has passed this is ~0, so the probe times out immediately
    // and the caller fails closed (retains the run dir) instead of pushing on a
    // half-finished scan.
    let remaining = |timeout: Duration| -> Duration {
        match deadline.checked_duration_since(Instant::now()) {
            Some(r) if !r.is_zero() => r.min(timeout),
            _ => Duration::from_nanos(1),
        }
    };
    // Resolve the work-branch tip from the workspace's refs. This is the only
    // workspace read the push depends on; it carries no config influence.
    let tip = git(
        &[
            "rev-parse".into(),
            "--verify".into(),
            format!("refs/heads/{branch}^{{commit}}"),
        ],
        Some(workspace),
        remaining(timeout),
        None,
    )
    .await
    .context("resolving the work-branch tip for the clean push context")?;
    let branch_tip = tip.trim().to_string();
    if branch_tip.is_empty() {
        bail!("the work branch {branch:?} has no resolvable tip");
    }

    // The workspace's on-disk path and object store. Resolve the real git-dir
    // rather than assuming `<workspace>/.git`: a normal clone has a `.git`
    // directory, but a hostile agent could replace it with a gitdir-pointer
    // file (or the checkout could be a linked worktree), so derive the object
    // store from git's own resolution. `--absolute-git-dir` always returns an
    // absolute path, so no re-anchoring to the workspace is needed.
    let git_dir = git(
        &["rev-parse".into(), "--absolute-git-dir".into()],
        Some(workspace),
        remaining(timeout),
        None,
    )
    .await
    .context("resolving the workspace git-dir for the clean push context")?;
    let git_dir = git_dir.trim();
    if git_dir.is_empty() {
        bail!("the workspace git-dir did not resolve");
    }
    let objects = Path::new(git_dir).join("objects");
    let objects = std::fs::canonicalize(&objects)
        .with_context(|| format!("canonicalizing the object store {}", objects.display()))?;
    if !objects.is_dir() {
        bail!(
            "the workspace object store {} is not a directory",
            objects.display()
        );
    }

    // Fresh, supervisor-owned context git-dir created as a direct child of the
    // run dir (the workspace's parent), never the shared system temp dir. The
    // run dir is prepared mode `0700` under a `0700` runs root and pinned
    // no-follow, so the context is protected from *other* UIDs — closing the
    // post-creation tamper window a world-writable temp dir would leave open.
    // It is NOT isolated from a same-UID agent (which can traverse upward from
    // its checkout into the run dir); that residual risk is accepted under the
    // daemon's "host sandbox only" model — see the `FinalizePushContext` docs.
    // The name is a
    // single component carrying a process/clock-unique suffix (no agent
    // influence); the uniqueness also keeps the tests — which place their
    // workspace directly under the shared temp dir — from colliding on a fixed
    // name.
    let run_dir_path = workspace
        .path()
        .context("recovering the pinned checkout path")?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("the checkout has no parent run dir"))?
        .to_path_buf();
    let uniq = format!(
        ".nano-finalize-push-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        // Process-local sequence: two concurrent finalizers in this worker can
        // observe the same clock tick (or a backward-moving clock), so pid+nanos
        // alone is not unique and the second `create_dir` would spuriously fail,
        // leaving pushable work retained. The counter makes each name distinct.
        FINALIZE_CTX_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let dir = run_dir_path.join(uniq);
    std::fs::create_dir(&dir)
        .with_context(|| format!("creating the clean push context {}", dir.display()))?;
    let info = dir.join("objects").join("info");
    std::fs::create_dir_all(&info)
        .with_context(|| format!("creating the clean push context {}", info.display()))?;
    std::fs::create_dir_all(dir.join("refs").join("heads"))
        .with_context(|| "creating the clean push context refs dir".to_string())?;
    // Borrow the workspace's object store. Write the alternates pointer before
    // any git invocation so the context can resolve the branch tip's objects.
    std::fs::write(info.join("alternates"), format!("{}\n", objects.display()))
        .with_context(|| "writing the object-store alternates pointer".to_string())?;
    // A valid repo needs a HEAD; point it at the work branch (the ref is pinned
    // below). An empty config means no local/worktree/include state applies.
    std::fs::write(dir.join("HEAD"), format!("ref: refs/heads/{branch}\n"))
        .with_context(|| "writing the clean context HEAD".to_string())?;
    std::fs::write(dir.join("config"), "")
        .with_context(|| "writing the clean context config".to_string())?;
    // Pin the work-branch tip as the context's own ref so the explicit-URL push
    // resolves `refs/heads/<branch>` without touching the workspace's refs. The
    // branch name can carry slashes (`feat/work`), so create its parent dirs.
    let ref_path = dir.join("refs").join("heads").join(branch);
    if let Some(parent) = ref_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| "creating the clean context ref parent dirs".to_string())?;
    }
    std::fs::write(&ref_path, format!("{branch_tip}\n"))
        .with_context(|| "pinning the work-branch tip in the clean context".to_string())?;

    Ok(FinalizePushContext { dir, branch_tip })
}

/// After a finalize push returns an error, decide whether the branch's commits
/// are nevertheless durable on the trusted remote. A nonzero/timed-out
/// `git push` is NOT proof the ref was not updated: the server can accept the
/// fast-forward and apply it before the client sees the response. Fetch the
/// branch from the SAME trusted `fetch_url`, under the SAME clean-context
/// isolation the push used (`cfg` carries the `--git-dir`/`-c` prefix), then:
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
    push_ctx: &FinalizePushContext,
    cfg: &[String],
    fetch_url: &str,
    branch: &str,
    cred: Option<&GitCredential>,
    timeout: Duration,
    deadline: Instant,
) -> Option<bool> {
    // This helper runs up to THREE git subprocesses serially (`ls-remote`,
    // `fetch`, `merge-base`). Handing each the SAME full `timeout` would let the
    // verification path consume ~3× the remaining stage budget; and ignoring the
    // stage `deadline` would let it overrun the budget entirely after the push
    // already consumed it. Recompute the remaining budget before EACH command
    // (`remaining` = min(per-command `timeout`, time left to `deadline`)); once
    // the deadline has passed this is ~0, so the next command times out
    // immediately and the run fails closed (retained) rather than sweeping on an
    // inconclusive verification.
    let remaining = |timeout: Duration| -> Duration {
        match deadline.checked_duration_since(Instant::now()) {
            Some(r) if !r.is_zero() => r.min(timeout),
            _ => Duration::from_nanos(1),
        }
    };
    // The branch tip pinned into the clean context at build time is the trusted
    // local state (just prepared/committed); read it back from the context's own
    // ref, never from the agent-mutable checkout.
    let local_tip = push_ctx.branch_tip.clone();
    if local_tip.is_empty() {
        return None;
    }
    // Ask the trusted remote for the branch's current tip (no local fetch/merge
    // side effects): `ls-remote <url> refs/heads/<branch>` → `<sha>\t<ref>`. Run
    // from the clean context (cwd None) so no agent-mutable config applies.
    let mut ls = cfg.to_vec();
    ls.push("ls-remote".into());
    ls.push("--".into());
    ls.push(fetch_url.to_string());
    ls.push(format!("refs/heads/{branch}"));
    let listing = git_isolated(&ls, None, remaining(timeout), cred)
        .await
        .ok()?;
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
    // so fetch it into the clean context's object store (via its alternate) over
    // the same trusted channel; if we cannot obtain it, fail closed (unconfirmed).
    let mut fetch = cfg.to_vec();
    fetch.push("fetch".into());
    fetch.push("--no-tags".into());
    fetch.push("--".into());
    fetch.push(fetch_url.to_string());
    fetch.push(format!("refs/heads/{branch}"));
    git_isolated(&fetch, None, remaining(timeout), cred)
        .await
        .ok()?;
    // `merge-base` must run against the SAME clean context the fetch wrote
    // into: without `cfg`'s `--git-dir` prefix (and with `cwd=None`) git cannot
    // find a repository at all and exits "not a git repository", which
    // `.is_ok()` would misread as "not an ancestor" — reporting a landed,
    // fast-forwarded push as unconfirmed (`pushed = false`, retained). Prefix
    // the command with `cfg` exactly like the `ls-remote`/`fetch` above.
    let mut mb = cfg.to_vec();
    mb.push("merge-base".into());
    mb.push("--is-ancestor".into());
    mb.push(local_tip);
    mb.push(remote_tip);
    let landed = git_isolated(&mb, None, remaining(timeout), None)
        .await
        .is_ok();
    Some(landed)
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
const GIT_CONFIG_INJECTION_ENV: &[&str] =
    &["GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"];

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
                // after provisioning "succeeds". The spawn-time `group_guard` (not a
                // fresh capture) verifies the group's identity, so this is a no-op
                // when git left nothing behind and does not re-signal a recycled
                // pgid outside the accepted residual windows (see
                // `pdeath::GroupIdentity`).
                #[cfg(unix)]
                {
                    crate::pdeath::terminate_group_and_reap(
                        &mut child,
                        group_guard.guard(),
                        Duration::from_secs(3),
                    )
                    .await;
                    group_guard.disarm();
                }
                res
            }
            Err(_) => {
                // Timed out: SIGKILL the whole group (not just the leader that
                // `kill_on_drop` reaps) so a helper git spawned cannot outlive it.
                // Reuse the guard captured at spawn (`group_guard`, line ~733)
                // rather than re-capturing the pgid's identity here: the `wait`
                // future (and its `child.wait()`) is dropped when the timeout fires,
                // so if git and every descendant exited in that interval the pgid can
                // be released and recycled by an unrelated group before this call. A
                // fresh `PgidGuard::capture` at signal time would read *that*
                // recycled group's identity and bless it; the spawn-time guard still
                // holds git's original identity, so `kill_group_if_ours` declines a
                // recycled pgid (issue #27) — upholding the guard's guarantee.
                #[cfg(unix)]
                {
                    group_guard.kill_group_if_ours();
                    group_guard.disarm();
                }
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

    /// A generous stage deadline for the push-context/verification helpers:
    /// these tests exercise the happy path (no expiry), so supply a deadline far
    /// in the future and let the per-command `timeout` govern.
    fn test_deadline() -> Instant {
        Instant::now() + Duration::from_secs(300)
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
            &[
                "checkout".into(),
                "-B".into(),
                "develop".into(),
                "--".into(),
            ],
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
        assert_eq!(
            on.trim(),
            branch,
            "the checkout must move onto the fallback"
        );
        assert_ne!(
            on.trim(),
            "develop",
            "the shared default must never stay the work branch"
        );
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
            &[
                "checkout".into(),
                "-B".into(),
                "feat/work".into(),
                "--".into(),
            ],
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
        // The verification runs from a clean push context built over the
        // workspace's object store + branch tip.
        let ctx = finalize_push_context(&dir, "feat/work", t, test_deadline())
            .await
            .unwrap();
        // Before the branch exists on the remote: not published.
        assert_eq!(
            remote_contains_branch_tip(&ctx, &[], &url, "feat/work", None, t, test_deadline())
                .await,
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
            remote_contains_branch_tip(&ctx, &[], &url, "feat/work", None, t, test_deadline())
                .await,
            Some(true),
            "an equal remote tip must confirm the push landed despite the error"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
    }

    #[tokio::test]
    async fn remote_contains_branch_tip_confirms_a_fast_forwarded_remote() {
        // Regression for the descendant-confirmation finding: when the push's
        // response is lost AND the remote branch is then fast-forwarded on top
        // of our tip, the remote tip differs from the local tip, so finalize
        // must fetch it and run `merge-base --is-ancestor` against the SAME
        // clean context (`--git-dir`). Without that prefix the command cannot
        // find a repository and `.is_ok()` misreads the failure as "not an
        // ancestor", reporting a durable push as unconfirmed.
        let dir = git_workspace("verify-push-ff").await;
        let t = Duration::from_secs(30);
        git(
            &[
                "checkout".into(),
                "-B".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        commit(&dir, "durable work").await;
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-verifyff-{}-{}",
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
        // The verification context is built over the workspace's object store +
        // branch tip; `cfg` carries its `--git-dir` prefix, exactly as the real
        // finalize caller passes it.
        let ctx = finalize_push_context(&dir, "feat/work", t, test_deadline())
            .await
            .unwrap();
        let cfg: Vec<String> = vec![
            format!("--git-dir={}", ctx.dir.display()),
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
        ];
        // Publish our tip, then fast-forward the remote with a descendant commit
        // (someone built on top before our lost response was retried).
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
        commit(&dir, "someone else fast-forwards").await;
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
        // The remote tip is now a DESCENDANT of the context's pinned tip: the
        // push must be confirmed durable, not reported unconfirmed.
        assert_eq!(
            remote_contains_branch_tip(&ctx, &cfg, &url, "feat/work", None, t, test_deadline())
                .await,
            Some(true),
            "a remote tip that is a descendant of ours must confirm the push landed"
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
            &[
                "checkout".into(),
                "--detach".into(),
                legacy_tip.trim().into(),
            ],
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
        assert!(
            res.pushed,
            "the clean work branch pushes to the reachable remote"
        );
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
        git(
            &["add".into(), ".".into(), "--".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        commit(&dir, "add tracked file").await;
        std::fs::write(
            dir_path(&dir).join("f.txt"),
            "v2 WIP — the stash holds the only copy\n",
        )
        .unwrap();
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
        assert!(
            res.work_found,
            "the stash net records that real work exists"
        );
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
        git(
            &["tag".into(), "v-keep".into(), newsha.clone()],
            Some(&dir),
            t,
            None,
        )
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
        git(
            &["tag".into(), "v-ok".into(), "HEAD".into()],
            Some(&dir),
            t,
            None,
        )
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
        git(
            &["checkout".into(), "--detach".into(), "HEAD".into()],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();
        let prep = prepare_work_branch(&dir, &test_repo(), None, None, true, "udp", t).await;
        let b = prep.working_branch.clone();
        assert!(
            b.as_deref()
                .is_some_and(|b| b.starts_with("nano/agent-work/")),
            "a push-enabled detached provision must cut a fallback branch, got {b:?}"
        );
        let head = git(
            &["symbolic-ref".into(), "--short".into(), "HEAD".into()],
            Some(&dir),
            t,
            None,
        )
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
        git(
            &["checkout".into(), "--detach".into(), "HEAD".into()],
            Some(&dir),
            t,
            None,
        )
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
        for v in [
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "GIT_PROXY_COMMAND",
        ] {
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
        // The finalize push hands git the trusted `fetch_url` positionally, but a
        // local `url.<attacker>.insteadOf = <fetch_url>` rewrite would silently
        // redirect it off-box. finalize runs the push from a clean git admin
        // context that never reads the checkout's local config, so the push lands
        // on the TRUSTED destination despite the rewrite.
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
            format!("[url \"file:///nonexistent/attacker2\"]\n\tpushInsteadOf = {trusted}\n"),
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
    async fn finalize_push_context_lives_inside_the_run_dir() {
        // Regression for the writable-temp-context finding (HIGH): the clean
        // push context must NOT be created under the shared, world-writable
        // system temp dir (where ANY process — including one of another UID —
        // could watch for it and mutate its config/refs/alternates after
        // construction). It must live inside the per-job run dir — the
        // workspace's parent — which is prepared mode 0700 under a 0700 runs
        // root, so it is protected from other UIDs. (It is not isolated from a
        // same-UID agent; that residual risk is accepted — see the
        // `FinalizePushContext` docs.)
        let dir = git_workspace("fin-ctxloc").await;
        git(
            &[
                "checkout".into(),
                "-B".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work").await;
        let ctx =
            finalize_push_context(&dir, "feat/work", Duration::from_secs(30), test_deadline())
                .await
                .unwrap();
        let workspace = dir_path(&dir);
        let run_dir = workspace
            .parent()
            .expect("the checkout has a parent run dir");
        assert_eq!(
            ctx.dir.parent(),
            Some(run_dir),
            "the push context must be a direct child of the run dir (which production prepares \
             mode 0700 under a 0700 runs root), not a sibling of the checkout in a shared temp dir"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_push_ignores_local_config_planted_after_context_build() {
        // Regression for the scrub-then-use race (HIGH): the credentialed push
        // must run from a clean git administrative context that never reads the
        // checkout's mutable local config. A rewrite planted in `.git/config`
        // AFTER the push context is built (standing in for a detached agent
        // helper rewriting config between a scrub and the spawn) must NOT affect
        // the push — the clean context has no agent-writable config in its search
        // path, so there is nothing to race over.
        let dir = git_workspace("fin-toctou").await;
        let t = Duration::from_secs(30);
        let bare = std::env::temp_dir().join(format!(
            "nano-bare-toctou-{}-{}",
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
        let trusted = format!("file://{}", bare.display());
        repo.url = trusted.clone();
        let prep = prepare_work_branch(&dir, &repo, None, Some("feat/work"), true, "u77", t).await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "work to push").await;

        // Build the clean push context FIRST (as finalize does), THEN plant the
        // malicious rewrite in the checkout's local config — the exact ordering a
        // scrub-then-use race would need to exploit.
        let ctx = finalize_push_context(&dir, "feat/work", t, test_deadline())
            .await
            .unwrap();
        git(
            &[
                "config".into(),
                "--local".into(),
                "url.file:///nonexistent/toctou-attacker.insteadOf".into(),
                trusted.clone(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap();

        // Run the push from the clean context (mirroring finalize's push args).
        let cfg: Vec<String> = vec![
            format!("--git-dir={}", ctx.dir.display()),
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
        ];
        let mut args = cfg.clone();
        args.push("push".into());
        args.push("--".into());
        args.push(trusted.clone());
        args.push("refs/heads/feat/work:refs/heads/feat/work".into());
        git_isolated(&args, None, t, None)
            .await
            .expect("the push must reach the trusted URL, ignoring the late-planted local rewrite");
        let on_remote = git(
            &[
                "--git-dir".into(),
                bare.to_string_lossy().into_owned(),
                "rev-parse".into(),
                "--verify".into(),
                "refs/heads/feat/work".into(),
            ],
            None,
            t,
            None,
        )
        .await;
        assert!(
            on_remote.is_ok(),
            "the work branch must land on the trusted URL; a local rewrite planted after the \
             context build must not redirect it"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
        let _ = std::fs::remove_dir_all(&bare);
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
        let pre_sha = git(&["rev-parse".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap()
            .trim()
            .to_string();
        git(&["checkout".into(), "main".into()], Some(&dir), t, None)
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
        let prep = prepare_work_branch(
            &dir,
            &repo,
            Some("main"),
            Some("feat/work"),
            true,
            "u-rt",
            t,
        )
        .await;
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

        let prep = prepare_work_branch(
            &dir,
            &repo,
            Some("main"),
            Some("feat/work"),
            true,
            "u-rtp",
            t,
        )
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
        assert!(
            cred.is_none(),
            "a credential-free source yields no credential"
        );

        // Remote URLs and absolute paths pass through unchanged.
        let (remote, _) = trusted_fetch_source("https://github.com/o/r.git");
        assert_eq!(remote, "https://github.com/o/r.git");
        let abs = if cfg!(windows) {
            "C:/x/y.git"
        } else {
            "/x/y.git"
        };
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
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/side".into(),
                "--".into(),
            ],
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
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
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
    async fn finalize_marks_still_unborn_repo_no_ref() {
        // Regression for the slot-side empty-result bypass: on an unborn base
        // where the agent made NO commit, the empty-scan guards retain
        // (fail closed — they cannot prove completeness with no anchor), but
        // finalize must ALSO mark the proven-unborn verdict so the caller does
        // not read that retain as evidence a commit exists (which would let a
        // quiet no-op agent bypass the empty-result failure contract).
        let dir = empty_base_workspace("unborn-noop").await;
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            res.unborn_no_ref,
            "a no-op run on an unborn base must be marked unborn_no_ref (retain={}, work_found={}, commits={:?})",
            res.retain,
            res.work_found,
            res.commits
        );
        assert!(
            !res.work_found && res.commits.is_empty(),
            "a no-op run reports no work and no commits (work_found={}, commits={:?})",
            res.work_found,
            res.commits
        );
        assert!(
            !res.pushed,
            "nothing was created, so nothing can have been pushed"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_mark_unborn_no_ref_when_agent_committed() {
        // Companion: on an unborn base where the agent DID commit on the work
        // branch, the verdict must stay clear — the run holds real work.
        let dir = empty_base_workspace("unborn-commit").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "first work").await;
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(30)).await;
        assert!(
            !res.unborn_no_ref,
            "a committing run on an unborn base must NOT be marked unborn_no_ref"
        );
        assert_eq!(res.commits.len(), 1, "the first commit is enumerated");
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_mark_unborn_no_ref_for_stranded_work_on_empty_base() {
        // Companion: a stranded side-branch commit on an unborn base sets
        // `work_found` (and `retain`), so the proven-unborn verdict must stay
        // clear — the run dir holds the only copy of real work.
        let dir = empty_base_workspace("unborn-side").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/side".into(),
                "--".into(),
            ],
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
            res.retain && res.work_found,
            "stranded side-branch work flags retain+work_found (retain={}, work_found={})",
            res.retain,
            res.work_found
        );
        assert!(
            !res.unborn_no_ref,
            "stranded work must NOT be marked unborn_no_ref (the dir holds the only copy)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_mark_unborn_no_ref_for_orphaned_branch_commit() {
        // Regression for the unborn early-return: an agent that commits on the
        // ONLY branch and then deletes it (`update-ref -d`) leaves HEAD unborn
        // and `refs/heads/` empty, but the commit still dangles in the HEAD
        // reflog. Finalize must NOT mark `unborn_no_ref` from the HEAD probe
        // alone and return before the nets — the slot would fail the run as
        // empty and the retry would wipe the run dir holding the only copy.
        // The nets run first (fail closed: the reflog net cannot enumerate an
        // unborn HEAD's log, so it retains), and the end-of-function verdict
        // stays clear.
        let dir = empty_base_workspace("unborn-orphan").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        // Delete the only branch: HEAD is unborn again, the commit dangles.
        git(
            &[
                "update-ref".into(),
                "-d".into(),
                "refs/heads/feat/work".into(),
            ],
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
            !res.unborn_no_ref,
            "an orphaned commit on an unborn base must NOT be marked unborn_no_ref \
             (the dir holds the only copy; retain={}, work_found={}, commits={:?})",
            res.retain, res.work_found, res.commits
        );
        assert!(
            res.retain,
            "the nets fail closed on the orphaned commit (retain keeps the run dir)"
        );
        assert!(
            !res.pushed,
            "nothing publishable: the only branch was deleted"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_mark_unborn_no_ref_when_nonhead_ref_listing_overflows() {
        // Regression for the inconclusive-scan bypass (scan_incomplete): an agent
        // on an UNBORN base can `commit-tree` work, park it under a NON-head ref
        // (never moving HEAD, so no HEAD reflog), and pad the ref set until the
        // non-head `for-each-ref refs/` listing overflows the capture cap. That
        // leaves `retain=true, work_found=false, commits=[]` with an unborn HEAD
        // and ABSENT HEAD reflog — the exact shape the unborn verdict keyed on —
        // yet the parked commit's only copy is in the run dir. Finalize must NOT
        // mark `unborn_no_ref` (which would let the caller fail the run as empty
        // and wipe it); the truncated scan is not proof of "no work".
        let dir = empty_base_workspace("unborn-nonhead-overflow").await;
        let t = Duration::from_secs(30);
        // The empty tree is always valid, so `commit-tree` yields a parked commit
        // on the unborn base without touching HEAD or any branch.
        let sha = git(
            &[
                "-c".into(),
                "user.email=t@t".into(),
                "-c".into(),
                "user.name=t".into(),
                "commit-tree".into(),
                "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
                "-m".into(),
                "parked work".into(),
            ],
            Some(&dir),
            t,
            None,
        )
        .await
        .unwrap()
        .trim()
        .to_string();
        // Park it under enough long-named NON-head refs to drive the
        // `for-each-ref refs/` listing past the 1 MiB capture cap. Writing
        // packed-refs directly keeps the fixture fast.
        let packed = dir_path(&dir).join(".git").join("packed-refs");
        let pad = "a".repeat(220);
        let mut blob = String::new();
        if !packed.exists() {
            blob.push_str("# pack-refs with: peeled fully-peeled\n");
        }
        for i in 0..6000 {
            blob.push_str(&format!("{sha} refs/tags/zpad/{pad}/{i:05}\n"));
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&packed)
                .unwrap();
            f.write_all(blob.as_bytes()).unwrap();
        }
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), t).await;
        assert!(
            !res.unborn_no_ref,
            "an overflowing non-head-ref scan is inconclusive, so the run must NOT be marked \
             unborn_no_ref (retain={}, work_found={}, commits={:?})",
            res.retain, res.work_found, res.commits
        );
        assert!(
            res.retain,
            "the overflowing non-head-ref scan fails closed (retain keeps the run dir)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_does_not_mark_unborn_no_ref_when_nonhead_candidates_exceed_cap() {
        // Companion variant: the non-head-ref candidate set can exceed
        // `MAX_REFLOG_SCAN` even when the listing itself does NOT overflow the
        // capture cap — the agent parks MANY distinct commits under short-named
        // non-head refs. The capped sweep is still truncated, so a parked commit
        // beyond the cap could be missed; finalize must NOT mark `unborn_no_ref`.
        let dir = empty_base_workspace("unborn-nonhead-cap").await;
        let t = Duration::from_secs(30);
        // `MAX_REFLOG_SCAN + 1` DISTINCT parked commits (distinct messages →
        // distinct SHAs over the same empty tree), each under its own short
        // non-head ref so the listing stays well under the capture cap and the
        // sweep reaches the candidate-count cap.
        let mut blob = String::new();
        let packed = dir_path(&dir).join(".git").join("packed-refs");
        if !packed.exists() {
            blob.push_str("# pack-refs with: peeled fully-peeled\n");
        }
        for i in 0..(MAX_REFLOG_SCAN + 1) {
            let sha = git(
                &[
                    "-c".into(),
                    "user.email=t@t".into(),
                    "-c".into(),
                    "user.name=t".into(),
                    "commit-tree".into(),
                    "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
                    "-m".into(),
                    format!("parked {i}"),
                ],
                Some(&dir),
                t,
                None,
            )
            .await
            .unwrap()
            .trim()
            .to_string();
            blob.push_str(&format!("{sha} refs/custom/{i:05}\n"));
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&packed)
                .unwrap();
            f.write_all(blob.as_bytes()).unwrap();
        }
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), t).await;
        assert!(
            !res.unborn_no_ref,
            "an over-cap non-head-ref candidate set is inconclusive, so the run must NOT be \
             marked unborn_no_ref (retain={}, work_found={}, commits={:?})",
            res.retain, res.work_found, res.commits
        );
        assert!(
            res.retain,
            "the over-cap non-head-ref scan fails closed (retain keeps the run dir)"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_reflog_scan_breaks_at_cap_without_quadratic_dedup() {
        // Regression for the quadratic de-dup: the HEAD-reflog net must stop
        // de-duplicating as soon as the distinct count exceeds
        // `MAX_REFLOG_SCAN` (O(1) HashSet membership, early break), failing
        // closed as unbounded — not linear-probe a `Vec` for every one of an
        // agent-controlled reflog's lines before the cap guard fires.
        let dir = git_workspace("reflog-cap").await; // checkout on `main`, one commit
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
        // Inflate the HEAD reflog past the cap with distinct positions. Each
        // `--allow-empty` commit + reset pair appends two DISTINCT SHAs, so
        // MAX_REFLOG_SCAN/2 iterations already overflow it.
        for i in 0..(MAX_REFLOG_SCAN / 2 + 4) {
            commit(&dir, &format!("churn {i}")).await;
            git(
                &["reset".into(), "--hard".into(), start.clone()],
                Some(&dir),
                Duration::from_secs(30),
                None,
            )
            .await
            .unwrap();
        }
        let prep = GitPrep {
            working_branch: Some("main".into()),
            want_push: false,
            start_sha: Some(start.clone()),
            provision_tips: Some(std::collections::BTreeMap::from([(
                "main".to_string(),
                start.clone(),
            )])),
            provision_shas: Some(std::collections::BTreeSet::from([start])),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_secs(60)).await;
        assert!(
            res.retain,
            "a HEAD reflog past the distinct-position cap must fail closed as unbounded"
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
            &[
                "checkout".into(),
                "-b".into(),
                "feat/side".into(),
                "--".into(),
            ],
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
        let branch = prep
            .working_branch
            .clone()
            .expect("a fallback branch is cut");
        // Commit clean work on the work branch, then strand a commit on a side
        // branch and switch back.
        commit(&dir, "clean work-branch commit").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/side".into(),
                "--".into(),
            ],
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
        let prep = prepare_work_branch(
            &dir,
            &test_repo(),
            None,
            None,
            true,
            "u6",
            Duration::from_secs(30),
        )
        .await;
        let branch = prep
            .working_branch
            .clone()
            .expect("a fallback branch is cut");
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
        assert!(
            res.retain,
            "a stranded detached-HEAD commit must flag retain"
        );
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
        assert_eq!(
            complete_last, maximum,
            "complete listing ends at the maximum"
        );
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
        assert_eq!(
            complete_first, minimum,
            "complete listing starts at the minimum"
        );
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
            &[
                "symbolic-ref".into(),
                "--short".into(),
                "-q".into(),
                "HEAD".into(),
            ],
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
            &[
                "checkout".into(),
                "-b".into(),
                "agent-side".into(),
                "--".into(),
            ],
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
        .expect(
            "control: the non-isolated push must land on the ATTACKER repo, proving the \
                 planted insteadOf rewrite redirects the trusted URL",
        );
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
    async fn finalize_fails_closed_when_side_branch_listing_overflows_capture_cap() {
        // The side-branch sweep enumerates `refs/heads/` with `git_untruncated`,
        // which keeps only the LAST bytes of stdout under the 1 MiB capture cap.
        // The prior probe-based "completeness proof" was defeatable: the capture
        // can cut in the MIDDLE of a ref name, so an agent could pad the listing
        // until the surviving suffix of a late ref equals the true minimum name
        // and passes both the min and max anchors while the early-sorting
        // branches hiding stranded work were dropped. `git_untruncated` closes
        // that class structurally — a listing larger than the capture cap is
        // refused outright, so finalize fails closed (retain, no push) rather
        // than trusting a truncated tail.
        let dir = git_workspace("fin-overflow").await;
        let t = Duration::from_secs(30);
        let prep =
            prepare_work_branch(&dir, &test_repo(), None, Some("feat/work"), true, "ov1", t).await;
        assert_eq!(prep.working_branch.as_deref(), Some("feat/work"));
        commit(&dir, "work to push").await;
        let sha = git(&["rev-parse".into(), "HEAD".into()], Some(&dir), t, None)
            .await
            .unwrap()
            .trim()
            .to_string();
        // Pack enough long-named heads to drive the `refs/heads/` listing well
        // past the 1 MiB capture cap (each `refname:short` line is ~230 bytes).
        // Writing packed-refs directly keeps the fixture fast — no thousands of
        // serial `git branch` invocations.
        let packed = dir_path(&dir).join(".git").join("packed-refs");
        let pad = "a".repeat(220);
        let mut blob = String::new();
        if !packed.exists() {
            blob.push_str("# pack-refs with: peeled fully-peeled\n");
        }
        for i in 0..6000 {
            blob.push_str(&format!("{sha} refs/heads/zpad/{pad}/{i:05}\n"));
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&packed)
                .unwrap();
            f.write_all(blob.as_bytes()).unwrap();
        }
        let res = finalize_git(&dir, &prep, &test_repo(), t).await;
        assert!(
            res.retain,
            "an overflowing side-branch listing must fail closed and retain the run dir"
        );
        assert!(
            !res.pushed,
            "the push is refused when the side-branch listing overflows the capture cap"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
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

    #[test]
    fn finalize_deadline_budget_bounds_the_whole_stage() {
        // Regression for the missing overall finalize deadline (MEDIUM): the
        // per-command `timeout` alone does not bound the stage, because finalize
        // launches many git subprocesses SERIALLY (per side branch / reflog
        // position / non-head candidate, up to the scan caps). The stage budget
        // must be a small multiple of the per-command timeout — far below
        // scan-caps × timeout (which would be hours at the default 120 s) — with
        // a floor so a tiny configured timeout stays usable.
        let per_command = Duration::from_secs(120);
        let budget = finalize_deadline_budget(per_command);
        // Bounded: the whole stage must finish well under the per-caps product
        // (512+512+512 commands × 120 s ≈ 51 hours). 8× is 16 minutes.
        assert_eq!(budget, Duration::from_secs(960));
        assert!(
            budget < per_command * 512,
            "the stage budget must be far below scan-caps × per-command timeout"
        );
        // The floor keeps a tiny configured timeout from making the deadline
        // unusably tight.
        assert_eq!(
            finalize_deadline_budget(Duration::from_secs(1)),
            Duration::from_secs(60)
        );
    }

    #[tokio::test]
    async fn finalize_overall_deadline_fails_closed_and_returns_promptly() {
        // Regression for the missing overall finalize deadline: with an
        // already-EXPIRED overall deadline, finalize must not launch its serial
        // chain of git subprocesses — the very first `remaining!()` must hit the
        // genuine expiry branch (`checked_duration_since` → `None`), yield a
        // near-zero budget, and the error path must map that to `retain` (fail
        // closed) and return promptly. This drives the real deadline-expiry
        // branch by injecting a deadline in the PAST; a large per-command
        // `timeout` is used deliberately so that the ONLY thing forcing the
        // immediate timeout is the exhausted overall deadline — if the deadline
        // machinery were removed, this test would hang for the full per-command
        // timeout instead of returning promptly.
        let dir = empty_base_workspace("deadline").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        // Deadline already in the past + a LARGE per-command timeout: the
        // near-zero remaining budget comes solely from the exhausted overall
        // deadline, so this exercises the genuine expiry branch (not merely a
        // tiny per-command timeout).
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test clock is far enough from the epoch to subtract 1 s");
        let started = std::time::Instant::now();
        let res = finalize_git_with_deadline(
            &dir,
            &prep,
            &test_repo(),
            Duration::from_secs(300),
            expired,
        )
        .await;
        let elapsed = started.elapsed();
        assert!(
            res.retain,
            "an exhausted finalize budget must fail closed and retain the run dir"
        );
        assert!(
            !res.pushed,
            "an incomplete (deadline-expired) scan must never report a clean push"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "finalize must return promptly once the overall deadline is exhausted (took \
             {elapsed:?}); with the deadline machinery intact the near-zero remaining budget \
             forces every probe to time out immediately despite the 300 s per-command timeout"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }

    #[tokio::test]
    async fn finalize_per_command_timeout_fails_closed() {
        // Companion to the overall-deadline test: even when the overall deadline
        // is NOT exhausted, a tiny per-command `timeout` must still make every
        // git subprocess time out and fail CLOSED (retain), never report a clean
        // push. `remaining!()` returns `min(budget_left, timeout)`, so a 1 ns
        // per-command timeout dominates and each probe times out at once.
        let dir = empty_base_workspace("per-command").await;
        git(
            &[
                "checkout".into(),
                "-b".into(),
                "feat/work".into(),
                "--".into(),
            ],
            Some(&dir),
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();
        commit(&dir, "work commit").await;
        let prep = GitPrep {
            working_branch: Some("feat/work".into()),
            want_push: true,
            start_sha: None,
            provision_tips: Some(std::collections::BTreeMap::new()),
            provision_shas: Some(std::collections::BTreeSet::new()),
        };
        let res = finalize_git(&dir, &prep, &test_repo(), Duration::from_nanos(1)).await;
        assert!(
            res.retain,
            "a per-command timeout that expires every probe must fail closed and retain"
        );
        assert!(
            !res.pushed,
            "an incomplete (timed-out) scan must never report a clean push"
        );
        let _ = std::fs::remove_dir_all(dir_path(&dir));
    }
}
