//! Cross-platform validated working-directory capability for launching child
//! processes (git subcommands, the agent) *through a pinned directory handle*
//! rather than by re-resolving a cwd *path* at spawn time.
//!
//! # Why
//!
//! #25 hardened the run-dir *creation* path: on Linux the runs root is pinned
//! with `openat2(RESOLVE_NO_SYMLINKS)` and the per-job dir is created relative
//! to that handle. But the follow-on **launches** — `git clone`/`fetch`/
//! `checkout` and the agent itself — still took the run dir as a `current_dir`
//! *path*, so the kernel re-resolved that path in the forked child right before
//! `exec`. On a shared host where the runs root can sit under a world-writable
//! ancestor, a same-UID actor can swap an ancestor component for a symlink in
//! the window between the provisioning check and the launch, redirecting the
//! child's cwd (and therefore its clone target / working tree) outside the
//! validated tree. No amount of *re-checking the path* closes that window —
//! each check is a fresh, non-atomic resolution (#35).
//!
//! # How
//!
//! Resolve the directory **once**, no-follow, into a pinned fd, then `fchdir`
//! to that fd in the child's `pre_exec` hook. The child's cwd becomes the
//! validated inode, immune to any later component swap: a rename of an
//! already-opened component cannot move the pinned inode, and a component
//! swapped to a symlink *before* it is opened is refused by the no-follow open
//! (the launch fails rather than escaping).
//!
//! Resolution is no-symlink on every supported host:
//! - **Linux ≥5.6**: `openat2(RESOLVE_NO_SYMLINKS)` refuses the whole path if
//!   any component is a symlink, in one atomic kernel resolution.
//! - **macOS / older Linux**: an `O_NOFOLLOW` `openat` chain walked component by
//!   component (the cap-std style). `O_NOFOLLOW` refuses a symlink at each
//!   `openat`'s own final component, so chaining the opens covers the whole
//!   path — and each descent is pinned by the fd we already hold, so a rename of
//!   a component we have passed cannot redirect the remainder.
//!
//! On a non-Unix host (no `fchdir`/`pre_exec`) this degrades to the prior
//! `current_dir(path)` behaviour; those targets are not supported daemon hosts.

use std::io;
use std::path::Path;

/// A directory resolved no-follow and pinned by its fd, used to launch a child
/// with its cwd set to the validated inode (via `fchdir` in `pre_exec`) rather
/// than by re-resolving a path at spawn time.
pub(crate) struct CwdHandle {
    /// The path the handle was resolved from — the non-Unix `current_dir`
    /// fallback target (on Unix the launch binds the pinned fd, not a path).
    #[cfg(not(unix))]
    path: std::path::PathBuf,
    #[cfg(unix)]
    fd: std::os::unix::io::OwnedFd,
}

impl CwdHandle {
    /// Resolve `path` as a directory without following a symlink at any
    /// component and pin the result. A symlinked component anywhere in `path`
    /// is refused (so the caller's launch fails closed instead of escaping the
    /// validated tree); a missing directory or a non-directory target is an
    /// error.
    pub(crate) fn open(path: &Path) -> io::Result<CwdHandle> {
        #[cfg(unix)]
        {
            let fd = open_nofollow(path)?;
            Ok(CwdHandle { fd })
        }
        #[cfg(not(unix))]
        {
            // No `fchdir`/`pre_exec`: fall back to validating the leaf is not a
            // symlink and then using the path. Best-effort — these are not
            // supported daemon hosts.
            let meta = std::fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing symlinked working directory",
                ));
            }
            Ok(CwdHandle {
                path: path.to_path_buf(),
            })
        }
    }

    /// Arm `cmd` to enter this pinned directory in the forked child before
    /// `exec`. On Unix this installs a `pre_exec` `fchdir` on a close-on-exec
    /// dup of the pinned fd, so the child's cwd is the validated inode and no
    /// path is re-resolved; on other hosts it sets `current_dir` to the
    /// (leaf-validated) path.
    #[cfg(unix)]
    pub(crate) fn apply(&self, cmd: &mut tokio::process::Command) -> io::Result<()> {
        // SAFETY: `pre_exec` runs in the forked child before `exec`; we only
        // call the async-signal-safe `fchdir` and touch no Rust allocator state.
        unsafe {
            arm_fchdir(cmd.as_std_mut(), self.dup_fd()?);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn apply(&self, cmd: &mut tokio::process::Command) -> io::Result<()> {
        cmd.current_dir(&self.path);
        Ok(())
    }

    /// `apply`, for a synchronous [`std::process::Command`]. Only the tests
    /// need to drive a child synchronously; the production launch sites all use
    /// the async [`apply`](Self::apply).
    #[cfg(all(unix, test))]
    pub(crate) fn apply_std(&self, cmd: &mut std::process::Command) -> io::Result<()> {
        // SAFETY: as `apply` — async-signal-safe `fchdir` in the pre-exec child.
        unsafe {
            arm_fchdir(cmd, self.dup_fd()?);
        }
        Ok(())
    }

    #[cfg(all(not(unix), test))]
    pub(crate) fn apply_std(&self, cmd: &mut std::process::Command) -> io::Result<()> {
        cmd.current_dir(&self.path);
        Ok(())
    }

    /// A close-on-exec dup of the pinned fd, moved into each `pre_exec` closure
    /// so the child-side `fchdir` target is owned by the `Command` itself and
    /// stays valid through the fork regardless of when this handle is dropped.
    #[cfg(unix)]
    fn dup_fd(&self) -> io::Result<std::os::unix::io::OwnedFd> {
        use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
        let new = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if new < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `new` is a fresh, owned fd just returned by `fcntl`.
        Ok(unsafe { OwnedFd::from_raw_fd(new) })
    }
}

/// Install a `pre_exec` hook that `fchdir`s into `fd` (consumed by the closure,
/// so it survives the fork and is closed with the `Command`). The fd is
/// close-on-exec, so it never leaks into the exec'd child — `fchdir` runs
/// *before* `exec` while the fd is still open.
#[cfg(unix)]
unsafe fn arm_fchdir<C: UnixCommandExt>(cmd: &mut C, fd: std::os::unix::io::OwnedFd) {
    use std::os::unix::io::AsRawFd;
    cmd.pre_exec_hook(move || {
        if libc::fchdir(fd.as_raw_fd()) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    });
}

/// Abstracts `std::os::unix::process::CommandExt::pre_exec` across the sync
/// `std::process::Command` and tokio's `&mut std::process::Command` view so the
/// `fchdir` hook is installed the same way for both.
#[cfg(unix)]
trait UnixCommandExt {
    unsafe fn pre_exec_hook<F>(&mut self, f: F)
    where
        F: FnMut() -> io::Result<()> + Send + Sync + 'static;
}

#[cfg(unix)]
impl UnixCommandExt for std::process::Command {
    unsafe fn pre_exec_hook<F>(&mut self, f: F)
    where
        F: FnMut() -> io::Result<()> + Send + Sync + 'static,
    {
        use std::os::unix::process::CommandExt;
        self.pre_exec(f);
    }
}

/// Resolve `path` to a pinned directory fd without following any symlink.
#[cfg(unix)]
fn open_nofollow(path: &Path) -> io::Result<std::os::unix::io::OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        match open_nofollow_openat2(path) {
            Ok(fd) => return Ok(fd),
            // Pre-5.6 kernel without `openat2`: fall back to the portable
            // `O_NOFOLLOW` `openat` chain, which gives the same no-symlink
            // guarantee component by component.
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
            Err(e) => return Err(e),
        }
    }
    open_nofollow_chain(path)
}

/// `openat2(RESOLVE_NO_SYMLINKS)` — one atomic resolution that refuses the whole
/// path if any component is a symlink. `RESOLVE_BENEATH` is intentionally not
/// set: `path` is absolute, so the resolution must be allowed to start from
/// `/` (mirroring `saferoot::DirHandle::open_root_nofollow`).
#[cfg(target_os = "linux")]
fn open_nofollow_openat2(path: &Path) -> io::Result<std::os::unix::io::OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{FromRawFd, OwnedFd};

    // `struct open_how` (linux/openat2.h). `libc::open_how` is `#[non_exhaustive]`
    // and cannot be built with a struct literal, so this is a byte-compatible
    // local mirror passed to the raw syscall.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has NUL"))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `how` outlives the call and its size is passed explicitly; a
    // non-negative return is a fresh, owned fd.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `ret` is a valid, freshly opened fd we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Portable no-symlink resolution: open each path component with `O_NOFOLLOW`
/// relative to the handle for the component before it. `O_NOFOLLOW` fails the
/// `openat` when that component is a symlink, so walking the whole path refuses
/// a symlink anywhere in it — and because each descent is anchored on the fd we
/// already hold, a rename of a component we have passed cannot redirect the
/// remainder.
#[cfg(unix)]
fn open_nofollow_chain(path: &Path) -> io::Result<std::os::unix::io::OwnedFd> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Component;

    fn open_dir(name: &std::ffi::CStr, flags: i32) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::open(name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn openat_dir(dirfd: i32, name: &std::ffi::CStr, flags: i32) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    let base_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let step_flags = base_flags | libc::O_NOFOLLOW;

    let mut cur: Option<OwnedFd> = None;
    for comp in path.components() {
        match comp {
            // `/` and `.` are never symlinks; open the anchor without
            // `O_NOFOLLOW` so a legitimate root/relative base is accepted.
            Component::RootDir => {
                let c = CString::new("/".as_bytes()).unwrap();
                cur = Some(open_dir(&c, base_flags)?);
            }
            Component::CurDir => {
                if cur.is_none() {
                    let c = CString::new(".".as_bytes()).unwrap();
                    cur = Some(open_dir(&c, base_flags)?);
                }
            }
            Component::Normal(name) => {
                // A relative path with no explicit `.` anchors at the cwd.
                let dir = match cur.as_ref() {
                    Some(d) => d,
                    None => {
                        let c = CString::new(".".as_bytes()).unwrap();
                        cur = Some(open_dir(&c, base_flags)?);
                        cur.as_ref().unwrap()
                    }
                };
                let c = CString::new(name.as_bytes())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has NUL"))?;
                let next = openat_dir(dir.as_raw_fd(), &c, step_flags)?;
                cur = Some(next);
            }
            // `..` could climb out of the validated prefix; refuse it rather
            // than resolve it. The run-dir paths this is used for are
            // normalized absolute paths that never contain `..`.
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing `..` in a validated working directory",
                ));
            }
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected path prefix",
                ));
            }
        }
    }
    cur.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty working directory path"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nano-safecwd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::canonicalize(&root).unwrap()
    }

    /// The child's cwd must be the pinned directory (compared by canonical
    /// path, so platform symlinks like macOS `/var` → `/private/var` do not
    /// confuse the assertion).
    fn child_cwd(handle: &CwdHandle) -> PathBuf {
        let mut cmd = Command::new("pwd");
        cmd.arg("-P");
        handle.apply_std(&mut cmd).expect("arm fchdir");
        let out = cmd.output().expect("run pwd");
        assert!(out.status.success(), "pwd failed");
        let s = String::from_utf8(out.stdout).unwrap();
        PathBuf::from(s.trim())
    }

    #[test]
    fn launches_in_the_pinned_directory() {
        let dir = scratch("happy");
        let handle = CwdHandle::open(&dir).expect("open dir");
        assert_eq!(
            std::fs::canonicalize(child_cwd(&handle)).unwrap(),
            std::fs::canonicalize(&dir).unwrap(),
            "child cwd must be the pinned directory"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_a_symlinked_leaf() {
        let base = scratch("leaf");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            CwdHandle::open(&link).is_err(),
            "a symlinked leaf must be refused"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn refuses_a_symlinked_ancestor() {
        let base = scratch("ancestor");
        let real = base.join("real");
        std::fs::create_dir_all(real.join("child")).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // `<base>/link/child` reaches a real dir only *through* the symlink.
        assert!(
            CwdHandle::open(&link.join("child")).is_err(),
            "a path through a symlinked ancestor must be refused"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// The core #35 guarantee: once the handle is pinned, swapping an ancestor
    /// for a symlink *between provisioning and launch* cannot redirect the
    /// child — it still lands in the original validated inode, never the
    /// attacker's target.
    #[test]
    fn ancestor_swapped_after_open_does_not_redirect_the_launch() {
        let base = scratch("toctou");
        let ancestor = base.join("ancestor");
        let run = ancestor.join("run");
        std::fs::create_dir_all(&run).unwrap();
        // A marker identifying the real pinned inode.
        std::fs::write(run.join("real-marker"), b"real").unwrap();

        // Provision-time: resolve + pin the validated run dir.
        let handle = CwdHandle::open(&run).expect("open run dir");

        // Attacker swaps the ancestor for a symlink to a directory they control,
        // in the window before launch. The real subtree is moved aside (so the
        // pinned inode stays linked and reachable) and `<base>/ancestor` is
        // repointed at an evil tree, so the *path* `<base>/ancestor/run` now
        // resolves to the attacker's directory.
        let moved = base.join("ancestor-moved");
        std::fs::rename(&ancestor, &moved).unwrap();
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join("run")).unwrap();
        std::fs::write(evil.join("run").join("evil-marker"), b"attacker").unwrap();
        std::os::unix::fs::symlink(&evil, &ancestor).unwrap();

        // Launch still lands in the pinned inode (now at `moved/run`), never the
        // swapped-in attacker target the path would now resolve to.
        let landed = std::fs::canonicalize(child_cwd(&handle)).unwrap();
        assert_eq!(
            landed,
            std::fs::canonicalize(moved.join("run")).unwrap(),
            "pinned launch must stay in the validated inode after an ancestor swap"
        );
        assert!(
            landed.join("real-marker").exists(),
            "launch must land in the real validated inode"
        );
        assert!(
            !landed.join("evil-marker").exists(),
            "launch must not land in the attacker-controlled target"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
