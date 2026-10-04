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
use std::path::{Path, PathBuf};

/// Lexically normalize a run-directory path: resolve every `.`/`..` component
/// **without touching the filesystem** (no symlink is ever followed), so the
/// result is an absolute path free of parent components.
///
/// This runs at the run-path *input boundary* (the slot resolving
/// `<runs_dir>/<key>`), not on the untrusted tail: `..` between existing
/// directories is resolved against the trusted current directory lexically,
/// which is exactly how the kernel resolves it (a parent component traverses
/// the *directory entry*, never a symlink), while the not-yet-created job-dir
/// tail is left literal. Normalizing here keeps a parent-relative
/// `--runs-dir ../runs` working on every backend — the Linux `openat2`
/// resolution accepts interior `..`, but the portable `O_NOFOLLOW` chain
/// resolves it against its pinned parent fd, which is *not* path resolution
/// (a renamed ancestor would silently redirect the descent) — and gives both
/// backends one identical, already-normalized path.
///
/// A relative input is anchored at the current directory first (the same
/// anchor the launch backends resolve a relative path against). Like the
/// kernel, a `..` at the filesystem root is a no-op (clamps at `/`); only a
/// RELATIVE input that climbs above its anchor is refused (the anchor is the
/// process cwd, so that can only mean malformed input).
pub(crate) fn normalize_run_path(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;
    let anchored: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut out = PathBuf::new();
    for comp in anchored.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::Normal(name) => out.push(name),
            Component::ParentDir => {
                // `out` always holds at least the root/prefix here (the input
                // was anchored), so a `pop` that empties it means a `..` AT the
                // root: the kernel clamps that to `/`, so keep the root rather
                // than error — a parent-relative `--runs-dir` is legitimate.
                let _ = out.pop();
                if out.as_os_str().is_empty() {
                    out.push(Component::RootDir.as_os_str());
                }
            }
        }
    }
    Ok(out)
}

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

#[cfg(unix)]
impl Clone for CwdHandle {
    /// A second handle to the SAME pinned inode (a close-on-exec dup of the
    /// fd), so the capability can be carried by several consumers (the agent
    /// launch, the HEAD probes) without re-resolving the path.
    fn clone(&self) -> Self {
        // `dup_fd` only fails on a genuine fd-table/OS error; treat that like
        // any other fd-ownership failure here (there is no `TryClone`).
        let fd = self.dup_fd().expect("dup the pinned directory fd");
        CwdHandle { fd }
    }
}

#[cfg(not(unix))]
impl Clone for CwdHandle {
    fn clone(&self) -> Self {
        CwdHandle {
            path: self.path.clone(),
        }
    }
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

    /// `apply`, for a synchronous [`std::process::Command`]. The bounded
    /// `git rev-parse HEAD` probe (`slot::git_head_timeout`) drives its child
    /// synchronously, and the tests drive one too; both bind the pinned fd the
    /// same way the async [`apply`](Self::apply) does.
    #[cfg(unix)]
    pub(crate) fn apply_std(&self, cmd: &mut std::process::Command) -> io::Result<()> {
        // SAFETY: as `apply` — async-signal-safe `fchdir` in the pre-exec child.
        unsafe {
            arm_fchdir(cmd, self.dup_fd()?);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn apply_std(&self, cmd: &mut std::process::Command) -> io::Result<()> {
        cmd.current_dir(&self.path);
        Ok(())
    }

    /// Pin a direct child directory of this handle, never following a symlink
    /// at the child and never leaving this directory. Because the open is
    /// anchored on the pinned fd, a rename or symlink swap of any *ancestor*
    /// cannot redirect it, and a same-UID actor replacing the child itself
    /// between provisioning and this open is bound to whatever the name
    /// resolves to *now* — so the launch that then binds the returned handle
    /// can never land in a tree swapped in afterwards. `name` must be a single
    /// path component.
    #[cfg(unix)]
    pub(crate) fn open_child(&self, name: &std::ffi::OsStr) -> io::Result<CwdHandle> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty()
            || name_bytes.contains(&b'/')
            || name_bytes == b"."
            || name_bytes == b".."
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "open_child expects a single path component",
            ));
        }
        let c = CString::new(name_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component has NUL"))?;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor just returned by `openat`.
        Ok(CwdHandle {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn open_child(&self, name: &std::ffi::OsStr) -> io::Result<CwdHandle> {
        let path = self.path.join(name);
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing symlinked working directory",
            ));
        }
        Ok(CwdHandle { path })
    }

    /// The absolute path of the pinned directory *right now*, recovered through
    /// the fd (`fchdir` + `getcwd`) rather than remembered from resolution
    /// time, so it still names the pinned inode after an ancestor rename. Used
    /// where a path string is genuinely required — the ACP `session/new` `cwd`
    /// — so the value sent to the agent is the same directory the launch bound,
    /// never a pre-swap pathname. On non-Unix hosts this is the (leaf-validated)
    /// path the handle was opened from.
    #[cfg(unix)]
    pub(crate) fn path(&self) -> io::Result<PathBuf> {
        use std::os::unix::io::AsRawFd;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        // Save the process cwd, fchdir into the pinned fd, read getcwd, then
        // restore — all plain libc, no Rust state the restore could race.
        // SAFETY: `saved`/`self.fd` are valid fds; `buf` is writable for its
        // length and NUL-terminated by `getcwd` on success.
        unsafe {
            let saved = libc::open(
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            );
            if saved < 0 {
                return Err(io::Error::last_os_error());
            }
            let body = (|| {
                if libc::fchdir(self.fd.as_raw_fd()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getcwd(buf.as_mut_ptr().cast(), buf.len()).is_null() {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })();
            // ALWAYS restore the process cwd before propagating any error: a
            // failed `getcwd` with the process left inside the pinned dir
            // would silently redirect every later relative resolution.
            let restore = libc::fchdir(saved);
            libc::close(saved);
            if restore != 0 {
                return Err(io::Error::last_os_error());
            }
            body?;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(
            std::ffi::OsStr::from_bytes(&buf[..len]).to_os_string(),
        ))
    }

    #[cfg(not(unix))]
    pub(crate) fn path(&self) -> io::Result<PathBuf> {
        Ok(self.path.clone())
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
            // `..` is resolved against the pinned parent fd — matching the
            // `openat2` backend, which resolves interior `..` against the real
            // parent directory — so both backends enforce one consistent
            // interior-parent policy. Callers pass run paths already
            // lexically normalized by `normalize_run_path`, so this only ever
            // sees a `..` a caller constructed by hand; resolving it here
            // (rather than refusing) keeps the two backends from diverging on
            // the same input. Note this is *fd-relative* traversal, not path
            // resolution: the kernel's `..` lookup on the pinned fd follows
            // the directory entry, never a symlink.
            Component::ParentDir => {
                let dir = match cur.as_ref() {
                    Some(d) => d,
                    None => {
                        let c = CString::new(".".as_bytes()).unwrap();
                        cur = Some(open_dir(&c, base_flags)?);
                        cur.as_ref().unwrap()
                    }
                };
                let c = CString::new("..".as_bytes()).unwrap();
                // No O_NOFOLLOW: `..` is never a symlink, and the lookup is
                // anchored on the pinned parent fd.
                let next = openat_dir(dir.as_raw_fd(), &c, base_flags)?;
                cur = Some(next);
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

#[cfg(test)]
mod normalize_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn normalize_run_path_resolves_parents_lexically() {
        // Interior `..` collapses without touching the filesystem.
        let got = normalize_run_path(Path::new("/a/b/../c/./d")).unwrap();
        assert_eq!(got, PathBuf::from("/a/c/d"));
        // A leading `..` on an absolute path clamps at the root like the kernel.
        let got = normalize_run_path(Path::new("/a/../../b")).unwrap();
        assert_eq!(got, PathBuf::from("/b"));
        // A relative input is anchored at the current directory.
        let got = normalize_run_path(Path::new("x/../y")).unwrap();
        assert_eq!(got, std::env::current_dir().unwrap().join("y"));
        // A `..` run that climbs past the root clamps at `/` like the kernel
        // (the relative form is anchored at the cwd first, so it can never
        // actually escape — this is the absolute-path clamp applied uniformly).
        let got = normalize_run_path(Path::new("/../../../../../../..")).unwrap();
        assert_eq!(got, PathBuf::from("/"));
    }
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

    /// `open_child` pins the child *relative to the pinned parent fd*, so
    /// swapping an ancestor for a symlink after the parent was opened cannot
    /// redirect the descent — the child handle still names the real inode.
    #[test]
    fn open_child_survives_an_ancestor_swap() {
        let base = scratch("child-swap");
        let ancestor = base.join("ancestor");
        let run = ancestor.join("run");
        std::fs::create_dir_all(run.join("repo")).unwrap();
        std::fs::write(run.join("repo").join("real-marker"), b"real").unwrap();

        let run_handle = CwdHandle::open(&run).expect("open run dir");

        // Swap the ancestor for a symlink to an attacker tree.
        let moved = base.join("ancestor-moved");
        std::fs::rename(&ancestor, &moved).unwrap();
        let evil = base.join("evil");
        std::fs::create_dir_all(evil.join("run").join("repo")).unwrap();
        std::fs::write(
            evil.join("run").join("repo").join("evil-marker"),
            b"attacker",
        )
        .unwrap();
        std::os::unix::fs::symlink(&evil, &ancestor).unwrap();

        // The child open is anchored on the pinned run-dir fd, so it lands in
        // the real inode even though the path now resolves to the attacker.
        let child = run_handle.open_child(std::ffi::OsStr::new("repo")).unwrap();
        let landed = std::fs::canonicalize(child_cwd(&child)).unwrap();
        assert_eq!(
            landed,
            std::fs::canonicalize(moved.join("run").join("repo")).unwrap(),
            "open_child must stay under the pinned parent after an ancestor swap"
        );
        assert!(landed.join("real-marker").exists());
        assert!(!landed.join("evil-marker").exists());

        // And the handle still reports the pinned inode's current path.
        let reported = child.path().expect("path of pinned child");
        assert_eq!(
            std::fs::canonicalize(reported).unwrap(),
            std::fs::canonicalize(moved.join("run").join("repo")).unwrap(),
            "path() must name the pinned inode, not a pre-swap pathname"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn open_child_refuses_a_symlinked_child() {
        let base = scratch("child-link");
        let run = base.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, run.join("repo")).unwrap();
        let run_handle = CwdHandle::open(&run).expect("open run dir");
        assert!(
            run_handle.open_child(std::ffi::OsStr::new("repo")).is_err(),
            "a symlinked child must be refused"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn interior_parent_resolves_against_the_pinned_parent() {
        // Both backends accept an interior `..` and resolve it identically —
        // against the real parent directory, never through a symlink. The
        // walked-through `x` must EXIST: the chain opens each component to pin
        // it before the `..` climbs back to the real parent.
        let base = scratch("dotdot");
        let run = base.join("a").join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(base.join("a").join("x")).unwrap();
        std::fs::write(run.join("marker"), b"real").unwrap();
        let via_parent = base.join("a").join("x").join("..").join("run");
        let handle = CwdHandle::open(&via_parent).expect("open via interior ..");
        let landed = std::fs::canonicalize(child_cwd(&handle)).unwrap();
        assert_eq!(landed, std::fs::canonicalize(&run).unwrap());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn parent_dir_at_the_root_clamps_like_the_kernel() {
        // `..` at `/` is a no-op for the kernel (`/..` == `/`); the chain must
        // match so a normalized path can never diverge between backends. This
        // is the fd-relative walk resolving `..` against the pinned root fd.
        let handle = CwdHandle::open(Path::new("/..")).expect("/.. must clamp to /");
        let landed = std::fs::canonicalize(child_cwd(&handle)).unwrap();
        assert_eq!(landed, std::fs::canonicalize(Path::new("/")).unwrap());
    }
}
