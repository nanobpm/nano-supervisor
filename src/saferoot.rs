//! Symlink-race-free directory operations for the run-directory provisioning
//! and sweep paths (Linux `openat2(RESOLVE_NO_SYMLINKS)` pinned handles).
//!
//! `sweep_stale_runs` and `prepare_run_dir` operate on a `runs_dir` that can
//! sit under a world-writable ancestor on a shared host. Validating the path
//! with `symlink_metadata` and *then* calling `read_dir` / `remove_dir_all` /
//! `create_dir_all` is a time-of-check/time-of-use race: a same-UID actor can
//! swap `runs_dir` (or an ancestor) for a symlink in the window between the
//! path check and the operation, redirecting the traversal or removal to a
//! target outside the validated workspace. No amount of *re-checking the path*
//! closes that window — each check is itself a fresh, non-atomic resolution.
//!
//! This module closes it on Linux by resolving `runs_dir` **once** with
//! [`libc::SYS_openat2`] and `RESOLVE_NO_SYMLINKS`: the kernel refuses to
//! traverse any symlink in the path and returns a directory handle pinned to
//! the resolved inode. Every subsequent stat / read / unlink / mkdir is then
//! performed *relative to that handle* with the `*at` syscalls (and, for
//! descendants, `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`), so no later path
//! re-resolution — and therefore no swapped component — can redirect it.
//!
//! `openat2` needs Linux 5.6+. When the kernel is older the syscall returns
//! `ENOSYS`, surfaced here as [`PinError::Unsupported`] so the caller can fall
//! back to the best-effort path-based checks. This whole module is
//! `#[cfg(target_os = "linux")]`; other Unix platforms use the path-based path.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{self, ErrorKind};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `struct open_how` (linux/openat2.h). `libc::open_how` is `#[non_exhaustive]`
/// and so cannot be constructed with a struct literal here; this is a
/// byte-compatible local mirror we pass to the raw `openat2` syscall.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// `resolve` flags (linux/openat2.h). `RESOLVE_NO_SYMLINKS` refuses to traverse
// *any* symlink while resolving the path; `RESOLVE_BENEATH` additionally forbids
// escaping the anchor directory (e.g. via `..`) — used for every descendant
// open so a traversal can never climb out of the pinned root.
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// The reason a pinned-handle operation could not be performed.
#[derive(Debug)]
pub(crate) enum PinError {
    /// The running kernel lacks `openat2` (pre-5.6). The caller should fall
    /// back to the path-based implementation rather than treat this as a
    /// failure — no security decision has been made yet.
    Unsupported,
    /// A genuine I/O error, **including a refused symlinked component**
    /// (`openat2` returns `ELOOP`). A refusal is a real, security-relevant
    /// outcome and must NOT be downgraded to a path-based retry.
    Io(io::Error),
}

impl From<io::Error> for PinError {
    fn from(e: io::Error) -> Self {
        PinError::Io(e)
    }
}

/// Metadata of a directory entry as seen by `lstat` (never following the entry
/// itself), enough to drive the sweep's triage.
pub(crate) struct EntryMeta {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub modified: Option<SystemTime>,
}

/// A directory handle pinned by inode: obtained via `openat2` so the path it
/// was resolved from contained no symlink, and stable against later renames of
/// its path components. All operations are performed relative to it.
pub(crate) struct DirHandle {
    fd: OwnedFd,
}

fn cstr(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "path component contains NUL"))
}

/// The common open-flag set for a directory handle we only stat/read/unlink
/// through: read-only, must be a directory, close-on-exec, never follow the
/// final component.
fn dir_open_flags() -> u64 {
    (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64
}

/// Raw `openat2` wrapper. `dirfd`/`path` anchor the resolution; `resolve`
/// carries the `RESOLVE_*` hardening flags.
fn openat2_raw(dirfd: RawFd, path: &CStr, flags: u64, resolve: u64) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags,
        mode: 0,
        resolve,
    };
    // SAFETY: `how` outlives the call and its size is passed explicitly; the
    // kernel copies it. A non-negative return is a fresh, owned fd.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const OpenHow,
            mem::size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `ret` is a valid, freshly opened file descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

impl DirHandle {
    /// Resolve `path` from the current working directory with
    /// `RESOLVE_NO_SYMLINKS` and pin the result. A symlinked component anywhere
    /// in `path` is refused (`ELOOP` → [`PinError::Io`]); a missing kernel
    /// syscall is [`PinError::Unsupported`]. `path` may be absolute, so
    /// `RESOLVE_BENEATH` is intentionally NOT set on this anchoring open.
    pub(crate) fn open_root_nofollow(path: &Path) -> Result<DirHandle, PinError> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| PinError::Io(io::Error::new(ErrorKind::InvalidInput, "path has NUL")))?;
        match openat2_raw(
            libc::AT_FDCWD,
            &c,
            (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            RESOLVE_NO_SYMLINKS,
        ) {
            Ok(fd) => Ok(DirHandle { fd }),
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => Err(PinError::Unsupported),
            Err(e) => Err(PinError::Io(e)),
        }
    }

    /// Open a direct child directory relative to this handle, never following a
    /// symlink and never escaping this directory
    /// (`RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`).
    pub(crate) fn open_child_dir(&self, name: &OsStr) -> io::Result<DirHandle> {
        let c = cstr(name)?;
        let fd = openat2_raw(
            self.fd.as_raw_fd(),
            &c,
            dir_open_flags(),
            RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
        )?;
        Ok(DirHandle { fd })
    }

    /// `lstat` a direct child (relative, never following the entry).
    pub(crate) fn symlink_metadata(&self, name: &OsStr) -> io::Result<EntryMeta> {
        let c = cstr(name)?;
        // SAFETY: zeroed `stat` is a valid target; `fstatat` fully initialises
        // the fields we read on success.
        let mut st: libc::stat = unsafe { mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        let fmt = st.st_mode & libc::S_IFMT;
        let modified = if st.st_mtime >= 0 {
            Some(
                UNIX_EPOCH
                    + Duration::new(
                        st.st_mtime as u64,
                        (st.st_mtime_nsec as u32) % 1_000_000_000,
                    ),
            )
        } else {
            None
        };
        Ok(EntryMeta {
            is_dir: fmt == libc::S_IFDIR,
            is_symlink: fmt == libc::S_IFLNK,
            modified,
        })
    }

    /// Enumerate this directory's entry names (excluding `.` and `..`),
    /// relative to the pinned handle. `fdopendir` consumes the fd it is given,
    /// so a duplicate is used and the original pinned fd is left intact.
    pub(crate) fn entry_names(&self) -> io::Result<Vec<OsString>> {
        // SAFETY: dup of a valid fd; ownership of `dupfd` is handed to
        // `fdopendir` (closed by `closedir`), or closed directly on the error
        // path below.
        let dupfd = unsafe { libc::dup(self.fd.as_raw_fd()) };
        if dupfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let dirp = unsafe { libc::fdopendir(dupfd) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            unsafe { libc::close(dupfd) };
            return Err(e);
        }
        // `dup` shares the underlying open file description — and thus the
        // directory read offset — with `self.fd`. A prior enumeration (or one
        // on another dup of the same handle) can have advanced that shared
        // offset to EOF, so a fresh `fdopendir` would resume past the end and
        // report the directory empty. Rewind to the start so every call
        // enumerates the full, current contents; this also makes `entry_names`
        // safe to call again after the directory has been mutated (e.g. the
        // sweep's post-reap emptiness check).
        unsafe { libc::rewinddir(dirp) };
        let mut names = Vec::new();
        loop {
            // The classic `while ((e = readdir(d)))` idiom: a NULL return is
            // end-of-directory. (Best-effort: a rare mid-stream error also ends
            // enumeration, which for the sweep merely defers reaping.)
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                break;
            }
            // SAFETY: `d_name` is a NUL-terminated C string within the entry.
            let cs = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            let bytes = cs.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsStr::from_bytes(bytes).to_os_string());
        }
        unsafe { libc::closedir(dirp) };
        Ok(names)
    }

    /// Recursively remove a direct child (`name`) relative to this handle,
    /// never following a symlink at any level. A directory is descended through
    /// its own pinned handle and emptied before an `AT_REMOVEDIR` unlink; a
    /// file or symlink entry is unlinked directly (so a symlinked entry deletes
    /// the *link*, never its target). A missing entry is treated as success.
    pub(crate) fn remove_tree(&self, name: &OsStr) -> io::Result<()> {
        let meta = match self.symlink_metadata(name) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let c = cstr(name)?;
        if meta.is_dir && !meta.is_symlink {
            // Descend through a pinned handle so the recursion cannot be
            // redirected by a component swapped after this stat.
            let child = self.open_child_dir(name)?;
            for entry in child.entry_names()? {
                child.remove_tree(&entry)?;
            }
            self.unlink_at(&c, libc::AT_REMOVEDIR)
        } else {
            self.unlink_at(&c, 0)
        }
    }

    fn unlink_at(&self, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        let r = unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), flags) };
        if r != 0 {
            let e = io::Error::last_os_error();
            if e.kind() != ErrorKind::NotFound {
                return Err(e);
            }
        }
        Ok(())
    }

    /// Restrict this directory to `mode` via `fchmod` on the pinned fd (no path
    /// re-resolution, so no swapped component can redirect the chmod).
    fn restrict_mode(&self, mode: u32) -> io::Result<()> {
        if unsafe { libc::fchmod(self.fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wipe any stale `name` under this handle, create it fresh as a directory,
    /// and lock both it and this root directory to `mode` — all relative to the
    /// pinned handle. `mkdirat` is umask-subject, so an explicit `fchmod` on the
    /// freshly pinned child makes the final mode exact regardless of umask.
    ///
    /// Returns the pinned child handle so the caller carries the *exact* inode
    /// preparation validated into the launch, instead of reopening `name` by
    /// path afterwards — a same-UID actor could replace the freshly prepared
    /// directory (or an ancestor) with an ordinary tree between this return and
    /// a later no-follow reopen, which would then bind a directory preparation
    /// never wiped or secured (#35).
    pub(crate) fn prepare_child_dir(&self, name: &OsStr, mode: u32) -> io::Result<DirHandle> {
        match self.symlink_metadata(name) {
            Ok(_) => self.remove_tree(name)?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let c = cstr(name)?;
        if unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Pin the child we just created (no-follow, beneath us) and set its mode
        // through the fd, immune to a post-mkdir swap.
        let child = self.open_child_dir(name)?;
        child.restrict_mode(mode)?;
        self.restrict_mode(mode)?;
        Ok(child)
    }

    /// Consume this handle, yielding the owned, no-follow-pinned directory fd —
    /// used to hand a freshly prepared child (e.g. a run dir) to a `CwdHandle`
    /// without reopening it by path.
    pub(crate) fn into_fd(self) -> OwnedFd {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nano-saferoot-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::canonicalize(&root).unwrap()
    }

    // `entry_names` must enumerate the full, current contents on EVERY call —
    // including a second call on the same handle and a call made after the
    // directory has been mutated. `dup` shares the open file description's read
    // offset, so without a rewind the second call would resume at EOF and
    // wrongly report the directory empty (which made the sweep delete a live
    // sibling run dir).
    #[test]
    fn entry_names_is_idempotent_and_survives_mutation() {
        let root = scratch_root("entrynames");
        for name in ["aaa", "bbb", "ccc"] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        let handle = DirHandle::open_root_nofollow(&root).expect("pin root");

        let mut first = handle.entry_names().expect("first list");
        first.sort();
        assert_eq!(
            first,
            vec![
                OsString::from("aaa"),
                OsString::from("bbb"),
                OsString::from("ccc")
            ]
        );

        // Second call on the SAME handle must see everything again, not resume
        // from the prior call's EOF offset.
        let mut second = handle.entry_names().expect("second list");
        second.sort();
        assert_eq!(
            first, second,
            "entry_names must be idempotent on a reused handle"
        );

        // After removing one child, a fresh call must report exactly the
        // survivors (and crucially NOT empty).
        handle.remove_tree(OsStr::new("aaa")).expect("remove aaa");
        let mut after = handle.entry_names().expect("post-mutation list");
        after.sort();
        assert_eq!(after, vec![OsString::from("bbb"), OsString::from("ccc")]);
        assert!(
            !after.is_empty(),
            "a non-empty dir must never list as empty"
        );

        // Remove the rest; only a genuinely empty dir lists empty.
        handle.remove_tree(OsStr::new("bbb")).unwrap();
        handle.remove_tree(OsStr::new("ccc")).unwrap();
        assert!(handle.entry_names().unwrap().is_empty());

        std::fs::remove_dir_all(&root).ok();
    }
}
