//! Symlink-race-free directory operations for the run-directory provisioning
//! and sweep paths, via directory handles pinned by inode.
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
//! This module closes it by resolving `runs_dir` **once**, no-follow, into a
//! directory handle pinned to the resolved inode. Every subsequent stat / read
//! / unlink / mkdir is then performed *relative to that handle* with the `*at`
//! syscalls, so no later path re-resolution — and therefore no swapped
//! component — can redirect it. The no-follow resolution backend is:
//! - **Linux ≥5.6**: `openat2(RESOLVE_NO_SYMLINKS)` refuses the whole path if
//!   any component is a symlink, in one atomic kernel resolution.
//! - **macOS / older Linux / any Unix**: an `O_NOFOLLOW` `openat` chain walked
//!   component by component (the cap-std style). `O_NOFOLLOW` refuses a symlink
//!   at each `openat`'s own final component, so chaining the opens covers the
//!   whole path — and each descent is pinned by the fd already held, so a
//!   rename of a component already passed cannot redirect the remainder.
//!
//! This whole module is Unix-only (`#[cfg(unix)]`); a non-Unix host keeps the
//! prior best-effort path-based checks (those are not supported daemon hosts).

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{self, ErrorKind};
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `struct open_how` (linux/openat2.h). `libc::open_how` is `#[non_exhaustive]`
/// and so cannot be constructed with a struct literal here; this is a
/// byte-compatible local mirror we pass to the raw `openat2` syscall.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const RESOLVE_BENEATH: u64 = 0x08;

/// The reason a pinned-handle operation could not be performed: a genuine I/O
/// error, **including a refused symlinked component** (`openat2` returns
/// `ELOOP`; the portable chain returns `ELOOP`/`EINVAL`). A refusal is a real,
/// security-relevant outcome and must NOT be downgraded to a path-based retry.
///
/// (The portable `O_NOFOLLOW` chain means a no-follow resolution is always
/// available on Unix, so there is no longer an "unsupported platform" case.)
#[derive(Debug)]
pub(crate) enum PinError {
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

/// A directory handle pinned by inode: resolved no-follow (so the path it was
/// resolved from contained no symlink) and stable against later renames of its
/// path components. All operations are performed relative to it.
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
///
/// Returns `i32` — the natural type of the `libc::O_*` constants and of the
/// portable `libc::openat` flags argument. The Linux `openat2` path takes a
/// `u64` `flags` field, so it widens this with `as u64` at its call site.
/// Sharing the helper across both backends keeps it used on every Unix host
/// (a Linux-only caller would leave it dead on macOS, failing `-D warnings`).
fn dir_open_flags() -> i32 {
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
}

/// Raw `openat2` wrapper. `dirfd`/`path` anchor the resolution; `resolve`
/// carries the `RESOLVE_*` hardening flags.
#[cfg(target_os = "linux")]
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
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `ret` is a valid, freshly opened file descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// Portable no-follow resolution of `path` to a pinned directory fd: an
/// `O_NOFOLLOW` `openat` chain walked component by component (the cap-std
/// style), used where `openat2` is unavailable (non-Linux, or a pre-5.6
/// kernel). `O_NOFOLLOW` refuses a symlink at each `openat`'s own final
/// component, so chaining the opens covers the whole path; each descent is
/// anchored on the fd already held, so a rename of a component already passed
/// cannot redirect the remainder. Mirrors `safecwd::open_nofollow_chain`.
///
/// Intermediate components are opened traversal-only where the platform offers
/// it (Linux `O_PATH`, macOS `O_SEARCH`), so a run dir beneath a search-only
/// ancestor (mode `0111`, no read bit) still resolves — ordinary traversal
/// needs only the ancestor's search permission, not its read bit, and the
/// `openat2` backend imposes no such extra ancestor-read requirement. On Linux
/// an `O_PATH` + `O_NOFOLLOW` open does not *fail* on a symlink — it opens the
/// link itself — so a symlinked intermediate is caught with an `fstat`
/// `S_ISLNK` check after the open (the leaf's `O_RDONLY` + `O_NOFOLLOW` open
/// refuses a symlinked leaf outright, as does every component on macOS).
fn open_nofollow_chain(path: &Path) -> io::Result<OwnedFd> {
    fn open_dir(name: &CStr, flags: i32) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::open(name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor just returned by `open`.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn openat_dir(dirfd: RawFd, name: &CStr, flags: i32) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::openat(dirfd, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor just returned by `openat`.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Is this fd a symlink? Linux-only: the traversal-only `O_PATH`
    /// intermediate open does not fail on a symlink (it opens the link
    /// itself), so the no-follow guarantee must be enforced with an `fstat`
    /// after the open. Only the intermediate `O_PATH` fds are checked; the
    /// leaf and the non-Linux backends refuse a symlink at the `openat`.
    #[cfg(target_os = "linux")]
    fn fd_is_symlink(fd: &OwnedFd) -> io::Result<bool> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid, writable `stat`; `fd` is a live descriptor.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st.st_mode & libc::S_IFMT == libc::S_IFLNK)
    }

    // The leaf (the directory we pin and hand back) is opened `O_RDONLY`
    // because the returned fd is used for more than traversal (`fstatat`,
    // `fdopendir`, `mkdirat`, `unlinkat`, `fchmod`, and as the `openat` dirfd
    // for descendants). `O_NOFOLLOW` refuses a symlinked leaf.
    let base_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let step_flags = base_flags | libc::O_NOFOLLOW;

    // Intermediate components are only ever traversed *through*, never read or
    // handed back, so open them traversal-only where the platform allows
    // (Linux `O_PATH`, macOS `O_SEARCH`); any other Unix falls back to
    // `O_RDONLY` + `O_NOFOLLOW` (which refuses a symlink but needs the read
    // bit on every ancestor).
    #[cfg(target_os = "linux")]
    let trav_flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let trav_flags = libc::O_SEARCH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let trav_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    let components: Vec<Component> = path.components().collect();
    let last_normal = components
        .iter()
        .rposition(|c| matches!(c, Component::Normal(_)));

    let mut cur: Option<OwnedFd> = None;
    for (i, comp) in components.iter().enumerate() {
        // Only a `Normal` component can be the pinned leaf; the anchor (`/` /
        // `.`) and `..` are structural and use the anchor flags.
        let is_leaf_normal = Some(i) == last_normal;
        match comp {
            // `/` and `.` are never symlinks; open the anchor without
            // `O_NOFOLLOW` so a legitimate root/relative base is accepted.
            Component::RootDir => {
                cur = Some(open_dir(c"/", base_flags)?);
            }
            Component::CurDir => {
                if cur.is_none() {
                    cur = Some(open_dir(c".", base_flags)?);
                }
            }
            Component::Normal(name) => {
                // A relative path with no explicit `.` anchors at the cwd.
                if cur.is_none() {
                    cur = Some(open_dir(c".", base_flags)?);
                }
                let dir = cur.as_ref().unwrap();
                let c = cstr(name)?;
                // Intermediate components are traversal-only; only the final
                // component is opened `O_RDONLY` as the pinned leaf.
                let flags = if is_leaf_normal {
                    step_flags
                } else {
                    trav_flags
                };
                let next = openat_dir(dir.as_raw_fd(), &c, flags)?;
                // Linux: the traversal-only `O_PATH` open does NOT fail on a
                // symlink — it opens the link itself — so detect a symlinked
                // intermediate here and refuse, preserving the no-follow
                // guarantee the chain exists to enforce. (On macOS `O_SEARCH`
                // + `O_NOFOLLOW` already failed the open with `ELOOP`, as did
                // `O_NOFOLLOW` on the `O_RDONLY` fallback, so this check is
                // Linux-only.)
                #[cfg(target_os = "linux")]
                if !is_leaf_normal && fd_is_symlink(&next)? {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "refusing symlinked path component",
                    ));
                }
                cur = Some(next);
            }
            // `..` is resolved against the pinned parent fd — the kernel's
            // `..` lookup on a pinned fd follows the directory entry, never a
            // symlink. Run paths reaching here are first validated by
            // `normalize_run_path`, which REFUSES an interior `..`, so in
            // practice this only ever sees a leading `..` a caller constructed
            // by hand (e.g. `--runs-dir ../runs`); resolving it here keeps the
            // two backends from diverging on the same input.
            Component::ParentDir => {
                if cur.is_none() {
                    cur = Some(open_dir(c".", base_flags)?);
                }
                let dir = cur.as_ref().unwrap();
                // No O_NOFOLLOW: `..` is never a symlink, and the lookup is
                // anchored on the pinned parent fd.
                let next = openat_dir(dir.as_raw_fd(), c"..", base_flags)?;
                cur = Some(next);
            }
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "unexpected path prefix",
                ));
            }
        }
    }
    cur.ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "empty directory path"))
}

impl DirHandle {
    /// Resolve `path` from the current working directory no-follow and pin the
    /// result. A symlinked component anywhere in `path` is refused (`ELOOP` →
    /// [`PinError::Io`]). On Linux ≥5.6 this is one atomic
    /// `openat2(RESOLVE_NO_SYMLINKS)` resolution; elsewhere (non-Linux, or a
    /// pre-5.6 kernel reporting `ENOSYS`) it falls back to the portable
    /// `O_NOFOLLOW` `openat` chain, which gives the same no-symlink guarantee
    /// component by component. `path` may be absolute, so `RESOLVE_BENEATH` is
    /// intentionally NOT set on this anchoring open.
    pub(crate) fn open_root_nofollow(path: &Path) -> Result<DirHandle, PinError> {
        #[cfg(target_os = "linux")]
        {
            let c = cstr(path.as_os_str()).map_err(PinError::Io)?;
            match openat2_raw(
                libc::AT_FDCWD,
                &c,
                (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                RESOLVE_NO_SYMLINKS,
            ) {
                Ok(fd) => return Ok(DirHandle { fd }),
                // Pre-5.6 kernel without `openat2`: fall back to the portable
                // chain below, which gives the same no-symlink guarantee
                // component by component.
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                Err(e) => return Err(PinError::Io(e)),
            }
        }
        open_nofollow_chain(path)
            .map(|fd| DirHandle { fd })
            .map_err(PinError::Io)
    }

    /// Open a direct child directory relative to this handle, never following a
    /// symlink and never escaping this directory. On Linux this is one
    /// `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`; elsewhere a portable
    /// `openat` with `O_NOFOLLOW` anchored on this handle's fd (which cannot
    /// escape the pinned parent, since the open is relative to it).
    pub(crate) fn open_child_dir(&self, name: &OsStr) -> io::Result<DirHandle> {
        let c = cstr(name)?;
        #[cfg(target_os = "linux")]
        {
            match openat2_raw(
                self.fd.as_raw_fd(),
                &c,
                dir_open_flags() as u64,
                RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
            ) {
                Ok(fd) => return Ok(DirHandle { fd }),
                // Pre-5.6 kernel without `openat2`: fall back to the portable
                // openat below.
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                Err(e) => return Err(e),
            }
        }
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                dir_open_flags(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor just returned by `openat`.
        Ok(DirHandle {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
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
    pub(crate) fn restrict_mode(&self, mode: u32) -> io::Result<()> {
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

    /// The portable no-follow chain must refuse a symlinked intermediate
    /// component, not traverse it. This exercises [`open_nofollow_chain`]
    /// DIRECTLY (not `DirHandle::open_root_nofollow`, which on a modern Linux
    /// kernel resolves via `openat2` and never reaches the chain): the chain is
    /// the sole backend on macOS and pre-5.6 Linux, which is exactly where the
    /// portable-prepare finding bites.
    #[test]
    fn chain_refuses_a_symlinked_intermediate() {
        let base = scratch_root("chain-symlink");
        let real = base.join("real");
        std::fs::create_dir_all(real.join("child")).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // `<base>/link/child` reaches a real dir only *through* the symlink;
        // the chain must refuse it at the intermediate component.
        assert!(
            open_nofollow_chain(&link.join("child")).is_err(),
            "the no-follow chain must refuse a symlinked intermediate"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// The portable no-follow chain must refuse a symlinked leaf, not pin the
    /// link's target.
    #[test]
    fn chain_refuses_a_symlinked_leaf() {
        let base = scratch_root("chain-leaf");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            open_nofollow_chain(&link).is_err(),
            "the no-follow chain must refuse a symlinked leaf"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// The portable chain must pin a run dir beneath a search-only ancestor
    /// (mode `0111`, no read bit): ordinary traversal needs only the ancestor's
    /// search permission, not its read bit. The intermediate is opened
    /// traversal-only (`O_PATH`/`O_SEARCH`), so this must not fail with EACCES.
    /// Runs unprivileged (skipped under root, which bypasses the check).
    #[test]
    fn chain_pins_beneath_a_search_only_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root bypasses the ancestor permission check");
            return;
        }
        let base = scratch_root("chain-search-only");
        let ancestor = base.join("locked");
        let run = ancestor.join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();

        let opened = open_nofollow_chain(&run);
        // Restore writability so cleanup can descend, whatever the outcome.
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o755)).unwrap();

        opened.expect(
            "the no-follow chain must pin a run dir beneath a search-only (0111) \
             ancestor: traversal needs only the ancestor's search bit, not its read bit",
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// `prepare_child_dir` must return a handle to the *exact* inode it created
    /// and secured, so a post-prepare swap of the child by path cannot redirect
    /// a later operation. The prepared child is chmod'd to `mode` (0700); a
    /// swapped-in replacement created by a plain `create_dir_all` is 0755. After
    /// the swap, `fstat` on the pinned handle must still report the *prepared*
    /// inode's 0700 mode — proving the handle is bound to the inode preparation
    /// secured, not to whatever the path now resolves to.
    #[test]
    fn prepare_child_dir_binds_the_created_inode_not_the_path() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::AsRawFd;
        let root = scratch_root("prep-inode");
        let handle = DirHandle::open_root_nofollow(&root).expect("pin root");
        let child = handle
            .prepare_child_dir(OsStr::new("run"), 0o700)
            .expect("prepare child");

        // Attacker replaces the child by path with a different (0755) directory.
        handle.remove_tree(OsStr::new("run")).unwrap();
        std::fs::create_dir_all(root.join("run")).unwrap();
        // `create_dir_all` applies the process umask, so under a restrictive
        // umask (e.g. 0077) the replacement would be 0700, not 0755 — colliding
        // with the prepared mode and defeating the distinction this test draws.
        // Set the replacement's mode explicitly so the 0755-vs-0700 assertion
        // holds regardless of the inherited umask.
        std::fs::set_permissions(root.join("run"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            std::fs::metadata(root.join("run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the swapped-in replacement is an ordinary 0755 dir"
        );

        // The pinned handle still reports the prepared inode's 0700 mode (the
        // now-unlinked original), never the swapped-in path's 0755.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(child.fd.as_raw_fd(), &mut st) }, 0);
        assert_eq!(
            st.st_mode & libc::S_IFMT,
            libc::S_IFDIR,
            "the pinned child must still be a directory"
        );
        assert_eq!(
            st.st_mode & 0o777,
            0o700,
            "the pinned child handle must stay bound to the prepared (0700) inode, \
             not the swapped-in (0755) path"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
