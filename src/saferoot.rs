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

    /// Open an anchor handle on an absolute/relative *root* for a component
    /// walk: `/` for an absolute path, `.` (the current directory) for a
    /// relative one. Resolved with `RESOLVE_NO_SYMLINKS` and NOT
    /// `RESOLVE_BENEATH` (the anchor is the walk's base, not a descent).
    ///
    /// `opath` selects the handle kind. `true` (`O_PATH`): the anchor and the
    /// intermediate ancestors it seeds are only ever used as a *dirfd* for
    /// `mkdirat` / `openat2` / `fstatat`, which an `O_PATH` handle supports
    /// with only search (`x`) permission — never a read of the directory. This
    /// matches how the kernel traversed ancestors in the old whole-path
    /// resolution (search, not read), so a legitimately non-readable ancestor
    /// (e.g. mode `0o300`) no longer fails the walk. `false` (`O_RDONLY`): a
    /// readable handle for the case where the anchor IS the requested root
    /// (a path with no components, e.g. `.` or `/`), which the caller stats /
    /// enumerates / `fchmod`s — all impossible on an `O_PATH` fd.
    fn open_anchor(absolute: bool, opath: bool) -> Result<DirHandle, PinError> {
        let anchor: &CStr = if absolute { c"/" } else { c"." };
        let access = if opath { libc::O_PATH } else { libc::O_RDONLY };
        match openat2_raw(
            libc::AT_FDCWD,
            anchor,
            (access | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            RESOLVE_NO_SYMLINKS,
        ) {
            Ok(fd) => Ok(DirHandle { fd }),
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => Err(PinError::Unsupported),
            Err(e) => Err(PinError::Io(e)),
        }
    }

    /// Establish `path` as a **private root** entirely through no-follow
    /// directory handles and return a handle pinned to its final component.
    ///
    /// Unlike `create_dir_all(path)` followed by [`open_root_nofollow`], this
    /// never resolves `path` as a string against the live filesystem: it opens
    /// an anchor (`/` or `.`) with `RESOLVE_NO_SYMLINKS`, then for each path
    /// component `mkdirat`s it (tolerating an existing directory) and re-opens
    /// it relative to the parent handle with
    /// `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`. Every component is therefore
    /// *created and re-opened through a handle*, closing the check-then-create
    /// TOCTOU that a path-based `reject_symlinked_ancestors` + `create_dir_all`
    /// bootstrap leaves open — a same-UID actor cannot swap an ancestor for a
    /// symlink in a window and redirect the `mkdir` outside the workspace,
    /// because the very next open refuses any symlinked or escaping component
    /// (`ELOOP`/`EXDEV` → [`PinError::Io`]).
    ///
    /// New components are created `0o777` (umask applies), matching
    /// `create_dir_all`; the caller locks the leaf it owns to its final mode.
    ///
    /// Intermediate ancestors are opened `O_PATH` (search-only, via
    /// [`open_child_dir_opath`](Self::open_child_dir_opath)) so a legitimately
    /// non-readable ancestor does not fail the walk; only the **final** runs
    /// root is opened readable, since the caller stats / enumerates / `fchmod`s
    /// it (which `O_PATH` cannot do). This preserves the old behaviour where
    /// only the runs root itself needed read permission.
    ///
    /// A path with no components at all (`.` or `/`) is the anchor itself, so
    /// it is opened READABLE — the returned handle is the root the caller
    /// operates on, and an `O_PATH` handle would fail every stat / enumerate /
    /// `fchmod` with `EBADF` (previously `--runs-dir .` broke every job's
    /// preparation exactly this way).
    pub(crate) fn create_root_nofollow(path: &Path) -> Result<DirHandle, PinError> {
        use std::path::Component;
        // Collect the directory components to create/open, rejecting `..` and
        // Windows prefixes *before* creating anything — fail closed earlier
        // rather than part-way through the walk. A `..` can never be honoured
        // here: the walk pins an anchor (`/` or the cwd) and descends with
        // `RESOLVE_BENEATH`, so a parent traversal would either climb out of
        // that anchor (forbidden) or require re-resolution against the live
        // path. Callers that accept an operator `--runs-dir` resolve a leading
        // `..` against the cwd (and reject any interior `..`) at the CLI
        // boundary (`main::normalize_runs_dir`) BEFORE the path reaches this
        // security layer, preserving the pre-hardening `../runs` behaviour the
        // non-Linux `create_dir_all` fallback still has; this walk stays
        // fail-closed so a `..` that slips past the boundary is refused, never
        // silently followed.
        let mut names: Vec<&OsStr> = Vec::new();
        for comp in path.components() {
            match comp {
                // The anchor already accounts for the root / cwd base.
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => names.push(name),
                // `..` and Windows prefixes have no business in a runs-root
                // path that has reached the security layer; refuse rather than
                // risk escaping the anchor (see the boundary normalization).
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(PinError::Io(io::Error::new(
                        ErrorKind::InvalidInput,
                        "runs-root path contains an unsupported component",
                    )));
                }
            }
        }
        // A path with no components (`.` or `/`) IS the anchor itself: open it
        // READABLE, since the returned handle is the root the caller stats /
        // enumerates / `fchmod`s — an `O_PATH` anchor would fail every such
        // operation (`EBADF`), so e.g. `--runs-dir .` would break every job's
        // preparation. Only an anchor that seeds a component walk (below) is
        // `O_PATH` (search-only), so a legitimately non-readable intermediate
        // ancestor (e.g. mode `0o300`) does not fail the walk.
        if names.is_empty() {
            return DirHandle::open_anchor(path.is_absolute(), false);
        }
        let mut handle = DirHandle::open_anchor(path.is_absolute(), true)?;
        let last = names.len() - 1;
        for (i, name) in names.into_iter().enumerate() {
            handle.mkdirat_ignore_existing(name, 0o777)?;
            // Re-open through a handle (no-follow, beneath the parent): a
            // component swapped to a symlink after the `mkdirat` is refused here
            // rather than silently traversed.
            handle = if i == last {
                // The final runs root is what the caller operates on (stat /
                // enumerate / fchmod), so it must be a readable, non-`O_PATH`
                // handle.
                handle.open_child_dir(name).map_err(PinError::Io)?
            } else {
                // Intermediate ancestors are only traversed; `O_PATH` needs no
                // read permission, so a valid non-readable ancestor is fine.
                handle.open_child_dir_opath(name).map_err(PinError::Io)?
            };
        }
        Ok(handle)
    }

    /// `mkdirat` a direct child relative to this handle, treating an existing
    /// directory as success (an existing non-directory surfaces later when the
    /// no-follow re-open fails). Never follows a symlink: creation is relative
    /// to the pinned parent fd.
    fn mkdirat_ignore_existing(&self, name: &OsStr, mode: u32) -> io::Result<()> {
        let c = cstr(name)?;
        if unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) } != 0 {
            let e = io::Error::last_os_error();
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        Ok(())
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

    /// Open a direct child **regular file** relative to this handle for
    /// read+write, never following a symlink and never escaping this directory
    /// (`RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, plus `O_NOFOLLOW` on the final
    /// component). `O_NONBLOCK` guards against an attacker-planted FIFO whose
    /// open would otherwise block the worker thread; the caller rejects any
    /// non-regular file after the open via `fstat`.
    ///
    /// Used by the submodule-config credential scrub so each `config` is opened
    /// *through the pinned parent handle* — a component swapped to a symlink
    /// after the entry was triaged (or the leaf itself swapped) cannot redirect
    /// the rewrite outside the checkout: the open is refused (`ELOOP`) rather
    /// than followed.
    pub(crate) fn open_child_file_rw_nofollow(&self, name: &OsStr) -> io::Result<std::fs::File> {
        let c = cstr(name)?;
        let fd = openat2_raw(
            self.fd.as_raw_fd(),
            &c,
            (libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
            RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
        )?;
        Ok(std::fs::File::from(fd))
    }

    /// Like [`open_child_dir`](Self::open_child_dir) but returns an `O_PATH`
    /// handle: usable only as a *dirfd* anchor for `*at` operations
    /// (`mkdirat` / `openat2` / `fstatat`), never for reading or `fchmod`.
    /// Opening a directory this way requires only search (`x`) permission, not
    /// read — so a legitimately non-readable intermediate ancestor (e.g. mode
    /// `0o300`) does not fail the walk — while `RESOLVE_NO_SYMLINKS |
    /// RESOLVE_BENEATH` still refuses a swapped-in or escaping component.
    fn open_child_dir_opath(&self, name: &OsStr) -> io::Result<DirHandle> {
        let c = cstr(name)?;
        let fd = openat2_raw(
            self.fd.as_raw_fd(),
            &c,
            (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
        )?;
        Ok(DirHandle { fd })
    }

    /// Create a direct child **regular file** (`name`) relative to this handle,
    /// write `contents`, and set it to `mode` — all no-follow and beneath this
    /// directory (`RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, plus
    /// `O_CREAT | O_EXCL | O_NOFOLLOW`). `O_EXCL` makes the create **fail
    /// closed** if `name` already exists as anything (a planted symlink, a
    /// pre-existing file, a FIFO): a same-UID sibling cannot pre-plant
    /// `name` as a symlink and have this write land on its target.
    ///
    /// Used to seed the agent's isolated c8ctl config files (issue #41) through
    /// the pinned per-run directory handle, so the write cannot be redirected
    /// outside the run dir onto the operator's global c8ctl config.
    pub(crate) fn write_new_child_file(
        &self,
        name: &OsStr,
        contents: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        use std::io::Write;
        let c = cstr(name)?;
        let fd = openat2_raw(
            self.fd.as_raw_fd(),
            &c,
            (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                as u64,
            RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
        )?;
        let mut f = std::fs::File::from(fd);
        // `openat2` created the file with mode 0 (we pass `mode: 0` in the
        // `open_how`), narrower than the target; `fchmod` on the fd makes the
        // final mode exact and immune to umask, without re-resolving the path.
        if unsafe { libc::fchmod(f.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        f.write_all(contents)?;
        f.flush()
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
    ///
    /// Best-effort: a mid-stream `readdir` error ends enumeration and the
    /// partial listing is returned as `Ok`. That is right for the sweep / slot
    /// reaping (a truncated list merely defers reaping to the next pass), but
    /// NOT for a security decision — callers that must not act on a partial
    /// listing (e.g. the credential scrub) use [`entry_names_strict`].
    pub(crate) fn entry_names(&self) -> io::Result<Vec<OsString>> {
        self.collect_entry_names(false)
    }

    /// Like [`entry_names`](Self::entry_names) but **strict**: a mid-stream
    /// `readdir` error is surfaced as `Err` rather than silently treated as
    /// end-of-directory. Use this wherever a partial listing would be a
    /// security hole — e.g. the submodule-config credential scrub, which must
    /// fail (and so refuse to hand out the checkout) rather than report success
    /// while an unenumerated `config` keeps its credentials.
    pub(crate) fn entry_names_strict(&self) -> io::Result<Vec<OsString>> {
        self.collect_entry_names(true)
    }

    /// Shared enumeration core. When `strict` is false a NULL `readdir` return
    /// is always end-of-directory; when true, `errno` is zeroed before each call
    /// and a NULL return with a non-zero `errno` is an I/O error, not EOF.
    fn collect_entry_names(&self, strict: bool) -> io::Result<Vec<OsString>> {
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
        let result = loop {
            // Distinguish EOF from a mid-stream error: `readdir` returns NULL
            // for both, setting `errno` only on error. Zero it first so a NULL
            // return with a clear `errno` is a genuine EOF.
            if strict {
                unsafe { *libc::__errno_location() = 0 };
            }
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                if strict {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(0) {
                        break Err(e);
                    }
                }
                // Best-effort (non-strict) mode keeps the historical behaviour:
                // a NULL ends enumeration whether it was EOF or a rare error.
                break Ok(());
            }
            // SAFETY: `d_name` is a NUL-terminated C string within the entry.
            let cs = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            let bytes = cs.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsStr::from_bytes(bytes).to_os_string());
        };
        unsafe { libc::closedir(dirp) };
        result.map(|()| names)
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
    pub(crate) fn prepare_child_dir(&self, name: &OsStr, mode: u32) -> io::Result<()> {
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
        Ok(())
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

    // The strict variant enumerates the same full, current contents as the
    // best-effort one on a healthy directory — it differs ONLY in that a
    // mid-stream `readdir` error is surfaced as `Err` rather than silently
    // treated as EOF. (A real mid-stream I/O error is not deterministically
    // reproducible in a unit test; the credential scrub relies on this path
    // failing closed rather than reporting a partial listing as success.)
    #[test]
    fn entry_names_strict_matches_best_effort_on_healthy_dir() {
        let root = scratch_root("entrynames-strict");
        for name in ["aaa", "bbb", "ccc"] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        let handle = DirHandle::open_root_nofollow(&root).expect("pin root");

        let mut strict = handle.entry_names_strict().expect("strict list");
        strict.sort();
        let mut best_effort = handle.entry_names().expect("best-effort list");
        best_effort.sort();
        assert_eq!(
            strict,
            vec![
                OsString::from("aaa"),
                OsString::from("bbb"),
                OsString::from("ccc")
            ]
        );
        assert_eq!(
            strict, best_effort,
            "strict and best-effort agree on a healthy dir"
        );

        // Idempotent on a reused handle, exactly like the best-effort variant.
        let mut again = handle.entry_names_strict().expect("second strict list");
        again.sort();
        assert_eq!(strict, again);

        std::fs::remove_dir_all(&root).ok();
    }

    // The post-triage symlink-swap race this PR's hardening exists to close: a
    // `config` leaf that stats as a regular file but is swapped for a symlink
    // (to a credential-bearing file OUTSIDE the checkout) before its relative
    // open must be REFUSED with `ELOOP` (`RESOLVE_NO_SYMLINKS | O_NOFOLLOW`),
    // leaving the outside target byte-for-byte untouched. A walker that
    // re-checks `file_type()` and then opens by path would follow the link and
    // rewrite the target; the pinned no-follow open must not.
    #[test]
    fn open_child_file_rw_nofollow_refuses_post_triage_symlink_swap() {
        let base = scratch_root("swap-leaf");
        let dir = base.join("mod");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("config");
        std::fs::write(
            &target,
            "url = https://x-access-token:s3cr3tPAT@h/o/r.git\n",
        )
        .unwrap();

        let handle = DirHandle::open_root_nofollow(&dir).expect("pin parent");

        // Triage: a real `config` regular file is present.
        let leaf = dir.join("config");
        std::fs::write(&leaf, "url = https://h/o/r.git\n").unwrap();
        let meta = handle
            .symlink_metadata(OsStr::new("config"))
            .expect("stat config");
        assert!(
            !meta.is_symlink && !meta.is_dir,
            "config stats as a regular file"
        );

        // Swap it for a symlink to the outside target before the open.
        std::fs::remove_file(&leaf).unwrap();
        std::os::unix::fs::symlink(&target, &leaf).unwrap();

        // The pinned no-follow open must refuse (ELOOP), not follow the link.
        let err = handle
            .open_child_file_rw_nofollow(OsStr::new("config"))
            .expect_err("a post-triage symlink swap must be refused");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "the swapped-in symlink must fail the open with ELOOP, got {err:?}"
        );
        // The outside target was never rewritten.
        let got = std::fs::read_to_string(&target).unwrap();
        assert!(
            got.contains("s3cr3tPAT"),
            "the scrub must not follow the swapped symlink out of the checkout"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    // The directory-descent half of the same race: an entry that stats as a
    // directory but is swapped for a symlink (to a dir outside the checkout)
    // before its relative open must be REFUSED with `ELOOP`
    // (`RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | O_NOFOLLOW`), never descended
    // into.
    #[test]
    fn open_child_dir_refuses_post_triage_symlink_swap() {
        let base = scratch_root("swap-dir");
        let dir = base.join("mod");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        let handle = DirHandle::open_root_nofollow(&dir).expect("pin parent");

        // Triage: a real `sub` directory is present.
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let meta = handle
            .symlink_metadata(OsStr::new("sub"))
            .expect("stat sub");
        assert!(
            meta.is_dir && !meta.is_symlink,
            "sub stats as a real directory"
        );

        // Swap it for a symlink to the outside dir before the open.
        std::fs::remove_dir(&sub).unwrap();
        std::os::unix::fs::symlink(&outside, &sub).unwrap();

        let err = handle
            .open_child_dir(OsStr::new("sub"))
            .err()
            .expect("a post-triage dir swap must be refused");
        // The open is refused either way: `RESOLVE_NO_SYMLINKS` fails it with
        // `ELOOP`, and `O_DIRECTORY` fails a symlink (whose target type is not
        // yet resolved) with `ENOTDIR`. Which one the kernel returns is
        // version-dependent; both are a secure refusal to descend into the link.
        assert!(
            matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)),
            "the swapped-in symlinked dir must be refused (ELOOP or ENOTDIR), got {err:?}"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    // `create_root_nofollow` must materialise a deep path through no-follow
    // handles and pin its leaf: every component is created and re-opened, and a
    // pre-existing path is tolerated (idempotent).
    #[test]
    fn create_root_nofollow_builds_and_pins_nested_path() {
        let base = scratch_root("create-nested");
        let target = base.join("a").join("b").join("runs");

        let handle = DirHandle::create_root_nofollow(&target).expect("create nested root");
        assert!(target.is_dir(), "every component must be created");

        // The returned handle is pinned to the leaf: a child created through it
        // must appear under the real target path.
        handle
            .mkdirat_ignore_existing(OsStr::new("job42"), 0o700)
            .expect("mkdir child through pinned leaf");
        assert!(
            target.join("job42").is_dir(),
            "the handle must be pinned to the created leaf"
        );

        // Idempotent: a second establishment over an existing tree succeeds.
        let again = DirHandle::create_root_nofollow(&target).expect("re-establish existing root");
        assert!(again
            .entry_names()
            .unwrap()
            .contains(&OsString::from("job42")));

        std::fs::remove_dir_all(&base).ok();
    }

    // A symlinked ANCESTOR of the runs root must be refused, not followed: the
    // no-follow re-open of the swapped component fails (ELOOP) and nothing is
    // created inside the link's target. This is the TOCTOU the former
    // path-based `create_dir_all` bootstrap could not close.
    #[test]
    fn create_root_nofollow_refuses_symlinked_ancestor() {
        let base = scratch_root("create-symlink");
        // Real tree the attacker would like the create redirected into.
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        // `link -> outside`; the runs root is requested as `<base>/link/runs`.
        let link = base.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let target = link.join("runs");

        let err = DirHandle::create_root_nofollow(&target)
            .err()
            .expect("a symlinked ancestor must be refused");
        assert!(
            matches!(err, PinError::Io(_)),
            "a refused symlink is a security-relevant Io error, never Unsupported"
        );
        assert!(
            !outside.join("runs").exists(),
            "the runs root must not be materialised inside the symlink target"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    // The final component itself being a symlink is refused too (the leaf is
    // re-opened no-follow just like every ancestor).
    #[test]
    fn create_root_nofollow_refuses_symlinked_leaf() {
        let base = scratch_root("create-symlink-leaf");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let link_runs = base.join("runs");
        std::os::unix::fs::symlink(&outside, &link_runs).unwrap();

        let err = DirHandle::create_root_nofollow(&link_runs)
            .err()
            .expect("a symlinked leaf must be refused");
        assert!(matches!(err, PinError::Io(_)));

        std::fs::remove_dir_all(&base).ok();
    }

    // A `..` that reaches the security layer is still refused (fail-closed):
    // the walk can never honour a parent traversal without escaping its pinned
    // anchor. The pre-hardening `--runs-dir ../runs` behaviour is preserved at
    // the CLI boundary (`main::normalize_runs_dir`), which resolves a leading
    // `..` against the cwd (and rejects any interior `..`) before the path gets
    // here — so this rejection only fires for a `..` that slipped past the
    // boundary, never for a legitimate runs dir.
    #[test]
    fn create_root_nofollow_rejects_parent_component() {
        let base = scratch_root("create-parent");
        let target = base.join("a").join("..").join("escape");
        let err = DirHandle::create_root_nofollow(&target)
            .err()
            .expect("a `..` component must be rejected");
        assert!(matches!(err, PinError::Io(_)));
        std::fs::remove_dir_all(&base).ok();
    }

    // The OTHER half of the parent-traversal contract: once the CLI boundary
    // (`main::normalize_runs_dir`) has resolved `--runs-dir ../runs` to an
    // absolute, `..`-free `<parent>/runs`, that path must establish cleanly
    // through the pinned walk. This is the regression test for "Linux rejects
    // parent-traversal runs directories": the normalized form of a
    // parent-traversal runs dir is accepted on Linux exactly as the non-Linux
    // `create_dir_all` fallback accepts the raw form.
    #[test]
    fn create_root_nofollow_accepts_normalized_parent_traversal_target() {
        let base = scratch_root("create-parent-ok");
        // A leading-`..` runs dir (e.g. `--runs-dir ../runs`) normalizes to an
        // absolute `..`-free path; `<base>/runs` is that already-normalized
        // form. Establish THAT.
        let normalized = base.join("runs");
        let handle = DirHandle::create_root_nofollow(&normalized)
            .expect("a normalized parent-traversal target must establish");
        assert!(normalized.is_dir(), "the runs root must be created");
        // The pinned handle operates on the real leaf.
        handle
            .mkdirat_ignore_existing(OsStr::new("job"), 0o700)
            .expect("mkdir through the pinned leaf");
        assert!(normalized.join("job").is_dir());
        // And crucially the cancelled `sub` was never created.
        assert!(
            !base.join("sub").exists(),
            "the cancelled `..` component must not be materialised"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    // A non-readable (but searchable) INTERMEDIATE ancestor must not fail root
    // creation: intermediate ancestors are opened `O_PATH` (search-only), so a
    // valid `0o300` ancestor — traversable and writable but not readable — no
    // longer breaks job preparation with `EACCES`, matching the old whole-path
    // resolution where only the final runs root needed read permission.
    #[test]
    fn create_root_nofollow_tolerates_non_readable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_root("create-nonreadable");
        let mid = base.join("mid");
        std::fs::create_dir_all(&mid).unwrap();
        // write + execute, NO read: `mkdirat`/traversal are allowed but an
        // `O_RDONLY` open of `mid` would fail `EACCES`.
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o300)).unwrap();
        let target = mid.join("runs");

        let handle = DirHandle::create_root_nofollow(&target)
            .expect("a non-readable (0o300) ancestor must not fail root creation");
        assert!(
            target.is_dir(),
            "the runs root must be created under a non-readable ancestor"
        );
        // The leaf itself is readable, so the caller can still operate on it.
        handle
            .mkdirat_ignore_existing(OsStr::new("job"), 0o700)
            .expect("mkdir through the pinned readable leaf");

        // Restore perms so the scratch tree can be removed.
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&base).ok();
    }

    // A runs-root path with NO components (`.` or `/`) is the anchor itself, so
    // `create_root_nofollow` must return a READABLE handle for it — the caller
    // stats / enumerates / `fchmod`s the root, and an `O_PATH` handle would
    // fail every one of those with `EBADF` (previously `--runs-dir .` broke
    // every job's preparation exactly this way). Regression test: establish the
    // current directory as the root and prepare a child through the returned
    // handle, exactly as `prepare_run_dir_pinned` does.
    #[test]
    fn create_root_nofollow_returns_readable_handle_for_empty_path() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_root("create-empty");
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&base).unwrap();

        // `.` has no `Normal` components: the handle must be the anchor itself,
        // opened readable — so the full `prepare_child_dir` sequence (stat,
        // mkdir, pin, fchmod of child AND root) succeeds through it.
        let handle = DirHandle::create_root_nofollow(Path::new("."))
            .expect("`.` must establish as a readable root handle");
        handle
            .prepare_child_dir(OsStr::new("job1"), 0o700)
            .expect("prepare a child through the returned handle (fchmod must not EBADF)");
        assert!(base.join("job1").is_dir(), "the child must be created");
        // The root itself is restricted too — proof the handle is not O_PATH.
        let mode = std::fs::metadata(&base).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the root fchmod must have taken effect");
        // Idempotent re-prepare wipes the stale child, again through the handle.
        handle
            .prepare_child_dir(OsStr::new("job1"), 0o700)
            .expect("re-prepare must wipe and recreate");
        assert!(base.join("job1").is_dir());

        std::env::set_current_dir(original_cwd).unwrap();
        std::fs::remove_dir_all(&base).ok();
    }
}
