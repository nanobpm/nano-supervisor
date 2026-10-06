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

/// Zero the calling thread's `errno` (so a NULL `readdir` with a clear `errno`
/// is a genuine EOF). The thread-local accessor differs per libc.
fn clear_errno() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
    unsafe {
        *libc::__errno() = 0;
    }
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

/// Is this fd a symlink? Linux-only: a traversal-only `O_PATH` open does not
/// fail on a symlink (it opens the link itself), so the no-follow guarantee
/// must be enforced with an `fstat` after the open. Only the intermediate
/// `O_PATH` fds are checked; the leaf and the non-Linux backends refuse a
/// symlink at the `openat`/`openat2`.
#[cfg(target_os = "linux")]
fn fd_is_symlink(fd: &OwnedFd) -> io::Result<bool> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid, writable `stat`; `fd` is a live descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFLNK)
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
    ///
    /// `trav` selects a traversal-only handle (Linux `O_PATH`, macOS
    /// `O_SEARCH`) for a root that is only descended *through* (e.g. the anchor
    /// seeding [`DirHandle::open_or_create_root_nofollow`]), so it resolves
    /// beneath a search-only ancestor without its read bit; `false` retains a
    /// readable (`O_RDONLY`) handle. On the portable-chain backend this only
    /// relaxes the *leaf* flags (intermediates are already traversal-only); on
    /// Linux a traversal-only `O_PATH` open does not fail on a symlinked leaf,
    /// so it is caught with a post-open `fstat` check.
    pub(crate) fn open_root_nofollow(path: &Path, trav: bool) -> Result<DirHandle, PinError> {
        #[cfg(target_os = "linux")]
        {
            let c = cstr(path.as_os_str()).map_err(PinError::Io)?;
            let flags = if trav {
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
            };
            match openat2_raw(libc::AT_FDCWD, &c, flags as u64, RESOLVE_NO_SYMLINKS) {
                // Linux: a traversal-only `O_PATH` open does NOT fail on a
                // symlinked leaf — it opens the link itself — so detect it here
                // and refuse, preserving the no-follow guarantee. (`O_PATH`
                // lacks `O_DIRECTORY`, so also refuse a non-directory.)
                Ok(fd) => {
                    if trav {
                        let mut st: libc::stat = unsafe { std::mem::zeroed() };
                        // SAFETY: `st` is valid/writable; `fd` is live.
                        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
                            return Err(PinError::Io(io::Error::last_os_error()));
                        }
                        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                            return Err(PinError::Io(io::Error::new(
                                ErrorKind::InvalidInput,
                                "refusing non-directory or symlinked root",
                            )));
                        }
                    }
                    return Ok(DirHandle { fd });
                }
                // Pre-5.6 kernel without `openat2`: fall back to the portable
                // chain below, which gives the same no-symlink guarantee
                // component by component.
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                Err(e) => return Err(PinError::Io(e)),
            }
        }
        // `trav` only relaxes the open flags on the Linux `openat2` path above;
        // the portable chain below already opens intermediates traversal-only
        // and its leaf handling is unchanged, so the flag is unused there.
        #[cfg(not(target_os = "linux"))]
        let _ = trav;
        open_nofollow_chain(path)
            .map(|fd| DirHandle { fd })
            .map_err(PinError::Io)
    }

    /// Open a direct child directory relative to this handle, never following a
    /// symlink and never escaping this directory. On Linux this is one
    /// `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`; elsewhere a portable
    /// `openat` with `O_NOFOLLOW` anchored on this handle's fd (which cannot
    /// escape the pinned parent, since the open is relative to it).
    ///
    /// `trav` selects a **traversal-only** handle for an intermediate component
    /// that is only ever descended *through* (used as the `openat`/`mkdirat`
    /// dirfd for the next step), never read or handed back. Where the platform
    /// offers it (Linux `O_PATH`, macOS `O_SEARCH`) the child is opened without
    /// its read bit, so the walk resolves beneath a search-only ancestor (mode
    /// `0111`, no read bit) — matching the `openat2` backend and
    /// `open_nofollow_chain`, which impose no such ancestor-read requirement.
    /// `trav == false` retains a readable (`O_RDONLY`) handle for a component
    /// that will be read or handed back (e.g. the pinned runs root). Any other
    /// Unix falls back to `O_RDONLY` + `O_NOFOLLOW` for both, which needs the
    /// read bit on every ancestor.
    ///
    /// The no-follow guarantee is preserved either way: on Linux an `O_PATH` +
    /// `O_NOFOLLOW` open does not *fail* on a symlink — it opens the link
    /// itself — so a symlinked intermediate is caught with an `fstat`
    /// `S_ISLNK` check after the open (the `O_RDONLY` leaf and the macOS
    /// `O_SEARCH` / fallback backends refuse a symlink at the `openat`
    /// itself).
    pub(crate) fn open_child_dir(&self, name: &OsStr, trav: bool) -> io::Result<DirHandle> {
        let c = cstr(name)?;
        // Traversal-only intermediate flags (Linux `O_PATH`, macOS `O_SEARCH`);
        // the readable-leaf / fallback flags are `dir_open_flags()`.
        #[cfg(target_os = "linux")]
        let trav_flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        #[cfg(target_os = "macos")]
        let trav_flags = libc::O_SEARCH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let trav_flags = dir_open_flags();
        let flags = if trav { trav_flags } else { dir_open_flags() };
        #[cfg(target_os = "linux")]
        {
            match openat2_raw(
                self.fd.as_raw_fd(),
                &c,
                flags as u64,
                RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
            ) {
                // Linux: a traversal-only `O_PATH` open does NOT fail on a
                // symlink — it opens the link itself — so detect a symlinked
                // intermediate here and refuse, preserving the no-follow
                // guarantee. (`RESOLVE_NO_SYMLINKS` already refuses a symlink
                // reached by *following*, but `O_PATH` opens the link rather
                // than following it.)
                Ok(fd) => {
                    if trav && fd_is_symlink(&fd)? {
                        return Err(io::Error::new(
                            ErrorKind::InvalidInput,
                            "refusing symlinked path component",
                        ));
                    }
                    return Ok(DirHandle { fd });
                }
                // Pre-5.6 kernel without `openat2`: fall back to the portable
                // openat below.
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                Err(e) => return Err(e),
            }
        }
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor just returned by `openat`.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Linux pre-5.6 fallback: the portable `O_PATH` open also opens a
        // symlink rather than failing, so apply the same post-open check. On
        // macOS `O_SEARCH` + `O_NOFOLLOW` and the `O_RDONLY` + `O_NOFOLLOW`
        // fallback already failed a symlinked child with `ELOOP` at the open.
        #[cfg(target_os = "linux")]
        if trav && fd_is_symlink(&fd)? {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "refusing symlinked path component",
            ));
        }
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
    ///
    /// Elsewhere (non-Linux, or a pre-5.6 kernel) `name` must be a single
    /// component — a `/`, `.` or `..` is refused — so the portable `openat`
    /// with `O_NOFOLLOW` is anchored on this pinned handle and cannot escape it.
    #[cfg(target_os = "linux")]
    pub(crate) fn open_child_file_rw_nofollow(&self, name: &OsStr) -> io::Result<std::fs::File> {
        let c = cstr(name)?;
        let flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        #[cfg(target_os = "linux")]
        {
            match openat2_raw(
                self.fd.as_raw_fd(),
                &c,
                flags as u64,
                RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
            ) {
                Ok(fd) => return Ok(std::fs::File::from(fd)),
                // Pre-5.6 kernel without `openat2`: fall back to the portable
                // single-component openat below.
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                Err(e) => return Err(e),
            }
        }
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.contains(&b'/') || bytes == b"." || bytes == b".." {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "refusing non-single-component child name",
            ));
        }
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned descriptor just returned by `openat`.
        Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
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
    #[cfg(target_os = "linux")]
    pub(crate) fn write_new_child_file(
        &self,
        name: &OsStr,
        contents: &[u8],
        mode: u32,
    ) -> io::Result<()> {
        use std::io::Write;
        let c = cstr(name)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = match openat2_raw(
            self.fd.as_raw_fd(),
            &c,
            flags as u64,
            RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
        ) {
            Ok(fd) => fd,
            // Pre-5.6 kernel without `openat2`: a single-component `openat`
            // anchored on this pinned handle, `O_NOFOLLOW | O_EXCL`, cannot
            // escape it or land on a planted symlink.
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                let bytes = name.as_bytes();
                if bytes.is_empty() || bytes.contains(&b'/') || bytes == b"." || bytes == b".." {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "refusing non-single-component child name",
                    ));
                }
                let raw = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags, 0) };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: `raw` is a fresh, owned descriptor just returned by `openat`.
                unsafe { OwnedFd::from_raw_fd(raw) }
            }
            Err(e) => return Err(e),
        };
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
    #[cfg(target_os = "linux")]
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
                clear_errno();
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
            let child = self.open_child_dir(name, false)?;
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

    /// Rename a direct child `from` to `to`, both relative to this handle, via
    /// `renameat`. Both names stay under the pinned parent inode, so a same-UID
    /// actor swapping an ancestor cannot redirect either side outside the
    /// workspace. `renameat` does not follow a symlink at the *source* leaf (it
    /// renames the link itself), and `to`/`from` are single components, so the
    /// operation is anchored on the pinned fd exactly like `remove_tree`. Used
    /// to set a retained run dir aside (quarantine) instead of wiping it.
    pub(crate) fn rename_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let from_c = cstr(from)?;
        let to_c = cstr(to)?;
        let r = unsafe {
            libc::renameat(
                self.fd.as_raw_fd(),
                from_c.as_ptr(),
                self.fd.as_raw_fd(),
                to_c.as_ptr(),
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
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
        // through the fd, immune to a post-mkdir swap. Readable (`trav = false`):
        // the prepared child is handed back and carried into the launch.
        let child = self.open_child_dir(name, false)?;
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

    /// Wrap an already-pinned, no-follow directory fd as a `DirHandle`, without
    /// re-resolving any path. The inverse of [`into_fd`]: lets a consumer that
    /// retained the exact validated run-dir inode (as a [`crate::safecwd::CwdHandle`])
    /// seed children *relative to that capability* instead of reopening the run
    /// dir by name — which a same-UID actor could swap for an ordinary tree in
    /// between (#35/#46). The caller owns the fd's no-follow provenance; this
    /// only rebinds it to the handle-relative mkdir/openat helpers.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_fd(fd: OwnedFd) -> DirHandle {
        DirHandle { fd }
    }

    /// Ensure a direct child directory `name` exists under this pinned handle,
    /// creating it (mode `mode`, umask-subject) when missing, and return it
    /// pinned no-follow. Every step is relative to this handle's fd, so the
    /// create and the open are anchored on the *pinned parent inode* — a
    /// same-UID actor that swaps `name` (or races the create) cannot redirect
    /// the result outside this directory: a pre-existing symlinked `name`
    /// fails the no-follow open, and a freshly created real directory is what
    /// gets pinned. This is the handle-relative building block that lets the
    /// runs root be materialised component-by-component without any
    /// path-based `create_dir_all` that would follow a swapped ancestor (#36).
    ///
    /// `trav` is forwarded to [`DirHandle::open_child_dir`]: `true` for an
    /// intermediate component that is only descended *through* (opened
    /// traversal-only, so the walk resolves beneath a search-only ancestor),
    /// `false` for the final root (retained readable).
    pub(crate) fn ensure_child_dir(
        &self,
        name: &OsStr,
        mode: u32,
        trav: bool,
    ) -> io::Result<DirHandle> {
        let c = cstr(name)?;
        if unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) } != 0 {
            let e = io::Error::last_os_error();
            // Already existing is fine — we pin whatever is there no-follow
            // below. Any other error (permissions, a non-dir in the way, ...)
            // is real and surfaced.
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        // Open no-follow, beneath us: if `name` is a symlink (planted before or
        // swapped in after the mkdirat), this open refuses it (ELOOP) rather
        // than following it to an attacker-chosen target.
        self.open_child_dir(name, trav)
    }

    /// Resolve `path` from the current working directory like
    /// [`DirHandle::open_root_nofollow`], but **create any missing directory
    /// component along the way** — each one created and opened relative to its
    /// already-pinned parent, never via a path-based `create_dir_all`. That is
    /// the whole point: a path-based create *follows* a symlinked ancestor, so
    /// a same-UID actor swapping a writable ancestor for a symlink between a
    /// no-follow check and the create could redirect the materialised root into
    /// an attacker-chosen target (the run dir would then be built outside the
    /// workspace before any no-follow open ran). Walking and creating
    /// component-by-component relative to the pinned parent closes that window:
    /// each step is anchored on the previous step's inode, an existing symlinked
    /// component is refused by the no-follow open, and a swapped-in symlink is
    /// refused the same way. `path` may be absolute; the anchor (`/` / `.`) is
    /// opened as-is (trusted, never a symlink).
    pub(crate) fn open_or_create_root_nofollow(
        path: &Path,
        mode: u32,
    ) -> Result<DirHandle, PinError> {
        // The final `Normal` component is the runs root we retain (readable);
        // every component before it is only traversed *through*, so it is
        // opened traversal-only (Linux `O_PATH` / macOS `O_SEARCH`) and needs
        // no read bit — letting the walk resolve beneath a search-only
        // ancestor (mode `0111`). Compute the leaf position up front.
        let components: Vec<Component> = path.components().collect();
        let last_normal = components
            .iter()
            .rposition(|c| matches!(c, Component::Normal(_)));
        let mut cur: Option<DirHandle> = None;
        for (i, comp) in components.iter().enumerate() {
            // Only the final `Normal` component is the retained, readable root;
            // everything before it (the anchor and each intermediate) is opened
            // traversal-only, so the walk resolves beneath a search-only
            // ancestor without needing its read bit.
            let trav = Some(i) != last_normal;
            match comp {
                // The anchor (`/` or a leading `.`) is structural and never a
                // symlink; open it directly to seed the walk. It is only ever
                // traversed through (the runs root is always a `Normal`
                // descendant), so open it traversal-only.
                Component::RootDir => {
                    cur = Some(DirHandle::open_root_nofollow(Path::new("/"), true)?);
                }
                Component::CurDir => {
                    if cur.is_none() {
                        cur = Some(DirHandle::open_root_nofollow(Path::new("."), true)?);
                    }
                }
                Component::Normal(name) => {
                    // A relative path with no explicit `.` anchors at the cwd.
                    let parent = match cur {
                        Some(ref p) => p,
                        None => {
                            cur = Some(DirHandle::open_root_nofollow(Path::new("."), true)?);
                            cur.as_ref().unwrap()
                        }
                    };
                    cur = Some(parent.ensure_child_dir(name, mode, trav)?);
                }
                // `..` cannot be created through, and resolving it against the
                // pinned parent would still leave the *named* components under it
                // to be created — but a `..` in a would-be-created path means the
                // target escapes the frame we just pinned, which a path-based
                // `create_dir_all` would have followed (possibly through a
                // symlinked ancestor). Run paths reaching here are validated by
                // `normalize_run_path`, which refuses an interior `..`, so this
                // only ever sees a leading `..` a caller built by hand; refuse it
                // rather than silently create outside the pinned frame.
                Component::ParentDir => {
                    return Err(PinError::Io(io::Error::new(
                        ErrorKind::InvalidInput,
                        "runs root with a `..` component cannot be created no-follow",
                    )));
                }
                Component::Prefix(_) => {
                    return Err(PinError::Io(io::Error::new(
                        ErrorKind::InvalidInput,
                        "unexpected path prefix",
                    )));
                }
            }
        }
        cur.ok_or_else(|| {
            PinError::Io(io::Error::new(
                ErrorKind::InvalidInput,
                "empty directory path",
            ))
        })
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
        let handle = DirHandle::open_root_nofollow(&root, false).expect("pin root");

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

    /// The *creation* walk (`open_or_create_root_nofollow`) must pin a
    /// run dir that already exists beneath a search-only ancestor (mode
    /// `0111`, no read bit) — the worker-startup / re-prepare path. The
    /// intermediate components are only ever traversed *through*, so they need
    /// only the ancestor's search permission, not its read bit; the final root
    /// is retained readable. (Creating a *missing* dir under a `0111` ancestor
    /// is impossible for any caller — `mkdirat` needs the parent's write bit —
    /// so only the pre-existing case is reachable.) Runs unprivileged (skipped
    /// under root, which bypasses the permission check).
    #[test]
    fn create_root_beneath_a_search_only_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: root bypasses the ancestor permission check");
            return;
        }
        let base = scratch_root("create-search-only");
        let ancestor = base.join("locked");
        let run = ancestor.join("run");
        // The run dir already exists (a prior run created it while the ancestor
        // was writable); only the ancestor is later locked to search-only.
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();

        let created = DirHandle::open_or_create_root_nofollow(&run, 0o700);
        // Restore writability so cleanup can descend, whatever the outcome.
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o755)).unwrap();

        let handle = created.expect(
            "the creation walk must pin an existing run dir beneath a search-only (0111) \
             ancestor: intermediates need only the ancestor's search bit, not its read bit",
        );
        assert!(run.is_dir(), "the run dir must still be on disk");
        drop(handle);
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
        let handle = DirHandle::open_root_nofollow(&root, false).expect("pin root");
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
