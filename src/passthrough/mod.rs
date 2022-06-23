// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod file_handle;
pub mod inode_store;
pub mod mount_fd;
pub mod stat;
pub mod util;
pub mod xattrmap;

use super::fs_cache_req_handler::FsCacheReqHandler;
use crate::filesystem::{
    Context, Entry, FileSystem, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SetattrValid, SetxattrFlags, ZeroCopyReader, ZeroCopyWriter,
};
use crate::fuse;
use crate::passthrough::inode_store::{Inode, InodeData, InodeIds, InodeStore};
use crate::passthrough::util::{ebadf, einval, is_safe_inode, openat, reopen_fd_through_proc};
use crate::read_dir::ReadDir;
use file_handle::{FileHandle, FileOrHandle, OpenableFileHandle};
use mount_fd::{MPRError, MountFds};
use stat::{statx, StatExt};
use std::borrow::Cow;
use std::collections::{btree_map, BTreeMap};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use xattrmap::{AppliedRule, XattrMap};

const EMPTY_CSTR: &[u8] = b"\0";

type Handle = u64;

struct HandleData {
    inode: Inode,
    file: RwLock<File>,
}

macro_rules! scoped_cred {
    ($name:ident, $ty:ty, $syscall_nr:expr) => {
        #[derive(Debug)]
        struct $name;

        impl $name {
            // Changes the effective uid/gid of the current thread to `val`.  Changes
            // the thread's credentials back to root when the returned struct is dropped.
            fn new(val: $ty) -> io::Result<Option<$name>> {
                if val == 0 {
                    // Nothing to do since we are already uid 0.
                    return Ok(None);
                }

                // We want credential changes to be per-thread because otherwise
                // we might interfere with operations being carried out on other
                // threads with different uids/gids.  However, posix requires that
                // all threads in a process share the same credentials.  To do this
                // libc uses signals to ensure that when one thread changes its
                // credentials the other threads do the same thing.
                //
                // So instead we invoke the syscall directly in order to get around
                // this limitation.  Another option is to use the setfsuid and
                // setfsgid systems calls.   However since those calls have no way to
                // return an error, it's preferable to do this instead.

                // This call is safe because it doesn't modify any memory and we
                // check the return value.
                let res = unsafe { libc::syscall($syscall_nr, -1, val, -1) };
                if res == 0 {
                    Ok(Some($name))
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // do nothing :)
            }
        }
    };
}
scoped_cred!(ScopedUid, libc::uid_t, libc::SYS_setresuid);
scoped_cred!(ScopedGid, libc::gid_t, libc::SYS_setresgid);

fn set_creds(
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<(Option<ScopedUid>, Option<ScopedGid>)> {
    // We have to change the gid before we change the uid because if we change the uid first then we
    // lose the capability to change the gid.  However changing back can happen in any order.
    ScopedGid::new(gid).and_then(|gid| Ok((ScopedUid::new(uid)?, gid)))
}

struct ScopedCaps {
    cap: capng::Capability,
}

impl ScopedCaps {
    fn new(cap_name: &str) -> io::Result<Option<Self>> {
        use capng::{Action, CUpdate, Set, Type};

        let cap = capng::name_to_capability(cap_name).map_err(|_| {
            let err = io::Error::last_os_error();
            error!(
                "couldn't get the capability id for name {}: {:?}",
                cap_name, err
            );
            err
        })?;

        if capng::have_capability(Type::EFFECTIVE, cap) {
            let req = vec![CUpdate {
                action: Action::DROP,
                cap_type: Type::EFFECTIVE,
                capability: cap,
            }];
            capng::update(req).map_err(|e| {
                error!("couldn't drop {} capability: {:?}", cap, e);
                einval()
            })?;
            capng::apply(Set::CAPS).map_err(|e| {
                error!(
                    "couldn't apply capabilities after dropping {}: {:?}",
                    cap, e
                );
                einval()
            })?;
            Ok(Some(Self { cap }))
        } else {
            Ok(None)
        }
    }
}

impl Drop for ScopedCaps {
    fn drop(&mut self) {
        use capng::{Action, CUpdate, Set, Type};

        let req = vec![CUpdate {
            action: Action::ADD,
            cap_type: Type::EFFECTIVE,
            capability: self.cap,
        }];

        if let Err(e) = capng::update(req) {
            panic!("couldn't restore {} capability: {:?}", self.cap, e);
        }
        if let Err(e) = capng::apply(Set::CAPS) {
            panic!(
                "couldn't apply capabilities after restoring {}: {:?}",
                self.cap, e
            );
        }
    }
}

fn drop_effective_cap(cap_name: &str) -> io::Result<Option<ScopedCaps>> {
    ScopedCaps::new(cap_name)
}

struct ScopedUmask {
    umask: libc::mode_t,
}

impl ScopedUmask {
    fn new(new_umask: u32) -> io::Result<Option<Self>> {
        let umask = unsafe { libc::umask(new_umask) };
        Ok(Some(Self { umask }))
    }
}

impl Drop for ScopedUmask {
    fn drop(&mut self) {
        unsafe { libc::umask(self.umask) };
    }
}

fn set_umask(umask: u32) -> io::Result<Option<ScopedUmask>> {
    ScopedUmask::new(umask)
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Debug, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy::Auto
    }
}

/// When to use file handles to reference inodes instead of `O_PATH` file descriptors.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InodeFileHandlesMode {
    /// Never use file handles, always use `O_PATH` file descriptors.
    Never,

    /// Attempt to generate file handles, but fall back to `O_PATH` file descriptors where the
    /// underlying filesystem does not support file handles.
    Prefer,

    /// Always use file handles, never fall back to `O_PATH` file descriptors.
    Mandatory,
}

impl Default for InodeFileHandlesMode {
    fn default() -> Self {
        InodeFileHandlesMode::Never
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// The path of the root directory.
    ///
    /// The default is `/`.
    pub root_dir: String,

    /// A prefix to strip from the mount points listed in /proc/self/mountinfo.
    ///
    /// The default is `None`.
    pub mountinfo_prefix: Option<String>,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// An optional translation layer for host<->guest Extended Attribute (xattr) names.
    pub xattrmap: Option<XattrMap>,

    /// The xattr name that "security.capability" is remapped to, if the client remapped it at all.
    /// If the client's xattrmap did not remap "security.capability", this will be `None`.
    pub xattr_security_capability: Option<CString>,

    /// Optional `File` object for /proc/self/fd. Callers can open a `File` and pass it here, so
    /// there's no need to open it in PassthroughFs::new(). This is specially useful for
    /// sandboxing.
    ///
    /// The default is `None`.
    pub proc_sfd_rawfd: Option<File>,

    /// Optional `File` object for /proc/self/mountinfo.  Callers can open a `File` and pass it
    /// here, so there is no need to open it in PassthroughFs::new().  This is especially useful
    /// for sandboxing.
    ///
    /// The default is `None`.
    pub proc_mountinfo_rawfd: Option<File>,

    /// Whether the file system should announce submounts to the guest.  Not doing so means that
    /// the FUSE client may see st_ino collisions: This stat field is passed through, so if the
    /// shared directory encompasses multiple mounts, some inodes (in different file systems) may
    /// have the same st_ino value.  If the FUSE client does not know these inodes are in different
    /// file systems, then it will be oblivious to this collision.
    /// By announcing submount points, the FUSE client can create virtual submounts with distinct
    /// st_dev values where necessary, so that the combination of st_dev and st_ino will stay
    /// unique.
    /// On the other hand, it may be undesirable to let the client know the shared directory's
    /// submount structure.  The user needs to decide which drawback weighs heavier for them, which
    /// is why this is a configurable option.
    ///
    /// The default is `false`.
    pub announce_submounts: bool,

    /// Whether to use file handles to reference inodes.  We need to be able to open file
    /// descriptors for arbitrary inodes, and by default that is done by storing an `O_PATH` FD in
    /// `InodeData`.  Not least because there is a maximum number of FDs a process can have open
    /// users may find it preferable to store a file handle instead, which we can use to open an FD
    /// when necessary.
    /// So this switch allows to choose between the alternatives: When set to `Never`, `InodeData`
    /// will store `O_PATH` FDs.  Otherwise, we will attempt to generate and store a file handle
    /// instead.  With `Prefer`, errors that are inherent to file handles (like no support from the
    /// underlying filesystem) lead to falling back to `O_PATH` FDs, and only generic errors (like
    /// `ENOENT` or `ENOMEM`) are passed to the guest.  `Mandatory` enforces the use of file
    /// handles, returning all errors to the guest.
    ///
    /// The default is `Never`.
    pub inode_file_handles: InodeFileHandlesMode,

    /// Whether the file system should support READDIRPLUS (READDIR+LOOKUP) operations.
    ///
    /// The default is `false`.
    pub readdirplus: bool,

    /// Whether the file system should honor the O_DIRECT flag. If this option is disabled (which
    /// is the default value), that flag will be filtered out at `open_inode`.
    ///
    /// The default is `false`.
    pub allow_direct_io: bool,

    /// If `killpriv_v2` is true then it indicates that the file system is expected to clear the
    /// setuid and setgid bits.
    pub killpriv_v2: bool,

    /// Enable support for posix ACLs
    ///
    /// The default is `false`.
    pub posix_acl: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            mountinfo_prefix: None,
            xattr: false,
            xattrmap: None,
            xattr_security_capability: None,
            proc_sfd_rawfd: None,
            proc_mountinfo_rawfd: None,
            announce_submounts: false,
            inode_file_handles: Default::default(),
            readdirplus: true,
            allow_direct_io: false,
            killpriv_v2: false,
            posix_acl: false,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    // File descriptors for various points in the file system tree. These fds are always opened with
    // the `O_PATH` option so they cannot be used for reading or writing any data. See the
    // documentation of the `O_PATH` flag in `open(2)` for more details on what one can and cannot
    // do with an fd opened with this flag.
    inodes: RwLock<InodeStore>,
    next_inode: AtomicU64,

    // File descriptors for open files and directories. Unlike the fds in `inodes`, these _can_ be
    // used for reading and writing data.
    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,

    // Maps mount IDs to an open FD on the respective ID for the purpose of open_by_handle_at().
    mount_fds: MountFds,

    // File descriptor pointing to the `/proc/self/fd` directory. This is used to convert an fd from
    // `inodes` into one that can go into `handles`. This is accomplished by reading the
    // `/proc/self/fd/{}` symlink. We keep an open fd here in case the file system tree that we are
    // meant to be serving doesn't have access to `/proc/self/fd`.
    proc_self_fd: File,

    // File descriptor pointing to the `/` directory.
    root_fd: File,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,

    // Whether to announce submounts (i.e., whether the guest supports them and whether they are
    // enabled in the configuration)
    announce_submounts: AtomicBool,

    // Whether posix ACLs is enabled.
    posix_acl: AtomicBool,

    cfg: Config,
}

impl PassthroughFs {
    pub fn new(mut cfg: Config) -> io::Result<PassthroughFs> {
        let proc_self_fd = if let Some(fd) = cfg.proc_sfd_rawfd.take() {
            fd
        } else {
            openat(
                &libc::AT_FDCWD,
                "/proc/self/fd",
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?
        };

        let root_fd = openat(
            &libc::AT_FDCWD,
            "/",
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;

        let mountinfo_fd = if let Some(fd) = cfg.proc_mountinfo_rawfd.take() {
            fd
        } else {
            openat(
                &libc::AT_FDCWD,
                "/proc/self/mountinfo",
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?
        };

        let mut fs = PassthroughFs {
            inodes: RwLock::new(Default::default()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 1),
            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(0),
            mount_fds: MountFds::new(mountinfo_fd, cfg.mountinfo_prefix.clone()),
            proc_self_fd,
            root_fd,
            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            posix_acl: AtomicBool::new(false),
            cfg,
        };

        // Check to see if the client remapped "security.capability", if so,
        // stash its mapping since the daemon will have to enforce semantics
        // that the host kernel otherwise would if the xattrname was not mapped.
        let sec_xattr = unsafe { CStr::from_bytes_with_nul_unchecked(b"security.capability\0") };
        fs.cfg.xattr_security_capability = fs
            .map_client_xattrname(sec_xattr)
            .ok()
            .filter(|n| !sec_xattr.eq(n))
            .map(CString::from);

        fs.check_working_file_handles()?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        Ok(fs)
    }

    pub fn keep_fds(&self) -> Vec<RawFd> {
        vec![self.proc_self_fd.as_raw_fd()]
    }

    fn find_handle(&self, handle: Handle, inode: Inode) -> io::Result<Arc<HandleData>> {
        self.handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        if !self.cfg.allow_direct_io && flags & libc::O_DIRECT != 0 {
            flags &= !libc::O_DIRECT;
        }

        data.open_file(flags | libc::O_CLOEXEC, &self.proc_self_fd)?
            .into_file()
    }

    /// Generate a file handle for `fd` using `FileHandle::from_fd()`.  `st` is `fd`'s stat
    /// information (we may need the mount ID for errors/warnings).
    ///
    /// These are the possible return values:
    /// - `Ok(Some(_))`: Success, caller should use this file handle.
    /// - `Ok(None)`: No error, but no file handle is available.  The caller should fall back to
    ///               using an `O_PATH` FD.
    /// - `Err(_)`: An error occurred, the caller should return this to the guest.
    ///
    /// This function takes the chosen `self.cfg.inode_file_handles` mode into account:
    /// - `Never`: Always return `Ok(None)`.
    /// - `Prefer`: Return `Ok(None)` when file handles are not supported by this filesystem.
    ///             Otherwise, return either `Ok(Some(_))` or `Err(_)`, depending on whether a file
    ///             handle could be generated or not.
    /// - `Mandatory`: Never return `Ok(None)`.  When the filesystem does not support file handles,
    ///                return an `Err(_)`.
    ///
    /// When the filesystem does not support file handles, this is logged (as a warning in
    /// `Prefer` mode, and as an error in `Mandatory` mode) one time per filesystem.
    fn get_file_handle_opt(
        &self,
        fd: &impl AsRawFd,
        st: &StatExt,
    ) -> io::Result<Option<FileHandle>> {
        let handle = match self.cfg.inode_file_handles {
            InodeFileHandlesMode::Never => {
                // Let's make this quick, so we can skip this case below
                return Ok(None);
            }

            InodeFileHandlesMode::Prefer | InodeFileHandlesMode::Mandatory => {
                FileHandle::from_fd(fd)?
            }
        };

        if handle.is_none() {
            // No error, but no handle (because of EOPNOTSUPP/EOVERFLOW)?  Log it.
            let io_err = io::Error::from_raw_os_error(libc::EOPNOTSUPP);

            let desc = match self.cfg.inode_file_handles {
                InodeFileHandlesMode::Never => unreachable!(),
                InodeFileHandlesMode::Prefer => {
                    "Filesystem does not support file handles, falling back to O_PATH FDs"
                }
                InodeFileHandlesMode::Mandatory => "Filesystem does not support file handles",
            };

            // Use the MPRError object, because (with a mount ID obtained through statx())
            // `self.mount_fds.error_for()` will attempt to add a prefix to the error description
            // that describes the offending filesystem by mount point and mount ID, and will also
            // suppress the message if we have already logged any error concerning file handles for
            // the respective filesystem (so we only log errors/warnings once).
            let err: MPRError = if st.mnt_id > 0 {
                // Valid mount ID
                self.mount_fds.error_for(st.mnt_id, io_err)
            } else {
                // No valid mount ID, return error object not bound to a filesystem
                io_err.into()
            }
            .set_desc(desc.to_string());

            // In `Prefer` mode, warn; in `Mandatory` mode, log and return an error.
            // (Suppress logging if the error is silenced, which means that we have already logged
            // a warning/error for this filesystem.)
            match self.cfg.inode_file_handles {
                InodeFileHandlesMode::Never => unreachable!(),
                InodeFileHandlesMode::Prefer => {
                    if !err.silent() {
                        warn!("{}", err);
                    }
                }
                InodeFileHandlesMode::Mandatory => {
                    if !err.silent() {
                        error!("{}", err);
                    }
                    return Err(err.into_inner());
                }
            }
        }

        Ok(handle)
    }

    fn make_file_handle_openable(&self, fh: &FileHandle) -> io::Result<OpenableFileHandle> {
        fh.to_openable(&self.mount_fds, |fd, flags| {
            reopen_fd_through_proc(&fd, flags, &self.proc_self_fd)
        })
        .map_err(|e| {
            if !e.silent() {
                error!("{}", e);
            }
            e.into_inner()
        })
    }

    fn check_working_file_handles(&mut self) -> io::Result<()> {
        if self.cfg.inode_file_handles == InodeFileHandlesMode::Never {
            // No need to check anything
            return Ok(());
        }

        // Try to open the root directory, turn it into a file handle, then try to open that file
        // handle to see whether file handles do indeed work
        // (Note that we pass through all I/O errors to the caller, because `PassthroughFs::init()`
        // will do these calls (`openat()`, `stat()`, etc.) anyway, so if they do not work now,
        // they probably are not going to work later either.  Better to report errors early then.)
        let root_dir = openat(
            &libc::AT_FDCWD,
            self.cfg.root_dir.as_str(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;

        let st = statx(&root_dir, None)?;
        if let Some(h) = self.get_file_handle_opt(&root_dir, &st)? {
            // Got an openable file handle, try opening it
            match self.make_file_handle_openable(&h)?.open(libc::O_PATH) {
                Ok(_) => (),
                Err(e) => match self.cfg.inode_file_handles {
                    InodeFileHandlesMode::Never => unreachable!(),
                    InodeFileHandlesMode::Prefer => {
                        warn!("Failed to open file handle for the root node: {}", e);
                        warn!("File handles do not appear safe to use, disabling file handles altogether");
                        self.cfg.inode_file_handles = InodeFileHandlesMode::Never;
                    }
                    InodeFileHandlesMode::Mandatory => {
                        error!("Failed to open file handle for the root node: {}", e);
                        error!("Refusing to use (mandatory) file handles, as they do not appear safe to use");
                        return Err(e);
                    }
                },
            }
        } else {
            // Did not get an openable file handle (nor an error), so we cannot be in `mandatory`
            // mode.  We also cannot be in `never` mode, because that is sorted out at the very
            // beginning of this function.  Still, use `match` so the compiler could warn us if we
            // were to forget some (future?) variant.
            match self.cfg.inode_file_handles {
                InodeFileHandlesMode::Never => unreachable!(),
                InodeFileHandlesMode::Prefer => {
                    warn!("Failed to generate a file handle for the root node, disabling file handles altogether");
                    self.cfg.inode_file_handles = InodeFileHandlesMode::Never;
                }
                InodeFileHandlesMode::Mandatory => unreachable!(),
            }
        }

        Ok(())
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let p = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let p_file = p.get_file()?;

        let path_fd = {
            // Safe because this doesn't modify any memory and we check the return value.
            let fd = unsafe {
                libc::openat(
                    p_file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Safe because we just opened this fd.
            unsafe { File::from_raw_fd(fd) }
        };

        let st = statx(&path_fd, None)?;

        // Note that this will always be `None` if `cfg.inode_file_handles` is `Never`, but we only
        // really need the handle when we do not have an `O_PATH` fd open for every inode.  So if
        // `cfg.inode_file_handles` is `Never`, we do not need it anyway.
        let handle = self.get_file_handle_opt(&path_fd, &st)?;

        let mut attr_flags: u32 = 0;

        if st.st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && self.announce_submounts.load(Ordering::Relaxed)
            && (st.st.st_dev != p.ids.dev || st.mnt_id != p.ids.mnt_id)
        {
            attr_flags |= fuse::ATTR_SUBMOUNT;
        }

        let ids = InodeIds {
            ino: st.st.st_ino,
            dev: st.st.st_dev,
            mnt_id: st.mnt_id,
        };

        let existing_inode = Self::claim_inode(&self.inodes.read().unwrap(), handle.as_ref(), &ids);

        let inode = if let Some(inode) = existing_inode {
            inode
        } else {
            let file_or_handle = if let Some(h) = handle.as_ref() {
                FileOrHandle::Handle(self.make_file_handle_openable(h)?)
            } else {
                FileOrHandle::File(path_fd)
            };

            // There is a possible race here where two (or more) threads end up creating an inode
            // ID.  However, only the one in the thread that locks `self.inodes` first will be used
            // and the others are wasted.
            let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
            let mut inodes = self.inodes.write().unwrap();

            if let Some(inode) = Self::claim_inode(&inodes, handle.as_ref(), &ids) {
                // An inode was added concurrently while we did not hold a lock on `self.inodes`, so
                // we use that instead.  `file_or_handle` will be dropped.
                inode
            } else {
                inodes.insert(Arc::new(InodeData {
                    inode,
                    file_or_handle,
                    refcount: AtomicU64::new(1),
                    ids,
                    mode: st.st.st_mode,
                }));

                inode
            }
        };

        Ok(Entry {
            inode,
            generation: 0,
            attr: st.st,
            attr_flags,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    /// Attempts to get an inode from `inodes` and increment its refcount.  Returns the inode
    /// number on success and `None` on failure.  Reasons for failure can be that the inode isn't
    /// in the map or that the refcount is zero.  This function will never increment a refcount
    /// that's already zero.
    fn claim_inode(
        inodes: &InodeStore,
        handle: Option<&FileHandle>,
        ids: &InodeIds,
    ) -> Option<Inode> {
        let data = handle.and_then(|h| inodes.get_by_handle(h)).or_else(|| {
            inodes.get_by_ids(ids).filter(|data| {
                // When we have to fall back to looking up an inode by its inode ID, ensure
                // that we hit an entry that has a valid file descriptor.  Having an FD
                // open means that the inode cannot really be deleted until the FD is
                // closed, so that the inode ID remains valid until we evict the
                // `InodeData`.  With no FD open (and just a file handle), the inode can be
                // deleted while we still have our `InodeData`, and so the inode ID may be
                // reused by a completely different new inode.  Such inodes must be looked
                // up by file handle, because this handle contains a generation ID to
                // differentiate between the old and the new inode.
                matches!(data.file_or_handle, FileOrHandle::File(_))
            })
        });
        if let Some(data) = data {
            // We use a CAS loop instead of `fetch_add()`, because we must never increment the
            // refcount from zero to one.
            let mut n = data.refcount.load(Ordering::Relaxed);
            loop {
                if n == 0 {
                    return None;
                }

                match data.refcount.compare_exchange_weak(
                    n,
                    n + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(data.inode),
                    Err(old) => n = old,
                }
            }
        }
        None
    }

    fn do_open(
        &self,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let file = RwLock::new({
            let _killpriv_guard = if self.cfg.killpriv_v2 && kill_priv {
                drop_effective_cap("FSETID")?
            } else {
                None
            };
            self.open_inode(inode, flags as i32)?
        });

        if flags & (libc::O_TRUNC as u32) != 0 {
            let file = file.read().expect("poisoned lock");
            self.drop_security_capability(file.as_raw_fd())?;
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData { inode, file };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(
                OpenOptions::DIRECT_IO,
                flags & (libc::O_DIRECTORY as u32) == 0,
            ),
            CachePolicy::Always => {
                if flags & (libc::O_DIRECTORY as u32) == 0 {
                    opts |= OpenOptions::KEEP_CACHE;
                } else {
                    opts |= OpenOptions::CACHE_DIR;
                }
            }
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle) {
            if e.get().inode == inode {
                // We don't need to close the file here because that will happen automatically when
                // the last `Arc` is dropped.
                e.remove();
                return Ok(());
            }
        }

        Err(ebadf())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(libc::stat64, Duration)> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let inode_file = data.get_file()?;
        let st = statx(&inode_file, None)?.st;

        Ok((st, self.cfg.attr_timeout))
    }

    fn do_unlink(&self, parent: Inode, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let parent_file = data.get_file()?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(parent_file.as_raw_fd(), name.as_ptr(), flags) };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn block_xattr(&self, name: &[u8]) -> bool {
        // Currently we only filter out posix acl xattrs.
        // If acls are enabled, there is nothing to  filter.
        if self.posix_acl.load(Ordering::Relaxed) {
            return false;
        }

        let acl_access = "system.posix_acl_access".as_bytes();
        let acl_default = "system.posix_acl_default".as_bytes();
        acl_access.starts_with(name) || acl_default.starts_with(name)
    }

    fn map_client_xattrname<'a>(&self, name: &'a CStr) -> std::io::Result<Cow<'a, CStr>> {
        if self.block_xattr(name.to_bytes()) {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
        }

        match &self.cfg.xattrmap {
            Some(map) => match map.map_client_xattr(name).expect("unterminated mapping") {
                AppliedRule::Deny => Err(io::Error::from_raw_os_error(libc::EPERM)),
                AppliedRule::Unsupported => Err(io::Error::from_raw_os_error(libc::ENOTSUP)),
                AppliedRule::Pass(new_name) => Ok(new_name),
            },
            None => Ok(Cow::Borrowed(name)),
        }
    }

    fn map_server_xattrlist(&self, xattr_names: Vec<u8>) -> Vec<u8> {
        let all_xattrs = match &self.cfg.xattrmap {
            Some(map) => map
                .map_server_xattrlist(xattr_names)
                .expect("unterminated mapping"),
            None => xattr_names,
        };

        // filter out the blocked xattrs
        let mut filtered = Vec::with_capacity(all_xattrs.len());
        let all_xattrs = all_xattrs.split(|b| *b == 0).filter(|bs| !bs.is_empty());

        for xattr in all_xattrs {
            if !self.block_xattr(xattr) {
                filtered.extend_from_slice(xattr);
                filtered.push(0);
            }
        }

        if filtered.is_empty() {
            filtered.push(0);
        }
        filtered.shrink_to_fit();

        filtered
    }

    fn drop_security_capability(&self, fd: libc::c_int) -> io::Result<()> {
        match self.cfg.xattr_security_capability.as_ref() {
            // Unmapped, let the kernel take care of this.
            None => Ok(()),
            // Otherwise we have to uphold the same semantics the kernel
            // would; which is to drop the "security.capability" xattr
            // on write
            Some(xattrname) => {
                let res = unsafe { libc::fremovexattr(fd, xattrname.as_ptr()) };
                if res == 0 {
                    Ok(())
                } else {
                    let eno = io::Error::last_os_error();
                    match eno.raw_os_error().unwrap() {
                        libc::ENODATA | libc::ENOTSUP => Ok(()),
                        _ => Err(eno),
                    }
                }
            }
        }
    }
}

fn forget_one(inodes: &mut InodeStore, inode: Inode, count: u64) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // We don't need any stronger ordering, because the refcount itself doesn't protect any
            // data.  The `inodes` map is protected since we hold an exclusive reference (obtained
            // from an `RwLock`).
            if data.refcount.compare_exchange(
                refcount,
                new_count,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) == Ok(refcount)
            {
                if new_count == 0 {
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;
    type DirIter = ReadDir<Vec<u8>>;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // We use `O_PATH` because we just want this for traversing the directory tree
        // and not for actually reading the contents.
        let path_fd = openat(
            &libc::AT_FDCWD,
            self.cfg.root_dir.as_str(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;

        let st = statx(&path_fd, None)?;
        let handle = self.get_file_handle_opt(&path_fd, &st)?;

        let file_or_handle = if let Some(h) = handle.as_ref() {
            FileOrHandle::Handle(self.make_file_handle_openable(h)?)
        } else {
            FileOrHandle::File(path_fd)
        };

        let mut inodes = self.inodes.write().unwrap();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(Arc::new(InodeData {
            inode: fuse::ROOT_ID,
            file_or_handle,
            refcount: AtomicU64::new(2),
            ids: InodeIds {
                ino: st.st.st_ino,
                dev: st.st.st_dev,
                mnt_id: st.mnt_id,
            },
            mode: st.st.st_mode,
        }));

        let mut opts = if self.cfg.readdirplus {
            FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO
        } else {
            FsOptions::empty()
        };
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        if self.cfg.announce_submounts {
            if capable.contains(FsOptions::SUBMOUNTS) {
                self.announce_submounts.store(true, Ordering::Relaxed);
            } else {
                eprintln!("Warning: Cannot announce submounts, client does not support it");
            }
        }
        if self.cfg.killpriv_v2 {
            if capable.contains(FsOptions::HANDLE_KILLPRIV_V2) {
                opts |= FsOptions::HANDLE_KILLPRIV_V2;
            } else {
                warn!("Cannot enable KILLPRIV_V2, client does not support it");
            }
        }
        if self.cfg.posix_acl {
            let acl_required_flags =
                FsOptions::POSIX_ACL | FsOptions::DONT_MASK | FsOptions::SETXATTR_EXT;
            if capable.contains(acl_required_flags) {
                opts |= acl_required_flags;
                self.posix_acl.store(true, Ordering::Relaxed);
                debug!("init: enabling posix acl");
            } else {
                error!("Cannot enable posix ACLs, client does not support it");
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
        self.writeback.store(false, Ordering::Relaxed);
        self.announce_submounts.store(false, Ordering::Relaxed);
        self.posix_acl.store(false, Ordering::Relaxed);
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<libc::statvfs64> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let inode_file = data.get_file()?;
        let mut out = MaybeUninit::<libc::statvfs64>::zeroed();

        // Safe because this will only modify `out` and we check the return value.
        let res = unsafe { libc::fstatvfs64(inode_file.as_raw_fd(), out.as_mut_ptr()) };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.write().unwrap();

        forget_one(&mut inodes, inode, count)
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();

        for (inode, count) in requests {
            forget_one(&mut inodes, inode, count)
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, false, flags | (libc::O_DIRECTORY as u32))
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let parent_file = data.get_file()?;

        let res = {
            let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
            let _umask_guard = if self.posix_acl.load(Ordering::Relaxed) {
                set_umask(umask)?
            } else {
                None
            };

            // Safe because this doesn't modify any memory and we check the return value.
            unsafe { libc::mkdirat(parent_file.as_raw_fd(), name.as_ptr(), mode) }
        };
        if res == 0 {
            self.do_lookup(parent, name)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
    ) -> io::Result<Self::DirIter> {
        if size == 0 {
            return Ok(ReadDir::default());
        }
        let data = self.find_handle(handle, inode)?;

        let buf = vec![0; size as usize];

        // Since we are going to work with the kernel offset, we have to acquire the file
        // lock for both the `lseek64` and `getdents64` syscalls to ensure that no other
        // thread changes the kernel offset while we are using it.
        let dir = data.file.write().unwrap();

        ReadDir::new(&*dir, offset as libc::off64_t, buf)
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, kill_priv, flags)
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let parent_file = data.get_file()?;

        let fd = {
            let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
            let _umask_guard = if self.posix_acl.load(Ordering::Relaxed) {
                set_umask(umask)?
            } else {
                None
            };

            // Safe because this doesn't modify any memory and we check the return value. We don't
            // really check `flags` because if the kernel can't handle poorly specified flags then we
            // have much bigger problems.
            //
            // Add libc:O_EXCL to ensure we're not accidentally opening a file the guest wouldn't
            // be allowed to access otherwise.
            unsafe {
                libc::openat(
                    parent_file.as_raw_fd(),
                    name.as_ptr(),
                    flags as i32
                        | libc::O_CREAT
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_EXCL,
                    mode,
                )
            }
        };

        let (entry, handle) = if fd < 0 {
            // Ignore the error if the file exists and O_EXCL is not present in `flags`
            let last_error = io::Error::last_os_error();
            match last_error.kind() {
                io::ErrorKind::AlreadyExists => {
                    if (flags as i32 & libc::O_EXCL) != 0 {
                        return Err(last_error);
                    }
                }
                _ => return Err(last_error),
            }

            let entry = self.do_lookup(parent, name)?;
            let (handle, _) = self.do_open(entry.inode, kill_priv, flags)?;
            let handle = handle.ok_or_else(ebadf)?;

            (entry, handle)
        } else {
            // Safe because we just opened this fd.
            let file = RwLock::new(unsafe { File::from_raw_fd(fd) });

            let entry = self.do_lookup(parent, name)?;

            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            let data = HandleData {
                inode: entry.inode,
                file,
            };

            self.handles.write().unwrap().insert(handle, Arc::new(data));

            (entry, handle)
        };

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((entry, Some(handle), opts))
    }

    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, 0)
    }

    fn setupmapping<T: FsCacheReqHandler>(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        vu_req: &mut T,
    ) -> io::Result<()> {
        debug!(
            "setupmapping: ino {:?} foffset {} len {} flags {} moffset {}",
            inode, foffset, len, flags, moffset
        );

        let open_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };

        let file = self.open_inode(inode, open_flags as i32)?;
        (*vu_req).map(foffset, moffset, len, flags, file.as_raw_fd())
    }

    fn removemapping<T: FsCacheReqHandler>(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        vu_req: &mut T,
    ) -> io::Result<()> {
        (*vu_req).unmap(requests)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.find_handle(handle, inode)?;

        // This is safe because write_from uses preadv64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        w.write_from(&f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.find_handle(handle, inode)?;

        // This is safe because read_to uses pwritev64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();

        {
            let _killpriv_guard = if self.cfg.killpriv_v2 && kill_priv {
                // We need to drop FSETID during a write so that the kernel will remove setuid
                // or setgid bits from the file if it was written to by someone other than the
                // owner.
                drop_effective_cap("FSETID")?
            } else {
                None
            };

            self.drop_security_capability(f.as_raw_fd())?;

            r.read_to(&f, size as usize, offset)
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: libc::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let inode_data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        // In this case, we need to open a new O_RDWR FD
        let rdwr_inode_file = handle.is_none() && valid.intersects(SetattrValid::SIZE);
        let inode_file = if rdwr_inode_file {
            inode_data.open_file(libc::O_NONBLOCK | libc::O_RDWR, &self.proc_self_fd)?
        } else {
            inode_data.get_file()?
        };

        enum Data {
            Handle(Arc<HandleData>, RawFd),
            ProcPath(CString),
        }

        // If we have a handle then use it otherwise get a new fd from the inode.
        let data = if let Some(handle) = handle {
            let hd = self.find_handle(handle, inode)?;

            let fd = hd.file.write().unwrap().as_raw_fd();
            Data::Handle(hd, fd)
        } else {
            let pathname = CString::new(format!("{}", inode_file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Data::ProcPath(pathname)
        };

        if valid.contains(SetattrValid::MODE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                match data {
                    Data::Handle(_, fd) => libc::fchmod(fd, attr.st_mode),
                    Data::ProcPath(ref p) => {
                        libc::fchmodat(self.proc_self_fd.as_raw_fd(), p.as_ptr(), attr.st_mode, 0)
                    }
                }
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };

            self.drop_security_capability(inode_file.as_raw_fd())?;

            // Safe because this is a constant value and a valid C string.
            let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                libc::fchownat(
                    inode_file.as_raw_fd(),
                    empty.as_ptr(),
                    uid,
                    gid,
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.contains(SetattrValid::SIZE) {
            let fd = match data {
                Data::Handle(_, fd) => fd,
                _ => {
                    // Should have opened an O_RDWR inode_file above
                    assert!(rdwr_inode_file);
                    inode_file.as_raw_fd()
                }
            };

            let _killpriv_guard =
                if self.cfg.killpriv_v2 && valid.contains(SetattrValid::KILL_SUIDGID) {
                    drop_effective_cap("FSETID")?
                } else {
                    None
                };

            // Safe because this doesn't modify any memory and we check the return value.
            let res = self
                .drop_security_capability(fd)
                .map(|_| unsafe { libc::ftruncate(fd, attr.st_size) })?;
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                Data::ProcPath(ref p) => unsafe {
                    libc::utimensat(self.proc_self_fd.as_raw_fd(), p.as_ptr(), tvs.as_ptr(), 0)
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(inode)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let old_inode = self
            .inodes
            .read()
            .unwrap()
            .get(&olddir)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;
        let new_inode = self
            .inodes
            .read()
            .unwrap()
            .get(&newdir)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let old_file = old_inode.get_file()?;
        let new_file = new_inode.get_file()?;

        // Safe because this doesn't modify any memory and we check the return value.
        // TODO: Switch to libc::renameat2 once https://github.com/rust-lang/libc/pull/1508 lands
        // and we have glibc 2.28.
        let res = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_file.as_raw_fd(),
                oldname.as_ptr(),
                new_file.as_raw_fd(),
                newname.as_ptr(),
                flags,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let parent_file = data.get_file()?;

        let res = {
            let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
            let _umask_guard = if self.posix_acl.load(Ordering::Relaxed) {
                set_umask(umask)?
            } else {
                None
            };

            // Safe because this doesn't modify any memory and we check the return value.
            unsafe {
                libc::mknodat(
                    parent_file.as_raw_fd(),
                    name.as_ptr(),
                    mode as libc::mode_t,
                    u64::from(rdev),
                )
            }
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            self.do_lookup(parent, name)
        }
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;
        let new_inode = self
            .inodes
            .read()
            .unwrap()
            .get(&newparent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let inode_file = data.get_file()?;
        let newparent_file = new_inode.get_file()?;

        let procname = CString::new(format!("{}", inode_file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::linkat(
                self.proc_self_fd.as_raw_fd(),
                procname.as_ptr(),
                newparent_file.as_raw_fd(),
                newname.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if res == 0 {
            self.do_lookup(newparent, newname)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let parent_file = data.get_file()?;

        let res = {
            let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;

            // Safe because this doesn't modify any memory and we check the return value.
            unsafe { libc::symlinkat(linkname.as_ptr(), parent_file.as_raw_fd(), name.as_ptr()) }
        };
        if res == 0 {
            self.do_lookup(parent, name)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let inode_file = data.get_file()?;

        let mut buf = vec![0; libc::PATH_MAX as usize];

        // Safe because this is a constant value and a valid C string.
        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

        // Safe because this will only modify the contents of `buf` and we check the return value.
        let res = unsafe {
            libc::readlinkat(
                inode_file.as_raw_fd(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        buf.resize(res as usize, 0);
        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        let data = self.find_handle(handle, inode)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.write().unwrap().as_raw_fd());
            if newfd < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::close(newfd) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn fsync(&self, _ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        let data = self.find_handle(handle, inode)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            if datasync {
                libc::fdatasync(fd)
            } else {
                libc::fsync(fd)
            }
        };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let inode_file = data.get_file()?;
        let st = statx(&inode_file, None)?.st;
        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        Ok(())
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
        extra_flags: SetxattrFlags,
    ) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let name = self.map_client_xattrname(name)?;

        // If we are setting posix access acl and if SGID needs to be
        // cleared, then switch to caller's gid and drop CAP_FSETID
        // and that should make sure host kernel clears SGID.
        //
        // This probably will not work when we support idmapped mounts.
        // In that case we will need to find a non-root gid and switch
        // to it. (Instead of gid in request). Fix it when we support
        // idmapped mounts.
        let xattr_name = name.as_ref().to_str().unwrap();
        let _clear_sgid_guard = if self.posix_acl.load(Ordering::Relaxed)
            && extra_flags.contains(SetxattrFlags::SETXATTR_ACL_KILL_SGID)
            && xattr_name.eq("system.posix_acl_access")
        {
            (drop_effective_cap("FSETID")?, set_creds(ctx.uid, ctx.gid)?)
        } else {
            (None, (None, None))
        };

        let res = if is_safe_inode(data.mode) {
            // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
            // need to get a new fd.
            let file = self.open_inode(inode, libc::O_RDONLY | libc::O_NONBLOCK)?;

            self.drop_security_capability(file.as_raw_fd())?;

            // Safe because this doesn't modify any memory and we check the return value.
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    flags as libc::c_int,
                )
            }
        } else {
            let file = data.get_file()?;

            self.drop_security_capability(file.as_raw_fd())?;

            let procname = CString::new(format!("{}", file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let err = unsafe { libc::fchdir(self.proc_self_fd.as_raw_fd()) };
            assert!(err == 0);

            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                libc::setxattr(
                    procname.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    flags as libc::c_int,
                )
            };

            let err = unsafe { libc::fchdir(self.root_fd.as_raw_fd()) };
            assert!(err == 0);

            res
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let mut buf = vec![0; size as usize];

        let name = self.map_client_xattrname(name).map_err(|e| {
            if e.kind() == ErrorKind::PermissionDenied {
                io::Error::from_raw_os_error(libc::ENODATA)
            } else {
                e
            }
        })?;

        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let res = if is_safe_inode(data.mode) {
            // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
            // need to get a new fd.
            let file = self.open_inode(inode, libc::O_RDONLY | libc::O_NONBLOCK)?;

            // Safe because this will only modify the contents of `buf`.
            unsafe {
                libc::fgetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    size as libc::size_t,
                )
            }
        } else {
            let file = data.get_file()?;

            let procname = CString::new(format!("{}", file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let err = unsafe { libc::fchdir(self.proc_self_fd.as_raw_fd()) };
            assert!(err == 0);

            // Safe because this will only modify the contents of `buf`.
            let res = unsafe {
                libc::getxattr(
                    procname.as_ptr(),
                    name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    size as libc::size_t,
                )
            };

            let err = unsafe { libc::fchdir(self.root_fd.as_raw_fd()) };
            assert!(err == 0);

            res
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let mut buf = vec![0; size as usize];

        let res = if is_safe_inode(data.mode) {
            // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
            // need to get a new fd.
            let file = self.open_inode(inode, libc::O_RDONLY | libc::O_NONBLOCK)?;

            // Safe because this will only modify the contents of `buf`.
            unsafe {
                libc::flistxattr(
                    file.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    size as libc::size_t,
                )
            }
        } else {
            let file = data.get_file()?;

            let procname = CString::new(format!("{}", file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let err = unsafe { libc::fchdir(self.proc_self_fd.as_raw_fd()) };
            assert!(err == 0);

            // Safe because this will only modify the contents of `buf`.
            let res = unsafe {
                libc::listxattr(
                    procname.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    size as libc::size_t,
                )
            };
            let err = unsafe { libc::fchdir(self.root_fd.as_raw_fd()) };
            assert!(err == 0);

            res
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(ListxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            let buf = self.map_server_xattrlist(buf);
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)?;

        let name = self.map_client_xattrname(name)?;

        let res = if is_safe_inode(data.mode) {
            // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
            // need to get a new fd.
            let file = self.open_inode(inode, libc::O_RDONLY | libc::O_NONBLOCK)?;

            // Safe because this doesn't modify any memory and we check the return value.
            unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) }
        } else {
            let file = data.get_file()?;

            let procname = CString::new(format!("{}", file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let err = unsafe { libc::fchdir(self.proc_self_fd.as_raw_fd()) };
            assert!(err == 0);

            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe { libc::removexattr(procname.as_ptr(), name.as_ptr()) };

            let err = unsafe { libc::fchdir(self.root_fd.as_raw_fd()) };
            assert!(err == 0);

            res
        };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self.find_handle(handle, inode)?;

        let fd = data.file.write().unwrap().as_raw_fd();
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::fallocate64(
                fd,
                mode as libc::c_int,
                offset as libc::off64_t,
                length as libc::off64_t,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let data = self.find_handle(handle, inode)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek(fd, offset as libc::off64_t, whence as libc::c_int) };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as u64)
        }
    }

    fn copyfilerange(
        &self,
        _ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        let data_in = self.find_handle(handle_in, inode_in)?;

        // Take just a read lock as we're not going to alter the file descriptor offset.
        let fd_in = data_in.file.read().unwrap().as_raw_fd();

        let data_out = self.find_handle(handle_out, inode_out)?;

        // Take just a read lock as we're not going to alter the file descriptor offset.
        let fd_out = data_out.file.read().unwrap().as_raw_fd();

        // Safe because this will only modify `offset_in` and `offset_out` and we check
        // the return value.
        let res = unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                fd_in,
                &mut (offset_in as i64) as &mut _ as *mut _,
                fd_out,
                &mut (offset_out as i64) as &mut _ as *mut _,
                len,
                flags,
            )
        };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    fn syncfs(&self, _ctx: Context, inode: Inode) -> io::Result<()> {
        // TODO: Branch here depending on whether virtiofsd announces submounts or not.

        let file = self.open_inode(inode, libc::O_RDONLY | libc::O_NOFOLLOW)?;
        let raw_fd = file.as_raw_fd();
        debug!("syncfs: inode={}, mount_fd={}", inode, raw_fd);
        let ret = unsafe { libc::syncfs(raw_fd) };
        if ret != 0 {
            // Thread-safe, because errno is stored in thread-local storage.
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
