// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::str::FromStr;
use std::{error, fmt, io};

#[derive(Debug)]
pub enum Error {
    /// Failed to bind mount `/proc/self/fd` into a temporary directory.
    BindMountProcSelfFd(io::Error),
    /// Failed to bind mount shared directory.
    BindMountSharedDir(io::Error),
    /// Failed to change to the old root directory.
    ChdirOldRoot(io::Error),
    /// Failed to change to the new root directory.
    ChdirNewRoot(io::Error),
    /// Call to libc::chroot returned an error.
    Chroot(io::Error),
    /// Failed to change to the root directory after the chroot call.
    ChrootChdir(io::Error),
    /// Failed to clean the properties of the mount point.
    CleanMount(io::Error),
    /// Failed to create a temporary directory.
    CreateTempDir(io::Error),
    /// Failed to drop supplemental groups.
    DropSupplementalGroups(io::Error),
    /// Call to libc::fork returned an error.
    Fork(io::Error),
    /// Failed to get the number of supplemental groups.
    GetSupplementalGroups(io::Error),
    /// Error bind-mounting a directory.
    MountBind(io::Error),
    /// Failed to mount old root.
    MountOldRoot(io::Error),
    /// Error mounting proc.
    MountProc(io::Error),
    /// Failed to mount new root.
    MountNewRoot(io::Error),
    /// Error mounting target directory.
    MountTarget(io::Error),
    /// Failed to open `/proc/self/mountinfo`.
    OpenMountinfo(io::Error),
    /// Failed to open new root.
    OpenNewRoot(io::Error),
    /// Failed to open old root.
    OpenOldRoot(io::Error),
    /// Failed to open `/proc/self`.
    OpenProcSelf(io::Error),
    /// Failed to open `/proc/self/fd`.
    OpenProcSelfFd(io::Error),
    /// Error switching root directory.
    PivotRoot(io::Error),
    /// Failed to remove temporary directory.
    RmdirTempDir(io::Error),
    /// Failed to lazily unmount old root.
    UmountOldRoot(io::Error),
    /// Failed to lazily unmount temporary directory.
    UmountTempDir(io::Error),
    /// Call to libc::unshare returned an error.
    Unshare(io::Error),
    /// Failed to write to `/proc/self/gid_map`.
    WriteGidMap(io::Error),
    /// Failed to write to `/proc/self/setgroups`.
    WriteSetGroups(io::Error),
    /// Failed to write to `/proc/self/uid_map`.
    WriteUidMap(io::Error),
    /// Sandbox mode unavailable for non-privileged users
    SandboxModeInvalidUID,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Error::SandboxModeInvalidUID;
        match self {
            SandboxModeInvalidUID => {
                write!(
                    f,
                    "sandbox modes chroot and none, can only be used by \
                    root (Use '--sandbox namespace' instead)"
                )
            }
            _ => write!(f, "{:?}", self),
        }
    }
}

/// Mechanism to be used for setting up the sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxMode {
    /// Create the sandbox using Linux namespaces.
    Namespace,
    /// Create the sandbox using chroot.
    Chroot,
    /// Don't attempt to isolate the process inside a sandbox.
    None,
}

impl FromStr for SandboxMode {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "namespace" => Ok(SandboxMode::Namespace),
            "chroot" => Ok(SandboxMode::Chroot),
            "none" => Ok(SandboxMode::None),
            _ => Err("Unknown sandbox mode"),
        }
    }
}

/// A helper for creating a sandbox for isolating the service.
pub struct Sandbox {
    /// The directory that is going to be shared with the VM. The sandbox will be constructed on top
    /// of this directory.
    shared_dir: String,
    /// A `File` object for `/proc/self/fd` obtained from the sandboxed context.
    proc_self_fd: Option<File>,
    /// A `File` object for `/proc/self/mountinfo` obtained from the sandboxed context.
    mountinfo_fd: Option<File>,
    /// Mechanism to be used for setting up the sandbox.
    sandbox_mode: SandboxMode,
}

impl Sandbox {
    pub fn new(shared_dir: String, sandbox_mode: SandboxMode) -> io::Result<Self> {
        let shared_dir_rp = fs::canonicalize(shared_dir)?;
        let shared_dir_rp_str = shared_dir_rp
            .to_str()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;

        Ok(Sandbox {
            shared_dir: shared_dir_rp_str.into(),
            proc_self_fd: None,
            mountinfo_fd: None,
            sandbox_mode,
        })
    }

    // Make `self.shared_dir` our root directory, and get isolated file descriptors for
    // `/proc/self/fd` and '/proc/self/mountinfo`.
    //
    // This is based on virtiofsd's setup_namespaces() and setup_mounts(), and it's very similar to
    // the strategy used in containers. Consists on a careful sequence of mounts and bind-mounts to
    // ensure it's not possible to escape the sandbox through `self.shared_dir` nor the file
    // descriptor obtained for `/proc/self/fd`.
    //
    // It's ugly, but it's the only way until Linux implements a proper containerization API.
    fn setup_mounts(&mut self) -> Result<(), Error> {
        // Open an FD to `/proc/self` so we can later open `/proc/self/mountinfo`.
        // (If we opened `/proc/self/mountinfo` now, it would appear empty by the end of this
        // function, which is why we need to defer opening it until then.)
        let c_proc_self = CString::new("/proc/self").unwrap();
        let proc_self_raw = unsafe { libc::open(c_proc_self.as_ptr(), libc::O_PATH) };
        if proc_self_raw < 0 {
            return Err(Error::OpenProcSelf(std::io::Error::last_os_error()));
        }

        // Encapsulate the `/proc/self` FD in a `File` object so it is closed when this function
        // returns
        let proc_self = unsafe { File::from_raw_fd(proc_self_raw) };

        // Ensure our mount changes don't affect the parent mount namespace.
        let c_root_dir = CString::new("/").unwrap();
        let ret = unsafe {
            libc::mount(
                std::ptr::null(),
                c_root_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(Error::CleanMount(std::io::Error::last_os_error()));
        }

        // Mount `/proc` in this context.
        let c_proc_dir = CString::new("/proc").unwrap();
        let c_proc_fs = CString::new("proc").unwrap();
        let ret = unsafe {
            libc::mount(
                c_proc_fs.as_ptr(),
                c_proc_dir.as_ptr(),
                c_proc_fs.as_ptr(),
                libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_RELATIME,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(Error::MountProc(std::io::Error::last_os_error()));
        }

        // Bind-mount `/proc/self/fd` onto /proc preventing access to ancestor
        // directories.
        let c_proc_self_fd = CString::new("/proc/self/fd").unwrap();
        let c_proc_dir = CString::new("/proc").unwrap();
        let ret = unsafe {
            libc::mount(
                c_proc_self_fd.as_ptr(),
                c_proc_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(Error::BindMountProcSelfFd(std::io::Error::last_os_error()));
        }

        // Obtain a file descriptor to /proc/self/fd/ by opening bind-mounted /proc directory.
        let proc_self_fd = unsafe { libc::open(c_proc_dir.as_ptr(), libc::O_PATH) };
        if proc_self_fd < 0 {
            return Err(Error::OpenProcSelfFd(std::io::Error::last_os_error()));
        }
        // Safe because we just opened this fd.
        self.proc_self_fd = Some(unsafe { File::from_raw_fd(proc_self_fd) });

        // Bind-mount `self.shared_dir` on itself so we can use as new root on `pivot_root` syscall.
        let c_shared_dir = CString::new(self.shared_dir.clone()).unwrap();
        let ret = unsafe {
            libc::mount(
                c_shared_dir.as_ptr(),
                c_shared_dir.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            return Err(Error::BindMountSharedDir(std::io::Error::last_os_error()));
        }

        // Get a file descriptor to our old root so we can reference it after switching root.
        let oldroot_fd = unsafe {
            libc::open(
                c_root_dir.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if oldroot_fd < 0 {
            return Err(Error::OpenOldRoot(std::io::Error::last_os_error()));
        }

        // Get a file descriptor to the new root so we can reference it after switching root.
        let newroot_fd = unsafe {
            libc::open(
                c_shared_dir.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if newroot_fd < 0 {
            return Err(Error::OpenNewRoot(std::io::Error::last_os_error()));
        }

        // Change to new root directory to prepare for `pivot_root` syscall.
        let ret = unsafe { libc::fchdir(newroot_fd) };
        if ret < 0 {
            return Err(Error::ChdirNewRoot(std::io::Error::last_os_error()));
        }

        // Call to `pivot_root` using `.` as both new and old root.
        let c_current_dir = CString::new(".").unwrap();
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                c_current_dir.as_ptr(),
                c_current_dir.as_ptr(),
            )
        };
        if ret < 0 {
            return Err(Error::PivotRoot(std::io::Error::last_os_error()));
        }

        // Change to old root directory to prepare for cleaning up and unmounting it.
        let ret = unsafe { libc::fchdir(oldroot_fd) };
        if ret < 0 {
            return Err(Error::ChdirOldRoot(std::io::Error::last_os_error()));
        }

        // Clean up old root to avoid mount namespace propagation.
        let c_empty = CString::new("").unwrap();
        let ret = unsafe {
            libc::mount(
                c_empty.as_ptr(),
                c_current_dir.as_ptr(),
                c_empty.as_ptr(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(Error::CleanMount(std::io::Error::last_os_error()));
        }

        // Lazily unmount old root.
        let ret = unsafe { libc::umount2(c_current_dir.as_ptr(), libc::MNT_DETACH) };
        if ret < 0 {
            return Err(Error::UmountOldRoot(std::io::Error::last_os_error()));
        }

        // Change to new root.
        let ret = unsafe { libc::fchdir(newroot_fd) };
        if ret < 0 {
            return Err(Error::ChdirNewRoot(std::io::Error::last_os_error()));
        }

        // We no longer need these file descriptors, so close them.
        unsafe { libc::close(newroot_fd) };
        unsafe { libc::close(oldroot_fd) };

        // Open `/proc/self/mountinfo` now
        let c_mountinfo = CString::new("mountinfo").unwrap();
        let mountinfo_fd =
            unsafe { libc::openat(proc_self.as_raw_fd(), c_mountinfo.as_ptr(), libc::O_RDONLY) };
        if mountinfo_fd < 0 {
            return Err(Error::OpenMountinfo(std::io::Error::last_os_error()));
        }
        // Safe because we just opened this fd.
        self.mountinfo_fd = Some(unsafe { File::from_raw_fd(mountinfo_fd) });

        Ok(())
    }

    /// Sets 1-to-1 mappings for the current uid and gid.
    fn setup_id_mappings(&self, uid: u32, gid: u32) -> Result<(), Error> {
        // To be able to set up the gid mapping, we're required to disable setgroups(2) first.
        fs::write("/proc/self/setgroups", "deny\n").map_err(Error::WriteSetGroups)?;

        // Set up 1-to-1 mappings for our uid and gid.
        let uid_mapping = format!("{} {} 1\n", uid, uid);
        fs::write("/proc/self/uid_map", uid_mapping).map_err(Error::WriteUidMap)?;

        let gid_mapping = format!("{} {} 1\n", gid, gid);
        fs::write("/proc/self/gid_map", gid_mapping).map_err(Error::WriteGidMap)?;
        Ok(())
    }

    pub fn enter_namespace(&mut self) -> Result<Option<i32>, Error> {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        let flags = if uid == 0 {
            libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWNET
        } else {
            // If running as an unprivileged user, rely on user_namespaces(7) for isolation. The
            // main limitation of this strategy is that only the current uid/gid are mapped into
            // the new namespace, so most operations on permissions will fail.
            libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWUSER
        };

        // Drop supplemental groups. This is running as root and will
        // support arbitrary uid/gid switching and we don't want to
        // retain membership of any supplementary groups.
        //
        // This is not necessarily required for non-root case, where
        // unprivileged user has started us, we will setup one user
        // namespace with 1:1 mapping and there is no arbitrary uid/gid
        // switching at all. In this mode setgroups() is not allowed, so
        // we can't drop supplementary groups even if wanted to. Only
        // way to do this will be to use newuidmap/newgidmap to setup
        // user namespace which will allow setgroups().
        if uid == 0 {
            self.drop_supplemental_groups()?;
        }

        let ret = unsafe { libc::unshare(flags) };
        if ret != 0 {
            return Err(Error::Unshare(std::io::Error::last_os_error()));
        }

        let child = unsafe { libc::fork() };
        match child {
            0 => {
                // This is the child. Request to receive SIGTERM on parent's death.
                // FIXME: Race condition: the parent process might have died already.
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
                if uid != 0 {
                    self.setup_id_mappings(uid, gid)?;
                }
                self.setup_mounts()?;
                Ok(None)
            }
            x if x > 0 => {
                // This is the parent.
                Ok(Some(child))
            }
            _ => Err(Error::Fork(std::io::Error::last_os_error())),
        }
    }

    pub fn enter_chroot(&mut self) -> Result<Option<i32>, Error> {
        let c_proc_self_fd = CString::new("/proc/self/fd").unwrap();
        let proc_self_fd = unsafe { libc::open(c_proc_self_fd.as_ptr(), libc::O_PATH) };
        if proc_self_fd < 0 {
            return Err(Error::OpenProcSelfFd(std::io::Error::last_os_error()));
        }
        // Safe because we just opened this fd.
        self.proc_self_fd = Some(unsafe { File::from_raw_fd(proc_self_fd) });

        let c_mountinfo = CString::new("/proc/self/mountinfo").unwrap();
        let mountinfo_fd = unsafe { libc::open(c_mountinfo.as_ptr(), libc::O_RDONLY) };
        if mountinfo_fd < 0 {
            return Err(Error::OpenMountinfo(std::io::Error::last_os_error()));
        }
        // Safe because we just opened this fd.
        self.mountinfo_fd = Some(unsafe { File::from_raw_fd(mountinfo_fd) });

        let c_shared_dir = CString::new(self.shared_dir.clone()).unwrap();
        let ret = unsafe { libc::chroot(c_shared_dir.as_ptr()) };
        if ret != 0 {
            return Err(Error::Chroot(std::io::Error::last_os_error()));
        }

        let c_root_dir = CString::new("/").unwrap();
        let ret = unsafe { libc::chdir(c_root_dir.as_ptr()) };
        if ret != 0 {
            return Err(Error::ChrootChdir(std::io::Error::last_os_error()));
        }

        Ok(None)
    }

    fn drop_supplemental_groups(&self) -> Result<(), Error> {
        let ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if ngroups < 0 {
            return Err(Error::GetSupplementalGroups(std::io::Error::last_os_error()));
        } else if ngroups != 0 {
            let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
            if ret != 0 {
                return Err(Error::DropSupplementalGroups(
                    std::io::Error::last_os_error(),
                ));
            }
        }

        Ok(())
    }

    /// Set up sandbox, fork and jump into it.
    ///
    /// On success, the returned value will be the PID of the child for the parent and `None` for
    /// the child itself, with the latter running isolated in `self.shared_dir`.
    pub fn enter(&mut self) -> Result<Option<i32>, Error> {
        let uid = unsafe { libc::geteuid() };
        if uid != 0 && self.sandbox_mode != SandboxMode::Namespace {
            return Err(Error::SandboxModeInvalidUID);
        }

        // Unconditionally drop supplemental groups for every sandbox mode.
        if self.sandbox_mode != SandboxMode::Namespace {
            self.drop_supplemental_groups()?;
        }
        match self.sandbox_mode {
            SandboxMode::Namespace => self.enter_namespace(),
            SandboxMode::Chroot => self.enter_chroot(),
            SandboxMode::None => Ok(None),
        }
    }

    pub fn get_proc_self_fd(&mut self) -> Option<File> {
        self.proc_self_fd.take()
    }

    pub fn get_mountinfo_fd(&mut self) -> Option<File> {
        self.mountinfo_fd.take()
    }

    pub fn get_root_dir(&self) -> String {
        match self.sandbox_mode {
            SandboxMode::Namespace | SandboxMode::Chroot => "/".to_string(),
            SandboxMode::None => self.shared_dir.clone(),
        }
    }

    /// Return the prefix to strip from /proc/self/mountinfo entries to get paths that are actually
    /// accessible in our sandbox
    pub fn get_mountinfo_prefix(&self) -> Option<String> {
        match self.sandbox_mode {
            SandboxMode::Namespace | SandboxMode::None => None,
            SandboxMode::Chroot => Some(self.shared_dir.clone()),
        }
    }
}
