// Copyright 2021 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::passthrough::stat::statx;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const MAX_HANDLE_SZ: usize = 128;
const EMPTY_CSTR: &[u8] = b"\0";

struct MountFd {
    file: File,
    refcount: AtomicUsize,
}

/**
 * Creating a file handle only returns a mount ID; opening a file handle requires an open fd on the
 * respective mount.  This is a type in which we can store fds that we know are associated with a
 * given mount ID, so that when opening a handle we can look it up.
 */
pub struct MountFds {
    map: Arc<RwLock<HashMap<u64, MountFd>>>,

    /// /proc/self/mountinfo
    mountinfo: Mutex<File>,
}

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
#[repr(C)]
struct CFileHandle {
    handle_bytes: libc::c_uint,
    handle_type: libc::c_int,
    f_handle: [libc::c_char; MAX_HANDLE_SZ],
}

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct FileHandle {
    mnt_id: u64,
    handle: CFileHandle,
}

pub struct OpenableFileHandle {
    handle: FileHandle,
    mount_fd_map: Arc<RwLock<HashMap<u64, MountFd>>>,
}

extern "C" {
    fn name_to_handle_at(
        dirfd: libc::c_int,
        pathname: *const libc::c_char,
        file_handle: *mut CFileHandle,
        mount_id: *mut libc::c_int,
        flags: libc::c_int,
    ) -> libc::c_int;

    // Technically `file_handle` should be a `mut` pointer, but `open_by_handle_at()` is specified
    // not to change it, so we can declare it `const`.
    fn open_by_handle_at(
        mount_fd: libc::c_int,
        file_handle: *const CFileHandle,
        flags: libc::c_int,
    ) -> libc::c_int;
}

impl MountFds {
    pub fn new(mountinfo: File) -> Self {
        MountFds {
            map: Default::default(),
            mountinfo: Mutex::new(mountinfo),
        }
    }

    /// Given a mount ID, return the mount root path (by reading `/proc/self/mountinfo`)
    fn get_mount_root(&self, mount_id: u64) -> io::Result<String> {
        let mountinfo = {
            let mountinfo_file = &mut *self.mountinfo.lock().unwrap();

            mountinfo_file.seek(SeekFrom::Start(0))?;

            let mut mountinfo = String::new();
            mountinfo_file.read_to_string(&mut mountinfo)?;

            mountinfo
        };

        let path = mountinfo.split('\n').find_map(|line| {
            let mut columns = line.split(char::is_whitespace);

            if columns.next()?.parse::<u64>().ok()? != mount_id {
                return None;
            }

            // Skip parent mount ID, major:minor device ID, and the root within the filesystem
            // (to get to the mount path)
            columns.nth(3)
        });

        match path {
            Some(p) => Ok(String::from(p)),
            None => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
}

impl FileHandle {
    /// Create a file handle for the given file.
    ///
    /// Return `Ok(None)` if no file handle can be generated for this file: Either because the
    /// filesystem does not support it, or because it would require a larger file handle than we
    /// can store.  These are not intermittent failures, i.e. if this function returns `Ok(None)`
    /// for a specific file, it will always return `Ok(None)` for it.  Conversely, if this function
    /// returns `Ok(Some)` at some point, it will never return `Ok(None)` later.
    ///
    /// Return an `io::Error` for all other errors.
    pub fn from_name_at(dir: &impl AsRawFd, path: &CStr) -> io::Result<Option<Self>> {
        let mut mount_id: libc::c_int = 0;
        let mut c_fh = CFileHandle {
            handle_bytes: MAX_HANDLE_SZ as libc::c_uint,
            handle_type: 0,
            f_handle: [0; MAX_HANDLE_SZ],
        };

        let ret = unsafe {
            name_to_handle_at(
                dir.as_raw_fd(),
                path.as_ptr(),
                &mut c_fh,
                &mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if ret == 0 {
            Ok(Some(FileHandle {
                mnt_id: mount_id as u64,
                handle: c_fh,
            }))
        } else {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // Filesystem does not support file handles
                Some(libc::EOPNOTSUPP) => Ok(None),
                // Handle would need more bytes than `MAX_HANDLE_SZ`
                Some(libc::EOVERFLOW) => Ok(None),
                // Other error
                _ => Err(err),
            }
        }
    }

    /// Create a file handle for `fd`.
    /// This is a wrapper around `from_name_at()` and so has the same interface.
    pub fn from_fd(fd: &impl AsRawFd) -> io::Result<Option<Self>> {
        // Safe because this is a constant value and a valid C string.
        let empty_path = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
        Self::from_name_at(fd, empty_path)
    }

    /**
     * Return an openable copy of the file handle by ensuring that `mount_fds` contains a valid fd
     * for the mount the file handle is for.
     *
     * `reopen_fd` will be invoked to duplicate an `O_PATH` fd with custom `libc::open()` flags.
     */
    pub fn to_openable<F>(
        &self,
        mount_fds: &MountFds,
        reopen_fd: F,
    ) -> io::Result<OpenableFileHandle>
    where
        F: FnOnce(RawFd, libc::c_int) -> io::Result<File>,
    {
        // The conditional block below (`if !existing_mount_fd`) takes a `.write()` lock to insert
        // a new mount FD into the hash map.  Separate the `.read()` lock we need to take for the
        // lookup (and hold until `mount_fd` is dropped) from the block below so we do not get into
        // a deadlock.
        let existing_mount_fd = match mount_fds.map.read().unwrap().get(&self.mnt_id) {
            Some(mount_fd) => {
                mount_fd.refcount.fetch_add(1, Ordering::Relaxed);
                true
            }
            None => false,
        };

        if !existing_mount_fd {
            // `open_by_handle_at()` needs a non-`O_PATH` fd, which we will need to open here.  We
            // are going to open the filesystem's mount point, but we do not know whether that is a
            // special file[1], and we must not open special files with anything but `O_PATH`, so
            // we have to get some `O_PATH` fd first that we can stat to find out whether it is
            // safe to open.
            // [1] While mount points are commonly directories, it is entirely possible for a
            //     filesystem's root inode to be a regular or even special file.
            let mount_point = mount_fds.get_mount_root(self.mnt_id)?;
            let c_mount_point = CString::new(mount_point)?;
            let mount_point_fd = unsafe { libc::open(c_mount_point.as_ptr(), libc::O_PATH) };
            if mount_point_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Safe because we have just opened this FD
            let mount_point_path = unsafe { File::from_raw_fd(mount_point_fd) };

            // Ensure that `mount_point_path` refers to an inode with the mount ID we need
            let stx = statx(&mount_point_path, None)?;
            if stx.mnt_id != self.mnt_id {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }

            // Ensure that we can safely reopen `mount_point_path` with `O_RDONLY`
            let file_type = stx.st.st_mode & libc::S_IFMT;
            if file_type != libc::S_IFREG && file_type != libc::S_IFDIR {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }

            // Now that we know that this is a regular file or directory, really open it
            let file = reopen_fd(
                mount_point_path.as_raw_fd(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;

            let mount_fds_locked = mount_fds.map.write();

            if let Some(mount_fd) = mount_fds_locked.as_ref().unwrap().get(&self.mnt_id) {
                // A mount FD was added concurrently while we did not hold a lock on
                // `mount_fds.map` -- use that entry (`file` will be dropped).
                mount_fd.refcount.fetch_add(1, Ordering::Relaxed);
            } else {
                let mount_fd = MountFd {
                    file,
                    refcount: AtomicUsize::new(1),
                };

                mount_fds_locked.unwrap().insert(self.mnt_id, mount_fd);
            }
        }

        Ok(OpenableFileHandle {
            handle: *self,
            mount_fd_map: mount_fds.map.clone(),
        })
    }
}

impl OpenableFileHandle {
    /**
     * Open a file handle (low-level wrapper).
     *
     * `mount_fd` must be an open non-`O_PATH` file descriptor for an inode on the same mount as
     * the file to be opened, i.e. the mount given by `self.handle.mnt_id`.
     */
    fn do_open(&self, mount_fd: &impl AsRawFd, flags: libc::c_int) -> io::Result<File> {
        let ret = unsafe { open_by_handle_at(mount_fd.as_raw_fd(), &self.handle.handle, flags) };
        if ret >= 0 {
            // Safe because `open_by_handle_at()` guarantees this is a valid fd
            let file = unsafe { File::from_raw_fd(ret) };
            Ok(file)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /**
     * Open a file handle, using our mount FDs hash map.
     *
     * Look up `self.handle.mnt_id` in `self.mount_fd_map`, and pass the result to
     * `self.do_open()`.
     */
    pub fn open(&self, flags: libc::c_int) -> io::Result<File> {
        let mount_fds_locked = self.mount_fd_map.read();

        // Creating an `OpenableFileHandle` requires an associated mount FD, so this lookup must
        // not fail.
        let mount_file = mount_fds_locked
            .as_ref()
            .unwrap()
            .get(&self.handle.mnt_id)
            .unwrap();

        self.do_open(&mount_file.file, flags)
    }
}

impl Drop for OpenableFileHandle {
    fn drop(&mut self) {
        // Take a write lock so we do not have to drop and reaquire it between decrementing the
        // refcount and removing the `MountFd` object from the map -- otherwise, a new user might
        // sneak in while we do not hold any lock.
        let mut mount_fds_locked = self.mount_fd_map.write();

        let drop_mount_fd = {
            // We have a strong reference to our `MountFd`, so this must not fail
            let mount_file = mount_fds_locked
                .as_ref()
                .unwrap()
                .get(&self.handle.mnt_id)
                .unwrap();

            mount_file.refcount.fetch_sub(1, Ordering::AcqRel) == 1
        };

        if drop_mount_fd {
            mount_fds_locked
                .as_mut()
                .unwrap()
                .remove(&self.handle.mnt_id);
        }
    }
}
