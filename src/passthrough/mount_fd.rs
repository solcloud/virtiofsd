// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use crate::passthrough::stat::{statx, MountId};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex, RwLock, Weak};

pub struct MountFd {
    map: Weak<RwLock<HashMap<MountId, Weak<MountFd>>>>,
    mount_id: MountId,
    file: File,
}

/// This type maintains a map where each entry maps a mount ID to an open FD on that mount.  Other
/// code can request an `Arc<MountFd>` for any mount ID.  A key gets added to the map, when the
/// first `Arc<MountFd>` for that mount ID is requested.  A key gets removed from the map, when the
/// last `Arc<MountFd>` for that mount ID is dropped.  That is, map entries are reference-counted
/// and other code can keep an entry in the map by holding on to an `Arc<MountFd>`.
///
/// We currently have one use case for `MountFds`:
///
/// 1. Creating a file handle only returns a mount ID, but opening a file handle requires an open FD
///    on the respective mount.  So we look that up in the map.
pub struct MountFds {
    map: Arc<RwLock<HashMap<MountId, Weak<MountFd>>>>,

    /// /proc/self/mountinfo
    mountinfo: Mutex<File>,

    /// An optional prefix to strip from all mount points in mountinfo
    mountprefix: Option<String>,
}

impl MountFd {
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for MountFd {
    fn drop(&mut self) {
        debug!(
            "Dropping MountFd: mount_id={}, mount_fd={}",
            self.mount_id,
            self.file.as_raw_fd(),
        );

        // If `self.map.upgrade()` fails, then the `MountFds` structure was dropped while there was
        // still an `Arc<MountFd>` alive.  In this case, we don't need to remove it from the map,
        // because the map doesn't exist anymore.
        if let Some(map) = self.map.upgrade() {
            let mut map = map.write().unwrap();
            // After the refcount reaches zero and before we lock the map, there's a window where
            // the value can be concurrently replaced by a `Weak` pointer to a new `MountFd`.
            // Therefore, only remove the value if the refcount in the map is zero, too.
            if let Some(0) = map.get(&self.mount_id).map(Weak::strong_count) {
                map.remove(&self.mount_id);
            }
        }
    }
}

impl MountFds {
    pub fn new(mountinfo: File, mountprefix: Option<String>) -> Self {
        MountFds {
            map: Default::default(),
            mountinfo: Mutex::new(mountinfo),
            mountprefix,
        }
    }

    pub fn get<F>(&self, mount_id: MountId, reopen_fd: F) -> io::Result<Arc<MountFd>>
    where
        F: FnOnce(RawFd, libc::c_int) -> io::Result<File>,
    {
        let existing_mount_fd = self
            .map
            // The `else` branch below (where `existing_mount_fd` matches `None`) takes a write lock
            // to insert a new mount FD into the hash map.  This doesn't deadlock, because the read
            // lock taken here doesn't have its lifetime extended beyond the statement, because
            // `Weak::upgrade` returns a new pointer and not a reference into the read lock.
            .read()
            .unwrap()
            .get(&mount_id)
            // We treat a failed upgrade just like a non-existent key, because it means that all
            // strong references to the `MountFd` have disappeared, so it's in the process of being
            // dropped, but `MountFd::drop()` just did not yet get to remove it from the map.
            .and_then(Weak::upgrade);

        let mount_fd = if let Some(mount_fd) = existing_mount_fd {
            mount_fd
        } else {
            // `open_by_handle_at()` needs a non-`O_PATH` fd, which we will need to open here.  We
            // are going to open the filesystem's mount point, but we do not know whether that is a
            // special file[1], and we must not open special files with anything but `O_PATH`, so
            // we have to get some `O_PATH` fd first that we can stat to find out whether it is
            // safe to open.
            // [1] While mount points are commonly directories, it is entirely possible for a
            //     filesystem's root inode to be a regular or even special file.
            let mount_point = self.get_mount_root(mount_id)?;
            let c_mount_point = CString::new(mount_point)?;
            let mount_point_fd = unsafe { libc::open(c_mount_point.as_ptr(), libc::O_PATH) };
            if mount_point_fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Safe because we have just opened this FD
            let mount_point_path = unsafe { File::from_raw_fd(mount_point_fd) };

            // Ensure that `mount_point_path` refers to an inode with the mount ID we need
            let stx = statx(&mount_point_path, None)?;
            if stx.mnt_id != mount_id {
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

            let mut mount_fds_locked = self.map.write().unwrap();

            // As above: by calling `and_then(Weak::upgrade)`, we treat a failed upgrade just like a
            // non-existent key.  If the key exists but upgrade fails, then `HashMap::insert()`
            // below will update the value.  `MountFd::drop()` takes care to only remove a `MountFd`
            // without strong references from the map, and hence will not touch the updated one.
            if let Some(mount_fd) = mount_fds_locked.get(&mount_id).and_then(Weak::upgrade) {
                // A mount FD was added concurrently while we did not hold a lock on
                // `mount_fds.map` -- use that entry (`file` will be dropped).
                mount_fd
            } else {
                debug!(
                    "Creating MountFd: mount_id={}, mount_fd={}",
                    mount_id,
                    file.as_raw_fd(),
                );
                let mount_fd = Arc::new(MountFd {
                    map: Arc::downgrade(&self.map),
                    mount_id,
                    file,
                });
                mount_fds_locked.insert(mount_id, Arc::downgrade(&mount_fd));
                mount_fd
            }
        };

        Ok(mount_fd)
    }

    /// Given a mount ID, return the mount root path (by reading `/proc/self/mountinfo`)
    fn get_mount_root(&self, mount_id: MountId) -> io::Result<String> {
        let mountinfo = {
            let mountinfo_file = &mut *self.mountinfo.lock().unwrap();

            mountinfo_file.seek(SeekFrom::Start(0))?;

            let mut mountinfo = String::new();
            mountinfo_file.read_to_string(&mut mountinfo)?;

            mountinfo
        };

        let path = mountinfo.split('\n').find_map(|line| {
            let mut columns = line.split(char::is_whitespace);

            if columns.next()?.parse::<MountId>().ok()? != mount_id {
                return None;
            }

            // Skip parent mount ID, major:minor device ID, and the root within the filesystem
            // (to get to the mount path)
            columns.nth(3)
        });

        match path {
            Some(p) => {
                let p = String::from(p);
                if let Some(prefix) = self.mountprefix.as_ref() {
                    if let Some(suffix) = p.strip_prefix(prefix) {
                        Ok(suffix.into())
                    } else {
                        // Mount is outside the shared directory, so it must be the mount the root
                        // directory is on
                        Ok("/".into())
                    }
                } else {
                    Ok(p)
                }
            }

            None => Err(io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
}
