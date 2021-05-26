// Copyright 2021 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;

const EMPTY_CSTR: &[u8] = b"\0";

pub struct StatExt {
    pub st: libc::stat64,
    pub mnt_id: u64,
}

pub fn stat64(f: &File) -> io::Result<StatExt> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe {
        libc::fstatat64(
            f.as_raw_fd(),
            pathname.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if res >= 0 {
        Ok(StatExt {
            // Safe because the kernel guarantees that the struct is now fully initialized.
            st: unsafe { st.assume_init() },
            mnt_id: 0,
        })
    } else {
        Err(io::Error::last_os_error())
    }
}

/*
 * Fields in libc::statx are only valid if their respective flag in
 * .stx_mask is set.  This trait provides functions that allow safe
 * access to the libc::statx components we are interested in.
 *
 * (The implementations of these functions need to check whether the
 * associated flag is set, and then extract the respective information
 * to return it.)
 */
trait SafeStatXAccess {
    fn stat64(&self) -> Option<libc::stat64>;
    fn mount_id(&self) -> Option<u64>;
}

impl SafeStatXAccess for libc::statx {
    fn stat64(&self) -> Option<libc::stat64> {
        fn makedev(maj: libc::c_uint, min: libc::c_uint) -> libc::dev_t {
            // Safe because there are no side effects
            unsafe { libc::makedev(maj, min) }
        }

        if self.stx_mask & libc::STATX_BASIC_STATS != 0 {
            /*
             * Unfortunately, we cannot use an initializer to create the
             * stat64 object, because it may contain padding and reserved
             * fields (depending on the architecture), and it does not
             * implement the Default trait.
             * So we take a zeroed struct and set what we can.
             * (Zero in all fields is wrong, but safe.)
             */
            let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };

            st.st_dev = makedev(self.stx_dev_major, self.stx_dev_minor);
            st.st_ino = self.stx_ino;
            st.st_mode = self.stx_mode as _;
            st.st_nlink = self.stx_nlink as _;
            st.st_uid = self.stx_uid;
            st.st_gid = self.stx_gid;
            st.st_rdev = makedev(self.stx_rdev_major, self.stx_rdev_minor);
            st.st_size = self.stx_size as _;
            st.st_blksize = self.stx_blksize as _;
            st.st_blocks = self.stx_blocks as _;
            st.st_atime = self.stx_atime.tv_sec;
            st.st_atime_nsec = self.stx_atime.tv_nsec as _;
            st.st_mtime = self.stx_mtime.tv_sec;
            st.st_mtime_nsec = self.stx_mtime.tv_nsec as _;
            st.st_ctime = self.stx_ctime.tv_sec;
            st.st_ctime_nsec = self.stx_ctime.tv_nsec as _;

            Some(st)
        } else {
            None
        }
    }

    fn mount_id(&self) -> Option<u64> {
        if self.stx_mask & libc::STATX_MNT_ID != 0 {
            Some(self.stx_mnt_id)
        } else {
            None
        }
    }
}

// Only works on Linux, and libc::SYS_statx is only defined for these
// environments
#[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
/// Performs a statx() syscall.  libc provides libc::statx() that does
/// the same, however, the system's libc may not have a statx() wrapper
/// (e.g. glibc before 2.28), so linking to it may fail.
/// libc::syscall() and libc::SYS_statx are always present, though, so
/// we can safely rely on them.
unsafe fn do_statx(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
    mask: libc::c_uint,
    statxbuf: *mut libc::statx,
) -> libc::c_int {
    libc::syscall(libc::SYS_statx, dirfd, pathname, flags, mask, statxbuf) as libc::c_int
}

// Real statx() that depends on do_statx()
#[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "musl")))]
pub fn statx(f: &File) -> io::Result<StatExt> {
    let mut stx_ui = MaybeUninit::<libc::statx>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `stx_ui` and we
    // check the return value.
    let res = unsafe {
        do_statx(
            f.as_raw_fd(),
            pathname.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            stx_ui.as_mut_ptr(),
        )
    };
    if res >= 0 {
        // Safe because we are only going to use the SafeStatXAccess
        // trait methods
        let stx = unsafe { stx_ui.assume_init() };

        Ok(StatExt {
            st: stx
                .stat64()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?,
            mnt_id: stx.mount_id().unwrap_or(0),
        })
    } else {
        Err(io::Error::last_os_error())
    }
}

// Fallback for when do_statx() is not available
#[cfg(not(all(target_os = "linux", any(target_env = "gnu", target_env = "musl"))))]
pub fn statx(_f: &File) -> io::Result<StatExt> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}
