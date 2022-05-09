// Copyright 2022 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::{File, OpenOptions};
use std::io::{Error, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::result::Result;
use std::{fs, process};

fn try_lock_file(file: &File) -> Result<(), Error> {
    // Safe because 'file' must exist and we check the return value.
    let file_fd = file.as_raw_fd();
    let ret = unsafe { libc::flock(file_fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == -1 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

pub fn write_pid_file(pid_file_name: &Path) -> std::result::Result<File, std::io::Error> {
    let mut pid_file = loop {
        let file = OpenOptions::new()
            .mode(libc::S_IRUSR | libc::S_IWUSR)
            .custom_flags(libc::O_CLOEXEC)
            .write(true)
            .create(true)
            .open(pid_file_name)?;

        try_lock_file(&file)?;

        // Let's make sure the file we locked still exists in the filesystem.
        let locked = file.metadata()?.ino();
        let current = match fs::metadata(pid_file_name) {
            Ok(stat) => stat.ino(),
            _ => continue, // the pid file got removed or some error happened, try again.
        };

        if locked == current {
            break file; // lock successfully acquired.
        }
        // the file changed, other process is racing with us, so try again.
    };

    let pid = format!("{}\n", process::id());
    pid_file.write_all(pid.as_bytes())?;

    Ok(pid_file)
}
