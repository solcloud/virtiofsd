# virtiofsd

A [virtio-fs](https://virtio-fs.gitlab.io/) vhost-user device daemon
written in Rust.

## Building from sources

### Requirements

This project depends on
[libcap-ng](https://people.redhat.com/sgrubb/libcap-ng/) and
[libseccomp](https://github.com/seccomp/libseccomp). You can obtain
those dependencies by building them for their respective sources, or
by installing the correspondent development packages from your
distribution, if available:

- Fedora/CentOS/RHEL
```
dnf install libcap-ng-devel libseccomp-devel
```

- Debian/Ubuntu
```
apt install libcap-ng-dev libseccomp-dev
```

### Compiling

virtiofsd uses [cargo](https://doc.rust-lang.org/cargo/) to manage the
project and its dependencies. You can compile it to a binary by
running:

```
cargo build --release
```

## CI-built binaries

Every time new code is merged, the CI pipeline will upload a debug binary
of virtiofsd. It is intended to be an accessible way for anyone to
download and test virtiofsd without needing a Rust toolchain installed.

The debug binary is built only for x86\_64 Linux-based systems.

[Click here to download the latest build](
https://gitlab.com/virtio-fs/virtiofsd/-/jobs/artifacts/main/download?job=publish)

## Usage
This program must be run as the root user or as a "fake" root inside a
user namespace (see below).

The program drops privileges where possible during startup,
although it must be able to create and access files with any uid/gid:

* The ability to invoke syscalls is limited using `seccomp(2)`.
* Linux `capabilities(7)` are dropped.

In "namespace" sandbox mode, the program switches into a new file system
namespace and invokes `pivot_root(2)` to make the shared directory tree its root.
A new pid and net namespace is also created to isolate the process.

In "chroot" sandbox mode, the program invokes `chroot(2)` to make the shared
directory tree its root. This mode is intended for container environments where
the container runtime has already set up the namespaces and the program does
not have permission to create namespaces itself.

Both sandbox modes prevent "file system escapes" due to symlinks and other file
system objects that might lead to files outside the shared directory.

### Examples
Export `/mnt` on vhost-user UNIX domain socket `/tmp/vfsd.sock`:

```
host# virtiofsd --socket-path=/tmp/vfsd.sock --shared-dir /mnt \
        --announce-submounts --inode-file-handles=mandatory &

host# qemu-system \
        -blockdev file,node-name=hdd,filename=<your image> \
        -device virtio-blk,drive=hdd \
        -chardev socket,id=char0,path=/tmp/vfsd.sock \
        -device vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=myfs \
        -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on \
        -numa node,memdev=mem \
        -accel kvm -m 4G

guest# mount -t virtiofs myfs /mnt
```

### Running as non-privileged user
When run without root, virtiofsd requires a user namespace (see `user_namespaces(7)`)
to be able to switch between arbitrary user/group IDs within the guest.
There are many options to run virtiofsd inside a user namespace. For instance:

Let's assume the invoking UID and GID is 1000 and the content of both `/etc/subuid`
and `/etc/subgid` are:
```
1000:100000:65536
```

Using `podman-unshare(1)` the user namespace will be configured so that the invoking user's UID
and primary GID (i.e., 1000) appear to be UID 0 and GID 0, respectively.
Any ranges which match that user and group in `/etc/subuid` and `/etc/subgid` are also
mapped in as themselves with the help of the `newuidmap(1)` and `newgidmap(1)` helpers:

```
host$ podman unshare -- virtiofsd --socket-path=/tmp/vfsd.sock --shared-dir /mnt \
        --announce-submounts --sandbox none &
```

Using `lxc-usernsexec(1)`, we could leave the invoking user outside the mapping, having
the root user inside the user namespace mapped to the user and group 100000:

```
host$ lxc-usernsexec -m b:0:100000:65536 -- virtiofsd --socket-path=/tmp/vfsd.sock \
        --shared-dir /mnt --announce-submounts --sandbox none &
```

In order to have the same behavior as `podman-unshare(1)`, we need to run

```
host$ lxc-usernsexec -m b:0:1000:1 -m b:1:100000:65536 -- virtiofsd --socket-path=/tmp/vfsd.sock \
        --shared-dir /mnt --announce-submounts --sandbox none &
```

We could also select '--sandbox chroot' instead of '--sandbox none'.

#### Limitations
- Within the guest, it is not possible to create block or char device nodes in the shared directory.

- virtiofsd can't use file handles (`--inode-file-handles` requires `CAP_DAC_READ_SEARCH`),
  so a large number of file descriptors is required.
  Additionally, on NFS, not using file handles may result in a hidden file lingering after some file is deleted
  (see [NFS FAQ, Section D2: "What is a "silly rename"?"](http://nfs.sourceforge.net/)).

- virtiofsd will not be able to increase `RLIMIT_NOFILE`.
