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
