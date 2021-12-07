# virtiofsd

A [virtio-fs](https://virtio-fs.gitlab.io/) vhost-user device daemon
written in Rust.

## CI-built binaries

Every time new code is merged, the CI pipeline will upload a debug binary
of virtiofsd. It is intended to be an accessible way for anyone to
download and test virtiofsd without needing a Rust toolchain installed.

The debug binary is built only for x86\_64 Linux-based systems.

[Click here to download the latest build](
https://gitlab.com/virtio-fs/virtiofsd/-/jobs/artifacts/main/download?job=publish)
