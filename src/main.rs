// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use futures::executor::{ThreadPool, ThreadPoolBuilder};
use libc::EFD_NONBLOCK;
use log::*;
use passthrough::xattrmap::XattrMap;
use std::collections::HashSet;
use std::convert::{self, TryFrom};
use std::ffi::CString;
use std::os::unix::io::{FromRawFd, RawFd};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::{env, error, fmt, io, process};

use structopt::StructOpt;

use vhost::vhost_user::message::*;
use vhost::vhost_user::Error::PartialMessage;
use vhost::vhost_user::{Listener, SlaveFsCacheReq};
use vhost_user_backend::Error::HandleRequest;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, VringMutex, VringState, VringT};
use virtio_bindings::bindings::virtio_net::*;
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use virtiofsd::descriptor_utils::{Error as VufDescriptorError, Reader, Writer};
use virtiofsd::filesystem::FileSystem;
use virtiofsd::passthrough::{self, CachePolicy, InodeFileHandlesMode, PassthroughFs};
use virtiofsd::sandbox::{Sandbox, SandboxMode};
use virtiofsd::seccomp::{enable_seccomp, SeccompAction};
use virtiofsd::server::Server;
use virtiofsd::Error as VhostUserFsError;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

// The guest queued an available buffer for the high priority queue.
const HIPRIO_QUEUE_EVENT: u16 = 0;
// The guest queued an available buffer for the request queue.
const REQ_QUEUE_EVENT: u16 = 1;

type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
enum Error {
    /// Failed to create kill eventfd.
    CreateKillEventFd(io::Error),
    /// Failed to create thread pool.
    CreateThreadPool(io::Error),
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Iterating through the queue failed.
    IterateQueue,
    /// No memory configured.
    NoMemoryConfigured,
    /// Processing queue failed.
    ProcessQueue(VhostUserFsError),
    /// Creating a queue reader failed.
    QueueReader(VufDescriptorError),
    /// Creating a queue writer failed.
    QueueWriter(VufDescriptorError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtiofsd_error: {:?}", self)
    }
}

impl error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

struct VhostUserFsThread<F: FileSystem + Send + Sync + 'static> {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    kill_evt: EventFd,
    server: Arc<Server<F>>,
    // handle request from slave to master
    vu_req: Option<SlaveFsCacheReq>,
    event_idx: bool,
    pool: Option<ThreadPool>,
}

impl<F: FileSystem + Send + Sync + 'static> Clone for VhostUserFsThread<F> {
    fn clone(&self) -> Self {
        VhostUserFsThread {
            mem: self.mem.clone(),
            kill_evt: self.kill_evt.try_clone().unwrap(),
            server: self.server.clone(),
            vu_req: self.vu_req.clone(),
            event_idx: self.event_idx,
            pool: self.pool.clone(),
        }
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserFsThread<F> {
    fn new(fs: F, thread_pool_size: usize) -> Result<Self> {
        let pool = if thread_pool_size > 0 {
            Some(
                ThreadPoolBuilder::new()
                    .pool_size(thread_pool_size)
                    .create()
                    .map_err(Error::CreateThreadPool)?,
            )
        } else {
            None
        };

        Ok(VhostUserFsThread {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            server: Arc::new(Server::new(fs)),
            vu_req: None,
            event_idx: false,
            pool,
        })
    }

    fn return_descriptor(vring_state: &mut VringState, head_index: u16, event_idx: bool) {
        if vring_state.add_used(head_index, 0).is_err() {
            warn!("Couldn't return used descriptors to the ring");
        }

        if event_idx {
            match vring_state.needs_notification() {
                Err(_) => {
                    warn!("Couldn't check if queue needs to be notified");
                    vring_state.signal_used_queue().unwrap();
                }
                Ok(needs_notification) => {
                    if needs_notification {
                        vring_state.signal_used_queue().unwrap();
                    }
                }
            }
        } else {
            vring_state.signal_used_queue().unwrap();
        }
    }

    fn process_queue_pool(&self, vring: VringMutex) -> Result<bool> {
        let mut used_any = false;
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        while let Some(avail_desc) = vring
            .get_mut()
            .get_queue_mut()
            .iter()
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            used_any = true;

            // Prepare a set of objects that can be moved to the worker thread.
            let atomic_mem = atomic_mem.clone();
            let server = self.server.clone();
            let mut vu_req = self.vu_req.clone();
            let event_idx = self.event_idx;
            let worker_vring = vring.clone();
            let worker_desc = avail_desc.clone();

            self.pool.as_ref().unwrap().spawn_ok(async move {
                let mem = atomic_mem.memory();
                let head_index = worker_desc.head_index();

                let reader = Reader::new(&mem, worker_desc.clone())
                    .map_err(Error::QueueReader)
                    .unwrap();
                let writer = Writer::new(&mem, worker_desc.clone())
                    .map_err(Error::QueueWriter)
                    .unwrap();

                server
                    .handle_message(reader, writer, vu_req.as_mut())
                    .map_err(Error::ProcessQueue)
                    .unwrap();

                Self::return_descriptor(&mut worker_vring.get_mut(), head_index, event_idx);
            });
        }

        Ok(used_any)
    }

    fn process_queue_serial(&self, vring_state: &mut VringState) -> Result<bool> {
        let mut used_any = false;
        let mem = match &self.mem {
            Some(m) => m.memory(),
            None => return Err(Error::NoMemoryConfigured),
        };
        let mut vu_req = self.vu_req.clone();

        let avail_chains: Vec<DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>> = vring_state
            .get_queue_mut()
            .iter()
            .map_err(|_| Error::IterateQueue)?
            .collect();

        for chain in avail_chains {
            used_any = true;

            let head_index = chain.head_index();

            let reader = Reader::new(&mem, chain.clone())
                .map_err(Error::QueueReader)
                .unwrap();
            let writer = Writer::new(&mem, chain.clone())
                .map_err(Error::QueueWriter)
                .unwrap();

            self.server
                .handle_message(reader, writer, vu_req.as_mut())
                .map_err(Error::ProcessQueue)
                .unwrap();

            Self::return_descriptor(vring_state, head_index, self.event_idx);
        }

        Ok(used_any)
    }

    fn handle_event_pool(
        &self,
        device_event: u16,
        vrings: &[VringMutex],
    ) -> VhostUserBackendResult<bool> {
        let idx = match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
                0
            }
            REQ_QUEUE_EVENT => {
                debug!("QUEUE_EVENT");
                1
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        };

        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_queue() until it stops finding new
            // requests on the queue.
            loop {
                vrings[idx].disable_notification().unwrap();
                self.process_queue_pool(vrings[idx].clone())?;
                if !vrings[idx].enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            self.process_queue_pool(vrings[idx].clone())?;
        }

        Ok(false)
    }

    fn handle_event_serial(
        &self,
        device_event: u16,
        vrings: &[VringMutex],
    ) -> VhostUserBackendResult<bool> {
        let mut vring_state = match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
                vrings[0].get_mut()
            }
            REQ_QUEUE_EVENT => {
                debug!("QUEUE_EVENT");
                vrings[1].get_mut()
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        };

        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_queue() until it stops finding new
            // requests on the queue.
            loop {
                vring_state.disable_notification().unwrap();
                self.process_queue_serial(&mut vring_state)?;
                if !vring_state.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            self.process_queue_serial(&mut vring_state)?;
        }

        Ok(false)
    }
}

struct VhostUserFsBackend<F: FileSystem + Send + Sync + 'static> {
    thread: RwLock<VhostUserFsThread<F>>,
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserFsBackend<F> {
    fn new(fs: F, thread_pool_size: usize) -> Result<Self> {
        let thread = RwLock::new(VhostUserFsThread::new(fs, thread_pool_size)?);
        Ok(VhostUserFsBackend { thread })
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserBackend<VringMutex> for VhostUserFsBackend<F> {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SLAVE_REQ
            | VhostUserProtocolFeatures::SLAVE_SEND_FD
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS
    }

    fn set_event_idx(&self, enabled: bool) {
        self.thread.write().unwrap().event_idx = enabled;
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> VhostUserBackendResult<()> {
        self.thread.write().unwrap().mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringMutex],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let thread = self.thread.read().unwrap();

        if thread.pool.is_some() {
            thread.handle_event_pool(device_event, vrings)
        } else {
            thread.handle_event_serial(device_event, vrings)
        }
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        Some(self.thread.read().unwrap().kill_evt.try_clone().unwrap())
    }

    fn set_slave_req_fd(&self, vu_req: SlaveFsCacheReq) {
        self.thread.write().unwrap().vu_req = Some(vu_req);
    }
}

fn parse_seccomp(src: &str) -> std::result::Result<SeccompAction, &'static str> {
    Ok(match src {
        "none" => SeccompAction::Allow, // i.e. no seccomp
        "kill" => SeccompAction::Kill,
        "log" => SeccompAction::Log,
        "trap" => SeccompAction::Trap,
        _ => return Err("Matching variant not found"),
    })
}

/// On the command line, we want to allow aliases for `InodeFileHandlesMode` values.  This enum has
/// all values allowed on the command line, and with `From`/`Into`, it can be translated into the
/// internally used `InodeFileHandlesMode` enum.
#[derive(Debug, Copy, Clone, PartialEq)]
enum InodeFileHandlesCommandLineMode {
    /// `InodeFileHandlesMode::Never`
    Never,
    /// Alias for `InodeFileHandlesMode::Prefer`
    Fallback,
    /// `InodeFileHandlesMode::Prefer`
    Prefer,
    /// `InodeFileHandlesMode::Mandatory`
    Mandatory,
}

impl From<InodeFileHandlesCommandLineMode> for InodeFileHandlesMode {
    fn from(clm: InodeFileHandlesCommandLineMode) -> Self {
        match clm {
            InodeFileHandlesCommandLineMode::Never => InodeFileHandlesMode::Never,
            InodeFileHandlesCommandLineMode::Fallback => InodeFileHandlesMode::Prefer,
            InodeFileHandlesCommandLineMode::Prefer => InodeFileHandlesMode::Prefer,
            InodeFileHandlesCommandLineMode::Mandatory => InodeFileHandlesMode::Mandatory,
        }
    }
}

impl FromStr for InodeFileHandlesCommandLineMode {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "never" => Ok(InodeFileHandlesCommandLineMode::Never),
            "fallback" => Ok(InodeFileHandlesCommandLineMode::Fallback),
            "prefer" => Ok(InodeFileHandlesCommandLineMode::Prefer),
            "mandatory" => Ok(InodeFileHandlesCommandLineMode::Mandatory),

            _ => Err("invalid inode file handles mode"),
        }
    }
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "virtiofsd backend", about = "Launch a virtiofsd backend.")]
struct Opt {
    /// Shared directory path
    #[structopt(long)]
    shared_dir: Option<String>,

    /// vhost-user socket path [deprecated]
    #[structopt(long, required_unless_one = &["fd", "socket-path", "print-capabilities"])]
    socket: Option<String>,

    /// vhost-user socket path
    #[structopt(long = "socket-path", required_unless_one = &["fd", "socket", "print-capabilities"])]
    socket_path: Option<String>,

    /// Name of group for the vhost-user socket
    #[structopt(long = "socket-group", conflicts_with_all = &["fd", "print-capabilites"])]
    socket_group: Option<String>,

    /// File descriptor for the listening socket
    #[structopt(long, required_unless_one = &["socket", "socket-path", "print-capabilities"], conflicts_with_all = &["sock", "socket"])]
    fd: Option<RawFd>,

    /// Maximum thread pool size. A value of "0" disables the pool
    #[structopt(long, default_value = "0")]
    thread_pool_size: usize,

    /// Enable support for extended attributes
    #[structopt(long)]
    xattr: bool,

    /// Add custom rules for translating extended attributes between host and guest
    /// (e.g. :map::user.virtiofs.:)
    #[structopt(long, parse(try_from_str = <XattrMap as TryFrom<&str>>::try_from))]
    xattrmap: Option<XattrMap>,

    /// Sandbox mechanism to isolate the daemon process (namespace, chroot, none)
    #[structopt(long, default_value = "namespace")]
    sandbox: SandboxMode,

    /// Action to take when seccomp finds a not allowed syscall (none, kill, log, trap)
    #[structopt(long, parse(try_from_str = parse_seccomp), default_value = "kill")]
    seccomp: SeccompAction,

    /// Tell the guest which directories are mount points
    #[structopt(long)]
    announce_submounts: bool,

    /// When to use file handles to reference inodes instead of O_PATH file descriptors (never,
    /// prefer, mandatory)
    ///
    /// - never: Never use file handles, always use O_PATH file descriptors.
    ///
    /// - prefer: Attempt to generate file handles, but fall back to O_PATH file descriptors where
    /// the underlying filesystem does not support file handles.  Useful when there are various
    /// different filesystems under the shared directory and some of them do not support file
    /// handles.  ("fallback" is a deprecated alias for "prefer".)
    ///
    /// - mandatory: Always use file handles, never fall back to O_PATH file descriptors.
    ///
    /// Using file handles reduces the number of file descriptors virtiofsd keeps open, which is
    /// not only helpful with resources, but may also be important in cases where virtiofsd should
    /// only have file descriptors open for files that are open in the guest, e.g. to get around
    /// bad interactions with NFS's silly renaming.
    #[structopt(long, require_equals = true, default_value = "never")]
    inode_file_handles: InodeFileHandlesCommandLineMode,

    /// The caching policy the file system should use (auto, always, never)
    #[structopt(long, default_value = "auto")]
    cache: CachePolicy,

    /// Disable support for READDIRPLUS operations
    #[structopt(long)]
    no_readdirplus: bool,

    /// Enable writeback cache
    #[structopt(long)]
    writeback: bool,

    /// Honor the O_DIRECT flag passed down by guest applications
    #[structopt(long)]
    allow_direct_io: bool,

    /// Print vhost-user.json backend program capabilities and exit
    #[structopt(long = "print-capabilities")]
    print_capabilities: bool,

    /// Modify the list of capabilities, e.g., --modcaps=+sys_admin:-chown
    #[structopt(long)]
    modcaps: Option<String>,

    /// Log level (error, warn, info, debug, trace, off)
    #[structopt(long = "log-level", default_value = "info")]
    log_level: LevelFilter,

    /// Log to syslog [default: stderr]
    #[structopt(long)]
    syslog: bool,

    /// Set maximum number of file descriptors (0 leaves rlimit unchanged) [default: the value read from `/proc/sys/fs/nr_open`]
    #[structopt(long = "rlimit-nofile")]
    rlimit_nofile: Option<u64>,

    /// Options in a format compatible with the legacy implementation [deprecated]
    #[structopt(short = "o")]
    compat_options: Option<Vec<String>>,

    /// Set log level to "debug" [deprecated]
    #[structopt(short = "d")]
    compat_debug: bool,

    /// Disable KILLPRIV V2 support
    #[structopt(long)]
    no_killpriv_v2: bool,

    /// Compatibility option that has no effect [deprecated]
    #[structopt(short = "f")]
    compat_foreground: bool,
}

fn parse_compat(opt: Opt) -> Opt {
    use structopt::clap::{Error, ErrorKind};
    fn value_error(arg: &str, value: &str) -> ! {
        Error::with_description(
            format!("Invalid compat value '{}' for '-o {}'", value, arg).as_str(),
            ErrorKind::InvalidValue,
        )
        .exit()
    }
    fn argument_error(arg: &str) -> ! {
        Error::with_description(
            format!("Invalid compat argument '-o {}'", arg).as_str(),
            ErrorKind::UnknownArgument,
        )
        .exit()
    }

    fn parse_tuple(opt: &mut Opt, tuple: &str) {
        match tuple.split('=').collect::<Vec<&str>>()[..] {
            ["xattrmap", value] => {
                opt.xattrmap = Some(
                    XattrMap::try_from(value).unwrap_or_else(|_| value_error("xattrmap", value)),
                )
            }
            ["cache", value] => match value {
                "auto" => opt.cache = CachePolicy::Auto,
                "always" => opt.cache = CachePolicy::Always,
                "none" => opt.cache = CachePolicy::Never,
                _ => value_error("cache", value),
            },
            ["loglevel", value] => match value {
                "debug" => opt.log_level = LevelFilter::Debug,
                "info" => opt.log_level = LevelFilter::Info,
                "warn" => opt.log_level = LevelFilter::Warn,
                "err" => opt.log_level = LevelFilter::Error,
                _ => value_error("loglevel", value),
            },
            ["sandbox", value] => match value {
                "namespace" => opt.sandbox = SandboxMode::Namespace,
                "chroot" => opt.sandbox = SandboxMode::Chroot,
                _ => value_error("sandbox", value),
            },
            ["source", value] => opt.shared_dir = Some(value.to_string()),
            ["modcaps", value] => opt.modcaps = Some(value.to_string()),
            _ => argument_error(tuple),
        }
    }

    fn parse_single(opt: &mut Opt, option: &str) {
        match option {
            "xattr" => opt.xattr = true,
            "no_xattr" => opt.xattr = false,
            "readdirplus" => opt.no_readdirplus = false,
            "no_readdirplus" => opt.no_readdirplus = true,
            "writeback" => opt.writeback = true,
            "no_writeback" => opt.writeback = false,
            "allow_direct_io" => opt.allow_direct_io = true,
            "no_allow_direct_io" => opt.allow_direct_io = false,
            "announce_submounts" => opt.announce_submounts = true,
            "killpriv_v2" => opt.no_killpriv_v2 = false,
            "no_killpriv_v2" => opt.no_killpriv_v2 = true,
            "no_posix_lock" | "no_flock" => (),
            _ => argument_error(option),
        }
    }

    let mut clean_opt = opt.clone();

    if let Some(compat_options) = opt.compat_options.as_ref() {
        for line in compat_options {
            for option in line.to_string().split(',') {
                if option.contains('=') {
                    parse_tuple(&mut clean_opt, option);
                } else {
                    parse_single(&mut clean_opt, option);
                }
            }
        }
    }

    clean_opt
}

fn print_capabilities() {
    println!("{{");
    println!("  \"type\": \"fs\"");
    println!("}}");
}

fn set_default_logger(log_level: LevelFilter) {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", log_level.to_string());
    }
    env_logger::init();
}

fn initialize_logging(opt: &Opt) {
    let log_level = if opt.compat_debug {
        LevelFilter::Debug
    } else {
        opt.log_level
    };

    if opt.syslog {
        if let Err(e) = syslog::init(syslog::Facility::LOG_USER, log_level, None) {
            set_default_logger(log_level);
            warn!("can't enable syslog: {}", e);
        }
    } else {
        set_default_logger(log_level);
    }
}

fn set_signal_handlers() {
    use vmm_sys_util::signal;

    extern "C" fn handle_signal(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
        unsafe { libc::_exit(1) };
    }
    let signals = vec![libc::SIGHUP, libc::SIGTERM];
    for s in signals {
        if let Err(e) = signal::register_signal_handler(s, handle_signal) {
            error!("Setting signal handlers: {}", e);
            process::exit(1);
        }
    }
}

fn parse_modcaps(
    default_caps: Vec<&str>,
    modcaps: Option<String>,
) -> (HashSet<String>, HashSet<String>) {
    let mut required_caps: HashSet<String> = default_caps.iter().map(|&s| s.into()).collect();
    let mut disabled_caps = HashSet::new();

    if let Some(modcaps) = modcaps {
        for modcap in modcaps.split(':').map(str::to_string) {
            if modcap.is_empty() {
                error!("empty modcap found: expected (+|-)capability:...");
                process::exit(1);
            }
            let (action, cap_name) = modcap.split_at(1);
            let cap_name = cap_name.to_uppercase();
            if !matches!(action, "+" | "-") {
                error!(
                    "invalid modcap action: expecting '+'|'-' but found '{}'",
                    action
                );
                process::exit(1);
            }
            if let Err(error) = capng::name_to_capability(&cap_name) {
                error!("invalid capability '{}': {}", &cap_name, error);
                process::exit(1);
            }

            match action {
                "+" => {
                    disabled_caps.remove(&cap_name);
                    required_caps.insert(cap_name);
                }
                "-" => {
                    required_caps.remove(&cap_name);
                    disabled_caps.insert(cap_name);
                }
                _ => unreachable!(),
            }
        }
    }
    (required_caps, disabled_caps)
}

fn drop_parent_capabilities() {
    // The parent doesn't require any capabilities, as it'd be just waiting for
    // the child to exit.
    capng::clear(capng::Set::BOTH);
    if let Err(e) = capng::apply(capng::Set::BOTH) {
        // Don't exit the process here since we already have a child.
        error!("warning: can't apply the parent capabilities: {}", e);
    }
}

fn drop_child_capabilities(inode_file_handles: InodeFileHandlesMode, modcaps: Option<String>) {
    let default_caps = vec![
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "SETGID",
        "SETUID",
        "MKNOD",
        "SETFCAP",
    ];
    let (mut required_caps, disabled_caps) = parse_modcaps(default_caps, modcaps);

    if inode_file_handles != InodeFileHandlesMode::Never {
        let required_cap = "DAC_READ_SEARCH".to_owned();
        if disabled_caps.contains(&required_cap) {
            error!(
                "can't disable {} when using --inode-file-handles={:?}",
                &required_cap, inode_file_handles
            );
            process::exit(1);
        }
        required_caps.insert(required_cap);
    }

    capng::clear(capng::Set::BOTH);
    // Configure the required set of capabilities for the child, and leave the
    // parent with none.
    if let Err(e) = capng::updatev(
        capng::Action::ADD,
        capng::Type::PERMITTED | capng::Type::EFFECTIVE,
        required_caps.iter().map(String::as_str).collect(),
    ) {
        error!("can't set up the child capabilities: {}", e);
        process::exit(1);
    }
    if let Err(e) = capng::apply(capng::Set::BOTH) {
        error!("can't apply the child capabilities: {}", e);
        process::exit(1);
    }
}

fn main() {
    let opt = parse_compat(Opt::from_args());

    let killpriv_v2 = !opt.no_killpriv_v2;

    if opt.print_capabilities {
        print_capabilities();
        return;
    }

    initialize_logging(&opt);
    set_signal_handlers();

    let shared_dir = match opt.shared_dir.as_ref() {
        Some(s) => s,
        None => {
            error!("missing \"--shared-dir\" or \"-o source\" option");
            process::exit(1);
        }
    };
    if opt.compat_foreground {
        warn!("Use of deprecated flag '-f': This flag has no effect, please remove it");
    }
    if opt.compat_debug {
        warn!("Use of deprecated flag '-d': Please use the '--log-level debug' option instead");
    }
    if opt.compat_options.is_some() {
        warn!("Use of deprecated option format '-o': Please specify options without it (e.g., '--cache auto' instead of '-o cache=auto')");
    }
    if opt.inode_file_handles == InodeFileHandlesCommandLineMode::Fallback {
        warn!("Use of deprecated value 'fallback' for '--inode-file-handles': Please use 'prefer' instead");
    }

    let sandbox_mode = opt.sandbox.clone();
    let xattrmap = opt.xattrmap.clone();
    let xattr = if xattrmap.is_some() { true } else { opt.xattr };
    let thread_pool_size = opt.thread_pool_size;
    let readdirplus = match opt.cache {
        CachePolicy::Never => false,
        _ => !opt.no_readdirplus,
    };

    let umask = if opt.socket_group.is_some() {
        libc::S_IROTH | libc::S_IWOTH | libc::S_IXOTH
    } else {
        libc::S_IRGRP
            | libc::S_IWGRP
            | libc::S_IXGRP
            | libc::S_IROTH
            | libc::S_IWOTH
            | libc::S_IXOTH
    };

    let (listener, socket_path) = match opt.fd.as_ref() {
        Some(fd) => unsafe { (Listener::from_raw_fd(*fd), None) },
        None => {
            // Set umask to ensure the socket is created with the right permissions
            let old_umask = unsafe { libc::umask(umask) };

            let socket = opt.socket_path.as_ref().unwrap_or_else(|| {
                warn!("use of deprecated parameter '--socket': Please use the '--socket-path' option instead");
                opt.socket.as_ref().unwrap() // safe to unwrap because clap ensures either --socket or --sock are passed
            });
            let listener = Listener::new(socket, true).unwrap_or_else(|error| {
                error!("Error creating listener: {}", error);
                process::exit(1);
            });

            // Restore umask
            unsafe { libc::umask(old_umask) };

            (listener, Some(socket.clone()))
        }
    };

    if let Some(group_name) = opt.socket_group {
        let c_name = CString::new(group_name).expect("invalid group name");
        let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
        if group.is_null() {
            error!("Couldn't resolve the group name specified for the socket path");
            process::exit(1);
        }

        // safe to unwrap because clap ensures --socket-group can't be specified alongside --fd
        let c_socket_path = CString::new(socket_path.unwrap()).expect("invalid socket path");
        let ret = unsafe { libc::chown(c_socket_path.as_ptr(), u32::MAX, (*group).gr_gid) };
        if ret != 0 {
            error!(
                "Couldn't set up the group for the socket path: {}",
                std::io::Error::last_os_error()
            );
            process::exit(1);
        }
    }

    let rlimit_nofile = if let Some(rlimit_nofile) = opt.rlimit_nofile {
        if rlimit_nofile != 0 {
            Some(rlimit_nofile)
        } else {
            None
        }
    } else {
        None
    };

    let mut sandbox = Sandbox::new(shared_dir.to_string(), sandbox_mode, rlimit_nofile)
        .unwrap_or_else(|error| {
            error!("Error creating sandbox: {}", error);
            process::exit(1)
        });
    let fs_cfg = match sandbox.enter().unwrap_or_else(|error| {
        error!("Error entering sandbox: {}", error);
        process::exit(1)
    }) {
        // `enter()` returns the PID of the child to the parent, if it forked.
        Some(child_pid) => {
            drop_parent_capabilities();
            let mut status = 0;
            // On success, `libc::waitpid()` returns the PID of the child.
            if unsafe { libc::waitpid(child_pid, &mut status, 0) } != child_pid {
                error!("Error during waitpid()");
                process::exit(1);
            }

            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                let signal = libc::WTERMSIG(status);
                error!("Child process terminated by signal {}", signal);
                -signal
            } else {
                error!("Unexpected waitpid status: {:#X}", status);
                libc::EXIT_FAILURE
            };

            process::exit(exit_code);
        }
        // `enter()` returns `None` to the process that should proceed (i.e. to the child, if it
        // forked).
        None => passthrough::Config {
            cache_policy: opt.cache,
            root_dir: sandbox.get_root_dir(),
            mountinfo_prefix: sandbox.get_mountinfo_prefix(),
            xattr,
            xattrmap,
            proc_sfd_rawfd: sandbox.get_proc_self_fd(),
            proc_mountinfo_rawfd: sandbox.get_mountinfo_fd(),
            announce_submounts: opt.announce_submounts,
            inode_file_handles: opt.inode_file_handles.into(),
            readdirplus,
            writeback: opt.writeback,
            allow_direct_io: opt.allow_direct_io,
            killpriv_v2,
            ..Default::default()
        },
    };

    // Must happen before we start the thread pool
    match opt.seccomp {
        SeccompAction::Allow => {}
        _ => enable_seccomp(opt.seccomp, opt.syslog).unwrap(),
    }

    drop_child_capabilities(fs_cfg.inode_file_handles, opt.modcaps);

    let fs = PassthroughFs::new(fs_cfg).unwrap();
    let fs_backend = Arc::new(VhostUserFsBackend::new(fs, thread_pool_size).unwrap());

    let mut daemon = VhostUserDaemon::new(
        String::from("virtiofsd-backend"),
        fs_backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    info!("Waiting for vhost-user socket connection...");

    if let Err(e) = daemon.start(listener) {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    info!("Client connected, servicing requests");

    if let Err(e) = daemon.wait() {
        match e {
            HandleRequest(PartialMessage) => info!("Client disconnected, shutting down"),
            _ => error!("Waiting for daemon failed: {:?}", e),
        }
    }

    let kill_evt = fs_backend
        .thread
        .read()
        .unwrap()
        .kill_evt
        .try_clone()
        .unwrap();
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
