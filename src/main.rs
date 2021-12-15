// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use futures::executor::{ThreadPool, ThreadPoolBuilder};
use libc::EFD_NONBLOCK;
use log::*;
use passthrough::xattrmap::XattrMap;
use std::convert::{self, TryFrom};
use std::ffi::CString;
use std::os::unix::io::{FromRawFd, RawFd};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::{env, error, fmt, io, process};

use structopt::StructOpt;

use vhost::vhost_user::message::*;
use vhost::vhost_user::{Listener, SlaveFsCacheReq};
use vhost_user_backend::{
    VhostUserBackendMut, VhostUserDaemon, VringMutex, VringStateMutGuard, VringT,
};
use virtio_bindings::bindings::virtio_net::*;
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use virtiofsd_rs::descriptor_utils::{Error as VufDescriptorError, Reader, Writer};
use virtiofsd_rs::filesystem::FileSystem;
use virtiofsd_rs::passthrough::{self, CachePolicy, InodeFileHandlesMode, PassthroughFs};
use virtiofsd_rs::sandbox::{Sandbox, SandboxMode};
use virtiofsd_rs::seccomp::{enable_seccomp, SeccompAction};
use virtiofsd_rs::server::Server;
use virtiofsd_rs::Error as VhostUserFsError;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

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
    /// Invalid compat argument found on the command line.
    InvalidCompatArgument,
    /// Invalid compat value found on the command line.
    InvalidCompatValue,
    /// Invalid xattr map compat argument found on the command line.
    InvalidXattrMap,
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

#[derive(Clone, Debug)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for LogLevel {
    type Err = &'static str;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Err("Unknown log level"),
        }
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

    fn process_queue_pool(&mut self, vring: VringMutex) -> Result<bool> {
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

                if event_idx {
                    if worker_vring.add_used(head_index, 0).is_err() {
                        warn!("Couldn't return used descriptors to the ring");
                    }

                    match worker_vring.needs_notification() {
                        Err(_) => {
                            warn!("Couldn't check if queue needs to be notified");
                            worker_vring.signal_used_queue().unwrap();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                worker_vring.signal_used_queue().unwrap();
                            }
                        }
                    }
                } else {
                    if worker_vring.add_used(head_index, 0).is_err() {
                        warn!("Couldn't return used descriptors to the ring");
                    }
                    worker_vring.signal_used_queue().unwrap();
                }
            });
        }

        Ok(used_any)
    }

    fn process_queue_serial(
        &mut self,
        vring_state: &mut VringStateMutGuard<GuestMemoryAtomic<GuestMemoryMmap>>,
    ) -> Result<bool> {
        let mut used_any = false;
        let mem = match &self.mem {
            Some(m) => m.memory(),
            None => return Err(Error::NoMemoryConfigured),
        };

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
                .handle_message(reader, writer, self.vu_req.as_mut())
                .map_err(Error::ProcessQueue)
                .unwrap();

            if self.event_idx {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }

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
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }
                vring_state.signal_used_queue().unwrap();
            }
        }

        Ok(used_any)
    }

    fn handle_event_pool(
        &mut self,
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
        &mut self,
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
    thread: Mutex<VhostUserFsThread<F>>,
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserFsBackend<F> {
    fn new(fs: F, thread_pool_size: usize) -> Result<Self> {
        let thread = Mutex::new(VhostUserFsThread::new(fs, thread_pool_size)?);
        Ok(VhostUserFsBackend { thread })
    }
}

impl<F: FileSystem + Send + Sync + 'static> VhostUserBackendMut<VringMutex>
    for VhostUserFsBackend<F>
{
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

    fn set_event_idx(&mut self, enabled: bool) {
        self.thread.lock().unwrap().event_idx = enabled;
    }

    fn update_memory(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> VhostUserBackendResult<()> {
        self.thread.lock().unwrap().mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringMutex],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut thread = self.thread.lock().unwrap();

        if thread.pool.is_some() {
            thread.handle_event_pool(device_event, vrings)
        } else {
            thread.handle_event_serial(device_event, vrings)
        }
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        Some(self.thread.lock().unwrap().kill_evt.try_clone().unwrap())
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.thread.lock().unwrap().vu_req = Some(vu_req);
    }
}

fn parse_seccomp(src: &str) -> std::result::Result<SeccompAction, &'static str> {
    Ok(match src {
        "none" => SeccompAction::Allow, // i.e. no seccomp
        "kill" => SeccompAction::Kill,
        "trap" => SeccompAction::Trap,
        _ => return Err("Matching variant not found"),
    })
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "virtiofsd backend", about = "Launch a virtiofsd backend.")]
struct Opt {
    /// Shared directory path
    #[structopt(long)]
    shared_dir: Option<String>,

    /// vhost-user socket path (deprecated)
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

    /// Action to take when seccomp finds a not allowed syscall (allow, kill, log, trap)
    #[structopt(long, parse(try_from_str = parse_seccomp), default_value = "kill")]
    seccomp: SeccompAction,

    /// Tell the guest which directories are mount points
    #[structopt(long)]
    announce_submounts: bool,

    /// When to use file handles to reference inodes instead of O_PATH file descriptors (never,
    /// fallback)
    ///
    /// - never: Never use file handles, always use O_PATH file descriptors.
    ///
    /// - fallback: Attempt to generate file handles, but fall back to O_PATH file descriptors
    /// where the underlying filesystem does not support file handles.
    ///
    /// Using file handles reduces the number of file descriptors virtiofsd keeps open, which is
    /// not only helpful with resources, but may also be important in cases where virtiofsd should
    /// only have file descriptors open for files that are open in the guest, e.g. to get around
    /// bad interactions with NFS's silly renaming.
    #[structopt(long, require_equals = true, default_value = "never")]
    inode_file_handles: InodeFileHandlesMode,

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

    /// Log level (error, warn, info, debug, trace)
    #[structopt(long = "log-level", default_value = "error")]
    log_level: LogLevel,

    /// Set maximum number of file descriptors (0 leaves rlimit unchanged) [default: the value read from `/proc/sys/fs/nr_open`]
    #[structopt(long = "rlimit-nofile")]
    rlimit_nofile: Option<u64>,

    /// Options in a format compatible with the legacy implementation
    #[structopt(short = "o")]
    compat_options: Option<Vec<String>>,
}

fn parse_compat(opt: Opt) -> Result<Opt> {
    fn parse_tuple(opt: &mut Opt, tuple: &str) -> Result<()> {
        match tuple.split('=').collect::<Vec<&str>>()[..] {
            ["xattrmap", value] => {
                opt.xattrmap = Some(XattrMap::try_from(value).map_err(|_| Error::InvalidXattrMap)?)
            }
            ["cache", value] => match value {
                "auto" => opt.cache = CachePolicy::Auto,
                "always" => opt.cache = CachePolicy::Always,
                "none" => opt.cache = CachePolicy::Never,
                _ => return Err(Error::InvalidCompatValue),
            },
            ["loglevel", value] => match value {
                "debug" => opt.log_level = LogLevel::Debug,
                "info" => opt.log_level = LogLevel::Info,
                "warn" => opt.log_level = LogLevel::Warn,
                "err" => opt.log_level = LogLevel::Error,
                _ => return Err(Error::InvalidCompatValue),
            },
            ["sandbox", value] => match value {
                "namespace" => opt.sandbox = SandboxMode::Namespace,
                "chroot" => opt.sandbox = SandboxMode::Chroot,
                _ => return Err(Error::InvalidCompatValue),
            },
            ["source", value] => opt.shared_dir = Some(value.to_string()),
            _ => return Err(Error::InvalidCompatArgument),
        }
        Ok(())
    }

    fn parse_single(opt: &mut Opt, option: &str) -> Result<()> {
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
            _ => return Err(Error::InvalidCompatArgument),
        }
        Ok(())
    }

    let mut clean_opt = opt.clone();

    if let Some(compat_options) = opt.compat_options.as_ref() {
        for line in compat_options {
            for option in line.to_string().split(',') {
                if option.contains('=') {
                    parse_tuple(&mut clean_opt, option)?;
                } else {
                    parse_single(&mut clean_opt, option)?;
                }
            }
        }
    }

    Ok(clean_opt)
}

fn print_capabilities() {
    println!("{{");
    println!("  \"type\": \"fs\"");
    println!("}}");
}

fn initialize_logging(log_level: &LogLevel) {
    match env::var("RUST_LOG") {
        Ok(_) => {}
        Err(_) => env::set_var("RUST_LOG", log_level.to_string()),
    }
    env_logger::init();
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

fn drop_child_capabilities(inode_file_handles: InodeFileHandlesMode) {
    let mut required_caps = vec![
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "SETGID",
        "SETUID",
        "MKNOD",
        "SETFCAP",
    ];

    if inode_file_handles != InodeFileHandlesMode::Never {
        required_caps.push("DAC_READ_SEARCH");
    }

    capng::clear(capng::Set::BOTH);
    // Configure the required set of capabilities for the child, and leave the
    // parent with none.
    if let Err(e) = capng::updatev(
        capng::Action::ADD,
        capng::Type::PERMITTED | capng::Type::EFFECTIVE,
        required_caps,
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
    let opt = parse_compat(Opt::from_args()).expect("invalid compat argument");

    if opt.print_capabilities {
        print_capabilities();
        return;
    }

    initialize_logging(&opt.log_level);

    let shared_dir = match opt.shared_dir.as_ref() {
        Some(s) => s,
        None => {
            error!("missing \"--shared-dir\" or \"-o source\" option");
            process::exit(1);
        }
    };
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
                println!("warning: use of deprecated parameter '--socket': Please use the '--socket-path' option instead.");
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

    let mut sandbox = Sandbox::new(shared_dir.to_string(), sandbox_mode, rlimit_nofile);
    let fs_cfg = match sandbox.enter().unwrap_or_else(|error| {
        error!("Error entering sandbox: {}", error);
        process::exit(1)
    }) {
        Some(child_pid) => {
            drop_parent_capabilities();
            unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), 0) };
            return;
        }
        None => passthrough::Config {
            cache_policy: opt.cache,
            root_dir: sandbox.get_root_dir(),
            xattr,
            xattrmap,
            proc_sfd_rawfd: sandbox.get_proc_self_fd(),
            proc_mountinfo_rawfd: sandbox.get_mountinfo_fd(),
            announce_submounts: opt.announce_submounts,
            inode_file_handles: opt.inode_file_handles,
            readdirplus,
            writeback: opt.writeback,
            allow_direct_io: opt.allow_direct_io,
            ..Default::default()
        },
    };

    // Must happen before we start the thread pool
    match opt.seccomp {
        SeccompAction::Allow => {}
        _ => enable_seccomp(opt.seccomp).unwrap(),
    }

    drop_child_capabilities(opt.inode_file_handles);

    let fs = PassthroughFs::new(fs_cfg).unwrap();
    let fs_backend = Arc::new(RwLock::new(
        VhostUserFsBackend::new(fs, thread_pool_size).unwrap(),
    ));

    let mut daemon = VhostUserDaemon::new(
        String::from("virtiofsd-backend"),
        fs_backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    if let Err(e) = daemon.start(listener) {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    if let Err(e) = daemon.wait() {
        error!("Waiting for daemon failed: {:?}", e);
    }

    let kill_evt = fs_backend
        .read()
        .unwrap()
        .thread
        .lock()
        .unwrap()
        .kill_evt
        .try_clone()
        .unwrap();
    if let Err(e) = kill_evt.write(1) {
        error!("Error shutting down worker thread: {:?}", e)
    }
}
