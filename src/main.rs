// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use clap::{crate_authors, crate_version, App, Arg};
use futures::executor::{ThreadPool, ThreadPoolBuilder};
use libc::EFD_NONBLOCK;
use log::*;
use seccomp::SeccompAction;
use std::sync::{Arc, Mutex, RwLock};
use std::{convert, error, fmt, io, process};

use vhost::vhost_user::message::*;
use vhost::vhost_user::{Listener, SlaveFsCacheReq};
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, Vring};
use virtio_bindings::bindings::virtio_net::*;
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtiofsd_rs::descriptor_utils::Error as VufDescriptorError;
use virtiofsd_rs::descriptor_utils::{Reader, Writer};
use virtiofsd_rs::filesystem::FileSystem;
use virtiofsd_rs::passthrough::{self, PassthroughFs};
use virtiofsd_rs::sandbox::Sandbox;
use virtiofsd_rs::seccomp::enable_seccomp;
use virtiofsd_rs::server::Server;
use virtiofsd_rs::Error as VhostUserFsError;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vm_virtio::Queue;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;
const THREAD_POOL_SIZE: usize = 64;

// The guest queued an available buffer for the high priority queue.
const HIPRIO_QUEUE_EVENT: u16 = 0;
// The guest queued an available buffer for the request queue.
const REQ_QUEUE_EVENT: u16 = 1;
// The device has been dropped.
const KILL_EVENT: u16 = 2;

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
    pool: ThreadPool,
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
        Ok(VhostUserFsThread {
            mem: None,
            kill_evt: EventFd::new(EFD_NONBLOCK).map_err(Error::CreateKillEventFd)?,
            server: Arc::new(Server::new(fs)),
            vu_req: None,
            event_idx: false,
            pool: ThreadPoolBuilder::new()
                .pool_size(thread_pool_size)
                .create()
                .map_err(Error::CreateThreadPool)?,
        })
    }

    fn process_queue(
        &mut self,
        queue: &mut Queue<GuestMemoryAtomic<GuestMemoryMmap>>,
        vring_lock: Arc<RwLock<Vring>>,
    ) -> Result<bool> {
        let mut used_any = false;
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        while let Some(avail_desc) = queue.iter().map_err(|_| Error::IterateQueue)?.next() {
            used_any = true;

            // Prepare a set of objects that can be moved to the worker thread.
            let atomic_mem = atomic_mem.clone();
            let server = self.server.clone();
            let mut vu_req = self.vu_req.clone();
            let event_idx = self.event_idx;
            let vring_lock = vring_lock.clone();
            let worker_desc = avail_desc.clone();

            self.pool.spawn_ok(async move {
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

                let mut vring = vring_lock.write().unwrap();

                if event_idx {
                    let queue = vring.mut_queue();
                    if queue.add_used(head_index, 0).is_err() {
                        warn!("Couldn't return used descriptors to the ring");
                    }

                    match queue.needs_notification() {
                        Err(_) => {
                            warn!("Couldn't check if queue needs to be notified");
                            vring.signal_used_queue().unwrap();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                vring.signal_used_queue().unwrap();
                            }
                        }
                    }
                } else {
                    if vring.mut_queue().add_used(head_index, 0).is_err() {
                        warn!("Couldn't return used descriptors to the ring");
                    }
                    vring.signal_used_queue().unwrap();
                }
            });
        }

        Ok(used_any)
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

impl<F: FileSystem + Send + Sync + 'static> VhostUserBackend for VhostUserFsBackend<F> {
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
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::SLAVE_REQ
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
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut thread = self.thread.lock().unwrap();

        let vring_lock = match device_event {
            HIPRIO_QUEUE_EVENT => {
                debug!("HIPRIO_QUEUE_EVENT");
                vrings[0].clone()
            }
            REQ_QUEUE_EVENT => {
                debug!("QUEUE_EVENT");
                vrings[1].clone()
            }
            _ => return Err(Error::HandleEventUnknownEvent.into()),
        };

        if thread.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_queue() until it stops finding new
            // requests on the queue.
            let mut vring = vring_lock.write().unwrap();
            let queue = vring.mut_queue();
            loop {
                queue.disable_notification().unwrap();
                thread.process_queue(queue, vring_lock.clone())?;
                if !queue.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            let mut vring = vring_lock.write().unwrap();
            let queue = vring.mut_queue();
            thread.process_queue(queue, vring_lock.clone())?;
        }

        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, Option<u16>)> {
        Some((
            self.thread.lock().unwrap().kill_evt.try_clone().unwrap(),
            Some(KILL_EVENT),
        ))
    }

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        self.thread.lock().unwrap().vu_req = Some(vu_req);
    }
}

fn main() {
    let cmd_arguments = App::new("virtiofsd backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a virtiofsd backend.")
        .arg(
            Arg::with_name("shared-dir")
                .long("shared-dir")
                .help("Shared directory path")
                .takes_value(true)
                .min_values(1)
                .required(true),
        )
        .arg(
            Arg::with_name("sock")
                .long("sock")
                .help("vhost-user socket path (deprecated)")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("socket")
                .long("socket")
                .help("vhost-user socket path")
                .takes_value(true)
                .min_values(1)
                .required_unless("sock"),
        )
        .arg(
            Arg::with_name("thread-pool-size")
                .long("thread-pool-size")
                .help("thread pool size (default 64)")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("disable-xattr")
                .long("disable-xattr")
                .help("Disable support for extended attributes"),
        )
        .arg(
            Arg::with_name("disable-sandbox")
                .long("disable-sandbox")
                .help("Don't set up a sandbox for the daemon"),
        )
        .arg(
            Arg::with_name("seccomp")
                .long("seccomp")
                .help("Disable/debug seccomp security")
                .possible_values(&["kill", "log", "trap", "none"])
                .default_value("kill"),
        )
        .arg(
            Arg::with_name("no-announce-submounts")
                .long("no-announce-submounts")
                .help("Don't tell the guest which directories are mount points"),
        )
        .get_matches();

    // Retrieve arguments
    let shared_dir = cmd_arguments
        .value_of("shared-dir")
        .expect("Failed to retrieve shared directory path");
    let socket = match cmd_arguments.value_of("socket") {
        Some(path) => path,
        None => {
            println!("warning: use of deprecated parameter '--sock': Please use the '--socket' option instead.");
            cmd_arguments
                .value_of("sock")
                .expect("Failed to retrieve vhost-user socket path")
        }
    };

    let thread_pool_size: usize = match cmd_arguments.value_of("thread-pool-size") {
        Some(size) => size.parse().expect("Invalid argument for thread-pool-size"),
        None => THREAD_POOL_SIZE,
    };
    let xattr: bool = !cmd_arguments.is_present("disable-xattr");
    let create_sandbox: bool = !cmd_arguments.is_present("disable-sandbox");
    let seccomp_mode: SeccompAction = match cmd_arguments.value_of("seccomp").unwrap() {
        "none" => SeccompAction::Allow, // i.e. no seccomp
        "kill" => SeccompAction::Kill,
        "log" => SeccompAction::Log,
        "trap" => SeccompAction::Trap,
        _ => unreachable!(), // We told Arg possible_values
    };
    let announce_submounts: bool = !cmd_arguments.is_present("no-announce-submounts");

    let listener = Listener::new(socket, true).unwrap();

    let fs_cfg = if create_sandbox {
        let mut sandbox = Sandbox::new(shared_dir.to_string());
        match sandbox.enter().unwrap() {
            Some(child_pid) => {
                unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), 0) };
                return;
            }
            None => passthrough::Config {
                root_dir: "/".to_string(),
                xattr,
                proc_sfd_rawfd: sandbox.get_proc_self_fd(),
                announce_submounts,
                ..Default::default()
            },
        }
    } else {
        passthrough::Config {
            root_dir: shared_dir.to_string(),
            xattr,
            announce_submounts,
            ..Default::default()
        }
    };

    // Must happen before we start the thread pool
    if seccomp_mode != SeccompAction::Allow {
        enable_seccomp(seccomp_mode).unwrap();
    };

    let fs = PassthroughFs::new(fs_cfg).unwrap();
    let fs_backend = Arc::new(RwLock::new(
        VhostUserFsBackend::new(fs, thread_pool_size).unwrap(),
    ));

    let mut daemon =
        VhostUserDaemon::new(String::from("virtiofsd-backend"), fs_backend.clone()).unwrap();

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
