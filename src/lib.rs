#![cfg_attr(feature = "unsafe-op-in-unsafe-fn", deny(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(feature = "unsafe-op-in-unsafe-fn"), allow(unused_unsafe))]

use std::io::Error;
use std::os::unix::io::RawFd;
use std::rc::Rc;
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

mod vhost_user;
pub mod virtqueue;

pub use vhost_user::VhostUser;

use virtqueue::{Virtqueue, VirtqueueLayout};

/// An interface to the virtio transport/bus of a device
pub trait VirtioTransport {
    /// Returns the maximum number of queues supported by the device.
    fn max_queues(&self) -> usize;

    /// Returns the maximum number of memory regions supported by the transport.
    fn max_mem_regions(&self) -> u64;

    /// Allocates or maps the memory to store the virtqueues in.
    ///
    /// This memory must be accessible by the device and is also used for additional per-request
    /// metadata (such as request headers) that is created internally by the driver and must be
    /// visible for the device.
    fn alloc_queue_mem(&mut self, layout: &VirtqueueLayout) -> Result<&mut [u8], Error>;

    /// Registers a memory region with the transport.
    ///
    /// Requests to the device may only refer to memory that is in a registered memory region.
    fn add_mem_region(
        &mut self,
        addr: usize,
        len: usize,
        fd: RawFd,
        fd_offset: i64,
    ) -> Result<(), Error>;

    /// Unregisters a memory region from the transport.
    fn del_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error>;

    /// Initialises and enables the passed queues on the transport level.
    fn setup_queues<R: Copy>(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error>;

    /// Returns the negotiated virtio feature flags.
    fn get_features(&self) -> u64;

    /// Queries the device configuration.
    fn get_config<C: ByteValued>(&mut self) -> Result<C, Error>;

    /// Returns an [`EventFd`] that can be written to notify the device of new requests in the
    /// queue.
    fn get_submission_fd(&self, queue_idx: usize) -> Rc<EventFd>;

    /// Returns an [`EventFd`] that can be read to be notified of request completions in the queue.
    fn get_completion_fd(&self, queue_idx: usize) -> Rc<EventFd>;
}
