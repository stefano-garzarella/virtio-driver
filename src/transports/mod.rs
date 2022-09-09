// SPDX-License-Identifier: (MIT OR Apache-2.0)

use std::io::Error;
use std::os::unix::io::RawFd;
use std::rc::Rc;

#[cfg(feature = "vhost-user")]
mod vhost_user;
#[cfg(feature = "vhost-vdpa")]
mod vhost_vdpa;

#[cfg(feature = "vhost-user")]
pub use vhost_user::VhostUser;
#[cfg(feature = "vhost-vdpa")]
pub use vhost_vdpa::VhostVdpa;

use crate::util::bytevalued::ByteValued;
use crate::util::eventfd::EventFd;
use crate::virtqueue::{Virtqueue, VirtqueueLayout};

/// An interface to the virtio transport/bus of a device
///
/// Type parameters:
/// - `C` represents the device configuration space, as returned by [`VirtioTransport::get_config`];
/// - `R` has the same meaning as in [`Virtqueue`], and is used to store device-specific per-request
///   data.
pub trait VirtioTransport<C: ByteValued, R: Copy> {
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

    /// Maps a memory region with the transport.
    ///
    /// Requests to the device may only refer to memory that is in a mapped memory region.
    fn map_mem_region(
        &mut self,
        addr: usize,
        len: usize,
        fd: RawFd,
        fd_offset: i64,
    ) -> Result<(), Error>;

    /// Unmaps a memory region from the transport.
    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error>;

    /// Initialises and enables the passed queues on the transport level.
    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error>;

    /// Returns the negotiated virtio feature flags.
    fn get_features(&self) -> u64;

    /// Queries the device configuration.
    fn get_config(&self) -> Result<C, Error>;

    /// Returns an [`EventFd`] that can be written to notify the device of new requests in the
    /// queue.
    fn get_submission_fd(&self, queue_idx: usize) -> Rc<EventFd>;

    /// Returns an [`EventFd`] that can be read to be notified of request completions in the queue.
    fn get_completion_fd(&self, queue_idx: usize) -> Rc<EventFd>;
}
