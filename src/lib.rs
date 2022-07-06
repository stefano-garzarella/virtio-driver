// SPDX-License-Identifier: LGPL-2.1-or-later

#![cfg_attr(feature = "_unsafe-op-in-unsafe-fn", deny(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(feature = "_unsafe-op-in-unsafe-fn"), allow(unused_unsafe))]

use bitflags::bitflags;
use std::io::Error;
use std::os::unix::io::RawFd;
use std::rc::Rc;

mod util;
mod virtio_blk;
pub mod virtqueue;

#[cfg(feature = "vhost-user")]
mod vhost_user;
#[cfg(feature = "vhost-vdpa")]
mod vhost_vdpa;

pub use util::bytevalued::*;
pub use util::endian::*;
pub use util::eventfd::*;

#[cfg(feature = "vhost-user")]
pub use vhost_user::VhostUser;
#[cfg(feature = "vhost-vdpa")]
pub use vhost_vdpa::VhostVdpa;

pub use virtio_blk::{
    validate_lba, VirtioBlkConfig, VirtioBlkFeatureFlags, VirtioBlkQueue, VirtioBlkReqBuf,
    VirtioBlkTransport,
};
use virtqueue::{Virtqueue, VirtqueueLayout};

bitflags! {
    pub struct VirtioFeatureFlags: u64 {
        const RING_INDIRECT_DESC = 1 << 28;
        const RING_EVENT_IDX = 1 << 29;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;
        const IN_ORDER = 1 << 35;
        const ORDER_PLATFORM = 1 << 36;
        const SR_IOV = 1 << 37;
        const NOTIFICATION_DATA = 1 << 38;
        const NOTIF_CONFIG_DATA = 1 << 39;
        const RING_RESET = 1 << 40;
    }
}

/// The result of a completed request.
///
/// Type parameter `C` denotes the type of the "context" associated with the request.
pub struct Completion<C> {
    /// The user-defined "context" that was associated with the request.
    pub context: C,

    /// 0 on success, a negative `errno` value on error.
    pub ret: i32,
}

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
    fn get_config(&mut self) -> Result<C, Error>;

    /// Returns an [`EventFd`] that can be written to notify the device of new requests in the
    /// queue.
    fn get_submission_fd(&self, queue_idx: usize) -> Rc<EventFd>;

    /// Returns an [`EventFd`] that can be read to be notified of request completions in the queue.
    fn get_completion_fd(&self, queue_idx: usize) -> Rc<EventFd>;
}
