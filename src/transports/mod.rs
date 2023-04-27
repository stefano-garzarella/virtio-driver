// SPDX-License-Identifier: (MIT OR Apache-2.0)

use std::io::Error;
use std::os::unix::io::RawFd;
use std::sync::Arc;

#[cfg(feature = "pci")]
mod pci;
#[cfg(feature = "vhost-user")]
mod vhost_user;
#[cfg(feature = "vhost-vdpa")]
mod vhost_vdpa;

#[cfg(feature = "pci")]
pub use pci::Pci;
#[cfg(feature = "vhost-user")]
pub use vhost_user::VhostUser;
#[cfg(feature = "vhost-vdpa")]
pub use vhost_vdpa::VhostVdpa;

use crate::util::bytevalued::ByteValued;
use crate::util::eventfd::EventFd;
use crate::util::iova::Iova;
use crate::virtqueue::{Virtqueue, VirtqueueLayout};

/// Something that can translate process addresses into IOVAs.
pub trait IovaTranslator: Send + Sync {
    /// Determines the base IOVA corresponding to the given process address range.
    ///
    /// If the transport requires memory to be mapped prior to use but the address doesn't belong to
    /// a mapped memory region, an `Err` will be returned.
    ///
    /// The `addr..addr + len` range must not cross memory region boundaries, otherwise `Err` is
    /// returned.
    fn translate_addr(&self, addr: usize, len: usize) -> Result<Iova, Error>;
}

/// An interface to the virtio transport/bus of a device
///
/// Type parameters:
/// - `C` represents the device configuration space, as returned by [`VirtioTransport::get_config`];
/// - `R` has the same meaning as in [`Virtqueue`], and is used to store device-specific per-request
///   data.
pub trait VirtioTransport<C: ByteValued, R: Copy>: Send + Sync {
    /// Returns the maximum number of queues supported by the device if the transport is able to
    /// get this information.
    fn max_queues(&self) -> Option<usize>;

    /// Returns the maximum number of memory regions supported by the transport.
    fn max_mem_regions(&self) -> u64;

    /// Returns the alignment requirement in bytes of the memory region
    fn mem_region_alignment(&self) -> usize;

    /// Allocates or maps the memory to store the virtqueues in.
    ///
    /// This memory must be accessible by the device and is also used for additional per-request
    /// metadata (such as request headers) that is created internally by the driver and must be
    /// visible for the device.
    fn alloc_queue_mem(&mut self, layout: &VirtqueueLayout) -> Result<&mut [u8], Error>;

    /// Maps a memory region with the transport.
    ///
    /// Returns the IOVA corresponding to the start of the memory region.
    ///
    /// Requests to the device may only refer to memory that is in a mapped memory region.
    fn map_mem_region(
        &mut self,
        addr: usize,
        len: usize,
        fd: RawFd,
        fd_offset: i64,
    ) -> Result<Iova, Error>;

    /// Unmaps a memory region from the transport.
    ///
    /// Note that mapped regions are implicitly unmapped when the transport is dropped.
    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error>;

    /// Returns a value that can translate process addresses into IOVAs.
    fn iova_translator(&self) -> Box<dyn IovaTranslator>;

    /// Initialises and enables the passed queues on the transport level.
    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error>;

    /// Returns the negotiated virtio feature flags.
    fn get_features(&self) -> u64;

    /// Queries the device configuration.
    fn get_config(&self) -> Result<C, Error>;

    /// Returns a [`QueueNotifier`] that can be used to notify the device of new requests in the
    /// queue.
    fn get_submission_notifier(&self, queue_idx: usize) -> Box<dyn QueueNotifier>;

    /// Returns an [`EventFd`] that can be read to be notified of request completions in the queue.
    fn get_completion_fd(&self, queue_idx: usize) -> Arc<EventFd>;
}

/// A trait for types that can be used to submit available buffer notifications to a queue.
pub trait QueueNotifier: Send + Sync {
    /// Trigger an available buffer notification.
    fn notify(&self) -> Result<(), Error>;
}
