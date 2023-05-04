// SPDX-License-Identifier: (MIT OR Apache-2.0)

//! A virtqueue implementation to be used internally by virtio device drivers.

mod packed;
mod split;

use crate::{Iova, IovaTranslator, Le16, VirtioFeatureFlags};
use bitflags::bitflags;
use libc::iovec;
use packed::VirtqueuePacked;
use split::VirtqueueSplit;
use std::io::{Error, ErrorKind};
use std::mem;

bitflags! {
    struct VirtqueueDescriptorFlags: u16 {
        const NEXT = 0x1;
        const WRITE = 0x2;
        const INDIRECT = 0x4;
    }
}

/// A description how the memory passed for each virtqueue is split into individual regions.
///
/// * The Virtqueue Descriptor Area starts from offset 0
/// * The Virtqueue Driver Area (Available Ring for split virtqueue) starts at `driver_area_offset`
/// * The Virtqueue Device Area (Used Ring for split virtqueue) starts at `device_area_offset`
/// * Driver-specific per request data that needs to be shared with the device (e.g. request
///   headers or status bytes) start at `req_offset`
pub struct VirtqueueLayout {
    pub num_queues: usize,
    pub driver_area_offset: usize,
    pub device_area_offset: usize,
    pub req_offset: usize,
    pub end_offset: usize,
}

impl VirtqueueLayout {
    pub fn new<R>(
        num_queues: usize,
        queue_size: usize,
        features: VirtioFeatureFlags,
    ) -> Result<Self, Error> {
        if features.contains(VirtioFeatureFlags::RING_PACKED) {
            let desc_bytes = mem::size_of::<packed::VirtqueueDescriptor>() * queue_size;
            let event_suppress_bytes = mem::size_of::<packed::VirtqueueEventSuppress>();

            Self::new_layout::<R>(
                num_queues,
                queue_size,
                desc_bytes,
                event_suppress_bytes,
                event_suppress_bytes,
            )
        } else {
            let desc_bytes = mem::size_of::<split::VirtqueueDescriptor>() * queue_size;
            let avail_bytes = 8 + mem::size_of::<Le16>() * queue_size;
            let used_bytes = 8 + mem::size_of::<split::VirtqueueUsedElem>() * queue_size;

            // Check queue size requirements (see 2.6 in the VIRTIO 1.1 spec)
            if !queue_size.is_power_of_two() || queue_size > 32768 {
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid queue size"));
            }

            // The used ring requires an alignment of 4 (see 2.6 in the VIRTIO 1.1 spec)
            let avail_bytes = (avail_bytes + 3) & !0x3;

            Self::new_layout::<R>(num_queues, queue_size, desc_bytes, avail_bytes, used_bytes)
        }
    }

    fn new_layout<R>(
        num_queues: usize,
        queue_size: usize,
        desc_bytes: usize,
        driver_area_bytes: usize,
        device_area_bytes: usize,
    ) -> Result<Self, Error> {
        let req_bytes = mem::size_of::<R>() * queue_size;

        // Consider the required alignment of R
        let req_align = mem::align_of::<R>();
        let req_offset = desc_bytes + driver_area_bytes + device_area_bytes;
        let req_offset_aligned = (req_offset + req_align - 1) & !(req_align - 1);

        // Maintain 16-byte descriptor table alignment (see 2.7 in the VIRTIO 1.1 spec) in
        // contiguous virtqueue arrays (useful for allocating memory for several queues at once)
        let end_offset = (req_offset_aligned + req_bytes + 15) & !15;

        Ok(VirtqueueLayout {
            num_queues,
            driver_area_offset: desc_bytes,
            device_area_offset: desc_bytes + driver_area_bytes,
            req_offset: req_offset_aligned,
            end_offset,
        })
    }
}

/// An interface for the virtqueue formats supported by VIRTIO specification.
trait VirtqueueFormat {
    /// Returns the number of entries of the descriptor table.
    fn queue_size(&self) -> u16;

    /// Returns a raw pointer to the start of the descriptor table.
    fn desc_table_ptr(&self) -> *const u8;

    /// Returns a raw pointer to the start of the device area.
    fn driver_area_ptr(&self) -> *const u8;

    /// Returns a raw pointer to the start of the driver area.
    fn device_area_ptr(&self) -> *const u8;

    /// Returns an identifier for the next chain of the available descriptor.
    fn avail_start_chain(&mut self) -> Option<u16>;

    /// Rewinds the last chain if there were any errors during building.
    ///
    /// `chain_id` is the identifier returned by `avail_start_chain()`.
    fn avail_rewind_chain(&mut self, chain_id: u16);

    /// Add a descriptor to the current chain and return its index in
    /// the descriptor table.
    fn avail_add_desc_chain(
        &mut self,
        addr: u64,
        len: u32,
        flags: VirtqueueDescriptorFlags,
    ) -> Result<u16, Error>;

    /// Expose the available descriptor chain to the device.
    ///
    /// `chain_id` is the identifier returned by `avail_start_chain()`.
    /// `last_desc_idx` is the index returned by avail_add_desc_chain() of the
    /// last descriptor added in the chain.
    fn avail_publish(&mut self, chain_id: u16, last_desc_idx: u16);

    /// Returns `true` if there are used chains available.
    fn used_has_next(&self) -> bool;

    /// Returns the identifier of a chain used by the device.
    fn used_next(&mut self) -> Option<u16>;

    /// Returns lower and upper bound of used chains.
    fn used_size_hint(&self) -> (usize, Option<usize>);

    /// Returns `true` if the avail notifications are needed.
    fn avail_notif_needed(&mut self) -> bool;

    /// Enable or disable used notifications.
    fn set_used_notif_enabled(&mut self, enabled: bool);
}

/// A virtqueue of a virtio device.
///
/// `R` is used to store device-specific per-request data (like the request header or status byte)
/// in memory shared with the device and is copied on completion. Don't put things there that the
/// device doesn't have to access, in the interest of both security and performance.
pub struct Virtqueue<'a, R: Copy> {
    iova_translator: Box<dyn IovaTranslator>,
    format: Box<dyn VirtqueueFormat + 'a>,
    req: *mut R,
    layout: VirtqueueLayout,
}

// `Send` and `Sync` are not implemented automatically due to the `avail`, `used`, and `req` fields.
unsafe impl<R: Copy> Send for Virtqueue<'_, R> {}
unsafe impl<R: Copy> Sync for Virtqueue<'_, R> {}

/// The result of a completed request
pub struct VirtqueueCompletion<R> {
    /// The identifier of the descriptors chain for the request as returned by [`add_request`].
    ///
    /// [`add_request`]: Virtqueue::add_request
    pub id: u16,

    /// Device-specific per-request data like the request header or status byte.
    pub req: R,
}

impl<'a, R: Copy> Virtqueue<'a, R> {
    /// Creates a new virtqueue in the passed memory buffer.
    ///
    /// `buf` has to be memory that is visible for the device. It is used to store all descriptors,
    /// rings and device-specific per-request data for the queue.
    pub fn new(
        iova_translator: Box<dyn IovaTranslator>,
        buf: &'a mut [u8],
        queue_size: u16,
        features: VirtioFeatureFlags,
    ) -> Result<Self, Error> {
        let layout = VirtqueueLayout::new::<R>(1, queue_size as usize, features)?;
        let event_idx_enabled = features.contains(VirtioFeatureFlags::RING_EVENT_IDX);
        let (format, req_mem) = if features.contains(VirtioFeatureFlags::RING_PACKED) {
            let mem = buf.get_mut(0..layout.end_offset).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "Incorrectly sized queue bu
fer",
                )
            })?;

            let (mem, req_mem) = mem.split_at_mut(layout.req_offset);
            let (mem, device_es_mem) = mem.split_at_mut(layout.device_area_offset);
            let (desc_mem, driver_es_mem) = mem.split_at_mut(layout.driver_area_offset);

            let format: Box<dyn VirtqueueFormat + 'a> = Box::new(VirtqueuePacked::new(
                desc_mem,
                driver_es_mem,
                device_es_mem,
                queue_size,
                event_idx_enabled,
            )?);

            (format, req_mem)
        } else {
            let mem = buf.get_mut(0..layout.end_offset).ok_or_else(|| {
                Error::new(ErrorKind::InvalidInput, "Incorrectly sized queue buffer")
            })?;

            let (mem, req_mem) = mem.split_at_mut(layout.req_offset);
            let (mem, used_mem) = mem.split_at_mut(layout.device_area_offset);
            let (desc_mem, avail_mem) = mem.split_at_mut(layout.driver_area_offset);

            let format: Box<dyn VirtqueueFormat + 'a> = Box::new(VirtqueueSplit::new(
                avail_mem,
                used_mem,
                desc_mem,
                queue_size,
                event_idx_enabled,
            )?);

            (format, req_mem)
        };

        let req = req_mem.as_mut_ptr() as *mut R;
        if req.align_offset(mem::align_of::<R>()) != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Insufficient memory alignment",
            ));
        }

        Ok(Virtqueue {
            iova_translator,
            format,
            req,
            layout,
        })
    }

    /// Returns the number of entries in each of the descriptor table and rings.
    pub fn queue_size(&self) -> u16 {
        self.format.queue_size()
    }

    /// Returns the virtqueue memory layout.
    pub fn layout(&self) -> &VirtqueueLayout {
        &self.layout
    }

    /// Returns a raw pointer to the start of the descriptor table.
    pub fn desc_table_ptr(&self) -> *const u8 {
        self.format.desc_table_ptr()
    }

    /// Returns a raw pointer to the start of the driver area.
    pub fn driver_area_ptr(&self) -> *const u8 {
        self.format.driver_area_ptr()
    }

    /// Returns a raw pointer to the start of the device area.
    pub fn device_area_ptr(&self) -> *const u8 {
        self.format.device_area_ptr()
    }

    /// Enqueues a new request.
    ///
    /// `prepare` is a function or closure that gets a reference to the device-specific per-request
    /// data in its final location in the virtqueue memory and a FnMut to add virtio descriptors to
    /// the request. It can set up the per-request data as necessary and must add all descriptors
    /// needed for the request.
    ///
    /// The parameters of the FnMut it received are the `iovec` describing the buffer to be added
    /// and a boolean `from_dev` that is `true` if this buffer is written by the device and `false`
    /// if it is read by the device.
    pub fn add_request<F>(&mut self, prepare: F) -> Result<u16, Error>
    where
        F: FnOnce(&mut R, &mut dyn FnMut(iovec, bool) -> Result<(), Error>) -> Result<(), Error>,
    {
        let chain_id = match self.format.avail_start_chain() {
            None => {
                return Err(Error::new(ErrorKind::Other, "Not enough free descriptors"));
            }
            Some(idx) => idx,
        };

        let req_ptr = unsafe { &mut *self.req.offset(chain_id as isize) };
        let mut last_desc_idx: Option<u16> = None;

        let res = prepare(req_ptr, &mut |iovec: iovec, from_dev: bool| {
            // Set NEXT for all descriptors, it is unset again below for the last one
            let mut flags = VirtqueueDescriptorFlags::NEXT;
            if from_dev {
                flags.insert(VirtqueueDescriptorFlags::WRITE);
            }
            let Iova(iova) = self
                .iova_translator
                .translate_addr(iovec.iov_base as usize, iovec.iov_len)?;
            last_desc_idx = Some(self.format.avail_add_desc_chain(
                iova,
                iovec.iov_len as u32,
                flags,
            )?);
            Ok(())
        });

        if let Err(e) = res {
            self.format.avail_rewind_chain(chain_id);
            return Err(e);
        }

        self.format.avail_publish(chain_id, last_desc_idx.unwrap());
        Ok(chain_id)
    }

    /// Returns an iterator that returns all completed requests.
    pub fn completions(&mut self) -> VirtqueueIter<'_, 'a, R> {
        VirtqueueIter { virtqueue: self }
    }

    pub fn avail_notif_needed(&mut self) -> bool {
        self.format.avail_notif_needed()
    }

    pub fn set_used_notif_enabled(&mut self, enabled: bool) {
        self.format.set_used_notif_enabled(enabled)
    }
}

/// An iterator that returns all completed requests.
pub struct VirtqueueIter<'a, 'queue, R: Copy> {
    virtqueue: &'a mut Virtqueue<'queue, R>,
}

impl<R: Copy> VirtqueueIter<'_, '_, R> {
    pub fn has_next(&self) -> bool {
        self.virtqueue.format.used_has_next()
    }
}

impl<'a, 'queue, R: Copy> Iterator for VirtqueueIter<'a, 'queue, R> {
    type Item = VirtqueueCompletion<R>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.virtqueue.format.used_next()?;

        let req = unsafe { *self.virtqueue.req.offset(id as isize) };
        Some(VirtqueueCompletion { id, req })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.virtqueue.format.used_size_hint()
    }
}
