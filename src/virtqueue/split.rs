// SPDX-License-Identifier: (MIT OR Apache-2.0)
use crate::virtqueue::{VirtqueueDescriptorFlags, VirtqueueFormat};
use crate::{Le16, Le32, Le64};
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem;
use std::num::Wrapping;
use std::sync::atomic::{fence, AtomicU16, Ordering};

const NO_FREE_DESC: u16 = 0xffff;

/// This is `struct virtq_desc` from the VIRTIO 1.1 specification (see 2.6.5).
#[repr(C, packed)]
#[allow(dead_code)]
pub struct VirtqueueDescriptor {
    addr: Le64,
    len: Le32,
    flags: Le16,
    next: Le16,
}

/// This is `struct virtq_used_elem` from the VIRTIO 1.1 specification (see 2.6.8).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct VirtqueueUsedElem {
    idx: Le32,
    _len: Le32,
}

/// This can represent (depending on `T`) `struct virtq_avail` or `struct virtq_used` from the
/// VIRTIO 1.1 specification (see 2.6.6 and 2.6.8).
#[repr(C)]
struct VirtqueueRingData<T> {
    flags: AtomicU16,
    idx: AtomicU16,
    ring: [T],
}

/// An implementation for both the available and the used ring.
///
/// Since it supports push and pop for both rings, it is a suitable building block both for drivers
/// and device implementations.
struct VirtqueueRing<'a, T: Clone> {
    ptr: *mut VirtqueueRingData<T>,
    event: *mut AtomicU16,
    _ptr_lifetime: PhantomData<&'a ()>,
    queue_size: usize,
    next_idx: Wrapping<u16>,
}

impl<'a, T: Clone> VirtqueueRing<'a, T> {
    fn new(mem: &'a mut [u8], queue_size: usize) -> Self {
        // See `struct virtq_avail` (2.7.6) and `struct virtq_used` (2.7.8) in the VIRTIO 1.2
        // specification. `flags` and `idx` are Le16 fields (4 bytes in total) that precede the
        // actual ring buffer. `queue_size` is the number of entries in the ring buffer, `event` is
        // used to enable/disable notification when the VIRTIO_F_EVENT_IDX feature is negotiated.
        assert!(mem.len() >= 6 + queue_size * mem::size_of::<T>());

        // VirtqueueRingData is a DST because of the unsized `ring` field. Construct a fat
        // pointer to it by casting a slice pointer.
        let slice_ptr = std::ptr::slice_from_raw_parts_mut(mem.as_mut_ptr(), queue_size);
        let ptr = slice_ptr as *mut VirtqueueRingData<T>;
        let event =
            unsafe { mem.as_mut_ptr().add(4 + queue_size * mem::size_of::<T>()) as *mut AtomicU16 };

        VirtqueueRing {
            ptr,
            event,
            _ptr_lifetime: PhantomData,
            queue_size,
            next_idx: Wrapping(0),
        }
    }

    fn ring_idx(&self) -> usize {
        self.next_idx.0 as usize % self.queue_size
    }

    fn push(&mut self, elem: T) {
        unsafe {
            (*self.ptr).ring[self.ring_idx()] = elem;
        }
        self.next_idx += Wrapping(1);
    }

    fn has_next(&self) -> bool {
        let remote_next_idx = self.load_next_idx();
        remote_next_idx != self.next_idx.0
    }

    fn pop(&mut self) -> Option<T> {
        if self.has_next() {
            let result = unsafe { (*self.ptr).ring[self.ring_idx()].clone() };
            self.next_idx += Wrapping(1);
            Some(result)
        } else {
            None
        }
    }

    fn store_next_idx(&self) {
        unsafe {
            (*self.ptr)
                .idx
                .store(self.next_idx.0.to_le(), Ordering::Release);
        }
    }

    fn store_flags(&self, value: u16) {
        unsafe {
            (*self.ptr).flags.store(value.to_le(), Ordering::Release);
        }
    }

    fn load_next_idx(&self) -> u16 {
        unsafe { u16::from_le((*self.ptr).idx.load(Ordering::Acquire)) }
    }

    fn load_event(&self) -> u16 {
        // Load used.event after storing avail.idx. The device follows the opposite order: load
        // avail.idx after storing used.event. This scheme ensures that the device never misses an
        // available buffer added by the driver.
        fence(Ordering::SeqCst);

        unsafe { u16::from_le((*self.event).load(Ordering::Relaxed)) }
    }

    fn load_flags(&self) -> u16 {
        unsafe { u16::from_le((*self.ptr).flags.load(Ordering::Acquire)) }
    }

    fn num_pending(&self) -> usize {
        let remote_next_idx = self.load_next_idx() as usize;
        let ring_len = self.queue_size;
        (remote_next_idx + ring_len - self.ring_idx()) % ring_len
    }
}

pub struct VirtqueueSplit<'a> {
    queue_size: u16,
    avail: VirtqueueRing<'a, Le16>,
    used: VirtqueueRing<'a, VirtqueueUsedElem>,
    desc: &'a mut [VirtqueueDescriptor],
    first_free_desc: u16,
    event_idx_enabled: bool,

    // Used only when event_idx_enabled is true
    used_notif_enabled: bool,
    old_avail_idx: Wrapping<u16>,
}

impl<'a> VirtqueueSplit<'a> {
    pub fn new(
        avail_mem: &'a mut [u8],
        used_mem: &'a mut [u8],
        desc_mem: &'a mut [u8],
        queue_size: u16,
        event_idx_enabled: bool,
    ) -> Result<Self, Error> {
        let avail = VirtqueueRing::new(avail_mem, queue_size as usize);
        let used = VirtqueueRing::new(used_mem, queue_size as usize);

        let desc: &mut [VirtqueueDescriptor] = unsafe {
            std::slice::from_raw_parts_mut(
                desc_mem.as_mut_ptr() as *mut VirtqueueDescriptor,
                queue_size as usize,
            )
        };
        for i in 0..queue_size - 1 {
            desc[i as usize].next = (i + 1).into();
        }
        desc[(queue_size - 1) as usize].next = NO_FREE_DESC.into();

        Ok(VirtqueueSplit {
            queue_size,
            avail,
            used,
            desc,
            first_free_desc: 0,
            event_idx_enabled,
            used_notif_enabled: false,
            old_avail_idx: Wrapping(0),
        })
    }

    fn free_desc(&mut self, first_idx: u16) {
        let mut idx = first_idx as usize;
        while self.desc[idx].flags.to_native() & VirtqueueDescriptorFlags::NEXT.bits() != 0 {
            idx = self.desc[idx].next.to_native().into();
        }

        self.desc[idx].next = self.first_free_desc.into();
        self.first_free_desc = first_idx;
    }

    fn update_used_event(&self) {
        unsafe { (*self.avail.event).store(self.used.next_idx.0.to_le(), Ordering::Relaxed) };

        // Store avail.event before loading used.idx in has_next(). The device follows the opposite
        // order: store used.idx before loading avail.event. This scheme ensures that the driver
        // never misses a used buffer added by the device.
        fence(Ordering::SeqCst);
    }
}

impl<'a> VirtqueueFormat for VirtqueueSplit<'a> {
    fn queue_size(&self) -> u16 {
        self.queue_size
    }

    fn desc_table_ptr(&self) -> *const u8 {
        self.desc.as_ptr() as *const u8
    }

    fn driver_area_ptr(&self) -> *const u8 {
        self.avail.ptr as *const u8
    }

    fn device_area_ptr(&self) -> *const u8 {
        self.used.ptr as *const u8
    }

    fn avail_add_desc_chain(
        &mut self,
        addr: u64,
        len: u32,
        flags: VirtqueueDescriptorFlags,
    ) -> Result<u16, Error> {
        let idx = self.first_free_desc;
        if idx == NO_FREE_DESC {
            return Err(Error::new(ErrorKind::Other, "Not enough free descriptors"));
        }

        let next_free_desc = self.desc[idx as usize].next;
        self.desc[idx as usize] = VirtqueueDescriptor {
            addr: addr.into(),
            len: len.into(),
            flags: flags.bits().into(),
            next: next_free_desc,
        };
        self.first_free_desc = next_free_desc.into();

        Ok(idx)
    }

    fn avail_start_chain(&mut self) -> Option<u16> {
        match self.first_free_desc {
            NO_FREE_DESC => None,
            idx => Some(idx),
        }
    }

    fn avail_rewind_chain(&mut self, chain_id: u16) {
        self.first_free_desc = chain_id;
    }

    fn avail_publish(&mut self, chain_id: u16, last_desc_idx: u16) {
        let mut last_flags = self.desc[last_desc_idx as usize].flags.to_native();
        last_flags &= !VirtqueueDescriptorFlags::NEXT.bits();
        self.desc[last_desc_idx as usize].flags = last_flags.into();

        assert!(chain_id < self.queue_size);
        self.avail.push(chain_id.into());
        self.avail.store_next_idx();
    }

    fn used_has_next(&self) -> bool {
        self.used.has_next()
    }

    fn used_next(&mut self) -> Option<u16> {
        if let Some(next) = self.used.pop() {
            let idx = (next.idx.to_native() % (self.queue_size as u32)) as u16;
            self.free_desc(idx);
            if self.event_idx_enabled && self.used_notif_enabled {
                self.update_used_event();
            }

            Some(idx)
        } else {
            None
        }
    }

    fn used_size_hint(&self) -> (usize, Option<usize>) {
        let len = self.used.num_pending();
        (len, Some(len))
    }

    fn avail_notif_needed(&mut self) -> bool {
        if self.event_idx_enabled {
            let new_avail_idx = self.avail.next_idx;
            let ret = new_avail_idx - Wrapping(self.used.load_event()) - Wrapping(1)
                < new_avail_idx - self.old_avail_idx;
            self.old_avail_idx = new_avail_idx;
            ret
        } else {
            self.used.load_flags() == 0
        }
    }

    fn set_used_notif_enabled(&mut self, enabled: bool) {
        self.used_notif_enabled = enabled;
        if self.event_idx_enabled {
            self.update_used_event();
        } else {
            self.avail.store_flags(!enabled as u16);
        }
    }
}
