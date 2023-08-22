// SPDX-License-Identifier: (MIT OR Apache-2.0)
use crate::virtqueue::{VirtqueueDescriptorFlags, VirtqueueFormat};
use crate::{Le16, Le32, Le64};
use bitflags::bitflags;
use std::io::{Error, ErrorKind};
use std::mem;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};

/// This is `struct pvirtq_desc` from the VIRTIO 1.2 specification (see 2.8.13).
#[repr(C)]
pub struct VirtqueueDescriptor {
    addr: Le64,
    len: Le32,
    id: Le16,
    flags: Le16,
}

bitflags! {
    struct VirtqueuePackedDescriptorFlags: u16 {
        const AVAIL = 1 << 7;
        const USED = 1 << 15;
    }
}

/// This is `struct pvirtq_event_suppress` from the VIRTIO 1.2 specification (see 2.8.14).
#[repr(C)]
pub struct VirtqueueEventSuppress {
    off_wrap: Le16,
    flags: Le16,
}

/// Wrap counter bit shift in event suppression structure of packed ring.
const VRING_PACKED_EVENT_F_WRAP_CTR: usize = 15;

bitflags! {
    /// These are `RING_EVENT_FLAGS_*` from VIRTIO 1.2 specification
    /// (see 2.8.10).
    ///
    /// /* Enable events */
    /// #define RING_EVENT_FLAGS_ENABLE 0x0
    /// /* Disable events */
    /// #define RING_EVENT_FLAGS_DISABLE 0x1
    /// /*
    ///  * Enable events for a specific descriptor
    ///  * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
    ///  * Only valid if VIRTIO_F_EVENT_IDX has been negotiated.
    ///  */
    /// #define RING_EVENT_FLAGS_DESC 0x2
    /// /* The value 0x3 is reserved */
    ///
    struct VirtqueueEventSuppressFlags: u16 {
        const EVENT_DISABLE = 0x01;
        const EVENT_DESC = 0x02;
    }
}

/// Available descriptor state
#[derive(Copy, Clone)]
struct Avail {
    /// Number of descriptor added before last notification.
    pending: u16,
    /// flags used to mark descriptor used/available
    /// (see 2.8.1 in VIRTIO 1.2 specification)
    flags: VirtqueuePackedDescriptorFlags,
    /// Index of the next available descriptor.
    next_index: u16,
    /// Driver ring wrap counter.
    wrap_counter: bool,
}

impl Default for Avail {
    fn default() -> Self {
        Avail {
            pending: 0,
            flags: VirtqueuePackedDescriptorFlags::AVAIL,
            next_index: 0,
            wrap_counter: true,
        }
    }
}

#[derive(Copy, Clone, Default)]
struct DescChainState {
    num_desc: u16,
    used_len: u32,
}

/// Descriptor chain state
///
/// For now, these APIs do not support the creation of multiple chains simultaneously.
struct DescChain {
    /// Snapshot of avail state of the first descriptor.
    /// Used to rewind the avail state and to publish the chain.
    first_avail: Avail,
    /// Flags for the first descriptor in the chain.
    /// They must be written as last step to publish the entire chain.
    first_flags: u16,
    /// ID used to track the chain (see "Buffer ID" in section 2.8 in VIRTIO 1.2 specification).
    free_ids: Vec<u16>,
    /// States of each chain. Used to free descriptors when used element is returned by the device.
    states: Vec<DescChainState>,
}

impl DescChain {
    fn new(queue_size: u16) -> Self {
        DescChain {
            first_avail: Avail::default(),
            first_flags: 0,
            free_ids: (0..queue_size).rev().collect(),
            states: vec![Default::default(); queue_size as usize],
        }
    }
}

/// Used descriptor state
#[derive(Copy, Clone)]
struct Used {
    /// Index of the last used descriptor.
    last_index: u16,
    /// Device ring wrap counter.
    wrap_counter: bool,
    /// Notification from the device enabled/disabled for new used descriptors
    notif_enabled: bool,
}

impl Default for Used {
    fn default() -> Self {
        Used {
            last_index: 0,
            wrap_counter: true,
            notif_enabled: false,
        }
    }
}

pub struct VirtqueuePacked<'a> {
    desc: &'a mut [VirtqueueDescriptor],
    driver: &'a mut VirtqueueEventSuppress,
    // `device` area can be written by the device, so we can't use exclusive
    // reference.
    device: *mut VirtqueueEventSuppress,

    queue_size: u16,
    queue_avail: u16,

    avail: Avail,
    desc_chain: DescChain,
    used: Used,

    event_idx_enabled: bool,
}

impl<'a> VirtqueuePacked<'a> {
    pub fn new(
        desc_mem: &'a mut [u8],
        driver_es_mem: &'a mut [u8],
        device_es_mem: &'a mut [u8],
        queue_size: u16,
        event_idx_enabled: bool,
    ) -> Result<Self, Error> {
        let desc_ptr = desc_mem.as_mut_ptr();
        // 16 bytes alignment requirement from section 2.8.10.1
        // "Structure Size and Alignment" in VIRTIO 1.2 specification
        assert_eq!(desc_ptr.align_offset(16), 0);
        assert!(desc_mem.len() >= queue_size as usize * mem::size_of::<VirtqueueDescriptor>());
        // SAFETY: Safe because we just checked the size and alignment
        let desc: &mut [VirtqueueDescriptor] = unsafe {
            std::slice::from_raw_parts_mut(
                desc_ptr as *mut VirtqueueDescriptor,
                queue_size as usize,
            )
        };

        let driver_es_ptr = driver_es_mem.as_mut_ptr();
        // 4 bytes alignment requirement from section 2.8.10.1
        // "Structure Size and Alignment" in VIRTIO 1.2 specification
        assert_eq!(driver_es_ptr.align_offset(4), 0);
        assert!(driver_es_mem.len() >= mem::size_of::<VirtqueueEventSuppress>());
        // SAFETY: Safe because we just checked the size and alignment
        let driver = unsafe { &mut *(driver_es_ptr as *mut VirtqueueEventSuppress) };

        let device_es_ptr = device_es_mem.as_mut_ptr();
        // 4 bytes alignment requirement from section 2.8.10.1
        // "Structure Size and Alignment" in VIRTIO 1.2 specification
        assert_eq!(device_es_ptr.align_offset(4), 0);
        assert!(device_es_mem.len() >= mem::size_of::<VirtqueueEventSuppress>());
        // SAFETY: Safe because we just checked the size and alignment
        let device = unsafe { &mut *(device_es_ptr as *mut VirtqueueEventSuppress) };

        Ok(VirtqueuePacked {
            desc,
            driver,
            device,
            queue_size,
            queue_avail: queue_size,
            avail: Avail::default(),
            desc_chain: DescChain::new(queue_size),
            used: Used::default(),
            event_idx_enabled,
        })
    }

    fn last_desc_is_used(&self) -> bool {
        let raw_flags = self.desc[self.used.last_index as usize].flags.into();

        let flags = VirtqueuePackedDescriptorFlags::from_bits_truncate(raw_flags);
        let avail = flags.contains(VirtqueuePackedDescriptorFlags::AVAIL);
        let used = flags.contains(VirtqueuePackedDescriptorFlags::USED);

        avail == used && used == self.used.wrap_counter
    }

    fn update_used_event(&mut self) {
        // 2.8.14 Event Suppression Structure Format
        // le16 {
        //     desc_event_off : 15; /* Descriptor Ring Change Event Offset */
        //     desc_event_wrap : 1; /* Descriptor Ring Change Event Wrap Counter */
        // } desc; /* If desc_event_flags set to RING_EVENT_FLAGS_DESC */
        let off_wrap = if self.used.wrap_counter {
            self.used.last_index | 1 << VRING_PACKED_EVENT_F_WRAP_CTR
        } else {
            self.used.last_index
        };
        self.driver.off_wrap = off_wrap.into();
    }
}

impl<'a> VirtqueueFormat for VirtqueuePacked<'a> {
    fn queue_size(&self) -> u16 {
        self.queue_size
    }

    fn desc_table_ptr(&self) -> *const u8 {
        self.desc.as_ptr() as *const u8
    }

    fn driver_area_ptr(&self) -> *const u8 {
        self.driver as *const VirtqueueEventSuppress as *const u8
    }

    fn device_area_ptr(&self) -> *const u8 {
        self.device as *const VirtqueueEventSuppress as *const u8
    }

    fn avail_add_desc_chain(
        &mut self,
        addr: u64,
        len: u32,
        flags: VirtqueueDescriptorFlags,
    ) -> Result<u16, Error> {
        if self.queue_avail == 0 {
            return Err(Error::new(ErrorKind::Other, "Not enough free descriptors"));
        }

        let index = self.avail.next_index;
        let chain_id = self.desc_chain.free_ids.last().copied().unwrap();
        let desc_flags = flags.bits() | self.avail.flags.bits();

        self.desc[index as usize].addr = addr.into();
        self.desc[index as usize].len = len.into();
        self.desc[index as usize].id = chain_id.into();

        if index == self.desc_chain.first_avail.next_index {
            // We can publish the flags of the first chain descriptor only
            // when the whole chain is ready.
            self.desc_chain.first_flags = desc_flags;
        } else {
            self.desc[index as usize].flags = desc_flags.into();
        }

        self.avail.next_index = if self.avail.next_index == self.queue_size - 1 {
            self.avail.flags ^= VirtqueuePackedDescriptorFlags::all();
            self.avail.wrap_counter = !self.avail.wrap_counter;
            0
        } else {
            self.avail.next_index + 1
        };

        self.queue_avail -= 1;
        self.avail.pending += 1;
        self.desc_chain.states[chain_id as usize].num_desc += 1;
        if flags.contains(VirtqueueDescriptorFlags::WRITE) {
            self.desc_chain.states[chain_id as usize].used_len += len;
        }

        Ok(index)
    }

    fn avail_start_chain(&mut self) -> Option<u16> {
        if self.queue_avail == 0 {
            return None;
        }

        let chain_id = self.desc_chain.free_ids.last().copied().unwrap();

        self.desc_chain.states[chain_id as usize] = DescChainState::default();
        self.desc_chain.first_avail = self.avail;
        self.desc_chain.first_flags = 0;
        Some(chain_id)
    }

    fn avail_rewind_chain(&mut self, chain_id: u16) {
        // We don't support the creation of multiple chains simultaneously.
        assert!(chain_id == self.desc_chain.free_ids.last().copied().unwrap());

        let chain_state = &mut self.desc_chain.states[chain_id as usize];

        self.queue_avail += chain_state.num_desc;
        self.avail = self.desc_chain.first_avail;

        *chain_state = Default::default();
    }

    fn avail_publish(&mut self, chain_id: u16, last_desc_idx: u16) {
        let id = self.desc_chain.free_ids.pop().unwrap();

        // We don't support the creation of multiple chains simultaneously.
        assert!(chain_id == id);

        let mut last_flags: u16 = self.desc[last_desc_idx as usize].flags.into();
        last_flags &= !VirtqueueDescriptorFlags::NEXT.bits();

        self.desc[last_desc_idx as usize].flags = last_flags.into();

        // Make sure that the flags field of the first available descriptor is
        // written after all other fields.
        fence(Ordering::Release);

        self.desc[self.desc_chain.first_avail.next_index as usize].flags =
            self.desc_chain.first_flags.into();
    }

    fn used_has_next(&self) -> bool {
        self.last_desc_is_used()
    }

    fn used_next(&mut self) -> Option<u16> {
        if !self.last_desc_is_used() {
            return None;
        }

        // Make sure that the flags field of the used descriptor is read before
        // all other fields.
        fence(Ordering::Acquire);

        let id = self.desc[self.used.last_index as usize].id.into();
        let used_len: u32 = self.desc[self.used.last_index as usize].len.into();

        let chain_state = &mut self.desc_chain.states[id as usize];
        assert_eq!(chain_state.used_len, used_len);

        self.used.last_index = if self.used.last_index >= self.queue_size - chain_state.num_desc {
            self.used.wrap_counter = !self.used.wrap_counter;
            self.used.last_index - (self.queue_size - chain_state.num_desc)
        } else {
            self.used.last_index + chain_state.num_desc
        };

        self.queue_avail += chain_state.num_desc;
        *chain_state = Default::default();
        self.desc_chain.free_ids.push(id);

        if self.event_idx_enabled && self.used.notif_enabled {
            self.update_used_event();
        }

        Some(id)
    }

    fn used_size_hint(&self) -> (usize, Option<usize>) {
        // With packed virtqueue, we don't have a way to know the exact number
        // of used descriptors, so let's provide a lower and upper bound.
        if self.last_desc_is_used() {
            (
                1,
                Some(self.queue_size as usize - self.desc_chain.free_ids.len()),
            )
        } else {
            (0, Some(0))
        }
    }

    fn avail_notif_needed(&mut self) -> bool {
        // We need to expose the new descriptor flags value before checking
        // notification suppressions.
        fence(Ordering::SeqCst);

        // SAFETY: Safe because we check the `self.device` address and size in `VirtqueuePacked::new()`
        let flags =
            unsafe { VirtqueueEventSuppressFlags::from_bits_truncate((*self.device).flags.into()) };

        if flags.contains(VirtqueueEventSuppressFlags::EVENT_DISABLE) {
            return false;
        }

        if !self.event_idx_enabled || !flags.contains(VirtqueueEventSuppressFlags::EVENT_DESC) {
            return true;
        }

        let new_avail_idx = Wrapping(self.avail.next_index);
        let old_avail_idx = new_avail_idx - Wrapping(self.avail.pending);
        self.avail.pending = 0;

        // SAFETY: Safe because we check the `self.device` address and size in `VirtqueuePacked::new()`
        let off_wrap: u16 = unsafe { (*self.device).off_wrap.into() };
        let wrap_counter: bool = (off_wrap >> VRING_PACKED_EVENT_F_WRAP_CTR) == 1;
        let mut event_idx = Wrapping(off_wrap & !(1 << VRING_PACKED_EVENT_F_WRAP_CTR));

        if wrap_counter != self.avail.wrap_counter {
            event_idx -= Wrapping(self.queue_size);
        }

        new_avail_idx - event_idx - Wrapping(1) < new_avail_idx - old_avail_idx
    }

    fn set_used_notif_enabled(&mut self, enabled: bool) {
        self.used.notif_enabled = enabled;

        self.driver.flags = if enabled {
            if self.event_idx_enabled {
                self.update_used_event();
                VirtqueueEventSuppressFlags::EVENT_DESC.bits().into()
            } else {
                VirtqueueEventSuppressFlags::empty().bits().into()
            }
        } else {
            VirtqueueEventSuppressFlags::EVENT_DISABLE.bits().into()
        };

        // We need to expose the notification suppression flags, before
        // publishing new available descriptors.
        fence(Ordering::SeqCst);
    }
}
