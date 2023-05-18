// SPDX-License-Identifier: (MIT OR Apache-2.0)

//! A PCI transport.
//!
//! TODO: Possibly support in the future:
//!   - Legacy devices.
//!   - INTx, for when device does not support MSI-X.
//!   - Cases where fewer than #queues MSI-X interrupts are available, which would require sharing
//!     vectors among queues.

use crate::virtqueue::{Virtqueue, VirtqueueLayout};
use crate::{
    ByteValued, EventFd, EventfdFlags, Iova, IovaSpace, IovaTranslator, QueueNotifier,
    VirtioFeatureFlags, VirtioTransport,
};
use pci_driver::config::caps::{CapabilityHeader, VendorSpecificCapability};
use pci_driver::device::PciDevice;
use pci_driver::regions::structured::{
    PciBitFieldReadable, PciBitFieldWriteable, PciRegisterRo, PciRegisterRw,
};
use pci_driver::regions::{BackedByPciSubregion, PciRegion, Permissions};
use pci_driver::{pci_bit_field, pci_struct};
use std::alloc::{self, Layout};
use std::io::{self, ErrorKind};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::{iter, slice, thread};

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

pci_struct! {
    struct VirtioPciCap<'a> {
        header   @ 0x00 : CapabilityHeader<'a>,
        cfg_type @ 0x03 : PciRegisterRo<'a, u8>,
        bar      @ 0x04 : PciRegisterRo<'a, u8>,
        offset   @ 0x08 : PciRegisterRo<'a, u32>,
        length   @ 0x0c : PciRegisterRo<'a, u32>,
    }

    struct VirtioPciNotifyCap<'a> {
        cap                   @ 0x00 : VirtioPciCap<'a>,
        notify_off_multiplier @ 0x10 : PciRegisterRo<'a, u32>,
    }

    struct VirtioPciCommonCfg<'a> {
        // about the whole device
        device_feature_select @ 0x00 : PciRegisterRw<'a, u32>,
        device_feature        @ 0x04 : PciRegisterRo<'a, u32>,
        driver_feature_select @ 0x08 : PciRegisterRw<'a, u32>,
        driver_feature        @ 0x0c : PciRegisterRw<'a, u32>,
        msix_config           @ 0x10 : PciRegisterRw<'a, u16>,
        num_queues            @ 0x12 : PciRegisterRo<'a, u16>,
        device_status         @ 0x14 : VirtioPciDeviceStatus<'a>,
        config_generation     @ 0x15 : PciRegisterRo<'a, u8>,

        // about a specific virtqueue
        queue_select          @ 0x16 : PciRegisterRw<'a, u16>,
        queue_size            @ 0x18 : PciRegisterRw<'a, u16>,
        queue_msix_vector     @ 0x1a : PciRegisterRw<'a, u16>,
        queue_enable          @ 0x1c : PciRegisterRw<'a, u16>,
        queue_notify_off      @ 0x1e : PciRegisterRo<'a, u16>,
        queue_desc_lower      @ 0x20 : PciRegisterRw<'a, u32>,
        queue_desc_upper      @ 0x24 : PciRegisterRw<'a, u32>,
        queue_driver_lower    @ 0x28 : PciRegisterRw<'a, u32>,
        queue_driver_upper    @ 0x2c : PciRegisterRw<'a, u32>,
        queue_device_lower    @ 0x30 : PciRegisterRw<'a, u32>,
        queue_device_upper    @ 0x34 : PciRegisterRw<'a, u32>,
    }
}

pci_bit_field! {
    struct VirtioPciDeviceStatus<'a> : RW u8 {
        acknowledge        @ 0 : RW,
        driver             @ 1 : RW,
        driver_ok          @ 2 : RW,
        features_ok        @ 3 : RW,
        device_needs_reset @ 6 : RW,
        failed             @ 7 : RW,
    }
}

fn validate_vendor_id_and_device_id(device: &dyn PciDevice) -> io::Result<()> {
    let vendor_id = device.config().vendor_id().read()?;
    let device_id = device.config().device_id().read()?;

    if vendor_id != 0x1af4 {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("Expected Vendor ID 0x1af4, got 0x{:04x}", vendor_id),
        ));
    }

    // Device IDs 0x1000 through 0x103f are "transitional", but the virtio 1.1 spec _appears_ to
    // allow non-transitional devices to use these as well.

    if !(0x1000..=0x107f).contains(&device_id) {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!(
                "Expected Device ID between 0x1000 and 0x107f (inclusive), got 0x{:04x}",
                device_id
            ),
        ));
    }

    Ok(())
}

/// Same as [`get_optional_virtio_cap`], but fails if there is no match.
fn get_virtio_cap<'a>(
    all_virtio_caps: &[VirtioPciCap<'a>],
    cfg_type: u8,
) -> io::Result<VirtioPciCap<'a>> {
    let cap_option = get_optional_virtio_cap(all_virtio_caps, cfg_type)?;

    cap_option.ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "Could not find vendor-specific PCI capability with type {}",
                cfg_type
            ),
        )
    })
}

/// Returns the first [`VirtioPciCap`] in `all_virtio_caps` with the given `cfg_type`, or `None` if
/// none match.
fn get_optional_virtio_cap<'a>(
    all_virtio_caps: &[VirtioPciCap<'a>],
    cfg_type: u8,
) -> io::Result<Option<VirtioPciCap<'a>>> {
    // There may be more than one cap of each type, and the spec says "The driver SHOULD use
    // the first instance of each virtio structure type they can support."
    for cap in all_virtio_caps {
        let cap_cfg_type = cap.cfg_type().read()?;
        let cap_bar = cap.bar().read()?;

        // virtio 1.1 spec, section 4.1.4.1: "The driver MUST ignore any vendor-specific
        // capability structure which has a reserved bar value."
        if cap_cfg_type == cfg_type && cap_bar <= 0x05 {
            return Ok(Some(*cap));
        }
    }

    Ok(None)
}

/// Finds the BAR region corresponding to the given `VirtioPciCap`, maps it if it is mappable, and
/// returns it.
fn get_virtio_struct_region(
    device: &dyn PciDevice,
    cap: &VirtioPciCap,
    permissions: Permissions,
) -> io::Result<Box<dyn PciRegion>> {
    let bar_index = cap.bar().read()? as usize;
    let offset = cap.offset().read()? as u64;
    let length = cap.length().read()? as u64;

    let range = offset..offset + length;

    let bar = device.bar(bar_index).ok_or_else(|| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "virtio device-specific configuration structure points to nonexistent BAR {}",
                bar_index
            ),
        )
    })?;

    // Mapping isn't strictly necessary (we could just use the "unmapped" subregion), but it
    // might make things faster.
    let subregion: Box<dyn PciRegion> = if bar.is_mappable() {
        Box::new(bar.map(range, permissions)?)
    } else {
        Box::new(bar.owning_subregion(range))
    };

    Ok(subregion)
}

fn reset_device(common_cfg: &VirtioPciCommonCfg) -> io::Result<()> {
    const TIMEOUT: Duration = Duration::from_secs(5);

    common_cfg.device_status().write(0)?;

    let start = Instant::now();

    while common_cfg.device_status().read()? != 0 {
        if Instant::now() - start > TIMEOUT {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "Device reset incomplete after {} seconds",
                    TIMEOUT.as_secs()
                ),
            ));
        }

        thread::yield_now();
    }

    Ok(())
}

/// Gets device features, negotiates against driver features, and returns resulting features.
fn negotiate_features(common_cfg: &VirtioPciCommonCfg, driver_features: u64) -> io::Result<u64> {
    // Get device features

    let device_features = {
        common_cfg.device_feature_select().write(0x0)?;
        let lower: u64 = common_cfg.device_feature().read()?.into();

        common_cfg.device_feature_select().write(0x1)?;
        let upper: u64 = common_cfg.device_feature().read()?.into();

        (upper << 32) | lower
    };

    if device_features & VirtioFeatureFlags::VERSION_1.bits() == 0 {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Device must support feature VIRTIO_F_VERSION_1",
        ));
    }

    // Negotiate features

    let driver_features = driver_features
        | (VirtioFeatureFlags::VERSION_1
            | VirtioFeatureFlags::RING_PACKED
            | VirtioFeatureFlags::ACCESS_PLATFORM
            | VirtioFeatureFlags::ORDER_PLATFORM)
            .bits();

    let negotiated_features = device_features & driver_features;

    {
        let lower = negotiated_features & 0xffffffff;
        let upper = negotiated_features >> 32;

        common_cfg.driver_feature_select().write(0x0)?;
        common_cfg.driver_feature().write(lower as u32)?;

        common_cfg.driver_feature_select().write(0x1)?;
        common_cfg.driver_feature().write(upper as u32)?;
    }

    // Returned negotiated features

    Ok(negotiated_features)
}

/// The transport for a PCI virtio device.
///
/// Type parameters `C` and `R` have the same meaning as in [`VirtioTransport`].
pub struct Pci<C: ByteValued, R: Copy> {
    device: Arc<dyn PciDevice>,
    negotiated_features: u64,

    // These regions correspond to ranges in BARs which may or may not be memory-mapped.
    common_cfg_region: Arc<dyn PciRegion>,
    notification_region: Arc<dyn PciRegion>,
    device_cfg_region: Option<Box<dyn PciRegion>>,

    max_queues: usize,
    queue_notify_offsets: Box<[u64]>,
    queue_memory: Option<(*mut u8, Layout)>,
    queue_completion_fds: Option<Box<[Arc<EventFd>]>>,

    iova_space: Arc<RwLock<IovaSpace>>,

    phantom: PhantomData<(C, R)>,
}

// `Send` and `Sync` are not implemented automatically due to the pointer in `queue_memory` and the
// `phantom` field.
unsafe impl<C: ByteValued, R: Copy> Send for Pci<C, R> {}
unsafe impl<C: ByteValued, R: Copy> Sync for Pci<C, R> {}

impl<C: ByteValued, R: Copy> Pci<C, R> {
    /// `driver_features` will be OR'd with VIRTIO_F_VERSION_1, VIRTIO_F_ACCESS_PLATFORM, and
    /// VIRTIO_F_ORDER_PLATFORM.
    pub fn new(device: Arc<dyn PciDevice>, driver_features: u64) -> io::Result<Self> {
        validate_vendor_id_and_device_id(&*device)?;

        let all_virtio_caps: Box<[_]> = device
            .config()
            .capabilities()?
            .of_type::<VendorSpecificCapability>()?
            .map(VirtioPciCap::backed_by)
            .collect();

        if all_virtio_caps.is_empty() {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Device has no vendor-specific PCI capabilities; is this a legacy device?",
            ));
        }

        let common_cfg_region = {
            let cap = get_virtio_cap(&all_virtio_caps, VIRTIO_PCI_CAP_COMMON_CFG)?;
            let region = get_virtio_struct_region(&*device, &cap, Permissions::ReadWrite)?;
            Arc::from(region)
        };
        let common_cfg = VirtioPciCommonCfg::backed_by(&*common_cfg_region);

        reset_device(&common_cfg)?;
        device.config().command().bus_master_enable().write(true)?;

        let result = Pci::new_inner(
            Arc::clone(&device),
            driver_features,
            &all_virtio_caps,
            Arc::clone(&common_cfg_region),
        );

        if result.is_err() {
            // virtio 1.1 spec section 3.1.1: "[...] the driver SHOULD set the FAILED status bit to
            // indicate that it has given up on the device [...]"
            let _ = common_cfg.device_status().failed().write(true);
        }

        result
    }

    fn new_inner(
        device: Arc<dyn PciDevice>,
        driver_features: u64,
        all_virtio_caps: &[VirtioPciCap],
        common_cfg_region: Arc<dyn PciRegion>,
    ) -> io::Result<Self> {
        let common_cfg = VirtioPciCommonCfg::backed_by(&*common_cfg_region);

        // some initialization steps (virtio 1.1 spec section 3.1.1)

        common_cfg.device_status().acknowledge().write(true)?;
        common_cfg.device_status().driver().write(true)?;

        let negotiated_features = negotiate_features(&common_cfg, driver_features)?;

        common_cfg.device_status().features_ok().write(true)?;

        // Must read bit after setting to ensure it's still set, cf. virtio 1.1 spec section 3.1.1.
        if !common_cfg.device_status().features_ok().read()? {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Device rejected negotiated features",
            ));
        }

        let max_queues = common_cfg.num_queues().read()? as usize;

        // Notification things

        let notification_region;
        let queue_notify_offsets;

        {
            if device.interrupts().msi_x().max() == 0 {
                return Err(io::Error::new(
                    ErrorKind::Other,
                    "Device does not support MSI-X",
                ));
            }

            // Get notification region

            let cap = get_virtio_cap(all_virtio_caps, VIRTIO_PCI_CAP_NOTIFY_CFG)?;
            notification_region = Arc::from(get_virtio_struct_region(
                &*device,
                &cap,
                Permissions::Write,
            )?);

            // Compute queue notification offsets

            let notify_off_multiplier = VirtioPciNotifyCap::backed_by(cap)
                .notify_off_multiplier()
                .read()?;

            queue_notify_offsets = (0..common_cfg.num_queues().read()?)
                .map(|i| {
                    common_cfg.queue_select().write(i)?;
                    let offset = common_cfg.queue_notify_off().read()?;
                    Ok(offset as u64 * notify_off_multiplier as u64)
                })
                .collect::<io::Result<_>>()?;
        }

        // Device-specific config things

        let device_cfg_region =
            match get_optional_virtio_cap(all_virtio_caps, VIRTIO_PCI_CAP_DEVICE_CFG)? {
                Some(cap) => Some(get_virtio_struct_region(&*device, &cap, Permissions::Read)?),
                None => None,
            };

        // Return things

        let iova_space = IovaSpace::new(
            device
                .iommu()
                .valid_iova_ranges()
                .iter()
                .map(|r| Iova(r.start)..=Iova(r.end - 1)),
        );

        Ok(Pci {
            device,
            negotiated_features,
            common_cfg_region,
            notification_region,
            device_cfg_region,
            max_queues,
            queue_notify_offsets,
            queue_memory: None,
            queue_completion_fds: None,
            iova_space: Arc::new(RwLock::new(iova_space)),
            phantom: PhantomData,
        })
    }

    fn setup_queues_inner(&mut self, queues: &[Virtqueue<R>]) -> io::Result<()> {
        let common_cfg = VirtioPciCommonCfg::backed_by(&*self.common_cfg_region);

        for (i, queue) in queues.iter().enumerate() {
            common_cfg.queue_select().write(i as u16)?;

            let max_queue_size = common_cfg.queue_size().read()?;
            if queue.queue_size() > max_queue_size {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "Trying to set up queue with {} descriptors, maximum is {}",
                        queue.queue_size(),
                        max_queue_size
                    ),
                ));
            }

            common_cfg.queue_size().write(queue.queue_size())?;
            common_cfg.queue_msix_vector().write(i as u16)?;

            let queue_layout = queue.layout();

            self.set_64_bit_iova_register(
                queue.desc_table_ptr(),
                queue_layout.driver_area_offset,
                common_cfg.queue_desc_lower(),
                common_cfg.queue_desc_upper(),
            )?;

            self.set_64_bit_iova_register(
                queue.driver_area_ptr(),
                queue_layout.device_area_offset - queue_layout.driver_area_offset,
                common_cfg.queue_driver_lower(),
                common_cfg.queue_driver_upper(),
            )?;

            self.set_64_bit_iova_register(
                queue.device_area_ptr(),
                queue_layout.req_offset - queue_layout.device_area_offset,
                common_cfg.queue_device_lower(),
                common_cfg.queue_device_upper(),
            )?;

            common_cfg.queue_enable().write(1)?;
        }

        // enable interrupts

        let completion_fds: Box<[_]> =
            iter::repeat_with(|| Ok(Arc::new(EventFd::new(EventfdFlags::CLOEXEC)?)))
                .take(queues.len())
                .collect::<io::Result<_>>()?;

        let raw_completion_fds: Box<[_]> = completion_fds.iter().map(|fd| fd.as_raw_fd()).collect();

        self.device
            .interrupts()
            .msi_x()
            .enable(&raw_completion_fds)?;

        // DRIVER_OK

        common_cfg.device_status().driver_ok().write(true)?;

        // success

        self.queue_completion_fds = Some(completion_fds);

        Ok(())
    }

    // Set two 32-bit registers that together make up a single 64-bit value.
    fn set_64_bit_iova_register(
        &self,
        process_address: *const u8,
        len: usize,
        lower_register: PciRegisterRw<u32>,
        upper_register: PciRegisterRw<u32>,
    ) -> io::Result<()> {
        let Iova(iova) = self
            .iova_space
            .read()
            .unwrap()
            .translate(process_address as usize, len)
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "TODO"))?;

        let lower = iova & 0xffffffff;
        let upper = iova >> 32;

        lower_register.write(lower as u32)?;
        upper_register.write(upper as u32)?;

        Ok(())
    }
}

impl<C: ByteValued, R: Copy> Drop for Pci<C, R> {
    fn drop(&mut self) {
        if let Some((mem, mem_layout)) = self.queue_memory {
            let _ = self.unmap_mem_region(mem as usize, mem_layout.size());
            unsafe { alloc::dealloc(mem, mem_layout) };
        }

        // We try our best here to ensure that the device stops accessing/modifying user buffers in
        // descriptors that have been made available but not yet used (i.e., in-flight requests).

        let _ = self
            .device
            .config()
            .command()
            .bus_master_enable()
            .write(false);

        if self.device.reset().is_err() {
            // Generic PCI device reset failed/unsupported, try virtio-specific reset method.
            let common_cfg = VirtioPciCommonCfg::backed_by(&*self.common_cfg_region);
            let _ = reset_device(&common_cfg);
        }
    }
}

impl<C: ByteValued, R: Copy> VirtioTransport<C, R> for Pci<C, R> {
    fn max_queues(&self) -> Option<usize> {
        Some(self.max_queues)
    }

    fn max_mem_regions(&self) -> u64 {
        self.device.iommu().max_num_mappings().into()
    }

    fn mem_region_alignment(&self) -> usize {
        self.device.iommu().alignment()
    }

    fn alloc_queue_mem(&mut self, layout: &VirtqueueLayout) -> io::Result<&mut [u8]> {
        if self.queue_memory.is_some() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Memory is already allocated",
            ));
        }

        let alignment = self.mem_region_alignment();

        // TODO This assumes that all virtqueues have the same queue_size
        let mem_size = layout
            .num_queues
            .checked_mul(layout.end_offset)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "Queue is too large"))?;

        let mem_size = ((mem_size + alignment - 1) / alignment) * alignment;
        let mem_layout = Layout::from_size_align(mem_size, alignment).unwrap();

        let mem = unsafe { alloc::alloc_zeroed(mem_layout) };
        if mem.is_null() {
            alloc::handle_alloc_error(mem_layout);
        }

        if let Err(err) = self.map_mem_region(mem as usize, mem_size, -1, -1) {
            unsafe { alloc::dealloc(mem, mem_layout) };
            return Err(err);
        }

        self.queue_memory = Some((mem, mem_layout));

        Ok(unsafe { slice::from_raw_parts_mut(mem, mem_size) })
    }

    fn map_mem_region(
        &mut self,
        addr: usize,
        len: usize,
        _fd: RawFd,
        _fd_offset: i64,
    ) -> io::Result<Iova> {
        let mut iova_space = self.iova_space.write().unwrap();

        let iova = iova_space.allocate(addr, len)?;

        let result = unsafe {
            self.device
                .iommu()
                .map(iova.0, len, addr as *const u8, Permissions::ReadWrite)
        };

        match result {
            Ok(()) => Ok(iova),
            Err(e) => {
                iova_space.free(addr, len);
                Err(e)
            }
        }
    }

    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> io::Result<()> {
        let mut iova_space = self.iova_space.write().unwrap();

        let Iova(iova) = iova_space.translate(addr, len).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Address range [{:#x}, {:#x}) is not mapped",
                    addr,
                    addr + len
                ),
            )
        })?;

        self.device.iommu().unmap(iova, len)?;
        iova_space.free(addr, len);

        Ok(())
    }

    fn iova_translator(&self) -> Box<dyn IovaTranslator> {
        #[derive(Clone)]
        struct PciIovaTranslator {
            iova_space: Arc<RwLock<IovaSpace>>,
        }

        impl IovaTranslator for PciIovaTranslator {
            fn translate_addr(&self, addr: usize, len: usize) -> io::Result<Iova> {
                self.iova_space
                    .read()
                    .unwrap()
                    .translate(addr, len)
                    .ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            format!("Trying to translate unmapped address {} into an IOVA", addr),
                        )
                    })
            }
        }

        Box::new(PciIovaTranslator {
            iova_space: Arc::clone(&self.iova_space),
        })
    }

    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> io::Result<()> {
        // TODO: Assuming here that the current method is never called twice. We should really
        // somehow use the type system to enforce this.

        if queues.len() > self.max_queues {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Device allows up to {} queues, requested to set up {}",
                    self.max_queues,
                    queues.len()
                ),
            ));
        }

        let max_vectors = self.device.interrupts().msi_x().max();
        if max_vectors < queues.len() {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!(
                    "Device allow using at most {} MSI-X vectors, need {}",
                    max_vectors,
                    queues.len()
                ),
            ));
        }

        let result = self.setup_queues_inner(queues);

        if result.is_err() {
            let common_cfg = VirtioPciCommonCfg::backed_by(&*self.common_cfg_region);
            let _ = common_cfg.device_status().failed().write(true);
        }

        result
    }

    fn get_features(&self) -> u64 {
        self.negotiated_features
    }

    fn get_config(&self) -> io::Result<C> {
        let region = self.device_cfg_region.as_ref().ok_or_else(|| {
            io::Error::new(
                ErrorKind::Other,
                "Device has no device-specific configuration",
            )
        })?;

        let layout = Layout::new::<C>();

        if layout.size() as u64 > region.len() {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Not enough bytes for the given config type",
            ));
        }

        let mem = unsafe { alloc::alloc(layout) };
        if mem.is_null() {
            alloc::handle_alloc_error(layout);
        }

        let result = {
            let slice = unsafe { slice::from_raw_parts_mut(mem, layout.size()) };
            match region.read_bytes(0, slice) {
                Ok(()) => Ok(*C::from_slice(slice).unwrap()),
                Err(e) => Err(e),
            }
        };

        unsafe { alloc::dealloc(mem, layout) };

        result
    }

    fn get_submission_notifier(&self, queue_idx: usize) -> Box<dyn QueueNotifier> {
        Box::new(PciNotifier {
            region: Arc::clone(&self.notification_region),
            offset: self.queue_notify_offsets[queue_idx],
            queue_idx: queue_idx as u16,
        })
    }

    fn get_completion_fd(&self, queue_idx: usize) -> Arc<EventFd> {
        Arc::clone(&self.queue_completion_fds.as_ref().unwrap()[queue_idx])
    }
}

#[derive(Debug)]
struct PciNotifier {
    region: Arc<dyn PciRegion>,
    offset: u64,
    queue_idx: u16,
}

impl QueueNotifier for PciNotifier {
    fn notify(&self) -> io::Result<()> {
        // TODO: This breaks spec if called before DRIVER_OK is set. Really should make the type
        // system prevent this kind of thing.
        self.region.write_le_u16(self.offset, self.queue_idx)
    }
}
