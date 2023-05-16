// SPDX-License-Identifier: (MIT OR Apache-2.0)

mod vhost_bindings;
mod vhost_vdpa_kernel;

use crate::virtqueue::{Virtqueue, VirtqueueLayout};
use crate::{
    ByteValued, EventFd, EventfdFlags, Iova, IovaSpace, IovaTranslator, QueueNotifier,
    VirtioFeatureFlags, VirtioTransport,
};
use memmap2::MmapMut;
use rustix::fs::{memfd_create, MemfdFlags};
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, RwLock};
use vhost_bindings::VHOST_PAGE_SIZE;
use vhost_vdpa_kernel::VhostVdpaKernel;
use virtio_bindings::virtio_config::*;

#[derive(Debug)]
pub struct VhostVdpaError(std::io::Error);

impl<E: 'static + std::error::Error + Send + Sync> From<E> for VhostVdpaError {
    fn from(e: E) -> Self {
        VhostVdpaError(Error::new(ErrorKind::Other, e))
    }
}

/// Type parameters `C` and `R` have the same meaning as in [`VirtioTransport`].
pub struct VhostVdpa<C: ByteValued, R: Copy> {
    vdpa: VhostVdpaKernel,
    features: u64,
    max_queues: Option<usize>,
    max_mem_regions: u64,
    virtqueue_mem_file: File,
    mmap: Option<MmapMut>,
    eventfd_kick: Vec<Arc<EventFd>>,
    eventfd_call: Vec<Arc<EventFd>>,
    iova_space: Arc<RwLock<IovaSpace>>,
    phantom: PhantomData<(C, R)>,
}

// `Send` and `Sync` are not implemented automatically due to the `memory` and `phantom` fields.
unsafe impl<C: ByteValued, R: Copy> Send for VhostVdpa<C, R> {}
unsafe impl<C: ByteValued, R: Copy> Sync for VhostVdpa<C, R> {}

impl<C: ByteValued, R: Copy> VhostVdpa<C, R> {
    /// Creates a new vhost-vdpa connection using the given system path of the
    /// vhost-vdpa character device.
    ///
    /// A connection created this way is usually passed to a virtio driver.
    ///
    /// `virtio_features` is a bit mask that contains all virtio features that should be accepted
    /// while connecting if the device offers them. It is not an error if the device doesn't offer
    /// feature flags. The caller is responsible for checking them if it requires a flag.
    pub fn with_path(path: &str, virtio_features: u64) -> Result<Self, VhostVdpaError> {
        let vdpa = VhostVdpaKernel::with_path(path)?;

        Self::init(vdpa, virtio_features)
    }

    /// Creates a new vhost-vdpa connection using the given file descriptor.
    ///
    /// A connection created this way is usually passed to a virtio driver.
    ///
    /// `virtio_features` is a bit mask that contains all virtio features that should be accepted
    /// while connecting if the device offers them. It is not an error if the device doesn't offer
    /// feature flags. The caller is responsible for checking them if it requires a flag.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `fd` is a valid file descriptor of a vhost-vdpa character
    /// device.
    pub unsafe fn with_fd(fd: RawFd, virtio_features: u64) -> Result<Self, VhostVdpaError> {
        let vdpa = unsafe { VhostVdpaKernel::with_fd(fd)? };

        Self::init(vdpa, virtio_features)
    }

    fn init(mut vdpa: VhostVdpaKernel, virtio_features: u64) -> Result<Self, VhostVdpaError> {
        vdpa.set_status(0)?;

        vdpa.add_status((VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER) as u8)?;

        let mut features = vdpa.get_features()?;
        // VIRTIO_F_ACCESS_PLATFORM required by vhost-vdpa kernel module
        features &= virtio_features | VirtioFeatureFlags::ACCESS_PLATFORM.bits();
        vdpa.set_features(features)?;

        vdpa.add_status(VIRTIO_CONFIG_S_FEATURES_OK as u8)?;

        let virtqueue_mem_file: File = memfd_create("virtio-ring", MemfdFlags::empty())?.into();

        // VHOST_VDPA_GET_VQS_COUNT ioctl is only supported starting with Linux v5.18.
        let max_queues = vdpa.get_vqs_count().map(|v| v as usize).ok();
        let max_mem_regions = u64::MAX;

        let (iova_start, iova_end) = vdpa.get_iova_range()?.into_inner();
        let iova_space = IovaSpace::new([Iova(iova_start)..=Iova(iova_end)]);

        let vu = VhostVdpa {
            vdpa,
            features,
            max_queues,
            max_mem_regions,
            virtqueue_mem_file,
            mmap: None,
            eventfd_kick: Vec::new(),
            eventfd_call: Vec::new(),
            iova_space: Arc::new(RwLock::new(iova_space)),
            phantom: PhantomData,
        };

        Ok(vu)
    }

    fn setup_queue(&mut self, queue_idx: usize, q: &Virtqueue<R>) -> Result<(), Error> {
        let vdpa = &mut self.vdpa;
        let iova_space = self.iova_space.read().unwrap();
        let q_layout = q.layout();

        vdpa.set_vring_num(queue_idx, q.queue_size().into())?;
        vdpa.set_vring_base(queue_idx, 0)?;

        let Iova(desc_user_addr) = iova_space
            .translate(q.desc_table_ptr() as usize, q_layout.driver_area_offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Descriptor table is not mapped"))?;
        let Iova(used_user_addr) = iova_space
            .translate(
                q.device_area_ptr() as usize,
                q_layout.req_offset - q_layout.device_area_offset,
            )
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Used ring is not mapped"))?;
        let Iova(avail_user_addr) = iova_space
            .translate(
                q.driver_area_ptr() as usize,
                q_layout.device_area_offset - q_layout.driver_area_offset,
            )
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Available ring is not mapped"))?;

        vdpa.set_vring_addr(queue_idx, desc_user_addr, used_user_addr, avail_user_addr)?;

        vdpa.set_vring_kick(queue_idx, self.eventfd_kick[queue_idx].as_raw_fd())?;
        vdpa.set_vring_call(queue_idx, self.eventfd_call[queue_idx].as_raw_fd())?;

        vdpa.set_vring_enable(queue_idx, true)?;

        Ok(())
    }
}

impl<C: ByteValued, R: Copy> VirtioTransport<C, R> for VhostVdpa<C, R> {
    fn max_queues(&self) -> Option<usize> {
        self.max_queues
    }

    fn max_mem_regions(&self) -> u64 {
        self.max_mem_regions
    }

    fn mem_region_alignment(&self) -> usize {
        VHOST_PAGE_SIZE as usize
    }

    fn alloc_queue_mem(&mut self, layout: &VirtqueueLayout) -> Result<&mut [u8], Error> {
        // VDUSE requires that memory should be allocated with an associated fd,
        // so we use the same approach as vhost-user, allocating the virtqueues
        // memory through a memory mapped anonymous file.

        if self.mmap.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Memory is already allocated",
            ));
        }

        let alignment = self.mem_region_alignment();

        let vq_mem_size = layout
            .num_queues
            .checked_mul(layout.end_offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Queue is too large"))?;
        let vq_mem_size = ((vq_mem_size + alignment - 1) / alignment) * alignment;

        // TODO This assumes that all virtqueues have the same queue_size
        self.virtqueue_mem_file.set_len(vq_mem_size as u64)?;

        let mmap = unsafe { MmapMut::map_mut(&self.virtqueue_mem_file) }?;
        self.map_mem_region(
            mmap.as_ptr() as usize,
            mmap.len(),
            self.virtqueue_mem_file.as_raw_fd(),
            0,
        )?;

        self.mmap = Some(mmap);
        Ok(self.mmap.as_mut().unwrap().as_mut())
    }

    fn map_mem_region(
        &mut self,
        addr: usize,
        len: usize,
        _fd: RawFd,
        _fd_offset: i64,
    ) -> Result<Iova, Error> {
        let mut iova_space = self.iova_space.write().unwrap();
        let iova = iova_space.allocate(addr, len)?;

        // `_fd` is not used here because the vhost-vdpa kernel module retrieves
        // the fd associated with the VA directly into the kernel, so there is
        // no need to pass it to the call.
        // This is needed only when the vDPA device uses VA and requires an
        // associated fd (e.g. VDUSE devices).
        let ret = self
            .vdpa
            .dma_map(iova.0, len as u64, addr as *const u8, false);

        match ret {
            Ok(()) => Ok(iova),
            Err(e) => {
                iova_space.free(addr, len);
                Err(e)
            }
        }
    }

    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error> {
        let mut iova_space = self.iova_space.write().unwrap();

        let Iova(iova) = iova_space.translate(addr, len).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Address range [{:#x}, {:#x}) is not mapped",
                    addr,
                    addr + len
                ),
            )
        })?;

        self.vdpa
            .dma_unmap(iova, len as u64)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        iova_space.free(addr, len);

        Ok(())
    }

    fn iova_translator(&self) -> Box<dyn IovaTranslator> {
        #[derive(Clone)]
        struct VhostVdpaIovaTranslator {
            iova_space: Arc<RwLock<IovaSpace>>,
        }

        impl IovaTranslator for VhostVdpaIovaTranslator {
            fn translate_addr(&self, addr: usize, len: usize) -> Result<Iova, Error> {
                self.iova_space
                    .read()
                    .unwrap()
                    .translate(addr, len)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidInput,
                            format!("Trying to translate unmapped address {} into an IOVA", addr),
                        )
                    })
            }
        }

        Box::new(VhostVdpaIovaTranslator {
            iova_space: Arc::clone(&self.iova_space),
        })
    }

    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error> {
        for (i, q) in queues.iter().enumerate() {
            self.eventfd_kick
                .push(Arc::new(EventFd::new(EventfdFlags::CLOEXEC).unwrap()));
            self.eventfd_call
                .push(Arc::new(EventFd::new(EventfdFlags::CLOEXEC).unwrap()));
            self.setup_queue(i, q)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
        }

        self.vdpa.add_status(VIRTIO_CONFIG_S_DRIVER_OK as u8)
    }

    fn get_features(&self) -> u64 {
        self.features
    }

    fn get_config(&self) -> Result<C, Error> {
        let cfg_size: usize = mem::size_of::<C>();
        let mut buf = vec![0u8; cfg_size];

        self.vdpa
            .get_config(0, &mut buf)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(*C::from_slice(&buf).unwrap())
    }

    fn get_submission_notifier(&self, queue_idx: usize) -> Box<dyn QueueNotifier> {
        let eventfd = Arc::clone(&self.eventfd_kick[queue_idx]);
        Box::new(VhostVdpaNotifier { eventfd })
    }

    fn get_completion_fd(&self, queue_idx: usize) -> Arc<EventFd> {
        Arc::clone(&self.eventfd_call[queue_idx])
    }
}

struct VhostVdpaNotifier {
    eventfd: Arc<EventFd>,
}

impl QueueNotifier for VhostVdpaNotifier {
    fn notify(&self) -> Result<(), Error> {
        self.eventfd.write(1)
    }
}
