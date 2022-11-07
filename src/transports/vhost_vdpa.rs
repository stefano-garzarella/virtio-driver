// SPDX-License-Identifier: (MIT OR Apache-2.0)

mod vhost_bindings;
mod vhost_vdpa_kernel;

use crate::virtqueue::{Virtqueue, VirtqueueLayout};
use crate::{
    ByteValued, EfdFlags, EventFd, Iova, IovaTranslator, QueueNotifier, VirtioFeatureFlags,
    VirtioTransport,
};
use memfd::MemfdOptions;
use memmap::MmapMut;
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use vhost_vdpa_kernel::VhostVdpaKernel;
use virtio_bindings::bindings::virtio_blk::*;

#[derive(Debug)]
pub struct VhostVdpaBlkError(std::io::Error);

impl<E: 'static + std::error::Error + Send + Sync> From<E> for VhostVdpaBlkError {
    fn from(e: E) -> Self {
        VhostVdpaBlkError(Error::new(ErrorKind::Other, e))
    }
}

/// Type parameters `C` and `R` have the same meaning as in [`VirtioTransport`].
pub struct VhostVdpa<C: ByteValued, R: Copy> {
    vdpa: VhostVdpaKernel,
    features: u64,
    max_queues: usize,
    max_mem_regions: u64,
    virtqueue_mem_file: File,
    mmap: Option<MmapMut>,
    eventfd_kick: Vec<Arc<EventFd>>,
    eventfd_call: Vec<Arc<EventFd>>,
    phantom: PhantomData<(C, R)>,
}

// `Send` and `Sync` are not implemented automatically due to the `memory` and `phantom` fields.
unsafe impl<C: ByteValued, R: Copy> Send for VhostVdpa<C, R> {}
unsafe impl<C: ByteValued, R: Copy> Sync for VhostVdpa<C, R> {}

impl<C: ByteValued, R: Copy> VhostVdpa<C, R> {
    pub fn new(path: &str, virtio_features: u64) -> Result<Self, VhostVdpaBlkError> {
        let mut vdpa = VhostVdpaKernel::new(path)?;

        vdpa.set_status(0)?;

        vdpa.add_status((VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER) as u8)?;

        let mut features = vdpa.get_features()?;
        // VIRTIO_F_ACCESS_PLATFORM required by vhost-vdpa kernel module
        features &= virtio_features | VirtioFeatureFlags::ACCESS_PLATFORM.bits();
        vdpa.set_features(features)?;

        vdpa.add_status(VIRTIO_CONFIG_S_FEATURES_OK as u8)?;

        let memfd = MemfdOptions::new()
            .create("virtio-ring")
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let virtqueue_mem_file = memfd.into_file();

        //TODO: VHOST_VDPA_GET_VQS_COUNT support (we need to update the vhost crate)
        let max_queues = u16::MAX as usize;
        let max_mem_regions = u64::MAX;

        let vu = VhostVdpa {
            vdpa,
            features,
            max_queues,
            max_mem_regions,
            virtqueue_mem_file,
            mmap: None,
            eventfd_kick: Vec::new(),
            eventfd_call: Vec::new(),
            phantom: PhantomData,
        };

        Ok(vu)
    }

    fn setup_queue(&mut self, queue_idx: usize, q: &Virtqueue<R>) -> Result<(), Error> {
        let vdpa = &mut self.vdpa;

        vdpa.set_vring_num(queue_idx, q.queue_size().into())?;
        vdpa.set_vring_base(queue_idx, 0)?;
        vdpa.set_vring_addr(
            queue_idx,
            q.desc_table_ptr() as u64,
            q.used_ring_ptr() as u64,
            q.avail_ring_ptr() as u64,
        )?;

        vdpa.set_vring_kick(queue_idx, self.eventfd_kick[queue_idx].as_raw_fd())?;
        vdpa.set_vring_call(queue_idx, self.eventfd_call[queue_idx].as_raw_fd())?;

        vdpa.set_vring_enable(queue_idx, true)?;

        Ok(())
    }
}

impl<C: ByteValued, R: Copy> VirtioTransport<C, R> for VhostVdpa<C, R> {
    fn max_queues(&self) -> usize {
        self.max_queues
    }

    fn max_mem_regions(&self) -> u64 {
        self.max_mem_regions
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

        // TODO This assumes that all virtqueues have the same queue_size
        self.virtqueue_mem_file.set_len(
            layout
                .num_queues
                .checked_mul(layout.end_offset)
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Queue is too large"))?
                as u64,
        )?;

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
        // `_fd` is not used here because the vhost-vdpa kernel module retrieves
        // the fd associated with the VA directly into the kernel, so there is
        // no need to pass it to the call.
        // This is needed only when the vDPA device uses VA and requires an
        // associated fd (e.g. VDUSE devices).
        self.vdpa
            .dma_map(addr as u64, len as u64, addr as *const u8, false)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(Iova(addr as u64))
    }

    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error> {
        self.vdpa
            .dma_unmap(addr as u64, len as u64)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(())
    }

    fn iova_translator(&self) -> Box<dyn IovaTranslator> {
        #[derive(Clone)]
        struct VhostVdpaIovaTranslator;

        impl IovaTranslator for VhostVdpaIovaTranslator {
            fn translate_addr(&self, addr: usize, _len: usize) -> Result<Iova, Error> {
                Ok(Iova(addr as u64))
            }
        }

        Box::new(VhostVdpaIovaTranslator)
    }

    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error> {
        for (i, q) in queues.iter().enumerate() {
            self.eventfd_kick
                .push(Arc::new(EventFd::new(EfdFlags::EFD_CLOEXEC).unwrap()));
            self.eventfd_call
                .push(Arc::new(EventFd::new(EfdFlags::EFD_CLOEXEC).unwrap()));
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
