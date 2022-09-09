// SPDX-License-Identifier: (MIT OR Apache-2.0)

mod vhost_bindings;
mod vhost_vdpa_kernel;

use crate::virtqueue::{Virtqueue, VirtqueueLayout};
use crate::{ByteValued, EfdFlags, EventFd, VirtioFeatureFlags, VirtioTransport};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
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
    memory: *mut u8,
    layout: Option<Layout>,
    eventfd_kick: Vec<Rc<EventFd>>,
    eventfd_call: Vec<Rc<EventFd>>,
    phantom: PhantomData<(C, R)>,
}

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

        //TODO: VHOST_VDPA_GET_VQS_COUNT support (we need to update the vhost crate)
        let max_queues = u16::MAX as usize;
        let max_mem_regions = u64::MAX;

        let vu = VhostVdpa {
            vdpa,
            features,
            max_queues,
            max_mem_regions,
            layout: None,
            memory: std::ptr::null_mut::<u8>(),
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

impl<C: ByteValued, R: Copy> Drop for VhostVdpa<C, R> {
    fn drop(&mut self) {
        if self.layout.is_some() {
            let layout = self.layout.unwrap();

            self.vdpa
                .dma_unmap(self.memory as u64, layout.size() as u64)
                .unwrap();

            unsafe { dealloc(self.memory, layout) };
        }
    }
}

impl<C: ByteValued, R: Copy> VirtioTransport<C, R> for VhostVdpa<C, R> {
    fn max_queues(&self) -> usize {
        self.max_queues
    }

    fn max_mem_regions(&self) -> u64 {
        self.max_mem_regions
    }

    fn alloc_queue_mem(&mut self, vq_layout: &VirtqueueLayout) -> Result<&mut [u8], Error> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        /* allocate vq and requests memory aligned to page size to do a single
         * dma_map() for this regions accessed by the device
         */
        let layout = Layout::from_size_align(vq_layout.end_offset, page_size).unwrap();
        let memory = unsafe { alloc_zeroed(layout) };

        let vq_mem: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(memory, vq_layout.end_offset) };

        self.memory = memory;
        self.layout = Some(layout);

        self.vdpa
            .dma_map(
                self.memory as u64,
                layout.size() as u64,
                self.memory as *const u8,
                false,
            )
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(vq_mem)
    }

    fn map_mem_region(
        &mut self,
        addr: usize,
        len: usize,
        _fd: RawFd,
        _fd_offset: i64,
    ) -> Result<(), Error> {
        self.vdpa
            .dma_map(addr as u64, len as u64, addr as *const u8, false)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(())
    }

    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error> {
        self.vdpa
            .dma_unmap(addr as u64, len as u64)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(())
    }

    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error> {
        for (i, q) in queues.iter().enumerate() {
            self.eventfd_kick
                .push(Rc::new(EventFd::new(EfdFlags::EFD_CLOEXEC).unwrap()));
            self.eventfd_call
                .push(Rc::new(EventFd::new(EfdFlags::EFD_CLOEXEC).unwrap()));
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

    fn get_submission_fd(&self, queue_idx: usize) -> Rc<EventFd> {
        Rc::clone(&self.eventfd_kick[queue_idx])
    }

    fn get_completion_fd(&self, queue_idx: usize) -> Rc<EventFd> {
        Rc::clone(&self.eventfd_call[queue_idx])
    }
}
