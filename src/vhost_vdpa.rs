// SPDX-License-Identifier: LGPL-2.1-or-later

use crate::virtqueue::{Virtqueue, VirtqueueLayout};
use crate::{VirtioFeatureFlags, VirtioTransport};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::convert::TryFrom;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind};
use std::mem;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::RawFd;
use std::rc::Rc;
use std::sync::Arc;
use vhost::vdpa::VhostVdpa as VhostVdpaBackend;
use vhost::vhost_kern::VhostKernFeatures;
use vhost::{VhostBackend, VringConfigData};
use virtio_bindings::bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub struct VhostVdpaBlkError(std::io::Error);

impl<E: 'static + std::error::Error + Send + Sync> From<E> for VhostVdpaBlkError {
    fn from(e: E) -> Self {
        VhostVdpaBlkError(Error::new(ErrorKind::Other, e))
    }
}

type VhostKernVdpa = vhost::vhost_kern::vdpa::VhostKernVdpa<Arc<GuestMemoryMmap>>;

pub struct VhostVdpa {
    vdpa: VhostKernVdpa,
    features: u64,
    max_queues: usize,
    max_mem_regions: u64,
    memory: *mut u8,
    layout: Option<Layout>,
    eventfd_kick: Vec<Rc<EventFd>>,
    eventfd_call: Vec<Rc<EventFd>>,
}

fn vdpa_add_status(vdpa: &VhostKernVdpa, status: u32) -> Result<(), VhostVdpaBlkError> {
    let status = u8::try_from(status)?;
    let mut current_status = vdpa.get_status()?;

    vdpa.set_status(current_status | status)?;

    current_status = vdpa.get_status()?;
    if (current_status & status) != status {
        return Err(VhostVdpaBlkError(Error::new(
            ErrorKind::Other,
            "failed to set the status".to_string(),
        )));
    }

    Ok(())
}

impl VhostVdpa {
    pub fn new(path: &str, virtio_features: u64) -> Result<Self, VhostVdpaBlkError> {
        let file = OpenOptions::new()
            .custom_flags(libc::O_CLOEXEC)
            .write(true)
            .open(path)?;

        /* Workaround to disable all the protection provided by GuestMemory
         * since we are not using GuestMemoryMmap to map the guest address
         * space.
         */
        let mr = unsafe {
            MmapRegion::<()>::build_raw(
                std::ptr::null_mut::<u8>(),
                usize::MAX,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_NORESERVE | libc::MAP_PRIVATE,
            )?
        };
        let gmr = GuestRegionMmap::new(mr, GuestAddress(0))?;
        let m = GuestMemoryMmap::from_regions(vec![gmr])?;

        let mut vdpa = VhostKernVdpa::with(file, Arc::new(m), 0);

        vdpa.set_owner()?;

        let backend_features = vdpa.get_backend_features()?;
        //TODO: ack only supported features by the backend (should be done by vhost crate?)
        vdpa.set_backend_features(backend_features)?;

        vdpa.set_status(0)?;

        vdpa_add_status(&vdpa, VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER)?;

        let mut features = vdpa.get_features()?;
        // VIRTIO_F_ACCESS_PLATFORM required by vhost-vdpa kernel module
        features &= virtio_features | VirtioFeatureFlags::ACCESS_PLATFORM.bits();
        vdpa.set_features(features)?;

        vdpa_add_status(&vdpa, VIRTIO_CONFIG_S_FEATURES_OK)?;

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
        };

        Ok(vu)
    }

    fn setup_queue<R: Copy>(
        &mut self,
        queue_idx: usize,
        q: &Virtqueue<R>,
    ) -> Result<(), vhost::Error> {
        let vdpa = &mut self.vdpa;

        vdpa.set_vring_num(queue_idx, q.queue_size())?;
        vdpa.set_vring_base(queue_idx, 0)?;
        vdpa.set_vring_addr(
            queue_idx,
            &VringConfigData {
                queue_max_size: q.queue_size(),
                queue_size: q.queue_size(),
                flags: 0,
                desc_table_addr: q.desc_table_ptr() as u64,
                avail_ring_addr: q.avail_ring_ptr() as u64,
                used_ring_addr: q.used_ring_ptr() as u64,
                log_addr: None,
            },
        )?;

        vdpa.set_vring_kick(queue_idx, &self.eventfd_kick[queue_idx])?;
        vdpa.set_vring_call(queue_idx, &self.eventfd_call[queue_idx])?;

        vdpa.set_vring_enable(queue_idx, true)?;

        Ok(())
    }
}

impl Drop for VhostVdpa {
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

impl VirtioTransport for VhostVdpa {
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

    fn add_mem_region(
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

    fn del_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error> {
        self.vdpa
            .dma_unmap(addr as u64, len as u64)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(())
    }

    fn setup_queues<R: Copy>(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error> {
        for (i, q) in queues.iter().enumerate() {
            self.eventfd_kick.push(Rc::new(EventFd::new(0).unwrap()));
            self.eventfd_call.push(Rc::new(EventFd::new(0).unwrap()));
            self.setup_queue(i, q)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
        }

        vdpa_add_status(&self.vdpa, VIRTIO_CONFIG_S_DRIVER_OK).map_err(|e| e.0)
    }

    fn get_features(&self) -> u64 {
        self.features
    }

    fn get_config<C: ByteValued>(&mut self) -> Result<C, Error> {
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
