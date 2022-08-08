// SPDX-License-Identifier: LGPL-2.1-or-later

mod front_end;
mod vhost_user_protocol;

use crate::virtqueue::{Virtqueue, VirtqueueLayout};
use crate::{ByteValued, EfdFlags, EventFd, VirtioTransport};
use front_end::{VhostUserFrontEnd, VhostUserMemoryRegionInfo};
use memfd::MemfdOptions;
use memmap::MmapMut;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use vhost_user_protocol::{
    VhostUserHeaderFlag, VhostUserMemoryRegion, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};

#[derive(Debug)]
pub struct VhostUserError(Error);

impl From<Error> for VhostUserError {
    fn from(e: Error) -> Self {
        VhostUserError(e)
    }
}

/// The transport to connect to a device using the vhost-user protocol.
///
/// Type parameters `C` and `R` have the same meaning as in [`VirtioTransport`].
pub struct VhostUser<C: ByteValued, R: Copy> {
    vhost: VhostUserFrontEnd,
    features: u64,
    max_queues: usize,
    max_mem_regions: u64,
    mem_table: Vec<VhostUserMemoryRegionInfo>,
    virtqueue_mem_file: File,
    mmap: Option<MmapMut>,
    eventfd_kick: Vec<Rc<EventFd>>,
    eventfd_call: Vec<Rc<EventFd>>,
    phantom: PhantomData<(C, R)>,
}

impl<C: ByteValued, R: Copy> VhostUser<C, R> {
    fn connect(path: &str, virtio_features: u64) -> Result<Self, VhostUserError> {
        let mut vhost = VhostUserFrontEnd::new(path)?;
        vhost.set_owner()?;

        let mut features = vhost.get_features()?;
        if features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(VhostUserError(Error::new(
                ErrorKind::Other,
                "Backend doesn't support PROTOCOL_FEATURES",
            )));
        }
        features &= virtio_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        vhost.set_features(features)?;

        // TODO CONFIG can be made optional to support more device types
        let required_vhost_features = VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS;

        let mut vhost_features = vhost.get_protocol_features()?;
        if !vhost_features.contains(required_vhost_features) {
            return Err(VhostUserError(Error::new(
                ErrorKind::Other,
                "Backend doesn't support required protocol features",
            )));
        }
        vhost_features &= required_vhost_features | VhostUserProtocolFeatures::MQ;
        vhost.set_protocol_features(vhost_features)?;

        vhost.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);

        let max_queues = if vhost_features.contains(VhostUserProtocolFeatures::MQ) {
            vhost
                .get_queue_num()?
                .try_into()
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?
        } else {
            1
        };
        let max_mem_regions = vhost.get_max_mem_slots()?;

        let memfd = MemfdOptions::new()
            .create("virtio-ring")
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let virtqueue_mem_file = memfd.into_file();

        let vu = VhostUser {
            vhost,
            features,
            max_queues,
            max_mem_regions,
            mem_table: Vec::new(),
            virtqueue_mem_file,
            mmap: None,
            eventfd_kick: Vec::new(),
            eventfd_call: Vec::new(),
            phantom: PhantomData,
        };

        Ok(vu)
    }

    /// Creates a new vhost-user connection using the given Unix socket.
    ///
    /// A connection created this way is usually passed to a virtio driver.
    ///
    /// `virtio_features` is a bit mask that contains all virtio features that should be accepted
    /// while connecting if the device offers them. It is not an error if the device doesn't offer
    /// feature flags. The caller is responsible for checking them if it requires a flag.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use virtio_driver::{VhostUser, VirtioBlkQueue, VirtioFeatureFlags};
    /// let mut vhost = VhostUser::new("/tmp/vhost.sock", VirtioFeatureFlags::VERSION_1.bits())?;
    /// let mut queues = VirtioBlkQueue::<()>::setup_queues(&mut vhost, 1, 128);
    /// # Result::<(), Box<dyn std::error::Error>>::Ok(())
    /// ```
    pub fn new(path: &str, virtio_features: u64) -> Result<Self, Error> {
        Self::connect(path, virtio_features).map_err(|e| e.0)
    }

    fn setup_queue(&mut self, i: usize, q: &Virtqueue<R>) -> Result<(), Error> {
        let vhost = &mut self.vhost;
        vhost.set_vring_num(i, q.queue_size().into())?;
        vhost.set_vring_base(i, 0)?;
        vhost.set_vring_addr(
            i,
            q.desc_table_ptr() as u64,
            q.used_ring_ptr() as u64,
            q.avail_ring_ptr() as u64,
        )?;

        vhost.set_vring_kick(i, self.eventfd_kick[i].as_raw_fd())?;
        vhost.set_vring_call(i, self.eventfd_call[i].as_raw_fd())?;
        vhost.set_vring_enable(i, true)?;
        Ok(())
    }
}

impl<C: ByteValued, R: Copy> VirtioTransport<C, R> for VhostUser<C, R> {
    fn max_queues(&self) -> usize {
        self.max_queues
    }

    fn max_mem_regions(&self) -> u64 {
        self.max_mem_regions
    }

    fn alloc_queue_mem(&mut self, layout: &VirtqueueLayout) -> Result<&mut [u8], Error> {
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
        fd: RawFd,
        fd_offset: i64,
    ) -> Result<(), Error> {
        let mmap_offset = u64::try_from(fd_offset)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid fd_offset"))?;

        let region = VhostUserMemoryRegionInfo {
            mr: VhostUserMemoryRegion {
                guest_addr: addr as u64,
                size: len as u64,
                user_addr: addr as u64,
                mmap_offset,
            },
            fd,
        };

        self.vhost
            .add_mem_region(&region)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        self.mem_table.push(region);
        Ok(())
    }

    fn unmap_mem_region(&mut self, addr: usize, len: usize) -> Result<(), Error> {
        for (i, region) in self.mem_table.iter().enumerate() {
            if region.mr.user_addr == addr as u64 && region.mr.size == len as u64 {
                self.vhost
                    .remove_mem_region(region)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                self.mem_table.swap_remove(i);
                return Ok(());
            }
        }
        Err(Error::new(
            ErrorKind::InvalidInput,
            "Memory region not found",
        ))
    }

    fn setup_queues(&mut self, queues: &[Virtqueue<R>]) -> Result<(), Error> {
        for (i, q) in queues.iter().enumerate() {
            self.eventfd_kick
                .push(Rc::new(EventFd::new(EfdFlags::EFD_CLOEXEC).unwrap()));
            self.eventfd_call
                .push(Rc::new(EventFd::new(EfdFlags::EFD_CLOEXEC).unwrap()));
            self.setup_queue(i, q).map_err(|e| {
                // If the user actually retries `setup_queues` instead of dropping the
                // VhostUser object on error, we're going to reconfigure all queues anyway, so
                // drop even successfully registered eventfds from previous loop iterations.
                self.eventfd_kick.clear();
                self.eventfd_call.clear();

                Error::new(ErrorKind::Other, e)
            })?;
        }
        Ok(())
    }

    fn get_features(&self) -> u64 {
        self.features
    }

    fn get_config(&mut self) -> Result<C, Error> {
        let cfg_size: usize = mem::size_of::<C>();
        let mut buf = vec![0u8; cfg_size];
        self.vhost
            .get_config(0, 0, &mut buf)
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
