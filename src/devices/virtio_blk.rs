// SPDX-License-Identifier: (MIT OR Apache-2.0)

use crate::virtqueue::{Virtqueue, VirtqueueIter, VirtqueueLayout};
use crate::{ByteValued, Completion, Le16, Le32, Le64, VirtioFeatureFlags, VirtioTransport};
use bitflags::bitflags;
use libc::{c_void, iovec, EIO, ENOTSUP, EPROTO};
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use std::iter;
use std::mem;

bitflags! {
    pub struct VirtioBlkFeatureFlags: u64 {
        const SIZE_MAX = 1 << 1;
        const SEG_MAX = 1 << 2;
        const GEOMETRY = 1 << 4;
        const RO = 1 << 5;
        const BLK_SIZE = 1 << 6;
        const FLUSH = 1 << 9;
        const TOPOLOGY = 1 << 10;
        const CONFIG_WCE = 1 << 11;
        const MQ = 1 << 12;
        const DISCARD = 1 << 13;
        const WRITE_ZEROES = 1 << 14;
        const LIFETIME = 1 << 15;
        const SECURE_ERASE = 1 << 16;
    }
}

/// The Device Configuration Space for a virtio-blk device.
///
/// This is `struct virtio_blk_config`` from the VIRTIO 1.1 specification (see 5.2.4).
#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub struct VirtioBlkConfig {
    pub capacity: Le64,
    pub size_max: Le32,
    pub seg_max: Le32,
    pub cylinders: Le16,
    pub heads: u8,
    pub sectors: u8,
    pub blk_size: Le32,
    pub physical_block_exp: u8,
    pub alignment_offset: u8,
    pub min_io_size: Le16,
    pub opt_io_size: Le32,
    pub writeback: u8,
    _unused0: u8,
    pub num_queues: Le16,
    pub max_discard_sectors: Le32,
    pub max_discard_seg: Le32,
    pub discard_sector_alignment: Le32,
    pub max_write_zeroes_sectors: Le32,
    pub max_write_zeroes_seg: Le32,
    pub write_zeroes_may_unmap: u8,
    _unused1: [u8; 3],
}

unsafe impl ByteValued for VirtioBlkConfig {}

fn to_lba(offset: u64) -> Result<u64, Error> {
    // This is independent of the reported block size of the device
    let block_size = 512;

    if offset & (block_size - 1) != 0 {
        return Err(Error::new(ErrorKind::InvalidInput, "Unaligned request"));
    }

    Ok(offset / block_size)
}

pub fn validate_lba(offset: u64) -> Result<(), Error> {
    to_lba(offset).map(|_| ())
}

pub fn virtio_blk_max_queues(transport: &VirtioBlkTransport) -> Result<usize, Error> {
    // Some transports (e.g. vhost-vdpa before Linux v5.18) may not be able
    // to provide the number of queues, so let's look in the config space.
    let features = VirtioBlkFeatureFlags::from_bits_truncate(transport.get_features());
    if features.contains(VirtioBlkFeatureFlags::MQ) {
        let cfg = transport.get_config()?;
        Ok(u16::from(cfg.num_queues) as usize)
    } else {
        // If VirtioBlkFeatureFlags::MQ is not negotiated, the device supports
        // only a single queue
        Ok(1)
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
struct DiscardWriteZeroesData {
    sector: Le64,
    num_sectors: Le32,
    flags: Le32,
}

bitflags! {
    pub struct DiscardWriteZeroesFlags: u32 {
        const UNMAP = 1 << 0;
    }
}

impl DiscardWriteZeroesData {
    fn new(offset: u64, len: u64, unmap: bool) -> Result<Self, Error> {
        let start = to_lba(offset)?;
        let num_sectors = u32::try_from(to_lba(len)?)
            .map_err(|_e| Error::new(ErrorKind::InvalidInput, "Discard length too large"))?;
        let flags = if unmap {
            DiscardWriteZeroesFlags::UNMAP.bits()
        } else {
            0
        };

        Ok(DiscardWriteZeroesData {
            sector: start.into(),
            num_sectors: num_sectors.into(),
            flags: flags.into(),
        })
    }
}

/// The request header for virtio-blk devices.
///
/// This is the first part of `struct virtio_blk_req`` from the VIRTIO 1.1 specification (see
/// 5.2.6).
#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
struct VirtioBlkReqHeader {
    req_type: Le32,
    _reserved: Le32,
    sector: Le64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum VirtioBlkReqType {
    Read = 0,
    Write = 1,
    Flush = 4,
    Discard = 11,
    WriteZeroes = 13,
}

impl VirtioBlkReqType {
    fn is_from_dev(&self) -> bool {
        // The return value for Flush doesn't matter because it doesn't have any buffers
        *self == Self::Read
    }
}

impl VirtioBlkReqHeader {
    fn new(req_type: VirtioBlkReqType, offset: u64) -> Self {
        Self {
            req_type: (req_type as u32).into(),
            _reserved: 0.into(),
            sector: offset.into(),
        }
    }
}

unsafe impl ByteValued for VirtioBlkReqHeader {}

#[derive(Clone, Copy)]
pub struct VirtioBlkReqBuf {
    header: VirtioBlkReqHeader,
    status: u8,
    dwz_data: DiscardWriteZeroesData,
}

pub type VirtioBlkTransport = dyn VirtioTransport<VirtioBlkConfig, VirtioBlkReqBuf>;

/// A queue of a virtio-blk device.
///
/// This is used to send block I/O requests to the device and receive completions. Note that calling
/// transport specific functions may need to be called before or after certain operations on the
/// `VirtioBlkQueue`:
///
/// * All request methods only enqueue the requests in the rings. They don't notify the device of
///   new requests, so it may or may not start processing them. Call
///   [`crate::QueueNotifier::notify`] on the result of [`VirtioTransport::get_submission_notifier`]
///   after queuing requests to notify the device. You can queue multiple requests and then send a
///   single notification for all of them.
///
/// * To be notified of new completions, use the `EventFd` returned by
///   [`VirtioTransport::get_completion_fd`].
///
/// When a request is submitted, the user provides a "context" of type `C` that will later be
/// returned in the completion for that request.
///
/// Use [`setup_queues`] to create the queues for a device.
///
/// # Examples
///
/// ```no_run
/// # use virtio_driver::{
/// #     VhostUser, VirtioBlkQueue, VirtioBlkTransport, VirtioFeatureFlags, VirtioTransport
/// # };
/// use rustix::fs::{memfd_create, MemfdFlags};
/// use std::ffi::CStr;
/// use std::fs::File;
/// use std::os::unix::io::{AsRawFd, FromRawFd};
/// use std::sync::{Arc, RwLock};
///
/// // Connect to the vhost-user socket and create the queues
/// let mut vhost = VhostUser::new("/tmp/vhost.sock", VirtioFeatureFlags::VERSION_1.bits())?;
/// let mut vhost = Arc::new(RwLock::new(Box::new(vhost) as Box<VirtioBlkTransport>));
/// let mut queues = VirtioBlkQueue::<&'static str>::setup_queues(&vhost, 1, 128)?;
///
/// // Create shared memory that is visible for the device
/// let mem_file: File = memfd_create("guest-ram", MemfdFlags::empty())?.into();
/// mem_file.set_len(512)?;
/// let mut mem = unsafe { memmap2::MmapMut::map_mut(&mem_file) }?;
/// vhost.write().unwrap().map_mem_region(mem.as_ptr() as usize, 512, mem_file.as_raw_fd(), 0)?;
///
/// // Submit a request
/// queues[0].read(0, &mut mem, "my-request-context")?;
/// vhost.read().unwrap().get_submission_notifier(0).notify()?;
///
/// // Wait for its completion
/// let mut done = false;
/// while !done {
///     let ret = vhost.read().unwrap().get_completion_fd(0).read();
///     if ret.is_err() {
///         continue;
///     }
///
///     for c in queues[0].completions() {
///         println!("Completed request with context {:?}, return value {}", c.context, c.ret);
///         done = true;
///     }
/// }
/// # Result::<(), Box<dyn std::error::Error>>::Ok(())
/// ```
///
/// [`setup_queues`]: Self::setup_queues
pub struct VirtioBlkQueue<'a, C> {
    vq: Virtqueue<'a, VirtioBlkReqBuf>,
    req_contexts: Box<[Option<C>]>,
}

impl<'a, C> VirtioBlkQueue<'a, C> {
    fn new(vq: Virtqueue<'a, VirtioBlkReqBuf>) -> Self {
        let queue_size = vq.queue_size().into();
        let req_contexts = iter::repeat_with(|| None).take(queue_size).collect();

        Self { vq, req_contexts }
    }

    /// Creates the queues for a virtio-blk device.
    pub fn setup_queues(
        transport: &mut VirtioBlkTransport,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<Vec<Self>, Error> {
        if virtio_blk_max_queues(transport)? < num_queues {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Too many queues requested",
            ));
        }

        let features = VirtioFeatureFlags::from_bits_truncate(transport.get_features());
        let layout =
            VirtqueueLayout::new::<VirtioBlkReqBuf>(num_queues, queue_size as usize, features)?;
        let queues: Vec<_> = {
            // Not actually needless: must drop the borrow on the transport before alloc_queue_mem()
            #[allow(clippy::needless_collect)]
            let iova_translators: Vec<_> = iter::repeat_with(|| transport.iova_translator())
                .take(num_queues)
                .collect();

            let mem = transport.alloc_queue_mem(&layout)?;

            iova_translators
                .into_iter()
                .enumerate()
                .map(|(i, iova_translator)| {
                    let mem_queue = unsafe {
                        std::slice::from_raw_parts_mut(
                            &mut mem[i * layout.end_offset] as *mut u8,
                            layout.end_offset,
                        )
                    };
                    Virtqueue::new(iova_translator, mem_queue, queue_size, features)
                })
                .collect::<Result<_, _>>()?
        };
        transport.setup_queues(&queues)?;

        Ok(queues.into_iter().map(Self::new).collect())
    }

    fn queue_request_full(
        &mut self,
        req_type: VirtioBlkReqType,
        offset: u64,
        buf: &[iovec],
        dwz_data: Option<DiscardWriteZeroesData>,
        context: C,
    ) -> Result<(), Error> {
        let lba = to_lba(offset)?;

        let desc_idx = self.vq.add_request(|req, add_desc| {
            *req = VirtioBlkReqBuf {
                header: VirtioBlkReqHeader::new(req_type, lba),
                status: 0,
                dwz_data: dwz_data.unwrap_or_default(),
            };

            add_desc(
                iovec {
                    iov_base: &mut req.header as *mut _ as *mut c_void,
                    iov_len: mem::size_of::<VirtioBlkReqHeader>(),
                },
                false,
            )?;

            if dwz_data.is_some() {
                add_desc(
                    iovec {
                        iov_base: &mut req.dwz_data as *mut _ as *mut c_void,
                        iov_len: mem::size_of::<DiscardWriteZeroesData>(),
                    },
                    false,
                )?;
            }

            for b in buf {
                add_desc(*b, req_type.is_from_dev())?;
            }

            add_desc(
                iovec {
                    iov_base: &mut req.status as *mut _ as *mut c_void,
                    iov_len: 1,
                },
                true,
            )?;

            Ok(())
        })?;

        let old = self.req_contexts[desc_idx as usize].replace(context);
        assert!(old.is_none());

        Ok(())
    }

    fn queue_request(
        &mut self,
        req_type: VirtioBlkReqType,
        offset: u64,
        buf: &[iovec],
        context: C,
    ) -> Result<(), Error> {
        self.queue_request_full(req_type, offset, buf, None, context)
    }

    /// Reads from the disk image into a given iovec.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `iovec`/`iovcnt` pair is valid and all memory regions
    /// referenced by it are safe to access.
    pub unsafe fn readv(
        &mut self,
        offset: u64,
        iovec: *const iovec,
        iovcnt: usize,
        context: C,
    ) -> Result<(), Error> {
        let iov = unsafe { std::slice::from_raw_parts(iovec, iovcnt) };
        self.queue_request(VirtioBlkReqType::Read, offset, iov, context)
    }

    /// Reads from the disk image into a given buffer.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the buffer described by `buf` and `len` is safe to access.
    pub unsafe fn read_raw(
        &mut self,
        offset: u64,
        buf: *mut u8,
        len: usize,
        context: C,
    ) -> Result<(), Error> {
        let iov = iovec {
            iov_base: buf as *mut c_void,
            iov_len: len,
        };

        self.queue_request(VirtioBlkReqType::Read, offset, &[iov], context)
    }

    /// Reads from the disk image into a given byte slice.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn read(&mut self, offset: u64, buf: &mut [u8], context: C) -> Result<(), Error> {
        unsafe { self.read_raw(offset, buf.as_mut_ptr(), buf.len(), context) }
    }

    /// Writes to the disk image from a given iovec.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `iovec`/`iovcnt` pair is valid and all memory regions
    /// referenced by it are safe to access.
    pub unsafe fn writev(
        &mut self,
        offset: u64,
        iovec: *const iovec,
        iovcnt: usize,
        context: C,
    ) -> Result<(), Error> {
        let iov = unsafe { std::slice::from_raw_parts(iovec, iovcnt) };
        self.queue_request(VirtioBlkReqType::Write, offset, iov, context)
    }

    /// Writes to the disk image from a given buffer.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the buffer described by `buf` and `len` is safe to access.
    pub unsafe fn write_raw(
        &mut self,
        offset: u64,
        buf: *const u8,
        len: usize,
        context: C,
    ) -> Result<(), Error> {
        let iov = iovec {
            iov_base: buf as *mut c_void,
            iov_len: len,
        };

        self.queue_request(VirtioBlkReqType::Write, offset, &[iov], context)
    }

    /// Writes to the disk image from a given byte slice.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn write(&mut self, offset: u64, buf: &[u8], context: C) -> Result<(), Error> {
        unsafe { self.write_raw(offset, buf.as_ptr(), buf.len(), context) }
    }

    /// Discards an area in the disk image.
    ///
    /// After completion, the content of the specified area is undefined. Discard is only a hint
    /// and doing nothing is a valid implementation. This means that the discarded data may remain
    /// accessible, this is not a way to safely delete data.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn discard(&mut self, offset: u64, len: u64, context: C) -> Result<(), Error> {
        let dwz_data = DiscardWriteZeroesData::new(offset, len, false)?;
        self.queue_request_full(VirtioBlkReqType::Discard, 0, &[], Some(dwz_data), context)
    }

    /// Zeroes out an area in the disk image.
    ///
    /// If `unmap` is `true`, the area is tried to be deallocated if we know that it will read back
    /// as all zeroes afterwards. If it is `false`, allocated parts will remain allocated.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn write_zeroes(
        &mut self,
        offset: u64,
        len: u64,
        unmap: bool,
        context: C,
    ) -> Result<(), Error> {
        let dwz_data = DiscardWriteZeroesData::new(offset, len, unmap)?;
        self.queue_request_full(
            VirtioBlkReqType::WriteZeroes,
            0,
            &[],
            Some(dwz_data),
            context,
        )
    }

    /// Flushes the disk cache.
    ///
    /// This ensures that on successful completion, any requests that had completed before this
    /// flush request was issued are not sitting in any writeback cache, but are actually stored on
    /// disk.
    ///
    /// `context` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn flush(&mut self, context: C) -> Result<(), Error> {
        self.queue_request(VirtioBlkReqType::Flush, 0, &[], context)
    }

    /// Returns the result for any completed requests.
    pub fn completions(&mut self) -> CompletionIter<'_, 'a, C> {
        CompletionIter {
            it: self.vq.completions(),
            req_contexts: &mut self.req_contexts,
        }
    }

    pub fn avail_notif_needed(&mut self) -> bool {
        self.vq.avail_notif_needed()
    }

    pub fn set_used_notif_enabled(&mut self, enabled: bool) {
        self.vq.set_used_notif_enabled(enabled);
    }
}

pub struct CompletionIter<'a, 'queue, C> {
    it: VirtqueueIter<'a, 'queue, VirtioBlkReqBuf>,
    req_contexts: &'a mut Box<[Option<C>]>,
}

impl<C> CompletionIter<'_, '_, C> {
    pub fn has_next(&self) -> bool {
        self.it.has_next()
    }
}

impl<'queue, C> Iterator for CompletionIter<'_, 'queue, C> {
    type Item = Completion<C>;

    fn next(&mut self) -> Option<Self::Item> {
        let completion = self.it.next()?;

        // If the backend sent a completion for a request we never made, just ignore it.
        let context = self.req_contexts[completion.id as usize].take()?;

        Some(Completion {
            context,
            ret: match completion.req.status {
                0 => 0,
                1 => -EIO,
                2 => -ENOTSUP,
                _ => -EPROTO,
            },
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.it.size_hint()
    }
}
