use crate::virtqueue::{Virtqueue, VirtqueueIter, VirtqueueLayout};
use crate::{Completion, VirtioTransport};
use bitflags::bitflags;
use libc::{c_void, iovec, EIO, ENOTSUP, EPROTO};
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use std::mem;
use vm_memory::{ByteValued, Le16, Le32, Le64};

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
        const DISCARD = 1 << 13;
        const WRITE_ZEROES = 1 << 14;
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
    _unused0: [u8; 3],
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

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
#[allow(dead_code)]
struct DiscardWriteZeroesData {
    sector: Le64,
    num_sectors: Le32,
    flags: Le32,
}

impl DiscardWriteZeroesData {
    fn new(offset: u64, len: u64, unmap: bool) -> Result<Self, Error> {
        let start = to_lba(offset)?;
        let end = to_lba(offset + len)?;
        let num_sectors = u32::try_from(end - start + 1)
            .map_err(|_e| Error::new(ErrorKind::InvalidInput, "Discard length too large"))?;
        let flags = if unmap { 1 } else { 0 };

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

#[derive(Clone, Copy, PartialEq)]
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

#[derive(Clone)]
struct VirtioBlkRequest {
    user_data: usize,
}

#[derive(Clone, Copy)]
struct VirtioBlkReqBuf {
    header: VirtioBlkReqHeader,
    status: u8,
    dwz_data: DiscardWriteZeroesData,
}

/// A queue of a virtio-blk device.
///
/// This is used to send block I/O requests to the device and receive completions. Note that
/// calling transport specific functions may need to be called before or after certain operations
/// on the `VirtioBlkQueue`:
///
/// * All request methods only enqueue the requests in the rings. They don't notify the device of
///   new requests, so it may or may not start processing them. Write to the `EventFd` returned
///   by [`VirtioTransport::get_submission_fd`] after queuing requests to notify the device. You
///   can queue multiple requests and then send a single notification for all of them.
///
/// * To be notified of new completions, use the `EventFd` returned by
///   [`VirtioTransport::get_completion_fd`].
///
/// Use [`setup_queues`] to create the queues for a device.
///
/// # Examples
///
/// ```
/// use std::os::unix::io::AsRawFd;
///
/// // Connect to the vhost-user socket and create the queues
/// let mut vhost = VhostUser::new("/tmp/vhost.sock").unwrap();
/// let mut queues = VirtioBlkQueue::setup_queues(&mut vhost, 1, 128).unwrap();
///
/// // Create shared memory that is visible for the device
/// let mem_file = memfd::MemfdOptions::new().create("guest-ram").unwrap().into_file();
/// mem_file.set_len(512).unwrap();
/// let mut mem = unsafe { memmap::MmapMut::map_mut(&mem_file) }.unwrap();
/// vhost.add_mem_region(mem.as_ptr() as usize, 512, mem_file.as_raw_fd(), 0).unwrap();
///
/// // Submit a request
/// queues[0].read(0, &mut mem, 1234).unwrap();
/// vhost.get_submission_fd().write(1).unwrap();
///
/// // Wait for its completion
/// let mut done = false;
/// while !done {
///     let ret = vhost.get_completion_fd().read();
///     if ret.is_err() {
///         continue;
///     }
///
///     for c in queues[0].completions() {
///         println!("Completed request {}, return value {}", c.user_data, c.ret);
///         done = true;
///     }
/// }
/// ```
///
/// [`setup_queues`]: Self::setup_queues
pub struct VirtioBlkQueue<'a> {
    vq: Virtqueue<'a, VirtioBlkReqBuf>,
    requests: Box<[Option<VirtioBlkRequest>]>,
}

impl<'a> VirtioBlkQueue<'a> {
    fn new(vq: Virtqueue<'a, VirtioBlkReqBuf>) -> Self {
        let queue_size = vq.queue_size().into();
        let requests = vec![None; queue_size].into_boxed_slice();

        Self { vq, requests }
    }

    /// Creates the queues for a virtio-blk device.
    pub fn setup_queues(
        transport: &mut impl VirtioTransport,
        num_queues: usize,
        queue_size: u16,
    ) -> Result<Vec<Self>, Error> {
        if transport.max_queues() < num_queues {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Too many queues requested",
            ));
        }

        let layout = VirtqueueLayout::new::<VirtioBlkReqBuf>(num_queues, queue_size as usize)?;
        let queues: Vec<_> = {
            let mem = transport.alloc_queue_mem(&layout)?;
            (0..num_queues)
                .map(|i| {
                    let mem_queue = unsafe {
                        std::slice::from_raw_parts_mut(
                            &mut mem[i * layout.end_offset] as *mut u8,
                            layout.end_offset,
                        )
                    };
                    Virtqueue::new(mem_queue, queue_size)
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
        user_data: usize,
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

        let old = self.requests[desc_idx as usize].replace(VirtioBlkRequest { user_data });
        assert!(old.is_none());

        Ok(())
    }

    fn queue_request(
        &mut self,
        req_type: VirtioBlkReqType,
        offset: u64,
        buf: &[iovec],
        user_data: usize,
    ) -> Result<(), Error> {
        self.queue_request_full(req_type, offset, buf, None, user_data)
    }

    /// Reads from the disk image into a given iovec.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
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
        user_data: usize,
    ) -> Result<(), Error> {
        let iov = unsafe { std::slice::from_raw_parts(iovec, iovcnt) };
        self.queue_request(VirtioBlkReqType::Read, offset, iov, user_data)
    }

    /// Reads from the disk image into a given buffer.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
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
        user_data: usize,
    ) -> Result<(), Error> {
        let iov = iovec {
            iov_base: buf as *mut c_void,
            iov_len: len,
        };

        self.queue_request(VirtioBlkReqType::Read, offset, &[iov], user_data)
    }

    /// Reads from the disk image into a given byte slice.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn read(&mut self, offset: u64, buf: &mut [u8], user_data: usize) -> Result<(), Error> {
        unsafe { self.read_raw(offset, buf.as_mut_ptr(), buf.len(), user_data) }
    }

    /// Writes to the disk image from a given iovec.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
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
        user_data: usize,
    ) -> Result<(), Error> {
        let iov = unsafe { std::slice::from_raw_parts(iovec, iovcnt) };
        self.queue_request(VirtioBlkReqType::Write, offset, iov, user_data)
    }

    /// Writes to the disk image from a given buffer.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
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
        user_data: usize,
    ) -> Result<(), Error> {
        let iov = iovec {
            iov_base: buf as *mut c_void,
            iov_len: len,
        };

        self.queue_request(VirtioBlkReqType::Write, offset, &[iov], user_data)
    }

    /// Writes to the disk image from a given byte slice.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn write(&mut self, offset: u64, buf: &[u8], user_data: usize) -> Result<(), Error> {
        unsafe { self.write_raw(offset, buf.as_ptr(), buf.len(), user_data) }
    }

    /// Discards an area in the disk image.
    ///
    /// After completion, the content of the specified area is undefined. Discard is only a hint
    /// and doing nothing is a valid implementation. This means that the discarded data may remain
    /// accessible, this is not a way to safely delete data.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn discard(&mut self, offset: u64, len: u64, user_data: usize) -> Result<(), Error> {
        let dwz_data = DiscardWriteZeroesData::new(offset, len, true)?;
        self.queue_request_full(VirtioBlkReqType::Discard, 0, &[], Some(dwz_data), user_data)
    }

    /// Zeroes out an area in the disk image.
    ///
    /// If `unmap` is `true`, the area is tried to be deallocated if we know that it will read back
    /// as all zeroes afterwards. If it is `false`, allocated parts will remain allocated.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn write_zeroes(
        &mut self,
        offset: u64,
        len: u64,
        unmap: bool,
        user_data: usize,
    ) -> Result<(), Error> {
        let dwz_data = DiscardWriteZeroesData::new(offset, len, unmap)?;
        self.queue_request_full(
            VirtioBlkReqType::WriteZeroes,
            0,
            &[],
            Some(dwz_data),
            user_data,
        )
    }

    /// Flushes the disk cache.
    ///
    /// This ensures that on successful completion, any requests that had completed before this
    /// flush request was issued are not sitting in any writeback cache, but are actually stored on
    /// disk.
    ///
    /// `user_data` is an arbitrary caller-defined value that is returned in the corresponding
    /// [`Completion`] to allow associating the result with a specific request.
    pub fn flush(&mut self, user_data: usize) -> Result<(), Error> {
        self.queue_request(VirtioBlkReqType::Flush, 0, &[], user_data)
    }

    /// Returns the result for any completed requests.
    pub fn completions(&mut self) -> CompletionIter<'_, 'a> {
        CompletionIter {
            it: self.vq.completions(),
            requests: &mut self.requests,
        }
    }
}

pub struct CompletionIter<'a, 'queue> {
    it: VirtqueueIter<'a, 'queue, VirtioBlkReqBuf>,
    requests: &'a mut Box<[Option<VirtioBlkRequest>]>,
}

impl<'queue> Iterator for CompletionIter<'_, 'queue> {
    type Item = Completion;

    fn next(&mut self) -> Option<Self::Item> {
        self.it.next().and_then(|completion| {
            let req = self.requests[completion.idx as usize].take();

            // If the backend sent a completion for a request we never made, just ignore it.
            req.map(|req| Completion {
                user_data: req.user_data,
                ret: match completion.req.status {
                    0 => 0,
                    1 => -EIO,
                    2 => -ENOTSUP,
                    _ => -EPROTO,
                },
            })
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.it.size_hint()
    }
}
