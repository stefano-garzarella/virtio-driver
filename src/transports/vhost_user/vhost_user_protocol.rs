// SPDX-License-Identifier: (MIT OR Apache-2.0)

//! Structures and constants defined by vhost-user protocol
//! https://qemu.readthedocs.io/en/latest/interop/vhost-user.html

use crate::ScmSocket;
use bitflags::bitflags;
use std::io::{Error, ErrorKind, IoSlice};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::slice;

pub const VHOST_USER_VERSION_MASK: u32 = 3;
pub const VHOST_USER_VERSION_1: u32 = 1;

pub const VHOST_USER_SET_VRING_INDEX_MASK: u64 = 255;

bitflags! {
    pub struct VhostUserVirtioFeatures: u64 {
        const PROTOCOL_FEATURES = 1 << 30;
    }
}

bitflags! {
    pub struct VhostUserProtocolFeatures: u64 {
        const MQ = 1 << 0;
        const REPLY_ACK = 1 << 3;
        const CONFIG = 1 << 9;
        const CONFIGURE_MEM_SLOTS = 1 << 15;
    }
}

bitflags! {
    pub struct VhostUserHeaderFlag: u32 {
        const REPLY = 1 << 2;
        const NEED_REPLY = 1 << 3;
    }
}

pub struct VhostUserRequest;
impl VhostUserRequest {
    pub const GET_FEATURES: u32 = 1;
    pub const SET_FEATURES: u32 = 2;
    pub const SET_OWNER: u32 = 3;
    pub const SET_VRING_NUM: u32 = 8;
    pub const SET_VRING_ADDR: u32 = 9;
    pub const SET_VRING_BASE: u32 = 10;
    pub const SET_VRING_KICK: u32 = 12;
    pub const SET_VRING_CALL: u32 = 13;
    pub const GET_PROTOCOL_FEATURES: u32 = 15;
    pub const SET_PROTOCOL_FEATURES: u32 = 16;
    pub const GET_QUEUE_NUM: u32 = 17;
    pub const SET_VRING_ENABLE: u32 = 18;
    pub const GET_CONFIG: u32 = 24;
    pub const SET_CONFIG: u32 = 25;
    pub const GET_MAX_MEM_SLOTS: u32 = 36;
    pub const ADD_MEM_REG: u32 = 37;
    pub const REM_MEM_REG: u32 = 38;
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct VhostUserHeader {
    pub request: u32,
    pub flags: u32,
    pub size: u32,
}

impl VhostUserHeader {
    pub fn new(request: u32, flags: VhostUserHeaderFlag, size: u32) -> Self {
        VhostUserHeader {
            request,
            flags: flags.bits() | VHOST_USER_VERSION_1,
            size,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VhostUserConfigHeader {
    pub offset: u32,
    pub size: u32,
    pub flags: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VhostUserConfig {
    pub header: VhostUserConfigHeader,
    pub region: [u8; 256usize],
}

impl Default for VhostUserConfig {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VhostUserMemoryRegion {
    pub guest_addr: u64,
    pub size: u64,
    pub user_addr: u64,
    pub mmap_offset: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VhostUserSingleMemReg {
    pub padding: u64,
    pub region: VhostUserMemoryRegion,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VhostUserVringState {
    pub index: u32,
    pub num: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VhostUserVringAddr {
    pub index: u32,
    pub flags: u32,
    pub descriptor_addr: u64,
    pub used_addr: u64,
    pub available_addr: u64,
    pub log_guest_addr: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union VhostUserPayload {
    pub u64_: u64,
    pub state: VhostUserVringState,
    pub addr: VhostUserVringAddr,
    pub single_mem_reg: VhostUserSingleMemReg,
    pub config: VhostUserConfig,
}

impl Default for VhostUserPayload {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// vhost-user message exchanged by front-end and back-end
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserMsg {
    pub hdr: VhostUserHeader,
    pub payload: VhostUserPayload,
}

impl VhostUserMsg {
    fn send_with_fds(&self, backend: &UnixStream, fds: &[RawFd]) -> Result<(), Error> {
        if self.hdr.size as usize > std::mem::size_of::<VhostUserPayload>() {
            return Err(Error::new(
                ErrorKind::Other,
                "failed to send vhost-user message, payload exceeds the maximum".to_string(),
            ));
        }

        let to_send = std::mem::size_of::<VhostUserHeader>() + self.hdr.size as usize;
        let data =
            unsafe { slice::from_raw_parts(self as *const VhostUserMsg as *const u8, to_send) };

        let mut sent: usize = 0;

        while sent < to_send {
            let buf = IoSlice::new(&data[sent..]);
            let bytes = backend.send_with_fds(&[buf], fds)?;
            if bytes == 0 {
                return Err(Error::new(
                    ErrorKind::Other,
                    "failed to send msg".to_string(),
                ));
            }

            sent += bytes;
        }

        Ok(())
    }

    /// Send the vhost-user message to the other side.
    /// The header is always sent, followed by `self.hdr.size` bytes of payload
    ///
    /// `backend` is the Unix Domain Socket connected to the other side
    pub fn send(&self, backend: &UnixStream) -> Result<(), Error> {
        self.send_with_fds(backend, &[])
    }

    /// Send the vhost-user message and file descriptor to the other side
    /// The header is always sent, followed by `self.hdr.size` bytes of payload
    ///
    /// `backend` is the Unix Domain Socket connected to the other side
    /// `fd` is the file descriptor to send with control message
    pub fn send_with_fd(&self, backend: &UnixStream, fd: RawFd) -> Result<(), Error> {
        self.send_with_fds(backend, &[fd])
    }

    /// Receive data from the other side and fill the vhost-user message
    ///
    /// `backend` is the Unix Domain Socket connected to the other side
    pub fn recv(&mut self, backend: &UnixStream) -> Result<(), Error> {
        fn recv_all(backend: &UnixStream, data: &mut [u8]) -> Result<(), Error> {
            let mut received: usize = 0;

            while received < data.len() {
                let (bytes, _) = backend.recv_with_fds(&mut data[received..], &mut [])?;
                if bytes == 0 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "failed to receive vhost-user message".to_string(),
                    ));
                }

                received += bytes;
            }

            Ok(())
        }

        let header_buf = unsafe {
            slice::from_raw_parts_mut(
                &self.hdr as *const VhostUserHeader as *mut u8,
                std::mem::size_of::<VhostUserHeader>(),
            )
        };

        recv_all(backend, header_buf)?;

        if (self.hdr.flags & VHOST_USER_VERSION_MASK) != VHOST_USER_VERSION_1 {
            return Err(Error::new(
                ErrorKind::Other,
                "unexpected version in the header".to_string(),
            ));
        }

        if self.hdr.size == 0 {
            return Ok(());
        }

        if self.hdr.size as usize > std::mem::size_of::<VhostUserPayload>() {
            return Err(Error::new(
                ErrorKind::Other,
                "failed to read vhost-user message, payload exceeds the maximum".to_string(),
            ));
        }

        // We can't create a reference to `self.payload` because it would be unaligned, and we can't
        // use `std::ptr::addr_of` since it isn't available in Rust 1.48. But we know that we have a
        // single field of type `VhostUserHeader` before the `self.payload` field, and that there is
        // no padding because `VhostUserMsg` is packed, so we just get a pointer to `self` and
        // advance it by the size of `VhostUserHeader`.
        let payload_offset = std::mem::size_of::<VhostUserHeader>();
        let payload_buf = unsafe {
            slice::from_raw_parts_mut(
                (self as *const VhostUserMsg as *mut u8).add(payload_offset),
                self.hdr.size as usize,
            )
        };

        recv_all(backend, payload_buf)?;

        Ok(())
    }

    /// Check if a received message is a correct reply for this vhost-user message
    ///
    /// `reply` contains the message received as a reply
    /// `expected_size` is the expected size od the reply's payload
    pub fn check_reply(&self, reply: &VhostUserMsg, expected_size: u32) -> Result<(), Error> {
        let reply_flags = VhostUserHeaderFlag::from_bits_truncate(reply.hdr.flags);

        if reply.hdr.request != self.hdr.request
            || !reply_flags.contains(VhostUserHeaderFlag::REPLY)
            || reply.hdr.size != expected_size
        {
            return Err(Error::new(
                ErrorKind::Other,
                "received unexpected vhost-user message type".to_string(),
            ));
        }

        Ok(())
    }
}
