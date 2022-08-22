// SPDX-License-Identifier: (MIT OR Apache-2.0)

//! Partial implementation of vhost-user front-end side
//! https://qemu.readthedocs.io/en/latest/interop/vhost-user.html#front-end-message-types
//!
//! Currently only the features needed by vhost-user-blk are implemented.

use std::io::{Error, ErrorKind};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

use super::vhost_user_protocol::*;

pub struct VhostUserMemoryRegionInfo {
    pub mr: VhostUserMemoryRegion,
    pub fd: RawFd,
}

pub struct VhostUserFrontEnd {
    backend: UnixStream,
    protocol_features_acked: VhostUserProtocolFeatures,
    hdr_flags: VhostUserHeaderFlag,
}

impl VhostUserFrontEnd {
    /// Creates a new vhost-user front-end side handler
    ///
    /// `path` contains the Unix Domain Socket path to connect to the back-end
    pub fn new(path: &str) -> Result<Self, Error> {
        let vhost = VhostUserFrontEnd {
            backend: UnixStream::connect(path)?,
            protocol_features_acked: VhostUserProtocolFeatures::empty(),
            hdr_flags: VhostUserHeaderFlag::empty(),
        };

        Ok(vhost)
    }

    fn get_u64(&self, request: u32) -> Result<u64, Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(request, self.hdr_flags, 0),
            ..Default::default()
        };

        msg.send(&self.backend)?;

        let mut reply = VhostUserMsg::default();
        reply.recv(&self.backend)?;

        msg.check_reply(&reply, std::mem::size_of::<u64>() as u32)?;

        Ok(unsafe { reply.payload.u64_ })
    }

    fn set_u64(&self, request: u32, value: u64) -> Result<(), Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(request, self.hdr_flags, std::mem::size_of::<u64>() as u32),
            payload: VhostUserPayload { u64_: value },
        };

        msg.send(&self.backend)?;
        self.wait_ack(&msg)
    }

    fn wait_ack(&self, msg: &VhostUserMsg) -> Result<(), Error> {
        let msg_flags = VhostUserHeaderFlag::from_bits_truncate(msg.hdr.flags);

        if !msg_flags.contains(VhostUserHeaderFlag::NEED_REPLY)
            || !self
                .protocol_features_acked
                .contains(VhostUserProtocolFeatures::REPLY_ACK)
        {
            return Ok(());
        }

        let mut reply = VhostUserMsg::default();

        reply.recv(&self.backend)?;

        msg.check_reply(&reply, std::mem::size_of::<u64>() as u32)?;

        if unsafe { reply.payload.u64_ } != 0 {
            return Err(Error::new(
                ErrorKind::Other,
                "reply contains an error".to_string(),
            ));
        }

        Ok(())
    }

    pub fn set_hdr_flags(&mut self, flags: VhostUserHeaderFlag) {
        self.hdr_flags = flags;
    }

    pub fn set_owner(&self) -> Result<(), Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(VhostUserRequest::SET_OWNER, self.hdr_flags, 0),
            ..Default::default()
        };

        msg.send(&self.backend)?;
        self.wait_ack(&msg)
    }

    pub fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures, Error> {
        let features = self.get_u64(VhostUserRequest::GET_PROTOCOL_FEATURES)?;

        Ok(unsafe { VhostUserProtocolFeatures::from_bits_unchecked(features) })
    }

    pub fn set_protocol_features(
        &mut self,
        features: VhostUserProtocolFeatures,
    ) -> Result<(), Error> {
        self.set_u64(VhostUserRequest::SET_PROTOCOL_FEATURES, features.bits())?;

        self.protocol_features_acked = features;

        Ok(())
    }

    pub fn get_queue_num(&self) -> Result<u64, Error> {
        self.get_u64(VhostUserRequest::GET_QUEUE_NUM)
    }

    pub fn get_max_mem_slots(&self) -> Result<u64, Error> {
        self.get_u64(VhostUserRequest::GET_MAX_MEM_SLOTS)
    }

    pub fn get_features(&self) -> Result<u64, Error> {
        self.get_u64(VhostUserRequest::GET_FEATURES)
    }

    pub fn set_features(&self, features: u64) -> Result<(), Error> {
        self.set_u64(VhostUserRequest::SET_FEATURES, features)
    }

    fn set_vring_state(&self, request: u32, index: u32, num: u32) -> Result<(), Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(
                request,
                self.hdr_flags,
                std::mem::size_of::<VhostUserVringState>() as u32,
            ),
            payload: VhostUserPayload {
                state: VhostUserVringState { index, num },
            },
        };

        msg.send(&self.backend)?;
        self.wait_ack(&msg)
    }

    pub fn set_vring_num(&self, queue_idx: usize, num: u32) -> Result<(), Error> {
        self.set_vring_state(VhostUserRequest::SET_VRING_NUM, queue_idx as u32, num)
    }

    pub fn set_vring_addr(
        &self,
        queue_idx: usize,
        descriptor_addr: u64,
        used_addr: u64,
        available_addr: u64,
    ) -> Result<(), Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(
                VhostUserRequest::SET_VRING_ADDR,
                self.hdr_flags,
                std::mem::size_of::<VhostUserVringAddr>() as u32,
            ),
            payload: VhostUserPayload {
                addr: VhostUserVringAddr {
                    index: queue_idx as u32,
                    flags: 0,
                    descriptor_addr,
                    used_addr,
                    available_addr,
                    log_guest_addr: 0,
                },
            },
        };

        msg.send(&self.backend)?;
        self.wait_ack(&msg)
    }

    pub fn set_vring_base(&self, queue_idx: usize, base: u32) -> Result<(), Error> {
        self.set_vring_state(VhostUserRequest::SET_VRING_BASE, queue_idx as u32, base)
    }

    pub fn set_vring_enable(&self, queue_idx: usize, enabled: bool) -> Result<(), Error> {
        self.set_vring_state(
            VhostUserRequest::SET_VRING_ENABLE,
            queue_idx as u32,
            enabled as u32,
        )
    }

    fn set_vring_fd(&self, request: u32, index: u64, fd: RawFd) -> Result<(), Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(request, self.hdr_flags, std::mem::size_of::<u64>() as u32),
            payload: VhostUserPayload {
                u64_: index & VHOST_USER_SET_VRING_INDEX_MASK,
            },
        };

        msg.send_with_fd(&self.backend, fd)?;
        self.wait_ack(&msg)
    }

    pub fn set_vring_kick(&self, queue_idx: usize, fd: RawFd) -> Result<(), Error> {
        self.set_vring_fd(VhostUserRequest::SET_VRING_KICK, queue_idx as u64, fd)
    }

    pub fn set_vring_call(&self, queue_idx: usize, fd: RawFd) -> Result<(), Error> {
        self.set_vring_fd(VhostUserRequest::SET_VRING_CALL, queue_idx as u64, fd)
    }

    pub fn get_config(&self, offset: u32, flags: u32, buffer: &mut [u8]) -> Result<(), Error> {
        let config_len = buffer.len() as u32;
        let payload_len = std::mem::size_of::<VhostUserConfigHeader>() as u32 + config_len;

        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(VhostUserRequest::GET_CONFIG, self.hdr_flags, payload_len),
            payload: VhostUserPayload {
                config: VhostUserConfig {
                    header: VhostUserConfigHeader {
                        offset,
                        size: config_len,
                        flags,
                    },
                    ..Default::default()
                },
            },
        };

        msg.send(&self.backend)?;

        let mut reply = VhostUserMsg::default();
        reply.recv(&self.backend)?;

        msg.check_reply(&reply, payload_len)?;

        buffer.copy_from_slice(unsafe { &reply.payload.config.region[..buffer.len()] });

        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_config(&self, offset: u32, flags: u32, buffer: &[u8]) -> Result<(), Error> {
        let config_len = buffer.len() as u32;
        let payload_len = std::mem::size_of::<VhostUserConfigHeader>() as u32 + config_len;

        let mut msg = VhostUserMsg {
            hdr: VhostUserHeader::new(VhostUserRequest::SET_CONFIG, self.hdr_flags, payload_len),
            payload: VhostUserPayload {
                config: VhostUserConfig {
                    header: VhostUserConfigHeader {
                        offset,
                        size: config_len,
                        flags,
                    },
                    ..Default::default()
                },
            },
        };

        unsafe { msg.payload.config.region.copy_from_slice(buffer) };

        msg.send(&self.backend)?;
        self.wait_ack(&msg)
    }

    fn mem_region(&self, request: u32, mri: &VhostUserMemoryRegionInfo) -> Result<(), Error> {
        let msg = VhostUserMsg {
            hdr: VhostUserHeader::new(
                request,
                self.hdr_flags,
                std::mem::size_of::<VhostUserSingleMemReg>() as u32,
            ),
            payload: VhostUserPayload {
                single_mem_reg: VhostUserSingleMemReg {
                    padding: 0,
                    region: mri.mr,
                },
            },
        };

        msg.send_with_fd(&self.backend, mri.fd)?;
        self.wait_ack(&msg)
    }

    pub fn add_mem_region(&self, mri: &VhostUserMemoryRegionInfo) -> Result<(), Error> {
        self.mem_region(VhostUserRequest::ADD_MEM_REG, mri)
    }

    pub fn remove_mem_region(&self, mri: &VhostUserMemoryRegionInfo) -> Result<(), Error> {
        self.mem_region(VhostUserRequest::REM_MEM_REG, mri)
    }
}
