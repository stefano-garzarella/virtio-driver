// SPDX-License-Identifier: (MIT OR Apache-2.0)

use super::vhost_bindings::{
    vhost_iotlb_msg, vhost_vdpa_config, vhost_vdpa_iova_range, vhost_vring_addr, vhost_vring_file,
    vhost_vring_state, VHOST_ACCESS_RO, VHOST_ACCESS_RW, VHOST_BACKEND_F_IOTLB_MSG_V2,
    VHOST_IOTLB_INVALIDATE, VHOST_IOTLB_UPDATE,
};
use std::alloc::{alloc, dealloc, Layout};
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::mem;
use std::ops::RangeInclusive;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

mod kuapi {
    use super::super::vhost_bindings::*;
    use libc::{c_ulong, ioctl};
    use rustix::fd::AsFd;
    use rustix::io::write;
    use std::io::Error;
    use std::os::unix::io::RawFd;

    const IOC_NRBITS: c_ulong = 8;
    const IOC_TYPEBITS: c_ulong = 8;
    const IOC_SIZEBITS: c_ulong = 14;

    const IOC_NRSHIFT: c_ulong = 0;
    const IOC_TYPESHIFT: c_ulong = IOC_NRSHIFT + IOC_NRBITS;
    const IOC_SIZESHIFT: c_ulong = IOC_TYPESHIFT + IOC_TYPEBITS;
    const IOC_DIRSHIFT: c_ulong = IOC_SIZESHIFT + IOC_SIZEBITS;

    const IOC_NONE: c_ulong = 0;
    const IOC_WRITE: c_ulong = 1;
    const IOC_READ: c_ulong = 2;

    const fn ioctl_cmd<T>(dir: c_ulong, ty: c_ulong, nr: c_ulong) -> c_ulong {
        (dir << IOC_DIRSHIFT)
            | (ty << IOC_TYPESHIFT)
            | (nr << IOC_NRSHIFT)
            | ((std::mem::size_of::<T>() as c_ulong) << IOC_SIZESHIFT)
    }

    fn ioctl_return_to_result(ret: i32) -> Result<i32, Error> {
        if ret >= 0 {
            Ok(ret)
        } else {
            Err(Error::last_os_error())
        }
    }

    macro_rules! ioctl_none {
        ($name:ident, $ty:expr, $nr:expr) => {
            pub unsafe fn $name(fd: RawFd) -> Result<i32, Error> {
                const CMD: c_ulong = ioctl_cmd::<()>(IOC_NONE, $ty as c_ulong, $nr as c_ulong);
                let ret = unsafe { ioctl(fd, CMD) };
                ioctl_return_to_result(ret)
            }
        };
    }

    macro_rules! ioctl_write_ptr {
        ($name:ident, $ty:expr, $nr:expr, $arg:ty) => {
            pub unsafe fn $name(fd: RawFd, arg: *const $arg) -> Result<i32, Error> {
                const CMD: c_ulong = ioctl_cmd::<$arg>(IOC_WRITE, $ty as c_ulong, $nr as c_ulong);
                let ret = unsafe { ioctl(fd, CMD, arg) };
                ioctl_return_to_result(ret)
            }
        };
    }

    macro_rules! ioctl_read {
        ($name:ident, $ty:expr, $nr:expr, $arg:ty) => {
            pub unsafe fn $name(fd: RawFd, arg: *mut $arg) -> Result<i32, Error> {
                const CMD: c_ulong = ioctl_cmd::<$arg>(IOC_READ, $ty as c_ulong, $nr as c_ulong);
                let ret = unsafe { ioctl(fd, CMD, arg) };
                ioctl_return_to_result(ret)
            }
        };
    }

    ioctl_read!(vhost_get_features, VHOST_VIRTIO, 0x00, u64);
    ioctl_write_ptr!(vhost_set_features, VHOST_VIRTIO, 0x00, u64);
    ioctl_none!(vhost_set_owner, VHOST_VIRTIO, 0x01);
    ioctl_write_ptr!(vhost_set_vring_num, VHOST_VIRTIO, 0x10, vhost_vring_state);
    ioctl_write_ptr!(vhost_set_vring_addr, VHOST_VIRTIO, 0x11, vhost_vring_addr);
    ioctl_write_ptr!(vhost_set_vring_base, VHOST_VIRTIO, 0x12, vhost_vring_state);
    ioctl_write_ptr!(vhost_set_vring_kick, VHOST_VIRTIO, 0x20, vhost_vring_file);
    ioctl_write_ptr!(vhost_set_vring_call, VHOST_VIRTIO, 0x21, vhost_vring_file);
    ioctl_write_ptr!(vhost_set_backend_features, VHOST_VIRTIO, 0x25, u64);
    ioctl_read!(vhost_get_backend_features, VHOST_VIRTIO, 0x26, u64);

    // ioctl_read!(vhost_vdpa_get_device_id, VHOST_VIRTIO, 0x70, u32);
    ioctl_read!(vhost_vdpa_get_status, VHOST_VIRTIO, 0x71, u8);
    ioctl_write_ptr!(vhost_vdpa_set_status, VHOST_VIRTIO, 0x72, u8);
    ioctl_read!(vhost_vdpa_get_config, VHOST_VIRTIO, 0x73, vhost_vdpa_config);
    ioctl_write_ptr!(vhost_vdpa_set_config, VHOST_VIRTIO, 0x74, vhost_vdpa_config);
    ioctl_write_ptr!(
        vhost_vdpa_set_vring_enable,
        VHOST_VIRTIO,
        0x75,
        vhost_vring_state
    );
    // ioctl_read!(vhost_vdpa_get_vring_num, VHOST_VIRTIO, 0x76, u16);
    ioctl_read!(
        vhost_vdpa_get_iova_range,
        VHOST_VIRTIO,
        0x78,
        vhost_vdpa_iova_range
    );
    ioctl_read!(vhost_vdpa_get_vqs_count, VHOST_VIRTIO, 0x80, u32);

    pub fn send_iotlb_msg(
        fd: impl AsFd,
        iotlb: &vhost_iotlb_msg,
        backend_features_acked: u64,
    ) -> Result<(), Error> {
        if backend_features_acked & (1 << VHOST_BACKEND_F_IOTLB_MSG_V2) != 0 {
            let mut msg = vhost_msg_v2 {
                type_: VHOST_IOTLB_MSG_V2,
                ..Default::default()
            };

            msg.__bindgen_anon_1.iotlb = *iotlb;

            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    &msg as *const vhost_msg_v2 as *const u8,
                    std::mem::size_of::<vhost_msg_v2>(),
                )
            };

            write(fd, buf)?;
        } else {
            let mut msg = vhost_msg {
                type_: VHOST_IOTLB_MSG as i32,
                ..Default::default()
            };

            msg.__bindgen_anon_1.iotlb = *iotlb;

            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    &msg as *const vhost_msg as *const u8,
                    std::mem::size_of::<vhost_msg>(),
                )
            };

            write(fd, buf)?;
        }

        Ok(())
    }
}

pub struct VhostVdpaKernel {
    backend: File,
    backend_features_acked: u64,
}

impl VhostVdpaKernel {
    pub fn with_path(path: &str) -> Result<Self, Error> {
        let mut vdpa = VhostVdpaKernel {
            backend: OpenOptions::new()
                .custom_flags(libc::O_CLOEXEC)
                .write(true)
                .open(path)?,
            backend_features_acked: 0,
        };

        vdpa.connect()?;

        Ok(vdpa)
    }

    pub unsafe fn with_fd(fd: RawFd) -> Result<Self, Error> {
        let mut vdpa = VhostVdpaKernel {
            backend: unsafe { File::from_raw_fd(fd) },
            backend_features_acked: 0,
        };

        vdpa.connect()?;

        Ok(vdpa)
    }

    fn connect(&mut self) -> Result<(), Error> {
        unsafe { kuapi::vhost_set_owner(self.backend.as_raw_fd())? };

        let backend_features = self.get_backend_features()?;
        // We only need VHOST_BACKEND_F_IOTLB_MSG_V2 (if available) to support
        // dma_map/dma_unmap messages
        self.set_backend_features(backend_features & VHOST_BACKEND_F_IOTLB_MSG_V2 as u64)?;

        Ok(())
    }

    fn get_backend_features(&self) -> Result<u64, Error> {
        let mut features: u64 = 0;

        unsafe { kuapi::vhost_get_backend_features(self.backend.as_raw_fd(), &mut features)? };

        Ok(features)
    }

    fn set_backend_features(&mut self, features: u64) -> Result<(), Error> {
        unsafe { kuapi::vhost_set_backend_features(self.backend.as_raw_fd(), &features)? };
        self.backend_features_acked = features;
        Ok(())
    }

    pub fn set_status(&self, status: u8) -> Result<(), Error> {
        unsafe { kuapi::vhost_vdpa_set_status(self.backend.as_raw_fd(), &status)? };

        Ok(())
    }

    fn get_status(&self) -> Result<u8, Error> {
        let mut status: u8 = 0;

        unsafe { kuapi::vhost_vdpa_get_status(self.backend.as_raw_fd(), &mut status)? };

        Ok(status)
    }

    pub fn add_status(&mut self, status: u8) -> Result<(), Error> {
        let mut current_status = self.get_status()?;

        self.set_status(current_status | status)?;

        current_status = self.get_status()?;
        if (current_status & status) != status {
            return Err(Error::new(
                ErrorKind::Other,
                "failed to set the status".to_string(),
            ));
        }

        Ok(())
    }

    pub fn get_features(&self) -> Result<u64, Error> {
        let mut features: u64 = 0;

        unsafe { kuapi::vhost_get_features(self.backend.as_raw_fd(), &mut features)? };

        Ok(features)
    }

    pub fn set_features(&self, features: u64) -> Result<(), Error> {
        unsafe { kuapi::vhost_set_features(self.backend.as_raw_fd(), &features)? };

        Ok(())
    }

    pub fn set_vring_num(&self, queue_idx: usize, num: u32) -> Result<(), Error> {
        let param = vhost_vring_state {
            index: queue_idx as u32,
            num,
        };

        unsafe { kuapi::vhost_set_vring_num(self.backend.as_raw_fd(), &param)? };

        Ok(())
    }

    pub fn set_vring_addr(
        &self,
        queue_idx: usize,
        desc_user_addr: u64,
        used_user_addr: u64,
        avail_user_addr: u64,
    ) -> Result<(), Error> {
        let param = vhost_vring_addr {
            index: queue_idx as u32,
            flags: 0,
            desc_user_addr,
            used_user_addr,
            avail_user_addr,
            log_guest_addr: 0,
        };

        unsafe { kuapi::vhost_set_vring_addr(self.backend.as_raw_fd(), &param)? };

        Ok(())
    }

    pub fn set_vring_base(&self, queue_idx: usize, base: u32) -> Result<(), Error> {
        let param = vhost_vring_state {
            index: queue_idx as u32,
            num: base,
        };

        unsafe { kuapi::vhost_set_vring_base(self.backend.as_raw_fd(), &param)? };

        Ok(())
    }

    pub fn set_vring_kick(&self, queue_idx: usize, fd: RawFd) -> Result<(), Error> {
        let param = vhost_vring_file {
            index: queue_idx as u32,
            fd,
        };

        unsafe { kuapi::vhost_set_vring_kick(self.backend.as_raw_fd(), &param)? };

        Ok(())
    }

    pub fn set_vring_call(&self, queue_idx: usize, fd: RawFd) -> Result<(), Error> {
        let param = vhost_vring_file {
            index: queue_idx as u32,
            fd,
        };

        unsafe { kuapi::vhost_set_vring_call(self.backend.as_raw_fd(), &param)? };

        Ok(())
    }

    pub fn set_vring_enable(&self, queue_idx: usize, enabled: bool) -> Result<(), Error> {
        let param = vhost_vring_state {
            index: queue_idx as u32,
            num: enabled as u32,
        };

        unsafe { kuapi::vhost_vdpa_set_vring_enable(self.backend.as_raw_fd(), &param)? };

        Ok(())
    }

    pub fn get_config(&self, offset: u32, buffer: &mut [u8]) -> Result<(), Error> {
        let buffer_len = buffer.len();
        let layout =
            Layout::from_size_align(mem::size_of::<vhost_vdpa_config>() + buffer_len, 1).unwrap();

        unsafe {
            let ptr = alloc(layout);
            let config = ptr as *mut vhost_vdpa_config;
            (*config).off = offset;
            (*config).len = buffer_len as u32;

            let ret = kuapi::vhost_vdpa_get_config(self.backend.as_raw_fd(), config);

            buffer.copy_from_slice((*config).buf.as_slice(buffer_len));

            dealloc(ptr, layout);

            match ret {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::new(ErrorKind::InvalidInput, e)),
            }
        }
    }

    #[allow(dead_code)]
    pub fn set_config(&self, offset: u32, buffer: &[u8]) -> Result<(), Error> {
        let buffer_len = buffer.len();
        let layout =
            Layout::from_size_align(mem::size_of::<vhost_vdpa_config>() + buffer_len, 1).unwrap();

        unsafe {
            let ptr = alloc(layout);
            let config = ptr as *mut vhost_vdpa_config;
            (*config).off = offset;
            (*config).len = buffer_len as u32;

            (*config)
                .buf
                .as_mut_slice(buffer_len)
                .copy_from_slice(buffer);

            let ret = kuapi::vhost_vdpa_set_config(self.backend.as_raw_fd(), config);

            dealloc(ptr, layout);

            match ret {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::new(ErrorKind::InvalidInput, e)),
            }
        }
    }

    pub fn get_iova_range(&self) -> Result<RangeInclusive<u64>, Error> {
        let mut iova = vhost_vdpa_iova_range::default();

        unsafe { kuapi::vhost_vdpa_get_iova_range(self.backend.as_raw_fd(), &mut iova)? };

        Ok(iova.first..=iova.last)
    }

    pub fn get_vqs_count(&self) -> Result<u32, Error> {
        let mut count: u32 = 0;

        unsafe { kuapi::vhost_vdpa_get_vqs_count(self.backend.as_raw_fd(), &mut count)? };

        Ok(count)
    }

    pub fn dma_map(
        &self,
        iova: u64,
        size: u64,
        uaddr: *const u8,
        readonly: bool,
    ) -> Result<(), Error> {
        let iotlb = vhost_iotlb_msg {
            iova,
            size,
            uaddr: uaddr as u64,
            perm: match readonly {
                true => VHOST_ACCESS_RO as u8,
                false => VHOST_ACCESS_RW as u8,
            },
            type_: VHOST_IOTLB_UPDATE as u8,
        };

        kuapi::send_iotlb_msg(&self.backend, &iotlb, self.backend_features_acked)
    }

    pub fn dma_unmap(&self, iova: u64, size: u64) -> Result<(), Error> {
        let iotlb = vhost_iotlb_msg {
            iova,
            size,
            type_: VHOST_IOTLB_INVALIDATE as u8,
            ..Default::default()
        };

        kuapi::send_iotlb_msg(&self.backend, &iotlb, self.backend_features_acked)
    }
}
