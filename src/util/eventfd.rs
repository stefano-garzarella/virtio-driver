// SPDX-License-Identifier: (MIT OR Apache-2.0)

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
pub use rustix::io::EventfdFlags;
use rustix::io::{eventfd, read, write};
use std::io::Error;
use std::os::unix::io::{AsRawFd, RawFd};

#[derive(Debug)]
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    #[allow(dead_code)] // unused when virtio-driver is build with no features enabled
    pub(crate) fn new(flags: EventfdFlags) -> Result<Self, Error> {
        let fd = eventfd(0, flags)?;
        Ok(EventFd { fd })
    }

    pub fn read(&self) -> Result<u64, Error> {
        let mut buf = [0u8; 8];

        read(&self.fd, &mut buf)?;

        Ok(u64::from_ne_bytes(buf))
    }

    pub fn write(&self, val: u64) -> Result<(), Error> {
        let buf = val.to_ne_bytes();

        write(&self.fd, &buf)?;

        Ok(())
    }
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd {
        self.fd.as_fd()
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
