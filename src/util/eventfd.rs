// SPDX-License-Identifier: (MIT OR Apache-2.0)

use nix::sys::eventfd::eventfd;
pub use nix::sys::eventfd::EfdFlags;
use nix::unistd::{read, write};
use std::fs::File;
use std::io::Error;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

#[derive(Debug)]
pub struct EventFd {
    file: File,
}

impl EventFd {
    #[allow(dead_code)] // unused when virtio-driver is build with no features enabled
    pub(crate) fn new(flags: EfdFlags) -> Result<Self, Error> {
        let fd = eventfd(0, flags)?;
        let file = unsafe { File::from_raw_fd(fd) };

        Ok(EventFd { file })
    }

    pub fn read(&self) -> Result<u64, Error> {
        let mut buf = [0u8; 8];

        read(self.file.as_raw_fd(), &mut buf)?;

        Ok(u64::from_ne_bytes(buf))
    }

    pub fn write(&self, val: u64) -> Result<(), Error> {
        let buf = val.to_ne_bytes();

        write(self.file.as_raw_fd(), &buf)?;

        Ok(())
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
