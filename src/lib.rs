// SPDX-License-Identifier: (MIT OR Apache-2.0)

#![deny(unsafe_op_in_unsafe_fn)]
// Support using this crate without the standard library
#![cfg_attr(not(feature = "std"), no_std)]
// To handle std/no_std we re-include some items already included by std.
// clippy (nightly) prints warnings about that, so let's silence them
// to not complicate the inclusion.
#![cfg_attr(feature = "std", allow(unused_imports))]
// As long as there is a memory allocator, we can still use this crate
// without the rest of the standard library by using the `alloc` crate
#[cfg(feature = "alloc")]
extern crate alloc;

/// A facade around all the types we need from the `std`, `core`, and `alloc`
/// crates. This avoids elaborate import wrangling having to happen in every
/// module.
mod lib {
    mod core {
        #[cfg(not(feature = "std"))]
        pub use core::*;
        #[cfg(feature = "std")]
        pub use std::*;
    }

    mod alloc {
        #[cfg(feature = "std")]
        pub use std::*;

        #[cfg(all(feature = "alloc", not(feature = "std")))]
        pub use ::alloc::*;
    }

    #[cfg(not(feature = "std"))]
    #[allow(non_camel_case_types)]
    mod libc {
        pub use core::ffi::c_int;
        pub use core::ffi::c_void;
        pub const EIO: c_int = 5;
        pub const EPROTO: c_int = 71;
        pub const EOPNOTSUPP: c_int = 95;
        pub const ENOTSUP: c_int = EOPNOTSUPP;
        pub type size_t = usize;

        #[derive(Clone, Copy)]
        #[repr(C)]
        pub struct iovec {
            pub iov_base: *mut c_void,
            pub iov_len: size_t,
        }
    }

    // alloc modules (re-exported by `std` when have the standard library)
    pub use self::alloc::{boxed::Box, collections, format, vec, vec::Vec};
    // core modules (re-exported by `std` when have the standard library)
    pub use self::core::{iter, marker, mem, num, ops, ptr, slice, sync::atomic};

    #[cfg(feature = "std")]
    pub use std::os::unix::io::RawFd;
    #[cfg(not(feature = "std"))]
    pub type RawFd = core::ffi::c_int;

    #[cfg(feature = "std")]
    pub use ::libc::{c_void, iovec, EIO, ENOTSUP, EPROTO};
    #[cfg(not(feature = "std"))]
    pub use libc::*;
}

use bitflags::bitflags;

mod devices;
mod transports;
mod util;
pub mod virtqueue;

pub use devices::*;
pub use transports::*;
pub use util::bytevalued::*;
pub use util::endian::*;
#[cfg(feature = "std")]
pub use util::eventfd::*;
pub use util::iova::IovaSpace;
use util::iova::*;
#[cfg(feature = "std")]
pub use util::sock_ctrl_msg::*;

// Reexport `iovec` since it appear in public APIs.
pub use lib::iovec;

bitflags! {
    pub struct VirtioFeatureFlags: u64 {
        const RING_INDIRECT_DESC = 1 << 28;
        const RING_EVENT_IDX = 1 << 29;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;
        const IN_ORDER = 1 << 35;
        const ORDER_PLATFORM = 1 << 36;
        const SR_IOV = 1 << 37;
        const NOTIFICATION_DATA = 1 << 38;
        const NOTIF_CONFIG_DATA = 1 << 39;
        const RING_RESET = 1 << 40;
    }
}

/// The result of a completed request.
///
/// Type parameter `C` denotes the type of the "context" associated with the request.
pub struct Completion<C> {
    /// The user-defined "context" that was associated with the request.
    pub context: C,

    /// 0 on success, a negative `errno` value on error.
    pub ret: i32,
}
