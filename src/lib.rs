// SPDX-License-Identifier: (MIT OR Apache-2.0)

#![deny(unsafe_op_in_unsafe_fn)]

use bitflags::bitflags;
use std::io::Error;

mod devices;
mod transports;
mod util;
pub mod virtqueue;

pub use devices::*;
pub use transports::*;
pub use util::bytevalued::*;
pub use util::endian::*;
pub use util::eventfd::*;
use util::iova::*;
pub use util::sock_ctrl_msg::*;

// Reexport `iovec` since it appear in public APIs.
pub use libc::iovec;

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
