/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#![cfg_attr(feature = "_unsafe-op-in-unsafe-fn", allow(unsafe_op_in_unsafe_fn))]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

// This file was generated by running
//
//    bindgen usr/include/linux/vhost.h \
//      --allowlist-var "VHOST.*|VIRTIO.*" --allowlist-type "vhost.*" \
//      --with-derive-default --no-layout-tests -o vhost_bindings.rs \
//      -- -I usr/include
//
// at the root of the Linux v5.19 build directory.
// The SPDX header, the lints, and this note were then added manually.

/* automatically generated by rust-bindgen 0.60.1 */

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub const VIRTIO_CONFIG_S_ACKNOWLEDGE: u32 = 1;
pub const VIRTIO_CONFIG_S_DRIVER: u32 = 2;
pub const VIRTIO_CONFIG_S_DRIVER_OK: u32 = 4;
pub const VIRTIO_CONFIG_S_FEATURES_OK: u32 = 8;
pub const VIRTIO_CONFIG_S_NEEDS_RESET: u32 = 64;
pub const VIRTIO_CONFIG_S_FAILED: u32 = 128;
pub const VIRTIO_TRANSPORT_F_START: u32 = 28;
pub const VIRTIO_TRANSPORT_F_END: u32 = 38;
pub const VIRTIO_F_NOTIFY_ON_EMPTY: u32 = 24;
pub const VIRTIO_F_ANY_LAYOUT: u32 = 27;
pub const VIRTIO_F_VERSION_1: u32 = 32;
pub const VIRTIO_F_ACCESS_PLATFORM: u32 = 33;
pub const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
pub const VIRTIO_F_RING_PACKED: u32 = 34;
pub const VIRTIO_F_IN_ORDER: u32 = 35;
pub const VIRTIO_F_ORDER_PLATFORM: u32 = 36;
pub const VIRTIO_F_SR_IOV: u32 = 37;
pub const VIRTIO_RING_F_INDIRECT_DESC: u32 = 28;
pub const VIRTIO_RING_F_EVENT_IDX: u32 = 29;
pub const VHOST_VRING_F_LOG: u32 = 0;
pub const VHOST_ACCESS_RO: u32 = 1;
pub const VHOST_ACCESS_WO: u32 = 2;
pub const VHOST_ACCESS_RW: u32 = 3;
pub const VHOST_IOTLB_MISS: u32 = 1;
pub const VHOST_IOTLB_UPDATE: u32 = 2;
pub const VHOST_IOTLB_INVALIDATE: u32 = 3;
pub const VHOST_IOTLB_ACCESS_FAIL: u32 = 4;
pub const VHOST_IOTLB_BATCH_BEGIN: u32 = 5;
pub const VHOST_IOTLB_BATCH_END: u32 = 6;
pub const VHOST_IOTLB_MSG: u32 = 1;
pub const VHOST_IOTLB_MSG_V2: u32 = 2;
pub const VHOST_PAGE_SIZE: u32 = 4096;
pub const VHOST_SCSI_ABI_VERSION: u32 = 1;
pub const VHOST_F_LOG_ALL: u32 = 26;
pub const VHOST_NET_F_VIRTIO_NET_HDR: u32 = 27;
pub const VHOST_BACKEND_F_IOTLB_MSG_V2: u32 = 1;
pub const VHOST_BACKEND_F_IOTLB_BATCH: u32 = 2;
pub const VHOST_BACKEND_F_IOTLB_ASID: u32 = 3;
pub const VHOST_FILE_UNBIND: i32 = -1;
pub const VHOST_VIRTIO: u32 = 175;
pub const VHOST_VRING_LITTLE_ENDIAN: u32 = 0;
pub const VHOST_VRING_BIG_ENDIAN: u32 = 1;
pub type __u8 = ::std::os::raw::c_uchar;
pub type __u32 = ::std::os::raw::c_uint;
pub type __u64 = ::std::os::raw::c_ulonglong;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vhost_vring_state {
    pub index: ::std::os::raw::c_uint,
    pub num: ::std::os::raw::c_uint,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vhost_vring_file {
    pub index: ::std::os::raw::c_uint,
    pub fd: ::std::os::raw::c_int,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vhost_vring_addr {
    pub index: ::std::os::raw::c_uint,
    pub flags: ::std::os::raw::c_uint,
    pub desc_user_addr: __u64,
    pub used_user_addr: __u64,
    pub avail_user_addr: __u64,
    pub log_guest_addr: __u64,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vhost_iotlb_msg {
    pub iova: __u64,
    pub size: __u64,
    pub uaddr: __u64,
    pub perm: __u8,
    pub type_: __u8,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct vhost_msg {
    pub type_: ::std::os::raw::c_int,
    pub __bindgen_anon_1: vhost_msg__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union vhost_msg__bindgen_ty_1 {
    pub iotlb: vhost_iotlb_msg,
    pub padding: [__u8; 64usize],
}
impl Default for vhost_msg__bindgen_ty_1 {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
impl Default for vhost_msg {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct vhost_msg_v2 {
    pub type_: __u32,
    pub asid: __u32,
    pub __bindgen_anon_1: vhost_msg_v2__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union vhost_msg_v2__bindgen_ty_1 {
    pub iotlb: vhost_iotlb_msg,
    pub padding: [__u8; 64usize],
}
impl Default for vhost_msg_v2__bindgen_ty_1 {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
impl Default for vhost_msg_v2 {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vhost_memory_region {
    pub guest_phys_addr: __u64,
    pub memory_size: __u64,
    pub userspace_addr: __u64,
    pub flags_padding: __u64,
}
#[repr(C)]
#[derive(Debug, Default)]
pub struct vhost_memory {
    pub nregions: __u32,
    pub padding: __u32,
    pub regions: __IncompleteArrayField<vhost_memory_region>,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vhost_scsi_target {
    pub abi_version: ::std::os::raw::c_int,
    pub vhost_wwpn: [::std::os::raw::c_char; 224usize],
    pub vhost_tpgt: ::std::os::raw::c_ushort,
    pub reserved: ::std::os::raw::c_ushort,
}
impl Default for vhost_scsi_target {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default)]
pub struct vhost_vdpa_config {
    pub off: __u32,
    pub len: __u32,
    pub buf: __IncompleteArrayField<__u8>,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct vhost_vdpa_iova_range {
    pub first: __u64,
    pub last: __u64,
}
