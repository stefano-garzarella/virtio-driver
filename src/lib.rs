#![cfg_attr(feature = "unsafe-op-in-unsafe-fn", deny(unsafe_op_in_unsafe_fn))]
#![cfg_attr(not(feature = "unsafe-op-in-unsafe-fn"), allow(unused_unsafe))]

#[allow(dead_code)]
pub mod virtqueue;
