//! Fuzz target for IdentityAck::deserialize().
//!
//! Ensures the parser never panics on arbitrary input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_protocol::IdentityAck;

fuzz_target!(|data: &[u8]| {
    let _ = IdentityAck::deserialize(data);
});
