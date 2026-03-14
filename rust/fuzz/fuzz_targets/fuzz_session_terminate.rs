//! Fuzz target for SessionTerminate::deserialize().
//!
//! Ensures the parser never panics on arbitrary input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_protocol::SessionTerminate;

fuzz_target!(|data: &[u8]| {
    let _ = SessionTerminate::deserialize(data);
});
