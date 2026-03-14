//! Fuzz target for IdentityProof::deserialize().
//!
//! Ensures the parser never panics on arbitrary input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_protocol::IdentityProof;

fuzz_target!(|data: &[u8]| {
    let _ = IdentityProof::deserialize(data);
});
