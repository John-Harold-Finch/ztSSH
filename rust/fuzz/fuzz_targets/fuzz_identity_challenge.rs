//! Fuzz target for IdentityChallenge::deserialize().
//!
//! Ensures the parser never panics on arbitrary input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_protocol::IdentityChallenge;

fuzz_target!(|data: &[u8]| {
    let _ = IdentityChallenge::deserialize(data);
});
