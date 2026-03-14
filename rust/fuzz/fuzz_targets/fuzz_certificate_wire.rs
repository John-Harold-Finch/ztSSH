//! Fuzz target for ZtsshCertificate::from_wire().
//!
//! Ensures the parser never panics on arbitrary input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_crypto::ZtsshCertificate;

fuzz_target!(|data: &[u8]| {
    // Must not panic — errors are fine, panics are not.
    let _ = ZtsshCertificate::from_wire(data);
});
