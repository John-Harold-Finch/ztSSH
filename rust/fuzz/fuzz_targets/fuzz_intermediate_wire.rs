//! Fuzz target for IntermediateCertificate::from_wire().
//!
//! Ensures the parser never panics on arbitrary input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_crypto::IntermediateCertificate;

fuzz_target!(|data: &[u8]| {
    let _ = IntermediateCertificate::from_wire(data);
});
