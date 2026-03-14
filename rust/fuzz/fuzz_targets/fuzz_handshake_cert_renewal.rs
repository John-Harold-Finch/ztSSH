//! Fuzz target for CertRenewal handshake parsers.
//!
//! Exercises both the renewal request and response parsers.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_transport::server::{parse_cert_renewal_request_v2, parse_cert_renewal_response};

fuzz_target!(|data: &[u8]| {
    let _ = parse_cert_renewal_request_v2(data);
    let _ = parse_cert_renewal_response(data);
});
