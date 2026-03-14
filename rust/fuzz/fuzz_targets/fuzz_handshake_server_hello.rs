//! Fuzz target for ServerHello handshake parser.
//!
//! The ServerHello contains an embedded ZtsshCertificate — this exercises
//! both the handshake envelope parser and the certificate wire parser.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_transport::server::parse_server_hello;

fuzz_target!(|data: &[u8]| {
    let _ = parse_server_hello(data);
});
