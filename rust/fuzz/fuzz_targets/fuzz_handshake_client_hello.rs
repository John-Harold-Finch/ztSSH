//! Fuzz target for ClientHello handshake parser.
//!
//! Tests parse_client_hello from the transport layer.

#![no_main]
use libfuzzer_sys::fuzz_target;
use ztssh_transport::server::parse_client_hello;

fuzz_target!(|data: &[u8]| {
    let _ = parse_client_hello(data);
});
