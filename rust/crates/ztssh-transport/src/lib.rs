//! # ztssh-transport
//!
//! Transport layer for ZTSSH.
//!
//! - **Framing** — length-prefixed binary messages over AsyncRead/AsyncWrite
//! - **Handshake** — ClientHello / ServerHello / CertRenewal messages
//! - **Server** — server-side ZTSSH session (challenge loop, verification)
//! - **Client** — client-side ZTSSH session (proof, renewal)

mod error;
mod framing;
pub mod server;
pub mod client;

pub use error::TransportError;
pub use framing::{read_message, write_message};

/// Handshake message type codes (transport-level, outside the SSH private-use range).
pub mod handshake_msg {
    pub const CLIENT_HELLO: u8 = 0xC5;
    pub const SERVER_HELLO: u8 = 0xC6;
    pub const CERT_RENEWAL_REQUEST: u8 = 0xC7;
    pub const CERT_RENEWAL_RESPONSE: u8 = 0xC8;
}
