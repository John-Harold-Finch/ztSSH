//! # ztssh-ssh
//!
//! SSH transport layer for ZTSSH.
//!
//! Runs the ZTSSH continuous identity verification protocol over
//! SSH channels provided by the `russh` library. This adds:
//!
//! - **Transport encryption** — SSH provides AES-GCM / ChaCha20-Poly1305
//! - **Host authentication** — SSH host keys verify the server identity
//! - **Channel multiplexing** — ZTSSH runs as a subsystem over SSH channels
//!
//! The ZTSSH framing layer (`read_message` / `write_message`) operates
//! directly over the SSH channel's `AsyncRead + AsyncWrite` stream.

pub mod server;
pub mod client;
mod error;
pub mod host_keys;

pub use error::SshTransportError;
pub use client::SshClientConfig;
pub use server::SshServerConfig;
pub use host_keys::generate_host_key;
