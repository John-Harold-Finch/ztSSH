//! # ztssh-protocol
//!
//! Wire protocol messages for ZTSSH.
//!
//! All message types live in the SSH private-use range (0xC0–0xCF)
//! and are compatible with RFC 4250 / RFC 8308 extension negotiation.
//!
//! ## Message types
//!
//! | Code | Direction | Type |
//! |------|-----------|------|
//! | 0xC0 | Client → Server | `IdentityProof` |
//! | 0xC1 | Server → Client | `IdentityChallenge` |
//! | 0xC2 | Server → Client | `IdentityAck` |
//! | 0xC3 | Server → Client | `SessionTerminate` |
//! | 0xC4 | Bidirectional | `ExtensionNegotiation` |

mod constants;
mod error;
mod messages;

pub use constants::*;
pub use error::ProtocolError;
pub use messages::{IdentityAck, IdentityChallenge, IdentityProof, SessionTerminate};
