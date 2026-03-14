//! # ztssh-ca
//!
//! Hierarchical Certificate Authority for ZTSSH.
//!
//! - **RootCA** — Offline, issues server licences (IntermediateCertificate)
//! - **SubCA** — Embedded per-server, issues client badges (ZtsshCertificate)
//! - **RevocationList** — 3-level revocation (principal ban, server revoke, client revoke)

mod error;
mod revocation;
mod root;
mod sub;
mod verify;

pub use error::CaError;
pub use revocation::{RevocationList, SignedRevocationList};
pub use root::RootCa;
pub use sub::SubCa;
pub use verify::CertVerifyResult;
