//! # ztssh-policy
//!
//! Configurable policy engine for ZTSSH servers.
//!
//! Policies are loaded from TOML configuration files and evaluated
//! at connection time and during the challenge-response loop.

mod engine;
mod error;
pub mod rate_limit;
mod rules;

pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use rate_limit::RateLimiter;
pub use rules::{PolicyConfig, PrincipalRule, ServerPolicy};
