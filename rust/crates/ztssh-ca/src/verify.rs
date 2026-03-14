//! Certificate verification result.

/// The result of verifying a ZTSSH certificate or intermediate certificate.
#[derive(Debug, Clone)]
pub struct CertVerifyResult {
    /// Whether the certificate is valid.
    pub valid: bool,
    /// Human-readable reason (e.g., "ok", "expired", "revoked", "issuer_mismatch").
    pub reason: String,
    /// The authenticated principal, if valid.
    pub principal: Option<String>,
    /// Remaining TTL in seconds, if valid.
    pub ttl_remaining: Option<f64>,
}

impl CertVerifyResult {
    /// Create a successful result.
    pub fn ok(principal: impl Into<String>, ttl_remaining: f64) -> Self {
        Self {
            valid: true,
            reason: "ok".into(),
            principal: Some(principal.into()),
            ttl_remaining: Some(ttl_remaining),
        }
    }

    /// Create a failure result.
    pub fn fail(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason: reason.into(),
            principal: None,
            ttl_remaining: None,
        }
    }
}
