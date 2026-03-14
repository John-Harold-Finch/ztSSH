//! Audit event types for ZTSSH.

use std::fmt;

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Outcome of an auditable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failure,
}

/// Which phase of the session lifecycle an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Handshake,
    Challenge,
    Renewal,
    Termination,
}

/// A structured audit event for security-critical operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Event type identifier.
    pub event_type: AuditEventType,
    /// Operation outcome.
    pub outcome: AuditOutcome,
    /// Session phase (for transport events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<SessionPhase>,
    /// Authenticated principal (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Peer address (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_addr: Option<String>,
    /// Server ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    /// Certificate serial (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_serial: Option<u64>,
    /// Challenge sequence number (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
    /// Human-readable detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Reason for failure/denial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event builder with the current timestamp.
    pub fn new(event_type: AuditEventType, outcome: AuditOutcome) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            outcome,
            phase: None,
            principal: None,
            peer_addr: None,
            server_id: None,
            cert_serial: None,
            sequence: None,
            detail: None,
            reason: None,
        }
    }

    pub fn phase(mut self, phase: SessionPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    pub fn principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    pub fn peer(mut self, addr: impl Into<String>) -> Self {
        self.peer_addr = Some(addr.into());
        self
    }

    pub fn server_id(mut self, id: impl Into<String>) -> Self {
        self.server_id = Some(id.into());
        self
    }

    pub fn cert_serial(mut self, serial: u64) -> Self {
        self.cert_serial = Some(serial);
        self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        self.sequence = Some(seq);
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Categories of audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // ── Server lifecycle ──
    ServerStarted,
    ServerStopped,

    // ── Session lifecycle ──
    ConnectionAccepted,
    ConnectionClosed,
    HandshakeCompleted,
    HandshakeFailed,

    // ── Certificate operations ──
    CertIssued,
    CertRenewed,
    CertVerified,
    CertRejected,

    // ── Challenge-response ──
    ChallengeSent,
    ProofReceived,
    ProofVerified,
    ProofRejected,

    // ── Session termination ──
    SessionTerminated,

    // ── Revocation ──
    ServerRevoked,
    PrincipalBanned,
    ClientCertRevoked,

    // ── Policy ──
    PolicyLoaded,
    PolicyDenied,

    // ── CA operations ──
    CaInitialized,
    IntermediateIssued,
    RevocationExported,
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serialize as the serde snake_case name
        let s = serde_json::to_string(self).unwrap_or_else(|_| format!("{:?}", self));
        // Strip surrounding quotes
        write!(f, "{}", s.trim_matches('"'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serialization_roundtrip() {
        let event = AuditEvent::new(AuditEventType::CertIssued, AuditOutcome::Success)
            .principal("alice")
            .cert_serial(42)
            .server_id("srv-01");

        let json = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.event_type, AuditEventType::CertIssued);
        assert_eq!(restored.outcome, AuditOutcome::Success);
        assert_eq!(restored.principal.as_deref(), Some("alice"));
        assert_eq!(restored.cert_serial, Some(42));
    }

    #[test]
    fn event_type_display() {
        assert_eq!(format!("{}", AuditEventType::CertIssued), "cert_issued");
        assert_eq!(
            format!("{}", AuditEventType::ProofRejected),
            "proof_rejected"
        );
    }

    #[test]
    fn denied_event_has_reason() {
        let event = AuditEvent::new(AuditEventType::PolicyDenied, AuditOutcome::Denied)
            .principal("hacker")
            .reason("principal_banned");

        assert_eq!(event.outcome, AuditOutcome::Denied);
        assert_eq!(event.reason.as_deref(), Some("principal_banned"));
    }

    #[test]
    fn optional_fields_skipped_in_json() {
        let event = AuditEvent::new(AuditEventType::ServerStarted, AuditOutcome::Success);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("principal"));
        assert!(!json.contains("cert_serial"));
    }
}
