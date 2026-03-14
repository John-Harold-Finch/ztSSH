//! # ztssh-audit
//!
//! Structured audit logging for ZTSSH.
//!
//! Provides typed audit events for all security-critical operations:
//! session lifecycle, certificate issuance, verification, revocation,
//! challenge-response, and policy enforcement.

mod events;

pub use events::{AuditEvent, AuditEventType, AuditOutcome, SessionPhase};

/// Emit an audit event via tracing.
///
/// Events are emitted at `INFO` level for successful operations
/// and `WARN` level for failures/denials.
pub fn emit(event: &AuditEvent) {
    let json = serde_json::to_string(event).unwrap_or_else(|_| format!("{:?}", event));
    match event.outcome {
        AuditOutcome::Success => {
            tracing::info!(
                audit = true,
                event_type = %event.event_type,
                principal = event.principal.as_deref().unwrap_or("-"),
                peer = event.peer_addr.as_deref().unwrap_or("-"),
                "{}",
                json
            );
        }
        AuditOutcome::Denied | AuditOutcome::Failure => {
            tracing::warn!(
                audit = true,
                event_type = %event.event_type,
                principal = event.principal.as_deref().unwrap_or("-"),
                peer = event.peer_addr.as_deref().unwrap_or("-"),
                "{}",
                json
            );
        }
    }
}
