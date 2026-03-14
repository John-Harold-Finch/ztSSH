//! Client-side ZTSSH session — handshake, proof generation, certificate renewal.

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{BufReader, BufWriter};
use tokio::net::TcpStream;

use ztssh_audit::{emit, AuditEvent, AuditEventType, AuditOutcome, SessionPhase};
use ztssh_crypto::KeyPair;
use ztssh_protocol::*;

use crate::error::TransportError;
use crate::framing::{read_message, write_message};
use crate::server::{
    build_cert_renewal_request, build_client_hello, parse_cert_renewal_response,
    parse_server_hello,
};

/// Run a ZTSSH client session.
pub async fn run_session(addr: &str, principal: &str) -> Result<(), TransportError> {
    let stream = TcpStream::connect(addr).await?;
    tracing::info!(server = addr, "Connected");

    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // Generate ephemeral keypair
    let mut ephemeral_key = KeyPair::new();

    // ── Handshake ──
    let hello = build_client_hello(principal, &ephemeral_key.public_key_bytes());
    write_message(&mut writer, &hello).await?;
    tracing::info!(principal = principal, "ClientHello sent");

    let response = read_message(&mut reader).await?;
    let mut cert = parse_server_hello(&response)?;
    tracing::info!(
        serial = cert.serial,
        ttl = format!("{:.0}s", cert.ttl_remaining()),
        "ServerHello received"
    );
    emit(&AuditEvent::new(AuditEventType::HandshakeCompleted, AuditOutcome::Success)
        .principal(principal)
        .cert_serial(cert.serial)
        .phase(SessionPhase::Handshake));

    // ── Protocol Loop ──
    loop {
        let msg = read_message(&mut reader).await?;
        if msg.is_empty() {
            return Err(TransportError::ConnectionClosed);
        }

        match msg[0] {
            msg_type::IDENTITY_CHALLENGE => {
                let challenge = IdentityChallenge::deserialize(&msg)
                    .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

                tracing::debug!(
                    seq = challenge.sequence_number,
                    deadline = challenge.deadline_seconds,
                    "IDENTITY_CHALLENGE received"
                );

                // Check if certificate needs renewal
                if cert.ttl_remaining() < DEFAULT_RENEWAL_WINDOW {
                    tracing::info!(
                        ttl = format!("{:.0}s", cert.ttl_remaining()),
                        "Certificate nearing expiry, renewing"
                    );

                    let new_key = KeyPair::new();
                    let renewal_request =
                        build_cert_renewal_request(principal, &new_key.public_key_bytes());
                    write_message(&mut writer, &renewal_request).await?;

                    let renewal_response = read_message(&mut reader).await?;
                    let new_cert = parse_cert_renewal_response(&renewal_response)?;
                    tracing::info!(
                        serial = new_cert.serial,
                        ttl = format!("{:.0}s", new_cert.ttl_remaining()),
                        "Certificate renewed"
                    );
                    emit(&AuditEvent::new(AuditEventType::CertRenewed, AuditOutcome::Success)
                        .principal(principal)
                        .cert_serial(new_cert.serial)
                        .phase(SessionPhase::Renewal));

                    cert = new_cert;
                    ephemeral_key = new_key;
                }

                // Sign the challenge
                let sig = ephemeral_key.sign(&msg);
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock before Unix epoch")
                    .as_secs();

                let proof = IdentityProof {
                    sequence_number: challenge.sequence_number,
                    timestamp,
                    certificate: cert.to_wire(),
                    signature: sig.to_bytes().to_vec(),
                };

                write_message(&mut writer, &proof.serialize()).await?;
                tracing::debug!(
                    seq = challenge.sequence_number,
                    serial = cert.serial,
                    "IDENTITY_PROOF sent"
                );

                // Wait for ACK or TERMINATE
                let ack_msg = read_message(&mut reader).await?;
                if ack_msg.is_empty() {
                    return Err(TransportError::ConnectionClosed);
                }

                match ack_msg[0] {
                    msg_type::IDENTITY_ACK => {
                        let ack = IdentityAck::deserialize(&ack_msg)
                            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
                        tracing::info!(
                            seq = ack.sequence_number,
                            next_in = ack.next_challenge_in_seconds,
                            "IDENTITY_ACK received"
                        );
                    }
                    msg_type::SESSION_TERMINATE => {
                        let term = SessionTerminate::deserialize(&ack_msg)
                            .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
                        tracing::warn!(
                            reason = ?term.reason_code,
                            message = %term.reason_message,
                            "SESSION_TERMINATE received"
                        );
                        emit(&AuditEvent::new(AuditEventType::SessionTerminated, AuditOutcome::Denied)
                            .principal(principal)
                            .reason(format!("{:?}: {}", term.reason_code, term.reason_message))
                            .phase(SessionPhase::Termination));
                        return Ok(());
                    }
                    other => {
                        return Err(TransportError::InvalidMessageType(other));
                    }
                }
            }
            msg_type::SESSION_TERMINATE => {
                let term = SessionTerminate::deserialize(&msg)
                    .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;
                tracing::warn!(
                    reason = ?term.reason_code,
                    message = %term.reason_message,
                    "SESSION_TERMINATE received"
                );
                emit(&AuditEvent::new(AuditEventType::SessionTerminated, AuditOutcome::Denied)
                    .principal(principal)
                    .reason(format!("{:?}: {}", term.reason_code, term.reason_message))
                    .phase(SessionPhase::Termination));
                return Ok(());
            }
            other => {
                return Err(TransportError::InvalidMessageType(other));
            }
        }
    }
}
