//! Server-side ZTSSH session — handshake, challenge loop, verification.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use ztssh_audit::{emit, AuditEvent, AuditEventType, AuditOutcome, SessionPhase};
use ztssh_ca::{RevocationList, SubCa};
use ztssh_crypto::{generate_nonce, KeyPair, ZtsshCertificate};
use ztssh_policy::PolicyEngine;
use ztssh_protocol::*;

use crate::error::TransportError;
use crate::framing::{read_message, write_message};
use crate::handshake_msg;

/// A ZTSSH server that listens for connections and runs the challenge loop.
pub struct ZtsshServer {
    sub_ca: Arc<Mutex<SubCa>>,
    challenge_interval: u32,
    challenge_deadline: u32,
    policy: Arc<PolicyEngine>,
    active_connections: Arc<AtomicU32>,
    revocation_list: Arc<Mutex<RevocationList>>,
}

impl ZtsshServer {
    pub fn new(sub_ca: SubCa) -> Self {
        Self {
            sub_ca: Arc::new(Mutex::new(sub_ca)),
            challenge_interval: DEFAULT_CHALLENGE_INTERVAL,
            challenge_deadline: DEFAULT_CHALLENGE_DEADLINE,
            policy: Arc::new(PolicyEngine::permissive()),
            active_connections: Arc::new(AtomicU32::new(0)),
            revocation_list: Arc::new(Mutex::new(RevocationList::new())),
        }
    }

    pub fn with_policy(mut self, policy: PolicyEngine) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    pub fn with_intervals(mut self, challenge_interval: u32, challenge_deadline: u32) -> Self {
        self.challenge_interval = challenge_interval;
        self.challenge_deadline = challenge_deadline;
        self
    }

    /// Attach a revocation list to the server for certificate checking.
    pub fn with_revocation_list(mut self, crl: RevocationList) -> Self {
        self.revocation_list = Arc::new(Mutex::new(crl));
        self
    }

    /// Get a handle to the revocation list for runtime updates.
    pub fn revocation_list(&self) -> Arc<Mutex<RevocationList>> {
        self.revocation_list.clone()
    }

    /// Start listening for ZTSSH connections.
    pub async fn listen(&self, addr: &str) -> Result<(), TransportError> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(listen_addr = addr, "ZTSSH server listening");
        emit(
            &AuditEvent::new(AuditEventType::ServerStarted, AuditOutcome::Success)
                .detail(format!("Listening on {addr}")),
        );

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let peer = peer_addr.to_string();
            let peer_ip = peer_addr.ip().to_string();

            // ── Connection throttling ──
            let max_conn = self.policy.max_connections();
            if max_conn > 0 {
                let current = self.active_connections.load(Ordering::Relaxed);
                if current >= max_conn {
                    tracing::warn!(peer = %peer, current, max_conn, "Connection rejected: max connections reached");
                    emit(
                        &AuditEvent::new(AuditEventType::PolicyDenied, AuditOutcome::Denied)
                            .peer(&peer)
                            .reason(format!("max connections ({max_conn}) reached")),
                    );
                    drop(stream);
                    continue;
                }
            }

            // ── Rate limiting ──
            if let Err(e) = self.policy.evaluate_rate_limit(&peer_ip) {
                tracing::warn!(peer = %peer, reason = %e, "Connection rate-limited");
                emit(
                    &AuditEvent::new(AuditEventType::PolicyDenied, AuditOutcome::Denied)
                        .peer(&peer)
                        .reason(e.to_string()),
                );
                drop(stream);
                continue;
            }

            tracing::info!(peer = %peer, "New connection");
            emit(
                &AuditEvent::new(AuditEventType::ConnectionAccepted, AuditOutcome::Success)
                    .peer(&peer),
            );

            self.active_connections.fetch_add(1, Ordering::Relaxed);

            let sub_ca = self.sub_ca.clone();
            let challenge_interval = self.challenge_interval;
            let challenge_deadline = self.challenge_deadline;
            let policy = self.policy.clone();
            let conn_counter = self.active_connections.clone();
            let crl = self.revocation_list.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    stream,
                    sub_ca,
                    challenge_interval,
                    challenge_deadline,
                    &peer,
                    &policy,
                    &crl,
                )
                .await
                {
                    tracing::warn!(peer = %peer, error = %e, "Session error");
                }
                conn_counter.fetch_sub(1, Ordering::Relaxed);
                tracing::info!(peer = %peer, "Connection closed");
                emit(
                    &AuditEvent::new(AuditEventType::ConnectionClosed, AuditOutcome::Success)
                        .peer(&peer),
                );
            });
        }
    }
}

/// Handle a single ZTSSH client connection.
async fn handle_connection(
    stream: TcpStream,
    sub_ca: Arc<Mutex<SubCa>>,
    challenge_interval: u32,
    challenge_deadline: u32,
    peer: &str,
    policy: &PolicyEngine,
    crl: &Mutex<RevocationList>,
) -> Result<(), TransportError> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    // ── Handshake ──
    let hello_data = read_message(&mut reader).await?;
    if hello_data.is_empty() || hello_data[0] != handshake_msg::CLIENT_HELLO {
        emit(
            &AuditEvent::new(AuditEventType::HandshakeFailed, AuditOutcome::Failure)
                .peer(peer)
                .reason("expected ClientHello"),
        );
        return Err(TransportError::HandshakeFailed(
            "expected ClientHello".into(),
        ));
    }

    let (principal, client_pk) = parse_client_hello(&hello_data)?;
    tracing::info!(peer = peer, principal = %principal, "ClientHello received");

    // ── Policy check ──
    if let Err(e) = policy.evaluate_connection(&principal) {
        tracing::warn!(peer = peer, principal = %principal, reason = %e, "Policy denied connection");
        emit(
            &AuditEvent::new(AuditEventType::PolicyDenied, AuditOutcome::Denied)
                .peer(peer)
                .principal(&principal)
                .reason(e.to_string()),
        );
        return Err(TransportError::PolicyDenied(e.to_string()));
    }

    // Evaluate source IP (extract IP from "ip:port")
    if let Some(ip) = peer.rsplit_once(':').map(|(ip, _)| ip) {
        if let Err(e) = policy.evaluate_source_ip(&principal, ip) {
            tracing::warn!(peer = peer, principal = %principal, reason = %e, "Policy denied source IP");
            emit(
                &AuditEvent::new(AuditEventType::PolicyDenied, AuditOutcome::Denied)
                    .peer(peer)
                    .principal(&principal)
                    .reason(e.to_string()),
            );
            return Err(TransportError::PolicyDenied(e.to_string()));
        }
    }

    // ── Revocation check (principal ban) ──
    {
        let revoked = crl.lock().await;
        if revoked.is_principal_banned(&principal) {
            tracing::warn!(peer = peer, principal = %principal, "Principal is banned (revoked)");
            emit(
                &AuditEvent::new(AuditEventType::PolicyDenied, AuditOutcome::Denied)
                    .peer(peer)
                    .principal(&principal)
                    .reason("principal is revoked"),
            );
            return Err(TransportError::PolicyDenied(format!(
                "principal '{}' is revoked",
                principal
            )));
        }
    }

    // Issue initial certificate
    let cert = {
        let ca = sub_ca.lock().await;
        ca.issue_certificate(client_pk, &principal)?
    };

    let server_hello = build_server_hello(&cert);
    write_message(&mut writer, &server_hello).await?;
    tracing::info!(
        peer = peer,
        principal = %principal,
        serial = cert.serial,
        ttl = format!("{:.0}s", cert.ttl_remaining()),
        "Certificate issued, handshake complete"
    );
    emit(
        &AuditEvent::new(AuditEventType::HandshakeCompleted, AuditOutcome::Success)
            .peer(peer)
            .principal(&principal)
            .cert_serial(cert.serial)
            .phase(SessionPhase::Handshake),
    );
    emit(
        &AuditEvent::new(AuditEventType::CertIssued, AuditOutcome::Success)
            .peer(peer)
            .principal(&principal)
            .cert_serial(cert.serial),
    );

    // ── Challenge Loop ──
    let mut sequence: u32 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(challenge_interval as u64)).await;

        sequence += 1;
        let nonce = generate_nonce(32);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs();

        let challenge = IdentityChallenge {
            sequence_number: sequence,
            timestamp,
            nonce: nonce.clone(),
            deadline_seconds: challenge_deadline,
        };

        let challenge_bytes = challenge.serialize();
        write_message(&mut writer, &challenge_bytes).await?;
        tracing::debug!(peer = peer, seq = sequence, "IDENTITY_CHALLENGE sent");
        emit(
            &AuditEvent::new(AuditEventType::ChallengeSent, AuditOutcome::Success)
                .peer(peer)
                .sequence(sequence)
                .phase(SessionPhase::Challenge),
        );

        // Wait for proof, handling possible renewal requests within the deadline.
        let deadline_instant =
            tokio::time::Instant::now() + std::time::Duration::from_secs(challenge_deadline as u64);

        let result = await_proof(
            &mut reader,
            &mut writer,
            &sub_ca,
            &challenge_bytes,
            deadline_instant,
            peer,
            crl,
        )
        .await;

        match result {
            Ok(ProofOutcome::Verified { principal, seq }) => {
                let ack = IdentityAck {
                    sequence_number: seq,
                    next_challenge_in_seconds: challenge_interval,
                };
                write_message(&mut writer, &ack.serialize()).await?;
                tracing::info!(peer = peer, principal = %principal, seq = seq, "IDENTITY_ACK sent");
                emit(
                    &AuditEvent::new(AuditEventType::ProofVerified, AuditOutcome::Success)
                        .peer(peer)
                        .principal(&principal)
                        .sequence(seq)
                        .phase(SessionPhase::Challenge),
                );
            }
            Ok(ProofOutcome::Failed { reason, terminate }) => {
                write_message(&mut writer, &terminate.serialize()).await?;
                tracing::warn!(peer = peer, reason = %reason, "SESSION_TERMINATE");
                emit(
                    &AuditEvent::new(AuditEventType::SessionTerminated, AuditOutcome::Denied)
                        .peer(peer)
                        .reason(&reason)
                        .sequence(sequence)
                        .phase(SessionPhase::Termination),
                );
                return Ok(());
            }
            Err(TransportError::ChallengeTimeout) => {
                let terminate = SessionTerminate {
                    sequence_number: sequence,
                    reason_code: TerminateReason::ChallengeTimeout,
                    reason_message: "No response to identity challenge within deadline".into(),
                };
                write_message(&mut writer, &terminate.serialize()).await?;
                tracing::warn!(peer = peer, seq = sequence, "Challenge timeout");
                emit(
                    &AuditEvent::new(AuditEventType::SessionTerminated, AuditOutcome::Denied)
                        .peer(peer)
                        .reason("challenge_timeout")
                        .sequence(sequence)
                        .phase(SessionPhase::Termination),
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
}

enum ProofOutcome {
    Verified {
        principal: String,
        seq: u32,
    },
    Failed {
        reason: String,
        terminate: SessionTerminate,
    },
}

/// Wait for an IDENTITY_PROOF, handling CERT_RENEWAL_REQUEST messages in between.
async fn await_proof<R, W>(
    reader: &mut R,
    writer: &mut W,
    sub_ca: &Arc<Mutex<SubCa>>,
    challenge_bytes: &[u8],
    deadline: tokio::time::Instant,
    peer: &str,
    crl: &Mutex<RevocationList>,
) -> Result<ProofOutcome, TransportError>
where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::ChallengeTimeout);
        }

        let msg_data = match tokio::time::timeout(remaining, read_message(reader)).await {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(TransportError::ChallengeTimeout),
        };

        if msg_data.is_empty() {
            return Err(TransportError::ConnectionClosed);
        }

        match msg_data[0] {
            handshake_msg::CERT_RENEWAL_REQUEST => {
                let (new_pk, principal) = parse_cert_renewal_request_v2(&msg_data)?;
                let new_cert = {
                    let ca = sub_ca.lock().await;
                    ca.issue_certificate(new_pk, &principal)?
                };
                tracing::info!(
                    peer = peer,
                    principal = %principal,
                    serial = new_cert.serial,
                    "Certificate renewed"
                );
                emit(
                    &AuditEvent::new(AuditEventType::CertRenewed, AuditOutcome::Success)
                        .peer(peer)
                        .principal(&principal)
                        .cert_serial(new_cert.serial)
                        .phase(SessionPhase::Renewal),
                );
                let response = build_cert_renewal_response(&new_cert);
                write_message(writer, &response).await?;
            }
            msg_type::IDENTITY_PROOF => {
                let proof = IdentityProof::deserialize(&msg_data)
                    .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

                let cert = ZtsshCertificate::from_wire(&proof.certificate)
                    .map_err(|e| TransportError::HandshakeFailed(e.to_string()))?;

                // Verify certificate
                let verify_result = {
                    let ca = sub_ca.lock().await;
                    ca.verify_certificate(&cert)
                };

                if !verify_result.valid {
                    let reason_code = match verify_result.reason.as_str() {
                        "expired" => TerminateReason::CertExpired,
                        "revoked" => TerminateReason::CertRevoked,
                        "principal_banned" => TerminateReason::PrincipalBanned,
                        _ => TerminateReason::InvalidProof,
                    };
                    return Ok(ProofOutcome::Failed {
                        reason: verify_result.reason.clone(),
                        terminate: SessionTerminate {
                            sequence_number: proof.sequence_number,
                            reason_code,
                            reason_message: format!(
                                "Certificate verification failed: {}",
                                verify_result.reason
                            ),
                        },
                    });
                }

                // Check revocation list for the client cert serial
                {
                    let revoked = crl.lock().await;
                    if revoked.is_client_revoked(cert.serial) {
                        return Ok(ProofOutcome::Failed {
                            reason: format!("client cert serial {} is revoked", cert.serial),
                            terminate: SessionTerminate {
                                sequence_number: proof.sequence_number,
                                reason_code: TerminateReason::CertRevoked,
                                reason_message: format!(
                                    "Certificate serial {} has been revoked",
                                    cert.serial
                                ),
                            },
                        });
                    }
                    if revoked.is_principal_banned(&cert.principal) {
                        return Ok(ProofOutcome::Failed {
                            reason: format!("principal '{}' is banned", cert.principal),
                            terminate: SessionTerminate {
                                sequence_number: proof.sequence_number,
                                reason_code: TerminateReason::PrincipalBanned,
                                reason_message: format!(
                                    "Principal '{}' has been banned",
                                    cert.principal
                                ),
                            },
                        });
                    }
                }

                // Verify signature over the challenge
                let sig_bytes: [u8; 64] = proof.signature.as_slice().try_into().map_err(|_| {
                    TransportError::HandshakeFailed(format!(
                        "invalid signature length: expected 64, got {}",
                        proof.signature.len()
                    ))
                })?;

                let sig_valid =
                    KeyPair::verify_with_key(&cert.subject_public_key, &sig_bytes, challenge_bytes);

                match sig_valid {
                    Ok(true) => {
                        return Ok(ProofOutcome::Verified {
                            principal: cert.principal.clone(),
                            seq: proof.sequence_number,
                        });
                    }
                    _ => {
                        return Ok(ProofOutcome::Failed {
                            reason: "invalid proof signature".into(),
                            terminate: SessionTerminate {
                                sequence_number: proof.sequence_number,
                                reason_code: TerminateReason::InvalidProof,
                                reason_message: "Challenge signature verification failed".into(),
                            },
                        });
                    }
                }
            }
            other => {
                return Err(TransportError::InvalidMessageType(other));
            }
        }
    }
}

// ─── Handshake message builders / parsers ───

pub fn parse_client_hello(data: &[u8]) -> Result<(String, [u8; 32]), TransportError> {
    // [0xC5] [ver_len:u32] [version] [principal_len:u32] [principal] [ephem_pk:32]
    if data.len() < 1 + 4 {
        return Err(TransportError::HandshakeFailed(
            "ClientHello too short".into(),
        ));
    }
    let mut pos = 1;

    let ver_len = read_u32_at(data, &mut pos)?;
    check_remaining(data, pos, ver_len)?;
    // skip version string
    pos += ver_len;

    let principal_len = read_u32_at(data, &mut pos)?;
    check_remaining(data, pos, principal_len + 32)?;

    let principal = String::from_utf8(data[pos..pos + principal_len].to_vec())
        .map_err(|e| TransportError::HandshakeFailed(format!("invalid UTF-8 principal: {e}")))?;
    pos += principal_len;

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data[pos..pos + 32]);

    Ok((principal, pk))
}

pub fn build_server_hello(cert: &ZtsshCertificate) -> Vec<u8> {
    let version = PROTOCOL_VERSION.as_bytes();
    let cert_wire = cert.to_wire();
    let mut buf = Vec::with_capacity(1 + 4 + version.len() + 4 + cert_wire.len());
    buf.push(handshake_msg::SERVER_HELLO);
    buf.extend_from_slice(&(version.len() as u32).to_be_bytes());
    buf.extend_from_slice(version);
    buf.extend_from_slice(&(cert_wire.len() as u32).to_be_bytes());
    buf.extend_from_slice(&cert_wire);
    buf
}

/// Build a CLIENT_HELLO message.
pub fn build_client_hello(principal: &str, ephemeral_pk: &[u8; 32]) -> Vec<u8> {
    let version = PROTOCOL_VERSION.as_bytes();
    let mut buf = Vec::with_capacity(1 + 4 + version.len() + 4 + principal.len() + 32);
    buf.push(handshake_msg::CLIENT_HELLO);
    buf.extend_from_slice(&(version.len() as u32).to_be_bytes());
    buf.extend_from_slice(version);
    buf.extend_from_slice(&(principal.len() as u32).to_be_bytes());
    buf.extend_from_slice(principal.as_bytes());
    buf.extend_from_slice(ephemeral_pk);
    buf
}

/// Parse a SERVER_HELLO message, returns the ZtsshCertificate.
pub fn parse_server_hello(data: &[u8]) -> Result<ZtsshCertificate, TransportError> {
    if data.is_empty() || data[0] != handshake_msg::SERVER_HELLO {
        return Err(TransportError::HandshakeFailed(
            "expected ServerHello".into(),
        ));
    }
    let mut pos = 1;

    let ver_len = read_u32_at(data, &mut pos)?;
    check_remaining(data, pos, ver_len)?;
    pos += ver_len;

    let cert_len = read_u32_at(data, &mut pos)?;
    check_remaining(data, pos, cert_len)?;

    let cert = ZtsshCertificate::from_wire(&data[pos..pos + cert_len]).map_err(|e| {
        TransportError::HandshakeFailed(format!("invalid cert in ServerHello: {e}"))
    })?;
    Ok(cert)
}

/// Build a CERT_RENEWAL_REQUEST message.
/// Format: [0xC7] [principal_len:u32] [principal] [new_pk:32]
pub fn build_cert_renewal_request(principal: &str, new_pk: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + principal.len() + 32);
    buf.push(handshake_msg::CERT_RENEWAL_REQUEST);
    buf.extend_from_slice(&(principal.len() as u32).to_be_bytes());
    buf.extend_from_slice(principal.as_bytes());
    buf.extend_from_slice(new_pk);
    buf
}

/// Parse renewal request: [0xC7] [principal_len:u32] [principal] [new_pk:32]
pub fn parse_cert_renewal_request_v2(data: &[u8]) -> Result<([u8; 32], String), TransportError> {
    if data.len() < 1 + 4 {
        return Err(TransportError::HandshakeFailed(
            "CertRenewalRequest too short".into(),
        ));
    }
    let mut pos = 1;
    let principal_len = read_u32_at(data, &mut pos)?;
    check_remaining(data, pos, principal_len + 32)?;

    let principal = String::from_utf8(data[pos..pos + principal_len].to_vec())
        .map_err(|e| TransportError::HandshakeFailed(format!("invalid UTF-8: {e}")))?;
    pos += principal_len;

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data[pos..pos + 32]);
    Ok((pk, principal))
}

fn build_cert_renewal_response(cert: &ZtsshCertificate) -> Vec<u8> {
    let cert_wire = cert.to_wire();
    let mut buf = Vec::with_capacity(1 + 4 + cert_wire.len());
    buf.push(handshake_msg::CERT_RENEWAL_RESPONSE);
    buf.extend_from_slice(&(cert_wire.len() as u32).to_be_bytes());
    buf.extend_from_slice(&cert_wire);
    buf
}

/// Parse a CERT_RENEWAL_RESPONSE message.
pub fn parse_cert_renewal_response(data: &[u8]) -> Result<ZtsshCertificate, TransportError> {
    if data.is_empty() || data[0] != handshake_msg::CERT_RENEWAL_RESPONSE {
        return Err(TransportError::HandshakeFailed(
            "expected CertRenewalResponse".into(),
        ));
    }
    let mut pos = 1;
    let cert_len = read_u32_at(data, &mut pos)?;
    check_remaining(data, pos, cert_len)?;

    let cert = ZtsshCertificate::from_wire(&data[pos..pos + cert_len]).map_err(|e| {
        TransportError::HandshakeFailed(format!("invalid cert in CertRenewalResponse: {e}"))
    })?;
    Ok(cert)
}

// ─── Helpers ───

fn read_u32_at(data: &[u8], pos: &mut usize) -> Result<usize, TransportError> {
    if *pos + 4 > data.len() {
        return Err(TransportError::HandshakeFailed("truncated u32".into()));
    }
    let val = u32::from_be_bytes(
        data[*pos..*pos + 4]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    ) as usize;
    *pos += 4;
    Ok(val)
}

fn check_remaining(data: &[u8], pos: usize, needed: usize) -> Result<(), TransportError> {
    if pos + needed > data.len() {
        Err(TransportError::HandshakeFailed(format!(
            "truncated: need {} bytes at offset {}, have {}",
            needed,
            pos,
            data.len()
        )))
    } else {
        Ok(())
    }
}
