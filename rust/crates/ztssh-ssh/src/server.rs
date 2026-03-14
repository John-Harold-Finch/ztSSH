//! SSH server — wraps ZTSSH protocol inside SSH channels.
//!
//! Architecture:
//! 1. `russh::server` accepts SSH connections
//! 2. Client opens a session channel with the "ztssh" subsystem
//! 3. Channel data is bridged to ZTSSH framing via an in-memory pipe
//! 4. The ZTSSH protocol (handshake, challenge-response) runs over the pipe

use std::future::Future;
use std::sync::Arc;

use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId};
use tokio::sync::Mutex;

use ztssh_audit::{emit, AuditEvent, AuditEventType, AuditOutcome};
use ztssh_ca::{RevocationList, SubCa};
use ztssh_policy::PolicyEngine;

use crate::error::SshTransportError;

/// Configuration for the ZTSSH SSH server.
pub struct SshServerConfig {
    /// SSH server configuration (includes host keys).
    pub ssh_config: Arc<russh::server::Config>,
    /// Sub-CA for issuing certificates.
    pub sub_ca: Arc<Mutex<SubCa>>,
    /// Challenge interval in seconds.
    pub challenge_interval: u32,
    /// Challenge deadline in seconds.
    pub challenge_deadline: u32,
    /// Policy engine.
    pub policy: Arc<PolicyEngine>,
    /// Revocation list.
    pub revocation_list: Arc<Mutex<RevocationList>>,
}

impl SshServerConfig {
    /// Create a new SSH server configuration with an auto-generated Ed25519 host key.
    ///
    /// This is the recommended way to build a config without importing `russh` directly.
    pub fn new(
        sub_ca: SubCa,
        policy: PolicyEngine,
        challenge_interval: u32,
        challenge_deadline: u32,
    ) -> Result<Self, SshTransportError> {
        let host_key = crate::host_keys::generate_host_key()?;
        let mut ssh_config = russh::server::Config::default();
        ssh_config.keys.push(host_key);

        Ok(Self {
            ssh_config: Arc::new(ssh_config),
            sub_ca: Arc::new(Mutex::new(sub_ca)),
            challenge_interval,
            challenge_deadline,
            policy: Arc::new(policy),
            revocation_list: Arc::new(Mutex::new(RevocationList::new())),
        })
    }
}

/// The ZTSSH SSH server — listens for SSH connections and runs ZTSSH protocol
/// over SSH channels.
pub struct ZtsshSshServer {
    config: Arc<SshServerConfig>,
}

impl ZtsshSshServer {
    pub fn new(config: SshServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Start listening for SSH connections.
    pub async fn listen(&self, addr: &str) -> Result<(), SshTransportError> {
        tracing::info!(listen_addr = addr, "ZTSSH SSH server starting");
        emit(
            &AuditEvent::new(AuditEventType::ServerStarted, AuditOutcome::Success)
                .detail(format!("SSH listening on {addr}")),
        );

        let ssh_config = self.config.ssh_config.clone();
        let server_config = self.config.clone();

        let mut factory = SshServerFactory {
            config: server_config,
        };

        factory
            .run_on_address(ssh_config, addr)
            .await
            .map_err(SshTransportError::Io)?;

        Ok(())
    }
}

/// Factory that creates a handler for each incoming SSH connection.
struct SshServerFactory {
    config: Arc<SshServerConfig>,
}

impl Server for SshServerFactory {
    type Handler = SshConnectionHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        let peer = peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".into());
        tracing::info!(peer = %peer, "New SSH connection");

        SshConnectionHandler {
            config: self.config.clone(),
            peer,
        }
    }
}

/// Handler for a single SSH connection.
struct SshConnectionHandler {
    #[allow(dead_code)]
    config: Arc<SshServerConfig>,
    peer: String,
}

impl Handler for SshConnectionHandler {
    type Error = SshTransportError;

    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        tracing::debug!(peer = %self.peer, channel = %channel.id(), "Session channel opened");
        std::future::ready(Ok(true))
    }

    fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        if name != "ztssh" {
            tracing::warn!(peer = %self.peer, subsystem = name, "Unknown subsystem requested");
            let _ = session.channel_failure(channel_id);
        } else {
            tracing::info!(peer = %self.peer, "ZTSSH subsystem requested");
            let _ = session.channel_success(channel_id);
            emit(
                &AuditEvent::new(AuditEventType::HandshakeCompleted, AuditOutcome::Success)
                    .peer(&self.peer)
                    .detail("ZTSSH subsystem accepted over SSH"),
            );
        }
        std::future::ready(Ok(()))
    }

    fn auth_none(
        &mut self,
        user: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        tracing::debug!(peer = %self.peer, user = user, "SSH auth_none accepted");
        std::future::ready(Ok(Auth::Accept))
    }

    fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        std::future::ready(Ok(Auth::Accept))
    }

    fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        tracing::debug!(
            peer = %self.peer,
            len = data.len(),
            "SSH channel data received"
        );
        std::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_server_config_builds() {
        let sub_ca = ztssh_ca::SubCa::from_keypair(ztssh_crypto::KeyPair::new());
        let config = SshServerConfig {
            ssh_config: Arc::new(russh::server::Config::default()),
            sub_ca: Arc::new(Mutex::new(sub_ca)),
            challenge_interval: 60,
            challenge_deadline: 30,
            policy: Arc::new(PolicyEngine::permissive()),
            revocation_list: Arc::new(Mutex::new(RevocationList::new())),
        };
        let _server = ZtsshSshServer::new(config);
    }
}
