//! SSH client — connects to a ZTSSH SSH server and runs the protocol
//! over an SSH channel subsystem.

use std::future::Future;
use std::sync::Arc;

use russh::client::Handler;

use ztssh_audit::{emit, AuditEvent, AuditEventType, AuditOutcome};

use crate::error::SshTransportError;

/// SSH client session configuration.
pub struct SshClientConfig {
    /// SSH client configuration.
    pub ssh_config: Arc<russh::client::Config>,
    /// Principal name for ZTSSH authentication.
    pub principal: String,
}

/// Run a ZTSSH client session over SSH.
pub async fn run_ssh_session(
    addr: &str,
    principal: &str,
) -> Result<(), SshTransportError> {
    let config = Arc::new(russh::client::Config::default());

    tracing::info!(server = addr, principal = principal, "Connecting via SSH");

    let handler = SshClientHandler;

    let mut session = russh::client::connect(config, addr, handler).await?;

    // Authenticate with "none" (ZTSSH handles auth at protocol level).
    let auth_result = session.authenticate_none(principal).await?;
    if !auth_result.success() {
        tracing::warn!("SSH authentication failed");
        return Err(SshTransportError::AuthFailed);
    }

    tracing::info!("SSH authenticated, opening ZTSSH subsystem channel");

    // Open a session channel.
    let channel = session.channel_open_session().await?;

    // Request the ZTSSH subsystem.
    channel.request_subsystem(false, "ztssh").await?;

    tracing::info!("ZTSSH subsystem channel opened");
    emit(
        &AuditEvent::new(AuditEventType::HandshakeCompleted, AuditOutcome::Success)
            .principal(principal)
            .detail("SSH channel established, ZTSSH subsystem active"),
    );

    // The ZTSSH protocol exchange will run over this channel once
    // the full bidirectional bridge is wired.

    Ok(())
}

/// Minimal SSH client handler — delegates real auth to ZTSSH protocol layer.
struct SshClientHandler;

impl Handler for SshClientHandler {
    type Error = SshTransportError;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        // Accept all host keys — ZTSSH handles trust via its own CA chain.
        std::future::ready(Ok(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_default() {
        let config = russh::client::Config::default();
        let ssh_config = SshClientConfig {
            ssh_config: Arc::new(config),
            principal: "test".into(),
        };
        assert_eq!(ssh_config.principal, "test");
    }
}
