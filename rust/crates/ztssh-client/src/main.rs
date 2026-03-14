//! ZTSSH client binary.
//!
//! Connects to a ZTSSH server, performs the handshake, and enters the
//! continuous identity verification loop.
//!
//! Usage:
//!   ztssh --connect 127.0.0.1:2222 --principal alice

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Transport mode: raw TCP or SSH.
#[derive(Clone, Debug, Default, clap::ValueEnum)]
enum TransportMode {
    /// Direct TCP transport (ZTSSH framing only).
    #[default]
    Tcp,
    /// SSH transport (ZTSSH protocol runs over SSH subsystem channel).
    Ssh,
}

/// ZTSSH client — continuous identity verification.
///
/// Usage:
///   ztssh root@72.145.85.63
///   ztssh root@72.145.85.63:2222
///   ztssh --connect 72.145.85.63:2222 --principal root
#[derive(Parser)]
#[command(name = "ztssh", version, about)]
struct Cli {
    /// Destination in SSH-style notation: [principal@]host[:port].
    /// If omitted, --connect and --principal must be set explicitly.
    #[arg(value_name = "DESTINATION", conflicts_with_all = ["connect", "principal"])]
    destination: Option<String>,

    /// Server address (host:port). Ignored when DESTINATION is given.
    #[arg(long, required_unless_present = "destination")]
    connect: Option<String>,

    /// Principal name (user identity). Ignored when DESTINATION is given.
    #[arg(long, required_unless_present = "destination")]
    principal: Option<String>,

    /// Log format: "text" (human-readable) or "json" (structured).
    #[arg(long, default_value = "text")]
    log_format: String,

    /// Transport mode: "tcp" (default) or "ssh".
    #[arg(long, value_enum, default_value_t = TransportMode::Tcp)]
    mode: TransportMode,
}

/// Parse `[user@]host[:port]` → (principal, "host:port").
/// Defaults to the current OS username if no `user@` prefix, port to 2222.
fn parse_destination(dest: &str) -> anyhow::Result<(String, String)> {
    let (principal, hostport) = if let Some((user, rest)) = dest.split_once('@') {
        if user.is_empty() {
            anyhow::bail!("empty username in destination '{dest}'");
        }
        (user.to_string(), rest.to_string())
    } else {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "user".to_string());
        (user, dest.to_string())
    };

    // Append default port if none given (and it's not an IPv6 literal)
    let connect = if hostport.contains(':') && !hostport.starts_with('[') {
        hostport
    } else if hostport.starts_with('[') {
        // IPv6 bracket notation: [::1] — add port
        format!("{hostport}:2222")
    } else {
        format!("{hostport}:2222")
    };

    Ok((principal, connect))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Resolve principal + server address from either positional or flags
    let (principal, connect) = if let Some(dest) = &cli.destination {
        parse_destination(dest)?
    } else {
        (
            cli.principal.expect("required when no DESTINATION"),
            cli.connect.expect("required when no DESTINATION"),
        )
    };

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match cli.log_format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
    }

    tracing::info!(
        server = %connect,
        principal = %principal,
        mode = ?cli.mode,
        "ZTSSH client starting"
    );

    match cli.mode {
        TransportMode::Tcp => {
            ztssh_transport::client::run_session(&connect, &principal)
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }
        TransportMode::Ssh => {
            ztssh_ssh::client::run_ssh_session(&connect, &principal)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
    }
}
