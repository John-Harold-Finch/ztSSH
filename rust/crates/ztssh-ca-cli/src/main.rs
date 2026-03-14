//! ZTSSH offline Root CA management CLI.
//!
//! Commands:
//!   init               — Generate a new Root CA and save state
//!   authorize-server   — Issue an IntermediateCertificate for a server
//!   revoke-server      — Revoke a server's intermediate certificate
//!   ban-principal      — Globally ban a principal
//!   show               — Display Root CA information
//!   export-revocation  — Export the revocation list

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use ztssh_ca::{RevocationList, RootCa};
use ztssh_crypto::KeyPair;
use ztssh_keystore::{FilesystemKeystore, KeyPurpose, Keystore};

/// ZTSSH offline Root CA management tool.
#[derive(Parser)]
#[command(name = "ztssh-ca", version, about)]
struct Cli {
    /// Directory for Root CA state (default: ./ztssh-ca-state)
    #[arg(long, default_value = "ztssh-ca-state")]
    dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Root CA (generates keypair).
    Init,

    /// Issue an IntermediateCertificate to authorize a server.
    AuthorizeServer {
        /// Human-readable server identifier (e.g., srv-01).
        #[arg(long)]
        server_id: String,

        /// Server Sub-CA public key (hex-encoded 32 bytes).
        #[arg(long)]
        pubkey: String,

        /// Comma-separated list of allowed principals (omit for wildcard).
        #[arg(long)]
        principals: Option<String>,

        /// Output file for the intermediate certificate.
        #[arg(long)]
        out: PathBuf,
    },

    /// Revoke a server's intermediate certificate by serial number.
    RevokeServer {
        /// Serial number of the intermediate certificate.
        #[arg(long)]
        serial: u64,
    },

    /// Globally ban a principal.
    BanPrincipal {
        /// Principal name to ban.
        #[arg(long)]
        name: String,
    },

    /// Display Root CA information.
    Show,

    /// Export the revocation list to a file.
    ExportRevocation {
        /// Output file path.
        #[arg(long)]
        out: PathBuf,
    },

    /// Generate a new Sub-CA keypair for a server.
    GenerateServerKey {
        /// Output file for the private key.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Persisted Root CA metadata (stored as JSON alongside the raw key file).
#[derive(Serialize, Deserialize)]
struct CaState {
    public_key_hex: String,
    next_serial: u64,
    intermediate_ttl: f64,
    revocation_list: RevocationList,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(&cli.dir),
        Commands::AuthorizeServer {
            server_id,
            pubkey,
            principals,
            out,
        } => cmd_authorize_server(&cli.dir, &server_id, &pubkey, principals.as_deref(), &out),
        Commands::RevokeServer { serial } => cmd_revoke_server(&cli.dir, serial),
        Commands::BanPrincipal { name } => cmd_ban_principal(&cli.dir, &name),
        Commands::Show => cmd_show(&cli.dir),
        Commands::ExportRevocation { out } => cmd_export_revocation(&cli.dir, &out),
        Commands::GenerateServerKey { out } => cmd_generate_server_key(&out),
    }
}

// ─── Commands ───

fn cmd_init(dir: &Path) -> Result<()> {
    if dir.join("root.key").exists() {
        bail!(
            "Root CA already initialized in {}. Remove the directory to reinitialize.",
            dir.display()
        );
    }

    fs::create_dir_all(dir).context("failed to create CA state directory")?;

    let root_ca = RootCa::new();

    // Save private key (raw 32 bytes)
    fs::write(dir.join("root.key"), root_ca.key_bytes()).context("failed to write root.key")?;

    // Also store in keystore for structured management
    let keystore =
        FilesystemKeystore::open(dir.join("keystore")).context("failed to initialize keystore")?;
    keystore
        .store(
            "root-ca",
            &root_ca.key_bytes(),
            &root_ca.public_key_bytes(),
            KeyPurpose::RootCa,
            Some("Root CA signing key"),
        )
        .context("failed to store root key in keystore")?;

    // Save state (JSON)
    let state = CaState {
        public_key_hex: hex::encode(root_ca.public_key_bytes()),
        next_serial: root_ca.next_serial(),
        intermediate_ttl: ztssh_protocol::DEFAULT_INTERMEDIATE_TTL,
        revocation_list: RevocationList::new(),
    };
    let json = serde_json::to_string_pretty(&state)?;
    fs::write(dir.join("state.json"), json).context("failed to write state.json")?;

    println!("Root CA initialized in {}", dir.display());
    println!("Public key: {}", state.public_key_hex);
    println!("Keystore:   {}", dir.join("keystore").display());
    println!("IMPORTANT: Keep root.key offline and secure.");

    Ok(())
}

fn cmd_authorize_server(
    dir: &Path,
    server_id: &str,
    pubkey_hex: &str,
    principals: Option<&str>,
    out: &Path,
) -> Result<()> {
    let (root_ca, mut state) = load_root_ca(dir)?;

    let pubkey_bytes = hex::decode(pubkey_hex).context("invalid hex for server public key")?;
    if pubkey_bytes.len() != 32 {
        bail!(
            "server public key must be 32 bytes, got {}",
            pubkey_bytes.len()
        );
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);

    let allowed = principals.map(|p| p.split(',').map(|s| s.trim().to_string()).collect());

    let cert = root_ca.authorize_server(pk, server_id, allowed);

    // Save cert wire format
    fs::write(out, cert.to_wire())
        .with_context(|| format!("failed to write certificate to {}", out.display()))?;

    // Update state
    state.next_serial = root_ca.next_serial();
    save_state(dir, &state)?;

    println!("Intermediate certificate issued:");
    println!("  Serial:     {}", cert.serial);
    println!("  Server ID:  {}", cert.server_id);
    println!("  Principals: {:?}", cert.allowed_principals);
    println!(
        "  TTL:        {:.0}s ({:.1}h)",
        cert.ttl_remaining(),
        cert.ttl_remaining() / 3600.0
    );
    println!("  Written to: {}", out.display());

    Ok(())
}

fn cmd_revoke_server(dir: &Path, serial: u64) -> Result<()> {
    let (mut root_ca, mut state) = load_root_ca_mut(dir)?;
    root_ca.revoke_server(serial);
    state.revocation_list = root_ca.revocation_list.snapshot();
    save_state(dir, &state)?;
    println!("Server serial {serial} revoked.");
    Ok(())
}

fn cmd_ban_principal(dir: &Path, name: &str) -> Result<()> {
    let (mut root_ca, mut state) = load_root_ca_mut(dir)?;
    root_ca.ban_principal(name);
    state.revocation_list = root_ca.revocation_list.snapshot();
    save_state(dir, &state)?;
    println!("Principal '{name}' globally banned.");
    Ok(())
}

fn cmd_show(dir: &Path) -> Result<()> {
    let state = load_state(dir)?;
    println!("ZTSSH Root CA");
    println!("  State dir:   {}", dir.display());
    println!("  Public key:  {}", state.public_key_hex);
    println!("  Next serial: {}", state.next_serial);
    println!(
        "  Intermediate TTL: {:.0}s ({:.1}h)",
        state.intermediate_ttl,
        state.intermediate_ttl / 3600.0
    );
    println!(
        "  Revocation list: {} bans, {} server revocations, {} client revocations",
        serde_json::to_value(&state.revocation_list)?
            .get("banned_principals")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        serde_json::to_value(&state.revocation_list)?
            .get("revoked_server_serials")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        serde_json::to_value(&state.revocation_list)?
            .get("revoked_client_serials")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
    );
    Ok(())
}

fn cmd_export_revocation(dir: &Path, out: &Path) -> Result<()> {
    let state = load_state(dir)?;
    let json = serde_json::to_string_pretty(&state.revocation_list)?;
    fs::write(out, json).with_context(|| format!("failed to write to {}", out.display()))?;
    println!("Revocation list exported to {}", out.display());
    Ok(())
}

fn cmd_generate_server_key(out: &Path) -> Result<()> {
    let kp = KeyPair::new();
    fs::write(out, kp.to_bytes())
        .with_context(|| format!("failed to write to {}", out.display()))?;

    // If a keystore directory exists alongside the output, store metadata there too
    if let Some(parent) = out.parent() {
        let keystore_dir = parent.join("keystore");
        if keystore_dir.exists() {
            if let Ok(ks) = FilesystemKeystore::open(&keystore_dir) {
                let key_id = out.file_stem().and_then(|s| s.to_str()).unwrap_or("server");
                let _ = ks.store(
                    key_id,
                    &kp.to_bytes(),
                    &kp.public_key_bytes(),
                    KeyPurpose::SubCa,
                    Some("Server Sub-CA key"),
                );
            }
        }
    }

    println!("Server Sub-CA keypair generated.");
    println!("  Public key: {}", hex::encode(kp.public_key_bytes()));
    println!("  Private key written to: {}", out.display());
    Ok(())
}

// ─── Helpers ───

fn load_state(dir: &Path) -> Result<CaState> {
    let json = fs::read_to_string(dir.join("state.json"))
        .context("failed to read state.json — is the CA initialized?")?;
    serde_json::from_str(&json).context("failed to parse state.json")
}

fn save_state(dir: &Path, state: &CaState) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    fs::write(dir.join("state.json"), json).context("failed to write state.json")
}

fn load_root_ca(dir: &Path) -> Result<(RootCa, CaState)> {
    let state = load_state(dir)?;
    let key_bytes: [u8; 32] = fs::read(dir.join("root.key"))
        .context("failed to read root.key")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("root.key must be 32 bytes, got {}", v.len()))?;

    let kp = KeyPair::from_bytes(&key_bytes);
    let root_ca = RootCa::from_keypair(kp);
    root_ca.set_serial_counter(state.next_serial);
    // Restore revocation list
    // We need a mutable reference for this — but from_keypair returns an owned value.
    // For now, the revocation list is loaded from state but not injected into RootCa
    // (it's used for verification, which the CLI doesn't do in this path).
    Ok((root_ca, state))
}

fn load_root_ca_mut(dir: &Path) -> Result<(RootCa, CaState)> {
    let state = load_state(dir)?;
    let key_bytes: [u8; 32] = fs::read(dir.join("root.key"))
        .context("failed to read root.key")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("root.key must be 32 bytes, got {}", v.len()))?;

    let kp = KeyPair::from_bytes(&key_bytes);
    let mut root_ca = RootCa::from_keypair(kp);
    root_ca.set_serial_counter(state.next_serial);
    root_ca.revocation_list = state.revocation_list.clone();
    Ok((root_ca, state))
}
