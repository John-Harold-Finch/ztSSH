//! Policy configuration types — TOML-serializable rules.

use serde::{Deserialize, Serialize};

/// Top-level policy configuration (loaded from a TOML file).
///
/// # Example TOML
///
/// ```toml
/// [server]
/// max_connections = 100
/// allowed_principals = ["alice", "bob"]
/// denied_principals = ["hacker"]
/// require_principal_allowlist = true
/// max_cert_ttl = 300
/// min_challenge_interval = 10
///
/// [[principal_rules]]
/// principal = "alice"
/// max_sessions = 5
/// allowed_source_ips = ["10.0.0.0/8", "192.168.1.0/24"]
///
/// [[principal_rules]]
/// principal = "bob"
/// max_sessions = 2
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Server-wide policy settings.
    #[serde(default)]
    pub server: ServerPolicy,

    /// Per-principal rules.
    #[serde(default)]
    pub principal_rules: Vec<PrincipalRule>,
}

/// Server-wide policy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPolicy {
    /// Maximum concurrent connections (0 = unlimited).
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Principals explicitly allowed to connect (empty = all allowed).
    #[serde(default)]
    pub allowed_principals: Vec<String>,

    /// Principals explicitly denied.
    #[serde(default)]
    pub denied_principals: Vec<String>,

    /// If true, only principals in `allowed_principals` may connect.
    #[serde(default)]
    pub require_principal_allowlist: bool,

    /// Maximum certificate TTL in seconds the server will issue.
    #[serde(default = "default_max_cert_ttl")]
    pub max_cert_ttl: u32,

    /// Minimum challenge interval the server will accept.
    #[serde(default = "default_min_challenge_interval")]
    pub min_challenge_interval: u32,

    /// Maximum new connections per IP per minute (0 = unlimited).
    #[serde(default)]
    pub rate_limit_per_ip: u32,

    /// Rate-limit window in seconds (default: 60).
    #[serde(default = "default_rate_window")]
    pub rate_limit_window: u32,
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            allowed_principals: Vec::new(),
            denied_principals: Vec::new(),
            require_principal_allowlist: false,
            max_cert_ttl: default_max_cert_ttl(),
            min_challenge_interval: default_min_challenge_interval(),
            rate_limit_per_ip: 0,
            rate_limit_window: default_rate_window(),
        }
    }
}

fn default_max_connections() -> u32 { 0 }
fn default_max_cert_ttl() -> u32 { 300 }
fn default_min_challenge_interval() -> u32 { 10 }
fn default_rate_window() -> u32 { 60 }

/// Per-principal policy overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalRule {
    /// The principal this rule applies to.
    pub principal: String,

    /// Maximum concurrent sessions for this principal (0 = unlimited).
    #[serde(default)]
    pub max_sessions: u32,

    /// Source IP allowlist (CIDR notation). Empty = no IP restriction.
    #[serde(default)]
    pub allowed_source_ips: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml_str = "[server]\n";
        let config: PolicyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.max_connections, 0);
        assert!(config.principal_rules.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
[server]
max_connections = 50
allowed_principals = ["alice", "bob"]
denied_principals = ["hacker"]
require_principal_allowlist = true
max_cert_ttl = 120
min_challenge_interval = 5

[[principal_rules]]
principal = "alice"
max_sessions = 3
allowed_source_ips = ["10.0.0.0/8"]

[[principal_rules]]
principal = "bob"
max_sessions = 1
"#;
        let config: PolicyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.max_connections, 50);
        assert_eq!(config.server.allowed_principals, vec!["alice", "bob"]);
        assert!(config.server.require_principal_allowlist);
        assert_eq!(config.principal_rules.len(), 2);
        assert_eq!(config.principal_rules[0].principal, "alice");
        assert_eq!(config.principal_rules[0].max_sessions, 3);
    }

    #[test]
    fn default_config() {
        let config = PolicyConfig::default();
        assert_eq!(config.server.max_cert_ttl, 300);
        assert!(!config.server.require_principal_allowlist);
    }

    #[test]
    fn serialize_roundtrip() {
        let config = PolicyConfig {
            server: ServerPolicy {
                max_connections: 10,
                allowed_principals: vec!["admin".into()],
                ..Default::default()
            },
            principal_rules: vec![PrincipalRule {
                principal: "admin".into(),
                max_sessions: 5,
                allowed_source_ips: vec!["127.0.0.1/32".into()],
            }],
        };
        let toml_str = toml::to_string(&config).unwrap();
        let restored: PolicyConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.server.max_connections, 10);
        assert_eq!(restored.principal_rules[0].principal, "admin");
    }
}
