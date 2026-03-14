//! Policy evaluation engine.

use std::collections::HashMap;
use std::path::Path;

use crate::error::PolicyError;
use crate::rate_limit::RateLimiter;
use crate::rules::{PolicyConfig, PrincipalRule};

/// The policy engine evaluates access decisions based on loaded configuration.
pub struct PolicyEngine {
    config: PolicyConfig,
    /// Index: principal name → rule index in config.principal_rules
    principal_index: HashMap<String, usize>,
    /// Per-IP rate limiter (created from config).
    rate_limiter: RateLimiter,
}

impl PolicyEngine {
    /// Create a policy engine from a configuration.
    pub fn new(config: PolicyConfig) -> Self {
        let principal_index = config
            .principal_rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.principal.clone(), i))
            .collect();

        let rate_limiter = RateLimiter::new(
            config.server.rate_limit_per_ip,
            config.server.rate_limit_window,
        );

        Self {
            config,
            principal_index,
            rate_limiter,
        }
    }

    /// Load policy from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path)?;
        let config: PolicyConfig = toml::from_str(&content)?;
        Ok(Self::new(config))
    }

    /// Create a permissive default engine (no restrictions).
    pub fn permissive() -> Self {
        Self::new(PolicyConfig::default())
    }

    /// Get a reference to the underlying configuration.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Evaluate whether a principal is allowed to connect.
    ///
    /// Returns `Ok(())` if allowed, `Err(PolicyError::Denied)` if not.
    pub fn evaluate_connection(&self, principal: &str) -> Result<(), PolicyError> {
        // Check denied list first
        if self
            .config
            .server
            .denied_principals
            .contains(&principal.to_string())
        {
            return Err(PolicyError::Denied(format!(
                "principal '{}' is in the deny list",
                principal
            )));
        }

        // Check allowlist
        if self.config.server.require_principal_allowlist
            && !self
                .config
                .server
                .allowed_principals
                .contains(&principal.to_string())
        {
            return Err(PolicyError::Denied(format!(
                "principal '{}' is not in the allow list",
                principal
            )));
        }

        Ok(())
    }

    /// Evaluate whether a principal is allowed from a given source IP.
    ///
    /// Returns `Ok(())` if allowed, `Err(PolicyError::Denied)` if not.
    pub fn evaluate_source_ip(&self, principal: &str, source_ip: &str) -> Result<(), PolicyError> {
        if let Some(&idx) = self.principal_index.get(principal) {
            let rule = &self.config.principal_rules[idx];
            if !rule.allowed_source_ips.is_empty()
                && !ip_matches_any(source_ip, &rule.allowed_source_ips)
            {
                return Err(PolicyError::Denied(format!(
                    "source IP '{}' not allowed for principal '{}'",
                    source_ip, principal
                )));
            }
        }
        Ok(())
    }

    /// Get the per-principal rule (if any).
    pub fn principal_rule(&self, principal: &str) -> Option<&PrincipalRule> {
        self.principal_index
            .get(principal)
            .map(|&idx| &self.config.principal_rules[idx])
    }

    /// Get the maximum certificate TTL from server policy.
    pub fn max_cert_ttl(&self) -> u32 {
        self.config.server.max_cert_ttl
    }

    /// Get the maximum concurrent connections from server policy.
    pub fn max_connections(&self) -> u32 {
        self.config.server.max_connections
    }

    /// Evaluate rate limit for a source IP.
    ///
    /// Returns `Ok(())` if allowed, `Err(PolicyError::RateLimited)` if over limit.
    pub fn evaluate_rate_limit(&self, source_ip: &str) -> Result<(), PolicyError> {
        if !self.rate_limiter.check_and_record(source_ip) {
            return Err(PolicyError::RateLimited(format!(
                "IP '{}' exceeded {} connections per {}s",
                source_ip,
                self.config.server.rate_limit_per_ip,
                self.config.server.rate_limit_window,
            )));
        }
        Ok(())
    }

    /// Get a reference to the rate limiter.
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }
}

/// Simple prefix-match for IP addresses against CIDR-like patterns.
///
/// For production use, this should be replaced with a proper CIDR parser.
/// Currently supports:
/// - Exact match: "127.0.0.1" matches "127.0.0.1"  
/// - Prefix match: "10.0.0.5" matches "10.0.0.0/8" (checks the prefix before /)
fn ip_matches_any(ip: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if let Some(prefix) = pattern.strip_suffix("/32") {
            if ip == prefix {
                return true;
            }
        } else if let Some((network, mask_str)) = pattern.split_once('/') {
            let mask_bits: u32 = match mask_str.parse() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if let (Some(ip_num), Some(net_num)) = (parse_ipv4(ip), parse_ipv4(network)) {
                let mask = if mask_bits == 0 {
                    0
                } else {
                    !0u32 << (32 - mask_bits)
                };
                if (ip_num & mask) == (net_num & mask) {
                    return true;
                }
            }
        } else if ip == pattern {
            return true;
        }
    }
    false
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u32 = parts[0].parse().ok()?;
    let b: u32 = parts[1].parse().ok()?;
    let c: u32 = parts[2].parse().ok()?;
    let d: u32 = parts[3].parse().ok()?;
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{PolicyConfig, PrincipalRule, ServerPolicy};

    #[test]
    fn permissive_allows_all() {
        let engine = PolicyEngine::permissive();
        assert!(engine.evaluate_connection("anyone").is_ok());
    }

    #[test]
    fn denied_principal_rejected() {
        let config = PolicyConfig {
            server: ServerPolicy {
                denied_principals: vec!["hacker".into()],
                ..Default::default()
            },
            principal_rules: vec![],
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.evaluate_connection("hacker").is_err());
        assert!(engine.evaluate_connection("alice").is_ok());
    }

    #[test]
    fn allowlist_enforced() {
        let config = PolicyConfig {
            server: ServerPolicy {
                allowed_principals: vec!["alice".into()],
                require_principal_allowlist: true,
                ..Default::default()
            },
            principal_rules: vec![],
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.evaluate_connection("alice").is_ok());
        assert!(engine.evaluate_connection("bob").is_err());
    }

    #[test]
    fn allowlist_not_enforced_by_default() {
        let config = PolicyConfig {
            server: ServerPolicy {
                allowed_principals: vec!["alice".into()],
                require_principal_allowlist: false,
                ..Default::default()
            },
            principal_rules: vec![],
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.evaluate_connection("bob").is_ok());
    }

    #[test]
    fn source_ip_enforced() {
        let config = PolicyConfig {
            server: ServerPolicy::default(),
            principal_rules: vec![PrincipalRule {
                principal: "alice".into(),
                max_sessions: 0,
                allowed_source_ips: vec!["10.0.0.0/8".into()],
            }],
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.evaluate_source_ip("alice", "10.1.2.3").is_ok());
        assert!(engine.evaluate_source_ip("alice", "192.168.1.1").is_err());
        // Unknown principal → no IP rule → allowed
        assert!(engine.evaluate_source_ip("bob", "192.168.1.1").is_ok());
    }

    #[test]
    fn exact_ip_match() {
        assert!(ip_matches_any("127.0.0.1", &["127.0.0.1".into()]));
        assert!(!ip_matches_any("127.0.0.2", &["127.0.0.1".into()]));
    }

    #[test]
    fn cidr_32_match() {
        assert!(ip_matches_any("10.0.0.1", &["10.0.0.1/32".into()]));
        assert!(!ip_matches_any("10.0.0.2", &["10.0.0.1/32".into()]));
    }

    #[test]
    fn cidr_subnet_match() {
        assert!(ip_matches_any("192.168.1.100", &["192.168.1.0/24".into()]));
        assert!(!ip_matches_any("192.168.2.1", &["192.168.1.0/24".into()]));
    }

    #[test]
    fn principal_rule_lookup() {
        let config = PolicyConfig {
            server: ServerPolicy::default(),
            principal_rules: vec![PrincipalRule {
                principal: "alice".into(),
                max_sessions: 3,
                allowed_source_ips: vec![],
            }],
        };
        let engine = PolicyEngine::new(config);
        let rule = engine.principal_rule("alice").unwrap();
        assert_eq!(rule.max_sessions, 3);
        assert!(engine.principal_rule("bob").is_none());
    }
}
