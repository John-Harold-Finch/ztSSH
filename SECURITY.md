# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.x (current) | :warning: Pre-release — not for production use |

## Reporting a Vulnerability

If you discover a security vulnerability in ZTSSH, **please report it responsibly**.

### Do NOT

- Open a public GitHub issue
- Post details on social media or forums
- Exploit the vulnerability against production systems

### Do

Send your report to the project maintainers via **GitHub Security Advisories**:

1. Go to the [Security tab](../../security) of this repository
2. Click "Report a vulnerability"
3. Provide:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

| Step | Target |
|---|---|
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix available | 30 days (90 days for complex issues) |
| Public disclosure | After fix is released |

## Security Design Principles

ZTSSH is built on these security foundations:

### Cryptographic Choices
- **Ed25519** — No RSA, no NIST curves, no legacy crypto
- **CSPRNG** via OS entropy (`/dev/urandom`, `BCryptGenRandom`)
- **zeroize** — All private key material is wiped from memory on drop
- Fixed-time signature verification (via ed25519-dalek constant-time ops)

### Architecture
- **Air-gapped Root CA** — The root signing key never touches the network
- **5-minute certificate TTL** — Maximum exposure window on compromise
- **Continuous verification** — Identity re-proven every 60 seconds in-session
- **Multi-server isolation** — Certificates are scoped to the issuing server's Sub-CA
- **3-level revocation** — Global principal ban, server revocation, individual cert revocation

### What We Do NOT Trust
- Network connectivity during sessions (Sub-CA operates locally)
- Long-lived credentials (maximum 5 minutes)
- Single point of authentication (continuous, not one-shot)
- The client's previous authentication state (re-verified from scratch each cycle)

## Threat Model

| Threat | Mitigation |
|---|---|
| Compromised client key | Certificate expires in ≤5 minutes |
| Session hijacking | Challenge-response fails without client's ephemeral private key |
| Replay attacks | Unique nonce + timestamp + sequence number per challenge |
| Lateral movement | Sub-CA isolation — Server A's certs rejected by Server B |
| Compromised server | Root CA revokes server licence; all its certs become invalid |
| Root CA compromise | Air-gapped by design; use HSM in production |
| Memory disclosure | zeroize wipes keys on drop; Rust prevents use-after-free |
| Timing attacks | Constant-time Ed25519 operations |

## Audit Status

This project has **not yet been professionally audited**. If you are a security firm interested in auditing ZTSSH, please reach out.

## Dependency Policy

- All cryptographic operations rely on `ed25519-dalek` and `zeroize`
- SSH transport uses `russh`, async runtime is `tokio`
- CLI parsing via `clap`, serialization via `serde`/`bincode`
- Observability through `tracing`/`tracing-subscriber`
- No `unsafe` blocks in ZTSSH code (relies on audited unsafe in ed25519-dalek and russh internals)
- Regular `cargo audit` runs for known vulnerabilities
