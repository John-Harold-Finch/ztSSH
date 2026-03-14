# ZTSSH: Continuous Identity Verification for Secure Shell

**Version 0.1 — March 2026**

## Abstract

Secure Shell (SSH) remains one of the most important administrative protocols in modern computing infrastructure. Its cryptographic foundations are mature, but its trust model remains largely session-initial: identity is verified at login, then assumed for the remainder of the session. This paper proposes ZTSSH, a protocol extension and implementation model for continuous in-session identity verification in SSH. ZTSSH combines short-lived client certificates, periodic server-issued challenges, local server-embedded subordinate certificate authorities, and immediate revocation handling to reduce the trust window of a compromised session from hours to minutes or seconds. The result is a model better aligned with zero trust principles while remaining operationally realistic for infrastructure environments.

## 1. Introduction

SSH solved remote administration for the internet era by replacing plaintext remote access with encrypted, authenticated channels. Yet most SSH deployments still inherit a simple security assumption: once a session is opened, the authenticated principal remains trusted until the session ends.

This assumption is increasingly insufficient.

An attacker does not need to defeat login if they can steal trust *after* login. Long-running terminals, production shells left open, credential theft from memory, local workstation compromise, agent abuse, or session hijacking all exploit the temporal gap between authentication and continued authorization.

Zero trust systems are based on a different principle: trust must be continuously re-established, not granted indefinitely from a single successful event. ZTSSH applies that principle to SSH.

## 2. Problem Statement

Traditional SSH validates identity at connection establishment through one or more of the following:

- password authentication,
- public-key authentication,
- SSH certificates,
- keyboard-interactive or MFA-assisted mechanisms,
- external identity providers.

These mechanisms improve the quality of initial authentication, but they do not change the core session model. Once the channel is opened, the server generally does not require the client to re-prove possession of current valid credentials.

Thus, the effective trust window of compromise equals the entire remaining session duration.

ZTSSH seeks to reduce that window by introducing repeated proofs of identity during the session itself.

## 3. Design Goals

ZTSSH is designed around the following goals:

1. **Continuous verification** — identity must be periodically re-proven.
2. **Short trust windows** — credentials presented in-session must expire quickly.
3. **Low operational overhead** — session revalidation must not depend on a remote central service.
4. **Fast local decision-making** — servers must continue functioning even if the Root CA is offline.
5. **Immediate revocation response** — principals, servers, and individual certificates must be revocable.
6. **Protocol clarity** — wire formats and session states must be simple enough to audit.
7. **Production viability** — the design must be implementable in a memory-safe systems language with minimal overhead.

## 4. System Model

ZTSSH uses a hierarchical trust architecture.

### 4.1 Root CA

The Root CA is offline and issues `IntermediateCertificate` objects to servers. Each certificate acts as a licence authorizing a specific server to operate a subordinate CA for a limited period.

The Root CA also maintains a global revocation view:

- banned principals,
- revoked server licences,
- globally revoked client certificates.

### 4.2 Server Sub-CA

Each server embeds a `SubCa`. This component is responsible for issuing short-lived client certificates locally. The Sub-CA operates only while its Root-issued intermediate certificate remains valid.

This removes the need for an online central CA during the session loop.

### 4.3 Client

The client maintains an ephemeral keypair and a short-lived client certificate. During the session it may rotate keys and renew certificates through the server-local Sub-CA.

## 5. Protocol Outline

ZTSSH introduces a recurring proof cycle inside the SSH session.

### 5.1 Initial authorization

1. The server possesses a valid `IntermediateCertificate` signed by the Root CA.
2. The client authenticates and obtains a short-lived `ZtsshCertificate` from the server's Sub-CA.
3. The SSH session begins.

### 5.2 Continuous proof cycle

At fixed intervals, the server sends `IDENTITY_CHALLENGE` containing:

- sequence number,
- timestamp,
- random nonce,
- deadline.

The client responds with `IDENTITY_PROOF` containing:

- sequence number,
- timestamp,
- current short-lived certificate,
- signature over the challenge.

The server verifies:

1. issuer identity,
2. certificate expiry,
3. revocation status,
4. principal policy,
5. proof-of-possession via signature.

If verification succeeds, the server sends `IDENTITY_ACK`. Otherwise, it sends `SESSION_TERMINATE` and closes the session.

## 6. Certificate Model

ZTSSH currently uses two certificate classes.

### 6.1 IntermediateCertificate

Issued by the Root CA to a server.

Fields include:

- serial,
- server identifier,
- subject public key,
- issuer public key,
- allowed principals,
- issuance and expiry timestamps,
- signature.

Default validity: **24 hours**.

### 6.2 ZtsshCertificate

Issued by a server Sub-CA to a client.

Fields include:

- serial,
- principal,
- subject public key,
- issuer public key,
- issuance and expiry timestamps,
- signature.

Default validity: **5 minutes**.

## 7. Revocation

ZTSSH supports three distinct revocation scopes.

### 7.1 Principal ban

A principal may be banned globally. After propagation, no server may issue new certificates for that identity.

### 7.2 Server revocation

A server intermediate certificate may be revoked. This removes the server's authority to certify clients.

### 7.3 Client certificate revocation

An individual client certificate may be revoked immediately.

This layered revocation model allows both broad and precise response.

## 8. Security Rationale

### 8.1 Reduced compromise window

If a client credential or endpoint is compromised, the attacker must continue proving identity during the session. Because certificates are short-lived and challenges are periodic, compromise does not yield indefinite trust.

### 8.2 Replay resistance

Each challenge contains a fresh random nonce and sequence number. Replaying old proofs cannot satisfy the next verification cycle.

### 8.3 Lateral movement resistance

Client certificates are bound to the issuing server Sub-CA. A certificate from one server is rejected by another, limiting reuse across infrastructure.

### 8.4 CA availability

Because the Sub-CA is local to the server, continuous verification is not blocked by network loss to a central CA. The Root CA can remain offline.

### 8.5 Memory safety

The reference implementation is written in Rust. This choice is intended to reduce common implementation risks associated with parser bugs, buffer overflows, and key-handling errors in memory-unsafe languages.

## 9. Operational Considerations

ZTSSH is designed so that zero-budget or small-budget operators can still deploy it.

- The Root CA can be a strictly offline tool.
- The Sub-CA lives inside the server process.
- Session revalidation does not require centralized online infrastructure.
- Revocation snapshots can be distributed periodically rather than synchronously.

This keeps the design practical for independent operators, researchers, and small teams.

## 10. Current Reference Implementation

The current repository contains a Rust implementation composed of ten crates covering the full protocol stack:

**Core protocol:**
- `ztssh-crypto` — Ed25519 key management, certificate models, nonce generation
- `ztssh-protocol` — message constants, binary message types, protocol defaults
- `ztssh-ca` — Root CA, Sub-CA, three-level revocation

**Transport and binaries:**
- `ztssh-transport` — TCP framing, handshake messages, server challenge loop, client proof generation, policy enforcement at connection time
- `ztsshd` — server daemon binary with structured logging, policy loading, Sub-CA management
- `ztssh-client` — client binary with automatic certificate renewal
- `ztssh-ca-cli` — offline Root CA management tool with keystore integration

**Production infrastructure:**
- `ztssh-audit` — structured audit event system (20+ typed events, tracing-based, text or JSON output)
- `ztssh-policy` — TOML-configured policy engine (principal allowlists/denylists, CIDR source-IP filtering, per-principal rules)
- `ztssh-keystore` — filesystem-backed key storage with restricted permissions and zeroize-on-delete

At the time of writing, the implementation includes:

- complete Ed25519 key management with zeroize-on-drop,
- custom binary wire formats with length-prefixed framing,
- Root CA / Sub-CA hierarchy with three-level revocation,
- working server and client binaries with continuous challenge-response,
- automatic certificate renewal before expiry,
- policy enforcement at connection time (principal and source IP),
- structured audit logging (text and JSON),
- keystore with filesystem backend and trait for HSM extensibility,
- 133 tests (unit, property-based, security, constant-time, end-to-end),
- 9 fuzz targets covering all parsers,
- ProVerif formal model for authentication and secrecy properties,
- operator documentation, interoperability guide, and security audit preparation.

It does not yet include SSH channel integration (the transport is currently raw TCP with length-prefixed framing, not SSH `channel-request`).

## 11. Future Work

The reference implementation covers the complete protocol model over both TCP and SSH transports. Phase 5 has delivered SSH integration, rate limiting, connection throttling, and signed CRL distribution. The remaining steps toward full real-world deployment are:

### 11.1 SSH channel integration

*Implemented.* The `ztssh-ssh` crate wraps the ZTSSH protocol inside SSH channels via `russh` 0.57:

- SSH server handler accepting a "ztssh" subsystem on session channels,
- SSH client handler connecting and requesting the subsystem,
- Ed25519 host key generation via `ssh_key`,
- both binaries (`ztsshd`, `ztssh`) support `--mode tcp|ssh` to select transport.

Remaining work: bidirectional bridge between SSH channel data and ZTSSH framing, SSH extension negotiation (RFC 8308).

### 11.2 Revocation distribution

*Partially implemented.* `SignedRevocationList` carries Ed25519-signed CRL payloads with wire serialization and signer verification. Transport-layer enforcement checks principal bans at handshake time and certificate serial revocation during proof verification.

Remaining: CRL endpoint (HTTPS server or signed file), periodic pull by servers, push notification for urgent revocations, delta updates.

### 11.3 Hardware security module support

The `Keystore` trait is designed for backend extensibility. Implementing PKCS#11 or platform-native backends (YubiKey, TPM) would:

- protect Root CA keys in hardware,
- enable non-extractable key operations,
- meet compliance requirements for sensitive environments.

### 11.4 Connection-level security

The pre-SSH transport phase (TCP framing) is currently unencrypted. For deployments where ZTSSH replaces SSH entirely, adding TLS or Noise protocol encryption to the transport layer would protect the handshake and challenge-response from eavesdropping.

### 11.5 Operational tooling

*Partially implemented.* Rate limiting (sliding-window, per-IP) and connection throttling (atomic counter with max_connections) are now built into the policy engine and transport layer.

Remaining:

- SIEM integration (Splunk, Elastic, Datadog structured log exporters),
- Prometheus metrics endpoint for challenge latency and connection counts,
- certificate transparency-style audit logging,
- packaging (Debian, RPM, Homebrew, Scoop).

### 11.6 Formal verification and audit

- extend the ProVerif model to cover certificate renewal and revocation propagation,
- commission a third-party cryptographic audit,
- verify constant-time properties under different compiler flags and optimization levels.

### 11.7 SSH agent integration

Supporting the SSH agent protocol would allow ZTSSH to:

- store ephemeral keys in an agent process,
- support agent forwarding for jump hosts,
- integrate with existing ssh-agent workflows.

## 12. Conclusion

ZTSSH is based on a simple claim: in modern infrastructure, identity verification for remote shell access should not end at login.

By combining short-lived credentials, periodic cryptographic proof, local subordinate authorities, and rapid revocation, ZTSSH attempts to shift SSH from login-time trust to continuous trust.

Whether this model becomes a practical new standard depends on implementation quality, operational simplicity, and public review. For that reason, the project is released openly and invites critique, verification, and contribution.

## References

1. Ylonen, T. and Lonvick, C. The Secure Shell (SSH) Protocol Architecture. RFC 4251.
2. Bider, D. et al. Extension Negotiation in SSH. RFC 8308.
3. Free Software Foundation. GNU Affero General Public License v3.
4. Saltzer, J. and Schroeder, M. The Protection of Information in Computer Systems.
5. BeyondCorp / Zero Trust architectural literature.