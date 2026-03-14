# ZTSSH Interoperability with Existing SSH Ecosystems

## Overview

ZTSSH is designed to complement — not replace — the existing SSH ecosystem. This document describes the integration strategies, compatibility boundaries, and migration paths.

## Architecture Position

```
┌─────────────────────────────────────────────┐
│            Standard SSH Session              │
│                                             │
│  OpenSSH Client ←──────→ OpenSSH Server     │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │       ZTSSH Extension Layer         │    │
│  │                                     │    │
│  │  Continuous identity verification   │    │
│  │  inside the existing SSH channel    │    │
│  │                                     │    │
│  │  Extension: ztssh-continuous-auth   │    │
│  │           @.io              │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

ZTSSH operates as an **SSH channel extension** that runs inside an established SSH session, not as a replacement transport.

## Integration Strategy: SSH Extension Negotiation (RFC 8308)

ZTSSH uses the SSH extension negotiation mechanism (RFC 8308) to advertise its capability:

```
Extension name: ztssh-continuous-auth@nexaflow.io
Protocol version: 0.2
```

### Negotiation Flow

1. Client advertises `ztssh-continuous-auth@nexaflow.io` during SSH key exchange
2. Server acknowledges if it supports ZTSSH
3. If both sides agree, the continuous verification loop activates inside the SSH channel
4. If the server does not support ZTSSH, standard SSH proceeds normally

This ensures **full backward compatibility**: a ZTSSH-capable client can connect to any standard OpenSSH server, and a ZTSSH server can accept standard SSH clients.

## Compatibility Matrix

| Client | Server | Result |
|---|---|---|
| ZTSSH-enabled | ZTSSH-enabled | Full continuous verification |
| ZTSSH-enabled | Standard OpenSSH | Standard SSH session (no ZTSSH) |
| Standard OpenSSH | ZTSSH-enabled | Standard SSH session (no ZTSSH) |
| Standard OpenSSH | Standard OpenSSH | Standard SSH session |

## Integration with `russh`

The planned integration path uses [`russh`](https://github.com/warp-tech/russh), a pure Rust SSH implementation:

1. **Phase**: Replace the current TCP transport layer with `russh`
2. **Approach**: ZTSSH messages flow over an SSH channel dedicated to continuous auth
3. **Benefit**: Full SSH protocol compliance (key exchange, encryption, compression)

### Channel Architecture

```
SSH Connection
  ├── Channel 0: session (shell/exec)
  ├── Channel 1: ztssh-continuous-auth
  │     ├── IDENTITY_CHALLENGE (server → client)
  │     ├── IDENTITY_PROOF (client → server)
  │     ├── IDENTITY_ACK (server → client)
  │     ├── SESSION_TERMINATE (server → client)
  │     └── CERT_RENEWAL_REQUEST/RESPONSE
  └── …
```

## Key Management Interoperability

### SSH Agent Protocol (RFC Draft)

ZTSSH keys are standard Ed25519 keys and can be stored in existing SSH agents:

- **ssh-agent**: ZTSSH ephemeral keys can be loaded via `ssh-add`
- **PKCS#11**: Hardware token support via standard PKCS#11 interface
- **FIDO2/U2F**: Security key support (future, requires Ed25519-SK)

### Key Format Compatibility

| Key Format | ZTSSH Support | Notes |
|---|---|---|
| OpenSSH Ed25519 (`ssh-ed25519`) | ✅ Native | Direct compatibility |
| OpenSSH RSA | ❌ No | ZTSSH is Ed25519-only by design |
| OpenSSH ECDSA | ❌ No | ZTSSH is Ed25519-only by design |
| PKCS#8 (DER) | 🔄 Planned | Via conversion on import |

### Certificate Format

ZTSSH certificates are **not** OpenSSH certificates (`ssh-ed25519-cert-v01@openssh.com`). They use a custom binary wire format optimized for the continuous verification use case:

- Shorter expiry (5 minutes vs hours/days)
- No options/extensions map
- Lighter serialization for frequent renewal

A future bridge could translate between formats for mixed environments.

## Migration Path for Operators

### Phase 1: Audit Mode (parallel deployment)

1. Deploy ZTSSH alongside existing SSH infrastructure
2. Configure ZTSSH in audit-only mode (log but don't terminate)
3. Monitor session verification success rates
4. Identify clients/users that fail re-authentication

### Phase 2: Soft Enforcement

1. Enable ZTSSH verification with graceful degradation
2. Sessions that fail re-auth are logged and flagged
3. Grace period before termination (configurable)
4. Operator alerts on verification failures

### Phase 3: Full Enforcement

1. Enable strict ZTSSH mode
2. Failed re-authentication immediately terminates the session
3. Standard SSH fallback still available for non-ZTSSH clients

## Existing Ecosystem Components

### PAM Integration

ZTSSH does **not** replace PAM for initial authentication. The trust chain is:

```
1. PAM (or SSH key auth) → initial login → establishes identity
2. ZTSSH → continuous verification → proves ongoing identity
```

PAM modules can be configured to:
- Require ZTSSH-capable clients for specific groups
- Log ZTSSH verification events alongside PAM events
- Enforce ZTSSH policy based on PAM context

### Audit Systems (SIEM Integration)

ZTSSH audit events are emitted as structured JSON and can be forwarded to:

- **Splunk**: JSON log ingestion via HEC
- **ELK Stack**: Filebeat → Logstash → Elasticsearch
- **AWS CloudWatch**: JSON structured logs
- **Datadog**: Log forwarder integration

Audit event fields:
```json
{
  "timestamp": "2026-03-13T12:00:00Z",
  "event_type": "proof_verified",
  "outcome": "success",
  "principal": "alice",
  "peer_addr": "10.0.1.5:54321",
  "cert_serial": 42,
  "sequence": 7
}
```

### Certificate Management

ZTSSH's Root CA can coexist with existing PKI:

- Root CA key stored in the same HSM as other PKI roots
- Intermediate certificates follow X.509-like hierarchy
- Revocation lists can be distributed via existing CRL/OCSP infrastructure (future)

## Limitations and Trade-offs

1. **Ed25519 only**: No RSA/ECDSA support. This is a deliberate security choice.
2. **Custom certificate format**: Not X.509 or OpenSSH cert. Essential for 5-minute lifecycle.
3. **No SSH subsystem (yet)**: Current implementation uses raw TCP. `russh` integration planned.
4. **No SSH agent integration (yet)**: Ephemeral keys are managed in-process.
5. **Single server architecture**: No clustering or HA in the current implementation.

## Future Interop Work

- [ ] `russh` transport integration
- [ ] SSH agent protocol support for key storage
- [ ] OpenSSH ProxyCommand mode
- [ ] Certificate bridge (ZTSSH ↔ OpenSSH cert format)
- [ ] SCIM provisioning for principal management
- [ ] HashiCorp Vault integration for Root CA key storage
