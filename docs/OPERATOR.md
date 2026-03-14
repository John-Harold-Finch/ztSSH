# ZTSSH Operator Guide

## Quick Start

### Prerequisites

- Rust toolchain (1.75+)
- `cargo` build system

### Build

```bash
cd rust/
cargo build --release
```

Binaries are produced in `target/release/`:
- `ztssh-ca` — Offline Root CA management
- `ztsshd` — Server daemon
- `ztssh` — Client

---

## Root CA Setup (Offline)

The Root CA should be managed on an air-gapped machine. It generates server licences and manages global revocation.

### Initialize the Root CA

```bash
ztssh-ca --dir /secure/ca-state init
```

Output:
```
Root CA initialized in /secure/ca-state
Public key: a1b2c3d4e5f6...
IMPORTANT: Keep root.key offline and secure.
```

**Files created:**
| File | Contents | Security |
|---|---|---|
| `root.key` | 32-byte Ed25519 private key | **CRITICAL** — keep offline |
| `state.json` | Public key, serial counter, revocation list | Non-sensitive metadata |

### State Directory Layout

```
/secure/ca-state/
├── root.key         ← 32B Ed25519 private key (air-gapped!)
└── state.json       ← JSON metadata
```

---

## Server Provisioning

### 1. Generate a server Sub-CA key

```bash
ztssh-ca --dir /secure/ca-state generate-server-key --out srv-01.key
```

Output:
```
Server Sub-CA keypair generated.
  Public key: 7f8e9d...
  Private key written to: srv-01.key
```

### 2. Authorize the server

```bash
ztssh-ca --dir /secure/ca-state authorize-server \
  --server-id srv-01 \
  --pubkey 7f8e9d... \
  --principals alice,bob,carol \
  --out srv-01.cert
```

Output:
```
Intermediate certificate issued:
  Serial:     1
  Server ID:  srv-01
  Principals: ["alice", "bob", "carol"]
  TTL:        86400s (24.0h)
  Written to: srv-01.cert
```

### 3. Transfer to server

Copy `srv-01.key` and `srv-01.cert` to the server securely. Delete from the CA machine.

**Important:** The intermediate certificate has a 24h TTL. You must re-authorize the server before it expires.

---

## Server Daemon Configuration

### Basic startup

```bash
ztsshd \
  --cert /etc/ztssh/intermediate.cert \
  --key /etc/ztssh/server.key \
  --listen 0.0.0.0:2222 \
  --challenge-interval 60 \
  --challenge-deadline 30
```

### CLI Options

| Flag | Default | Description |
|---|---|---|
| `--cert` | (required) | Path to IntermediateCertificate file |
| `--key` | (required) | Path to Sub-CA private key (32 bytes) |
| `--listen` | `127.0.0.1:2222` | Listen address |
| `--challenge-interval` | `60` | Seconds between challenges |
| `--challenge-deadline` | `30` | Seconds to respond to a challenge |
| `--log-format` | `text` | Log format: `text` or `json` |

### Logging

ZTSSH uses structured logging via the `tracing` framework.

**Control log verbosity with `RUST_LOG`:**

```bash
# Default (info level)
RUST_LOG=info ztsshd --cert ... --key ...

# Debug level (includes challenge details)
RUST_LOG=debug ztsshd --cert ... --key ...

# JSON format for SIEM ingestion
ztsshd --cert ... --key ... --log-format json
```

**Log levels:**
| Level | Content |
|---|---|
| `error` | Fatal errors, startup failures |
| `warn` | Session terminations, proof rejections, policy denials |
| `info` | Connections, handshakes, ACKs, certificate operations |
| `debug` | Individual challenges, frame-level details |
| `trace` | Wire protocol bytes (development only) |

### JSON Log Format

When `--log-format json` is used, each log line is a JSON object:

```json
{"timestamp":"2026-03-13T12:00:00Z","level":"INFO","fields":{"message":"ZTSSH server listening","listen_addr":"0.0.0.0:2222"}}
```

Audit events contain an `audit=true` field for filtering:

```json
{"timestamp":"2026-03-13T12:00:01Z","level":"INFO","fields":{"audit":true,"event_type":"proof_verified","principal":"alice","peer":"10.0.1.5:54321"}}
```

---

## Policy Configuration

Create a TOML file for server policy:

```toml
# /etc/ztssh/policy.toml

[server]
# Maximum concurrent connections (0 = unlimited)
max_connections = 100

# Only these principals may connect (enforced if require_principal_allowlist = true)
allowed_principals = ["alice", "bob", "carol", "dave"]

# These principals are always rejected
denied_principals = ["hacker", "banned-user"]

# Enforce allowlist
require_principal_allowlist = true

# Maximum certificate TTL the server will issue (seconds)
max_cert_ttl = 300

# Minimum challenge interval (seconds) — prevents misconfiguration
min_challenge_interval = 10

# Per-principal rules
[[principal_rules]]
principal = "alice"
max_sessions = 5
allowed_source_ips = ["10.0.0.0/8"]

[[principal_rules]]
principal = "bob"
max_sessions = 2
allowed_source_ips = ["192.168.1.0/24", "10.0.0.0/8"]
```

---

## Client Configuration

### Basic connection

```bash
ztssh --connect srv-01.example.com:2222 --principal alice
```

### CLI Options

| Flag | Default | Description |
|---|---|---|
| `--connect` | (required) | Server address (`host:port`) |
| `--principal` | (required) | User identity |
| `--log-format` | `text` | Log format: `text` or `json` |

### Client Logging

```bash
RUST_LOG=info ztssh --connect ... --principal alice
RUST_LOG=debug ztssh --connect ... --principal alice --log-format json
```

---

## Revocation Management

### Ban a principal globally

```bash
ztssh-ca --dir /secure/ca-state ban-principal --name hacker
```

All servers that receive an updated revocation list will immediately reject this principal.

### Revoke a server's licence

```bash
ztssh-ca --dir /secure/ca-state revoke-server --serial 1
```

### Export the revocation list

```bash
ztssh-ca --dir /secure/ca-state export-revocation --out crl.json
```

Distribute `crl.json` to servers. They merge it into their local revocation list.

### View CA state

```bash
ztssh-ca --dir /secure/ca-state show
```

---

## Monitoring and Alerting

### Key Metrics

| Metric | Source | Alert Threshold |
|---|---|---|
| Challenge failures | `event_type=proof_rejected` | > 5 per minute per server |
| Session terminations | `event_type=session_terminated` | Depends on environment |
| Certificate renewals | `event_type=cert_renewed` | Sudden drop (potential issue) |
| Connection rate | `event_type=connection_accepted` | Unusual spike |
| Policy denials | `event_type=policy_denied` | Any occurrence |

### SIEM Integration

Filter audit events with `"audit":true` in JSON log output. Forward via:

1. **File-based**: Log to file, tail with Filebeat/Fluentd
2. **Stdout**: Capture container stdout in Kubernetes
3. **Journal**: `ztsshd 2>&1 | systemd-cat -t ztsshd`

### Health Check

A healthy server will produce periodic `challenge_sent` and `proof_verified` events for active sessions.

---

## Operational Runbook

### Certificate Expiry

**Symptom:** Server logs `Intermediate certificate has expired`

**Resolution:**
1. On the CA machine: `ztssh-ca authorize-server --server-id srv-01 --pubkey ... --out new.cert`
2. Transfer `new.cert` to the server
3. Restart `ztsshd` with `--cert new.cert`

### Client Repeatedly Terminated

**Symptom:** Client keeps getting `SESSION_TERMINATE: challenge_timeout`

**Possible causes:**
- Client CPU overloaded (signing too slow)
- Network latency exceeds deadline
- Clock skew between client/server

**Resolution:**
- Increase `--challenge-deadline` on server
- Check client system resources
- Sync clocks (NTP)

### Unauthorized Access Attempt

**Symptom:** `event_type=policy_denied` or `event_type=proof_rejected` in logs

**Resolution:**
1. Check the principal name and source IP
2. If malicious: `ztssh-ca ban-principal --name <principal>`
3. Export and distribute updated revocation list
4. Review access logs for lateral movement

---

## Security Hardening Checklist

- [ ] Root CA key stored on air-gapped machine
- [ ] Server key files have 0600 permissions
- [ ] `RUST_LOG` not set to `trace` in production
- [ ] JSON log format enabled for SIEM ingestion
- [ ] Revocation lists distributed regularly
- [ ] Challenge interval ≤ 60s
- [ ] Challenge deadline ≤ 30s
- [ ] Certificate TTL ≤ 300s
- [ ] Policy file restricts allowed principals
- [ ] Denied principals list maintained
- [ ] Monitoring alerts configured for proof rejections
