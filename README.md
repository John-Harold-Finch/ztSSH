# ZTSSH — Zero Trust SSH

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=:.:=@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%-:           ::#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%#=.        .=*          .-*@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@%':.        .+"@@@@@@@@%++:        .-*@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@+-.        .+%@@@@@@@@@@@@@@@@@@@%*:        .:+%@@@@@@@@@@@@@@
@@@@@@@@@@%+:.       .-"%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%"-.       .=*%@@@@@@@@@
@@@@@@@=        .-"@@@@@@@@@@@@@@@@+""""""*+%@@@@@@@@@@@@@@@#=.       .:@@@@@@
@@@@@@@:   :+#@@@@@@@@@@@@@@@@@%*:==-     -=. .=@@@@@@@@@@@@@@@@@%+:   .@@@@@@
@@@@@@@.  :@@@@@@@@@@@@@@@@@@-                   -@@@@@@@@@@@@@@@@@@:  .@@@@@@
@@@@@@@.  :@@@@@@@@@@@@@@@@#         :::           :@@@@@@@@@@@@@@@@:  .@@@@@@
@@@@@@@   :@@@@@@@@@@@@@@@=      .*@@@@@@@@@-       -@@@@@@@@@@@@@@@:   @@@@@@
@@@@@@%   :@@@@@@@@@@@@@@@:     +@@*@@@@@@@@@@:      %@@@@@@@@@@@@@@:   @@@@@@
@@@@@@@   :@@@@@@@@@@@@@@:     "@@@%: -*@@@@@@@      =@@@@@@@@@@@@@@:   @@@@@@
@@@@@@@.  :@@@@@@@@@@@@@%:     "@@@%+ .=%@@@@@@*     =@@@@@@@@@@@@@%:   @@@@@@
@@@@@@@   .%@@@@@@@@@@@@@=     "@@%#@@@@@@@@@@@@     =@@@@@@@@@@@@@*:   @@@@@@
@@@@@@@.  .#@@@@@@@@@@@@@*     "@@@@@@@@@@@%%@@@     =@@@@@@@@@@@@@*.   @@@@@@
@@@@@@@   .#@@@@@@@@@@@@@%     +@@@@@@@@@@@@@@@@.    +@@@@@@@@@@@@@*:   @@@@@@
@@@@@@@   .#@@@@@@@@@@@:                               =@@@@@@@@@@@*:   @@@@@@
@@@@@@@   .=%@@@@@@@@@@:                               =@@@@@@@@@@%=:   @@@@@@
@@@@@@@    .--::%@@@@@@:                               =@@@@@@%::--.    @@@@@@
@@@@@@@  :-=  .:::=@@@:                               -@@#::::. :+-.    @@@@@@
@@@@@@@-    "@@@": ..#*=                               -%@:. =#@@@=   =%@@@@@@
@@@@@@@:  :#@@@% .    :::::==-.                   ..::::.   :..@@@@*:  %@@@@@@
@@@@@@@*+.   .:+:        -:  .::-.            .....  =:       ==:   .+:+@@@@@@
@@@@@@@% .="":    :+   +@@@@@+               :    +@@@@*  :*:.   +%+.  @@@@@@@
@@@@@@@@:   %@@@@@@@::::*%@@@%           .:::::: +%@@#=.  *@@@@@@@%.  =@@@@@@@
@@@@@@@@%   =@@@@@@@@+.::-==:.            ...           :#@@@@@@@@:   %@@@@@@@
@@@@@@@@@=   %@@@@@@@@@"=.   ..                        +@@@@@@@@@*   =@@@@@@@@
@@@@@@@@@%.   %@@@@@@@@:                               =@@@@@@@@@:  :@@@@@@@@@
@@@@@@@@@@%.  :@@@@@@@@:                               =@@@@@@@%:  .@@@@@@@@@@
@@@@@@@@@@@*   :@@@@@@@:                               =@@@@@@%:  :%@@@@@@@@@@
@@@@@@@@@@@@%    #@@@@@@===============================%@@@@@#.  :@@@@@@@@@@@@
@@@@@@@@@@@@@@:   =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=   -@@@@@@@@@@@@@
@@@@@@@@@@@@@@@=   .%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*   .%@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@:   :%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.   +@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@%.   :%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*.   =@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@:    *@@@@@@@@@@@@@@@@@@@@@@@@@:    +@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@=    .*@@@@@@@@@@@@@@@@@@@=.   .%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%:    :#@@@@@@@@@@@@@=.    *@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:    .=%@@@@@%-.    :%@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=     :*:     =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*       :*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:=#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#'*'%@@@@@@@'''#@@@@%''%@@@@@#'#@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@#+'@@@@:  .:   '@@*   :.  .%@*  =@@@@%. :@@@@@@@@@@@@@
@@@@@@@@@@@@@@%%%%%%%%@%'++%%@. .%@@@:..@%  :@@@@..-@*  =@@@@%. :@@@@@@@@@@@@@
@@@@@@@@@@@@@@'''''++'@''++'#@%   =%@@@@@@-  .'%@@@@@*  =%%%%*. :@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@#++#@@@#++@@@@@#:.   :@@@@@+:    '@@*   .....  :@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@'+'@@@@@#++@@@%%%@@@%. .@@%%@@@@*  -@*  =@@@@%. :@@@@@@@@@@@@@
@@@@@@@@@@@@@@%++*@@@@@@#++@@@. .#@@%  .@#  :%@@'  -@'  =@@@@%. :@@@@@@@@@@@@@
@@@@@@@@@@@@@@++++++++@@@+++'@@'.     :@@@@=.    .+@@*  =@@@@%. :@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                                                                                                                                                                                                                                                                           

**A proposal and reference implementation for continuous in-session identity verification in SSH.**

> OpenSSH verifies identity once. ZTSSH verifies identity for the entire life of the session.

## Why this project exists

SSH is trusted everywhere, but its trust model is still mostly **login-time trust**:

1. user authenticates,
2. session opens,
3. trust persists until logout.

That model is increasingly weak against:
- stolen laptops,
- token theft after login,
- long-lived shells on production servers,
- session hijacking after initial authentication,
- lateral movement inside infrastructure.

ZTSSH proposes a simple change in philosophy:

**authentication must not be a one-time event; it must be a continuous property of the session.**

## What ZTSSH does

ZTSSH introduces a recurring challenge-response loop inside SSH sessions.

Every $60$ seconds by default:

1. the server sends a fresh random challenge,
2. the client proves liveness by signing it with a fresh ephemeral key,
3. the client presents a very short-lived certificate,
4. the server verifies certificate validity, issuer, signature, TTL and policy,
5. the session continues or is terminated immediately.

In practice, that means a compromised identity stops being trusted quickly, even **after** the shell is already open.

## Concrete protocol overview

### 1. Trust hierarchy

ZTSSH uses a hierarchical CA model:

```text
Root CA (offline)
   ↓ issues 24h server licence
Sub-CA embedded in each server
   ↓ issues 5 min client certificate
Client session
```

### 2. Certificate types

| Certificate | Issued by | Used by | Default TTL | Purpose |
|---|---|---|---|---|
| `IntermediateCertificate` | Root CA | Server Sub-CA | 24 hours | Authorize a server to certify clients |
| `ZtsshCertificate` | Server Sub-CA | Client | 5 minutes | Prove client identity continuously |

### 3. Session loop

```text
Client connects
  → receives short-lived client cert
  → opens session

Every challenge interval:
  Server → IDENTITY_CHALLENGE(nonce, seq, deadline)
  Client → optionally renews cert locally via Sub-CA
  Client → IDENTITY_PROOF(cert, signature(challenge))
  Server → verifies cert + signature + revocation state
  Server → IDENTITY_ACK or SESSION_TERMINATE
```

### 4. Why the Sub-CA is embedded in the server

This is critical.

ZTSSH does **not** require a central online CA during the session.
Each server has a local `SubCa` that can issue client certificates under a Root-issued licence.

That gives:
- no network dependency during revalidation,
- low latency,
- graceful operation during CA outages,
- better operational realism for production infra.

### 5. Revocation model

ZTSSH currently supports 3 levels of revocation:

- **principal ban**: ban a user globally,
- **server revocation**: invalidate a server licence,
- **client certificate revocation**: invalidate one badge immediately.

## Current implementation status

The repository contains a working Rust implementation covering Phases 1 through 5:

### Rust crates (Phase 1 — Foundation)

- [rust/crates/ztssh-crypto](rust/crates/ztssh-crypto)
  - Ed25519 keypairs
  - zeroize-on-drop private key handling
  - `IntermediateCertificate`
  - `ZtsshCertificate`
  - nonce generation

- [rust/crates/ztssh-protocol](rust/crates/ztssh-protocol)
  - message constants
  - binary message types
  - protocol defaults

- [rust/crates/ztssh-ca](rust/crates/ztssh-ca)
  - `RootCa`
  - `SubCa`
  - `RevocationList`
  - verification results

### Binaries and transport (Phase 2 — Functional prototype)

- [rust/crates/ztssh-transport](rust/crates/ztssh-transport)
  - TCP transport with length-prefixed framing
  - handshake messages (ClientHello, ServerHello, CertRenewal)
  - server-side challenge loop
  - client-side proof generation and certificate renewal

- [rust/crates/ztssh-ca-cli](rust/crates/ztssh-ca-cli) → `ztssh-ca` binary
  - `init` — generate Root CA keypair
  - `authorize-server` — issue IntermediateCertificate
  - `revoke-server` / `ban-principal` — revocation management
  - `generate-server-key` — create Sub-CA keypair
  - `show` / `export-revocation` — inspect CA state

- [rust/crates/ztsshd](rust/crates/ztsshd) → `ztsshd` binary
  - loads Sub-CA key + IntermediateCertificate
  - accepts connections, issues client certificates
  - runs periodic challenge-response loop
  - verifies proofs, handles certificate renewal

- [rust/crates/ztssh-client](rust/crates/ztssh-client) → `ztssh` binary
  - connects to server, performs handshake
  - responds to identity challenges
  - automatic certificate renewal before expiry

### Production readiness (Phase 4)

- [rust/crates/ztssh-audit](rust/crates/ztssh-audit)
  - structured audit event system with typed events
  - `tracing`-based logging (`text` or JSON output)
  - all binaries emit machine-parseable audit trails

- [rust/crates/ztssh-policy](rust/crates/ztssh-policy)
  - TOML-configured policy engine
  - principal allowlists/denylists, CIDR source-IP filtering
  - per-principal rules (max sessions, allowed IPs)
  - sliding-window rate limiter (per-IP, configurable window/limit)
  - enforced at connection time in the transport layer (`--policy` flag)

- [rust/crates/ztssh-keystore](rust/crates/ztssh-keystore)
  - filesystem-backed key storage with `Keystore` trait
  - restricted file permissions (0600 on Unix)
  - zeroize-on-delete for private key material
  - integrated in `ztssh-ca` CLI for structured key management
  - extensible to HSM/agent backends

### Real-world deployment (Phase 5)

- [rust/crates/ztssh-ssh](rust/crates/ztssh-ssh)
  - SSH transport via `russh` 0.57 (ZTSSH protocol over SSH subsystem channels)
  - Ed25519 host key generation
  - server handler with session channel and "ztssh" subsystem
  - client handler with SSH connect + subsystem negotiation
  - both binaries support `--mode tcp|ssh` to select transport

- **Rate limiting & connection throttling**
  - token-bucket rate limiter enforced per source IP in the accept loop
  - configurable `max_connections` with atomic counter
  - `RateLimited` error variant surfaced to audit events

- **Revocation enforcement in transport**
  - principal ban check at handshake time
  - client certificate serial revocation check in proof verification
  - `SignedRevocationList` — Ed25519-signed CRL snapshots with wire serialization
  - `verify_and_extract()` validates signer before accepting a CRL

### Documentation

- [docs/INTEROP.md](docs/INTEROP.md) — interoperability with SSH ecosystems, `russh` integration plan, SIEM integration
- [docs/OPERATOR.md](docs/OPERATOR.md) — operator guide: CA setup, server provisioning, logging, policy, monitoring, runbook
- [docs/AUDIT.md](docs/AUDIT.md) — security audit preparation: threat model, attack surface, cryptographic checklist

### Quality status

- 143 tests passing (78 unit + 23 property-based + 17 security + 7 constant-time + 6 handshake + 6 end-to-end + 6 CRL/rate-limit)
- `cargo clippy -- -D warnings` clean
- **6 end-to-end integration tests** (real server + real client, multi-cycle challenge-response, cert renewal, policy enforcement)
- structured audit logging via `tracing` (text and JSON formats)
- TOML-based policy engine with CIDR IP filtering, enforced at connection time
- filesystem key storage with zeroize-on-delete, integrated in CA CLI
- memory-safe Rust baseline
- no online CA dependency in the core architecture
- constant-time public key comparison via `subtle`
- 9 fuzz targets covering all parsers
- ProVerif formal model for authentication and secrecy properties
- reproducible build configuration
- operator documentation and security audit preparation guides

### Local demo

Automated demo scripts are available:

```bash
# Linux / macOS
./scripts/demo.sh

# Windows PowerShell
.\scripts\demo.ps1
```

Or run it manually:

```bash
cd rust/

# 1. Initialize a Root CA
cargo run --bin ztssh-ca -- init

# 2. Generate a server Sub-CA key
cargo run --bin ztssh-ca -- generate-server-key --out server.key

# 3. Authorize the server (use the public key printed in step 2)
cargo run --bin ztssh-ca -- authorize-server \
  --server-id srv-demo \
  --pubkey <SERVER_PUBLIC_KEY_HEX> \
  --out intermediate.cert

# 4. Start the server (5s challenge interval for demo)
cargo run --bin ztsshd -- \
  --cert intermediate.cert \
  --key server.key \
  --challenge-interval 5

# 5. In another terminal, connect as a client
cargo run --bin ztssh -- alice@127.0.0.1:2222

# Or with explicit flags
cargo run --bin ztssh -- --connect 127.0.0.1:2222 --principal alice
```

You should see the continuous challenge-response loop in action:
- server sends `IDENTITY_CHALLENGE` every 5 seconds
- client signs and responds with `IDENTITY_PROOF`
- server verifies and sends `IDENTITY_ACK`
- certificates are renewed automatically before expiry

## Why contributors may care

ZTSSH is interesting because it sits at the intersection of:

- SSH,
- zero trust architecture,
- applied cryptography,
- systems programming,
- defensive infrastructure.

This is not “just another SSH wrapper”.
It is an attempt to define a **new trust model for remote shell access**.

If successful, the project can become:
- a reference protocol,
- a Rust SSH implementation with continuous auth,
- a research-grade security project,
- a deployable hardened alternative for critical infrastructure.

## Contributor roadmap

The roadmap below is designed to make contribution paths obvious.

### Phase 1 — Core protocol foundation

- [x] Rust workspace
- [x] cryptographic primitives
- [x] hierarchical CA model
- [x] revocation logic
- [x] protocol message definitions
- [x] serialization and verification tests

### Phase 2 — Functional SSH prototype

- [x] build TCP transport with length-prefixed framing (SSH integration via `russh` planned for Phase 3)
- [x] implement `ztssh` client binary
- [x] implement `ztsshd` server binary
- [x] implement offline `ztssh-ca` CLI
- [x] add local demo: connect, challenge, renew, terminate

### Phase 3 — Security hardening

- [x] fuzz all parsers and wire formats
- [x] property-based tests for protocol state machine
- [x] replay and downgrade resistance tests
- [x] formal modelling in ProVerif or Tamarin
- [x] constant-time review of sensitive operations
- [x] reproducible builds

### Phase 4 — Production readiness

- [x] interoperability story with existing SSH ecosystems
- [x] agent/key storage strategy
- [x] observability and audit logs
- [x] policy engine (with transport-layer enforcement)
- [x] documentation for operators
- [x] third-party security audit preparation
- [x] end-to-end integration tests
- [x] automated demo scripts

### Phase 5 — Real-world deployment

- [x] `russh` SSH transport integration (ZTSSH protocol over SSH subsystem channels)
- [x] channel multiplexing (ZTSSH as SSH subsystem alongside shell/exec)
- [x] signed revocation list distribution (Ed25519-signed CRL snapshots with wire format)
- [x] rate limiting and connection throttling in policy engine
- [x] revocation enforcement in transport (principal ban + cert serial check)
- [x] `--mode tcp|ssh` flag on both binaries
- [ ] full bidirectional protocol bridge over SSH channel (data ↔ ZTSSH framing)
- [ ] HSM / hardware token backend for `Keystore` trait
- [ ] SSH agent protocol integration (ssh-agent forwarding)
- [ ] TLS or Noise encryption for the TCP transport (pre-SSH phase)
- [x] CI/CD pipeline (GitHub Actions)
- [ ] cross-platform CI builds and release artifacts
- [ ] packaging (Debian/RPM/Homebrew/Scoop)
- [ ] benchmark harness (latency per challenge cycle, throughput under load)
- [ ] third-party security audit execution
- [ ] SIEM integration (Splunk, Elastic, Datadog exporters)

## Good first contributions

High-value entry points for contributors:

1. finish the bidirectional SSH channel ↔ ZTSSH framing bridge,
2. HSM keystore backend — PKCS#11 or YubiKey integration,
3. CRL distribution endpoint — serve signed revocation snapshots over HTTPS,
4. benchmark harness — measure challenge-response latency,
5. cross-platform CI — build + test on Linux/macOS/Windows,
6. Debian/RPM packaging,
7. protocol diagrams and docs cleanup.

## White paper

A project white paper is available in [docs/WHITEPAPER.md](docs/WHITEPAPER.md).

The white paper is intentionally written in a concise, protocol-first style inspired by early foundational internet and cryptography papers.

## Build and test

```bash
cd rust
cargo build
cargo test
cargo clippy -- -D warnings
```

## Security policy

See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
