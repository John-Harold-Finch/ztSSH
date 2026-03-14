# ZTSSH Security Audit Preparation

## Audit Scope

This document provides a structured approach for a third-party security audit of the ZTSSH project. It describes the threat model, attack surface, cryptographic properties to verify, and known areas requiring scrutiny.

## 1. Threat Model

### Attacker Capabilities

| Attacker Class | Capabilities | Relevant ZTSSH Component |
|---|---|---|
| **Network adversary (Dolev-Yao)** | Intercept, replay, inject, modify messages | Transport, Protocol |
| **Compromised client** | Valid credentials, running malicious code | Challenge loop, certificate renewal |
| **Compromised server** | Valid Sub-CA key, attempting to expand access | CA hierarchy, certificate scope |
| **Stolen key material** | Possesses a copy of private keys | Keystore, zeroization, TTL limits |
| **Insider threat** | Authorized principal, attempting unauthorized actions | Policy engine, principal restrictions |

### Security Goals

1. **Continuous authentication**: A session must not persist beyond one challenge interval after identity is lost
2. **Certificate scoping**: A certificate from Server A must not be accepted by Server B
3. **Forward secrecy of sessions**: Compromising a key after session end must not reveal past session data
4. **Revocation immediacy**: A revoked certificate must be rejected on the next verification
5. **No trust escalation**: A client authorized for one principal must not access another

## 2. Cryptographic Properties to Verify

### Ed25519 Usage

| Property | Implementation | File | Audit Priority |
|---|---|---|---|
| Key generation | `OsRng` via `rand` crate | `keypair.rs` | HIGH |
| Signature scheme | Ed25519 via `ed25519-dalek` | `keypair.rs` | HIGH |
| Key zeroization | `ZeroizeOnDrop` on `ed25519-dalek::SigningKey` | `keypair.rs` | HIGH |
| Constant-time comparison | `subtle::ConstantTimeEq` | `keypair.rs` | HIGH |
| Nonce generation | `OsRng.fill_bytes()` | `nonce.rs` | HIGH |

### Certificate Lifecycle

| Property | Implementation | File |
|---|---|---|
| Certificate TTL enforcement | `is_expired()` checks `SystemTime::now()` | `certificate.rs`, `intermediate.rs` |
| Signature binding | `signable_bytes()` excludes signature field | `certificate.rs`, `intermediate.rs` |
| Issuer verification | Constant-time key comparison | `sub.rs`, `root.rs` |
| Serial uniqueness | `AtomicU64` counter | `root.rs`, `sub.rs` |

### Areas Requiring Scrutiny

1. **`signable_bytes()` completeness**: Ensure all security-relevant fields are included in the signed data. Missing a field could allow certificate modification.

2. **Timestamp source**: `SystemTime::now()` is used for TTL. Clock manipulation could extend certificate lifetime.

3. **Serial counter**: `AtomicU64` with `fetch_add`. In crash scenarios, serials could be reused if not persisted atomically.

4. **Wire format parsing**: All `from_wire()` and `deserialize()` functions accept untrusted input. Fuzz targets exist but should be run for extended periods.

## 3. Attack Surface Inventory

### Network-Facing Code

| Component | Entry Point | Input Source | Fuzzing |
|---|---|---|---|
| TCP framing | `read_message()` | Network | ✅ (via message parsers) |
| ClientHello parser | `parse_client_hello()` | Network | ✅ fuzz target |
| ServerHello parser | `parse_server_hello()` | Network | ✅ fuzz target |
| CertRenewal parser | `parse_cert_renewal_request_v2()` | Network | ✅ fuzz target |
| IdentityChallenge | `IdentityChallenge::deserialize()` | Network | ✅ fuzz target |
| IdentityProof | `IdentityProof::deserialize()` | Network | ✅ fuzz target |
| IdentityAck | `IdentityAck::deserialize()` | Network | ✅ fuzz target |
| SessionTerminate | `SessionTerminate::deserialize()` | Network | ✅ fuzz target |
| Certificate wire | `ZtsshCertificate::from_wire()` | Network | ✅ fuzz target |
| Intermediate wire | `IntermediateCertificate::from_wire()` | Network | ✅ fuzz target |

### File-Based Input

| Component | Input | Validation |
|---|---|---|
| Root key loading | 32-byte raw file | Length check |
| Server key loading | 32-byte raw file | Length check |
| Intermediate cert loading | Wire format | `from_wire()` + expiry check |
| Policy file | TOML | `toml::from_str()` with typed schema |
| CA state | JSON | `serde_json::from_str()` with typed schema |

### Privilege Boundaries

| Boundary | From | To | Control |
|---|---|---|---|
| Network → Server | TCP stream | Parsed messages | Framing (64KB max), parser validation |
| CA → Sub-CA | Root CA cert | Server authority | Intermediate cert lifetime (24h) |
| Sub-CA → Client | Server cert | Client identity | Certificate lifetime (5 min) |
| Admin → CA | CLI input | Revocation state | Input validation, state file |

## 4. Formal Verification

A ProVerif model exists at `rust/formal/proverif/ztssh.pv` that verifies:

1. **Authentication**: If the server accepts a proof, the client must have sent it
2. **Secrecy**: The attacker cannot learn the session payload
3. **Injective agreement**: Each accepted proof corresponds to a unique client action

### Limitations of the Formal Model

- Does not model clock drift or timing side-channels
- Does not model the revocation list distribution mechanism
- Assumes perfect random number generation
- Does not model certificate renewal race conditions

## 5. Known Limitations

| Limitation | Risk | Mitigation |
|---|---|---|
| No TLS/SSH encryption layer | Messages sent in cleartext | Current TCP transport for development only; `russh` integration planned |
| `SystemTime` for TTL | Clock manipulation extends certificates | NTP sync recommended; short TTLs limit window |
| `AtomicU64` serial counter | Non-persistent in crash | State.json backup; minor risk (duplicate serial → signature differs) |
| No rate limiting on connections | DoS possible | OS-level `iptables`/firewall; policy engine `max_connections` config |
| No TLS for CRL distribution | CRL could be tampered | Signed CRLs planned; distribute over trusted channels |

## 6. Dependency Audit

### Critical Dependencies

| Crate | Version | Role | Audit Status |
|---|---|---|---|
| `ed25519-dalek` | 2.x | Signature scheme | RustCrypto; widely audited |
| `rand` | 0.8 | CSPRNG, nonce generation | RustCrypto; widely audited |
| `subtle` | 2.x | Constant-time operations | RustCrypto; widely audited |
| `zeroize` | 1.x | Memory wiping | RustCrypto; widely audited |
| `tokio` | 1.x | Async runtime | Widely audited; no crypto role |

### Recommended: `cargo audit`

```bash
cargo install cargo-audit
cargo audit
```

### Recommended: `cargo deny`

```bash
cargo install cargo-deny
cargo deny check advisories
cargo deny check licenses
```

## 7. Recommended Audit Focus Areas

### Priority 1 (Critical)

1. Certificate `signable_bytes()` completeness (both types)
2. Ed25519 signature verification correctness
3. Nonce uniqueness and entropy quality
4. Wire format parsers: buffer overflow, integer overflow, untrusted length fields
5. Key zeroization: verify private keys are actually zeroed after drop

### Priority 2 (High)

6. Challenge-response loop: replay protection, sequence enforcement
7. Revocation list merge: union correctness, no entries lost
8. Constant-time operations: verify `subtle` usage prevents timing leaks
9. Sub-CA certificate scoping: cross-server isolation
10. Policy engine: deny list bypass, allowlist logic

### Priority 3 (Medium)

11. State persistence: JSON/file race conditions
12. Concurrency: `Arc<Mutex<SubCa>>` under load
13. Error handling: information leakage in error messages
14. Log output: no private key material in logs

## 8. Reproduction Environment

```bash
# Clone and build
git clone <repo>
cd ztssh/rust
cargo build

# Run all tests
cargo test

# Run clippy
cargo clippy --all-targets -- -D warnings

# Run fuzzing (requires nightly)
cd fuzz
cargo +nightly fuzz run fuzz_certificate_wire -- -max_total_time=300

# Run ProVerif model
cd formal/proverif
proverif ztssh.pv
```

## 9. Contact

For coordinated vulnerability disclosure, see [SECURITY.md](../SECURITY.md).
