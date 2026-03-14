# ZTSSH Formal Verification

This directory contains formal models for the ZTSSH protocol.

## ProVerif Model

[`proverif/ztssh.pv`](proverif/ztssh.pv) models the core challenge-response 
loop of ZTSSH in the [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) 
protocol analyser (Dolev-Yao network attacker model).

### What is modelled

- **Root CA** (offline): issues intermediate certificates
- **Server** (Sub-CA): issues short-lived client certificates, sends challenges
- **Client**: signs challenges with ephemeral keys
- **Full Dolev-Yao attacker**: can intercept, modify, replay, inject messages

### Security properties verified

| Property | Query | Status |
|----------|-------|--------|
| Authentication | `ProofVerified(p, n) ==> ChallengeIssued(n, seq)` | To verify |
| Secrecy | `attacker(secret_payload)` | To verify |
| Injective agreement | `inj-event(ProofVerified) ==> inj-event(ChallengeIssued)` | To verify |

### Running the model

Install ProVerif (≥ 2.04):

```bash
# macOS (Homebrew)
brew install proverif

# Linux (from source)
# See https://bblanche.gitlabpages.inria.fr/proverif/

# Run the model
proverif formal/proverif/ztssh.pv
```

### Extending the model

Natural extensions for future work:
- Model certificate renewal within the challenge loop
- Add revocation to the model (banned principals)
- Model multiple servers with different Sub-CAs
- Add Tamarin model for more fine-grained temporal properties

## Tamarin Model (planned)

A Tamarin prover model is planned for Phase 4 to verify:
- Temporal ordering of challenge-response sequences
- Post-compromise security with ephemeral key rotation
- Multi-session composition properties
