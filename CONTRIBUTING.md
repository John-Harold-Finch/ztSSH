# Contributing to ZTSSH

Thank you for considering contributing to ZTSSH. This is a security-critical project, so we hold contributions to a high standard.

## Getting Started

```bash
# Clone
git clone https://github.com/John-Harold-Finch/ztSSH.git
cd ztssh/rust

# Build
cargo build

# Test (all 143 tests must pass)
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt --check
```

## What We Need Help With

Check the [Issues](../../issues) tab for tasks labeled:

- `good first issue` — Great for newcomers
- `help wanted` — Non-trivial tasks we'd love help with
- `security` — Security-sensitive work (experience required)

### Priority Areas

1. **Fuzz Testing** — Fuzz all wire format parsers with `cargo-fuzz`
2. **Formal Verification** — Model the protocol in ProVerif or Tamarin
3. **HSM Integration** — Hardware security module support for Root CA keys
4. **Audit Tooling** — Real-time dashboards and SIEM export for audit events
5. **Platform Packages** — Debian/RPM/Homebrew distribution packages

## Contribution Guidelines

### Code

- **Zero `unsafe`** — No unsafe blocks in ZTSSH code. If you think you need it, open an issue first.
- **All tests must pass** — `cargo test` must show 0 failures
- **No warnings** — `cargo clippy -- -D warnings` must be clean
- **Formatted** — `cargo fmt` before committing
- **Documented** — Public APIs must have doc comments with `///`

### Security

- **Never log private keys** or certificate signatures at INFO level
- **Always zeroize** sensitive material on drop
- **Constant-time** operations for anything involving secrets
- **No `unwrap()` on user input** — Use proper error handling with `Result`

### Commits

- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `security:`
- One logical change per commit
- Reference issue numbers: `feat: add SSH transport layer (#42)`

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/ssh-transport`
3. Write tests first (TDD encouraged)
4. Ensure `cargo test && cargo clippy -- -D warnings && cargo fmt --check` passes
5. Open a PR with a clear description of what and why

## Code of Conduct

Be respectful. Be constructive. Focus on the code, not the person.

## License

By contributing, you agree that your contributions will be licensed under the GNU AGPLv3-or-later license used by this project.

## Read first

Before opening larger design PRs, read the project overview in [README.md](README.md), the protocol details in [docs/PROTOCOL.md](docs/PROTOCOL.md), and the research-style overview in [docs/WHITEPAPER.md](docs/WHITEPAPER.md).
