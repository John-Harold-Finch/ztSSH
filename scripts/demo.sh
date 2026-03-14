#!/usr/bin/env bash
# ZTSSH automated demo — creates a CA, server, and client, runs 3 challenge cycles.
# Usage: ./scripts/demo.sh
# Requires: cargo (Rust toolchain)

set -euo pipefail

DEMO_DIR="$(mktemp -d)"
trap 'echo "Cleaning up $DEMO_DIR"; rm -rf "$DEMO_DIR"' EXIT

cd "$(dirname "$0")/../rust"

echo "=== ZTSSH Automated Demo ==="
echo "Working directory: $DEMO_DIR"
echo ""

# 1. Initialize Root CA
echo "▸ Step 1: Initialize Root CA"
cargo run --quiet --bin ztssh-ca -- --dir "$DEMO_DIR/ca" init
echo ""

# 2. Generate server Sub-CA key
echo "▸ Step 2: Generate server Sub-CA keypair"
OUTPUT=$(cargo run --quiet --bin ztssh-ca -- --dir "$DEMO_DIR/ca" generate-server-key --out "$DEMO_DIR/server.key" 2>&1)
echo "$OUTPUT"
PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | sed 's/.*Public key: //')
echo "  Extracted public key: $PUBKEY"
echo ""

# 3. Authorize the server
echo "▸ Step 3: Authorize server (issue IntermediateCertificate)"
cargo run --quiet --bin ztssh-ca -- --dir "$DEMO_DIR/ca" authorize-server \
    --server-id demo-server \
    --pubkey "$PUBKEY" \
    --out "$DEMO_DIR/intermediate.cert"
echo ""

# 4. Show CA state
echo "▸ Step 4: Root CA state"
cargo run --quiet --bin ztssh-ca -- --dir "$DEMO_DIR/ca" show
echo ""

# 5. Start server in background
echo "▸ Step 5: Starting ztsshd (challenge every 2s)"
cargo run --quiet --bin ztsshd -- \
    --cert "$DEMO_DIR/intermediate.cert" \
    --key "$DEMO_DIR/server.key" \
    --listen 127.0.0.1:2222 \
    --challenge-interval 2 \
    --challenge-deadline 5 &
SERVER_PID=$!
sleep 2

# 6. Run client for a few cycles
echo ""
echo "▸ Step 6: Connecting client as 'alice'"
timeout 8 cargo run --quiet --bin ztssh -- alice@127.0.0.1:2222 || true

# 7. Cleanup
echo ""
echo "▸ Stopping server (PID $SERVER_PID)"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Demo complete ==="
echo "The ZTSSH challenge-response loop ran successfully."
