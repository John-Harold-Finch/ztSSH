#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# verify-reproducible.sh — Reproducible build verification
# ─────────────────────────────────────────────────────────
#
# Builds the workspace twice and compares binary outputs.
# If the hashes match, the build is reproducible.
#
# Usage:
#   cd rust/
#   ./scripts/verify-reproducible.sh
#
# Requirements:
#   - cargo, sha256sum
#   - Unix-like shell (Linux, macOS, WSL)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

echo "=== ZTSSH Reproducible Build Verification ==="
echo ""

# Build pass 1
echo "[1/4] Building (pass 1)..."
cargo build --profile reproducible 2>/dev/null
mkdir -p /tmp/ztssh-repro-1
for bin in target/reproducible/ztssh target/reproducible/ztsshd target/reproducible/ztssh-ca; do
    if [ -f "$bin" ]; then
        cp "$bin" "/tmp/ztssh-repro-1/$(basename "$bin")"
    fi
done
sha256sum /tmp/ztssh-repro-1/* > /tmp/ztssh-repro-1/checksums.txt
echo "   Pass 1 complete."

# Clean
echo "[2/4] Cleaning build artifacts..."
cargo clean 2>/dev/null

# Build pass 2
echo "[3/4] Building (pass 2)..."
cargo build --profile reproducible 2>/dev/null
mkdir -p /tmp/ztssh-repro-2
for bin in target/reproducible/ztssh target/reproducible/ztsshd target/reproducible/ztssh-ca; do
    if [ -f "$bin" ]; then
        cp "$bin" "/tmp/ztssh-repro-2/$(basename "$bin")"
    fi
done
sha256sum /tmp/ztssh-repro-2/* > /tmp/ztssh-repro-2/checksums.txt
echo "   Pass 2 complete."

# Compare
echo "[4/4] Comparing checksums..."
echo ""

PASS=true
while IFS= read -r line; do
    hash=$(echo "$line" | awk '{print $1}')
    file=$(basename "$(echo "$line" | awk '{print $2}')")
    hash2=$(grep "$file" /tmp/ztssh-repro-2/checksums.txt | awk '{print $1}')
    
    if [ "$hash" = "$hash2" ]; then
        echo "  ✓ $file: MATCH ($hash)"
    else
        echo "  ✗ $file: MISMATCH"
        echo "    Pass 1: $hash"
        echo "    Pass 2: $hash2"
        PASS=false
    fi
done < /tmp/ztssh-repro-1/checksums.txt

echo ""
if $PASS; then
    echo "=== RESULT: REPRODUCIBLE BUILD VERIFIED ==="
else
    echo "=== RESULT: BUILD IS NOT REPRODUCIBLE ==="
    exit 1
fi

# Cleanup
rm -rf /tmp/ztssh-repro-1 /tmp/ztssh-repro-2
