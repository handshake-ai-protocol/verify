#!/usr/bin/env sh
# Hermetic Handshake evidence-pack verifier entrypoint (template).
# Copied verbatim into every emitted pack. Requires only python3 (>=3.10).
set -eu
PACK_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PACK_DIR"
exec python3 -m verifier "$PACK_DIR"
