# handshake-evidence-verifier

Hermetic offline verifier for Handshake compliance evidence packs.

## Why hermetic?

An auditor must be able to verify a pack without trusting the Registry
that produced it — even years later, even on an air-gapped laptop. So
the verifier:

* uses only the Python standard library (no `cryptography`, no
  `pynacl`, no `pydantic`),
* embeds a pure-Python Ed25519 implementation (RFC 8032 reference port),
* embeds a pure-Python RFC 8785 JCS canonicalizer,
* makes zero network calls.

It runs offline, cleanly, on `python:3.12-slim --network=none`.

## Usage

```sh
unzip handshake-evidence-soc2-….zip -d /pack
python3 -m verifier /pack
# or:
/pack/verify.sh
```

Exits 0 on success, 1 on any verification failure.
A JSON report is printed to stdout.

## Hermetic mode (Docker)

```sh
docker run --rm --network=none -v "$PWD:/in" python:3.12-slim \
  sh -c 'unzip -q /in/pack.zip -d /pack && /pack/verify.sh'
```

## What it checks

Each pack contains a `manifest.json` plus signed receipts, Trillian
inclusion proofs, two tree-head snapshots, and the relevant DID
Documents. The verifier re-checks every layer:

1. Tree-head signature (Registry's Ed25519 key).
2. Every receipt's producer signature (each agent's Ed25519 key).
3. Every receipt's leaf hash (SHA-256 over the canonical envelope).
4. Every Trillian inclusion proof (RFC 6962 audit-path replay).
5. Module-specific assertions (e.g. SOC 2 CC7.2 capability filter).

See the security audit documentation included in your evidence pack for
the per-module control matrix.
