"""Top-level verification orchestrator.

Verification phases (each phase fails fast with a specific error code):

  1. ``manifest_loaded``         — ``manifest.json`` parses; manifest
                                   version supported.
  2. ``module_catalog_drift``    — verifier's embedded module catalog
                                   reproduces the manifest's
                                   ``module_catalog_hash_hex``. Refuses
                                   any pack whose Registry-side catalog
                                   has drifted from this verifier's
                                   embedded mirror.
  3. ``path_outside_pack``       — every manifest-controlled file path
                                   (DID documents, receipts, proofs)
                                   resolves *inside* the pack root.
                                   Refuses path-traversal attempts
                                   crafted into the manifest.
  4. ``leaf_hash_matches``       — for every receipt, SHA-256 over the
                                   on-disk JSON bytes equals the
                                   manifest's ``leaf_hash_hex``.
  5. ``receipt_signature``       — for every receipt, the producer
                                   signature over the JCS-canonical
                                   envelope (with ``signature`` blanked)
                                   verifies under the producer DID's
                                   verification key.
  6. ``inclusion_proof``         — RFC 6962 audit-path recomputation
                                   yields the same root_hash as the
                                   tree-head's ``root_hash_hex``.
  7. ``module_assertions``       — every receipt's ``action`` matches the
                                   module's capability filter; no
                                   forbidden capabilities present.

The verifier deliberately runs every receipt before exiting, so the
report lists ALL failures rather than the first one (better auditor UX).

Why no Trillian tree-head signature check?
------------------------------------------
Earlier drafts embedded the latest Trillian-signed ``LogRootV1`` bytes
plus the Registry's signature over them. That broke determinism: the
same (module, range, tenant, receipt-set) input would produce different
zips on different days because Trillian only signs the *latest* root
and the latest root keeps moving. Tree-level non-repudiation across time
is delivered by the public log-witness layer (Phase 8); the per-pack
artifact only needs the receipts to chain to a *consistent* root, which
the inclusion-proof cross-check guarantees. ADR-0013 has the full
argument.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import ed25519
from .jcs import jcs
from .merkle import recompute_root
from .modules import get_module, module_catalog_hash_hex


SUPPORTED_MANIFEST_VERSIONS = {"1"}


@dataclass
class Failure:
    code: str
    message: str
    receipt_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.receipt_id is not None:
            d["receipt_id"] = self.receipt_id
        return d


@dataclass
class Report:
    pack_dir: str
    module_id: str
    receipt_count: int
    receipts_verified: int = 0
    failures: list[Failure] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def fail(self, code: str, message: str, receipt_id: str | None = None) -> None:
        self.failures.append(Failure(code=code, message=message, receipt_id=receipt_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_dir": self.pack_dir,
            "module_id": self.module_id,
            "receipt_count": self.receipt_count,
            "receipts_verified": self.receipts_verified,
            "ok": self.ok,
            "failures": [f.to_dict() for f in self.failures],
        }


def verify_pack(pack_dir: str | Path) -> Report:
    """Run all verification phases on the unpacked pack at ``pack_dir``."""

    root = Path(pack_dir).resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        r = Report(pack_dir=str(root), module_id="?", receipt_count=0)
        r.fail("manifest_missing", f"no manifest.json at {manifest_path}")
        return r

    try:
        manifest = json.loads(manifest_path.read_text("utf-8"))
    except json.JSONDecodeError as exc:
        r = Report(pack_dir=str(root), module_id="?", receipt_count=0)
        r.fail("manifest_invalid_json", f"could not parse manifest: {exc}")
        return r

    mv = str(manifest.get("manifest_version"))
    module_id = str(manifest.get("module_id", "?"))
    receipts = list(manifest.get("receipts", []))
    rep = Report(pack_dir=str(root), module_id=module_id, receipt_count=len(receipts))

    if mv not in SUPPORTED_MANIFEST_VERSIONS:
        rep.fail(
            "manifest_version_unsupported",
            f"manifest_version={mv!r}; supported: {sorted(SUPPORTED_MANIFEST_VERSIONS)}",
        )
        return rep

    # ---- Module catalog drift check ------------------------------------------
    # The Registry side embeds a SHA-256 over its JCS-canonical ModuleSpec.
    # The verifier embeds an *independently vendored* mirror of the catalog.
    # If they disagree, the assembler and the verifier are working from
    # different rules: refuse the pack rather than silently apply a stale
    # capability filter that might admit forbidden actions. See ADR-0014.
    expected_catalog_hash = str(manifest.get("module_catalog_hash_hex", ""))
    try:
        actual_catalog_hash = module_catalog_hash_hex(module_id)
    except KeyError:
        actual_catalog_hash = ""
        rep.fail(
            "unknown_module",
            f"verifier has no spec for module {module_id!r}",
        )
    if expected_catalog_hash and actual_catalog_hash and expected_catalog_hash != actual_catalog_hash:
        rep.fail(
            "module_catalog_drift",
            f"manifest module_catalog_hash_hex={expected_catalog_hash!r}"
            f" != verifier-embedded {actual_catalog_hash!r}; the Registry"
            " catalog has drifted from this verifier's embedded mirror — refuse",
        )
        return rep
    if not expected_catalog_hash:
        rep.fail(
            "module_catalog_hash_missing",
            "manifest is missing module_catalog_hash_hex; cannot bind"
            " pack to a specific catalog version — refuse",
        )
        return rep

    # ---- Tree-head (deterministic, no Trillian signature) --------------------
    head = manifest.get("tree_head_end") or {}
    try:
        tree_root = bytes.fromhex(str(head["root_hash_hex"]))
        expected_tree_size = int(head["tree_size"])
    except (KeyError, ValueError) as exc:
        rep.fail("tree_head_malformed", f"could not decode tree-head: {exc}")
        return rep
    if expected_tree_size <= 0 or len(tree_root) != 32:
        rep.fail(
            "tree_head_invalid",
            f"tree_size={expected_tree_size} root_hash_len={len(tree_root)}",
        )
        return rep

    registry_did = str(manifest.get("registry_did", ""))
    registry_doc_path = _safe_join(root, "did/registry.json", rep)
    if registry_doc_path is None or not registry_doc_path.is_file():
        rep.fail("registry_did_missing", "did/registry.json is absent from pack")
        return rep
    try:
        registry_doc = json.loads(registry_doc_path.read_text("utf-8"))
    except json.JSONDecodeError as exc:
        rep.fail("registry_did_invalid", f"did/registry.json invalid: {exc}")
        return rep
    if registry_doc.get("id") != registry_did:
        rep.fail(
            "registry_did_mismatch",
            f"manifest registry_did={registry_did!r} != document id={registry_doc.get('id')!r}",
        )

    # ---- Producer DID Documents → pubkeys ------------------------------------
    did_pubkeys: dict[str, bytes | None] = {}
    for entry in manifest.get("did_documents", []):
        did = str(entry.get("did", ""))
        rel = str(entry.get("path", ""))
        doc_path = _safe_join(root, rel, rep)
        if doc_path is None:
            did_pubkeys[did] = None
            continue
        if not doc_path.is_file():
            rep.fail("producer_did_missing", f"missing {rel}", receipt_id=None)
            did_pubkeys[did] = None
            continue
        try:
            doc = json.loads(doc_path.read_text("utf-8"))
        except json.JSONDecodeError as exc:
            rep.fail("producer_did_invalid", f"{rel}: {exc}")
            did_pubkeys[did] = None
            continue
        if doc.get("id") != did:
            rep.fail("producer_did_mismatch", f"{rel}: id != {did}")
        did_pubkeys[did] = _extract_ed25519_pubkey(doc)

    # ---- Per-receipt phases --------------------------------------------------
    spec = None
    try:
        spec = get_module(module_id)
    except KeyError:
        # Already reported as unknown_module above; spec stays None and
        # capability assertions are skipped (failures are already raised).
        pass

    for entry in receipts:
        rid = str(entry.get("receipt_id", ""))
        rel = str(entry.get("path", ""))
        leaf_hash_hex = str(entry.get("leaf_hash_hex", ""))
        action = str(entry.get("action", ""))

        # Module filter: action MUST match the module's capability set.
        if spec is not None:
            if not spec.matches(action):
                rep.fail(
                    "action_outside_module",
                    f"action {action!r} does not match module {module_id!r} capability filter",
                    receipt_id=rid,
                )
            if spec.is_forbidden(action):
                rep.fail(
                    "action_forbidden",
                    f"action {action!r} is on the module's forbidden list",
                    receipt_id=rid,
                )

        receipt_path = _safe_join(root, rel, rep, receipt_id=rid)
        if receipt_path is None:
            continue
        if not receipt_path.is_file():
            rep.fail("receipt_missing", f"{rel} not present", receipt_id=rid)
            continue

        receipt_bytes = receipt_path.read_bytes()
        actual_leaf = hashlib.sha256(receipt_bytes).hexdigest()
        if actual_leaf != leaf_hash_hex:
            rep.fail(
                "leaf_hash_mismatch",
                f"sha256(file)={actual_leaf!r} != manifest={leaf_hash_hex!r}",
                receipt_id=rid,
            )
            continue  # everything downstream depends on this matching.

        try:
            envelope = json.loads(receipt_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            rep.fail("receipt_invalid_json", str(exc), receipt_id=rid)
            continue

        sig_b64 = envelope.get("signature")
        if not isinstance(sig_b64, str) or not sig_b64:
            rep.fail("receipt_no_signature", "envelope.signature missing", receipt_id=rid)
            continue
        try:
            sig = _b64u_decode(sig_b64)
        except (binascii.Error, ValueError) as exc:
            rep.fail("receipt_signature_b64", f"invalid b64: {exc}", receipt_id=rid)
            continue

        iss_did = str(envelope.get("iss", entry.get("iss_did", "")))
        producer_pubkey = did_pubkeys.get(iss_did)
        if producer_pubkey is None:
            rep.fail(
                "producer_pubkey_missing",
                f"no public key resolved for iss DID {iss_did!r}",
                receipt_id=rid,
            )
            continue

        body = {k: v for k, v in envelope.items() if k != "signature"}
        try:
            canonical = jcs(body)
        except Exception as exc:  # JcsTypeError or similar
            rep.fail("receipt_canonicalize_failed", str(exc), receipt_id=rid)
            continue
        if not ed25519.verify(producer_pubkey, canonical, sig):
            rep.fail(
                "signature_invalid",
                "Ed25519 signature over receipt envelope did not verify",
                receipt_id=rid,
            )
            continue

        # ---- Inclusion proof --------------------------------------------------
        proof_path = _safe_join(root, f"proofs/{rid}.json", rep, receipt_id=rid)
        if proof_path is None:
            continue
        if not proof_path.is_file():
            rep.fail("proof_missing", f"proofs/{rid}.json absent", receipt_id=rid)
            continue
        try:
            proof = json.loads(proof_path.read_text("utf-8"))
        except json.JSONDecodeError as exc:
            rep.fail("proof_invalid_json", str(exc), receipt_id=rid)
            continue

        try:
            audit_path = [bytes.fromhex(h) for h in proof["audit_path_hex"]]
            leaf_index = int(proof["leaf_index"])
            tree_size = int(proof["tree_size"])
            leaf_hash = bytes.fromhex(proof["leaf_hash_hex"])
        except (KeyError, ValueError) as exc:
            rep.fail("proof_malformed", str(exc), receipt_id=rid)
            continue

        if leaf_hash.hex() != leaf_hash_hex:
            rep.fail(
                "proof_leaf_hash_mismatch",
                f"proof leaf_hash {leaf_hash.hex()} != manifest {leaf_hash_hex}",
                receipt_id=rid,
            )
            continue
        if tree_size != expected_tree_size:
            # Every receipt's inclusion proof must be rooted at the
            # manifest's pinned tree-head size. A mismatch means the
            # assembler shipped a pack whose proofs do not all chain to
            # the same root — refuse rather than partially trust.
            rep.fail(
                "proof_tree_size_mismatch",
                f"proof tree_size={tree_size} != manifest tree_head_end.tree_size={expected_tree_size}",
                receipt_id=rid,
            )
            continue

        try:
            recomputed = recompute_root(
                leaf_hash=leaf_hash,
                leaf_index=leaf_index,
                tree_size=tree_size,
                audit_path=audit_path,
            )
        except ValueError as exc:
            rep.fail("inclusion_proof_invalid", str(exc), receipt_id=rid)
            continue
        if recomputed != tree_root:
            rep.fail(
                "inclusion_proof_root_mismatch",
                f"recomputed root {recomputed.hex()} != tree_head root {tree_root.hex()}",
                receipt_id=rid,
            )
            continue

        rep.receipts_verified += 1

    return rep


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _safe_join(
    root: Path,
    rel: str,
    rep: Report,
    receipt_id: str | None = None,
) -> Path | None:
    """Resolve ``root / rel`` and confirm the result stays under ``root``.

    Manifest-controlled relative paths (DID document paths, receipt
    paths, proof file ids) are untrusted: a malicious manifest could
    embed ``../../../etc/passwd`` to make the verifier read or check
    files outside the pack. We resolve symlinks and ``..`` segments,
    then assert the resolved path is a descendant of the resolved pack
    root. On violation we record ``path_outside_pack`` and return
    ``None`` so the caller skips the entry. ``root`` is assumed to
    already be ``.resolve()``-d by ``verify_pack``.
    """
    if not isinstance(rel, str) or not rel:
        rep.fail(
            "path_outside_pack",
            f"empty or non-string relative path: {rel!r}",
            receipt_id=receipt_id,
        )
        return None
    # Reject absolute paths up-front; ``root / "/etc/passwd"`` would
    # discard ``root`` entirely on POSIX. ``Path.is_absolute`` catches
    # both POSIX absolute paths and Windows-drive paths defensively.
    if Path(rel).is_absolute():
        rep.fail(
            "path_outside_pack",
            f"absolute path not allowed in manifest: {rel!r}",
            receipt_id=receipt_id,
        )
        return None
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        rep.fail(
            "path_outside_pack",
            f"path {rel!r} resolves to {candidate} which is outside pack root {root}",
            receipt_id=receipt_id,
        )
        return None
    return candidate


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58btc_decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise ValueError(f"invalid base58 character: {c!r}")
        n = n * 58 + _B58_INDEX[c]
    # Count leading "1"s as leading-zero bytes.
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return b"\x00" * pad + body


def _extract_ed25519_pubkey(doc: dict[str, Any]) -> bytes | None:
    """Pull the first Ed25519VerificationKey2020 public key out of a DID
    Document. Supports the two encodings the Registry actually emits:
    ``publicKeyMultibase`` (z-base58btc) and ``publicKeyBase64u``."""
    for vm in doc.get("verificationMethod", []) or []:
        if not isinstance(vm, dict):
            continue
        if vm.get("type") != "Ed25519VerificationKey2020":
            continue
        mb = vm.get("publicKeyMultibase")
        if isinstance(mb, str) and mb.startswith("z"):
            try:
                return _b58btc_decode(mb[1:])
            except ValueError:
                continue
        b64 = vm.get("publicKeyBase64u")
        if isinstance(b64, str):
            try:
                return _b64u_decode(b64)
            except (binascii.Error, ValueError):
                continue
    return None
