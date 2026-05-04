# SPDX-License-Identifier: MIT
"""Top-level verification orchestrator.

Verification phases (each phase fails fast with a specific error code):

  1. ``manifest_loaded``               — ``manifest.json`` parses;
                                         ``manifest_version`` supported.
  2. ``module_catalog_drift``          — verifier's embedded module
                                         catalog reproduces the
                                         manifest's
                                         ``module_catalog_hash_hex``.
  3. ``path_outside_pack``             — every manifest-controlled file
                                         path resolves *inside* the pack
                                         root.
  4. ``registry_did_*``                — ``did/registry.json`` matches
                                         ``manifest.registry_did`` and
                                         exposes a usable Ed25519 key.
  5. ``tree_head_signature_invalid``   — both ``tree_head_start`` and
                                         ``tree_head_end`` carry an
                                         RFC-8032 Ed25519 signature
                                         from the Registry over the
                                         exact bound payload defined by
                                         ``tree_head_signed_message``.
  6. ``leaf_hash_matches``             — for every receipt, SHA-256 over
                                         the on-disk JSON bytes equals
                                         the manifest's
                                         ``leaf_hash_hex``.
  7. ``receipt_signature``             — for every receipt, the producer
                                         signature over the JCS-canonical
                                         envelope (with ``signature``
                                         blanked) verifies under the
                                         producer DID's *issuance-time*
                                         verification key — looked up
                                         by ``(iss_did, iss_did_version)``
                                         in the manifest's
                                         ``did_documents`` index.
  8. ``inclusion_proof``               — RFC 6962 audit-path
                                         recomputation against
                                         ``tree_head_end`` for every
                                         receipt; also against
                                         ``tree_head_start`` for the
                                         start-anchor receipts in
                                         ``proofs_start/``.
  9. ``module_assertions``             — every receipt's ``action``
                                         matches the module's capability
                                         filter; no forbidden
                                         capabilities present.

The verifier deliberately runs every receipt before exiting, so the
report lists ALL failures rather than the first one (better auditor UX).

Trust scope of the tree-head signatures
---------------------------------------
The Registry self-signs both tree-heads with its long-lived Ed25519 key
(published as ``did/registry.json``). This proves THIS Registry, at the
DID published in ``manifest.registry_did``, attested to the
(tree_size, root_hash) pair while assembling the pack. The signatures
are deterministic (RFC 8032) so the bytes are stable across rebuilds —
preserving the "same input → byte-identical zip" contract.

This is *Registry self-attestation*, NOT an independent witness over
Trillian. The public log-witness layer in Phase 8 binds tree_head_end
to externally-co-signed checkpoints; until then, the verifier prints a
``[note]`` on PASS so an auditor cannot accidentally over-claim.
ADR-0013 §"Tree-head pinning" and ADR-0014 §"Compliance filter
contract" capture the trade-off.
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


SUPPORTED_MANIFEST_VERSIONS = {"2"}


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

    # ---- Tree-heads (start/end) ---------------------------------------------
    head_start_raw = manifest.get("tree_head_start") or {}
    head_end_raw = manifest.get("tree_head_end") or {}
    try:
        start_root = bytes.fromhex(str(head_start_raw["root_hash_hex"]))
        start_size = int(head_start_raw["tree_size"])
        start_sig_b64 = str(head_start_raw["signature_b64u"])
        start_signer = str(head_start_raw["signed_by_did"])
        end_root = bytes.fromhex(str(head_end_raw["root_hash_hex"]))
        end_size = int(head_end_raw["tree_size"])
        end_sig_b64 = str(head_end_raw["signature_b64u"])
        end_signer = str(head_end_raw["signed_by_did"])
    except (KeyError, ValueError) as exc:
        rep.fail("tree_head_malformed", f"could not decode tree-heads: {exc}")
        return rep
    if start_size <= 0 or end_size <= 0 or len(start_root) != 32 or len(end_root) != 32:
        rep.fail(
            "tree_head_invalid",
            f"start={start_size}/{len(start_root)} end={end_size}/{len(end_root)}",
        )
        return rep
    if start_size > end_size:
        rep.fail(
            "tree_head_invalid",
            f"start_size={start_size} > end_size={end_size}",
        )
        return rep

    registry_did = str(manifest.get("registry_did", ""))
    if start_signer != registry_did or end_signer != registry_did:
        rep.fail(
            "tree_head_signer_mismatch",
            f"start signed_by_did={start_signer!r} or end signed_by_did="
            f"{end_signer!r} differs from manifest.registry_did={registry_did!r}",
        )

    # Resolve the Registry's signing key.
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
    registry_pubkey = _extract_ed25519_pubkey(registry_doc)
    if registry_pubkey is None:
        rep.fail(
            "registry_pubkey_missing",
            "did/registry.json has no Ed25519VerificationKey2020 we can parse",
        )
        return rep

    # Verify both tree-head signatures.
    range_from = str(manifest.get("range_from", ""))
    range_to = str(manifest.get("range_to", ""))
    tenant_slug = str(manifest.get("tenant_slug", ""))
    for position, head_size, head_root, sig_b64 in (
        ("start", start_size, start_root, start_sig_b64),
        ("end", end_size, end_root, end_sig_b64),
    ):
        msg = _tree_head_signed_message(
            position=position,
            tree_size=head_size,
            root_hash_hex=head_root.hex(),
            range_from=range_from,
            range_to=range_to,
            tenant_slug=tenant_slug,
            module_id=module_id,
            registry_did=registry_did,
        )
        try:
            sig = _b64u_decode(sig_b64)
        except (binascii.Error, ValueError) as exc:
            rep.fail(
                "tree_head_signature_b64",
                f"{position}-head signature b64 invalid: {exc}",
            )
            continue
        if len(sig) != 64 or not ed25519.verify(registry_pubkey, msg, sig):
            rep.fail(
                "tree_head_signature_invalid",
                f"Registry Ed25519 signature on {position}-head did not verify",
            )

    # ---- Producer DID Documents → (did, version) → pubkey -------------------
    did_pubkeys: dict[tuple[str, int], bytes | None] = {}
    for entry in manifest.get("did_documents", []):
        did = str(entry.get("did", ""))
        rel = str(entry.get("path", ""))
        try:
            version = int(entry.get("version", 0))
        except (TypeError, ValueError):
            rep.fail(
                "producer_did_invalid",
                f"non-integer version on did_documents entry for {did!r}",
            )
            continue
        doc_path = _safe_join(root, rel, rep)
        if doc_path is None:
            did_pubkeys[(did, version)] = None
            continue
        if not doc_path.is_file():
            rep.fail("producer_did_missing", f"missing {rel}")
            did_pubkeys[(did, version)] = None
            continue
        try:
            doc = json.loads(doc_path.read_text("utf-8"))
        except json.JSONDecodeError as exc:
            rep.fail("producer_did_invalid", f"{rel}: {exc}")
            did_pubkeys[(did, version)] = None
            continue
        if doc.get("id") != did:
            rep.fail("producer_did_mismatch", f"{rel}: id != {did}")
        did_pubkeys[(did, version)] = _extract_ed25519_pubkey(doc)

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
        try:
            iss_did_version = int(entry.get("iss_did_version", 0))
        except (TypeError, ValueError):
            rep.fail(
                "receipt_iss_did_version_invalid",
                f"receipt {rid} has non-integer iss_did_version",
                receipt_id=rid,
            )
            continue

        # Module filter: a receipt is admissible if EITHER its action
        # matches a capability prefix OR its body's ``result_summary``
        # contains a truthy marker the module declares. The marker
        # check is deferred until after the envelope is parsed (below)
        # — but ``forbidden_patterns`` are still rejected up-front
        # since they are a hard exclusion regardless of markers.
        if spec is not None and spec.is_forbidden(action):
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
        producer_pubkey = did_pubkeys.get((iss_did, iss_did_version))
        if producer_pubkey is None:
            rep.fail(
                "producer_pubkey_missing",
                f"no public key resolved for iss DID {iss_did!r} v{iss_did_version}",
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

        # ── Module-admission check (deferred from up-front so the
        # marker-based path can see ``result_summary`` from the
        # signature-verified body). A receipt with an action outside
        # the module's capability filter MUST also produce a truthy
        # marker in result_summary the module declares; otherwise it
        # is not admissible evidence.
        if spec is not None and not spec.matches(action):
            if not spec.matches_marker(body.get("result_summary")):
                rep.fail(
                    "action_outside_module",
                    f"action {action!r} does not match module {module_id!r} "
                    "capability filter and no result_summary marker is set",
                    receipt_id=rid,
                )
                continue

        # ---- End-head inclusion proof ----------------------------------------
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
        if tree_size != end_size:
            rep.fail(
                "proof_tree_size_mismatch",
                f"proof tree_size={tree_size} != manifest tree_head_end.tree_size={end_size}",
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
        if recomputed != end_root:
            rep.fail(
                "inclusion_proof_root_mismatch",
                f"recomputed end-root {recomputed.hex()} != tree_head_end "
                f"root {end_root.hex()}",
                receipt_id=rid,
            )
            continue

        rep.receipts_verified += 1

    # ---- Start-head proofs --------------------------------------------------
    # The manifest names the start-anchor receipts (those with
    # tree_size_at_inclusion == start_size). For each, ``proofs_start/{rid}.json``
    # carries an inclusion proof at start_size that MUST recompute to
    # tree_head_start.root_hash_hex. We require at least one such
    # receipt — refuse a manifest that claims the empty set.
    #
    # Crucially, each start-anchor proof is bound to the receipt entry it
    # claims to anchor: rid MUST appear in manifest.receipts, and the
    # proof's leaf_hash_hex MUST equal that receipt's leaf_hash_hex.
    # Without this binding a tampered pack could anchor the start root
    # using leaves entirely unrelated to the matched receipt-set
    # (architect re-review CRITICAL #2 residual).
    receipts_by_id: dict[str, dict[str, Any]] = {
        str(e.get("receipt_id", "")): e for e in receipts
    }
    start_anchor_ids = list(manifest.get("start_anchor_receipt_ids", []) or [])
    if not start_anchor_ids:
        rep.fail(
            "tree_head_start_unanchored",
            "manifest declares no start_anchor_receipt_ids; cannot validate"
            " tree_head_start without at least one inclusion proof at start_size",
        )
    for rid in start_anchor_ids:
        rid = str(rid)
        receipt_entry = receipts_by_id.get(rid)
        if receipt_entry is None:
            rep.fail(
                "start_anchor_receipt_unknown",
                f"start_anchor_receipt_ids[{rid!r}] does not appear in"
                " manifest.receipts; cannot bind start-head proof to a"
                " matched receipt",
                receipt_id=rid,
            )
            continue
        expected_leaf_hex = str(receipt_entry.get("leaf_hash_hex", ""))
        sp_path = _safe_join(root, f"proofs_start/{rid}.json", rep, receipt_id=rid)
        if sp_path is None:
            continue
        if not sp_path.is_file():
            rep.fail(
                "proof_start_missing",
                f"proofs_start/{rid}.json absent",
                receipt_id=rid,
            )
            continue
        try:
            sp = json.loads(sp_path.read_text("utf-8"))
            sp_audit = [bytes.fromhex(h) for h in sp["audit_path_hex"]]
            sp_leaf_index = int(sp["leaf_index"])
            sp_tree_size = int(sp["tree_size"])
            sp_leaf_hash_hex = str(sp["leaf_hash_hex"])
            sp_leaf_hash = bytes.fromhex(sp_leaf_hash_hex)
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            rep.fail("proof_start_malformed", str(exc), receipt_id=rid)
            continue
        # Bind the start-head proof to the receipt entry: same leaf hash.
        if sp_leaf_hash_hex != expected_leaf_hex:
            rep.fail(
                "start_anchor_leaf_mismatch",
                f"proofs_start/{rid}.json leaf_hash {sp_leaf_hash_hex!r} != "
                f"manifest receipt leaf_hash {expected_leaf_hex!r}",
                receipt_id=rid,
            )
            continue
        if sp_tree_size != start_size:
            rep.fail(
                "proof_start_tree_size_mismatch",
                f"proofs_start/{rid}.json tree_size={sp_tree_size} != "
                f"manifest tree_head_start.tree_size={start_size}",
                receipt_id=rid,
            )
            continue
        try:
            sp_recomputed = recompute_root(
                leaf_hash=sp_leaf_hash,
                leaf_index=sp_leaf_index,
                tree_size=sp_tree_size,
                audit_path=sp_audit,
            )
        except ValueError as exc:
            rep.fail("inclusion_proof_invalid", str(exc), receipt_id=rid)
            continue
        if sp_recomputed != start_root:
            rep.fail(
                "tree_head_start_root_mismatch",
                f"start-head recomputed root {sp_recomputed.hex()} != "
                f"tree_head_start root {start_root.hex()}",
                receipt_id=rid,
            )
            continue

    return rep


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _tree_head_signed_message(
    *,
    position: str,
    tree_size: int,
    root_hash_hex: str,
    range_from: str,
    range_to: str,
    tenant_slug: str,
    module_id: str,
    registry_did: str,
) -> bytes:
    """Bound payload the Registry signs for one tree-head.

    Mirrors :func:`handshake_registry.evidence.manifest.tree_head_signed_message`
    byte-for-byte. Both sides MUST stay in lock-step; ADR-0013 §"Tree-head
    pinning" documents the binding fields and rationale.
    """
    payload = {
        "module_id": module_id,
        "position": position,
        "range_from": range_from,
        "range_to": range_to,
        "registry_did": registry_did,
        "root_hash_hex": root_hash_hex,
        "tenant_slug": tenant_slug,
        "tree_size": tree_size,
        "v": "handshake.tree_head/1",
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


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
