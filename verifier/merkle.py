# SPDX-License-Identifier: MIT
"""RFC 6962 Merkle inclusion-proof verifier (stdlib-only).

Trillian uses Certificate-Transparency-style domain separation:

  leaf_hash    = SHA-256(0x00 || leaf_value)   (already done by the Registry;
                                                we receive it pre-hashed)
  branch_hash  = SHA-256(0x01 || left || right)

Given a leaf hash, the leaf's index in the log, the tree size at the
moment of proof generation, and the audit path (a sequence of sibling
hashes, leaf-to-root), we recompute the root hash and return it. The
caller compares against the signed tree-head's ``root_hash``.
"""

from __future__ import annotations

import hashlib


def hash_branch(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def recompute_root(
    *, leaf_hash: bytes, leaf_index: int, tree_size: int, audit_path: list[bytes]
) -> bytes:
    """Implements RFC 6962 §2.1.1 inclusion-proof verification."""
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        raise ValueError("leaf_index out of range for tree_size")

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash
    for sibling in audit_path:
        if sn == 0:
            raise ValueError("audit path longer than tree depth")
        if (fn & 1) == 1 or fn == sn:
            # Right child (or rightmost ragged node): sibling on the left.
            r = hash_branch(sibling, r)
            if (fn & 1) == 0:
                # Walk up the right edge: shift until LSB(fn) is set or
                # sn becomes 0 (we've reached the root path).
                while (fn & 1) == 0 and sn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hash_branch(r, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("audit path shorter than tree depth")
    return r
