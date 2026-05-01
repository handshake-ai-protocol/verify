"""Trillian SignedLogRoot parser — duplicates Registry's parse_log_root.

Both layouts are supported (canonical Trillian + Handshake's Postgres
shim) so the same verifier binary handles either backend.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LogRoot:
    tree_size: int
    timestamp_ns: int
    root_hash: bytes


def parse_log_root(blob: bytes) -> LogRoot:
    if len(blob) < 11:
        raise ValueError("log_root blob too short")

    # Canonical Trillian LogRootV1 (version u16 BE == 1).
    try:
        if int.from_bytes(blob[0:2], "big") == 1:
            tree_size = int.from_bytes(blob[2:10], "big")
            rh_len = blob[10]
            if 11 + rh_len + 16 <= len(blob):
                rh = bytes(blob[11 : 11 + rh_len])
                ts_ns = int.from_bytes(blob[11 + rh_len : 19 + rh_len], "big")
                return LogRoot(tree_size, ts_ns, rh)
    except Exception:
        pass

    # Postgres shim layout: tree_size(8) ts(8) rev(8) rh_len(1) rh.
    tree_size = int.from_bytes(blob[0:8], "big")
    ts_ns = int.from_bytes(blob[8:16], "big") if len(blob) >= 16 else 0
    rh = b""
    if len(blob) >= 25:
        rh_len = blob[24]
        if 25 + rh_len <= len(blob):
            rh = bytes(blob[25 : 25 + rh_len])
    if not rh:
        raise ValueError("log_root blob did not parse as either layout")
    return LogRoot(tree_size, ts_ns, rh)
