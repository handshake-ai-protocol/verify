"""Command-line entrypoint: ``python -m verifier <pack_dir>``.

Exits 0 on success, 1 on any verification failure, 2 on usage errors.
Prints a structured JSON report to stdout (so CI / shell scripts can
parse it) and a concise human-readable summary to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys

from .verify import verify_pack


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m verifier",
        description="Hermetic offline verifier for Handshake evidence packs.",
    )
    p.add_argument("pack_dir", help="Path to an unpacked evidence-pack directory.")
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the human-readable stderr summary; only emit JSON to stdout.",
    )
    args = p.parse_args(argv)

    report = verify_pack(args.pack_dir)
    sys.stdout.write(json.dumps(report.to_dict(), sort_keys=True, indent=2) + "\n")

    if not args.quiet:
        verb = "PASS" if report.ok else "FAIL"
        sys.stderr.write(
            f"[{verb}] module={report.module_id} "
            f"verified={report.receipts_verified}/{report.receipt_count} "
            f"failures={len(report.failures)}\n"
        )
        for f in report.failures[:20]:
            tag = f" rid={f.receipt_id}" if f.receipt_id else ""
            sys.stderr.write(f"  - {f.code}{tag}: {f.message}\n")
        if report.ok:
            # Make the proof scope explicit so an auditor reading the
            # success line does not over-claim. The verifier proves
            # internal consistency of the pack — every receipt's
            # producer signature, every inclusion proof's recomputation
            # to a single pinned root, every module-catalog rule. It
            # does NOT prove independent time-of-existence over that
            # root; that requires a public log-witness checkpoint
            # (Phase 8). ADR-0013 §4 + ADR-0014 §"Compliance filter
            # contract" document the trade-off.
            sys.stderr.write(
                "[note] internal consistency only; independent"
                " proof-of-existence over the tree-head requires a"
                " public log-witness checkpoint (Phase 8)\n"
            )

    return 0 if report.ok else 1
