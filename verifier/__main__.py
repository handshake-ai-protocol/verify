"""Entrypoint: ``python -m verifier <pack_dir>``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
