"""RFC 8785 JCS (JSON Canonicalization Scheme) — stdlib-only.

The Handshake receipt envelopes contain only the JSON subset emitted by
the producer SDK: nested objects, arrays, strings, integers, booleans,
and null. No floats, no NaN/Infinity, no high-precision numerics. For
that subset, RFC 8785 reduces to:

  * Members of objects sorted lexicographically by UTF-16 code-unit value
    of the unescaped key.
  * No insignificant whitespace.
  * Strings escape only the JSON-required code points (the reverse-solidus
    escape table from RFC 8259 §7).
  * Integers in their shortest decimal form, no leading zeros, no '+'
    sign on the exponent.

We refuse to canonicalize floats / NaN / Infinity — receipts must never
contain them, and silently down-converting would mask a producer bug.
The encoder raises ``JcsTypeError`` instead.
"""

from __future__ import annotations

from typing import Any


class JcsTypeError(TypeError):
    """Raised when the value contains a type the receipt subset forbids."""


def jcs(value: Any) -> bytes:
    """Return the canonical UTF-8 byte representation of ``value``."""
    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        # Receipt envelopes must never carry floats; we refuse rather
        # than silently round-trip.
        raise JcsTypeError("floats are not permitted in receipt envelopes")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list) or isinstance(value, tuple):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 §3.2.3: sort by UTF-16 code units. Python strings are
        # already UTF-16-ish for the BMP; for full correctness we sort
        # using each char's UTF-16 code-unit sequence.
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        body = ",".join(_encode_string(k) + ":" + _encode(v) for k, v in items)
        return "{" + body + "}"
    raise JcsTypeError(f"unsupported type: {type(value).__name__}")


def _utf16_key(s: str) -> tuple[int, ...]:
    """RFC 8785 §3.2.3 sort key: sequence of UTF-16 code units."""
    raw = s.encode("utf-16-be")
    return tuple(int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2))


# JSON escape table per RFC 8259 §7. Anything outside the printable ASCII
# range that isn't required to be escaped is left as its raw UTF-8 bytes.
_ESCAPES = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x08: "\\b",
    0x0C: "\\f",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
