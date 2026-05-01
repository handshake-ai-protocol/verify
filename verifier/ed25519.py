"""Pure-Python Ed25519 verify (RFC 8032).

Adapted from the public-domain reference implementation in RFC 8032
Appendix A; trimmed to verify-only and the prime-ed25519 curve. We
implement signature verification as defined in RFC 8032 §5.1.7.

Performance note: ~5 ms per signature on commodity hardware. That is
three orders of magnitude slower than libsodium but irrelevant for
auditor-grade offline use (tens to hundreds of receipts per pack), and
buys hermeticity: no native code, no FFI, no toolchain.
"""

from __future__ import annotations

import hashlib

# Ed25519 group / field parameters per RFC 8032 §5.1.
_p = 2**255 - 19
_q = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p


def _modp_inv(x: int) -> int:
    return pow(x, _p - 2, _p)


# Square root of -1 in F_p (used for point decoding).
_modp_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little")


def _recover_x(y: int, sign: int) -> int | None:
    """Recover the x-coordinate from y per RFC 8032 §5.1.3."""
    if y >= _p:
        return None
    x2 = (y * y - 1) * _modp_inv(_d * y * y + 1) % _p
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _modp_sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


# Base point B as (x, y, z, t) extended coordinates (RFC 8032 §5.1).
_g_y = 4 * _modp_inv(5) % _p
_g_x = _recover_x(_g_y, 0)
assert _g_x is not None
_G = (_g_x, _g_y, 1, _g_x * _g_y % _p)


def _point_add(P: tuple[int, int, int, int], Q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = (y1 - x1) * (y2 - x2) % _p
    B = (y1 + x1) * (y2 + x2) % _p
    C = 2 * t1 * t2 * _d % _p
    D = 2 * z1 * z2 % _p
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _point_mul(s: int, P: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P: tuple[int, int, int, int], Q: tuple[int, int, int, int]) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _p != 0:
        return False
    return True


def _point_decompress(s: bytes) -> tuple[int, int, int, int] | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature on
    ``message`` under ``public_key``. Constant-time? No — verification
    runs over public data, so timing leakage is acceptable."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public_key)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _q:
        return False
    h = _sha512_int(Rs + public_key + message) % _q
    sB = _point_mul(s, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))
