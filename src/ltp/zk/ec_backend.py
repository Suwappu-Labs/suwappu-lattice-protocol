"""
BLS12-381 elliptic curve backend for ZK proofs.

Provides point arithmetic, serialization, and generator derivation
for Pedersen commitments and Sigma protocol proofs.

Requires: py_ecc >= 7.0.0 (optional dependency, [zk] extras group).
When py_ecc is not installed, bls12_381_available() returns False and
the ZK transfer module falls back to hash-based simulation.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

# ---------------------------------------------------------------------------
# py_ecc availability detection (mirrors primitives.py:59-84)
# ---------------------------------------------------------------------------

_py_ecc_available = False

try:
    from py_ecc.bls12_381 import (  # type: ignore[import-untyped]
        G1 as _BLS_G1,
        Z1 as _G1_IDENTITY,
        add as _g1_add,
        curve_order as _BLS_ORDER,
        field_modulus as _FIELD_MODULUS,
        multiply as _g1_multiply,
        neg as _g1_neg,
    )
    from py_ecc.bls12_381 import FQ as _FQ  # type: ignore[import-untyped]

    _py_ecc_available = True
except ImportError:
    _BLS_G1 = None
    _G1_IDENTITY = None
    _BLS_ORDER = None
    _FIELD_MODULUS = None
    _FQ = None


# G2 operations use the optimized backend (projective coordinates)
# Required for G2_to_signature / signature_to_G2 compatibility
_py_ecc_g2_available = False
try:
    from py_ecc.optimized_bls12_381 import (  # type: ignore[import-untyped]
        G2 as _OPT_G2,
        Z2 as _OPT_Z2,
        multiply as _opt_multiply,
        add as _opt_add,
        curve_order as _OPT_CURVE_ORDER,
    )
    from py_ecc.bls.g2_primitives import (  # type: ignore[import-untyped]
        G2_to_signature as _G2_to_signature,
        G1_to_pubkey as _G1_to_pubkey,
    )
    _py_ecc_g2_available = True
except ImportError:
    _OPT_G2 = None
    _OPT_Z2 = None
    _OPT_CURVE_ORDER = None


# Type alias for G1 points (tuple of FQ elements in py_ecc)
G1Point = Any

# Type alias for G2 points (optimized_bls12_381 projective 3-tuple)
G2Point = Any

# BLS12-381 G1 cofactor for subgroup clearing
_G1_COFACTOR = 0x396C8C005555E1568C00AAAB0000AAAB

# Cached H generator (computed once on first use)
_H_GENERATOR_CACHE: G1Point | None = None


def bls12_381_available() -> bool:
    """Return True if py_ecc BLS12-381 backend is installed."""
    return _py_ecc_available


def _require_backend() -> None:
    """Raise if py_ecc is not available."""
    if not _py_ecc_available:
        raise RuntimeError(
            "BLS12-381 backend requires py_ecc. "
            "Install with: pip install 'ltp[zk]'"
        )


# ---------------------------------------------------------------------------
# Generator points
# ---------------------------------------------------------------------------


def g1_generator() -> G1Point:
    """Return the standard BLS12-381 G1 generator."""
    _require_backend()
    return _BLS_G1


def g1_h_generator() -> G1Point:
    """
    Return the nothing-up-my-sleeve H generator for Pedersen commitments.

    H is derived via try-and-increment hash-to-curve so that the discrete
    log relationship between G and H is unknown, which is required for the
    binding property of Pedersen commitments.

    The result is cached at module level since H is a public constant.
    """
    global _H_GENERATOR_CACHE
    _require_backend()

    if _H_GENERATOR_CACHE is not None:
        return _H_GENERATOR_CACHE

    from ..domain import DOMAIN_ZK_TRANSFER

    seed = DOMAIN_ZK_TRANSFER + b"pedersen-h-generator"

    # Try-and-increment: hash seed with counter to find a valid x-coordinate
    for attempt in range(256):
        h = hashlib.sha3_256(seed + attempt.to_bytes(2, "big")).digest()
        x = int.from_bytes(h, "big") % _FIELD_MODULUS

        # BLS12-381 G1 curve: y^2 = x^3 + 4
        x_fq = _FQ(x)
        y_squared = x_fq**3 + _FQ(4)

        # Since p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
        y_candidate = y_squared ** ((_FIELD_MODULUS + 1) // 4)

        if y_candidate**2 == y_squared:
            # Valid point found — use even y (convention)
            y = y_candidate
            if int(y) % 2 != 0:
                y = _FQ(_FIELD_MODULUS - int(y))

            point = (x_fq, y)

            # Cofactor clearing to ensure point is in prime-order subgroup
            h_point = _g1_multiply(point, _G1_COFACTOR)

            if h_point is not None:
                _H_GENERATOR_CACHE = h_point
                return h_point

    raise RuntimeError("Failed to derive H generator (should never happen)")


# ---------------------------------------------------------------------------
# Point arithmetic wrappers
# ---------------------------------------------------------------------------


def g1_scalar_mul(point: G1Point, scalar: int) -> G1Point:
    """Compute scalar * point on BLS12-381 G1."""
    _require_backend()
    return _g1_multiply(point, scalar % _BLS_ORDER)


def g1_add(p1: G1Point, p2: G1Point) -> G1Point:
    """Add two G1 points."""
    _require_backend()
    return _g1_add(p1, p2)


def g1_neg(point: G1Point) -> G1Point:
    """Negate a G1 point."""
    _require_backend()
    return _g1_neg(point)


def g1_eq(p1: G1Point, p2: G1Point) -> bool:
    """Check equality of two G1 points (affine representation)."""
    _require_backend()
    # py_ecc uses affine (x, y) tuples; identity is None
    if p1 is None and p2 is None:
        return True
    if p1 is None or p2 is None:
        return False
    return p1[0] == p2[0] and p1[1] == p2[1]


def g1_identity() -> G1Point:
    """Return the identity element (point at infinity) of G1. None in py_ecc."""
    _require_backend()
    return None


# ---------------------------------------------------------------------------
# Serialization (uncompressed: 96 bytes = 48B x + 48B y)
# ---------------------------------------------------------------------------


def g1_serialize(point: G1Point) -> bytes:
    """
    Serialize a G1 point to 96 bytes (uncompressed).

    Format: x (48 bytes big-endian) || y (48 bytes big-endian)
    Identity point is serialized as 96 zero bytes.
    """
    _require_backend()
    if point is None:
        return b"\x00" * 96

    x_bytes = int(point[0]).to_bytes(48, "big")
    y_bytes = int(point[1]).to_bytes(48, "big")
    return x_bytes + y_bytes


def g1_deserialize(data: bytes) -> G1Point:
    """
    Deserialize 96 bytes to a G1 point.

    Validates that the point is on the BLS12-381 G1 curve.
    Raises ValueError for invalid points.
    """
    _require_backend()
    if len(data) != 96:
        raise ValueError(f"Expected 96 bytes, got {len(data)}")

    if data == b"\x00" * 96:
        return None

    x = int.from_bytes(data[:48], "big")
    y = int.from_bytes(data[48:], "big")

    if x >= _FIELD_MODULUS or y >= _FIELD_MODULUS:
        raise ValueError("Coordinate exceeds field modulus")

    x_fq = _FQ(x)
    y_fq = _FQ(y)

    # Verify point is on curve: y^2 = x^3 + 4
    if y_fq**2 != x_fq**3 + _FQ(4):
        raise ValueError("Point is not on BLS12-381 G1 curve")

    # Subgroup check: verify point is in prime-order subgroup
    # Prevents small-order point attacks on Pedersen commitments
    point = (x_fq, y_fq)
    check = _g1_multiply(point, _BLS_ORDER)
    if check is not None:
        raise ValueError("Point is not in the prime-order subgroup")

    return point


# ---------------------------------------------------------------------------
# Scalar utilities
# ---------------------------------------------------------------------------


def scalar_from_entity_id(entity_id: str) -> int:
    """
    Convert entity_id to a BLS12-381 scalar.

    Uses SHA3-256 of the entity_id bytes, reduced mod curve order.
    """
    _require_backend()
    digest = hashlib.sha3_256(entity_id.encode()).digest()
    return int.from_bytes(digest, "big") % _BLS_ORDER


def scalar_from_bytes(b: bytes) -> int:
    """Convert raw bytes to a BLS12-381 scalar (mod curve order)."""
    _require_backend()
    return int.from_bytes(b, "big") % _BLS_ORDER


def random_scalar() -> int:
    """Generate a cryptographically random BLS12-381 scalar."""
    _require_backend()
    return int.from_bytes(os.urandom(32), "big") % _BLS_ORDER


def curve_order() -> int:
    """Return the BLS12-381 curve order."""
    _require_backend()
    return _BLS_ORDER


# ---------------------------------------------------------------------------
# G2 point arithmetic (optimized backend — projective coordinates)
# ---------------------------------------------------------------------------


def g2_generator() -> G2Point:
    """Return the standard BLS12-381 G2 generator (optimized/projective)."""
    _require_backend()
    return _OPT_G2


def g2_scalar_mul(point: G2Point, scalar: int) -> G2Point:
    """Compute scalar * point on BLS12-381 G2."""
    _require_backend()
    return _opt_multiply(point, scalar % _OPT_CURVE_ORDER)


def g2_add(p1: G2Point, p2: G2Point) -> G2Point:
    """Add two G2 points."""
    _require_backend()
    return _opt_add(p1, p2)


def g2_identity() -> G2Point:
    """Return the identity element of G2 (optimized backend)."""
    _require_backend()
    return _OPT_Z2


def g2_compress(point: G2Point) -> bytes:
    """Compress a G2 point to 96 bytes (Zcash serialization).

    Compatible with BLS.verify() signature format.
    """
    _require_backend()
    return bytes(_G2_to_signature(point))


# ---------------------------------------------------------------------------
# G1 compression (for threshold verify bridge to BLS.verify)
# ---------------------------------------------------------------------------


def g1_compress(point: G1Point) -> bytes:
    """Compress a G1 point to 48 bytes.

    Converts from the affine (x, y) format used by ec_backend
    to the 48-byte compressed format used by BLS.verify().
    """
    _require_backend()
    if point is None:
        return b"\x00" * 48
    # py_ecc's G1_to_pubkey expects optimized (projective) format.
    # Convert affine (x, y) to projective (x, y, 1).
    from py_ecc.fields import optimized_bls12_381_FQ as OPT_FQ
    x_opt = OPT_FQ(int(point[0]))
    y_opt = OPT_FQ(int(point[1]))
    z_opt = OPT_FQ(1)
    projective = (x_opt, y_opt, z_opt)
    return bytes(_G1_to_pubkey(projective))
