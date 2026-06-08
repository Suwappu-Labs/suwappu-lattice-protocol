"""
SUWAPPU Dual-Lane hash functions and HashFunction enum.

Two hash lanes serve different trust boundaries:

  **Canonical Lane** (SHA3-256): Settlement-valid, regulator-facing, externally
  audited artifacts — entity IDs, commitment records, Merkle roots, proofs.
  Only FIPS-approved algorithms are permitted when compliance-strict mode is on.

  **Internal Lane** (BLAKE3-256): Shard indexing, chunk integrity, caching,
  AEAD keystream — never part of the compliance trust boundary. Falls back
  to SHA3-256 when the ``blake3`` package is not installed.
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# BLAKE3 optional dependency detection
# ---------------------------------------------------------------------------
import os
from enum import Enum

_blake3_available = False
try:
    import blake3 as _blake3_mod

    _blake3_available = True
except ImportError:
    _blake3_mod = None

if os.environ.get("ETP_REQUIRE_REAL_CRYPTO") == "1" and not _blake3_available:
    raise RuntimeError(
        "blake3 package required in production mode (ETP_REQUIRE_REAL_CRYPTO=1). "
        "Install with: pip install blake3"
    )


# ---------------------------------------------------------------------------
# HashFunction enum
# ---------------------------------------------------------------------------


class HashFunction(Enum):
    """
    Supported hash functions.

    SHA3_256:    FIPS 202, default canonical lane hash (32-byte output)
    BLAKE3_256:  Default internal lane hash (fast, 256-bit, not FIPS)
    BLAKE2B_256: Legacy PoC hash (fast, 256-bit, not FIPS-standardized)
    SHA_384:     FIPS 180-4, CNSA 2.0 approved, 384-bit output
    SHA_512:     FIPS 180-4, CNSA 2.0 approved, 512-bit output
    """

    SHA3_256 = "sha3-256"
    BLAKE3_256 = "blake3"
    BLAKE2B_256 = "blake2b"
    SHA_384 = "sha384"
    SHA_512 = "sha512"


# ---------------------------------------------------------------------------
# Core hash dispatch
# ---------------------------------------------------------------------------


def _hash_digest(data: bytes, algo: HashFunction, raw: bool = False):
    """Compute hash with the specified algorithm."""
    if algo == HashFunction.SHA3_256:
        d = hashlib.sha3_256(data)
        prefix = "sha3-256"
        digest_bytes = d.digest()
    elif algo == HashFunction.BLAKE3_256:
        if _blake3_available:
            digest_bytes = _blake3_mod.blake3(data).digest()
            prefix = "blake3"
        else:
            # Fallback to SHA3-256 when blake3 is not installed
            d = hashlib.sha3_256(data)
            prefix = "sha3-256"
            digest_bytes = d.digest()
            if raw:
                return digest_bytes
            return f"{prefix}:{d.hexdigest()}"
    elif algo == HashFunction.BLAKE2B_256:
        d = hashlib.blake2b(data, digest_size=32)
        prefix = "blake2b"
        digest_bytes = d.digest()
    elif algo == HashFunction.SHA_384:
        d = hashlib.sha384(data)
        prefix = "sha384"
        digest_bytes = d.digest()  # 48 bytes
    elif algo == HashFunction.SHA_512:
        d = hashlib.sha512(data)
        prefix = "sha512"
        digest_bytes = d.digest()  # 64 bytes
    else:
        raise ValueError(f"Unsupported hash function: {algo}")

    if raw:
        return digest_bytes
    if algo == HashFunction.BLAKE3_256 and _blake3_available:
        return f"{prefix}:{digest_bytes.hex()}"
    return f"{prefix}:{d.hexdigest()}"


# ---------------------------------------------------------------------------
# Hook functions — patched by primitives.py at import time to avoid circular
# imports. These provide access to the active SecurityProfile and crypto
# provider without hashing.py importing from primitives.py.
# ---------------------------------------------------------------------------

_get_active_profile = None  # -> get_security_profile()
_get_crypto_provider = None  # -> get_crypto_provider()


# ---------------------------------------------------------------------------
# Dual-lane hash functions
# ---------------------------------------------------------------------------


def canonical_hash(data: bytes) -> str:
    """Canonical lane hash. Returns '<algo>:<hex>' string.

    Used for settlement-valid, regulator-facing, externally audited artifacts:
    entity IDs, commitment records, Merkle roots, proofs, signatures.

    Hard-pinned to FIPS-approved algorithms (SHA3-256, SHA-384, SHA-512).
    Rejects BLAKE3/BLAKE2b unconditionally — compliance strict mode is not
    required; the canonical lane is always strict.
    """
    from .lanes import COMPLIANCE_APPROVED

    provider = _get_crypto_provider() if _get_crypto_provider else None
    if provider is not None and getattr(provider, "is_fips_mode", False):
        return provider.hash(data)
    profile = _get_active_profile()
    algo = profile.canonical_hash_fn
    if algo not in COMPLIANCE_APPROVED:
        raise ValueError(
            f"Canonical lane requires FIPS-approved hash, got {algo.value}. "
            f"Use SHA3-256, SHA-384, or SHA-512."
        )
    return _hash_digest(data, algo)


def canonical_hash_bytes(data: bytes) -> bytes:
    """Canonical lane hash. Returns raw bytes (no prefix).

    Used for settlement-valid artifacts where binary output is needed.

    Hard-pinned to FIPS-approved algorithms — same enforcement as canonical_hash().
    """
    from .lanes import COMPLIANCE_APPROVED

    provider = _get_crypto_provider() if _get_crypto_provider else None
    if provider is not None and getattr(provider, "is_fips_mode", False):
        return provider.hash_bytes(data)
    profile = _get_active_profile()
    algo = profile.canonical_hash_fn
    if algo not in COMPLIANCE_APPROVED:
        raise ValueError(
            f"Canonical lane requires FIPS-approved hash, got {algo.value}. "
            f"Use SHA3-256, SHA-384, or SHA-512."
        )
    return _hash_digest(data, algo, raw=True)


def internal_hash(data: bytes) -> str:
    """Internal lane hash. Returns '<algo>:<hex>' string.

    Used for performance-optimized internal operations: shard indexing,
    AEAD keystream, cache integrity. Never part of the compliance boundary.
    """
    profile = _get_active_profile()
    return _hash_digest(data, profile.internal_hash_fn)


def internal_hash_bytes(data: bytes) -> bytes:
    """Internal lane hash. Returns raw bytes (no prefix).

    Used for internal operations where binary output is needed.
    """
    profile = _get_active_profile()
    return _hash_digest(data, profile.internal_hash_fn, raw=True)
