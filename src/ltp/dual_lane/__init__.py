"""
GSX Dual-Lane Cryptographic Architecture.

Two hash lanes serve different trust boundaries:

  **Canonical Lane** (SHA3-256): Settlement-valid, regulator-facing, externally
  audited artifacts — entity IDs, commitment records, Merkle roots, proofs.

  **Internal Lane** (BLAKE3-256): Shard indexing, chunk integrity, caching,
  AEAD keystream — never part of the compliance trust boundary.
"""

from .hashing import (
    HashFunction,
    _blake3_available,
    _hash_digest,
    canonical_hash,
    canonical_hash_bytes,
    internal_hash,
    internal_hash_bytes,
)
from .lanes import (
    COMPLIANCE_APPROVED,
    CryptoLane,
    get_compliance_strict,
    set_compliance_strict,
)
from .profiles import SecurityProfile

__all__ = [
    "HashFunction",
    "CryptoLane",
    "SecurityProfile",
    "COMPLIANCE_APPROVED",
    "canonical_hash",
    "canonical_hash_bytes",
    "internal_hash",
    "internal_hash_bytes",
    "set_compliance_strict",
    "get_compliance_strict",
    "_blake3_available",
    "_hash_digest",
]
