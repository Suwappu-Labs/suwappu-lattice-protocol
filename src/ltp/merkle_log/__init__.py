"""
CT-Style Merkle Log — Reference Implementation for LTP §5.1.4

A Certificate-Transparency-inspired append-only Merkle log using LTP's
existing post-quantum primitives (BLAKE2b-256 + ML-DSA-65).

Proves the minimum conformance requirement for the recommended LTP commitment
log implementation:

  - Append-only binary Merkle tree with RFC 6962 domain separation
  - ML-DSA-65 Signed Tree Heads (STH) for operator attestation
  - O(log N) inclusion proofs for independent verification
  - Cryptographic equivocation detection (fork proof)

Public API:
  MerkleTree     — low-level append-only Merkle tree
  SignedTreeHead — ML-DSA-65 signed snapshot of the log state
  InclusionProof — verifiable proof of record membership
  MerkleLog      — high-level log: append, sign, prove, detect forks
"""

from .log import MerkleLog
from .proof import InclusionProof
from .sth import SignedTreeHead
from .tree import MerkleTree, verify_consistency

__all__ = [
    "MerkleTree",
    "SignedTreeHead",
    "InclusionProof",
    "MerkleLog",
    "verify_consistency",
]
