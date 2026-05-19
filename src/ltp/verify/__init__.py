"""
Verification SDK for the Lattice Transfer Protocol.

Pure verification functions — no network, no state, no side effects.
Designed for external verifiers (auditors, regulators, cross-chain bridges)
who need to verify trust artifacts without running an LTP node.

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.8
"""

from .core import (
    verify_commitment_chain,
    verify_envelope,
    verify_merkle_proof,
    verify_receipt,
    verify_sth,
    verify_zk_bridge_proof,
)
from .results import VerificationResult

__all__ = [
    "VerificationResult",
    "verify_envelope",
    "verify_receipt",
    "verify_merkle_proof",
    "verify_sth",
    "verify_commitment_chain",
    "verify_zk_bridge_proof",
]
