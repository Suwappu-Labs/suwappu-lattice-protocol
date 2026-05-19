"""
Fraud proof types for the optimistic bridge.

Three fraud proof types, each verifiable independently:
  - InvalidSignature:    ML-DSA signature on STH/record doesn't verify
  - InconsistentSTH:     Two valid STHs at same sequence with different roots (fork)
  - InvalidMerkleProof:  Inclusion proof doesn't verify against claimed root

A fraud proof's verify() returns True if the fraud IS valid (i.e., the
operator misbehaved).  A watcher constructs a proof, calls verify() locally,
and if True submits it to the ChallengeManager.

"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from ..domain import DOMAIN_FRAUD_PROOF, domain_hash_bytes
from ..primitives import MLDSA, canonical_hash_bytes

if TYPE_CHECKING:
    from ..merkle_log.portable_proof import PortableMerkleProof
    from ..merkle_log.sth import SignedTreeHead

__all__ = [
    "FraudProofType",
    "InvalidSignatureFraudProof",
    "InconsistentSTHFraudProof",
    "InvalidMerkleProofFraudProof",
]


class FraudProofType(Enum):
    """Discriminator for on-chain fraud proof type mapping."""

    INVALID_SIGNATURE = "invalid_signature"
    INCONSISTENT_STH = "inconsistent_sth"
    INVALID_MERKLE_PROOF = "invalid_merkle_proof"


@dataclass(frozen=True)
class InvalidSignatureFraudProof:
    """Fraud proof: ML-DSA signature doesn't verify against claimed signer.

    This proves an operator published a commitment record or STH with
    an invalid signature.  verify() returns True when the signature
    FAILS ML-DSA verification (i.e., the fraud is real).
    """

    anchor_digest: bytes  # 32B — the disputed anchor
    claimed_signer_vk: bytes  # ML-DSA-65 VK
    signed_data: bytes  # The data that was supposedly signed
    signature: bytes  # The invalid signature
    proof_type: FraudProofType = FraudProofType.INVALID_SIGNATURE

    def to_bytes(self) -> bytes:
        """Domain-separated canonical encoding for hashing."""
        return (
            DOMAIN_FRAUD_PROOF
            + self.proof_type.value.encode()
            + struct.pack(">I", len(self.anchor_digest))
            + self.anchor_digest
            + struct.pack(">I", len(self.claimed_signer_vk))
            + self.claimed_signer_vk
            + struct.pack(">I", len(self.signed_data))
            + self.signed_data
            + struct.pack(">I", len(self.signature))
            + self.signature
        )

    def proof_hash(self) -> bytes:
        """SHA3-256 hash of the canonical encoding (for on-chain submission)."""
        return canonical_hash_bytes(self.to_bytes())

    def verify(self) -> bool:
        """Returns True if this IS a valid fraud proof.

        A valid fraud proof means the signature does NOT verify —
        the operator published an invalid signature.
        """
        sig_valid = MLDSA.verify(self.claimed_signer_vk, self.signed_data, self.signature)
        # Fraud is valid when the signature is INVALID
        return not sig_valid


@dataclass(frozen=True)
class InconsistentSTHFraudProof:
    """Fraud proof: two STHs at the same sequence with different roots.

    This proves an operator forked the commitment log — a critical
    equivocation attack that violates append-only guarantees.

    verify() returns True when:
      1. Both STHs have the same operator_vk
      2. Both STHs have the same sequence number
      3. Both STHs have valid ML-DSA signatures
      4. The root hashes differ (fork detected)
    """

    sth_a: "SignedTreeHead"
    sth_b: "SignedTreeHead"
    proof_type: FraudProofType = FraudProofType.INCONSISTENT_STH

    def to_bytes(self) -> bytes:
        """Domain-separated canonical encoding."""
        return (
            DOMAIN_FRAUD_PROOF
            + self.proof_type.value.encode()
            + self.sth_a.signable_payload()
            + self.sth_a.signature
            + self.sth_b.signable_payload()
            + self.sth_b.signature
        )

    def proof_hash(self) -> bytes:
        """SHA3-256 hash of the canonical encoding."""
        return canonical_hash_bytes(self.to_bytes())

    def verify(self) -> bool:
        """Returns True if this IS a valid fork fraud proof."""
        # Must be from the same operator
        if self.sth_a.operator_vk != self.sth_b.operator_vk:
            return False

        # Must be at the same sequence
        if self.sth_a.sequence != self.sth_b.sequence:
            return False

        # Roots must differ (otherwise it's not a fork)
        if self.sth_a.root_hash == self.sth_b.root_hash:
            return False

        # Both signatures must be valid (otherwise it's a forgery, not a fork)
        vk = self.sth_a.operator_vk
        sig_a_valid = MLDSA.verify(vk, self.sth_a.signable_payload(), self.sth_a.signature)
        sig_b_valid = MLDSA.verify(vk, self.sth_b.signable_payload(), self.sth_b.signature)
        return sig_a_valid and sig_b_valid


@dataclass(frozen=True)
class InvalidMerkleProofFraudProof:
    """Fraud proof: Merkle inclusion proof doesn't verify against claimed root.

    This proves an operator published a commitment with a Merkle proof
    that is inconsistent with the claimed root hash.
    """

    anchor_digest: bytes  # 32B — the disputed anchor
    claimed_root: bytes  # 32B — root hash the operator published
    proof: "PortableMerkleProof"  # The proof that fails verification
    proof_type: FraudProofType = FraudProofType.INVALID_MERKLE_PROOF

    def to_bytes(self) -> bytes:
        """Domain-separated canonical encoding."""
        return (
            DOMAIN_FRAUD_PROOF
            + self.proof_type.value.encode()
            + struct.pack(">I", len(self.anchor_digest))
            + self.anchor_digest
            + struct.pack(">I", len(self.claimed_root))
            + self.claimed_root
            + struct.pack(">Q", self.proof.leaf_index)
            + self.proof.leaf_hash
            + self.proof.root_hash
        )

    def proof_hash(self) -> bytes:
        """SHA3-256 hash of the canonical encoding."""
        return canonical_hash_bytes(self.to_bytes())

    def verify(self) -> bool:
        """Returns True if this IS a valid fraud proof.

        Valid fraud means the Merkle proof does NOT verify against
        the claimed root — the operator published an inconsistent proof.
        """
        proof_valid = self.proof.verify()
        # Fraud is valid when the proof FAILS verification
        return not proof_valid
