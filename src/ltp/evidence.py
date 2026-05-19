"""
Evidence packaging for the Lattice Transfer Protocol.

An EvidenceBundle aggregates all trust artifacts related to a protocol action
into a single, self-contained package that can be verified independently.

Used for:
  - Regulatory submissions (complete audit trail)
  - Cross-chain bridge verification (all proofs in one package)
  - Dispute resolution (evidence for on-chain adjudication)

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.12
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .domain import DOMAIN_COMMIT_RECORD
from .encoding import CanonicalEncoder
from .primitives import canonical_hash

__all__ = ["EvidenceBundle"]


@dataclass
class EvidenceBundle:
    """A self-contained evidence package for a protocol action.

    Aggregates receipts, Merkle proofs, STH snapshots, and policy
    references into a single verifiable bundle.

    Fields:
        bundle_id:      Content-addressed identifier
        entity_id:      Entity this evidence covers
        created_at:     Bundle creation timestamp
        receipts:       Signed ApprovalReceipts (serialized)
        merkle_proofs:  PortableMerkleProofs (serialized)
        sth_snapshots:  SignedTreeHead canonical bytes
        policy_hash:    Hash of governing policy at time of action
        metadata:       Additional context (action type, chain ID, etc.)
    """

    bundle_id: str
    entity_id: str
    created_at: float
    receipts: list[bytes] = field(default_factory=list)
    merkle_proofs: list[bytes] = field(default_factory=list)
    sth_snapshots: list[bytes] = field(default_factory=list)
    policy_hash: str = ""
    metadata: dict = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding of the bundle content."""
        enc = (
            CanonicalEncoder(DOMAIN_COMMIT_RECORD)
            .string(self.entity_id)
            .float64(self.created_at)
            .string(self.policy_hash)
        )

        # Encode receipts
        enc.uint32(len(self.receipts))
        for r in self.receipts:
            enc.length_prefixed_bytes(r)

        # Encode proofs
        enc.uint32(len(self.merkle_proofs))
        for p in self.merkle_proofs:
            enc.length_prefixed_bytes(p)

        # Encode STH snapshots
        enc.uint32(len(self.sth_snapshots))
        for s in self.sth_snapshots:
            enc.length_prefixed_bytes(s)

        return enc.finalize()

    def compute_bundle_id(self) -> str:
        """Content-addressed bundle identifier."""
        return canonical_hash(self.canonical_bytes())

    @classmethod
    def create(
        cls,
        entity_id: str,
        receipts: list[bytes] | None = None,
        merkle_proofs: list[bytes] | None = None,
        sth_snapshots: list[bytes] | None = None,
        policy_hash: str = "",
        metadata: dict | None = None,
    ) -> "EvidenceBundle":
        """Factory: create a new evidence bundle."""
        bundle = cls(
            bundle_id="",
            entity_id=entity_id,
            created_at=time.time(),
            receipts=receipts or [],
            merkle_proofs=merkle_proofs or [],
            sth_snapshots=sth_snapshots or [],
            policy_hash=policy_hash,
            metadata=metadata or {},
        )
        bundle.bundle_id = bundle.compute_bundle_id()
        return bundle

    def add_receipt(self, receipt_bytes: bytes) -> None:
        """Add a serialized receipt and recompute bundle_id."""
        self.receipts.append(receipt_bytes)
        self.bundle_id = self.compute_bundle_id()

    def add_merkle_proof(self, proof_bytes: bytes) -> None:
        """Add a serialized Merkle proof and recompute bundle_id."""
        self.merkle_proofs.append(proof_bytes)
        self.bundle_id = self.compute_bundle_id()

    def add_sth_snapshot(self, sth_bytes: bytes) -> None:
        """Add a serialized STH snapshot and recompute bundle_id."""
        self.sth_snapshots.append(sth_bytes)
        self.bundle_id = self.compute_bundle_id()
