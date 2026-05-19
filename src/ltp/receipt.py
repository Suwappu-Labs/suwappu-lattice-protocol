"""
Approval receipts for the Lattice Transfer Protocol.

The trust artifact that smart contracts anchor. Each receipt captures a
complete, signed attestation that a protocol action (commit, materialize,
audit, rotation, deletion, governance) was performed correctly.

Receipt lifecycle:
  1. Protocol action completes (commit, materialize, etc.)
  2. Factory method builds receipt from action outputs
  3. Receipt is signed by the authorized signer
  4. receipt_id = H(canonical_bytes_unsigned) — content-addressed
  5. anchor_digest() → 32B for on-chain anchoring
  6. Smart contract stores anchor_digest + metadata

Temporal validation follows RFC 8392 (CWT) boundary semantics:
  - nbf <= now passes (receipt is active)
  - now >= exp (valid_until) fails (receipt has expired)

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.4
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum

from .domain import (
    DOMAIN_ANCHOR_DIGEST,
    DOMAIN_APPROVAL_RECEIPT,
    domain_hash_bytes,
    domain_sign,
    domain_verify,
)
from .encoding import CanonicalEncoder
from .primitives import canonical_hash, canonical_hash_bytes

__all__ = ["ReceiptType", "ApprovalReceipt"]


class ReceiptType(Enum):
    """Types of protocol actions that produce receipts."""

    COMMIT = "COMMIT"
    MATERIALIZE = "MATERIALIZE"
    SHARD_AUDIT_PASS = "SHARD_AUDIT_PASS"
    KEY_ROTATION = "KEY_ROTATION"
    DELETION = "DELETION"
    GOVERNANCE = "GOVERNANCE"


@dataclass
class ApprovalReceipt:
    """A signed attestation that a protocol action was performed correctly.

    This is the primary trust artifact for on-chain anchoring. Smart contracts
    store the anchor_digest(); external verifiers can verify the full receipt
    without running an LTP node.

    Fields:
        receipt_id:      H(canonical_bytes_unsigned) — content-addressed
        receipt_type:    Type of protocol action
        entity_id:       Entity this receipt covers
        action_summary:  Human-readable summary
        timestamp:       Unix time of receipt creation
        epoch:           Protocol epoch
        sequence:        Per-signer monotonic counter

        commitment_ref:  Hash of the commitment record
        sth_ref:         Hash of the STH at the time of action
        merkle_root:     32B Merkle root at the time of action

        signer_vk:       ML-DSA-65 verification key of the signer
        signer_role:     Role of the signer (e.g. "operator", "auditor")

        target_chain_id: Target blockchain for anchoring
        valid_until:     Expiry timestamp (RFC 8392 half-open interval)

        policy_hash:     Hash of the governing SignerPolicy

        signature:       ML-DSA-65 signature
    """

    receipt_id: str
    receipt_type: ReceiptType
    entity_id: str
    action_summary: str
    timestamp: float
    epoch: int
    sequence: int

    commitment_ref: str
    sth_ref: str
    merkle_root: bytes

    signer_vk: bytes
    signer_role: str

    target_chain_id: str
    valid_until: float

    policy_hash: str

    signature: bytes

    def canonical_bytes_unsigned(self) -> bytes:
        """Canonical encoding of all fields except receipt_id and signature.

        Used to compute receipt_id and as the signing input.
        """
        return (
            CanonicalEncoder(DOMAIN_APPROVAL_RECEIPT)
            .string(self.receipt_type.value)
            .string(self.entity_id)
            .string(self.action_summary)
            .float64(self.timestamp)
            .uint64(self.epoch)
            .uint64(self.sequence)
            .string(self.commitment_ref)
            .string(self.sth_ref)
            .raw_bytes(self.merkle_root)
            .length_prefixed_bytes(self.signer_vk)
            .string(self.signer_role)
            .string(self.target_chain_id)
            .float64(self.valid_until)
            .string(self.policy_hash)
            .finalize()
        )

    def compute_receipt_id(self) -> str:
        """Compute content-addressed receipt ID: H(canonical_bytes_unsigned)."""
        return canonical_hash(self.canonical_bytes_unsigned())

    def sign(self, signer) -> None:
        """Sign this receipt. Sets receipt_id and signature.

        `signer` may be raw `sk` bytes (legacy) or a `KeyPair`
        (LTP-A-032 Phase 4d). `domain_sign` already accepts both.
        """
        self.receipt_id = self.compute_receipt_id()
        self.signature = domain_sign(
            DOMAIN_APPROVAL_RECEIPT,
            signer,
            self.canonical_bytes_unsigned(),
        )

    def verify(self, signer_vk: bytes) -> bool:
        """Verify this receipt's signature against the given vk."""
        if not self.signature:
            return False
        # Verify receipt_id matches content
        if self.receipt_id != self.compute_receipt_id():
            return False
        return domain_verify(
            DOMAIN_APPROVAL_RECEIPT,
            signer_vk,
            self.canonical_bytes_unsigned(),
            self.signature,
        )

    def anchor_digest(self) -> bytes:
        """32-byte digest for on-chain anchoring.

        Domain-separated: H(DOMAIN_ANCHOR_DIGEST || canonical_bytes_unsigned || signature)
        """
        return domain_hash_bytes(
            DOMAIN_ANCHOR_DIGEST,
            self.canonical_bytes_unsigned() + self.signature,
        )

    @classmethod
    def for_commit(
        cls,
        entity_id: str,
        record: "CommitmentRecord",
        sth: "SignedTreeHead",
        signer_kp: "KeyPair",
        signer_role: str,
        sequence: int,
        target_chain_id: str,
        epoch: int = 0,
        valid_seconds: float = 3600.0,
        policy_hash: str = "",
    ) -> "ApprovalReceipt":
        """Factory: create a COMMIT receipt from protocol outputs.

        Args:
            entity_id:       Entity that was committed
            record:          The CommitmentRecord
            sth:             SignedTreeHead at the time of commit
            signer_kp:       KeyPair of the signer (uses vk, sk, label)
            signer_role:     Role string
            sequence:        Per-signer monotonic sequence number
            target_chain_id: Target chain for anchoring
            epoch:           Protocol epoch (default 0)
            valid_seconds:   Seconds until expiry (default 1 hour)
            policy_hash:     Hash of governing policy (default "")
        """
        now = time.time()
        commitment_ref = canonical_hash(record.to_bytes())
        sth_ref = canonical_hash(sth.signable_payload())

        receipt = cls(
            receipt_id="",
            receipt_type=ReceiptType.COMMIT,
            entity_id=entity_id,
            action_summary=f"COMMIT entity {entity_id[:16]}...",
            timestamp=now,
            epoch=epoch,
            sequence=sequence,
            commitment_ref=commitment_ref,
            sth_ref=sth_ref,
            merkle_root=sth.root_hash,
            signer_vk=signer_kp.vk,
            signer_role=signer_role,
            target_chain_id=target_chain_id,
            valid_until=now + valid_seconds,
            policy_hash=policy_hash,
            signature=b"",
        )
        receipt.sign(signer_kp)
        return receipt

    @classmethod
    def for_materialize(
        cls,
        entity_id: str,
        record: "CommitmentRecord",
        sth: "SignedTreeHead",
        signer_kp: "KeyPair",
        signer_role: str,
        sequence: int,
        target_chain_id: str,
        epoch: int = 0,
        valid_seconds: float = 3600.0,
        policy_hash: str = "",
    ) -> "ApprovalReceipt":
        """Factory: create a MATERIALIZE receipt from protocol outputs."""
        now = time.time()
        commitment_ref = canonical_hash(record.to_bytes())
        sth_ref = canonical_hash(sth.signable_payload())

        receipt = cls(
            receipt_id="",
            receipt_type=ReceiptType.MATERIALIZE,
            entity_id=entity_id,
            action_summary=f"MATERIALIZE entity {entity_id[:16]}...",
            timestamp=now,
            epoch=epoch,
            sequence=sequence,
            commitment_ref=commitment_ref,
            sth_ref=sth_ref,
            merkle_root=sth.root_hash,
            signer_vk=signer_kp.vk,
            signer_role=signer_role,
            target_chain_id=target_chain_id,
            valid_until=now + valid_seconds,
            policy_hash=policy_hash,
            signature=b"",
        )
        receipt.sign(signer_kp)
        return receipt
