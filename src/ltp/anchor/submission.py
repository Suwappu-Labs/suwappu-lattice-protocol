"""
Anchor submission — the calldata structure for on-chain anchoring.

An AnchorSubmission contains exactly the fields needed by the Solidity
anchor contract. All fields are fixed-width or bounded, so ABI encoding
is straightforward.

Reference: SUWAPPU_PRE_BLOCKCHAIN_ROADMAP.md §2.10
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = ["AnchorSubmission"]


@dataclass
class AnchorSubmission:
    """The on-chain submission payload for anchoring a trust artifact.

    All fields are designed for efficient Solidity storage:
      - 32B fields map to bytes32
      - uint fields map to uint64/uint256
      - receipt_type maps to a uint8 enum in Solidity

    Fields:
        anchor_digest:   32B receipt anchor digest
        entity_id_hash:  32B entity identifier (defaults to anchor_digest)
        merkle_root:     32B Merkle root at time of receipt
        policy_hash:     32B hash of governing SignerPolicy
        signer_vk_hash:  32B fingerprint of the signer's VK
        sequence:        Per-signer monotonic sequence number
        valid_until:     Expiry timestamp (unix seconds)
        target_chain_id: Target chain identifier (uint64)
        receipt_type:    Type discriminator string
    """

    anchor_digest: bytes
    merkle_root: bytes
    policy_hash: bytes
    signer_vk_hash: bytes
    sequence: int
    valid_until: int
    target_chain_id: int
    receipt_type: str
    entity_id_hash: bytes | None = None

    def __post_init__(self) -> None:
        if self.entity_id_hash is None:
            self.entity_id_hash = self.anchor_digest

    def to_calldata(self) -> bytes:
        """ABI-encode for Solidity consumption.

        Layout (packed, no padding — use abi.encodePacked on-chain):
          anchor_digest  (32B)
          merkle_root    (32B)
          policy_hash    (32B)
          signer_vk_hash (32B)
          sequence       (8B, uint64 BE)
          valid_until    (8B, uint64 BE)
          target_chain_id(8B, uint64 BE)
          receipt_type   (4B len + UTF-8)
        """
        if len(self.anchor_digest) != 32:
            raise ValueError(f"anchor_digest must be 32B, got {len(self.anchor_digest)}")
        if len(self.merkle_root) != 32:
            raise ValueError(f"merkle_root must be 32B, got {len(self.merkle_root)}")
        if len(self.policy_hash) != 32:
            raise ValueError(f"policy_hash must be 32B, got {len(self.policy_hash)}")
        if len(self.signer_vk_hash) != 32:
            raise ValueError(f"signer_vk_hash must be 32B, got {len(self.signer_vk_hash)}")

        rt_bytes = self.receipt_type.encode("utf-8")
        return (
            self.anchor_digest
            + self.merkle_root
            + self.policy_hash
            + self.signer_vk_hash
            + struct.pack(">Q", self.sequence)
            + struct.pack(">Q", self.valid_until)
            + struct.pack(">Q", self.target_chain_id)
            + struct.pack(">I", len(rt_bytes))
            + rt_bytes
        )

    @classmethod
    def from_receipt(
        cls,
        receipt: "ApprovalReceipt",
        policy_hash_bytes: bytes,
        target_chain_id_int: int,
    ) -> "AnchorSubmission":
        """Create an AnchorSubmission from an ApprovalReceipt.

        Args:
            receipt:              The signed receipt
            policy_hash_bytes:    32B hash of governing policy
            target_chain_id_int:  Numeric chain ID
        """
        from ..domain import signer_fingerprint

        return cls(
            anchor_digest=receipt.anchor_digest(),
            merkle_root=receipt.merkle_root,
            policy_hash=policy_hash_bytes,
            signer_vk_hash=signer_fingerprint(receipt.signer_vk),
            sequence=receipt.sequence,
            valid_until=int(receipt.valid_until),
            target_chain_id=target_chain_id_int,
            receipt_type=receipt.receipt_type.value,
        )
