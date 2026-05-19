"""
L1Anchor — source chain commitment for the ETP bridge.

Wraps LTPProtocol.commit() with bridge-specific logic:
  - Serializes BridgeMessage → Entity
  - Validates sequence monotonicity via SequenceTracker
  - Generates Merkle inclusion proof
  - Creates ApprovalReceipt for on-chain anchoring
  - Wraps commits in SignedEnvelope for authenticated transport
  - Returns BridgeCommitment + CEK
"""

from __future__ import annotations

import logging
import time

from ..anchor.submission import AnchorSubmission
from ..domain import DOMAIN_BRIDGE_MSG, signer_fingerprint
from ..entity import Entity
from ..envelope import SignedEnvelope
from ..keypair import KeyPair
from ..primitives import canonical_hash_bytes
from ..protocol import LTPProtocol
from ..receipt import ApprovalReceipt
from ..sequencing import SequenceTracker
from .message import BridgeCommitment, BridgeMessage

logger = logging.getLogger(__name__)

__all__ = ["L1Anchor"]


class L1Anchor:
    """
    Source-chain anchor: commits bridge messages to the ETP commitment log.

    Operates on the L1 side.  For each bridge message:
      1. Validates sequence freshness via SequenceTracker (replay protection)
      2. Serializes the message to an Entity
      3. Calls LTPProtocol.commit() (erasure-code, encrypt, distribute, sign)
      4. Creates an ApprovalReceipt for on-chain anchoring
      5. Wraps commit in SignedEnvelope for authenticated transport
      6. Generates a Merkle inclusion proof
      7. Returns a BridgeCommitment (public) + CEK (secret, for lattice phase)
    """

    def __init__(
        self,
        protocol: LTPProtocol,
        operator_keypair: KeyPair,
        chain_id: str = "ethereum",
        policy_hash: str = "",
    ) -> None:
        self.protocol = protocol
        self.operator_keypair = operator_keypair
        self.chain_id = chain_id
        self.policy_hash = policy_hash
        self.sequence_tracker = SequenceTracker(chain_id=chain_id)
        self._block_counter = 0  # Simulated L1 block height
        self._sequence_counter = 0  # Per-operator sequence counter
        # Message-level nonce tracking: (source_chain, sender) → highest nonce
        self._nonce_hwm: dict[tuple[str, str], int] = {}

    def commit_message(
        self,
        message: BridgeMessage,
        n: int = 8,
        k: int = 4,
    ) -> tuple[BridgeCommitment, bytes]:
        """
        Commit a bridge message to the L1 anchor.

        Steps:
          1. Validate source chain matches this anchor
          2. Validate sequence via SequenceTracker (strictly increasing per signer)
          3. Serialize message → Entity
          4. LTPProtocol.commit() → entity_id, record, CEK
          5. Create ApprovalReceipt for on-chain anchoring
          6. Wrap in SignedEnvelope for authenticated transport
          7. Generate Merkle inclusion proof
          8. Package as BridgeCommitment

        Returns: (BridgeCommitment, cek)
        Raises: ValueError if sequence is replayed or chain mismatch.
        """
        # Validate source chain
        if message.source_chain != self.chain_id:
            raise ValueError(
                f"Message source_chain '{message.source_chain}' "
                f"does not match anchor chain '{self.chain_id}'"
            )

        # Message-level nonce replay protection (per sender)
        nonce_key = (message.source_chain, message.sender)
        current_nonce = self._nonce_hwm.get(nonce_key, -1)
        if message.nonce <= current_nonce:
            raise ValueError(
                f"Nonce {message.nonce} for sender {message.sender} "
                f"is not strictly increasing (replay detected)"
            )
        self._nonce_hwm[nonce_key] = message.nonce

        # Advance sequence and validate via SequenceTracker
        self._sequence_counter += 1
        valid_until = time.time() + 3600.0  # 1 hour expiry
        ok, reason = self.sequence_tracker.validate_and_advance(
            signer_vk=self.operator_keypair.vk,
            sequence=self._sequence_counter,
            target_chain_id=self.chain_id,
            valid_until=valid_until,
        )
        if not ok:
            raise ValueError(f"Sequence validation failed: {reason}")

        # Serialize message → Entity
        content = message.to_canonical_bytes()
        entity = Entity(content=content, shape="application/vnd.etp.bridge-message+json")

        logger.info(
            "[L1Anchor] Committing bridge message: %s %s→%s nonce=%d seq=%d",
            message.msg_type,
            message.source_chain,
            message.dest_chain,
            message.nonce,
            self._sequence_counter,
        )

        # COMMIT phase
        entity_id, record, cek = self.protocol.commit(entity, self.operator_keypair, n=n, k=k)

        # Create ApprovalReceipt for on-chain anchoring (if STH available)
        sth = self.protocol.network.log.latest_sth
        receipt = None
        if sth is not None:
            receipt = ApprovalReceipt.for_commit(
                entity_id=entity_id,
                record=record,
                sth=sth,
                signer_kp=self.operator_keypair,
                signer_role="operator",
                sequence=self._sequence_counter,
                target_chain_id=self.chain_id,
                policy_hash=self.policy_hash,
            )

        # Wrap in SignedEnvelope for authenticated transport
        envelope = SignedEnvelope.create(
            domain=DOMAIN_BRIDGE_MSG,
            signer_vk=self.operator_keypair.vk,
            signer_sk=self.operator_keypair,
            signer_id=self.operator_keypair.label,
            payload_type="bridge-commit",
            payload=content,
        )

        # Generate Merkle inclusion proof
        proof = self.protocol.network.log.get_inclusion_proof(entity_id)
        if proof is None:
            raise RuntimeError(f"Failed to generate inclusion proof for {entity_id[:16]}...")

        # Advance simulated block height
        self._block_counter += 1

        commitment = BridgeCommitment(
            message=message,
            entity_id=entity_id,
            commitment_ref=record.to_bytes().hex()[:64],
            merkle_proof=proof,
            source_block=self._block_counter,
        )

        receipt_info = receipt.receipt_id[:16] if receipt else "n/a"
        logger.info(
            "[L1Anchor] Committed at block %d, entity_id=%s..., receipt_id=%s...",
            self._block_counter,
            entity_id[:16],
            receipt_info,
        )

        return commitment, cek

    @property
    def last_receipt_sequence(self) -> int:
        """Return the current sequence counter value."""
        return self._sequence_counter
