"""
Relayer — cross-chain sealed key transport for the ETP bridge.

Wraps LTPProtocol.lattice() to produce a RelayPacket:
  - Seals the CEK + entity_id + commitment_ref to the L2 verifier's public key
  - Packages the sealed key with bridge routing metadata
  - The relayer itself is UNTRUSTED — it transports an opaque blob

Trust model:
  The relayer cannot read the CEK (ML-KEM encrypted), cannot forge the
  commitment (ML-DSA signed), and cannot redirect to a different recipient
  (sealed to a specific ML-KEM encapsulation key).

  When a SignerPolicy is provided, the relayer verifies that the relay
  operator is authorized before forwarding. Relay messages are wrapped
  in a SignedEnvelope for authenticated transport.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from ..domain import DOMAIN_BRIDGE_MSG
from ..envelope import SignedEnvelope
from ..governance import SignerPolicy
from ..keypair import KeyPair
from ..protocol import LTPProtocol
from .message import BridgeCommitment, RelayPacket

logger = logging.getLogger(__name__)

__all__ = ["Relayer"]


class Relayer:
    """
    Cross-chain relayer: seals a LatticeKey and packages it for transport.

    The relayer is intentionally minimal and untrusted.  It:
      1. Receives a BridgeCommitment + CEK from the L1Anchor
      2. Optionally verifies relay authorization via SignerPolicy
      3. Calls LTPProtocol.lattice() to seal the key to the L2 verifier
      4. Wraps in SignedEnvelope for authenticated transport
      5. Returns a RelayPacket containing the sealed key + routing metadata

    The sealed key is ~1.3KB — orders of magnitude smaller than the original
    bridge message + shards.  This is the ONLY data that crosses chains.
    """

    def __init__(
        self,
        protocol: LTPProtocol,
        policy: Optional[SignerPolicy] = None,
        relay_keypair: Optional[KeyPair] = None,
    ) -> None:
        self.protocol = protocol
        self.policy = policy
        self.relay_keypair = relay_keypair

    def relay(
        self,
        commitment: BridgeCommitment,
        cek: bytes,
        l2_verifier_keypair: KeyPair,
    ) -> RelayPacket:
        """
        Seal the bridge commitment into a RelayPacket for L2.

        Args:
            commitment: The L1-side BridgeCommitment (public metadata)
            cek: The Content Encryption Key (secret, from L1Anchor)
            l2_verifier_keypair: The L2 verifier's keypair (only ek used)

        Returns:
            RelayPacket — the minimal cross-chain blob (~1.3KB sealed key
            + routing metadata).

        Raises:
            PermissionError: If policy is set and relay operator is unauthorized.
        """
        # Check relay authorization via SignerPolicy if configured
        if self.policy is not None and self.relay_keypair is not None:
            epoch = int(time.time())
            if not self.policy.is_signer_authorized(self.relay_keypair.vk, "RELAY", epoch):
                raise PermissionError(
                    f"Relay operator '{self.relay_keypair.label}' is not authorized "
                    f"for RELAY action at epoch {epoch}"
                )

        # Fetch the commitment record from the log
        record = self.protocol.network.log.fetch(commitment.entity_id)
        if record is None:
            raise ValueError(
                f"Commitment record not found for entity_id={commitment.entity_id[:16]}..."
            )

        logger.info(
            "[Relayer] Sealing key for %s→%s, entity_id=%s...",
            commitment.message.source_chain,
            commitment.message.dest_chain,
            commitment.entity_id[:16],
        )

        # LATTICE phase — seal to L2 verifier's public key
        sealed_key = self.protocol.lattice(
            entity_id=commitment.entity_id,
            record=record,
            cek=cek,
            receiver_keypair=l2_verifier_keypair,
        )

        # Wrap in SignedEnvelope if we have relay credentials
        relay_envelope = None
        if self.relay_keypair is not None:
            relay_envelope = SignedEnvelope.create(
                domain=DOMAIN_BRIDGE_MSG,
                signer_vk=self.relay_keypair.vk,
                signer_sk=self.relay_keypair,
                signer_id=self.relay_keypair.label,
                payload_type="bridge-relay",
                payload=sealed_key,
            )
            logger.info(
                "[Relayer] Signed relay envelope: %s",
                relay_envelope.fingerprint()[:16],
            )

        packet = RelayPacket(
            sealed_key=sealed_key,
            source_chain=commitment.message.source_chain,
            dest_chain=commitment.message.dest_chain,
            nonce=commitment.message.nonce,
            source_block=commitment.source_block,
            entity_id=commitment.entity_id,
            relay_envelope=relay_envelope,
        )

        logger.info(
            "[Relayer] RelayPacket ready: %d bytes sealed key, block=%d, nonce=%d",
            len(sealed_key),
            commitment.source_block,
            commitment.message.nonce,
        )

        return packet
