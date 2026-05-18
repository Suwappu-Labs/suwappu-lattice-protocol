"""AttestationWriter — creates LTP attestation records for bridge events."""

from __future__ import annotations

from dataclasses import dataclass

from ..domain import (
    DOMAIN_GATEWAY_ATTEST,
    domain_hash_bytes,
    domain_sign,
    domain_verify,
    signer_fingerprint,
)
from ..keypair import KeyPair
from .events import BridgeEvent


@dataclass(frozen=True)
class GatewayAttestation:
    """A signed attestation that a bridge event was observed and validated.

    The gateway operator signs: DOMAIN_GATEWAY_ATTEST || event.to_signable_bytes()
    The digest is: H(DOMAIN_GATEWAY_ATTEST, event.to_signable_bytes())
    """

    event_id: str
    source_chain_id: int
    dest_chain_id: int
    digest: bytes
    signer_vk_fingerprint: bytes
    signature: bytes
    event_bytes: bytes

    def verify(self, vk: bytes) -> bool:
        """Verify the attestation signature against a verification key."""
        return domain_verify(DOMAIN_GATEWAY_ATTEST, vk, self.event_bytes, self.signature)


class AttestationWriter:
    """Creates ML-DSA-65 signed attestation records for validated bridge events.

    Each attestation binds: the event data, the gateway operator's identity,
    and the destination chain — signed under the DOMAIN_GATEWAY_ATTEST domain.
    """

    def __init__(
        self,
        operator_keypair: KeyPair,
        dest_chain_id: int,
    ) -> None:
        if operator_keypair is None:
            raise TypeError("operator_keypair is required — attestations must be signed")
        self._keypair = operator_keypair
        self._dest_chain_id = dest_chain_id
        self._vk_fingerprint = signer_fingerprint(operator_keypair.vk)

    def create_attestation(self, event: BridgeEvent) -> GatewayAttestation:
        """Create a signed attestation for a validated bridge event."""
        event_bytes = event.to_signable_bytes()
        digest = domain_hash_bytes(DOMAIN_GATEWAY_ATTEST, event_bytes)
        signature = domain_sign(DOMAIN_GATEWAY_ATTEST, self._keypair, event_bytes)

        return GatewayAttestation(
            event_id=event.event_id,
            source_chain_id=event.source_chain_id,
            dest_chain_id=self._dest_chain_id,
            digest=digest,
            signer_vk_fingerprint=self._vk_fingerprint,
            signature=signature,
            event_bytes=event_bytes,
        )
