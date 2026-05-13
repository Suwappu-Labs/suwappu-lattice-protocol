"""BLS certificate signing and verification (Spec D1b §3)."""

from __future__ import annotations

from dataclasses import dataclass

from .types import Certificate
from .validator_set import ValidatorSet

from ..execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    PartialSignature,
    ThresholdSigningKey,
    combine_partial_signatures,
    partial_sign,
    threshold_verify,
)

__all__ = [
    "DOMAIN_CONSENSUS_ACK",
    "BLSCertificateManager",
    "SignedCertificate",
]

DOMAIN_CONSENSUS_ACK = b"ETP-CONSENSUS-ACK:v1"


@dataclass(frozen=True)
class SignedCertificate:
    """A D1a Certificate wrapped with an aggregated BLS signature."""

    certificate: Certificate
    aggregated_signature: bytes  # 96-byte aggregated G2
    signer_keys: frozenset[bytes]  # BLS public keys of signers


class BLSCertificateManager:
    """Manages BLS partial signing, aggregation, and verification for certificates."""

    def __init__(self, group_pk: bytes | None = None) -> None:
        self._group_pk = group_pk

    def update_keys(self, group_pk: bytes) -> None:
        self._group_pk = group_pk

    @property
    def group_pk(self) -> bytes | None:
        return self._group_pk

    def sign_ack(
        self,
        signing_key: ThresholdSigningKey,
        block_digest: bytes,
    ) -> PartialSignature:
        """Produce a BLS partial signature over a block digest."""
        return partial_sign(signing_key, block_digest, DOMAIN_CONSENSUS_ACK)

    def aggregate_ack_signatures(
        self,
        partials: list[PartialSignature],
        block_digest: bytes,
        validator_set: ValidatorSet,
    ) -> bytes:
        """Combine partial ack signatures into an aggregated BLS signature."""
        return combine_partial_signatures(partials, validator_set.quorum_threshold)

    def verify_certificate_signature(
        self,
        signed_cert: SignedCertificate,
    ) -> bool:
        """Verify an aggregated certificate signature against the group key."""
        if self._group_pk is None:
            return False
        try:
            return threshold_verify(
                self._group_pk,
                signed_cert.certificate.digest,
                signed_cert.aggregated_signature,
                DOMAIN_CONSENSUS_ACK,
            )
        except Exception:
            return False

    def sign_committed_batch(
        self,
        signing_key: ThresholdSigningKey,
        batch_bytes: bytes,
        domain: bytes = DOMAIN_ATTESTATION,
    ) -> PartialSignature:
        """Produce a BLS partial signature over committed batch bytes."""
        return partial_sign(signing_key, batch_bytes, domain)

    def verify_batch_attestation(
        self,
        signature: bytes,
        batch_bytes: bytes,
        group_pk: bytes,
        domain: bytes = DOMAIN_ATTESTATION,
    ) -> bool:
        """Verify a threshold BLS attestation signature."""
        try:
            return threshold_verify(group_pk, batch_bytes, signature, domain)
        except Exception:
            return False
