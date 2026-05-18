"""
Signed message envelope for the Lattice Transfer Protocol.

Universal authenticated wrapper — any protocol message that needs
authentication gets wrapped in a SignedEnvelope.

Design patterns adopted from crypto-rs (dark-bio/crypto-rs):
  - create_at() factory with explicit timestamps for deterministic testing
    (mirrors cose::sign_at())
  - extract_signer_kid() without full verification (mirrors cose::signer())
  - peek_payload() for unauthenticated payload access during key discovery
    (mirrors cose::peek())
  - max_drift parameter for timestamp freshness validation (CWT pattern)

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.3
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from .encoding import CanonicalEncoder
from .domain import (
    DOMAIN_SIGNED_ENVELOPE,
    domain_sign,
    domain_verify,
    signer_fingerprint,
)
from .primitives import canonical_hash, canonical_hash_bytes

__all__ = ["SignedEnvelope"]


@dataclass
class SignedEnvelope:
    """Universal authenticated wrapper for protocol messages.

    Any protocol object (CommitmentRecord, STH, ApprovalReceipt) can be
    wrapped in a SignedEnvelope for authenticated transport.

    Fields:
        version:      Protocol version (uint8, currently 1)
        domain:       Domain separation tag for the inner payload
        signer_vk:    ML-DSA-65 verification key (1952 bytes)
        signer_id:    Human-readable label (maps to KeyPair.label)
        signer_kid:   32B fingerprint = SHA3-256(signer_vk)
        timestamp:    IEEE 754 double (unix time)
        payload_type: Type discriminator ("commitment-record", "sth", etc.)
        payload_hash: canonical_hash_bytes(payload)
        payload:      canonical_bytes(inner object)
        signature:    ML-DSA-65 signature over signable_content()
    """

    version: int
    domain: bytes
    signer_vk: bytes
    signer_id: str
    signer_kid: bytes
    timestamp: float
    payload_type: str
    payload_hash: bytes
    payload: bytes
    signature: bytes

    def signable_content(self) -> bytes:
        """Canonical encoding of all fields except signature.

        This is the byte string that gets signed/verified.
        """
        return (
            CanonicalEncoder(DOMAIN_SIGNED_ENVELOPE)
            .uint8(self.version)
            .length_prefixed_bytes(self.domain)
            .length_prefixed_bytes(self.signer_vk)
            .string(self.signer_id)
            .raw_bytes(self.signer_kid)
            .float64(self.timestamp)
            .string(self.payload_type)
            .raw_bytes(self.payload_hash)
            .length_prefixed_bytes(self.payload)
            .finalize()
        )

    def verify(self, max_drift: float | None = None) -> bool:
        """Verify the ML-DSA signature and optional timestamp freshness.

        Args:
            max_drift: If set, reject envelopes older than max_drift seconds
                       from the current time (COSE/CWT temporal validation).

        Returns:
            True if the signature is valid (and timestamp is fresh if max_drift set).
        """
        if max_drift is not None:
            now = time.time()
            if abs(now - self.timestamp) > max_drift:
                return False

        # Verify signer_kid matches signer_vk
        if self.signer_kid != signer_fingerprint(self.signer_vk):
            return False

        return domain_verify(
            DOMAIN_SIGNED_ENVELOPE,
            self.signer_vk,
            self.signable_content(),
            self.signature,
        )

    def fingerprint(self) -> str:
        """32-byte hash of the signed envelope for on-chain anchoring reference."""
        content = self.signable_content() + self.signature
        return canonical_hash(content)

    @classmethod
    def create(
        cls,
        domain: bytes,
        signer_vk: bytes,
        signer_sk,
        signer_id: str,
        payload_type: str,
        payload: bytes,
    ) -> "SignedEnvelope":
        """Factory: build, sign, return. Uses current time.

        `signer_sk` accepts either raw `sk` bytes (legacy) or a
        `KeyPair` (LTP-A-032 Phase 4d). The downstream `domain_sign`
        handles both transparently.
        """
        return cls.create_at(
            domain=domain,
            signer_vk=signer_vk,
            signer_sk=signer_sk,
            signer_id=signer_id,
            payload_type=payload_type,
            payload=payload,
            timestamp=time.time(),
        )

    @classmethod
    def create_at(
        cls,
        domain: bytes,
        signer_vk: bytes,
        signer_sk,
        signer_id: str,
        payload_type: str,
        payload: bytes,
        timestamp: float,
    ) -> "SignedEnvelope":
        """Factory with explicit timestamp — for deterministic testing.

        Mirrors the cose::sign_at() pattern from crypto-rs.
        """
        kid = signer_fingerprint(signer_vk)
        payload_hash = canonical_hash_bytes(payload)

        env = cls(
            version=1,
            domain=domain,
            signer_vk=signer_vk,
            signer_id=signer_id,
            signer_kid=kid,
            timestamp=timestamp,
            payload_type=payload_type,
            payload_hash=payload_hash,
            payload=payload,
            signature=b"",  # placeholder
        )

        env.signature = domain_sign(
            DOMAIN_SIGNED_ENVELOPE,
            signer_sk,
            env.signable_content(),
        )
        return env

    @classmethod
    def peek_payload(cls, envelope: "SignedEnvelope") -> tuple[str, bytes]:
        """Extract (payload_type, payload) without verifying signature.

        WARNING: Unauthenticated. Use for key discovery / routing only.
        Mirrors the cose::peek() pattern from crypto-rs.
        """
        return (envelope.payload_type, envelope.payload)

    @classmethod
    def extract_signer_kid(cls, envelope: "SignedEnvelope") -> bytes:
        """Extract signer fingerprint without full verification.

        Mirrors the cose::signer() pattern from crypto-rs.
        """
        return envelope.signer_kid
