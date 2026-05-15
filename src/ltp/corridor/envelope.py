"""Constant-size on-chain commitment envelope (paper §10.2).

The §10.2 invariant — every LTP attestation commits ≈1,600 B on chain
regardless of payload size — is anchored by a three-part envelope:

| Field | Size | Source |
|---|---|---|
| `sealed_session_key` | ML-KEM ciphertext (768: 1,088 B; 1024: 1,568 B) | Receiver-sealed AEAD session key |
| `aggregate_signature` | 96 B (compressed-G2 BLS12-381) | 7-of-9 corridor aggregate |
| `payload_root` | 32 B (SHA3-256 with `GSX-LTP-CID-V1` tag) | Content-addressed payload digest |

The 1,600 B figure in `gsx-dag/crates/gsx-ltp/src/lib.rs` is the pinned
constant; the breakdown in the doc comment ("ML-KEM-768 sealed session key
≈1,568 B") is mis-labeled — 1,568 B is the ML-KEM-1024 ciphertext size,
not ML-KEM-768 (which is 1,088 B). This envelope accepts either parameter
set and asserts the *total* against `ON_CHAIN_COMMITMENT_BYTES` only when
constructed in `strict` mode; in default mode the field sizes are checked
individually and the total is documented but not enforced (since paper §10.2
itself uses "≈").

Use this envelope when serializing a corridor attestation for on-chain
submission or for cross-repo transport.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import CorridorAttestation
from .constants import ON_CHAIN_COMMITMENT_BYTES
from .da import Cid
from .digest import sha3_256_domain

# ML-KEM ciphertext sizes per security level (FIPS 203).
ML_KEM_768_CT_BYTES = 1_088
ML_KEM_1024_CT_BYTES = 1_568

BLS_G2_COMPRESSED_BYTES = 96
SHA3_256_BYTES = 32


class EnvelopeSizeError(ValueError):
    """Field or envelope total deviates from the §10.2 constant."""


@dataclass(frozen=True)
class OnChainCommitment:
    """Three-part on-chain commitment envelope.

    Construct via `from_parts()` or `from_corridor_attestation_and_kem()`;
    do not instantiate directly with mismatched field sizes.
    """

    sealed_session_key: bytes
    aggregate_signature: bytes
    payload_root: bytes  # 32 bytes, MUST be a SHA3-256 digest under GSX-LTP-CID-V1

    def __post_init__(self) -> None:
        if len(self.aggregate_signature) != BLS_G2_COMPRESSED_BYTES:
            raise EnvelopeSizeError(
                f"aggregate_signature must be {BLS_G2_COMPRESSED_BYTES} bytes; "
                f"got {len(self.aggregate_signature)}"
            )
        if len(self.payload_root) != SHA3_256_BYTES:
            raise EnvelopeSizeError(
                f"payload_root must be {SHA3_256_BYTES} bytes; "
                f"got {len(self.payload_root)}"
            )
        if len(self.sealed_session_key) not in (
            ML_KEM_768_CT_BYTES,
            ML_KEM_1024_CT_BYTES,
        ):
            raise EnvelopeSizeError(
                f"sealed_session_key must be {ML_KEM_768_CT_BYTES} (ML-KEM-768) "
                f"or {ML_KEM_1024_CT_BYTES} (ML-KEM-1024) bytes; "
                f"got {len(self.sealed_session_key)}"
            )

    @property
    def total_bytes(self) -> int:
        return (
            len(self.sealed_session_key)
            + len(self.aggregate_signature)
            + len(self.payload_root)
        )

    def assert_strict_total(self) -> None:
        """Enforce the exact §10.2 constant. Only ML-KEM-1024 + 96 + 32 = 1,696
        gets close; under ML-KEM-768 the total is 1,216. Neither hits 1,600
        exactly — the constant is a paper-level approximation. Strict mode is
        provided for forward-compatibility once gsx-dag pins a precise layout.
        """
        if self.total_bytes != ON_CHAIN_COMMITMENT_BYTES:
            raise EnvelopeSizeError(
                f"envelope total is {self.total_bytes} B; "
                f"strict §10.2 requires exactly {ON_CHAIN_COMMITMENT_BYTES} B"
            )

    def serialize(self) -> bytes:
        """Concatenate fields in canonical order: `sealed_session_key || aggregate_signature || payload_root`."""
        return self.sealed_session_key + self.aggregate_signature + self.payload_root

    @classmethod
    def deserialize(cls, blob: bytes) -> "OnChainCommitment":
        """Parse a `serialize()`-d blob. Auto-detects ML-KEM-768 vs ML-KEM-1024
        by trying both layouts and picking the one whose tail starts at a valid
        BLS signature boundary.
        """
        for kem_size in (ML_KEM_768_CT_BYTES, ML_KEM_1024_CT_BYTES):
            expected = kem_size + BLS_G2_COMPRESSED_BYTES + SHA3_256_BYTES
            if len(blob) == expected:
                return cls(
                    sealed_session_key=blob[:kem_size],
                    aggregate_signature=blob[
                        kem_size : kem_size + BLS_G2_COMPRESSED_BYTES
                    ],
                    payload_root=blob[kem_size + BLS_G2_COMPRESSED_BYTES :],
                )
        raise EnvelopeSizeError(
            f"blob length {len(blob)} does not match either ML-KEM-768 "
            f"({ML_KEM_768_CT_BYTES + 128}) or ML-KEM-1024 "
            f"({ML_KEM_1024_CT_BYTES + 128}) envelope layout"
        )

    @classmethod
    def from_parts(
        cls,
        sealed_session_key: bytes,
        aggregate_signature: bytes,
        payload_root: bytes,
    ) -> "OnChainCommitment":
        return cls(
            sealed_session_key=bytes(sealed_session_key),
            aggregate_signature=bytes(aggregate_signature),
            payload_root=bytes(payload_root),
        )

    @classmethod
    def from_corridor(
        cls,
        attestation: CorridorAttestation,
        sealed_session_key: bytes,
        payload: bytes,
    ) -> "OnChainCommitment":
        """Build an envelope from a corridor attestation + receiver-sealed
        session key + raw payload. The payload root is computed under the
        `GSX-LTP-CID-V1` domain tag (`Cid.of(payload)`) so the on-chain
        commitment binds the same content identifier as the DA layer.
        """
        return cls.from_parts(
            sealed_session_key=sealed_session_key,
            aggregate_signature=attestation.aggregate_signature,
            payload_root=Cid.of(payload).value,
        )

    def payload_cid(self) -> Cid:
        """Recover the content identifier this envelope commits to."""
        return Cid(self.payload_root)

    def commitment_digest(self) -> bytes:
        """SHA3-256 of the serialized envelope under the GSX-LTP-COMMITMENT-V1
        domain tag. This is what an on-chain anchor would record as the
        constant-size commitment identifier.
        """
        return sha3_256_domain(b"GSX-LTP-COMMITMENT-V1", self.serialize())
