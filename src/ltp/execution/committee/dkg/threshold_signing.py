"""Threshold BLS signing protocol (Spec C3c).

Provides partial signing, combination via Lagrange interpolation in G2,
and verification via the existing BLS class. Combined threshold signatures
are mathematically identical to standard BLS signatures.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from src.ltp.bls import BLS
from src.ltp.zk.ec_backend import (
    g1_compress,
    g1_deserialize,
    g2_add,
    g2_compress,
    g2_identity,
    g2_scalar_mul,
)

from .scalar_poly import ScalarField, ScalarPoly

__all__ = [
    "ThresholdSigningKey",
    "PartialSignature",
    "partial_sign",
    "combine_partial_signatures",
    "threshold_verify",
    "DOMAIN_ATTESTATION",
    "DOMAIN_STATE_ROOT",
    "DOMAIN_CROSS_VM",
]

# ---------------------------------------------------------------------------
# Domain separation constants
# ---------------------------------------------------------------------------

DOMAIN_ATTESTATION = b"ETP-THRESHOLD-ATTESTATION:v1"
DOMAIN_STATE_ROOT = b"ETP-THRESHOLD-STATE-ROOT:v1"
DOMAIN_CROSS_VM = b"ETP-THRESHOLD-CROSS-VM:v1"

# Standard BLS DST — must match py_ecc G2ProofOfPossession
_BLS_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThresholdSigningKey:
    """Private material each participant holds after DKG."""

    participant_fp: bytes
    participant_index: int
    secret_share: int
    group_pk: bytes  # 96-byte uncompressed G1 from DKG
    threshold: int
    epoch: int
    vm_tag: int


@dataclass(frozen=True)
class PartialSignature:
    """A single participant's partial BLS signature."""

    signer_fp: bytes
    signer_index: int
    signature: bytes  # 96-byte compressed G2
    epoch: int


# ---------------------------------------------------------------------------
# Signing protocol
# ---------------------------------------------------------------------------


def partial_sign(
    key: ThresholdSigningKey,
    message: bytes,
    domain: bytes,
) -> PartialSignature:
    """Create a partial BLS signature using a threshold signing key.

    Uses hash_to_G2 with the standard BLS DST so the combined
    signature is verifiable by standard BLS.verify().
    """
    from py_ecc.bls.hash_to_curve import hash_to_G2  # type: ignore[import-untyped]

    tagged = domain + message
    h_point = hash_to_G2(tagged, _BLS_DST, hashlib.sha256)
    sig_point = g2_scalar_mul(h_point, key.secret_share)

    return PartialSignature(
        signer_fp=key.participant_fp,
        signer_index=key.participant_index,
        signature=g2_compress(sig_point),
        epoch=key.epoch,
    )


def combine_partial_signatures(
    partials: list[PartialSignature],
    threshold: int,
) -> bytes:
    """Combine t-of-n partial signatures into a standard BLS signature.

    Uses Lagrange interpolation in G2. The result is byte-identical
    to what a standard BLS.Sign(group_secret, message) would produce.
    """
    if len(partials) < threshold:
        raise ValueError(f"Need at least {threshold} partials, got {len(partials)}")

    from py_ecc.bls.g2_primitives import signature_to_G2  # type: ignore[import-untyped]

    indices = [p.signer_index for p in partials]
    combined = g2_identity()

    for partial in partials:
        li = ScalarPoly.lagrange_coefficient(partial.signer_index, indices)
        sig_point = signature_to_G2(partial.signature)
        weighted = g2_scalar_mul(sig_point, li)
        combined = g2_add(combined, weighted)

    return g2_compress(combined)


def threshold_verify(
    group_pk: bytes,
    message: bytes,
    signature: bytes,
    domain: bytes,
) -> bool:
    """Verify a threshold BLS signature against a group public key.

    Converts the DKG's uncompressed G1 group_pk to compressed format
    and delegates to BLS.verify().
    """
    tagged = domain + message
    group_pk_point = g1_deserialize(group_pk)
    compressed_pk = g1_compress(group_pk_point)
    return BLS.verify(compressed_pk, tagged, signature)
