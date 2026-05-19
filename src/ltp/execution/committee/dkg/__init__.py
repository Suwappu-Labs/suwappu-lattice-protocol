"""Threshold Distributed Key Generation and Signing (Specs C3b, C3c)."""

from .registry import DKGKeyRegistry
from .scalar_poly import ScalarField, ScalarPoly
from .threshold_signing import (
    DOMAIN_ATTESTATION,
    DOMAIN_CROSS_VM,
    DOMAIN_STATE_ROOT,
    PartialSignature,
    ThresholdSigningKey,
)
from .transport import DKGTransport, FakeDKGTransport
from .types import (
    DKGCommitment,
    DKGComplaint,
    DKGPhase,
    DKGResult,
    DKGSessionConfig,
    DKGShare,
    DKGState,
)

__all__ = [
    "DKGState",
    "DKGPhase",
    "DKGCommitment",
    "DKGShare",
    "DKGComplaint",
    "DKGResult",
    "DKGSessionConfig",
    "ScalarField",
    "ScalarPoly",
    "DKGTransport",
    "FakeDKGTransport",
    "DKGKeyRegistry",
    # Threshold Signing (Spec C3c)
    "ThresholdSigningKey",
    "PartialSignature",
    "DOMAIN_ATTESTATION",
    "DOMAIN_STATE_ROOT",
    "DOMAIN_CROSS_VM",
]
