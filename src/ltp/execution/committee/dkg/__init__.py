"""Threshold Distributed Key Generation and Signing (Specs C3b, C3c)."""

from .types import (
    DKGState,
    DKGPhase,
    DKGCommitment,
    DKGShare,
    DKGComplaint,
    DKGResult,
    DKGSessionConfig,
)
from .scalar_poly import ScalarField, ScalarPoly
from .transport import DKGTransport, FakeDKGTransport
from .registry import DKGKeyRegistry
from .threshold_signing import (
    ThresholdSigningKey,
    PartialSignature,
    DOMAIN_ATTESTATION,
    DOMAIN_STATE_ROOT,
    DOMAIN_CROSS_VM,
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
