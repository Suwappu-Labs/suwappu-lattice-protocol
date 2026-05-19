"""
Verification result type for the Lattice Transfer Protocol.

Structured result that captures success/failure, reason, and metadata
about what was verified. Designed to be serializable for audit logging.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["VerificationResult"]


@dataclass
class VerificationResult:
    """Result of a verification operation.

    Fields:
        valid:    True if verification passed
        reason:   Human-readable explanation (especially for failures)
        artifact: Type of artifact verified ("envelope", "receipt", "merkle-proof", etc.)
        details:  Additional metadata (e.g. signer_kid, policy_hash)
    """

    valid: bool
    reason: str
    artifact: str = ""
    details: dict = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.valid
