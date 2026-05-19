"""
CryptoLane classification and compliance strict mode.

The CryptoLane enum classifies hash operations by trust boundary:
  - CANONICAL: settlement-valid, regulator-facing artifacts
  - INTERNAL: performance-optimized internal operations
"""

from __future__ import annotations

from enum import Enum

from .hashing import HashFunction


class CryptoLane(Enum):
    """Classification of which trust boundary a hash operation serves."""

    CANONICAL = "canonical"  # Settlement-valid, regulator-facing
    INTERNAL = "internal"  # Performance-optimized, not compliance-facing


# Algorithms approved for the canonical lane under strict compliance.
COMPLIANCE_APPROVED = frozenset(
    {
        HashFunction.SHA3_256,
        HashFunction.SHA_384,
        HashFunction.SHA_512,
    }
)


# ---------------------------------------------------------------------------
# Compliance strict mode
# ---------------------------------------------------------------------------

_compliance_strict = False


def set_compliance_strict(strict: bool) -> None:
    """Enable/disable compliance strict mode.

    When enabled, canonical_hash() rejects non-FIPS-approved algorithms
    (only SHA3-256, SHA-384, SHA-512 allowed in the canonical lane).
    """
    global _compliance_strict
    _compliance_strict = strict


def get_compliance_strict() -> bool:
    """Return whether compliance strict mode is active."""
    return _compliance_strict
