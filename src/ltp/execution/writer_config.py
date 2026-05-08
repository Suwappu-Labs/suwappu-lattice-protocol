"""Registry configuration — tunable parameters for writer enrollment (Spec C2 §4.5)."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["RegistryConfig", "ProbationModifiers"]


@dataclass(frozen=True)
class ProbationModifiers:
    """Constraints applied to writers in PROBATION state (Spec C2 §6.4)."""
    rate_limit_divisor: int = 2            # Halve the VM's rate limit
    fee_multiplier_factor: float = 2.0     # Double the fee multiplier
    blocked_operations: frozenset[str] = frozenset({"deploy"})  # Deny these ops


@dataclass(frozen=True)
class RegistryConfig:
    """Global configuration for the WriterRegistry."""
    sponsor_threshold: int = 2
    probation_epochs: int = 10
    default_expiry_epochs: int = 0         # 0 = no expiry
    probation_modifiers: ProbationModifiers = field(default_factory=ProbationModifiers)
