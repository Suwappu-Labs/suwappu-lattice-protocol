"""
Per-VM writer policy engine (Spec C2 §6).

Provides a declarative 8-knob policy system (VMWriterPolicy) and a
stateless evaluator (PolicyEngine) that decides whether a writer may
perform an operation on a specific VM.

Evaluation order (short-circuit on first rejection):
  1. Tier not in allowed_tiers
  2. Fingerprint in denylist
  3. Allowlist set and fingerprint not in it
  4. PROBATION state + operation in blocked_operations
  5. Operation not in tier_operations[tier]
  6. Rate limit (halved for PROBATION)
  7. Insufficient stake
  8. Writer cap reached
  Pass → compute fee multiplier (x probation factor if PROBATION)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .types import OperationType
from .writer import IdentityTier, WriterRecord, WriterState
from .writer_config import ProbationModifiers, RegistryConfig

__all__ = [
    "VMWriterPolicy",
    "PolicyResult",
    "PolicyEngine",
]

# ---------------------------------------------------------------------------
# Default-factory helpers (module-level so dataclass field() can reference them)
# ---------------------------------------------------------------------------


def _default_allowed_tiers() -> set[IdentityTier]:
    return {IdentityTier.MLDSA, IdentityTier.BLS, IdentityTier.COMPOSITE}


def _default_tier_operations() -> dict[IdentityTier, set[OperationType]]:
    all_ops: set[OperationType] = set(OperationType)
    bls_ops: set[OperationType] = {OperationType.TRANSFER, OperationType.STATE_READ}
    return {
        IdentityTier.MLDSA: set(all_ops),
        IdentityTier.BLS: set(bls_ops),
        IdentityTier.COMPOSITE: set(all_ops),
    }


def _default_max_txs_per_epoch() -> dict[IdentityTier, int]:
    # 0 = unlimited
    return {
        IdentityTier.MLDSA: 0,
        IdentityTier.BLS: 1000,
        IdentityTier.COMPOSITE: 0,
    }


def _default_min_stake() -> dict[IdentityTier, int]:
    return {
        IdentityTier.MLDSA: 0,
        IdentityTier.BLS: 0,
        IdentityTier.COMPOSITE: 0,
    }


def _default_fee_multiplier() -> dict[IdentityTier, float]:
    return {
        IdentityTier.MLDSA: 1.0,
        IdentityTier.BLS: 1.0,
        IdentityTier.COMPOSITE: 1.0,
    }


# ---------------------------------------------------------------------------
# VMWriterPolicy
# ---------------------------------------------------------------------------


@dataclass
class VMWriterPolicy:
    """Declarative 8-knob per-VM policy governing writer access.

    NOT frozen — policies may be updated at runtime by governance.

    Knobs:
      1. allowed_tiers            — which identity tiers may write
      2. tier_operations          — per-tier allowed operation set
      3. max_txs_per_epoch        — per-tier rate limit (0 = unlimited)
      4. min_stake                — per-tier minimum stake requirement
      5. max_writers              — total writer cap (0 = unlimited)
      6. fee_multiplier           — per-tier base fee multiplier
      7. allowlist / denylist     — explicit allow/deny by fingerprint
      8. default_access_epochs    — default access duration (0 = perpetual)
    """

    vm_tag: int

    allowed_tiers: set[IdentityTier] = field(default_factory=_default_allowed_tiers)
    tier_operations: dict[IdentityTier, set[OperationType]] = field(
        default_factory=_default_tier_operations
    )
    max_txs_per_epoch: dict[IdentityTier, int] = field(default_factory=_default_max_txs_per_epoch)
    min_stake: dict[IdentityTier, int] = field(default_factory=_default_min_stake)
    max_writers: int = 0  # 0 = unlimited

    fee_multiplier: dict[IdentityTier, float] = field(default_factory=_default_fee_multiplier)

    allowlist: Optional[set[bytes]] = None  # None = open (no allowlist)
    denylist: set[bytes] = field(default_factory=set)

    default_access_epochs: int = 0  # 0 = perpetual


# ---------------------------------------------------------------------------
# PolicyResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of a single policy evaluation."""

    allowed: bool
    reason: Optional[str] = None
    fee_multiplier: float = 1.0

    # Convenience constructors

    @classmethod
    def deny(cls, reason: str) -> PolicyResult:
        return cls(allowed=False, reason=reason)

    @classmethod
    def permit(cls, fee_multiplier: float = 1.0) -> PolicyResult:
        return cls(allowed=True, fee_multiplier=fee_multiplier)


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Stateless evaluator for VMWriterPolicy.

    The engine itself carries no mutable state; ``config`` is read-only
    and used only to retrieve ``ProbationModifiers``.
    """

    def __init__(self, config: Optional[RegistryConfig] = None) -> None:
        self._config = config or RegistryConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        record: WriterRecord,
        operation: OperationType,
        policy: VMWriterPolicy,
        tx_count: int = 0,
        writer_count: int = 0,
        stake: int = 0,
    ) -> PolicyResult:
        """Evaluate whether *record* may perform *operation* under *policy*.

        Args:
            record:       The writer's current state record.
            operation:    The operation being attempted.
            policy:       The VMWriterPolicy for the target VM.
            tx_count:     How many transactions this writer has already
                          submitted in the current epoch.
            writer_count: Current number of writers registered on the VM
                          (used for max_writers check).
            stake:        The writer's current stake (wei or policy units).

        Returns:
            PolicyResult with allowed=True/False, optional reason, and
            the effective fee_multiplier.
        """
        tier = record.identity.tier
        fp = record.identity.fingerprint
        is_probation = record.state is WriterState.PROBATION
        mods: ProbationModifiers = self._config.probation_modifiers

        # ------------------------------------------------------------------
        # 1. Tier check
        # ------------------------------------------------------------------
        if tier not in policy.allowed_tiers:
            return PolicyResult.deny(f"tier {tier.value} not allowed")

        # ------------------------------------------------------------------
        # 2. Denylist
        # ------------------------------------------------------------------
        if fp in policy.denylist:
            return PolicyResult.deny("writer on denylist")

        # ------------------------------------------------------------------
        # 3. Allowlist
        # ------------------------------------------------------------------
        if policy.allowlist is not None and fp not in policy.allowlist:
            return PolicyResult.deny("writer not on allowlist")

        # ------------------------------------------------------------------
        # 4. Probation: blocked operations
        # ------------------------------------------------------------------
        if is_probation and operation.value in mods.blocked_operations:
            return PolicyResult.deny(f"operation {operation.value} blocked during probation")

        # ------------------------------------------------------------------
        # 5. Tier-operation permission
        # ------------------------------------------------------------------
        allowed_ops = policy.tier_operations.get(tier, set())
        if operation not in allowed_ops:
            return PolicyResult.deny(
                f"operation {operation.value} not permitted for tier {tier.value}"
            )

        # ------------------------------------------------------------------
        # 6. Rate limit
        # ------------------------------------------------------------------
        limit = policy.max_txs_per_epoch.get(tier, 0)
        if is_probation and limit > 0:
            divisor = mods.rate_limit_divisor
            limit = max(1, limit // divisor)
        if limit > 0 and tx_count >= limit:
            return PolicyResult.deny("rate limit exceeded")

        # ------------------------------------------------------------------
        # 7. Minimum stake
        # ------------------------------------------------------------------
        required_stake = policy.min_stake.get(tier, 0)
        if stake < required_stake:
            return PolicyResult.deny("insufficient stake")

        # ------------------------------------------------------------------
        # 8. Writer cap
        # ------------------------------------------------------------------
        if policy.max_writers > 0 and writer_count >= policy.max_writers:
            return PolicyResult.deny("writer cap reached")

        # ------------------------------------------------------------------
        # Pass — compute effective fee multiplier
        # ------------------------------------------------------------------
        base_fm = policy.fee_multiplier.get(tier, 1.0)
        effective_fm = base_fm
        if is_probation:
            effective_fm = base_fm * mods.fee_multiplier_factor

        return PolicyResult.permit(fee_multiplier=effective_fm)
