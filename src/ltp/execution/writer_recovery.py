"""
Emergency recovery primitives for the writer layer (Spec C2 §8).

Provides:
  - EmergencyAction   — 12-value enum of recovery operations
  - EmergencyIntervention — immutable audit record for each action taken
  - EmergencyState    — mutable state machine tracking active interventions
  - PolicySnapshotStore — append-only, per-VM policy version history
  - RecoveryQuorum    — threshold-gated approval for sensitive operations
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .writer_policy import VMWriterPolicy

__all__ = [
    "EmergencyAction",
    "EmergencyIntervention",
    "EmergencyState",
    "PolicySnapshotStore",
    "RecoveryQuorum",
]


# ---------------------------------------------------------------------------
# EmergencyAction
# ---------------------------------------------------------------------------


class EmergencyAction(Enum):
    """Recovery actions available to privileged operators."""

    FREEZE_REGISTRY = "freeze_registry"
    UNFREEZE_REGISTRY = "unfreeze_registry"
    FREEZE_VM = "freeze_vm"
    UNFREEZE_VM = "unfreeze_vm"
    BYPASS_AUTHORIZER = "bypass_authorizer"
    CLEAR_BYPASS = "clear_bypass"
    FORCE_REVOKE = "force_revoke"
    ROLLBACK_POLICY = "rollback_policy"
    ROTATE_OWNER = "rotate_owner"
    OVERRIDE_DISPATCH = "override_dispatch"
    CLEAR_OVERRIDE = "clear_override"
    FORCE_EPOCH_ADVANCE = "force_epoch_advance"


# ---------------------------------------------------------------------------
# EmergencyIntervention
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmergencyIntervention:
    """Immutable audit record for a single emergency action."""

    action: EmergencyAction
    actor_fp: bytes
    reason: str
    timestamp: int
    scope: Optional[int] = None  # vm_tag for VM-scoped actions
    auto_expires: Optional[int] = None  # epoch/timestamp when effect expires


# ---------------------------------------------------------------------------
# EmergencyState
# ---------------------------------------------------------------------------


class EmergencyState:
    """Tracks active emergency interventions and exposes guard predicates.

    All mutating methods append an EmergencyIntervention to the
    ``interventions`` audit trail.
    """

    def __init__(self) -> None:
        self._registry_frozen: bool = False
        self._frozen_vms: set[int] = set()
        self._bypassed_authorizers: set[int] = set()
        self._dispatch_overrides: dict[bytes, bool] = {}  # writer_fp → allow/block
        self.interventions: list[EmergencyIntervention] = []

    # ------------------------------------------------------------------
    # Guard predicates
    # ------------------------------------------------------------------

    @property
    def is_registry_frozen(self) -> bool:
        return self._registry_frozen

    def is_vm_frozen(self, vm_tag: int) -> bool:
        return vm_tag in self._frozen_vms

    def is_authorizer_bypassed(self, vm_tag: int) -> bool:
        return vm_tag in self._bypassed_authorizers

    def get_dispatch_override(self, writer_fp: bytes) -> Optional[bool]:
        """Return True (force-allow), False (force-block), or None (no override)."""
        return self._dispatch_overrides.get(writer_fp)

    # ------------------------------------------------------------------
    # Registry freeze / unfreeze
    # ------------------------------------------------------------------

    def freeze_registry(
        self,
        actor_fp: bytes,
        reason: str,
        timestamp: int,
    ) -> None:
        self._registry_frozen = True
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.FREEZE_REGISTRY,
                actor_fp=actor_fp,
                reason=reason,
                timestamp=timestamp,
            )
        )

    def unfreeze_registry(
        self,
        actor_fp: bytes,
        timestamp: int,
    ) -> None:
        self._registry_frozen = False
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.UNFREEZE_REGISTRY,
                actor_fp=actor_fp,
                reason="registry unfrozen",
                timestamp=timestamp,
            )
        )

    # ------------------------------------------------------------------
    # VM freeze / unfreeze
    # ------------------------------------------------------------------

    def freeze_vm(
        self,
        vm_tag: int,
        actor_fp: bytes,
        reason: str,
        timestamp: int,
    ) -> None:
        self._frozen_vms.add(vm_tag)
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.FREEZE_VM,
                actor_fp=actor_fp,
                reason=reason,
                timestamp=timestamp,
                scope=vm_tag,
            )
        )

    def unfreeze_vm(
        self,
        vm_tag: int,
        actor_fp: bytes,
        timestamp: int,
    ) -> None:
        self._frozen_vms.discard(vm_tag)
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.UNFREEZE_VM,
                actor_fp=actor_fp,
                reason="VM unfrozen",
                timestamp=timestamp,
                scope=vm_tag,
            )
        )

    # ------------------------------------------------------------------
    # Authorizer bypass / clear
    # ------------------------------------------------------------------

    def bypass_authorizer(
        self,
        vm_tag: int,
        actor_fp: bytes,
        reason: str,
        timestamp: int,
    ) -> None:
        self._bypassed_authorizers.add(vm_tag)
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.BYPASS_AUTHORIZER,
                actor_fp=actor_fp,
                reason=reason,
                timestamp=timestamp,
                scope=vm_tag,
            )
        )

    def clear_bypass(
        self,
        vm_tag: int,
        actor_fp: bytes,
        timestamp: int,
    ) -> None:
        self._bypassed_authorizers.discard(vm_tag)
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.CLEAR_BYPASS,
                actor_fp=actor_fp,
                reason="authorizer bypass cleared",
                timestamp=timestamp,
                scope=vm_tag,
            )
        )

    # ------------------------------------------------------------------
    # Force revoke (bypasses normal role checks)
    # ------------------------------------------------------------------

    def force_revoke(
        self,
        writer_fp: bytes,
        actor_fp: bytes,
        reason: str,
        timestamp: int,
        registry: object,
    ) -> None:
        """Force-revoke a writer, bypassing normal RBAC checks.

        Args:
            writer_fp: Fingerprint of the writer to revoke.
            actor_fp:  Fingerprint of the emergency operator.
            reason:    Human-readable justification.
            timestamp: Time of the action in milliseconds.
            registry:  A WriterRegistry instance (typed as object to avoid circular import).
        """
        # Import here to avoid circular dependency at module level
        from .writer_registry import WriterRegistry as _WR

        assert isinstance(registry, _WR)
        registry.revoke(
            writer_fp, reason=f"EMERGENCY: {reason}", actor_fp=actor_fp, timestamp=timestamp
        )
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.FORCE_REVOKE,
                actor_fp=actor_fp,
                reason=reason,
                timestamp=timestamp,
            )
        )

    # ------------------------------------------------------------------
    # Dispatch override (per-writer force-allow or force-block)
    # ------------------------------------------------------------------

    def set_dispatch_override(
        self,
        writer_fp: bytes,
        allow: bool,
        actor_fp: bytes,
        reason: str,
        timestamp: int,
    ) -> None:
        """Set a one-shot dispatch override for a specific writer."""
        self._dispatch_overrides[writer_fp] = allow
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.OVERRIDE_DISPATCH,
                actor_fp=actor_fp,
                reason=reason,
                timestamp=timestamp,
            )
        )

    def clear_dispatch_override(
        self,
        writer_fp: bytes,
        actor_fp: bytes,
        timestamp: int,
    ) -> None:
        """Remove a dispatch override for a specific writer."""
        self._dispatch_overrides.pop(writer_fp, None)
        self.interventions.append(
            EmergencyIntervention(
                action=EmergencyAction.CLEAR_OVERRIDE,
                actor_fp=actor_fp,
                reason="dispatch override cleared",
                timestamp=timestamp,
            )
        )


# ---------------------------------------------------------------------------
# PolicySnapshotStore
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PolicySnapshot:
    """Internal append-only record for a single policy version."""

    version: int
    policy: VMWriterPolicy
    timestamp: int


class PolicySnapshotStore:
    """Append-only, per-VM policy version history.

    Version numbers start at 0 and increment by 1 on each ``snapshot``
    call for a given vm_tag.
    """

    def __init__(self) -> None:
        # vm_tag -> list of _PolicySnapshot (ordered by version)
        self._history: dict[int, list[_PolicySnapshot]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def snapshot(
        self,
        vm_tag: int,
        policy: VMWriterPolicy,
        timestamp: int,
    ) -> int:
        """Deep-copy *policy* and store it as the next version.

        Returns:
            The new version number (0-based).
        """
        snaps = self._history.setdefault(vm_tag, [])
        version = len(snaps)
        snaps.append(
            _PolicySnapshot(
                version=version,
                policy=copy.deepcopy(policy),
                timestamp=timestamp,
            )
        )
        return version

    def rollback(self, vm_tag: int, version: int) -> VMWriterPolicy:
        """Return a deep copy of the policy at *version* for *vm_tag*.

        Raises:
            KeyError: if *vm_tag* has no history or *version* is out of range.
        """
        snaps = self._history.get(vm_tag)
        if snaps is None or version >= len(snaps) or version < 0:
            raise KeyError(f"no snapshot at version {version} for vm_tag {vm_tag}")
        return copy.deepcopy(snaps[version].policy)

    def version_count(self, vm_tag: int) -> int:
        """Return the number of snapshots stored for *vm_tag*."""
        return len(self._history.get(vm_tag, []))


# ---------------------------------------------------------------------------
# RecoveryQuorum
# ---------------------------------------------------------------------------


class RecoveryQuorum:
    """Threshold-gated approval mechanism for sensitive recovery operations.

    Args:
        recovery_keys: Exhaustive list of authorised key fingerprints.
        threshold:     Minimum number of distinct votes required.
    """

    def __init__(self, recovery_keys: list[bytes], threshold: int) -> None:
        self._recovery_keys: frozenset[bytes] = frozenset(recovery_keys)
        self._threshold: int = threshold
        self._votes: set[bytes] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_vote(self, key_fp: bytes) -> None:
        """Record a vote from *key_fp*.

        Raises:
            ValueError: if *key_fp* is not a recognised recovery key.
        """
        if key_fp not in self._recovery_keys:
            raise ValueError(f"key fingerprint {key_fp!r} is not a registered recovery key")
        self._votes.add(key_fp)

    def is_met(self) -> bool:
        """Return True when the required threshold of votes has been reached."""
        return len(self._votes) >= self._threshold

    def reset(self) -> None:
        """Clear all accumulated votes."""
        self._votes.clear()
