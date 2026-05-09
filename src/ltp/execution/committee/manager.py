"""CommitteeManager — top-level coordinator (Spec C3a §9)."""

from __future__ import annotations

from typing import Optional

from .types import CommitteeRoster, EpochRecord
from .policy import CommitteePolicy
from .formation import CommitteeFormation
from .epoch import EpochManager
from .eviction import EvictionHandler
from .standby import StandbySelector
from ..writer import WriterRecord, WriterState
from ..writer_recovery import EmergencyState
from ..writer_registry import WriterRegistry

__all__ = ["CommitteeManager"]


class CommitteeManager:
    """Top-level coordinator — one per VM."""

    def __init__(
        self,
        vm_tag: int,
        policy: CommitteePolicy,
        registry: WriterRegistry,
        emergency: EmergencyState,
    ) -> None:
        self._vm_tag = vm_tag
        self._policy = policy
        self._registry = registry
        self._formation = CommitteeFormation(registry)
        self._standby = StandbySelector(policy)
        self._eviction = EvictionHandler(policy, self._standby)
        self._epoch_mgr = EpochManager(vm_tag, policy, self._formation, emergency)

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None:
        """Hook called by WriterRegistry transitions."""
        roster = self._epoch_mgr.roster
        if roster is None:
            return
        self._eviction.handle_state_change(
            roster, writer.identity.fingerprint, old_state, new_state,
            timestamp=0,
        )

    def tick(self, current_round: int, timestamp_ms: int) -> bool:
        """Called every round. Returns True if epoch advanced."""
        return self._epoch_mgr.check_advance(current_round, timestamp_ms)

    @property
    def roster(self) -> Optional[CommitteeRoster]:
        return self._epoch_mgr.roster

    @property
    def epoch(self) -> int:
        return self._epoch_mgr.current_epoch

    @property
    def is_halted(self) -> bool:
        return self._eviction.is_halted

    def is_member(self, writer_fp: bytes) -> bool:
        roster = self._epoch_mgr.roster
        if roster is None:
            return False
        return any(m.writer_fp == writer_fp for m in roster.active_members)

    def history(self) -> list[EpochRecord]:
        return self._epoch_mgr.history
