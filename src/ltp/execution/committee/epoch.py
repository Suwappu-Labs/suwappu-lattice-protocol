"""Epoch lifecycle manager (Spec C3a §6)."""

from __future__ import annotations

from typing import Optional

from ..writer_recovery import EmergencyState
from .formation import CommitteeFormation
from .policy import CommitteePolicy, EpochStrategy
from .types import CommitteeRoster, EpochRecord, EpochTrigger

__all__ = ["EpochManager"]


class EpochManager:
    """Per-VM epoch lifecycle. Drives epoch transitions based on configured strategy."""

    def __init__(
        self,
        vm_tag: int,
        policy: CommitteePolicy,
        formation: CommitteeFormation,
        emergency: EmergencyState,
    ) -> None:
        self._vm_tag = vm_tag
        self._policy = policy
        self._formation = formation
        self._emergency = emergency
        self._current_epoch: int = 0
        self._epoch_start_round: int = 0
        self._epoch_start_ts: int = 0
        self._roster: Optional[CommitteeRoster] = None
        self._history: list[EpochRecord] = []

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    @property
    def roster(self) -> Optional[CommitteeRoster]:
        return self._roster

    @property
    def history(self) -> list[EpochRecord]:
        return list(self._history)

    def check_advance(self, current_round: int, timestamp_ms: int) -> bool:
        """Called every round. Returns True if epoch advanced."""
        strategy = self._policy.epoch_strategy

        if strategy is EpochStrategy.MANUAL:
            return False

        if strategy is EpochStrategy.ROUND_COUNT:
            if current_round - self._epoch_start_round < self._policy.epoch_length:
                return False

        elif strategy is EpochStrategy.TIME_BASED:
            if self._epoch_start_ts == 0 and self._current_epoch == 0:
                self._advance(current_round, timestamp_ms, EpochTrigger.ROUND_COUNT)
                return False
            if timestamp_ms - self._epoch_start_ts < self._policy.epoch_duration_ms:
                return False

        trigger = (
            EpochTrigger.TIME_BASED
            if strategy is EpochStrategy.TIME_BASED
            else EpochTrigger.ROUND_COUNT
        )
        self._advance(current_round, timestamp_ms, trigger)
        return True

    def admin_advance(self, actor_fp: bytes, timestamp: int) -> CommitteeRoster:
        """Governance-forced epoch advance."""
        self._advance(0, timestamp, EpochTrigger.ADMIN_SIGNAL)
        return self._roster

    def emergency_advance(self, actor_fp: bytes, reason: str, timestamp: int) -> CommitteeRoster:
        """Emergency-triggered epoch advance."""
        self._advance(0, timestamp, EpochTrigger.EMERGENCY)
        return self._roster

    def _advance(self, current_round: int, timestamp: int, trigger: EpochTrigger) -> None:
        """Internal: perform the epoch transition."""
        prev_epoch = self._current_epoch
        self._current_epoch += 1

        roster = self._formation.build_roster(
            self._policy,
            self._current_epoch,
            current_round,
            timestamp,
        )
        self._roster = roster

        record = EpochRecord(
            vm_tag=self._vm_tag,
            epoch=self._current_epoch,
            roster=roster,
            trigger=trigger,
            previous_epoch=prev_epoch,
            timestamp=timestamp,
        )
        self._history.append(record)

        self._epoch_start_round = current_round
        self._epoch_start_ts = timestamp
