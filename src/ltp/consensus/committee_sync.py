"""CommitteeSync — bridges CommitteeManager to consensus events (Spec D1b §5)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from .events import ConsensusEvent, ConsensusEventType
from .validator_set import ValidatorSet

if TYPE_CHECKING:
    from ..execution.committee.dkg.threshold_signing import ThresholdSigningKey
    from ..execution.committee.manager import CommitteeManager

__all__ = ["CommitteeSync"]


class CommitteeSync:
    """Detects epoch transitions and evictions, emits ConsensusEvents."""

    def __init__(self, committee_manager: CommitteeManager) -> None:
        self._cm = committee_manager
        self._current_epoch: int = committee_manager.epoch
        self._validator_set: ValidatorSet | None = None
        self._listeners: list[Callable[[ConsensusEvent], None]] = []
        self._known_evicted: set[bytes] = set()

    @property
    def current_validator_set(self) -> ValidatorSet | None:
        return self._validator_set

    def set_validator_set(self, vs: ValidatorSet) -> None:
        self._validator_set = vs
        self._known_evicted = set()

    def register_listener(self, callback: Callable[[ConsensusEvent], None]) -> None:
        self._listeners.append(callback)

    def has_signing_keys(self, epoch: int) -> bool:
        return self._cm.has_dkg_result(epoch)

    def get_signing_keys(self, epoch: int) -> list[ThresholdSigningKey]:
        return self._cm._signing_keys.get(epoch, [])

    def sync_epoch(self, round: int, timestamp_ms: int) -> ConsensusEvent | None:
        """Check if epoch advanced. If yes, build new ValidatorSet and emit event."""
        new_epoch = self._cm.epoch
        if new_epoch <= self._current_epoch:
            return None

        old_epoch = self._current_epoch
        self._current_epoch = new_epoch

        roster = self._cm.roster
        if roster is not None:
            self._validator_set = ValidatorSet.from_roster(roster)
            self._known_evicted = set()

        validator_count = self._validator_set.size if self._validator_set else 0
        dkg_completed = self._cm.has_dkg_result(new_epoch)

        event = ConsensusEvent(
            event_type=ConsensusEventType.EPOCH_TRANSITION,
            epoch=new_epoch,
            round=round,
            timestamp_ms=timestamp_ms,
            payload={
                "old_epoch": old_epoch,
                "new_epoch": new_epoch,
                "validator_count": validator_count,
                "dkg_completed": dkg_completed,
            },
        )
        self._notify(event)
        return event

    def sync_evictions(
        self,
        validator_set: ValidatorSet,
        round: int,
        timestamp_ms: int,
    ) -> list[ConsensusEvent]:
        """Compare roster against ValidatorSet, emit events for new evictions."""
        events: list[ConsensusEvent] = []
        roster = self._cm.roster
        if roster is None:
            return events

        active_fps = {m.writer_fp for m in roster.active_members}

        for member in validator_set.members:
            fp = member.writer_fp
            if fp in self._known_evicted:
                continue
            if fp not in active_fps and not validator_set.is_evicted(fp):
                validator_set.evict(fp)
                self._known_evicted.add(fp)
                event = ConsensusEvent(
                    event_type=ConsensusEventType.VALIDATOR_EVICTED,
                    epoch=self._current_epoch,
                    round=round,
                    timestamp_ms=timestamp_ms,
                    payload={
                        "writer_fp": fp,
                        "validator_index": member.validator_index,
                        "reason": "evicted_from_roster",
                        "remaining_active": validator_set.active_count(),
                    },
                )
                self._notify(event)
                events.append(event)

        return events

    def on_tick(
        self,
        round: int,
        timestamp_ms: int,
    ) -> list[ConsensusEvent]:
        """Run sync_epoch + sync_evictions, return all events."""
        events: list[ConsensusEvent] = []

        epoch_event = self.sync_epoch(round, timestamp_ms)
        if epoch_event is not None:
            events.append(epoch_event)

        if self._validator_set is not None:
            eviction_events = self.sync_evictions(
                self._validator_set,
                round,
                timestamp_ms,
            )
            events.extend(eviction_events)

        return events

    def _notify(self, event: ConsensusEvent) -> None:
        for listener in self._listeners:
            listener(event)
