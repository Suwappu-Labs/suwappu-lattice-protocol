"""Mid-epoch eviction handler (Spec C3a §7)."""

from __future__ import annotations

from typing import Optional

from .types import (
    CommitteeEvent,
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
    EvictionEvent,
    EvictionReason,
)
from .policy import CommitteePolicy, EvictionMode, FloorMode
from .standby import StandbySelector
from ..writer import WriterState

__all__ = ["EvictionHandler"]

_SECURITY_STATES = frozenset({WriterState.REVOKED})
_OPERATIONAL_STATES = frozenset({WriterState.SUSPENDED, WriterState.EXPIRED})

_STATE_TO_REASON: dict[WriterState, EvictionReason] = {
    WriterState.REVOKED:   EvictionReason.REVOKED,
    WriterState.SUSPENDED: EvictionReason.SUSPENDED,
    WriterState.EXPIRED:   EvictionReason.EXPIRED,
}


class EvictionHandler:
    """Handles mid-epoch committee membership changes."""

    def __init__(self, policy: CommitteePolicy, standby_selector: StandbySelector) -> None:
        self._policy = policy
        self._standby = standby_selector
        self._events: list[EvictionEvent] = []
        self._halted: bool = False
        self.pending_evictions: list[tuple[bytes, EvictionReason]] = []
        self.emitted_events: list[CommitteeEvent] = []

    @property
    def is_halted(self) -> bool:
        return self._halted

    def handle_state_change(
        self,
        roster: CommitteeRoster,
        writer_fp: bytes,
        old_state: WriterState,
        new_state: WriterState,
        timestamp: int,
    ) -> Optional[EvictionEvent]:
        """Process a writer state change. Returns EvictionEvent if member was evicted."""
        reason = _STATE_TO_REASON.get(new_state)
        if reason is None:
            return None

        member_idx = None
        for i, m in enumerate(roster.active_members):
            if m.writer_fp == writer_fp:
                member_idx = i
                break

        if member_idx is None:
            return None

        if new_state in _SECURITY_STATES:
            mode = self._policy.security_eviction
        else:
            mode = self._policy.operational_eviction

        if mode is EvictionMode.EPOCH_BOUNDARY:
            self.pending_evictions.append((writer_fp, reason))
            return None

        roster.active_members.pop(member_idx)
        backfill_fp: Optional[bytes] = None

        if mode is EvictionMode.IMMEDIATE_BACKFILL:
            replacement = self._standby.next(roster)
            if replacement is not None:
                roster.standby_members.remove(replacement)
                promoted = CommitteeMember(
                    writer_fp=replacement.writer_fp,
                    bls_pk=replacement.bls_pk,
                    tier=replacement.tier,
                    joined_epoch=replacement.joined_epoch,
                    role=CommitteeRole.ACTIVE,
                )
                roster.active_members.append(promoted)
                backfill_fp = replacement.writer_fp
                self.emitted_events.append(CommitteeEvent.MEMBER_BACKFILLED)

        self.emitted_events.append(CommitteeEvent.MEMBER_EVICTED)

        self._check_floor(roster)

        event = EvictionEvent(
            writer_fp=writer_fp,
            vm_tag=roster.vm_tag,
            epoch=roster.epoch,
            reason=reason,
            backfill_fp=backfill_fp,
            timestamp=timestamp,
        )
        self._events.append(event)
        return event

    def _check_floor(self, roster: CommitteeRoster) -> None:
        """Check if committee size is below minimum."""
        if len(roster.active_members) >= self._policy.min_committee_size:
            if self._halted:
                self._halted = False
                self.emitted_events.append(CommitteeEvent.FLOOR_RESTORED)
            return

        if self._policy.floor_mode is FloorMode.HARD:
            self._halted = True
            self.emitted_events.append(CommitteeEvent.COMMITTEE_HALTED)
        else:
            self.emitted_events.append(CommitteeEvent.BELOW_FLOOR)
