"""Epoch-driven operations — rate limits, expiration, promotion (Spec C2 §9.4)."""

from __future__ import annotations

from collections import defaultdict

from .writer import WriterState
from .writer_registry import WriterRegistry

__all__ = ["EpochTracker", "check_expirations", "promote_due_probations"]


class EpochTracker:
    """Per-writer, per-VM transaction counter with epoch rollover."""

    def __init__(self):
        self._counts: dict[tuple[bytes, int], int] = defaultdict(int)
        self._current_epoch: int = 0

    def increment(self, writer_fp: bytes, vm_tag: int, epoch: int) -> None:
        """Increment tx count. Auto-advances epoch if different."""
        if epoch != self._current_epoch:
            self.advance_epoch(epoch)
        self._counts[(writer_fp, vm_tag)] += 1

    def get_tx_count(self, writer_fp: bytes, vm_tag: int) -> int:
        return self._counts.get((writer_fp, vm_tag), 0)

    def advance_epoch(self, new_epoch: int) -> None:
        if new_epoch <= self._current_epoch:
            return  # ignore stale or duplicate epoch signals
        self._counts.clear()
        self._current_epoch = new_epoch


def check_expirations(registry: WriterRegistry, current_epoch: int) -> list[bytes]:
    """Wrapper around registry.check_expirations."""
    return registry.check_expirations(current_epoch)


def promote_due_probations(
    registry: WriterRegistry, current_epoch: int, timestamp: int
) -> list[bytes]:
    """Promote PROBATION writers whose probation_until <= current_epoch."""
    promoted = []
    for record in registry.active_writers():
        if (
            record.state == WriterState.PROBATION
            and record.probation_until is not None
            and current_epoch >= record.probation_until
        ):
            registry.promote(record.identity.fingerprint, timestamp=timestamp)
            promoted.append(record.identity.fingerprint)
    return promoted
