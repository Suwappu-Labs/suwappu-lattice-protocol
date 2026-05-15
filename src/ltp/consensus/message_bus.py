"""In-memory message routing with partition support (Spec D1a §3)."""

from __future__ import annotations

from collections import defaultdict

from .faults import PartitionConfig


class MessageBus:
    """Routes messages between simulated validators.

    Supports point-to-point, broadcast, and network partitions.
    Messages are tuples of (from_validator, payload).
    """

    def __init__(self, num_validators: int) -> None:
        self._num_validators = num_validators
        self._pending: dict[int, list[tuple[int, object]]] = defaultdict(list)
        self._partition: PartitionConfig | None = None

    def _is_partitioned(self, from_v: int, to_v: int) -> bool:
        """Check if delivery is blocked by an active partition."""
        if self._partition is None:
            return False
        p = self._partition
        from_in_a = from_v in p.group_a
        to_in_a = to_v in p.group_a
        from_in_b = from_v in p.group_b
        to_in_b = to_v in p.group_b
        if (from_in_a and to_in_b) or (from_in_b and to_in_a):
            return True
        return False

    def send(self, from_v: int, to_v: int, message: object) -> None:
        """Point-to-point delivery (subject to partition)."""
        if not self._is_partitioned(from_v, to_v):
            self._pending[to_v].append((from_v, message))

    def broadcast(self, from_v: int, message: object) -> None:
        """Broadcast to all validators except sender."""
        for to_v in range(self._num_validators):
            if to_v != from_v:
                self.send(from_v, to_v, message)

    def set_partition(self, config: PartitionConfig) -> None:
        """Activate a network partition."""
        self._partition = config

    def clear_partition(self) -> None:
        """Remove the active partition."""
        self._partition = None

    def pending_for(self, validator: int) -> list[tuple[int, object]]:
        """Messages waiting for a validator (not yet delivered)."""
        return list(self._pending.get(validator, []))

    def deliver_all(self) -> list[tuple[int, int, object]]:
        """Drain and return all pending messages as (from, to, message) triples."""
        delivered: list[tuple[int, int, object]] = []
        for to_v, messages in self._pending.items():
            for from_v, msg in messages:
                delivered.append((from_v, to_v, msg))
        self._pending.clear()
        return delivered
