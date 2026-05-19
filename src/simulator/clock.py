"""
Discrete-event simulation clock and event queue.

The SimClock provides a deterministic, reproducible simulation timeline.
Events are processed in strict time order, making runs deterministic
given the same initial conditions — essential for repeatable testing
and debugging of distributed protocol scenarios.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable


class EventType(Enum):
    """Categories of simulation events."""

    SHARD_STORE = auto()
    SHARD_FETCH = auto()
    SHARD_RESPONSE = auto()
    MESSAGE_SEND = auto()
    MESSAGE_DELIVER = auto()
    NODE_FAILURE = auto()
    NODE_RECOVERY = auto()
    LINK_DEGRADE = auto()
    LINK_RESTORE = auto()
    REGION_PARTITION = auto()
    REGION_RESTORE = auto()
    AUDIT_CHALLENGE = auto()
    AUDIT_RESPONSE = auto()
    CLIENT_COMMIT = auto()
    CLIENT_LATTICE = auto()
    CLIENT_MATERIALIZE = auto()
    TIMER = auto()
    CUSTOM = auto()


@dataclass(order=True)
class Event:
    """
    A simulation event scheduled for a specific time.

    Events are ordered by (time, sequence) to ensure deterministic
    processing when multiple events share the same timestamp.
    """

    time: float
    sequence: int = field(compare=True)
    event_type: EventType = field(compare=False)
    source: str = field(compare=False, default="")
    target: str = field(compare=False, default="")
    payload: Any = field(compare=False, default=None)
    callback: Callable | None = field(compare=False, default=None, repr=False)

    def __post_init__(self):
        if self.time < 0:
            raise ValueError(f"Event time must be non-negative, got {self.time}")


class SimClock:
    """
    Simulation clock providing a monotonically advancing time reference.

    Time is measured in milliseconds from simulation start (t=0).
    The clock only advances when events are processed — it does not
    track wall-clock time.
    """

    def __init__(self) -> None:
        self._now: float = 0.0
        self._ticks: int = 0

    @property
    def now(self) -> float:
        """Current simulation time in milliseconds."""
        return self._now

    @property
    def now_seconds(self) -> float:
        """Current simulation time in seconds."""
        return self._now / 1000.0

    @property
    def ticks(self) -> int:
        """Number of clock advances (events processed)."""
        return self._ticks

    def advance_to(self, time: float) -> None:
        """Advance the clock to the given time. Must be >= current time."""
        if time < self._now:
            raise ValueError(f"Cannot move clock backward: {time} < {self._now}")
        self._now = time
        self._ticks += 1

    def reset(self) -> None:
        """Reset clock to t=0."""
        self._now = 0.0
        self._ticks = 0


class EventQueue:
    """
    Priority queue of simulation events, ordered by time.

    Uses a min-heap for O(log n) insert and O(log n) pop.
    A monotonic sequence counter breaks ties deterministically.
    """

    def __init__(self) -> None:
        self._heap: list[Event] = []
        self._sequence: int = 0
        self._cancelled: set[int] = set()

    def schedule(
        self,
        time: float,
        event_type: EventType,
        source: str = "",
        target: str = "",
        payload: Any = None,
        callback: Callable | None = None,
    ) -> Event:
        """Schedule an event at the given simulation time."""
        event = Event(
            time=time,
            sequence=self._sequence,
            event_type=event_type,
            source=source,
            target=target,
            payload=payload,
            callback=callback,
        )
        self._sequence += 1
        heapq.heappush(self._heap, event)
        return event

    def schedule_event(self, event: Event) -> None:
        """Schedule a pre-built event."""
        heapq.heappush(self._heap, event)

    def cancel(self, event: Event) -> None:
        """Cancel a scheduled event (lazy deletion)."""
        self._cancelled.add(event.sequence)

    def pop(self) -> Event | None:
        """Pop the next event. Returns None if empty."""
        while self._heap:
            event = heapq.heappop(self._heap)
            if event.sequence not in self._cancelled:
                return event
        return None

    def peek(self) -> Event | None:
        """Peek at the next event without removing it."""
        while self._heap:
            if self._heap[0].sequence in self._cancelled:
                heapq.heappop(self._heap)
                continue
            return self._heap[0]
        return None

    @property
    def pending(self) -> int:
        """Number of pending (non-cancelled) events. O(n) scan."""
        return sum(1 for e in self._heap if e.sequence not in self._cancelled)

    @property
    def is_empty(self) -> bool:
        """Whether the queue has no pending events."""
        return self.peek() is None

    def clear(self) -> None:
        """Remove all events."""
        self._heap.clear()
        self._cancelled.clear()
        self._sequence = 0

    def drain_until(self, time: float) -> list[Event]:
        """Pop all events with time <= the given threshold."""
        events = []
        while self._heap:
            nxt = self.peek()
            if nxt is None or nxt.time > time:
                break
            events.append(self.pop())
        return events
