"""
Message queue abstraction for ETP enforcement pipeline.

Production: AWS SQS FIFO, Redis Streams, Kafka.
Development/Test: InMemoryQueue.

Models epoch-keyed violation evidence queuing. Messages are grouped by
group_id (e.g., epoch number) and consumed destructively — once dequeued,
they're gone (FIFO exactly-once semantics).
"""

from __future__ import annotations

import threading
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Optional

__all__ = ["MessageQueue", "InMemoryQueue"]


class MessageQueue(ABC):
    """Abstract FIFO message queue interface.

    Production: AWS SQS FIFO (MessageGroupId = group_id),
                Redis Streams, or Kafka topics.
    Development/Test: InMemoryQueue.
    """

    @abstractmethod
    def enqueue(self, group_id: str, payload: dict) -> str:
        """Enqueue a message into a group. Returns message_id (UUID)."""
        ...

    @abstractmethod
    def dequeue(self, group_id: str, max_messages: int = 100) -> list[dict]:
        """Dequeue up to max_messages from a group. Destructive — consumed.

        Returns list of message dicts, each containing at minimum:
          {"message_id": str, "group_id": str, "payload": dict}
        """
        ...

    @abstractmethod
    def peek(self, group_id: str) -> list[dict]:
        """View pending messages without consuming them."""
        ...

    @abstractmethod
    def pending_groups(self) -> list[str]:
        """List all group IDs that have pending messages."""
        ...

    @abstractmethod
    def queue_depth(self, group_id: str = "") -> int:
        """Return count of pending messages.

        If group_id is empty, returns total across all groups.
        Otherwise, returns count for that specific group.
        """
        ...


class InMemoryQueue(MessageQueue):
    """Thread-safe in-memory FIFO queue for testing and development.

    Messages are stored in per-group lists. Dequeue is destructive
    (pops from the front), matching SQS FIFO exactly-once delivery.

    Thread-safe via threading.Lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # group_id → list of message dicts (FIFO order)
        self._groups: dict[str, list[dict]] = defaultdict(list)

    def enqueue(self, group_id: str, payload: dict) -> str:
        message_id = str(uuid.uuid4())
        message = {
            "message_id": message_id,
            "group_id": group_id,
            "payload": payload,
        }
        with self._lock:
            self._groups[group_id].append(message)
        return message_id

    def dequeue(self, group_id: str, max_messages: int = 100) -> list[dict]:
        with self._lock:
            messages = self._groups.get(group_id, [])
            count = min(max_messages, len(messages))
            result = messages[:count]
            del messages[:count]
            # Clean up empty groups
            if not messages and group_id in self._groups:
                del self._groups[group_id]
            return result

    def peek(self, group_id: str) -> list[dict]:
        with self._lock:
            # Return defensive copies to prevent mutation leaking back
            return [
                {
                    "message_id": m["message_id"],
                    "group_id": m["group_id"],
                    "payload": dict(m["payload"]),
                }
                for m in self._groups.get(group_id, [])
            ]

    def pending_groups(self) -> list[str]:
        with self._lock:
            return sorted(g for g, msgs in self._groups.items() if msgs)

    def queue_depth(self, group_id: str = "") -> int:
        with self._lock:
            if group_id:
                return len(self._groups.get(group_id, []))
            return sum(len(msgs) for msgs in self._groups.values())
