"""
Message bus — simulates network message delivery with realistic timing.

Every shard store, shard fetch, lattice key transfer, and audit challenge
is modelled as a Message delivered through the MessageBus with latency
computed from the network topology. This allows the MetricsCollector to
accurately attribute time to each phase of the protocol.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


class MessageType(Enum):
    """Types of network messages in the LTP simulation."""

    SHARD_STORE_REQUEST = auto()
    SHARD_STORE_ACK = auto()
    SHARD_FETCH_REQUEST = auto()
    SHARD_FETCH_RESPONSE = auto()
    LATTICE_KEY_TRANSFER = auto()
    AUDIT_CHALLENGE = auto()
    AUDIT_RESPONSE = auto()
    COMMITMENT_RECORD_FETCH = auto()
    COMMITMENT_RECORD_RESPONSE = auto()
    REPAIR_COPY = auto()


@dataclass
class Message:
    """
    A network message between two participants (nodes or clients).

    Tracks source, destination, timing, payload size, and delivery status.
    """

    msg_id: str
    msg_type: MessageType
    source: str
    destination: str
    payload_bytes: int
    payload: Any = field(default=None, repr=False)

    # Timing (set by MessageBus during delivery)
    send_time_ms: float = 0.0
    deliver_time_ms: float = 0.0
    latency_ms: float = 0.0

    # Status
    delivered: bool = False
    lost: bool = False
    retries: int = 0

    @property
    def in_flight_ms(self) -> float:
        if not self.delivered:
            return 0.0
        return self.deliver_time_ms - self.send_time_ms


class MessageBus:
    """
    Central message delivery system for the simulation.

    All network communication flows through the MessageBus, which:
      1. Computes delivery time based on topology latency
      2. Simulates packet loss
      3. Records all messages for metrics analysis
      4. Schedules delivery events on the event queue

    The bus does NOT use the EventQueue directly — it returns computed
    delivery times so the NetworkSimulator can schedule events. This
    keeps the bus stateless with respect to the clock.
    """

    def __init__(self) -> None:
        self._messages: list[Message] = []
        self._msg_counter: int = 0
        self._in_flight: dict[str, Message] = {}

    def send(
        self,
        msg_type: MessageType,
        source: str,
        destination: str,
        payload_bytes: int,
        send_time_ms: float,
        latency_ms: float,
        payload: Any = None,
        packet_lost: bool = False,
    ) -> Message:
        """
        Create and record a message send.

        The caller (NetworkSimulator) is responsible for computing latency
        from the topology and determining packet loss.

        Returns the Message object with delivery time computed.
        """
        self._msg_counter += 1
        msg_id = f"msg-{self._msg_counter:06d}"

        msg = Message(
            msg_id=msg_id,
            msg_type=msg_type,
            source=source,
            destination=destination,
            payload_bytes=payload_bytes,
            payload=payload,
            send_time_ms=send_time_ms,
            deliver_time_ms=send_time_ms + latency_ms,
            latency_ms=latency_ms,
            delivered=not packet_lost,
            lost=packet_lost,
        )

        self._messages.append(msg)
        if not packet_lost:
            self._in_flight[msg_id] = msg
        return msg

    def confirm_delivery(self, msg_id: str) -> None:
        """Mark a message as delivered (called when event fires)."""
        msg = self._in_flight.pop(msg_id, None)
        if msg:
            msg.delivered = True

    def get_message(self, msg_id: str) -> Optional[Message]:
        for m in self._messages:
            if m.msg_id == msg_id:
                return m
        return None

    # --- Query ---

    @property
    def total_messages(self) -> int:
        return len(self._messages)

    @property
    def total_bytes_transferred(self) -> int:
        return sum(m.payload_bytes for m in self._messages if m.delivered)

    @property
    def total_lost(self) -> int:
        return sum(1 for m in self._messages if m.lost)

    def messages_for_entity(self, entity_id: str) -> list[Message]:
        """Get all messages related to a specific entity transfer."""
        return [
            m
            for m in self._messages
            if m.payload and isinstance(m.payload, dict) and m.payload.get("entity_id") == entity_id
        ]

    def messages_by_type(self, msg_type: MessageType) -> list[Message]:
        return [m for m in self._messages if m.msg_type == msg_type]

    def messages_between(self, source: str, destination: str) -> list[Message]:
        return [m for m in self._messages if m.source == source and m.destination == destination]

    @property
    def all_messages(self) -> list[Message]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()
        self._in_flight.clear()
        self._msg_counter = 0

    def stats(self) -> dict:
        delivered = [m for m in self._messages if m.delivered]
        latencies = [m.latency_ms for m in delivered]
        return {
            "total_messages": len(self._messages),
            "delivered": len(delivered),
            "lost": self.total_lost,
            "total_bytes": self.total_bytes_transferred,
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
            "max_latency_ms": max(latencies) if latencies else 0.0,
            "min_latency_ms": min(latencies) if latencies else 0.0,
        }
