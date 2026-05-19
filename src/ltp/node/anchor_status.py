"""
Per-entity anchor lifecycle tracker.

Tracks the status of on-chain anchor submissions from PENDING through
FINALIZED (or FAILED).  Thread-safe — all mutations are protected by
a threading.Lock.

Design decision: in-memory only.  The on-chain contract is the source of
truth; after restart the AnchorVerifier can re-derive status.
Persistence deferred to a future release.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

__all__ = ["AnchorStatus", "AnchorRecord", "AnchorStatusTracker"]


class AnchorStatus(Enum):
    """Lifecycle states for an on-chain anchor submission."""

    PENDING = "pending"  # Submission built, not yet sent
    SUBMITTED = "submitted"  # Tx sent, awaiting receipt
    CONFIRMED = "confirmed"  # Tx receipt received, below confirmation depth
    FINALIZED = "finalized"  # Sufficient block confirmations
    FAILED = "failed"  # Permanently failed (e.g., revert)


@dataclass
class AnchorRecord:
    """Mutable record tracking a single entity's anchor lifecycle."""

    entity_id: str
    anchor_digest: bytes  # 32-byte digest for contract queries
    status: AnchorStatus
    tx_hash: str = ""  # hex, empty until submitted
    block_number: int = 0  # 0 until confirmed
    gas_used: int = 0  # 0 until confirmed
    submitted_at: float = field(default_factory=time.time)
    confirmed_at: float = 0.0  # 0.0 until confirmed
    error: str = ""  # empty unless failed
    retry_count: int = 0
    chain_id: int = 0  # target chain (0 = legacy/unset)


class AnchorStatusTracker:
    """Thread-safe per-entity anchor lifecycle tracker.

    All public methods acquire the internal lock before mutating state.
    State transitions are validated — invalid transitions raise
    ``ValueError`` to surface scheduler bugs early rather than silently
    corrupting on-chain state.
    """

    # Valid (from_status, to_status) pairs — mirrors the Solidity contract's
    # _isValidTransition() pattern.  FAILED is reachable from any active state.
    _VALID_TRANSITIONS: frozenset[tuple[AnchorStatus, AnchorStatus]] = frozenset(
        {
            (AnchorStatus.PENDING, AnchorStatus.SUBMITTED),
            (AnchorStatus.SUBMITTED, AnchorStatus.CONFIRMED),
            (AnchorStatus.CONFIRMED, AnchorStatus.FINALIZED),
            # FAILED is a terminal sink — reachable from any non-terminal state
            (AnchorStatus.PENDING, AnchorStatus.FAILED),
            (AnchorStatus.SUBMITTED, AnchorStatus.FAILED),
            (AnchorStatus.CONFIRMED, AnchorStatus.FAILED),
        }
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AnchorRecord] = {}

    def _transition(self, entity_id: str, to_status: AnchorStatus) -> AnchorRecord:
        """Validate and apply a state transition (caller must hold the lock)."""
        rec = self._records.get(entity_id)
        if rec is None:
            raise KeyError(f"No anchor record for entity {entity_id!r}")
        if (rec.status, to_status) not in self._VALID_TRANSITIONS:
            raise ValueError(
                f"Invalid anchor transition for {entity_id!r}: "
                f"{rec.status.value} -> {to_status.value}"
            )
        rec.status = to_status
        return rec

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def mark_pending(self, entity_id: str, anchor_digest: bytes, chain_id: int = 0) -> None:
        """Create a new record in PENDING state.

        Raises ``ValueError`` if *anchor_digest* is not exactly 32 bytes
        (the on-chain contract expects ``bytes32``).
        """
        if len(anchor_digest) != 32:
            raise ValueError(f"anchor_digest must be exactly 32 bytes, got {len(anchor_digest)}")
        with self._lock:
            self._records[entity_id] = AnchorRecord(
                entity_id=entity_id,
                anchor_digest=anchor_digest,
                status=AnchorStatus.PENDING,
                chain_id=chain_id,
            )

    def mark_submitted(self, entity_id: str, tx_hash: str) -> None:
        """Transition PENDING -> SUBMITTED with the transaction hash."""
        with self._lock:
            rec = self._transition(entity_id, AnchorStatus.SUBMITTED)
            rec.tx_hash = tx_hash

    def mark_confirmed(self, entity_id: str, block_number: int, gas_used: int) -> None:
        """Transition SUBMITTED -> CONFIRMED with block metadata."""
        with self._lock:
            rec = self._transition(entity_id, AnchorStatus.CONFIRMED)
            rec.block_number = block_number
            rec.gas_used = gas_used
            rec.confirmed_at = time.time()

    def mark_finalized(self, entity_id: str) -> None:
        """Transition CONFIRMED -> FINALIZED (sufficient block confirmations)."""
        with self._lock:
            self._transition(entity_id, AnchorStatus.FINALIZED)

    def mark_failed(self, entity_id: str, error: str) -> None:
        """Mark an entity's anchor as permanently failed.

        Valid from PENDING, SUBMITTED, or CONFIRMED.
        """
        with self._lock:
            rec = self._transition(entity_id, AnchorStatus.FAILED)
            rec.error = error

    def increment_retry(self, entity_id: str) -> int:
        """Increment and return the retry count for an entity.

        Raises ``KeyError`` if the entity is not tracked.
        """
        with self._lock:
            rec = self._records.get(entity_id)
            if rec is None:
                raise KeyError(f"No anchor record for entity {entity_id!r}")
            rec.retry_count += 1
            return rec.retry_count

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, entity_id: str) -> Optional[AnchorRecord]:
        """Return the anchor record for *entity_id*, or None."""
        with self._lock:
            rec = self._records.get(entity_id)
            if rec is None:
                return None
            # Return a snapshot copy so callers can't mutate state
            return AnchorRecord(
                entity_id=rec.entity_id,
                anchor_digest=rec.anchor_digest,
                status=rec.status,
                tx_hash=rec.tx_hash,
                block_number=rec.block_number,
                gas_used=rec.gas_used,
                submitted_at=rec.submitted_at,
                confirmed_at=rec.confirmed_at,
                error=rec.error,
                retry_count=rec.retry_count,
                chain_id=rec.chain_id,
            )

    def get_by_status(self, status: AnchorStatus) -> list[AnchorRecord]:
        """Return snapshot copies of all records matching *status*."""
        with self._lock:
            return [
                AnchorRecord(
                    entity_id=r.entity_id,
                    anchor_digest=r.anchor_digest,
                    status=r.status,
                    tx_hash=r.tx_hash,
                    block_number=r.block_number,
                    gas_used=r.gas_used,
                    submitted_at=r.submitted_at,
                    confirmed_at=r.confirmed_at,
                    error=r.error,
                    retry_count=r.retry_count,
                    chain_id=r.chain_id,
                )
                for r in self._records.values()
                if r.status is status
            ]

    @property
    def pending_count(self) -> int:
        """Number of entities currently in PENDING state."""
        with self._lock:
            return sum(1 for r in self._records.values() if r.status is AnchorStatus.PENDING)

    def stats(self) -> dict[str, int]:
        """Aggregate counts by status: {\"pending\": N, \"submitted\": N, ...}."""
        with self._lock:
            counts: dict[str, int] = {s.value: 0 for s in AnchorStatus}
            for r in self._records.values():
                counts[r.status.value] += 1
            return counts
