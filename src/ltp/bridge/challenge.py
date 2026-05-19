"""
ChallengeManager — optimistic bridge challenge period state machine.

Manages per-entity challenge windows with auto-finalization:
  OPEN → CHALLENGED → RESOLVED  (fraud confirmed)
  OPEN → FINALIZED              (no challenge within window)
  CHALLENGED → EXPIRED          (challenge not resolved in time)

Follows the AnchorStatusTracker pattern: thread-safe, validated
transitions, snapshot copies on queries, injectable clock for
deterministic testing.

"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from ..primitives import canonical_hash_bytes

__all__ = [
    "ChallengeStatus",
    "ChallengeRecord",
    "ChallengeManager",
]

logger = logging.getLogger(__name__)

# Default challenge period: 7 days in seconds
DEFAULT_CHALLENGE_PERIOD = 7 * 24 * 3600  # 604800


class ChallengeStatus(Enum):
    """Lifecycle states for an optimistic bridge challenge window."""

    OPEN = "open"  # Window active, no challenge filed
    CHALLENGED = "challenged"  # Fraud proof submitted, pending resolution
    RESOLVED = "resolved"  # Adjudicated: valid fraud confirmed
    FINALIZED = "finalized"  # Window expired with no valid challenge
    EXPIRED = "expired"  # Challenge submitted but never resolved


@dataclass
class ChallengeRecord:
    """Mutable record tracking a single entity's challenge lifecycle."""

    entity_id: str
    anchor_digest: bytes  # 32B digest for contract queries
    status: ChallengeStatus
    opened_at: float
    challenge_deadline: float  # opened_at + challenge_period
    challenger_id: str = ""
    fraud_proof_hash: bytes = b""
    fraud_proof_type: str = ""
    resolved_at: float = 0.0
    resolution: str = ""  # "valid_fraud" or "invalid_challenge"


class ChallengeManager:
    """Thread-safe optimistic bridge challenge manager.

    Tracks per-entity challenge windows and auto-finalizes expired
    windows via tick().

    Args:
        challenge_period: Duration of the challenge window in seconds.
            Defaults to 7 days (604800s).
        clock: Callable returning current time (float). Defaults to
            time.time. Inject a mock for deterministic testing.
    """

    _VALID_TRANSITIONS: frozenset[tuple[ChallengeStatus, ChallengeStatus]] = frozenset(
        {
            (ChallengeStatus.OPEN, ChallengeStatus.CHALLENGED),
            (ChallengeStatus.OPEN, ChallengeStatus.FINALIZED),
            (ChallengeStatus.CHALLENGED, ChallengeStatus.RESOLVED),
            (ChallengeStatus.CHALLENGED, ChallengeStatus.EXPIRED),
            # ZK proof can finalize a challenged window
            (ChallengeStatus.CHALLENGED, ChallengeStatus.FINALIZED),
        }
    )

    def __init__(
        self,
        challenge_period: float = DEFAULT_CHALLENGE_PERIOD,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._challenge_period = challenge_period
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._records: dict[str, ChallengeRecord] = {}

    def _transition(self, entity_id: str, to_status: ChallengeStatus) -> ChallengeRecord:
        """Validate and apply a state transition (caller must hold lock)."""
        rec = self._records.get(entity_id)
        if rec is None:
            raise KeyError(f"No challenge record for entity {entity_id!r}")
        if (rec.status, to_status) not in self._VALID_TRANSITIONS:
            raise ValueError(
                f"Invalid challenge transition for {entity_id!r}: "
                f"{rec.status.value} -> {to_status.value}"
            )
        rec.status = to_status
        return rec

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def open_challenge_window(self, entity_id: str, anchor_digest: bytes) -> ChallengeRecord:
        """Open a new challenge window for an anchored entity.

        Raises ValueError if a window is already open for this entity
        or if anchor_digest is not exactly 32 bytes.
        """
        if len(anchor_digest) != 32:
            raise ValueError(f"anchor_digest must be 32 bytes, got {len(anchor_digest)}")
        now = self._clock()
        with self._lock:
            if entity_id in self._records:
                existing = self._records[entity_id]
                if existing.status in (ChallengeStatus.OPEN, ChallengeStatus.CHALLENGED):
                    raise ValueError(f"Challenge window already active for {entity_id!r}")
            rec = ChallengeRecord(
                entity_id=entity_id,
                anchor_digest=anchor_digest,
                status=ChallengeStatus.OPEN,
                opened_at=now,
                challenge_deadline=now + self._challenge_period,
            )
            self._records[entity_id] = rec
            logger.info(
                "Challenge window opened: entity=%s, deadline=%.0f",
                entity_id[:16],
                rec.challenge_deadline,
            )
            return ChallengeRecord(**rec.__dict__)

    def submit_challenge(
        self,
        entity_id: str,
        fraud_proof,
        challenger_id: str = "",
    ) -> ChallengeRecord:
        """Submit a fraud proof against an open challenge window.

        The fraud proof must have verify() and proof_hash() methods.
        Raises ValueError if the window has expired or the proof is invalid.
        """
        now = self._clock()
        with self._lock:
            rec = self._records.get(entity_id)
            if rec is None:
                raise KeyError(f"No challenge record for entity {entity_id!r}")

            if now > rec.challenge_deadline:
                raise ValueError(f"Challenge window expired for {entity_id!r}")

            if not fraud_proof.verify():
                raise ValueError("Fraud proof verification failed")

            self._transition(entity_id, ChallengeStatus.CHALLENGED)
            rec.challenger_id = challenger_id
            rec.fraud_proof_hash = fraud_proof.proof_hash()
            rec.fraud_proof_type = fraud_proof.proof_type.value
            logger.warning(
                "Challenge submitted: entity=%s, type=%s, challenger=%s",
                entity_id[:16],
                rec.fraud_proof_type,
                challenger_id,
            )
            return ChallengeRecord(**rec.__dict__)

    def resolve_challenge(self, entity_id: str, resolution: str) -> ChallengeRecord:
        """Resolve a challenged entity.

        Args:
            resolution: "valid_fraud" (operator slashed) or
                        "invalid_challenge" (challenger slashed).
        """
        if resolution not in ("valid_fraud", "invalid_challenge"):
            raise ValueError(f"Invalid resolution: {resolution!r}")

        now = self._clock()
        with self._lock:
            self._transition(entity_id, ChallengeStatus.RESOLVED)
            rec = self._records[entity_id]
            rec.resolved_at = now
            rec.resolution = resolution
            logger.info(
                "Challenge resolved: entity=%s, resolution=%s",
                entity_id[:16],
                resolution,
            )
            return ChallengeRecord(**rec.__dict__)

    def resolve_with_proof(self, entity_id: str, proof) -> ChallengeRecord:
        """Resolve a challenge window using a ZK proof.

        Verifies the proof and transitions directly to FINALIZED,
        bypassing the challenge period. Works from OPEN or CHALLENGED state.

        Raises ValueError if the proof is invalid.
        """
        from .zk_bridge import ZKBridgeVerifier

        if not ZKBridgeVerifier.verify(proof):
            raise ValueError("ZK bridge proof verification failed")

        now = self._clock()
        with self._lock:
            rec = self._records.get(entity_id)
            if rec is None:
                raise KeyError(f"No challenge record for entity {entity_id!r}")
            if rec.status not in (ChallengeStatus.OPEN, ChallengeStatus.CHALLENGED):
                raise ValueError(f"Cannot resolve with proof from status {rec.status.value}")
            rec.status = ChallengeStatus.FINALIZED
            rec.resolved_at = now
            rec.resolution = "zk_proof"
            logger.info(
                "Challenge resolved via ZK proof: entity=%s, proof_id=%s",
                entity_id[:16],
                proof.proof_id[:16],
            )
            return ChallengeRecord(**rec.__dict__)

    def tick(self, now: Optional[float] = None) -> list[str]:
        """Auto-finalize expired challenge windows.

        Returns list of entity_ids that were finalized or expired.
        """
        now = now or self._clock()
        finalized: list[str] = []

        with self._lock:
            for entity_id, rec in self._records.items():
                if rec.status == ChallengeStatus.OPEN and now > rec.challenge_deadline:
                    rec.status = ChallengeStatus.FINALIZED
                    finalized.append(entity_id)
                    logger.info(
                        "Challenge window finalized (no challenge): entity=%s",
                        entity_id[:16],
                    )
                elif rec.status == ChallengeStatus.CHALLENGED and now > rec.challenge_deadline:
                    rec.status = ChallengeStatus.EXPIRED
                    finalized.append(entity_id)
                    logger.warning(
                        "Challenge expired (not resolved in time): entity=%s",
                        entity_id[:16],
                    )

        return finalized

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, entity_id: str) -> Optional[ChallengeRecord]:
        """Return a snapshot of the challenge record, or None."""
        with self._lock:
            rec = self._records.get(entity_id)
            if rec is None:
                return None
            return ChallengeRecord(**rec.__dict__)

    def get_by_status(self, status: ChallengeStatus) -> list[ChallengeRecord]:
        """Return snapshot copies of all records matching status."""
        with self._lock:
            return [
                ChallengeRecord(**r.__dict__) for r in self._records.values() if r.status is status
            ]

    def stats(self) -> dict[str, int]:
        """Aggregate counts by status."""
        with self._lock:
            counts: dict[str, int] = {s.value: 0 for s in ChallengeStatus}
            for r in self._records.values():
                counts[r.status.value] += 1
            return counts

    @property
    def challenge_period(self) -> float:
        return self._challenge_period
