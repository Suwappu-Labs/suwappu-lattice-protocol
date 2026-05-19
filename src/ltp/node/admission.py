"""
Node Admission Protocol — m-of-n endorsement for permissioned node registration.

Implements the Founder's Protocol:
  Apply → Endorsed (m-of-n) → Admitted (stake deposited) → Active → Audit Loop

Each endorsement is an ML-DSA-65 signed vote from an existing operator.
The admission threshold (m-of-n) is configurable per network configuration.

Thread-safe via threading.Lock, following the ChallengeManager pattern.

Reference: ETP_UNIFIED_NODE_DEPLOYMENT_PLAN.md
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from ..domain import DOMAIN_NODE_ENDORSEMENT
from ..primitives import MLDSA, canonical_hash, canonical_hash_bytes

__all__ = [
    "AdmissionState",
    "EndorsementVote",
    "AdmissionRecord",
    "NodeAdmissionManager",
    "InvalidAdmissionTransition",
    "create_endorsement",
    "verify_endorsement",
]

logger = logging.getLogger(__name__)


class AdmissionState(Enum):
    """Node admission lifecycle states."""

    APPLYING = "applying"  # Application submitted, awaiting endorsements
    ENDORSED = "endorsed"  # Received m-of-n endorsements
    ADMITTED = "admitted"  # Stake deposited, ready to activate
    ACTIVE = "active"  # Operating in the network
    SUSPENDED = "suspended"  # Temporarily suspended (audit failure)
    EVICTED = "evicted"  # Permanently removed


class InvalidAdmissionTransition(Exception):
    """Raised when an illegal admission state transition is attempted."""

    def __init__(self, current: AdmissionState, target: AdmissionState):
        super().__init__(f"Invalid admission transition: {current.value} -> {target.value}")
        self.current = current
        self.target = target


_VALID_ADMISSION_TRANSITIONS: frozenset[tuple[AdmissionState, AdmissionState]] = frozenset(
    {
        (AdmissionState.APPLYING, AdmissionState.ENDORSED),
        (AdmissionState.ENDORSED, AdmissionState.ADMITTED),
        (AdmissionState.ADMITTED, AdmissionState.ACTIVE),
        (AdmissionState.ACTIVE, AdmissionState.SUSPENDED),
        (AdmissionState.SUSPENDED, AdmissionState.ACTIVE),
        (AdmissionState.ACTIVE, AdmissionState.EVICTED),
        (AdmissionState.SUSPENDED, AdmissionState.EVICTED),
    }
)


@dataclass
class EndorsementVote:
    """A single operator's endorsement of a node application."""

    endorser_vk_hash: str  # H(endorser.vk)
    applicant_node_id: str
    signature: bytes  # domain_sign(DOMAIN_NODE_ENDORSEMENT, endorser.sk, payload)
    timestamp: float
    endorser_label: str = ""


@dataclass
class AdmissionRecord:
    """Tracks a node's admission lifecycle."""

    node_id: str
    applicant_vk_hash: str  # H(applicant.vk)
    state: AdmissionState
    applied_at: float
    endorsements: list[EndorsementVote] = field(default_factory=list)
    required_endorsements: int = 2  # m (threshold)
    total_operators: int = 3  # n (pool size)
    admitted_at: float = 0.0
    activated_at: float = 0.0
    suspended_at: float = 0.0
    rejection_reason: str = ""


def create_endorsement(endorser_keypair, applicant_node_id: str) -> EndorsementVote:
    """Create a signed endorsement for a node application.

    The endorsement payload is domain-separated with DOMAIN_NODE_ENDORSEMENT
    to prevent cross-domain signature replay.
    """
    payload = DOMAIN_NODE_ENDORSEMENT + applicant_node_id.encode() + endorser_keypair.vk
    sig = endorser_keypair.sign(payload)
    return EndorsementVote(
        endorser_vk_hash=canonical_hash(endorser_keypair.vk),
        applicant_node_id=applicant_node_id,
        signature=sig,
        timestamp=time.time(),
        endorser_label=endorser_keypair.label,
    )


def verify_endorsement(vote: EndorsementVote, endorser_vk: bytes) -> bool:
    """Verify an endorsement signature against the endorser's VK."""
    payload = DOMAIN_NODE_ENDORSEMENT + vote.applicant_node_id.encode() + endorser_vk
    return MLDSA.verify(endorser_vk, payload, vote.signature)


class NodeAdmissionManager:
    """m-of-n endorsement protocol for node admission.

    Thread-safe. All mutations under threading.Lock, snapshot copies on queries.
    """

    def __init__(
        self,
        m: int = 2,
        n: int = 3,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if m < 1:
            raise ValueError("m must be >= 1")
        if n < m:
            raise ValueError("n must be >= m")
        self._m = m
        self._n = n
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._records: dict[str, AdmissionRecord] = {}

    def _validate_transition(self, node_id: str, target: AdmissionState) -> AdmissionRecord:
        """Validate and apply a state transition (caller must hold lock)."""
        rec = self._records.get(node_id)
        if rec is None:
            raise KeyError(f"No admission record for node {node_id!r}")
        if (rec.state, target) not in _VALID_ADMISSION_TRANSITIONS:
            raise InvalidAdmissionTransition(rec.state, target)
        rec.state = target
        return rec

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _snapshot(self, rec: AdmissionRecord) -> AdmissionRecord:
        """Create a defensive copy with a deep-copied endorsements list."""
        copy = AdmissionRecord(**rec.__dict__)
        copy.endorsements = list(rec.endorsements)  # Shallow copy of list
        return copy

    def apply(self, node_id: str, applicant_vk_hash: str) -> AdmissionRecord:
        """Submit a node application. Creates record in APPLYING state."""
        now = self._clock()
        with self._lock:
            if node_id in self._records:
                existing = self._records[node_id]
                if existing.state not in (AdmissionState.EVICTED,):
                    raise ValueError(f"Node {node_id!r} already has active application")
            rec = AdmissionRecord(
                node_id=node_id,
                applicant_vk_hash=applicant_vk_hash,
                state=AdmissionState.APPLYING,
                applied_at=now,
                required_endorsements=self._m,
                total_operators=self._n,
            )
            self._records[node_id] = rec
            logger.info("Node application: %s (requires %d-of-%d)", node_id, self._m, self._n)
            return self._snapshot(rec)

    def endorse(
        self,
        node_id: str,
        vote: EndorsementVote,
        endorser_vk: Optional[bytes] = None,
    ) -> AdmissionRecord:
        """Add an endorsement vote. Auto-transitions to ENDORSED when m reached.

        If endorser_vk is provided, verifies the endorsement signature before
        accepting. Production callers should always provide this.
        """
        # Verify signature if VK provided
        if endorser_vk is not None:
            if not verify_endorsement(vote, endorser_vk):
                raise ValueError("Endorsement signature verification failed")

        with self._lock:
            rec = self._records.get(node_id)
            if rec is None:
                raise KeyError(f"No admission record for node {node_id!r}")
            if rec.state != AdmissionState.APPLYING:
                raise ValueError(f"Node {node_id!r} is not in APPLYING state")

            # Reject duplicate endorser
            existing_hashes = {e.endorser_vk_hash for e in rec.endorsements}
            if vote.endorser_vk_hash in existing_hashes:
                raise ValueError(
                    f"Endorser {vote.endorser_vk_hash[:16]} already endorsed {node_id!r}"
                )

            rec.endorsements.append(vote)
            logger.info(
                "Endorsement received for %s: %d/%d",
                node_id,
                len(rec.endorsements),
                rec.required_endorsements,
            )

            # Auto-transition to ENDORSED when threshold reached
            if len(rec.endorsements) >= rec.required_endorsements:
                rec.state = AdmissionState.ENDORSED
                logger.info(
                    "Node %s reached endorsement threshold (%d-of-%d)",
                    node_id,
                    rec.required_endorsements,
                    rec.total_operators,
                )

            return self._snapshot(rec)

    def admit(self, node_id: str) -> AdmissionRecord:
        """Transition ENDORSED -> ADMITTED (stake deposited)."""
        now = self._clock()
        with self._lock:
            self._validate_transition(node_id, AdmissionState.ADMITTED)
            rec = self._records[node_id]
            rec.admitted_at = now
            logger.info("Node %s admitted", node_id)
            return self._snapshot(rec)

    def activate(self, node_id: str) -> AdmissionRecord:
        """Transition ADMITTED -> ACTIVE (ready to serve)."""
        now = self._clock()
        with self._lock:
            self._validate_transition(node_id, AdmissionState.ACTIVE)
            rec = self._records[node_id]
            rec.activated_at = now
            logger.info("Node %s activated", node_id)
            return self._snapshot(rec)

    def suspend(self, node_id: str, reason: str = "") -> AdmissionRecord:
        """Transition ACTIVE -> SUSPENDED."""
        now = self._clock()
        with self._lock:
            self._validate_transition(node_id, AdmissionState.SUSPENDED)
            rec = self._records[node_id]
            rec.suspended_at = now
            rec.rejection_reason = reason
            logger.warning("Node %s suspended: %s", node_id, reason)
            return self._snapshot(rec)

    def reactivate(self, node_id: str) -> AdmissionRecord:
        """Transition SUSPENDED -> ACTIVE (re-admitted after remediation)."""
        with self._lock:
            self._validate_transition(node_id, AdmissionState.ACTIVE)
            rec = self._records[node_id]
            rec.rejection_reason = ""
            logger.info("Node %s reactivated", node_id)
            return self._snapshot(rec)

    def evict(self, node_id: str, reason: str = "") -> AdmissionRecord:
        """Transition ACTIVE/SUSPENDED -> EVICTED (permanent removal)."""
        with self._lock:
            rec = self._records.get(node_id)
            if rec is None:
                raise KeyError(f"No admission record for node {node_id!r}")
            if rec.state not in (AdmissionState.ACTIVE, AdmissionState.SUSPENDED):
                raise InvalidAdmissionTransition(rec.state, AdmissionState.EVICTED)
            rec.state = AdmissionState.EVICTED
            rec.rejection_reason = reason
            logger.warning("Node %s evicted: %s", node_id, reason)
            return self._snapshot(rec)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, node_id: str) -> Optional[AdmissionRecord]:
        """Return a snapshot of the admission record, or None."""
        with self._lock:
            rec = self._records.get(node_id)
            if rec is None:
                return None
            return self._snapshot(rec)

    def get_by_state(self, state: AdmissionState) -> list[AdmissionRecord]:
        """Return snapshot copies of all records matching state."""
        with self._lock:
            return [self._snapshot(r) for r in self._records.values() if r.state is state]

    @property
    def m(self) -> int:
        return self._m

    @property
    def n(self) -> int:
        return self._n
