"""
WatcherService — off-chain verification daemon for the optimistic bridge.

Monitors on-chain anchors, verifies ML-DSA signatures off-chain, detects
STH forks, and submits fraud proofs to the ChallengeManager when violations
are detected.

Trust model: 1-of-n honest watchers — any single watcher can detect and
report fraud.

Follows the AnchorVerifier daemon pattern: start()/stop()/tick(), daemon
thread, epoch counter. tick() is public for deterministic testing.

"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from ..primitives import MLDSA

if TYPE_CHECKING:
    from ..merkle_log.sth import SignedTreeHead
    from .challenge import ChallengeManager
    from .fraud_proof import (
        InconsistentSTHFraudProof,
        InvalidSignatureFraudProof,
    )

__all__ = ["WatcherService", "STHStore", "WatcherTickResult"]

logger = logging.getLogger(__name__)


@dataclass
class WatcherTickResult:
    """Result of a single watcher verification epoch."""

    epoch: int
    anchors_checked: int = 0
    signatures_verified: int = 0
    signatures_invalid: int = 0
    fraud_proofs_submitted: int = 0
    forks_detected: int = 0
    error: str = ""


class STHStore:
    """In-memory store for Signed Tree Heads, keyed by (operator_vk, sequence).

    Used to detect equivocation (fork) attacks: two valid STHs at the
    same sequence with different roots from the same operator.
    """

    def __init__(self) -> None:
        # (operator_vk_hex, sequence) → SignedTreeHead
        self._store: dict[tuple[str, int], "SignedTreeHead"] = {}

    def record(self, sth: "SignedTreeHead") -> Optional["InconsistentSTHFraudProof"]:
        """Record an STH. Returns a fraud proof if a fork is detected, else None."""
        from .fraud_proof import InconsistentSTHFraudProof

        vk_hex = sth.operator_vk.hex()
        key = (vk_hex, sth.sequence)

        existing = self._store.get(key)
        if existing is not None:
            if existing.root_hash != sth.root_hash:
                logger.warning(
                    "STH FORK detected: operator=%s, seq=%d, root_a=%s, root_b=%s",
                    vk_hex[:16],
                    sth.sequence,
                    existing.root_hash.hex()[:16],
                    sth.root_hash.hex()[:16],
                )
                return InconsistentSTHFraudProof(sth_a=existing, sth_b=sth)
        else:
            self._store[key] = sth

        return None

    def get(self, operator_vk: bytes, sequence: int) -> Optional["SignedTreeHead"]:
        """Look up a stored STH."""
        return self._store.get((operator_vk.hex(), sequence))

    @property
    def size(self) -> int:
        return len(self._store)


class WatcherService:
    """Off-chain verification daemon for the optimistic bridge.

    Each tick():
      1. Receives a list of (anchor_digest, sth, record) to verify
      2. Verifies ML-DSA signature on each STH
      3. Checks STH consistency via STHStore (fork detection)
      4. Submits fraud proofs to ChallengeManager on violations

    The watcher does NOT interact with the blockchain directly —
    a higher-level coordinator feeds it anchor data (from an event
    listener or polling loop). This keeps the watcher pure and testable.
    """

    def __init__(
        self,
        challenge_manager: "ChallengeManager",
        sth_store: Optional[STHStore] = None,
        watcher_id: str = "watcher-0",
        interval_seconds: float = 60.0,
    ) -> None:
        self._challenge_manager = challenge_manager
        self._sth_store = sth_store or STHStore()
        self._watcher_id = watcher_id
        self._interval = interval_seconds

        # Pending verification queue: set by caller before tick()
        self._pending: list[dict] = []

        # Threading
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._epoch_lock = threading.Lock()
        self._epoch = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_for_verification(
        self,
        anchor_digest: bytes,
        sth: "SignedTreeHead",
        entity_id: str,
    ) -> None:
        """Queue an anchor for verification in the next tick."""
        self._pending.append(
            {
                "anchor_digest": anchor_digest,
                "sth": sth,
                "entity_id": entity_id,
            }
        )

    def tick(self, epoch: int) -> WatcherTickResult:
        """Execute a single verification epoch.

        Processes all pending anchors, verifies signatures and STH
        consistency, submits fraud proofs on violations.
        """
        result = WatcherTickResult(epoch=epoch)
        pending = list(self._pending)
        self._pending.clear()

        for item in pending:
            anchor_digest = item["anchor_digest"]
            sth = item["sth"]
            entity_id = item["entity_id"]
            result.anchors_checked += 1

            # 1. Verify ML-DSA signature on STH
            sig_valid = MLDSA.verify(
                sth.operator_vk,
                sth.signable_payload(),
                sth.signature,
            )
            result.signatures_verified += 1

            if not sig_valid:
                result.signatures_invalid += 1
                # Submit InvalidSignature fraud proof
                from .fraud_proof import InvalidSignatureFraudProof

                proof = InvalidSignatureFraudProof(
                    anchor_digest=anchor_digest,
                    claimed_signer_vk=sth.operator_vk,
                    signed_data=sth.signable_payload(),
                    signature=sth.signature,
                )
                try:
                    self._challenge_manager.submit_challenge(
                        entity_id,
                        proof,
                        challenger_id=self._watcher_id,
                    )
                    result.fraud_proofs_submitted += 1
                except (KeyError, ValueError) as e:
                    logger.warning("Watcher: failed to submit sig fraud proof: %s", e)
                continue

            # 2. Check STH consistency (fork detection)
            fork_proof = self._sth_store.record(sth)
            if fork_proof is not None:
                result.forks_detected += 1
                try:
                    self._challenge_manager.submit_challenge(
                        entity_id,
                        fork_proof,
                        challenger_id=self._watcher_id,
                    )
                    result.fraud_proofs_submitted += 1
                except (KeyError, ValueError) as e:
                    logger.warning("Watcher: failed to submit fork fraud proof: %s", e)

        return result

    def start(self) -> None:
        """Launch daemon thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name=f"watcher-{self._watcher_id}",
        )
        self._thread.start()
        logger.info("WatcherService[%s] started", self._watcher_id)

    def stop(self) -> None:
        """Signal shutdown and join thread."""
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 2)
            self._thread = None

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def running(self) -> bool:
        return self._running

    @property
    def sth_store(self) -> STHStore:
        return self._sth_store

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Periodic loop: verify pending anchors."""
        while self._running:
            with self._epoch_lock:
                self._epoch += 1
            try:
                self.tick(self._epoch)
            except Exception:
                logger.exception("WatcherService: error in epoch %d", self._epoch)
            if self._stop_event.wait(timeout=self._interval):
                break
