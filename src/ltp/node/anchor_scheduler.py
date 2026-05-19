"""
AnchorScheduler — batch submission pipeline for on-chain anchoring.

Polls the commitment log for new records, converts them to AnchorSubmission
payloads, and batch-submits to the on-chain LTPAnchorRegistry via an
AnchorClient (or duck-typed mock).

Follows the AuditScheduler pattern: daemon thread, tick(), start()/stop(),
epoch counter.  The tick() method is public for deterministic testing
without threads.

Scope boundary: this scheduler goes up to SUBMITTED status only.
Confirmation tracking (CONFIRMED → FINALIZED) is handled by AnchorVerifier.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ..anchor.submission import AnchorSubmission
from ..domain import DOMAIN_ANCHOR_DIGEST, domain_hash_bytes, signer_fingerprint
from ..primitives import canonical_hash_bytes

if TYPE_CHECKING:
    from ..network.safe_network import SafeCommitmentNetwork
    from .anchor_status import AnchorStatusTracker
    from .config import NodeConfig

logger = logging.getLogger(__name__)

__all__ = ["AnchorScheduler", "AnchorTickResult"]


@dataclass
class AnchorTickResult:
    """Result of a single scheduler tick."""

    epoch: int
    records_polled: int = 0
    records_queued: int = 0
    records_skipped: int = 0
    batch_submitted: bool = False
    batch_size: int = 0
    tx_hash: str = ""
    error: str = ""
    pending_batch_size: int = 0


class AnchorScheduler:
    """Background batch submission pipeline for on-chain anchoring.

    Polls ``SafeCommitmentNetwork.records_since()`` for new commitment
    records, converts them to ``AnchorSubmission`` payloads, and
    batch-submits via the configured anchor client.

    Batch triggers (whichever fires first):
      1. ``len(pending_batch) >= config.anchor_batch_size``
      2. ``time.monotonic() - oldest_pending >= config.anchor_max_wait_seconds``
    """

    def __init__(
        self,
        network: "SafeCommitmentNetwork",
        client,  # AnchorClient or duck-typed mock — must have batch_anchor()
        tracker: "AnchorStatusTracker",
        config: "NodeConfig",
        *,
        signer_vk: bytes = b"",
        chain_label: str = "",
        chain_id: int = 0,
    ) -> None:
        self._network = network
        self._client = client
        self._tracker = tracker
        self._config = config
        self._signer_vk = signer_vk
        self._chain_label = chain_label or str(chain_id) or "default"
        self._chain_id = chain_id

        # Poll position
        self._last_seen_index: int = 0

        # Batch accumulator: list of (entity_id, AnchorSubmission)
        self._pending_batch: list[tuple[str, AnchorSubmission]] = []
        self._batch_oldest_at: Optional[float] = None

        # Per-signer monotonic sequence counters
        self._signer_sequences: dict[bytes, int] = {}

        # Threading
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._epoch_lock = threading.Lock()
        self._epoch = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Launch daemon thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name=f"anchor-scheduler-{self._chain_label}",
        )
        self._thread.start()
        logger.info(
            "AnchorScheduler[%s] started (batch_size=%d, max_wait=%.1fs)",
            self._chain_label,
            self._config.anchor_batch_size,
            self._config.anchor_max_wait_seconds,
        )

    def stop(self) -> None:
        """Signal shutdown and join thread."""
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._config.anchor_interval_seconds + 2)
            self._thread = None

    def tick(self, epoch: int) -> AnchorTickResult:
        """Execute a single scheduler epoch (public for testing).

        1. Poll new records from the commitment log
        2. Convert to AnchorSubmission, mark PENDING in tracker
        3. Check batch triggers (size or max_wait)
        4. If triggered, submit batch via client
        """
        result = AnchorTickResult(epoch=epoch)

        # --- 1. Poll new records ---
        try:
            new_records = self._network.records_since(self._last_seen_index)
        except Exception as exc:
            logger.error("AnchorScheduler: poll failed: %s", exc)
            result.error = "poll failed (see logs)"
            result.pending_batch_size = len(self._pending_batch)
            return result

        result.records_polled = len(new_records)

        # --- 2. Convert each record ---
        for entity_id, record in new_records:
            self._last_seen_index += 1

            # Idempotency: skip if tracker already knows this entity
            if self._tracker.get(entity_id) is not None:
                result.records_skipped += 1
                continue

            try:
                submission = self._record_to_submission(entity_id, record)
            except Exception as exc:
                logger.warning("AnchorScheduler: skipping record %s: %s", entity_id, exc)
                continue

            self._tracker.mark_pending(
                entity_id,
                submission.anchor_digest,
                chain_id=self._chain_id,
            )
            self._pending_batch.append((entity_id, submission))
            if self._batch_oldest_at is None:
                self._batch_oldest_at = time.monotonic()
            result.records_queued += 1

        # --- 3. Check batch triggers ---
        should_submit = False
        if len(self._pending_batch) >= self._config.anchor_batch_size:
            should_submit = True
        elif (
            self._pending_batch
            and self._batch_oldest_at is not None
            and (time.monotonic() - self._batch_oldest_at) >= self._config.anchor_max_wait_seconds
        ):
            should_submit = True

        # --- 4. Submit if triggered ---
        if should_submit:
            self._submit_batch(result)

        result.pending_batch_size = len(self._pending_batch)
        return result

    def seed_sequence(self, vk_hash: bytes, on_chain_seq: int) -> None:
        """Bootstrap a signer's sequence counter from on-chain state."""
        self._signer_sequences[vk_hash] = on_chain_seq

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def running(self) -> bool:
        return self._running

    @property
    def last_seen_index(self) -> int:
        return self._last_seen_index

    @property
    def pending_batch_size(self) -> int:
        return len(self._pending_batch)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Periodic loop: poll + submit."""
        while self._running:
            with self._epoch_lock:
                self._epoch += 1
            try:
                self.tick(self._epoch)
            except Exception:
                logger.exception("AnchorScheduler: error in epoch %d", self._epoch)
            if self._stop_event.wait(timeout=self._config.anchor_interval_seconds):
                break

    def _record_to_submission(self, entity_id: str, record) -> AnchorSubmission:
        """Convert a CommitmentRecord to an AnchorSubmission."""
        # anchor_digest: domain-separated SHA3-256 of the full record bytes
        anchor_digest = domain_hash_bytes(DOMAIN_ANCHOR_DIGEST, record.to_bytes())

        # entity_id_hash: canonical SHA3-256 of the entity ID
        entity_id_hash = canonical_hash_bytes(entity_id.encode())

        # merkle_root: strip "sha3-256:" prefix, decode hex to raw 32 bytes
        root_str = record.shard_map_root
        if ":" in root_str:
            root_str = root_str.split(":", 1)[1]
        merkle_root = bytes.fromhex(root_str)

        # policy_hash: sentinel zero (no SignerPolicy in commitment path)
        policy_hash = b"\x00" * 32

        # signer_vk_hash: fingerprint of the record's sender VK
        vk = record.sender_vk if record.sender_vk else self._signer_vk
        signer_vk_hash = signer_fingerprint(vk)

        # sequence: per-signer monotonic counter
        sequence = self._next_sequence(signer_vk_hash)

        # valid_until: 1-hour validity window
        valid_until = int(time.time()) + 3600

        return AnchorSubmission(
            anchor_digest=anchor_digest,
            entity_id_hash=entity_id_hash,
            merkle_root=merkle_root,
            policy_hash=policy_hash,
            signer_vk_hash=signer_vk_hash,
            sequence=sequence,
            valid_until=valid_until,
            target_chain_id=self._config.anchor_chain_id,
            receipt_type="COMMIT",
        )

    def _next_sequence(self, vk_hash: bytes) -> int:
        """Increment and return the next sequence number for a signer."""
        current = self._signer_sequences.get(vk_hash, 0)
        next_seq = current + 1
        self._signer_sequences[vk_hash] = next_seq
        return next_seq

    def _submit_batch(self, result: AnchorTickResult) -> None:
        """Submit the pending batch via the anchor client."""
        batch = list(self._pending_batch)
        entity_ids = [eid for eid, _ in batch]
        submissions = [sub for _, sub in batch]

        # Snapshot sequence counters for rollback on failure
        seq_snapshot: dict[bytes, int] = {}
        for _, sub in batch:
            if sub.signer_vk_hash not in seq_snapshot:
                # Record the value *before* this batch incremented it
                seq_snapshot[sub.signer_vk_hash] = self._signer_sequences.get(
                    sub.signer_vk_hash, 0
                ) - sum(1 for _, s in batch if s.signer_vk_hash == sub.signer_vk_hash)

        result.batch_size = len(submissions)

        try:
            tx_hash = self._client.batch_anchor(submissions)
            result.batch_submitted = True
            result.tx_hash = tx_hash

            # Mark all entities SUBMITTED
            for eid in entity_ids:
                self._tracker.mark_submitted(eid, tx_hash)

            logger.info(
                "AnchorScheduler[%s]: batch submitted (%d records, tx=%s)",
                self._chain_label,
                len(submissions),
                tx_hash,
            )
        except Exception as exc:
            result.error = "batch submission failed (see logs)"
            logger.error("AnchorScheduler: batch submission failed: %s", exc)

            # Mark all entities FAILED — redact RPC details from tracker
            for eid in entity_ids:
                try:
                    self._tracker.mark_failed(eid, "batch submission failed")
                except (KeyError, ValueError):
                    pass  # Already transitioned or missing

            # Roll back sequence counters
            for vk_hash, pre_batch_seq in seq_snapshot.items():
                self._signer_sequences[vk_hash] = pre_batch_seq

        # Always clear the batch buffer
        self._pending_batch.clear()
        self._batch_oldest_at = None
