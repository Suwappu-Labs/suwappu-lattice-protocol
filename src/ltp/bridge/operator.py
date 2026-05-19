"""
BridgeOperatorService — persistent daemon for cross-chain bridging.

Polls the commitment log for new records, converts each to a BridgeMessage,
and calls LiveBridge.transfer() for cross-chain anchoring. Integrates
ChallengeManager.tick() for auto-finalization and optional WatcherService
for fraud detection.

Follows AnchorScheduler pattern: daemon thread, tick(), start()/stop(),
epoch counter. tick() is public for deterministic testing without threads.
"""

from __future__ import annotations

import logging
import threading
import time as _time
from dataclasses import dataclass, field
from typing import Optional

from .message import BridgeMessage

logger = logging.getLogger(__name__)

__all__ = ["BridgeOperatorService", "BridgeOperatorTickResult"]


@dataclass
class BridgeOperatorTickResult:
    """Result of a single operator tick."""

    epoch: int = 0
    records_polled: int = 0
    records_bridged: int = 0
    records_skipped: int = 0
    records_failed: int = 0
    retries_attempted: int = 0
    challenge_windows_ticked: int = 0
    error: str = ""


class BridgeOperatorService:
    """Persistent bridge operator daemon.

    Polls CommitmentLog (via SafeCommitmentNetwork.records_since()) for new
    records, converts each to a BridgeMessage, and calls LiveBridge.transfer()
    for cross-chain bridging.

    Follows AnchorScheduler pattern: daemon thread, tick(), start()/stop(),
    epoch counter. tick() is public for deterministic testing.
    """

    def __init__(
        self,
        network,
        live_bridge,
        *,
        operator_keypair=None,
        source_chain: str = "gsx_testnet",
        dest_chain: str = "base_sepolia",
        sender_address: str = "",
        recipient_address: str = "",
        interval_seconds: float = 30.0,
        max_retries: int = 3,
        challenge_manager=None,
        watcher_service=None,
        operator_id: str = "bridge-operator-0",
    ) -> None:
        if operator_keypair is None:
            raise TypeError("operator_keypair is required — bridge operations must be signed")
        self._operator_keypair = operator_keypair
        self._network = network
        self._bridge = live_bridge
        self._source_chain = source_chain
        self._dest_chain = dest_chain
        self._sender = sender_address
        self._recipient = recipient_address
        self._interval = interval_seconds
        self._max_retries = max_retries
        self._challenge_manager = challenge_manager
        self._watcher = watcher_service
        self._operator_id = operator_id

        # Poll position (mirrors AnchorScheduler._last_seen_index)
        self._last_seen_index: int = 0

        # Track bridged entity IDs (idempotency)
        self._bridged_entities: set[str] = set()

        # Retry queue: [(entity_id, record, attempt_count)]
        self._retry_queue: list[tuple[str, object, int]] = []

        # Nonce counter for BridgeMessages
        self._nonce: int = 0

        # Data lock for bridged_entities and retry_queue (thread safety)
        self._data_lock = threading.Lock()

        # Threading (mirrors AnchorScheduler exactly)
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
            name=f"bridge-operator-{self._operator_id}",
        )
        self._thread.start()
        logger.info(
            "BridgeOperatorService[%s] started (%s→%s, interval=%.1fs)",
            self._operator_id,
            self._source_chain,
            self._dest_chain,
            self._interval,
        )

    def stop(self) -> None:
        """Signal shutdown and join thread."""
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 5)
            self._thread = None
        logger.info(
            "BridgeOperatorService[%s] stopped (epoch=%d, bridged=%d)",
            self._operator_id,
            self._epoch,
            len(self._bridged_entities),
        )

    def tick(self) -> BridgeOperatorTickResult:
        """Execute a single operator epoch (public for testing).

        1. Process retry queue (failed records from previous ticks)
        2. Poll new records from the commitment log
        3. Convert each to BridgeMessage, call live_bridge.transfer()
        4. Tick challenge_manager for auto-finalization
        5. Return result with counts
        """
        with self._epoch_lock:
            self._epoch += 1
        result = BridgeOperatorTickResult(epoch=self._epoch)

        with self._data_lock:
            # --- 1. Process retry queue ---
            remaining_retries = []
            for entity_id, record, attempts in self._retry_queue:
                if attempts >= self._max_retries:
                    logger.warning(
                        "BridgeOperator: entity %s exceeded max retries (%d), dropping",
                        entity_id[:16],
                        self._max_retries,
                    )
                    result.records_failed += 1
                    continue
                result.retries_attempted += 1
                success = self._try_bridge(entity_id, record, result)
                if not success:
                    remaining_retries.append((entity_id, record, attempts + 1))
            self._retry_queue = remaining_retries

            # --- 2. Poll new records ---
            try:
                log = getattr(self._network, "log", self._network)
                new_records = log.records_since(self._last_seen_index)
            except Exception as exc:
                logger.error("BridgeOperator: poll failed: %s", exc)
                result.error = "poll failed"
                return result

            result.records_polled = len(new_records)

            # --- 3. Process each new record ---
            for entity_id, record in new_records:
                self._last_seen_index += 1

                # Idempotency: skip already-bridged entities
                if entity_id in self._bridged_entities:
                    result.records_skipped += 1
                    continue

                success = self._try_bridge(entity_id, record, result)
                if not success:
                    self._retry_queue.append((entity_id, record, 1))

        # --- 4. Tick challenge manager ---
        if self._challenge_manager is not None:
            try:
                finalized = self._challenge_manager.tick()
                result.challenge_windows_ticked = len(finalized) if finalized else 0
            except Exception:
                logger.exception("BridgeOperator: challenge tick failed")

        return result

    @property
    def running(self) -> bool:
        return self._running

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def last_seen_index(self) -> int:
        return self._last_seen_index

    @property
    def bridged_count(self) -> int:
        return len(self._bridged_entities)

    @property
    def retry_queue_size(self) -> int:
        return len(self._retry_queue)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Periodic loop: tick at configured interval."""
        while self._running:
            try:
                self.tick()
            except Exception:
                logger.exception("BridgeOperator: error in epoch %d", self._epoch)
            if self._stop_event.wait(timeout=self._interval):
                break

    def _try_bridge(self, entity_id: str, record, result: BridgeOperatorTickResult) -> bool:
        """Attempt to bridge a single entity. Returns True on success."""
        if self._bridge is None:
            logger.error(
                "BridgeOperator: live_bridge not configured, cannot bridge %s", entity_id[:16]
            )
            result.records_failed += 1
            return False

        self._nonce += 1
        message = self._record_to_bridge_message(entity_id, record)

        try:
            bridge_result = self._bridge.transfer(message)
        except Exception as exc:
            logger.warning(
                "BridgeOperator: transfer failed for %s: %s",
                entity_id[:16],
                exc,
            )
            result.records_failed += 1
            return False

        if bridge_result is None:
            logger.warning(
                "BridgeOperator: materialization failed for %s",
                entity_id[:16],
            )
            result.records_failed += 1
            return False

        self._bridged_entities.add(entity_id)
        result.records_bridged += 1
        logger.info(
            "BridgeOperator: bridged %s (L1 tx=%s)",
            entity_id[:16],
            bridge_result.l1_anchor_tx_hash[:16] if bridge_result.l1_anchor_tx_hash else "N/A",
        )
        return True

    def _record_to_bridge_message(self, entity_id: str, record) -> BridgeMessage:
        """Convert a CommitmentRecord to a BridgeMessage."""
        return BridgeMessage(
            msg_type="state_update",
            source_chain=self._source_chain,
            dest_chain=self._dest_chain,
            sender=self._sender,
            recipient=self._recipient,
            payload={
                "entity_id": entity_id,
                "content_hash": getattr(record, "content_hash", ""),
                "shard_map_root": getattr(record, "shard_map_root", ""),
            },
            nonce=self._nonce,
        )
