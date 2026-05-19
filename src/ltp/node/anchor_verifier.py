"""
AnchorVerifier — confirmation and finality tracking for on-chain anchors.

Polls SUBMITTED entities from the AnchorStatusTracker, queries transaction
receipts via the anchor client, and advances them through CONFIRMED →
FINALIZED.  Detects reverts (receipt status=0) and chain reorgs (block
number regression).

Follows the same daemon pattern as AuditScheduler and AnchorScheduler:
daemon thread, tick(), start()/stop(), epoch counter.

Scope boundary: verifier only.  No retry/re-submission of FAILED entities.
"""

from __future__ import annotations

import logging
import threading
import time as _time
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from .config import NodeConfig

if TYPE_CHECKING:
    from ..network.safe_network import SafeCommitmentNetwork
    from .anchor_status import AnchorStatusTracker

logger = logging.getLogger(__name__)

__all__ = ["AnchorVerifier", "AnchorVerifyResult", "reconcile_on_startup"]


@dataclass
class AnchorVerifyResult:
    """Result of a single verifier tick."""

    epoch: int
    submitted_checked: int = 0
    receipts_found: int = 0
    confirmed: int = 0
    finalized: int = 0
    failed: int = 0
    still_pending: int = 0
    errors: int = 0
    error: str = ""


class AnchorVerifier:
    """Background confirmation and finality tracker for on-chain anchors.

    Two-phase tick:
      Phase 1 — SUBMITTED → CONFIRMED (or FAILED on revert)
        Group SUBMITTED entities by tx_hash, query each receipt once,
        apply result to all entities sharing that hash.

      Phase 2 — CONFIRMED → FINALIZED (or FAILED on reorg)
        Check ``current_block - record.block_number`` against
        ``config.anchor_finality_depth``.

    An entity can traverse SUBMITTED → CONFIRMED → FINALIZED in a
    single tick if the receipt is already deep enough.
    """

    def __init__(
        self,
        client,  # duck-typed: get_tx_receipt(tx_hash), get_block_number()
        tracker: "AnchorStatusTracker",
        config: "NodeConfig",
        *,
        chain_label: str = "",
    ) -> None:
        self._client = client
        self._tracker = tracker
        self._config = config
        self._chain_label = chain_label or "default"

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
        # Guard: if operator set confirmation_depth but not finality_depth,
        # honour the legacy field so the setting isn't silently ignored.
        cd = self._config.anchor_confirmation_depth
        fd = self._config.anchor_finality_depth
        if cd != NodeConfig.anchor_confirmation_depth and fd == NodeConfig.anchor_finality_depth:
            logger.warning(
                "anchor_confirmation_depth=%d is set but anchor_finality_depth "
                "is at default (%d). Using confirmation_depth as finality_depth. "
                "Please migrate to anchor_finality_depth.",
                cd,
                fd,
            )
            self._config.anchor_finality_depth = cd
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name=f"anchor-verifier-{self._chain_label}",
        )
        self._thread.start()
        logger.info(
            "AnchorVerifier[%s] started (finality_depth=%d, interval=%.1fs)",
            self._chain_label,
            self._config.anchor_finality_depth,
            self._config.anchor_interval_seconds,
        )

    def stop(self) -> None:
        """Signal shutdown and join thread."""
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._config.anchor_interval_seconds + 2)
            self._thread = None

    def tick(self, epoch: int) -> AnchorVerifyResult:
        """Execute a single verification epoch (public for testing).

        Phase 1: SUBMITTED → CONFIRMED (or FAILED)
        Phase 2: CONFIRMED → FINALIZED (or FAILED)
        """
        result = AnchorVerifyResult(epoch=epoch)

        # --- Phase 1: SUBMITTED → CONFIRMED ---
        self._phase_confirm(result)

        # --- Phase 2: CONFIRMED → FINALIZED ---
        self._phase_finalize(result)

        return result

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def running(self) -> bool:
        return self._running

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
                logger.exception("AnchorVerifier: error in epoch %d", self._epoch)
            if self._stop_event.wait(timeout=self._config.anchor_interval_seconds):
                break

    def _phase_confirm(self, result: AnchorVerifyResult) -> None:
        """Phase 1: query receipts for SUBMITTED entities."""
        from .anchor_status import AnchorStatus

        submitted = self._tracker.get_by_status(AnchorStatus.SUBMITTED)
        result.submitted_checked = len(submitted)

        if not submitted:
            return

        # Group by tx_hash — batch entities share one hash
        by_tx: dict[str, list[str]] = defaultdict(list)
        for rec in submitted:
            by_tx[rec.tx_hash].append(rec.entity_id)

        for tx_hash, entity_ids in by_tx.items():
            try:
                receipt = self._client.get_tx_receipt(tx_hash)
            except Exception as exc:
                logger.warning(
                    "AnchorVerifier: receipt query failed for %s: %s",
                    tx_hash,
                    exc,
                )
                max_retries = self._config.anchor_max_rpc_retries
                for eid in entity_ids:
                    try:
                        count = self._tracker.increment_retry(eid)
                        if count >= max_retries:
                            self._tracker.mark_failed(
                                eid,
                                f"max RPC retries ({max_retries}) exceeded",
                            )
                            result.failed += 1
                        else:
                            result.errors += 1
                    except (KeyError, ValueError):
                        result.errors += 1
                continue

            if receipt is None:
                # Check for tx-not-mined timeout
                max_wait = self._config.anchor_max_wait_seconds
                for eid in entity_ids:
                    rec = self._tracker.get(eid)
                    if rec and (_time.time() - rec.submitted_at) > max_wait:
                        try:
                            self._tracker.mark_failed(eid, "tx_not_mined")
                            result.failed += 1
                        except (KeyError, ValueError):
                            pass
                    else:
                        result.still_pending += 1
                continue

            result.receipts_found += 1
            block_number = receipt.get("blockNumber", 0)
            gas_used = receipt.get("gasUsed", 0)
            status = receipt.get("status", 0)

            if status == 0:
                # Transaction reverted on-chain
                for eid in entity_ids:
                    try:
                        self._tracker.mark_failed(eid, "transaction reverted")
                        result.failed += 1
                    except (KeyError, ValueError):
                        pass
                continue

            # Receipt valid — mark CONFIRMED
            for eid in entity_ids:
                try:
                    self._tracker.mark_confirmed(eid, block_number, gas_used)
                    result.confirmed += 1
                except (KeyError, ValueError) as exc:
                    logger.warning("AnchorVerifier: confirm %s failed: %s", eid, exc)

    def _phase_finalize(self, result: AnchorVerifyResult) -> None:
        """Phase 2: check finality depth for CONFIRMED entities."""
        from .anchor_status import AnchorStatus

        confirmed = self._tracker.get_by_status(AnchorStatus.CONFIRMED)
        if not confirmed:
            return

        try:
            current_block = self._client.get_block_number()
        except Exception as exc:
            logger.error(
                "AnchorVerifier: block number query failed: %s",
                exc,
            )
            result.error = str(exc)
            return

        depth = self._config.anchor_finality_depth

        for rec in confirmed:
            confirmations = current_block - rec.block_number
            if confirmations >= depth:
                try:
                    self._tracker.mark_finalized(rec.entity_id)
                except (KeyError, ValueError) as exc:
                    logger.warning(
                        "AnchorVerifier: finalize %s failed: %s",
                        rec.entity_id,
                        exc,
                    )
                    continue
                result.finalized += 1
            elif confirmations < 0:
                try:
                    self._tracker.mark_failed(rec.entity_id, "chain reorg detected")
                except (KeyError, ValueError) as exc:
                    logger.warning(
                        "AnchorVerifier: reorg-fail %s failed: %s",
                        rec.entity_id,
                        exc,
                    )
                    continue
                result.failed += 1


def reconcile_on_startup(
    network: "SafeCommitmentNetwork",
    client,  # duck-typed: are_anchored(list[bytes]) → list[bool]
    tracker: "AnchorStatusTracker",
) -> int:
    """Re-populate the in-memory tracker from the commitment log + chain state.

    Called once during node bootstrap, before the verifier starts.
    Scans all commitment records, computes their anchor digests, and
    batch-checks the on-chain registry.  Already-anchored entities are
    inserted directly as FINALIZED; unanchored entities are ignored
    (the scheduler will pick them up on its next poll).

    Returns the number of entities reconciled (marked FINALIZED).
    """
    from ..domain import DOMAIN_ANCHOR_DIGEST, domain_hash_bytes

    records = network.records_since(0)
    if not records:
        return 0

    # Build mapping: anchor_digest → entity_id
    digest_to_entity: dict[bytes, str] = {}
    for entity_id, record in records:
        try:
            digest = domain_hash_bytes(DOMAIN_ANCHOR_DIGEST, record.to_bytes())
            digest_to_entity[digest] = entity_id
        except Exception as exc:
            logger.warning("reconcile_on_startup: skip %s: %s", entity_id, exc)

    if not digest_to_entity:
        return 0

    # Batch-check on-chain state
    digest_list = list(digest_to_entity.keys())
    try:
        anchored_flags = client.are_anchored(digest_list)
    except Exception as exc:
        logger.error("reconcile_on_startup: chain query failed: %s", exc)
        return 0

    reconciled = 0
    for digest, is_anchored in zip(digest_list, anchored_flags):
        if is_anchored:
            entity_id = digest_to_entity.get(digest)
            if entity_id and tracker.get(entity_id) is None:
                tracker.mark_pending(entity_id, digest)
                # Fast-forward through the lifecycle to FINALIZED
                tracker.mark_submitted(entity_id, "reconciled")
                tracker.mark_confirmed(entity_id, block_number=0, gas_used=0)
                tracker.mark_finalized(entity_id)
                reconciled += 1

    logger.info("reconcile_on_startup: %d entities reconciled from chain", reconciled)
    return reconciled
