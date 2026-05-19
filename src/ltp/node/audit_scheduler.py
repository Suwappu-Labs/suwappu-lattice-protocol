"""
AuditScheduler — background PDP audit loop for connected peers.

Runs a daemon thread that periodically issues PDP challenges to remote
peers via CommitmentNetwork.audit_node_pdp(). Provides a tick() method
for deterministic testing without threads.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..commitment import CommitmentNetwork

logger = logging.getLogger(__name__)

__all__ = ["AuditScheduler"]


class AuditScheduler:
    """Background PDP audit loop for connected peers.

    Runs a daemon thread that periodically issues PDP challenges
    to remote peers via CommitmentNetwork.audit_node_pdp().
    When a node's strikes reach the strike_threshold, it is
    automatically evicted via CommitmentNetwork.auto_evict_if_needed().
    """

    def __init__(
        self,
        network: "CommitmentNetwork",
        local_node_id: str,
        interval_seconds: float = 60.0,
        strike_threshold: int = 3,
        auditor_rotation=None,
        max_response_seconds: float = 0.001,
    ) -> None:
        self._network = network
        self._local_node_id = local_node_id
        self._interval = interval_seconds
        self._strike_threshold = strike_threshold
        self._auditor_rotation = auditor_rotation
        self._max_response_seconds = max_response_seconds
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._epoch_lock = threading.Lock()
        self._epoch = 0

    def start(self) -> None:
        """Start daemon thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._audit_loop,
            daemon=True,
            name=f"audit-{self._local_node_id}",
        )
        self._thread.start()
        logger.info(
            "AuditScheduler started (interval=%.1fs, node=%s)",
            self._interval,
            self._local_node_id,
        )

    def stop(self) -> None:
        """Signal shutdown and join thread."""
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 2)
            self._thread = None

    def _audit_loop(self) -> None:
        """Periodic loop: audit each remote peer."""
        while self._running:
            with self._epoch_lock:
                self._epoch += 1
            try:
                self.tick(self._epoch)
            except Exception:
                logger.exception("AuditScheduler: error in epoch %d", self._epoch)
            if self._stop_event.wait(timeout=self._interval):
                break

    def tick(self, epoch: int) -> list[dict]:
        """Manual single-epoch audit (for testing). Returns results."""
        results = []
        # Snapshot node list to avoid mutation during iteration
        nodes = list(self._network.nodes)

        # Determine which nodes this auditor should check
        if self._auditor_rotation is not None:
            all_node_ids = [n.node_id for n in nodes if not n.evicted]
            assignments = self._auditor_rotation.audit_assignments(epoch, all_node_ids)
            my_targets = set(assignments.get(self._local_node_id, []))
        else:
            my_targets = None  # Audit all (legacy behavior)

        for node in nodes:
            if node.node_id == self._local_node_id:
                continue
            if node.evicted:
                continue
            # If rotation is active, only audit assigned targets
            if my_targets is not None and node.node_id not in my_targets:
                continue
            try:
                result = self._network.audit_node_pdp(node, epoch)
                results.append(result)
                if result.get("failed", 0) > 0:
                    logger.warning(
                        "AuditScheduler: node %s FAILED PDP audit (epoch %d, strikes=%d)",
                        node.node_id,
                        epoch,
                        node.strikes,
                    )
                    # Auto-evict if strike threshold reached
                    eviction = self._network.auto_evict_if_needed(
                        node,
                        strike_threshold=self._strike_threshold,
                    )
                    if eviction is not None:
                        logger.warning(
                            "AuditScheduler: node %s AUTO-EVICTED (strikes=%d, repaired=%d, lost=%d)",
                            node.node_id,
                            node.strikes,
                            eviction.get("repaired", 0),
                            eviction.get("lost", 0),
                        )
                        result["eviction"] = eviction
            except Exception as e:
                logger.warning("AuditScheduler: audit of %s failed: %s", node.node_id, e)
                results.append(
                    {
                        "node_id": node.node_id,
                        "result": "ERROR",
                        "error": str(e),
                    }
                )
        return results

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def running(self) -> bool:
        return self._running
