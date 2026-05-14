"""ConsensusNode — bridges NodeExecutor to ETPNode (Spec D1c §7)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .node_executor import NodeExecutor, RoundResult

__all__ = ["ConsensusNode"]


class ConsensusNode:
    """Thin bridge composing NodeExecutor with ETPNode for production deployment."""

    def __init__(self, node_executor: NodeExecutor, etp_node: object) -> None:
        self._executor = node_executor
        self._etp_node = etp_node
        self._running = False

    def start(self) -> None:
        self._executor.start()
        if hasattr(self._etp_node, "start"):
            self._etp_node.start()
        self._running = True

    def stop(self) -> None:
        self._executor.stop()
        if hasattr(self._etp_node, "stop"):
            self._etp_node.stop()
        self._running = False

    def on_round_complete(self, result: RoundResult) -> None:
        """Forward attestation to ETPNode's anchor pipeline."""
        if result.attestation is None or result.attestation.mode == "none":
            return
        if hasattr(self._etp_node, "anchor_state_root"):
            self._etp_node.anchor_state_root(
                result.attestation.state_root,
                result.attestation.bls_signature,
            )

    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        return self._executor.submit_transaction(tx_bytes)

    def is_running(self) -> bool:
        return self._running
