"""BridgeModule — wraps Gate 3 GatewayVMService as a system module (0xE0).

Gate 3's bridge gateway (Base Sepolia event relay → ML-DSA-65 attestation
→ SUWAPPU anchor) becomes one module within the execution layer. The existing
poll-mode continues to work; consensus-mode is added on top.
"""

from __future__ import annotations

from ...primitives import canonical_hash_bytes
from ..model import VM_TAG_BRIDGE
from ..types import StateQuery, StateResult, TxResult


class BridgeModule:
    """Bridge system module (tag 0xE0).

    Stub implementation for Gate 4. Maintains a state root derived
    from processed bridge operations. Future versions will wrap the
    actual GatewayVMService.
    """

    vm_tag = VM_TAG_BRIDGE
    vm_name = "bridge"
    family = "system"

    def __init__(self) -> None:
        self._state_root = canonical_hash_bytes(b"bridge-genesis-state")
        self._op_count = 0

    def execute(self, tx_bytes: bytes) -> TxResult:
        """Process a bridge operation."""
        self._op_count += 1
        self._state_root = canonical_hash_bytes(
            self._state_root + tx_bytes + self._op_count.to_bytes(8, "big")
        )
        return TxResult.accepted()

    def state_root(self) -> bytes:
        return self._state_root

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return len(tx_bytes) > 0

    def query_state(self, query: StateQuery) -> StateResult:
        return StateResult.not_found()
