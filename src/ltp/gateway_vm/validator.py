"""EventValidator — 12-point validation checklist for bridge events."""

from __future__ import annotations

from typing import Callable, Optional

from .config import GatewayVMConfig
from .events import BridgeEvent
from .finality import FinalityWatcher
from .replay import ReplayDB


class EventValidator:
    """Validates bridge events against the gateway's 12-point checklist.

    Each check returns early on failure with a reason string. All checks
    must pass for the event to be accepted.

    Injectable dependencies (get_block_number, is_signer_authorized) allow
    deterministic testing without real RPC connections.
    """

    def __init__(
        self,
        config: GatewayVMConfig,
        replay_db: ReplayDB,
        get_block_number: Callable[[], int],
        is_signer_authorized: Callable[[], bool],
        finality_watcher: Optional[FinalityWatcher] = None,
    ) -> None:
        self._config = config
        self._replay_db = replay_db
        self._get_block_number = get_block_number
        self._is_signer_authorized = is_signer_authorized
        self._finality = finality_watcher or FinalityWatcher(
            finality_depth=config.finality_depth,
            get_block_number=get_block_number,
        )

    def validate(self, event: BridgeEvent) -> tuple[bool, str]:
        """Run all validation checks. Returns (True, "") or (False, reason)."""

        # 1. Source chain ID matches expected
        if event.source_chain_id != self._config.source_chain_id:
            return False, (
                f"chain mismatch: expected {self._config.source_chain_id}, "
                f"got {event.source_chain_id}"
            )

        # 2. Bridge contract address is authorized
        if event.bridge_contract.lower() != self._config.source_bridge_contract.lower():
            return False, (
                f"unauthorized contract: expected "
                f"{self._config.source_bridge_contract}, got {event.bridge_contract}"
            )

        # 3. Event name is non-empty (ABI signature check placeholder)
        if not event.event_name:
            return False, "empty event name"

        # 4. Transaction hash is non-empty
        if not event.tx_hash:
            return False, "empty transaction hash"

        # 5-6. Finality depth threshold met (delegates to FinalityWatcher)
        is_final, depth, required = self._finality.check(event.block_number)
        if not is_final:
            if depth < 0:
                return False, (
                    f"reorg detected: event block {event.block_number} "
                    f"is {abs(depth)} blocks ahead of chain head"
                )
            return False, (f"insufficient finality: depth {depth}, required {required}")

        # 7. Replay status — event not already processed
        if self._replay_db.is_processed(event.event_id):
            return False, f"replay: event {event.event_id[:32]}... already processed"

        # 8. Authorized signer status
        if not self._is_signer_authorized():
            return False, "gateway signer not authorized on devnet"

        # 9. Payload hash is well-formed
        if not event.payload_hash:
            return False, "empty payload hash"

        # 10. Payload hash format check (must be algo-prefixed)
        if ":" not in event.payload_hash:
            return False, f"malformed payload hash: missing algo prefix in {event.payload_hash}"

        # 11. Source/destination routing (sender and recipient non-empty)
        if not event.sender or not event.recipient:
            return False, "missing sender or recipient address"

        # 12. Block number sanity (must be positive)
        if event.block_number <= 0:
            return False, f"invalid block number: {event.block_number}"

        return True, ""
