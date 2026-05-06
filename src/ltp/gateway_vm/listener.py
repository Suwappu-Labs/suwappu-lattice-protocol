"""EventListener — polls external chain for bridge events."""

from __future__ import annotations

import time
from typing import Callable

from .events import BridgeEvent


class EventListener:
    """Polls an external chain for bridge contract events.

    Uses injectable fetch_logs and get_block_number callables so the
    listener can be tested without a real RPC connection. In production,
    these are wired to web3.py event filter calls.
    """

    def __init__(
        self,
        source_chain_id: int,
        fetch_logs: Callable[[int, int], list[dict]],
        get_block_number: Callable[[], int],
        start_block: int = 0,
        finality_depth: int = 0,
    ) -> None:
        self._source_chain_id = source_chain_id
        self._fetch_logs = fetch_logs
        self._get_block_number = get_block_number
        self._cursor = start_block
        self._finality_depth = finality_depth

    @property
    def cursor(self) -> int:
        """Current block cursor position."""
        return self._cursor

    def poll(self) -> list[BridgeEvent]:
        """Fetch new bridge events since the last poll.

        Returns a list of BridgeEvent objects. Advances the internal
        cursor past the highest block seen.
        """
        current_block = self._get_block_number()
        # Only scan up to (current - finality_depth) so we never fetch
        # events that the validator will reject for insufficient finality.
        # This prevents the cursor from advancing past un-final events.
        safe_block = current_block - self._finality_depth
        if self._cursor > safe_block:
            return []

        raw_logs = self._fetch_logs(self._cursor, safe_block)
        events = []
        max_block = self._cursor

        for log in raw_logs:
            args = log.get("args", {})
            block_num = log.get("blockNumber", 0)
            event = BridgeEvent(
                source_chain_id=self._source_chain_id,
                bridge_contract=log.get("address", ""),
                tx_hash=log.get("transactionHash", ""),
                block_number=block_num,
                log_index=log.get("logIndex", 0),
                event_name=log.get("event", ""),
                sender=args.get("sender", ""),
                recipient=args.get("recipient", ""),
                payload_hash=args.get("payloadHash", ""),
                amount=args.get("amount", 0),
                nonce=args.get("nonce", 0),
                timestamp=time.time(),
            )
            events.append(event)
            if block_num > max_block:
                max_block = block_num

        # Advance cursor past the highest block processed
        if events:
            self._cursor = max_block + 1
        else:
            # No events found — advance cursor to avoid re-scanning
            self._cursor = safe_block + 1
        return events
