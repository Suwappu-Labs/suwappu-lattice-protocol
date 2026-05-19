"""
Sequence tracker — per-signer monotonic sequencing with chain binding and expiry.

Semantics:
  - Per-signer (by VK fingerprint) monotonic sequence enforcement
  - Chain binding: receipts are rejected if target_chain_id doesn't match
  - Temporal expiry: receipts with past valid_until are rejected
  - Batch validation for efficient bulk processing

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.5
"""

from __future__ import annotations

import time

from .domain import signer_fingerprint

__all__ = ["SequenceTracker"]


class SequenceTracker:
    """Per-signer monotonic sequence tracker with chain binding and expiry.

    Each signer (identified by VK fingerprint) maintains an independent
    sequence counter. Receipts must present strictly increasing sequence
    numbers, be bound to the correct chain, and not be expired.
    """

    def __init__(self, chain_id: str, default_expiry_seconds: float = 3600.0) -> None:
        """Initialize the tracker for a specific chain.

        Args:
            chain_id:               The chain this tracker is bound to
            default_expiry_seconds: Default expiry window (informational only)
        """
        self.chain_id = chain_id
        self.default_expiry_seconds = default_expiry_seconds
        # signer_fingerprint(vk) → highest accepted sequence number
        self._hwm: dict[bytes, int] = {}

    def validate_and_advance(
        self,
        signer_vk: bytes,
        sequence: int,
        target_chain_id: str,
        valid_until: float,
    ) -> tuple[bool, str]:
        """Validate a sequence number and advance the high-water mark if valid.

        Checks:
          1. target_chain_id matches this tracker's chain_id
          2. valid_until is in the future
          3. sequence > current high-water mark for this signer

        Returns:
            (True, "") if accepted, (False, reason) if rejected.
        """
        # Chain binding check
        if target_chain_id != self.chain_id:
            return False, f"chain mismatch: expected {self.chain_id}, got {target_chain_id}"

        # Temporal expiry check (RFC 8392: now >= exp fails)
        now = time.time()
        if now >= valid_until:
            return False, f"expired: valid_until={valid_until}, now={now}"

        # Monotonic sequence check
        fp = signer_fingerprint(signer_vk)
        current = self._hwm.get(fp, -1)
        if sequence <= current:
            return False, f"replay: sequence {sequence} <= current {current}"

        self._hwm[fp] = sequence
        return True, ""

    def validate_batch(
        self,
        items: list[tuple[bytes, int, str, float]],
    ) -> list[tuple[bool, str]]:
        """Validate a batch of (signer_vk, sequence, target_chain_id, valid_until).

        Each item is validated independently. Accepted items advance the HWM,
        so order matters — earlier items in the batch take priority.

        Returns: list of (ok, reason) tuples, one per input item.
        """
        results = []
        for signer_vk, sequence, target_chain_id, valid_until in items:
            results.append(
                self.validate_and_advance(signer_vk, sequence, target_chain_id, valid_until)
            )
        return results

    def next_sequence(self, signer_vk: bytes) -> int:
        """Return the next expected sequence number for a signer.

        Returns 0 if the signer has never been seen.
        """
        fp = signer_fingerprint(signer_vk)
        return self._hwm.get(fp, -1) + 1

    def current_sequence(self, signer_vk: bytes) -> int:
        """Return the current (last accepted) sequence number for a signer.

        Returns -1 if the signer has never been seen.
        """
        fp = signer_fingerprint(signer_vk)
        return self._hwm.get(fp, -1)
