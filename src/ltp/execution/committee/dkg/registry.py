"""DKG key registry — per-VM, per-epoch group key store (Spec C3b §7)."""

from __future__ import annotations

from typing import Optional

from .types import DKGResult

__all__ = ["DKGKeyRegistry"]


class DKGKeyRegistry:
    """Append-only store mapping epoch -> DKGResult for a single VM."""

    def __init__(self, vm_tag: int) -> None:
        self.vm_tag = vm_tag
        self._epochs: dict[int, DKGResult] = {}

    def store(self, result: DKGResult) -> None:
        if result.epoch in self._epochs:
            raise ValueError(
                f"epoch {result.epoch} already has a group key"
            )
        if result.vm_tag != self.vm_tag:
            raise ValueError(
                f"vm_tag mismatch: {result.vm_tag} != {self.vm_tag}"
            )
        self._epochs[result.epoch] = result

    def get(self, epoch: int) -> DKGResult:
        return self._epochs[epoch]

    def current(self) -> Optional[DKGResult]:
        if not self._epochs:
            return None
        return self._epochs[max(self._epochs)]

    def group_pk(self, epoch: int) -> bytes:
        return self.get(epoch).group_pk

    def has_epoch(self, epoch: int) -> bool:
        return epoch in self._epochs

    def epoch_count(self) -> int:
        return len(self._epochs)
