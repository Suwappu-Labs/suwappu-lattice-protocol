"""VMRegistry — pluggable registry of all active VM executors."""

from __future__ import annotations

from typing import Optional

from .model import ExecutionModel


class VMRegistry:
    """Register and look up VM executors by tag."""

    def __init__(self) -> None:
        self._executors: dict[int, ExecutionModel] = {}

    def register(self, executor: ExecutionModel) -> None:
        """Register an executor. Raises ValueError on duplicate tag."""
        tag = executor.vm_tag
        if tag in self._executors:
            existing = self._executors[tag]
            raise ValueError(
                f"VM tag 0x{tag:02X} already registered to '{existing.vm_name}'"
            )
        self._executors[tag] = executor

    def get(self, vm_tag: int) -> Optional[ExecutionModel]:
        """Look up an executor by VM tag. Returns None if not found."""
        return self._executors.get(vm_tag)

    def all_executors(self) -> list[ExecutionModel]:
        """Return all registered executors."""
        return list(self._executors.values())

    def active_tags(self) -> list[int]:
        """Return sorted list of all registered VM tags."""
        return sorted(self._executors.keys())

    def health_check(self) -> dict[int, bool]:
        """Poll each executor for liveness via state_root()."""
        status: dict[int, bool] = {}
        for tag, executor in self._executors.items():
            try:
                executor.state_root()
                status[tag] = True
            except Exception:
                status[tag] = False
        return status
