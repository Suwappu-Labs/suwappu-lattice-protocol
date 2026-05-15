"""BatchExecutor — wraps TransactionRouter with catastrophic error capture (Spec D1c §3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import BatchResult

if TYPE_CHECKING:
    from .router import TransactionRouter
    from .types import OrderedBatch

__all__ = ["BatchExecutor"]


class BatchExecutor:
    """Wraps TransactionRouter. Catches exceptions as catastrophic failures."""

    def __init__(self, router: TransactionRouter) -> None:
        self._router = router
        self._catastrophic = False
        self._last_error: str | None = None

    def execute(self, batch: OrderedBatch) -> BatchResult:
        """Delegate to router. On exception: return empty BatchResult, flag catastrophic."""
        try:
            result = self._router.execute_batch(batch)
            self._catastrophic = False
            self._last_error = None
            return result
        except Exception as exc:
            self._catastrophic = True
            # Prefer the root cause message when the exception has a direct cause
            # (e.g. ExecutorUnavailable wraps the original executor exception).
            cause = exc.__cause__
            self._last_error = str(cause) if cause is not None else str(exc)
            return BatchResult(round=batch.round, tx_results=[], state_root=None)

    def last_was_catastrophic(self) -> bool:
        return self._catastrophic

    def last_error(self) -> str | None:
        return self._last_error
