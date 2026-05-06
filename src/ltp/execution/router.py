"""TransactionRouter — tag-based dispatch to VM executors."""

from __future__ import annotations

from .registry import VMRegistry
from .state_root import MultiVMStateRoot
from .types import BatchResult, OrderedBatch, TxResult


class ExecutorUnavailable(RuntimeError):
    """Raised when a registered VM executor can't produce a state root."""
    pass


class TransactionRouter:
    """Routes each transaction in an OrderedBatch to the correct executor.

    Execution order is sacred — consensus already ordered these
    transactions. The router executes them sequentially in exactly
    that order.
    """

    def __init__(self, registry: VMRegistry) -> None:
        self._registry = registry

    def execute_batch(self, batch: OrderedBatch) -> BatchResult:
        """Execute all transactions, then compute multi-VM state root."""
        results: list[TxResult] = []

        for tx_bytes in batch.transactions:
            if len(tx_bytes) == 0:
                results.append(TxResult.rejected("empty_transaction"))
                continue

            tag = tx_bytes[0]
            payload = tx_bytes[1:]
            executor = self._registry.get(tag)

            if executor is None:
                results.append(TxResult.rejected(f"unknown_vm_tag:0x{tag:02X}"))
                continue

            try:
                result = executor.execute(payload)
            except Exception as exc:
                result = TxResult.failed(f"execution_error:{exc}")
            results.append(result)

        # Collect state roots from all registered executors
        vm_roots: dict[int, bytes] = {}
        for executor in self._registry.all_executors():
            try:
                root = executor.state_root()
            except Exception as exc:
                raise ExecutorUnavailable(
                    f"executor '{executor.vm_name}' (0x{executor.vm_tag:02X}) "
                    f"unavailable: {exc}"
                ) from exc
            vm_roots[executor.vm_tag] = root

        state_root = MultiVMStateRoot(vm_roots=vm_roots, batch_round=batch.round)

        return BatchResult(
            round=batch.round,
            tx_results=results,
            state_root=state_root,
        )
