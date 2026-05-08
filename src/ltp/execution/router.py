"""TransactionRouter — tag-based dispatch to VM executors."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from .registry import VMRegistry
from .state_root import MultiVMStateRoot
from .types import BatchResult, OperationType, OrderedBatch, TxResult, infer_operation_type
from .writer_gate import WRITER_FP_SIZE

if TYPE_CHECKING:
    from .writer_gate import WriterGate


class ExecutorUnavailable(RuntimeError):
    """Raised when a registered VM executor can't produce a state root."""
    pass


class TransactionRouter:
    """Routes each transaction in an OrderedBatch to the correct executor.

    Execution order is sacred — consensus already ordered these
    transactions. The router executes them sequentially in exactly
    that order.

    When a WriterGate is provided, every transaction is expected to carry
    a 32-byte writer fingerprint prefix followed by the vm_tag byte and
    payload.  The gate performs two-phase enforcement: pre_dispatch
    (universal checks) and vm_authorize (per-VM policy).

    When no gate is provided the router behaves exactly as before:
    tx_bytes[0] is the vm_tag and tx_bytes[1:] is the payload.
    """

    def __init__(self, registry: VMRegistry,
                 writer_gate: Optional[WriterGate] = None) -> None:
        self._registry = registry
        self._gate = writer_gate

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute_batch(self, batch: OrderedBatch) -> BatchResult:
        """Execute all transactions, then compute multi-VM state root."""
        results: list[TxResult] = []

        for tx_bytes in batch.transactions:
            if len(tx_bytes) == 0:
                results.append(TxResult.rejected("empty_transaction"))
                continue

            if self._gate is not None:
                result = self._execute_gated(tx_bytes, batch.epoch)
            else:
                result = self._execute_ungated(tx_bytes)

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute_ungated(self, tx_bytes: bytes) -> TxResult:
        """Original dispatch logic — no gate present."""
        tag = tx_bytes[0]
        payload = tx_bytes[1:]
        executor = self._registry.get(tag)

        if executor is None:
            return TxResult.rejected(f"unknown_vm_tag:0x{tag:02X}")

        try:
            return executor.execute(payload)
        except Exception as exc:
            return TxResult.failed(f"execution_error:{exc}")

    def _execute_gated(self, tx_bytes: bytes, epoch: int) -> TxResult:
        """Gate-enforced dispatch — writer fingerprint prefix expected."""
        assert self._gate is not None  # guaranteed by caller

        # Phase 1: universal checks (size, registry frozen, writer state, VM frozen)
        decision = self._gate.pre_dispatch(tx_bytes)
        if not decision.allowed:
            return TxResult.rejected(f"writer_gate:{decision.reason}")

        # Strip the writer fingerprint prefix to reach vm_tag + payload
        tag = tx_bytes[WRITER_FP_SIZE]
        payload = tx_bytes[WRITER_FP_SIZE + 1:]

        executor = self._registry.get(tag)
        if executor is None:
            return TxResult.rejected(f"unknown_vm_tag:0x{tag:02X}")

        # Phase 2: per-VM authorization
        operation = infer_operation_type(payload)
        vm_decision = self._gate.vm_authorize(
            decision.writer_record, executor, operation, payload
        )
        if not vm_decision.allowed:
            return TxResult.rejected(f"writer_gate:{vm_decision.reason}")

        try:
            result = executor.execute(payload)
        except Exception as exc:
            return TxResult.failed(f"execution_error:{exc}")

        # Increment epoch counter on successful dispatch
        if result.success:
            writer_fp = tx_bytes[:WRITER_FP_SIZE]
            self._gate.record_dispatch(writer_fp, tag, epoch)

        return result
