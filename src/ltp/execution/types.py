"""Core data types for the multi-VM execution layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


@dataclass(frozen=True)
class OrderedBatch:
    """Canonical batch of ordered transactions from any consensus engine."""

    round: int
    epoch: int
    transactions: list[bytes]
    leader_authority: int
    timestamp_ms: int
    consensus_type: str  # "dag" | "bft" | "hybrid"


@dataclass(frozen=True)
class TxResult:
    """Result of executing a single transaction."""

    success: bool
    gas_used: int = 0
    error: str = ""
    return_data: bytes = b""

    @classmethod
    def accepted(cls, gas_used: int = 0, return_data: bytes = b"") -> TxResult:
        return cls(success=True, gas_used=gas_used, return_data=return_data)

    @classmethod
    def rejected(cls, reason: str) -> TxResult:
        return cls(success=False, error=reason)

    @classmethod
    def failed(cls, reason: str, gas_used: int = 0) -> TxResult:
        return cls(success=False, error=reason, gas_used=gas_used)


@dataclass(frozen=True)
class StateQuery:
    """Family-aware cross-VM state query."""

    target_vm: int
    query_type: str  # "storage" | "object" | "account" | "utxo" | "contract"
    key: bytes


@dataclass(frozen=True)
class StateResult:
    """Response to a state query."""

    data: bytes
    found: bool

    @classmethod
    def not_found(cls) -> StateResult:
        return cls(data=b"", found=False)


@dataclass
class BatchResult:
    """Result of executing an entire OrderedBatch."""

    round: int
    tx_results: list[TxResult] = field(default_factory=list)
    state_root: object = None  # MultiVMStateRoot, set by router


class OperationType(Enum):
    """Types of operations a writer can perform on a VM (Spec C2 §6.1)."""

    TRANSFER = "transfer"
    DEPLOY = "deploy"
    CALL = "call"
    STATE_MODIFY = "state_modify"
    STATE_READ = "state_read"


# Operation type byte tags for gated transaction format:
# [writer_fp (32)] [vm_tag (1)] [op_type (1)] [payload]
# If op_type byte is absent or unrecognized, default to TRANSFER.
_OP_TYPE_BYTE: dict[int, OperationType] = {
    0x00: OperationType.TRANSFER,
    0x01: OperationType.DEPLOY,
    0x02: OperationType.CALL,
    0x03: OperationType.STATE_MODIFY,
    0x04: OperationType.STATE_READ,
}


def infer_operation_type(payload: bytes) -> OperationType:
    """Infer operation type from the first byte of payload.

    If the payload is empty or the byte is unrecognized, defaults to TRANSFER.
    """
    if len(payload) == 0:
        return OperationType.TRANSFER
    return _OP_TYPE_BYTE.get(payload[0], OperationType.TRANSFER)
