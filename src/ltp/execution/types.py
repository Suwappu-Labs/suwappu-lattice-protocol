"""Core data types for the multi-VM execution layer."""

from __future__ import annotations

from dataclasses import dataclass, field


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
