"""Multi-VM execution layer (Gate 4, Spec B)."""

from .types import OrderedBatch, BatchResult, TxResult, StateQuery, StateResult
from .model import (
    ExecutionModel, family_from_tag,
    VM_TAG_EVM, VM_TAG_TVM, VM_TAG_MOVE, VM_TAG_SVM,
    VM_TAG_BITCOIN, VM_TAG_PLUTUS, VM_TAG_CANTON,
    VM_TAG_BRIDGE, VM_TAG_PRECOMPILE,
    VM_FAMILY_ACCOUNT, VM_FAMILY_OBJECT, VM_FAMILY_REGISTER,
    VM_FAMILY_UTXO, VM_FAMILY_LEDGER_NATIVE, VM_FAMILY_SYSTEM,
    FAMILY_NAMES,
)
from .registry import VMRegistry
from .router import TransactionRouter, ExecutorUnavailable
from .state_root import MultiVMStateRoot
from .precompile import CrossVMPrecompile, PrecompileResult
from .consensus import ConsensusAdapter, FakeConsensusAdapter
from .attestation import AttestationEngine, MultiVMAttestation

__all__ = [
    "OrderedBatch", "BatchResult", "TxResult", "StateQuery", "StateResult",
    "ExecutionModel", "family_from_tag",
    "VM_TAG_EVM", "VM_TAG_TVM", "VM_TAG_MOVE", "VM_TAG_SVM",
    "VM_TAG_BITCOIN", "VM_TAG_PLUTUS", "VM_TAG_CANTON",
    "VM_TAG_BRIDGE", "VM_TAG_PRECOMPILE",
    "VM_FAMILY_ACCOUNT", "VM_FAMILY_OBJECT", "VM_FAMILY_REGISTER",
    "VM_FAMILY_UTXO", "VM_FAMILY_LEDGER_NATIVE", "VM_FAMILY_SYSTEM",
    "FAMILY_NAMES",
    "VMRegistry",
    "TransactionRouter", "ExecutorUnavailable",
    "MultiVMStateRoot",
    "CrossVMPrecompile", "PrecompileResult",
    "ConsensusAdapter", "FakeConsensusAdapter",
    "AttestationEngine", "MultiVMAttestation",
]
