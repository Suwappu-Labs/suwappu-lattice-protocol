"""Multi-VM execution layer (Gate 4, Specs B + C2)."""

from .types import OrderedBatch, BatchResult, TxResult, StateQuery, StateResult, OperationType, infer_operation_type
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
from .attestation import AttestationEngine, MultiVMAttestation, AttestationAggregator

# Writer Registry (Spec C2)
from .writer import (
    IdentityTier, WriterState, WriterIdentity, WriterRecord,
    ApprovalPath, TransitionEntry,
    VALID_WRITER_TRANSITIONS, TRANSACTABLE_STATES, validate_writer_transition,
)
from .writer_config import RegistryConfig, ProbationModifiers
from .writer_roles import (
    RegistryAction, ScopedPermission, RegistryRole, RoleAssignment,
    builtin_owner, builtin_admin, builtin_sponsor,
)
from .writer_registry import WriterRegistry
from .writer_policy import VMWriterPolicy, PolicyEngine, PolicyResult
from .writer_auth import AuthorizationResult, DispatchDecision, WriterAuthorizer
from .writer_recovery import (
    EmergencyAction, EmergencyIntervention, EmergencyState,
    PolicySnapshotStore, RecoveryQuorum,
)
from .writer_epoch import EpochTracker, check_expirations, promote_due_probations
from .writer_gate import WriterGate

__all__ = [
    # Execution layer (Spec B)
    "OrderedBatch", "BatchResult", "TxResult", "StateQuery", "StateResult", "OperationType",
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
    "AttestationEngine", "MultiVMAttestation", "AttestationAggregator",
    # Writer Registry (Spec C2)
    "IdentityTier", "WriterState", "WriterIdentity", "WriterRecord",
    "ApprovalPath", "TransitionEntry",
    "VALID_WRITER_TRANSITIONS", "TRANSACTABLE_STATES", "validate_writer_transition",
    "RegistryConfig", "ProbationModifiers",
    "RegistryAction", "ScopedPermission", "RegistryRole", "RoleAssignment",
    "builtin_owner", "builtin_admin", "builtin_sponsor",
    "WriterRegistry",
    "VMWriterPolicy", "PolicyEngine", "PolicyResult",
    "AuthorizationResult", "DispatchDecision", "WriterAuthorizer",
    "EmergencyAction", "EmergencyIntervention", "EmergencyState",
    "PolicySnapshotStore", "RecoveryQuorum",
    "EpochTracker", "check_expirations", "promote_due_probations",
    "WriterGate",
]
