"""WriterGate — layered universal + per-VM enforcement (Spec C2 §9)."""
from __future__ import annotations
from typing import Optional
from .types import OperationType
from .writer import WriterRecord, TRANSACTABLE_STATES
from .writer_auth import AuthorizationResult, DispatchDecision, WriterAuthorizer
from .writer_config import RegistryConfig
from .writer_epoch import EpochTracker
from .writer_policy import PolicyEngine, PolicyResult, VMWriterPolicy
from .writer_recovery import EmergencyState
from .writer_registry import WriterRegistry

__all__ = ["WriterGate"]

WRITER_FP_SIZE = 32


class WriterGate:
    """Two-phase writer authorization gate (Spec C2 §9).

    Phase 1 (pre_dispatch): universal checks — tx length, registry frozen,
    writer state, VM frozen.
    Phase 2 (vm_authorize): per-VM — custom WriterAuthorizer or declarative
    PolicyEngine evaluation.
    """

    def __init__(self, registry: WriterRegistry,
                 emergency: Optional[EmergencyState] = None,
                 epoch_tracker: Optional[EpochTracker] = None,
                 config: Optional[RegistryConfig] = None) -> None:
        self._registry = registry
        self._emergency = emergency or EmergencyState()
        self._epoch = epoch_tracker or EpochTracker()
        self._policies: dict[int, VMWriterPolicy] = {}
        self._engine = PolicyEngine(config=config or registry.config)

    def set_policy(self, vm_tag: int, policy: VMWriterPolicy) -> None:
        self._policies[vm_tag] = policy

    def record_dispatch(self, writer_fp: bytes, vm_tag: int, epoch: int) -> None:
        """Increment the per-writer, per-VM tx counter after a successful dispatch."""
        self._epoch.increment(writer_fp, vm_tag, epoch)

    def pre_dispatch(self, tx_bytes: bytes) -> DispatchDecision:
        """Universal checks."""
        # 1. tx too short?
        if len(tx_bytes) < WRITER_FP_SIZE + 1:
            return DispatchDecision(allowed=False, reason="tx too short for writer gate")
        writer_fp = tx_bytes[:WRITER_FP_SIZE]
        vm_tag = tx_bytes[WRITER_FP_SIZE]
        # 2. Registry frozen?
        if self._emergency.is_registry_frozen:
            return DispatchDecision(allowed=False, reason="registry frozen")
        # 3. Writer exists?
        record = self._registry.lookup(writer_fp)
        if record is None:
            return DispatchDecision(allowed=False, reason="writer not found")
        # 4. Writer active/probation?
        if record.state not in TRANSACTABLE_STATES:
            return DispatchDecision(allowed=False, reason=f"writer not active (state={record.state.value})")
        # 5. VM frozen?
        if self._emergency.is_vm_frozen(vm_tag):
            return DispatchDecision(allowed=False, reason=f"VM 0x{vm_tag:02X} frozen")
        return DispatchDecision(allowed=True, writer_record=record)

    def vm_authorize(self, record: WriterRecord, executor: object,
                     operation: OperationType, tx_bytes: bytes) -> DispatchDecision:
        """Per-VM: custom authorizer or declarative policy."""
        vm_tag = getattr(executor, "vm_tag", None)
        bypassed = vm_tag is not None and self._emergency.is_authorizer_bypassed(vm_tag)
        # Custom authorizer?
        if not bypassed and isinstance(executor, WriterAuthorizer):
            result = executor.authorize_writer(record, operation, tx_bytes)
            return DispatchDecision(allowed=result.allowed, reason=result.reason,
                                    fee_multiplier=result.fee_multiplier, writer_record=record)
        # Declarative policy
        if vm_tag is not None and vm_tag in self._policies:
            policy = self._policies[vm_tag]
        else:
            policy = VMWriterPolicy(vm_tag=vm_tag or 0x00)
        fp = record.identity.fingerprint
        tx_count = self._epoch.get_tx_count(fp, vm_tag or 0x00)
        result_p = self._engine.evaluate(record, operation, policy, tx_count=tx_count)
        return DispatchDecision(allowed=result_p.allowed, reason=result_p.reason,
                                fee_multiplier=result_p.fee_multiplier, writer_record=record)
