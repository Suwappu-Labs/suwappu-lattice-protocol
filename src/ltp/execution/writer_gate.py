"""WriterGate — layered universal + per-VM enforcement (Spec C2 §9)."""
from __future__ import annotations
from typing import Optional
from .types import OperationType
from .writer import WriterRecord, TRANSACTABLE_STATES
from .writer_auth import AuthorizationResult, DispatchDecision, WriterAuthorizer
from .writer_config import RegistryConfig
from .writer_epoch import EpochTracker
from .writer_policy import PolicyEngine, PolicyResult, VMWriterPolicy
from .writer_recovery import EmergencyState, PolicySnapshotStore
from .writer_registry import WriterRegistry

__all__ = ["WriterGate"]

WRITER_FP_SIZE = 32


class WriterGate:
    """Two-phase writer authorization gate (Spec C2 §9).

    Phase 1 (pre_dispatch): universal checks — tx length, registry frozen,
    writer state, VM frozen, dispatch overrides.
    Phase 2 (vm_authorize): per-VM — custom WriterAuthorizer or declarative
    PolicyEngine evaluation.
    """

    def __init__(self, registry: WriterRegistry,
                 emergency: Optional[EmergencyState] = None,
                 epoch_tracker: Optional[EpochTracker] = None,
                 config: Optional[RegistryConfig] = None,
                 snapshot_store: Optional[PolicySnapshotStore] = None) -> None:
        self._registry = registry
        self._emergency = emergency or EmergencyState()
        self._epoch = epoch_tracker or EpochTracker()
        self._policies: dict[int, VMWriterPolicy] = {}
        self._engine = PolicyEngine(config=config or registry.config)
        self._snapshots = snapshot_store or PolicySnapshotStore()

    def set_policy(self, vm_tag: int, policy: VMWriterPolicy) -> None:
        self._snapshots.snapshot(vm_tag, policy, 0)
        self._policies[vm_tag] = policy

    def rollback_policy(self, vm_tag: int, version: int) -> VMWriterPolicy:
        """Rollback a VM's policy to a previous snapshot version."""
        policy = self._snapshots.rollback(vm_tag, version)
        self._policies[vm_tag] = policy
        return policy

    def record_dispatch(self, writer_fp: bytes, vm_tag: int, epoch: int) -> None:
        """Increment the per-writer, per-VM tx counter after a successful dispatch."""
        self._epoch.increment(writer_fp, vm_tag, epoch)

    def pre_dispatch(self, tx_bytes: bytes) -> DispatchDecision:
        """Universal checks (Spec C2 §9.2)."""
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
        # 5. Dispatch override? (force-allow or force-block)
        override = self._emergency.get_dispatch_override(writer_fp)
        if override is not None:
            if override:
                return DispatchDecision(allowed=True, writer_record=record)
            return DispatchDecision(allowed=False, reason="dispatch override: blocked")
        # 6. VM frozen?
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
        tag = vm_tag or 0x00
        tx_count = self._epoch.get_tx_count(fp, tag)
        writer_count = len(self._registry.active_writers())
        result_p = self._engine.evaluate(record, operation, policy,
                                         tx_count=tx_count, writer_count=writer_count)
        return DispatchDecision(allowed=result_p.allowed, reason=result_p.reason,
                                fee_multiplier=result_p.fee_multiplier, writer_record=record)
