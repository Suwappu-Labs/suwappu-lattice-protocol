"""Tests for WriterGate — layered universal + per-VM enforcement (Spec C2 §9)."""
from __future__ import annotations

import pytest

from src.ltp.execution.writer import (
    ApprovalPath,
    IdentityTier,
    WriterIdentity,
    WriterRecord,
    WriterState,
)
from src.ltp.execution.writer_auth import AuthorizationResult
from src.ltp.execution.writer_epoch import EpochTracker
from src.ltp.execution.writer_gate import WriterGate
from src.ltp.execution.writer_policy import VMWriterPolicy
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry
from src.ltp.execution.types import OperationType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ADMIN_FP = b"\xff" * 32


def _make_gate():
    """Create a WriterGate with fresh WriterRegistry, EmergencyState, EpochTracker."""
    reg = WriterRegistry()
    emergency = EmergencyState()
    epoch = EpochTracker()
    gate = WriterGate(registry=reg, emergency=emergency, epoch_tracker=epoch)
    return gate, reg, emergency, epoch


def _enroll_active(reg: WriterRegistry, fp: bytes = b"\xaa" * 32) -> WriterRecord:
    """Enroll and admin-approve a WriterIdentity with the given fingerprint."""
    identity = WriterIdentity(
        tier=IdentityTier.MLDSA,
        fingerprint=fp,
        mldsa_vk=b"\x01" * 32,
    )
    reg.enroll(identity, timestamp=1000)
    return reg.approve(fp, admin_fp=ADMIN_FP, timestamp=1001)


def _enroll_probation(reg: WriterRegistry, fp: bytes = b"\xbb" * 32) -> WriterRecord:
    """Enroll and sponsor a writer to PROBATION state."""
    identity = WriterIdentity(
        tier=IdentityTier.MLDSA,
        fingerprint=fp,
        mldsa_vk=b"\x02" * 32,
    )
    reg.enroll(identity, timestamp=1000)
    # Two sponsors to hit threshold=2
    reg.sponsor(fp, sponsor_fp=b"\x10" * 32, timestamp=1001)
    reg.sponsor(fp, sponsor_fp=b"\x11" * 32, timestamp=1002)
    return reg.lookup(fp)


def _make_tx(fp: bytes, vm_tag: int = 0x01, payload: bytes = b"data") -> bytes:
    """Build a well-formed gated transaction."""
    return fp + bytes([vm_tag]) + payload


# ---------------------------------------------------------------------------
# TestPreDispatch
# ---------------------------------------------------------------------------

class TestPreDispatch:
    def test_active_writer_allowed(self):
        gate, reg, _, _ = _make_gate()
        _enroll_active(reg, fp=b"\xaa" * 32)
        tx = _make_tx(b"\xaa" * 32, vm_tag=0x01)
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is True
        assert decision.writer_record is not None
        assert decision.writer_record.state == WriterState.ACTIVE

    def test_unknown_writer_rejected(self):
        gate, _, _, _ = _make_gate()
        # No writer enrolled — random fp
        tx = _make_tx(b"\xde" * 32, vm_tag=0x01)
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "not found" in decision.reason

    def test_pending_writer_rejected(self):
        gate, reg, _, _ = _make_gate()
        fp = b"\xcc" * 32
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA,
            fingerprint=fp,
            mldsa_vk=b"\x03" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        # Writer stays PENDING (not approved)
        tx = _make_tx(fp, vm_tag=0x01)
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "not active" in decision.reason
        assert "pending" in decision.reason

    def test_frozen_registry_rejected(self):
        gate, reg, emergency, _ = _make_gate()
        _enroll_active(reg, fp=b"\xaa" * 32)
        emergency.freeze_registry(actor_fp=ADMIN_FP, reason="drill", timestamp=9999)
        tx = _make_tx(b"\xaa" * 32, vm_tag=0x01)
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "registry frozen" in decision.reason

    def test_frozen_vm_rejected(self):
        gate, reg, emergency, _ = _make_gate()
        _enroll_active(reg, fp=b"\xaa" * 32)
        emergency.freeze_vm(vm_tag=0x01, actor_fp=ADMIN_FP, reason="incident", timestamp=9999)
        tx = _make_tx(b"\xaa" * 32, vm_tag=0x01)
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "VM 0x01 frozen" in decision.reason

    def test_probation_writer_allowed(self):
        gate, reg, _, _ = _make_gate()
        fp = b"\xbb" * 32
        _enroll_probation(reg, fp=fp)
        tx = _make_tx(fp, vm_tag=0x02)
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is True
        assert decision.writer_record.state == WriterState.PROBATION

    def test_short_tx_rejected(self):
        gate, _, _, _ = _make_gate()
        # 32 bytes is WRITER_FP_SIZE, but we need at least 33 (fp + 1 byte vm_tag)
        tx = b"\xaa" * 32  # exactly 32 bytes — missing vm_tag
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "too short" in decision.reason


# ---------------------------------------------------------------------------
# TestVMAuthorize
# ---------------------------------------------------------------------------

class TestVMAuthorize:
    def test_declarative_policy_allows_transfer(self):
        gate, reg, _, _ = _make_gate()
        fp = b"\xaa" * 32
        record = _enroll_active(reg, fp=fp)

        class SimpleExecutor:
            vm_tag = 0x01

        policy = VMWriterPolicy(vm_tag=0x01)
        gate.set_policy(0x01, policy)

        executor = SimpleExecutor()
        decision = gate.vm_authorize(record, executor, OperationType.TRANSFER, b"tx")
        assert decision.allowed is True
        assert decision.writer_record is record

    def test_custom_authorizer_rejects(self):
        gate, reg, _, _ = _make_gate()
        fp = b"\xaa" * 32
        record = _enroll_active(reg, fp=fp)

        class RejectingAuthorizer:
            vm_tag = 0x02

            def authorize_writer(self, writer, operation, tx_bytes):
                return AuthorizationResult(allowed=False, reason="custom rejection")

            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        executor = RejectingAuthorizer()
        decision = gate.vm_authorize(record, executor, OperationType.TRANSFER, b"tx")
        assert decision.allowed is False
        assert "custom rejection" in decision.reason

    def test_bypass_authorizer_falls_back_to_declarative_policy(self):
        gate, reg, emergency, _ = _make_gate()
        fp = b"\xaa" * 32
        record = _enroll_active(reg, fp=fp)

        class RejectingAuthorizer:
            vm_tag = 0x03

            def authorize_writer(self, writer, operation, tx_bytes):
                return AuthorizationResult(allowed=False, reason="should not be called")

            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        # Bypass the custom authorizer for vm_tag=0x03
        emergency.bypass_authorizer(vm_tag=0x03, actor_fp=ADMIN_FP, reason="test", timestamp=1)

        policy = VMWriterPolicy(vm_tag=0x03)
        gate.set_policy(0x03, policy)

        executor = RejectingAuthorizer()
        decision = gate.vm_authorize(record, executor, OperationType.TRANSFER, b"tx")
        # Declarative policy with defaults permits MLDSA TRANSFER
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# TestRouterIntegration
# ---------------------------------------------------------------------------

class FakeEVM:
    vm_tag = 0x01
    vm_name = "fake-evm"
    family = "account"

    def execute(self, tx_bytes):
        from src.ltp.execution.types import TxResult
        return TxResult.accepted(gas_used=21000)

    def state_root(self):
        return b"\xcc" * 32

    def validate_tx(self, tx_bytes):
        return True

    def query_state(self, query):
        from src.ltp.execution.types import StateResult
        return StateResult.not_found()


def _make_router(gate=None):
    from src.ltp.execution.registry import VMRegistry
    from src.ltp.execution.router import TransactionRouter
    reg = VMRegistry()
    reg.register(FakeEVM())
    return TransactionRouter(reg, writer_gate=gate)


def _make_ordered_batch(txs: list[bytes], round_num: int = 1):
    from src.ltp.execution.types import OrderedBatch
    return OrderedBatch(
        round=round_num,
        epoch=0,
        transactions=txs,
        leader_authority=0,
        timestamp_ms=1000,
        consensus_type="dag",
    )


class TestRouterIntegration:
    def test_router_without_gate_passthrough(self):
        """Original format (tag byte + payload) passes through unchanged when no gate."""
        router = _make_router(gate=None)
        batch = _make_ordered_batch([b"\x01hello"])
        result = router.execute_batch(batch)
        assert len(result.tx_results) == 1
        assert result.tx_results[0].success is True
        assert result.tx_results[0].gas_used == 21000

    def test_router_with_gate_rejects_unauthorized(self):
        """Gated format (fp + vm_tag + payload) with unknown writer is rejected."""
        gate, reg, _, _ = _make_gate()
        # Do NOT enroll any writer — unknown fingerprint
        router = _make_router(gate=gate)
        unknown_fp = b"\xde" * 32
        tx = unknown_fp + bytes([0x01]) + b"payload"
        batch = _make_ordered_batch([tx])
        result = router.execute_batch(batch)
        assert len(result.tx_results) == 1
        assert result.tx_results[0].success is False
        assert "writer_gate" in result.tx_results[0].error
        assert "not found" in result.tx_results[0].error

    def test_router_with_gate_allows_authorized(self):
        """Gated format with enrolled + approved writer is executed successfully."""
        gate, reg, _, _ = _make_gate()
        fp = b"\xaa" * 32
        _enroll_active(reg, fp=fp)
        router = _make_router(gate=gate)
        tx = fp + bytes([0x01]) + b"transfer_data"
        batch = _make_ordered_batch([tx])
        result = router.execute_batch(batch)
        assert len(result.tx_results) == 1
        assert result.tx_results[0].success is True
        assert result.tx_results[0].gas_used == 21000
