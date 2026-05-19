"""Tests for VMWriterPolicy and PolicyEngine (Spec C2 §6)."""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(tier_str: str = "mldsa", state_str: str = "active"):
    from src.ltp.execution.writer import (
        ApprovalPath,
        IdentityTier,
        WriterIdentity,
        WriterRecord,
        WriterState,
    )

    tier = IdentityTier(tier_str)
    identity = WriterIdentity(
        tier=tier,
        fingerprint=b"\xaa" * 32,
        mldsa_vk=b"\x01" * 32 if tier_str != "bls" else None,
        bls_pk=b"\x02" * 48 if tier_str != "mldsa" else None,
    )
    return WriterRecord(
        identity=identity,
        state=WriterState(state_str),
        approval_path=ApprovalPath.ADMIN,
        enrolled_at=1000,
    )


def _make_record_fp(tier_str: str = "mldsa", fingerprint: bytes = b"\xaa" * 32):
    """Make a record with a custom fingerprint."""
    from src.ltp.execution.writer import (
        ApprovalPath,
        IdentityTier,
        WriterIdentity,
        WriterRecord,
        WriterState,
    )

    tier = IdentityTier(tier_str)
    identity = WriterIdentity(
        tier=tier,
        fingerprint=fingerprint,
        mldsa_vk=b"\x01" * 32 if tier_str != "bls" else None,
        bls_pk=b"\x02" * 48 if tier_str != "mldsa" else None,
    )
    return WriterRecord(
        identity=identity,
        state=WriterState.ACTIVE,
        approval_path=ApprovalPath.ADMIN,
        enrolled_at=1000,
    )


# ---------------------------------------------------------------------------
# TestOperationType
# ---------------------------------------------------------------------------


class TestOperationType:
    def test_five_operations_exist(self):
        from src.ltp.execution.types import OperationType

        values = {op.value for op in OperationType}
        assert values == {"transfer", "deploy", "call", "state_modify", "state_read"}

    def test_transfer(self):
        from src.ltp.execution.types import OperationType

        assert OperationType.TRANSFER.value == "transfer"

    def test_deploy(self):
        from src.ltp.execution.types import OperationType

        assert OperationType.DEPLOY.value == "deploy"

    def test_call(self):
        from src.ltp.execution.types import OperationType

        assert OperationType.CALL.value == "call"

    def test_state_read(self):
        from src.ltp.execution.types import OperationType

        assert OperationType.STATE_READ.value == "state_read"


# ---------------------------------------------------------------------------
# TestVMWriterPolicyDefaults
# ---------------------------------------------------------------------------


class TestVMWriterPolicyDefaults:
    def test_all_tiers_allowed_by_default(self):
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=1)
        assert IdentityTier.MLDSA in policy.allowed_tiers
        assert IdentityTier.BLS in policy.allowed_tiers
        assert IdentityTier.COMPOSITE in policy.allowed_tiers

    def test_bls_restricted_to_transfer_and_state_read(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=1)
        bls_ops = policy.tier_operations[IdentityTier.BLS]
        assert bls_ops == {OperationType.TRANSFER, OperationType.STATE_READ}

    def test_mldsa_has_all_operations(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=1)
        mldsa_ops = policy.tier_operations[IdentityTier.MLDSA]
        assert mldsa_ops == set(OperationType)

    def test_composite_has_all_operations(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=1)
        composite_ops = policy.tier_operations[IdentityTier.COMPOSITE]
        assert composite_ops == set(OperationType)

    def test_default_fee_multipliers_are_one(self):
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=2)
        for tier in IdentityTier:
            assert policy.fee_multiplier[tier] == 1.0

    def test_allowlist_none_by_default(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=3)
        assert policy.allowlist is None

    def test_denylist_empty_by_default(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=3)
        assert policy.denylist == set()


# ---------------------------------------------------------------------------
# TestPolicyEvaluation
# ---------------------------------------------------------------------------


class TestPolicyEvaluation:
    def _engine(self):
        from src.ltp.execution.writer_policy import PolicyEngine

        return PolicyEngine()

    def _policy(self, **kwargs):
        from src.ltp.execution.writer_policy import VMWriterPolicy

        return VMWriterPolicy(vm_tag=0x10, **kwargs)

    def test_mldsa_deploy_allowed(self):
        from src.ltp.execution.types import OperationType

        record = _make_record("mldsa")
        result = self._engine().evaluate(record, OperationType.DEPLOY, self._policy())
        assert result.allowed is True

    def test_bls_deploy_rejected(self):
        from src.ltp.execution.types import OperationType

        record = _make_record("bls")
        result = self._engine().evaluate(record, OperationType.DEPLOY, self._policy())
        assert result.allowed is False
        assert "deploy" in result.reason
        assert "bls" in result.reason

    def test_bls_transfer_allowed(self):
        from src.ltp.execution.types import OperationType

        record = _make_record("bls")
        result = self._engine().evaluate(record, OperationType.TRANSFER, self._policy())
        assert result.allowed is True

    def test_denylist_blocks_writer(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_policy import VMWriterPolicy

        fp = b"\xaa" * 32
        record = _make_record_fp("mldsa", fp)
        policy = VMWriterPolicy(vm_tag=1, denylist={fp})
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is False
        assert "denylist" in result.reason

    def test_allowlist_blocks_unlisted_writer(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_policy import VMWriterPolicy

        fp_allowed = b"\xbb" * 32
        fp_writer = b"\xaa" * 32
        record = _make_record_fp("mldsa", fp_writer)
        policy = VMWriterPolicy(vm_tag=1, allowlist={fp_allowed})
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is False
        assert "allowlist" in result.reason

    def test_allowlist_permits_listed_writer(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_policy import VMWriterPolicy

        fp = b"\xaa" * 32
        record = _make_record_fp("mldsa", fp)
        policy = VMWriterPolicy(vm_tag=1, allowlist={fp})
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is True

    def test_tier_not_allowed(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        record = _make_record("bls")
        policy = VMWriterPolicy(
            vm_tag=1,
            allowed_tiers={IdentityTier.MLDSA, IdentityTier.COMPOSITE},
        )
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is False
        assert "bls" in result.reason

    def test_rate_limit_exceeded(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        record = _make_record("bls")
        # BLS default limit is 1000; push tx_count to 1000
        result = self._engine().evaluate(
            record, OperationType.TRANSFER, self._policy(), tx_count=1000
        )
        assert result.allowed is False
        assert "rate limit" in result.reason

    def test_fee_multiplier_returned_on_pass(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        record = _make_record("mldsa")
        policy = VMWriterPolicy(
            vm_tag=1,
            fee_multiplier={
                IdentityTier.MLDSA: 2.5,
                IdentityTier.BLS: 1.0,
                IdentityTier.COMPOSITE: 1.0,
            },
        )
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is True
        assert result.fee_multiplier == pytest.approx(2.5)

    def test_equal_access_policy_gives_bls_all_ops(self):
        """A policy that grants BLS all ops should allow BLS deploy."""
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy, _default_tier_operations

        # Override BLS operations to allow everything
        tier_ops = _default_tier_operations()
        tier_ops[IdentityTier.BLS] = set(OperationType)
        policy = VMWriterPolicy(vm_tag=1, tier_operations=tier_ops)
        record = _make_record("bls")
        result = self._engine().evaluate(record, OperationType.DEPLOY, policy)
        assert result.allowed is True

    def test_max_writers_cap(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(vm_tag=1, max_writers=5)
        record = _make_record("mldsa")
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy, writer_count=5)
        assert result.allowed is False
        assert "cap" in result.reason

    def test_insufficient_stake(self):
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        policy = VMWriterPolicy(
            vm_tag=1,
            min_stake={
                IdentityTier.MLDSA: 100,
                IdentityTier.BLS: 0,
                IdentityTier.COMPOSITE: 0,
            },
        )
        record = _make_record("mldsa")
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy, stake=50)
        assert result.allowed is False
        assert "stake" in result.reason


# ---------------------------------------------------------------------------
# TestProbationOverride
# ---------------------------------------------------------------------------


class TestProbationOverride:
    def _engine(self):
        from src.ltp.execution.writer_policy import PolicyEngine

        return PolicyEngine()

    def test_probation_blocks_deploy(self):
        """PROBATION writers may not DEPLOY (blocked_operations default = {'deploy'})."""
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_policy import VMWriterPolicy

        record = _make_record("mldsa", state_str="probation")
        policy = VMWriterPolicy(vm_tag=1)
        result = self._engine().evaluate(record, OperationType.DEPLOY, policy)
        assert result.allowed is False
        assert "probation" in result.reason

    def test_probation_doubles_fee(self):
        """PROBATION writers pay double the base fee multiplier."""
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.writer_policy import VMWriterPolicy

        record = _make_record("mldsa", state_str="probation")
        policy = VMWriterPolicy(
            vm_tag=1,
            fee_multiplier={
                IdentityTier.MLDSA: 1.0,
                IdentityTier.BLS: 1.0,
                IdentityTier.COMPOSITE: 1.0,
            },
        )
        # TRANSFER is not blocked during probation
        result = self._engine().evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is True
        # Default fee_multiplier_factor is 2.0 → 1.0 * 2.0
        assert result.fee_multiplier == pytest.approx(2.0)

    def test_probation_halves_rate_limit(self):
        """PROBATION writers get a halved rate limit (1000 // 2 = 500 for BLS)."""
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_policy import VMWriterPolicy

        record = _make_record("bls", state_str="probation")
        policy = VMWriterPolicy(vm_tag=1)
        # 500 transactions should still be under the halved BLS limit (500)
        result_ok = self._engine().evaluate(record, OperationType.TRANSFER, policy, tx_count=499)
        assert result_ok.allowed is True

        # Exactly at the halved limit (500) should be rejected
        result_exceeded = self._engine().evaluate(
            record, OperationType.TRANSFER, policy, tx_count=500
        )
        assert result_exceeded.allowed is False
        assert "rate limit" in result_exceeded.reason
