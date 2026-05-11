"""CommitteeManager + DKG integration tests (Spec C3b §8)."""

from __future__ import annotations

import pytest

from src.ltp.zk.ec_backend import bls12_381_available
from src.ltp.execution.committee.policy import CommitteePolicy, EpochStrategy
from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.writer import IdentityTier, WriterIdentity
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _enroll_active(reg, fp_byte, tier=IdentityTier.BLS):
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
    identity = WriterIdentity(tier=tier, fingerprint=fp, mldsa_vk=mldsa_vk, bls_pk=bls_pk)
    reg.enroll(identity, timestamp=1000 + fp_byte)
    reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + fp_byte)


class TestPolicyDKGFields:

    def test_default_dkg_disabled(self):
        p = CommitteePolicy(vm_tag=0x01)
        assert p.dkg_threshold == 0
        assert p.dkg_timeout_rounds == 10
        assert p.dkg_eager_start_rounds == 5

    def test_dkg_enabled(self):
        p = CommitteePolicy(vm_tag=0x01, dkg_threshold=3)
        assert p.dkg_threshold == 3


class TestManagerDKGDisabled:

    def test_tick_without_dkg(self):
        """When dkg_threshold=0, tick behaves exactly as C3a."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, dkg_threshold=0)
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        assert mgr.tick(10, 1000) is True
        assert mgr.epoch == 1
        assert mgr.roster is not None
        assert not mgr.has_dkg_result(1)


class TestManagerDKGRegistry:

    def test_dkg_registry_exposed(self):
        """Manager exposes DKG registry for querying."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, dkg_threshold=0)
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        assert mgr.dkg_registry is not None
        assert mgr.dkg_registry.epoch_count() == 0


@pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")
class TestManagerDKGCeremony:

    def test_dkg_runs_on_epoch_advance(self):
        """When dkg_threshold > 0, epoch advance triggers DKG."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        assert mgr.epoch == 1
        assert mgr.has_dkg_result(1)
        result = mgr.dkg_registry.get(1)
        assert result.threshold == 2
        assert len(result.group_pk) == 96

    def test_multiple_epochs_produce_different_keys(self):
        """Each epoch gets a fresh DKG — different group key."""
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01, epoch_length=10, dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        mgr.tick(20, 2000)
        pk1 = mgr.dkg_registry.group_pk(1)
        pk2 = mgr.dkg_registry.group_pk(2)
        assert pk1 != pk2
