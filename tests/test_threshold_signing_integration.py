"""CommitteeManager + threshold signing integration tests (Spec C3c)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.committee.policy import CommitteePolicy
from src.ltp.execution.writer import IdentityTier, WriterIdentity
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry
from src.ltp.zk.ec_backend import bls12_381_available

ADMIN_FP = b"\xff" * 32


def _enroll_active(reg, fp_byte, tier=IdentityTier.BLS):
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = (
        bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
    )
    identity = WriterIdentity(tier=tier, fingerprint=fp, mldsa_vk=mldsa_vk, bls_pk=bls_pk)
    reg.enroll(identity, timestamp=1000 + fp_byte)
    reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + fp_byte)


class TestManagerSigningDisabled:
    def test_sign_returns_none_when_dkg_disabled(self):
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, dkg_threshold=0)
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        result = mgr.sign_as_committee(b"test", b"domain")
        assert result is None


@pytest.mark.skipif(not bls12_381_available(), reason="py_ecc not installed")
class TestManagerSigningEnabled:
    def test_sign_produces_valid_signature(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
            threshold_verify,
        )

        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=10,
            dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        assert mgr.has_dkg_result(1)

        msg = b"attestation payload"
        sig = mgr.sign_as_committee(msg, DOMAIN_ATTESTATION)
        assert sig is not None
        assert len(sig) == 96

        group_pk = mgr.dkg_registry.group_pk(1)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION)

    def test_verify_committee_signature(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
        )

        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=10,
            dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)

        msg = b"verify test"
        sig = mgr.sign_as_committee(msg, DOMAIN_ATTESTATION)
        assert mgr.verify_committee_signature(msg, sig, DOMAIN_ATTESTATION)

    def test_verify_rejects_tampered(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
        )

        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=10,
            dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)

        sig = mgr.sign_as_committee(b"real", DOMAIN_ATTESTATION)
        assert not mgr.verify_committee_signature(b"fake", sig, DOMAIN_ATTESTATION)

    def test_multiple_epochs_sign_verify(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
            threshold_verify,
        )

        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=10,
            dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        sig1 = mgr.sign_as_committee(b"epoch1", DOMAIN_ATTESTATION)

        mgr.tick(20, 2000)
        sig2 = mgr.sign_as_committee(b"epoch2", DOMAIN_ATTESTATION)

        # Both valid against their respective epoch keys
        pk1 = mgr.dkg_registry.group_pk(1)
        pk2 = mgr.dkg_registry.group_pk(2)
        assert threshold_verify(pk1, b"epoch1", sig1, DOMAIN_ATTESTATION)
        assert threshold_verify(pk2, b"epoch2", sig2, DOMAIN_ATTESTATION)

    def test_verify_with_explicit_epoch(self):
        from src.ltp.execution.committee.dkg.threshold_signing import (
            DOMAIN_ATTESTATION,
        )

        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=10,
            dkg_threshold=2,
        )
        mgr = CommitteeManager(0x01, policy, reg, EmergencyState())
        mgr.tick(10, 1000)
        sig = mgr.sign_as_committee(b"msg", DOMAIN_ATTESTATION)

        mgr.tick(20, 2000)  # advance epoch
        # Verify against epoch 1 explicitly
        assert mgr.verify_committee_signature(b"msg", sig, DOMAIN_ATTESTATION, epoch=1)
