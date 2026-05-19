"""Tests for BLS attestation integration (Spec C1 §5)."""

import pytest

from src.ltp.bls import BLS
from src.ltp.bls_keys import BLSKeyPair
from src.ltp.execution.attestation import AttestationEngine, MultiVMAttestation
from src.ltp.execution.state_root import MultiVMStateRoot
from src.ltp.keypair import KeyPair


@pytest.fixture
def operator():
    return KeyPair.generate("attest-op", with_bls=True)


@pytest.fixture
def state_root():
    return MultiVMStateRoot(
        vm_roots={0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32},
        batch_round=42,
    )


class TestSignBLS:
    """Test BLS-only attestation signing (Spec C1 §5.2 mode 2)."""

    def test_sign_bls_produces_attestation(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_bls(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.bls_aggregate is not None
        assert len(att.bls_aggregate) == 96
        assert att.mldsa_signature is None

    def test_sign_bls_verifies(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_bls(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.verify_bls([bls_id.pk]) is True

    def test_sign_bls_wrong_pk_rejects(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_bls(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        wrong_pk = BLS.keygen()[0]
        assert att.verify_bls([wrong_pk]) is False


class TestSignDual:
    """Test dual-signed attestation (Spec C1 §5.2 mode 3)."""

    def test_sign_dual_has_both_signatures(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_dual(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.mldsa_signature is not None
        assert att.bls_aggregate is not None

    def test_sign_dual_mldsa_verifies(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_dual(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.verify_mldsa(operator.vk) is True

    def test_sign_dual_bls_verifies(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_dual(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.verify_bls([bls_id.pk]) is True


class TestBackwardCompatibility:
    """Existing sign() method works unchanged."""

    def test_sign_mldsa_only_still_works(self, operator, state_root):
        engine = AttestationEngine(operator, chain_id=1)
        att = engine.sign(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.mldsa_signature is not None
        assert att.bls_aggregate is None
        assert att.verify(vk=operator.vk) is True

    def test_verify_convenience_method(self, operator, state_root):
        bls_id = operator.to_bls_identity()
        engine = AttestationEngine(operator, chain_id=1, bls_identity=bls_id)
        att = engine.sign_dual(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        assert att.verify(vk=operator.vk, bls_pks=[bls_id.pk]) is True
        assert att.verify(vk=operator.vk) is True
        assert att.verify(bls_pks=[bls_id.pk]) is True


class TestAttestationAggregator:
    """Test AttestationAggregator for multi-operator aggregate (Spec C1 §5.4)."""

    def test_aggregator_collects_and_finalizes(self, state_root):
        from src.ltp.domain import DOMAIN_BLS_ATTEST, bls_domain_sign
        from src.ltp.execution.attestation import AttestationAggregator

        keys = [BLSKeyPair.generate(f"op-{i}") for i in range(5)]
        engine = AttestationEngine(KeyPair.generate("dummy"), chain_id=1)
        att = engine.sign(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        digest = att.digest

        agg = AttestationAggregator()
        for kp in keys:
            sig = bls_domain_sign(DOMAIN_BLS_ATTEST, kp.sk, digest)
            agg.add_signature(kp.pk, sig)

        assert agg.signer_count() == 5
        assert len(agg.signer_pks()) == 5

        agg_sig = agg.finalize()
        assert len(agg_sig) == 96

    def test_aggregator_produces_verifiable_aggregate(self, state_root):
        from src.ltp.domain import DOMAIN_BLS_ATTEST, bls_aggregate_verify, bls_domain_sign
        from src.ltp.execution.attestation import AttestationAggregator

        keys = [BLSKeyPair.generate(f"vop-{i}") for i in range(3)]
        engine = AttestationEngine(KeyPair.generate("dummy"), chain_id=1)
        att = engine.sign(state_root, consensus_round=10, epoch=1, active_vm_tags=[0x01, 0x10])
        digest = att.digest

        agg = AttestationAggregator()
        for kp in keys:
            sig = bls_domain_sign(DOMAIN_BLS_ATTEST, kp.sk, digest)
            agg.add_signature(kp.pk, sig)

        agg_sig = agg.finalize()
        pks = agg.signer_pks()
        assert bls_aggregate_verify(DOMAIN_BLS_ATTEST, pks, digest, agg_sig) is True

    def test_aggregator_empty_raises(self):
        from src.ltp.execution.attestation import AttestationAggregator

        agg = AttestationAggregator()
        with pytest.raises(ValueError, match="No signatures"):
            agg.finalize()
