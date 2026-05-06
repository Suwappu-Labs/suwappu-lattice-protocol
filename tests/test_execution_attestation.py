"""Tests for AttestationEngine — signs multi-VM state roots."""

import pytest


@pytest.fixture(scope="module")
def operator_kp():
    from src.ltp import KeyPair
    return KeyPair.generate("test-operator")


class TestMultiVMAttestation:
    def test_digest_deterministic(self):
        from src.ltp.execution.attestation import MultiVMAttestation
        from src.ltp.execution.state_root import MultiVMStateRoot

        root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=1)
        a1 = MultiVMAttestation(
            state_root=root, consensus_round=1, epoch=0,
            active_vm_tags=[0x01], mldsa_signature=None,
            bls_aggregate=None, operator_vk_hash=b"\x00" * 32,
            timestamp_ms=1000, chain_id=103115120,
        )
        a2 = MultiVMAttestation(
            state_root=root, consensus_round=1, epoch=0,
            active_vm_tags=[0x01], mldsa_signature=None,
            bls_aggregate=None, operator_vk_hash=b"\x00" * 32,
            timestamp_ms=1000, chain_id=103115120,
        )
        assert a1.digest == a2.digest
        assert len(a1.digest) == 32

    def test_different_round_different_digest(self):
        from src.ltp.execution.attestation import MultiVMAttestation
        from src.ltp.execution.state_root import MultiVMStateRoot

        root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=1)
        a1 = MultiVMAttestation(
            state_root=root, consensus_round=1, epoch=0,
            active_vm_tags=[0x01], mldsa_signature=None,
            bls_aggregate=None, operator_vk_hash=b"\x00" * 32,
            timestamp_ms=1000, chain_id=103115120,
        )
        root2 = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=2)
        a2 = MultiVMAttestation(
            state_root=root2, consensus_round=2, epoch=0,
            active_vm_tags=[0x01], mldsa_signature=None,
            bls_aggregate=None, operator_vk_hash=b"\x00" * 32,
            timestamp_ms=1000, chain_id=103115120,
        )
        assert a1.digest != a2.digest


class TestAttestationEngine:
    def test_sign_produces_valid_attestation(self, operator_kp):
        from src.ltp.execution.attestation import AttestationEngine
        from src.ltp.execution.state_root import MultiVMStateRoot

        engine = AttestationEngine(
            operator_keypair=operator_kp,
            chain_id=103115120,
        )
        root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=1)
        attestation = engine.sign(root, consensus_round=1, epoch=0, active_vm_tags=[0x01])

        assert attestation.mldsa_signature is not None
        assert len(attestation.mldsa_signature) > 0
        assert attestation.chain_id == 103115120
        assert attestation.consensus_round == 1

    def test_verify_signature(self, operator_kp):
        from src.ltp.execution.attestation import AttestationEngine
        from src.ltp.execution.state_root import MultiVMStateRoot

        engine = AttestationEngine(operator_keypair=operator_kp, chain_id=103115120)
        root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32, 0x10: b"\xbb" * 32}, batch_round=5)
        attestation = engine.sign(root, consensus_round=5, epoch=1, active_vm_tags=[0x01, 0x10])

        assert attestation.verify(operator_kp.vk) is True

    def test_wrong_key_fails_verify(self, operator_kp):
        from src.ltp import KeyPair
        from src.ltp.execution.attestation import AttestationEngine
        from src.ltp.execution.state_root import MultiVMStateRoot

        engine = AttestationEngine(operator_keypair=operator_kp, chain_id=103115120)
        root = MultiVMStateRoot(vm_roots={0x01: b"\xaa" * 32}, batch_round=1)
        attestation = engine.sign(root, consensus_round=1, epoch=0, active_vm_tags=[0x01])

        wrong_kp = KeyPair.generate("wrong-key")
        assert attestation.verify(wrong_kp.vk) is False

    def test_requires_keypair(self):
        from src.ltp.execution.attestation import AttestationEngine
        with pytest.raises(TypeError, match="operator_keypair"):
            AttestationEngine(operator_keypair=None, chain_id=1)
