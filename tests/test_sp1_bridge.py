"""
Tests for SP1 ZK Bridge Prover — Python wrapper for the SP1 ML-DSA-65 circuit.

All tests use mock mode (no SP1 toolchain needed).
"""

from __future__ import annotations

import struct

import pytest

from src.ltp.bridge.sp1_prover import SP1ZKBridgeProver
from src.ltp.bridge.zk_bridge import (
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgePublicInputs,
    ZKBridgeVerifier,
)
from src.ltp.commitment import CommitmentLog
from src.ltp.keypair import KeyPair
from src.ltp.primitives import canonical_hash_bytes

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def operator_kp():
    return KeyPair.generate("sp1-test-operator")


@pytest.fixture
def sth(operator_kp):
    """Create a real SignedTreeHead from a commitment log."""
    log = CommitmentLog()
    import time

    from src.ltp.commitment import CommitmentRecord

    record = CommitmentRecord(
        entity_id="sp1-test-entity",
        sender_id="sender",
        content_hash="hash",
        shard_map_root="root",
        encoding_params={"n": 5, "k": 3},
        shape="application/octet-stream",
        shape_hash="shape-hash",
        timestamp=time.time(),
        signature=b"\x00" * 64,
    )
    log.append(record)
    return log.latest_sth


@pytest.fixture
def prover():
    return SP1ZKBridgeProver(prove_mode="mock")


# ---------------------------------------------------------------------------
# Backend Property
# ---------------------------------------------------------------------------


class TestBackend:
    def test_backend_is_sp1(self, prover):
        assert prover.backend == ZKBridgeBackend.SP1

    def test_prove_mode_stored(self, prover):
        assert prover.prove_mode == "mock"

    def test_default_elf_path_resolves(self):
        p = SP1ZKBridgeProver(prove_mode="mock")
        assert "sp1-mldsa-verifier" in p.elf_path


# ---------------------------------------------------------------------------
# Proof Generation (mock mode)
# ---------------------------------------------------------------------------


class TestProveSTH:
    def test_returns_zkbridge_proof(self, prover, sth):
        proof = prover.prove_sth_signature(sth)
        assert isinstance(proof, ZKBridgeProof)
        assert proof.backend == ZKBridgeBackend.SP1

    def test_proof_has_correct_public_inputs(self, prover, sth):
        proof = prover.prove_sth_signature(sth)
        pi = proof.public_inputs
        assert pi.sth_root_hash == sth.root_hash
        assert pi.operator_vk_hash == canonical_hash_bytes(sth.operator_vk)
        assert pi.tree_size == sth.tree_size
        assert pi.sth_sequence == sth.sequence

    def test_proof_id_is_non_deterministic(self, prover, sth):
        """Real STARK uses random blinding, so proofs differ each time."""
        p1 = prover.prove_sth_signature(sth)
        p2 = prover.prove_sth_signature(sth)
        assert p1.proof_id != p2.proof_id

    def test_proof_bytes_real_stark(self, prover, sth):
        """SP1 proofs are real STARK proofs (> 100 bytes)."""
        proof = prover.prove_sth_signature(sth)
        assert len(proof.proof_bytes) > 100

    def test_proof_larger_than_simulated(self, prover, sth):
        """SP1 mock proofs (128B) are distinguishable from simulated (64B)."""
        proof = prover.prove_sth_signature(sth)
        assert proof.proof_size_bytes > 64

    def test_invalid_sth_raises(self, prover):
        """STH with invalid signature should raise ValueError."""
        from src.ltp.merkle_log.sth import SignedTreeHead

        bad_sth = SignedTreeHead(
            sequence=1,
            tree_size=1,
            timestamp=0.0,
            root_hash=b"\x00" * 32,
            operator_vk=b"\x00" * 1952,
            signature=b"\x00" * 3309,
        )
        with pytest.raises(ValueError, match="invalid"):
            prover.prove_sth_signature(bad_sth)


# ---------------------------------------------------------------------------
# Witness Marshaling
# ---------------------------------------------------------------------------


class TestMarshalWitnesses:
    def test_format_is_length_prefixed_le(self, prover, sth):
        data = prover._marshal_witnesses(sth)

        # Parse first vector: operator_vk
        offset = 0
        vk_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        assert vk_len == 1952
        offset += vk_len

        # Second vector: signature
        sig_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        assert sig_len == 3309
        offset += sig_len

        # Third vector: signable_payload
        payload_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        assert payload_len == 56

    def test_total_size(self, prover, sth):
        data = prover._marshal_witnesses(sth)
        expected = (4 + 1952) + (4 + 3309) + (4 + 56)  # 3 length-prefixed vectors
        assert len(data) == expected


# ---------------------------------------------------------------------------
# Verifier Integration
# ---------------------------------------------------------------------------


class TestVerifierIntegration:
    def test_mock_proof_verifiable(self, prover, sth):
        """ZKBridgeVerifier should accept SP1 mock proofs."""
        proof = prover.prove_sth_signature(sth)
        assert ZKBridgeVerifier.verify(proof) is True

    def test_tampered_proof_rejected(self, prover, sth):
        """Tampered proof bytes should fail verification."""
        proof = prover.prove_sth_signature(sth)
        tampered = bytearray(proof.proof_bytes)
        tampered[100] ^= 0xFF  # Flip a byte in the mock tag
        tampered_proof = ZKBridgeProof(
            proof_bytes=bytes(tampered),
            backend=ZKBridgeBackend.SP1,
            public_inputs=proof.public_inputs,
            proof_id="tampered",
        )
        assert ZKBridgeVerifier.verify(tampered_proof) is False

    def test_public_inputs_mismatch_rejected(self, prover, sth):
        """Proof with mismatched public inputs should fail verification."""
        proof = prover.prove_sth_signature(sth)
        wrong_inputs = ZKBridgePublicInputs(
            sth_root_hash=b"\xff" * 32,  # Wrong root hash
            operator_vk_hash=proof.public_inputs.operator_vk_hash,
            tree_size=proof.public_inputs.tree_size,
            sth_sequence=proof.public_inputs.sth_sequence,
        )
        mismatched = ZKBridgeProof(
            proof_bytes=proof.proof_bytes,
            backend=ZKBridgeBackend.SP1,
            public_inputs=wrong_inputs,
            proof_id=proof.proof_id,
        )
        assert ZKBridgeVerifier.verify(mismatched) is False

    def test_empty_proof_rejected(self):
        """Empty proof bytes should fail."""
        proof = ZKBridgeProof(
            proof_bytes=b"",
            backend=ZKBridgeBackend.SP1,
            public_inputs=ZKBridgePublicInputs(
                sth_root_hash=b"\x00" * 32,
                operator_vk_hash=b"\x00" * 32,
                tree_size=0,
                sth_sequence=0,
            ),
            proof_id="empty",
        )
        assert ZKBridgeVerifier.verify(proof) is False

    def test_64byte_proof_rejected_for_sp1(self):
        """64-byte proof (simulated size) should be rejected for SP1 backend."""
        proof = ZKBridgeProof(
            proof_bytes=b"\x00" * 64,
            backend=ZKBridgeBackend.SP1,
            public_inputs=ZKBridgePublicInputs(
                sth_root_hash=b"\x00" * 32,
                operator_vk_hash=b"\x00" * 32,
                tree_size=0,
                sth_sequence=0,
            ),
            proof_id="short",
        )
        assert ZKBridgeVerifier.verify(proof) is False
