"""
Tests for RISC Zero ZK Bridge Prover.

All tests use mock mode (no RISC Zero toolchain needed).
"""

from __future__ import annotations

import time

import pytest

from src.ltp.bridge.risc0_prover import RiscZeroZKBridgeProver
from src.ltp.bridge.zk_bridge import (
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgePublicInputs,
    ZKBridgeVerifier,
)
from src.ltp.commitment import CommitmentLog, CommitmentRecord
from src.ltp.primitives import canonical_hash_bytes


@pytest.fixture
def sth():
    log = CommitmentLog()
    record = CommitmentRecord(
        entity_id="r0-test",
        sender_id="s",
        content_hash="h",
        shard_map_root="r",
        encoding_params={"n": 5, "k": 3},
        shape="test",
        shape_hash="sh",
        timestamp=time.time(),
        signature=b"\x00" * 64,
    )
    log.append(record)
    return log.latest_sth


@pytest.fixture
def prover():
    return RiscZeroZKBridgeProver(prove_mode="mock")


class TestBackend:
    def test_backend_is_risc_zero(self, prover):
        assert prover.backend == ZKBridgeBackend.RISC_ZERO

    def test_prove_mode(self, prover):
        assert prover.prove_mode == "mock"


class TestMockProof:
    def test_returns_proof(self, prover, sth):
        proof = prover.prove_sth_signature(sth)
        assert isinstance(proof, ZKBridgeProof)
        assert proof.backend == ZKBridgeBackend.RISC_ZERO

    def test_proof_size(self, prover, sth):
        proof = prover.prove_sth_signature(sth)
        assert len(proof.proof_bytes) > 100  # Real STARK proof

    def test_proof_verifies(self, prover, sth):
        proof = prover.prove_sth_signature(sth)
        assert ZKBridgeVerifier.verify(proof) is True

    def test_invalid_sth_raises(self, prover):
        from src.ltp.merkle_log.sth import SignedTreeHead

        bad = SignedTreeHead(
            sequence=1,
            tree_size=1,
            timestamp=0.0,
            root_hash=b"\x00" * 32,
            operator_vk=b"\x00" * 1952,
            signature=b"\x00" * 3309,
        )
        with pytest.raises(ValueError, match="invalid"):
            prover.prove_sth_signature(bad)

    def test_non_deterministic(self, prover, sth):
        """Real STARK uses random blinding, so proofs differ each time."""
        p1 = prover.prove_sth_signature(sth)
        p2 = prover.prove_sth_signature(sth)
        assert p1.proof_id != p2.proof_id

    def test_different_from_sp1_mock(self, sth):
        """RISC Zero mock proofs are distinguishable from SP1 mock proofs."""
        from src.ltp.bridge.sp1_prover import SP1ZKBridgeProver

        r0 = RiscZeroZKBridgeProver(prove_mode="mock").prove_sth_signature(sth)
        sp1 = SP1ZKBridgeProver(prove_mode="mock").prove_sth_signature(sth)
        assert r0.proof_bytes != sp1.proof_bytes
        assert r0.backend != sp1.backend

    def test_tampered_rejected(self, prover, sth):
        proof = prover.prove_sth_signature(sth)
        tampered = bytearray(proof.proof_bytes)
        tampered[100] ^= 0xFF
        bad = ZKBridgeProof(
            proof_bytes=bytes(tampered),
            backend=ZKBridgeBackend.RISC_ZERO,
            public_inputs=proof.public_inputs,
            proof_id="tampered",
        )
        assert ZKBridgeVerifier.verify(bad) is False
