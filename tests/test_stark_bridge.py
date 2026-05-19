"""
STARK bridge integration tests.

Tests post-quantum hash-only proof generation and verification,
comparison with SNARK proofs, and end-to-end PQ-safe bridge flow.

STARKs use only collision-resistant hashing — no pairing-based crypto.
This completes the end-to-end PQ security chain:
  ML-DSA-65 (PQ) -> STARK proof (PQ) -> on-chain hash verification (PQ)
"""

from __future__ import annotations

import time
from enum import IntEnum

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge.challenge import ChallengeManager, ChallengeStatus
from src.ltp.bridge.zk_bridge import (
    SimulatedZKBridgeProver,
    STARKBridgeProver,
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgePublicInputs,
    ZKBridgeVerifier,
)
from src.ltp.primitives import MLDSA
from src.ltp.verify import verify_zk_bridge_proof

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sth(keypair: KeyPair, sequence: int = 1, root_hash: bytes = b"\x11" * 32):
    from src.ltp.merkle_log.sth import SignedTreeHead

    sth = SignedTreeHead(
        sequence=sequence,
        tree_size=sequence,
        timestamp=time.time(),
        root_hash=root_hash,
        operator_vk=keypair.vk,
        signature=b"",
    )
    sig = MLDSA.sign(keypair.sk, sth.signable_payload())
    return SignedTreeHead(
        sequence=sth.sequence,
        tree_size=sth.tree_size,
        timestamp=sth.timestamp,
        root_hash=sth.root_hash,
        operator_vk=sth.operator_vk,
        signature=sig,
    )


def _make_bad_sth(keypair: KeyPair):
    from src.ltp.merkle_log.sth import SignedTreeHead

    return SignedTreeHead(
        sequence=1,
        tree_size=1,
        timestamp=time.time(),
        root_hash=b"\x99" * 32,
        operator_vk=keypair.vk,
        signature=b"\x00" * 64,
    )


@pytest.fixture(scope="session")
def operator() -> KeyPair:
    return KeyPair.generate("4fiii-operator")


@pytest.fixture(scope="session")
def verifier_kp() -> KeyPair:
    return KeyPair.generate("4fiii-verifier")


# ---------------------------------------------------------------------------
# STARKBridgeProver
# ---------------------------------------------------------------------------


class TestSTARKBridgeProver:
    def test_prove_valid_sth(self, operator):
        sth = _make_sth(operator)
        prover = STARKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        assert isinstance(proof, ZKBridgeProof)
        assert proof.backend == ZKBridgeBackend.STARK
        assert proof.proof_size_bytes > 100  # Real FRI-based STARK

    def test_prove_invalid_sth_raises(self, operator):
        bad = _make_bad_sth(operator)
        prover = STARKBridgeProver()
        with pytest.raises(ValueError, match="invalid STH signature"):
            prover.prove_sth_signature(bad)

    def test_proof_size_is_real_stark(self, operator):
        sth = _make_sth(operator)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        # Real FRI-based STARK is larger than the old 32B hash simulation
        # but smaller than the old 392B fake-FRI format
        assert proof.proof_size_bytes > 100

    def test_proof_is_non_deterministic(self, operator):
        """Real STARK uses random blinding, so proofs differ each time."""
        sth = _make_sth(operator, sequence=5, root_hash=b"\xaa" * 32)
        prover = STARKBridgeProver()
        p1 = prover.prove_sth_signature(sth)
        p2 = prover.prove_sth_signature(sth)
        # Different random blinding → different proofs (both valid)
        assert p1.proof_id != p2.proof_id

    def test_backend_is_stark(self):
        assert STARKBridgeProver().backend == ZKBridgeBackend.STARK

    def test_proof_contains_fri_roots(self, operator):
        """The v3 proof should contain real FRI Merkle roots."""
        sth = _make_sth(operator)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        # Version 3 header
        assert proof.proof_bytes[0] == 3
        # Contains FRI layer roots (each 32 bytes) after header+hashes
        num_roots = proof.proof_bytes[1]
        assert num_roots >= 1

    def test_public_inputs_match_sth(self, operator):
        sth = _make_sth(operator, sequence=7, root_hash=b"\xbb" * 32)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        assert proof.public_inputs.sth_root_hash == b"\xbb" * 32
        assert proof.public_inputs.sth_sequence == 7
        assert proof.public_inputs.tree_size == 7


# ---------------------------------------------------------------------------
# STARK Verifier
# ---------------------------------------------------------------------------


class TestSTARKVerifier:
    def test_verify_valid_stark_proof(self, operator):
        sth = _make_sth(operator)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        assert ZKBridgeVerifier.verify(proof) is True

    def test_reject_tampered_stark_proof(self, operator):
        sth = _make_sth(operator)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        tampered = proof.proof_bytes[:96] + b"\x00" * 32
        bad = ZKBridgeProof(
            proof_bytes=tampered,
            backend=ZKBridgeBackend.STARK,
            public_inputs=proof.public_inputs,
            proof_id="bad",
        )
        assert ZKBridgeVerifier.verify(bad) is False

    def test_reject_wrong_inputs(self, operator):
        sth = _make_sth(operator, root_hash=b"\xcc" * 32)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        wrong = ZKBridgePublicInputs(
            sth_root_hash=b"\xdd" * 32,
            operator_vk_hash=proof.public_inputs.operator_vk_hash,
            tree_size=proof.public_inputs.tree_size,
            sth_sequence=proof.public_inputs.sth_sequence,
        )
        bad = ZKBridgeProof(
            proof_bytes=proof.proof_bytes,
            backend=ZKBridgeBackend.STARK,
            public_inputs=wrong,
            proof_id=proof.proof_id,
        )
        assert ZKBridgeVerifier.verify(bad) is False

    def test_reject_snark_size_proof_as_stark(self, operator):
        """A 64B proof (SNARK size) should fail STARK verification."""
        sth = _make_sth(operator)
        inputs = ZKBridgePublicInputs.from_sth(sth)
        short = ZKBridgeProof(
            proof_bytes=b"\x00" * 64,
            backend=ZKBridgeBackend.STARK,
            public_inputs=inputs,
            proof_id="short",
        )
        assert ZKBridgeVerifier.verify(short) is False


# ---------------------------------------------------------------------------
# STARK vs SNARK comparison
# ---------------------------------------------------------------------------


class TestSTARKvsSNARK:
    def test_same_sth_different_proofs(self, operator):
        """Same STH produces structurally different proofs for STARK vs SIMULATED."""
        sth = _make_sth(operator, sequence=3, root_hash=b"\xee" * 32)

        snark_proof = SimulatedZKBridgeProver().prove_sth_signature(sth)
        stark_proof = STARKBridgeProver().prove_sth_signature(sth)

        assert snark_proof.proof_bytes != stark_proof.proof_bytes
        assert len(snark_proof.proof_bytes) > 100  # SIMULATED now uses real STARK
        assert len(stark_proof.proof_bytes) > 100  # Real FRI-based STARK

    def test_both_verify_independently(self, operator):
        """Both proof types verify for the same STH."""
        sth = _make_sth(operator)

        snark = SimulatedZKBridgeProver().prove_sth_signature(sth)
        stark = STARKBridgeProver().prove_sth_signature(sth)

        assert ZKBridgeVerifier.verify(snark) is True
        assert ZKBridgeVerifier.verify(stark) is True

    def test_sdk_handles_both(self, operator):
        """verify_zk_bridge_proof() works for both STARK and SIMULATED."""
        sth = _make_sth(operator)

        snark = SimulatedZKBridgeProver().prove_sth_signature(sth)
        stark = STARKBridgeProver().prove_sth_signature(sth)

        assert verify_zk_bridge_proof(snark).valid is True
        assert verify_zk_bridge_proof(stark).valid is True
        assert verify_zk_bridge_proof(stark).details["backend"] == "stark"


# ---------------------------------------------------------------------------
# ChallengeManager with STARK proof
# ---------------------------------------------------------------------------


class TestChallengeManagerSTARK:
    def test_resolve_with_stark_proof(self, operator):
        """ChallengeManager accepts STARK proofs identically to SNARK proofs."""
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("stark-ent-1", b"\x01" * 32)

        sth = _make_sth(operator)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        rec = mgr.resolve_with_proof("stark-ent-1", proof)

        assert rec.status == ChallengeStatus.FINALIZED
        assert rec.resolution == "zk_proof"


# ---------------------------------------------------------------------------
# LiveBridge with STARK prover
# ---------------------------------------------------------------------------


class _MockEntityState(IntEnum):
    ANCHORED = 2


class _MockClient:
    def __init__(self):
        self._anchored = set()
        self._seq = 0

    def anchor(self, s):
        self._anchored.add(s.anchor_digest)
        self._seq = s.sequence
        return f"0x{'ab' * 32}"

    def is_anchored(self, d):
        return d in self._anchored

    def entity_state(self, e):
        return _MockEntityState.ANCHORED

    def signer_sequence(self, v):
        return self._seq

    def get_block_number(self):
        return 100


class TestLiveBridgeSTARK:
    def test_transfer_with_stark_prover(self):
        """LiveBridge with STARKBridgeProver gives instant finality."""
        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"st-{i}", ["US-East", "US-West", "EU-West"][i % 3])

        protocol = LTPProtocol(net)
        op = KeyPair.generate("stark-lb-op")
        vf = KeyPair.generate("stark-lb-vf")

        from src.ltp.bridge.live import LiveBridge
        from src.ltp.bridge.message import BridgeMessage

        mgr = ChallengeManager(challenge_period=604800.0)
        bridge = LiveBridge(
            protocol=protocol,
            l1_client=_MockClient(),
            operator_keypair=op,
            l2_verifier_keypair=vf,
            l1_chain_id=31337,
            challenge_manager=mgr,
            zk_prover=STARKBridgeProver(),
        )

        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="ethereum",
            dest_chain="optimism",
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 100},
            nonce=0,
        )

        result = bridge.transfer(msg)
        assert result is not None
        assert result.zk_finalized is True
        assert result.zk_proof_id is not None
        assert result.challenge_status == "finalized"


# ---------------------------------------------------------------------------
# End-to-end PQ-safe flow
# ---------------------------------------------------------------------------


class TestEndToEndPQ:
    def test_full_pq_safe_flow(self, operator):
        """Complete PQ-safe flow: commit -> STARK prove -> verify -> finalize."""
        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"pq-{i}", ["US-East", "US-West", "EU-West"][i % 3])
        protocol = LTPProtocol(net)

        from src.ltp.entity import Entity

        entity = Entity(content=b"Post-quantum end-to-end data " * 8, shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, operator)

        sth = protocol.network.log.latest_sth
        assert sth is not None

        # Generate STARK proof (PQ-safe — hash-only)
        proof = STARKBridgeProver().prove_sth_signature(sth)
        assert proof.backend == ZKBridgeBackend.STARK
        assert proof.proof_size_bytes > 100  # Real FRI-based STARK

        # Verify
        assert ZKBridgeVerifier.verify(proof) is True
        sdk_result = verify_zk_bridge_proof(proof)
        assert sdk_result.valid is True
        assert sdk_result.details["backend"] == "stark"

        # ChallengeManager finalization
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window(entity_id, b"\xff" * 32)
        rec = mgr.resolve_with_proof(entity_id, proof)
        assert rec.status == ChallengeStatus.FINALIZED
