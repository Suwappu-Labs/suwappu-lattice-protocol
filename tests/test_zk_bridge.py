"""
ZK bridge integration tests.

Tests ZK proof generation and verification, ChallengeManager ZK resolution,
LiveBridge ZK integration, and end-to-end instant finality flow.

All tests are deterministic — no threads, no sleeps.
"""

from __future__ import annotations

import time
from enum import IntEnum

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge.challenge import ChallengeManager, ChallengeStatus
from src.ltp.bridge.fraud_proof import FraudProofType, InvalidSignatureFraudProof
from src.ltp.bridge.zk_bridge import (
    SimulatedZKBridgeProver,
    ZKBridgeBackend,
    ZKBridgeProof,
    ZKBridgePublicInputs,
    ZKBridgeVerifier,
)
from src.ltp.primitives import MLDSA, canonical_hash_bytes
from src.ltp.verify import verify_zk_bridge_proof

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sth(keypair: KeyPair, sequence: int = 1, root_hash: bytes = b"\x11" * 32):
    """Create a valid SignedTreeHead with real ML-DSA signature."""
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


def _make_bad_sth(keypair: KeyPair, sequence: int = 1, root_hash: bytes = b"\x22" * 32):
    """Create an STH with an invalid signature."""
    from src.ltp.merkle_log.sth import SignedTreeHead

    return SignedTreeHead(
        sequence=sequence,
        tree_size=sequence,
        timestamp=time.time(),
        root_hash=root_hash,
        operator_vk=keypair.vk,
        signature=b"\x00" * 64,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def operator() -> KeyPair:
    return KeyPair.generate("4fii-operator")


@pytest.fixture(scope="session")
def verifier() -> KeyPair:
    return KeyPair.generate("4fii-verifier")


# ---------------------------------------------------------------------------
# ZKBridgePublicInputs
# ---------------------------------------------------------------------------


class TestZKBridgePublicInputs:
    def test_from_sth(self, operator):
        sth = _make_sth(operator, sequence=5, root_hash=b"\xaa" * 32)
        inputs = ZKBridgePublicInputs.from_sth(sth)

        assert inputs.sth_root_hash == b"\xaa" * 32
        assert inputs.operator_vk_hash == canonical_hash_bytes(operator.vk)
        assert inputs.tree_size == 5
        assert inputs.sth_sequence == 5

    def test_to_bytes_deterministic(self, operator):
        sth = _make_sth(operator, sequence=3)
        inputs = ZKBridgePublicInputs.from_sth(sth)
        assert inputs.to_bytes() == inputs.to_bytes()

    def test_to_bytes_includes_domain(self, operator):
        from src.ltp.domain import DOMAIN_ZK_BRIDGE

        sth = _make_sth(operator, sequence=1)
        inputs = ZKBridgePublicInputs.from_sth(sth)
        assert inputs.to_bytes().startswith(DOMAIN_ZK_BRIDGE)


# ---------------------------------------------------------------------------
# SimulatedZKBridgeProver
# ---------------------------------------------------------------------------


class TestSimulatedZKBridgeProver:
    def test_prove_valid_sth(self, operator):
        sth = _make_sth(operator, sequence=1)
        prover = SimulatedZKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        assert isinstance(proof, ZKBridgeProof)
        assert proof.backend == ZKBridgeBackend.SIMULATED
        assert len(proof.proof_bytes) > 100  # Real STARK proof
        assert proof.proof_id != ""

    def test_proof_has_correct_public_inputs(self, operator):
        sth = _make_sth(operator, sequence=7, root_hash=b"\xbb" * 32)
        prover = SimulatedZKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        assert proof.public_inputs.sth_root_hash == b"\xbb" * 32
        assert proof.public_inputs.sth_sequence == 7
        assert proof.public_inputs.tree_size == 7

    def test_prove_invalid_sth_raises(self, operator):
        bad_sth = _make_bad_sth(operator)
        prover = SimulatedZKBridgeProver()

        with pytest.raises(ValueError, match="invalid STH signature"):
            prover.prove_sth_signature(bad_sth)

    def test_proof_is_non_deterministic(self, operator):
        """Real STARK uses random blinding, so proofs differ each time."""
        sth = _make_sth(operator, sequence=1, root_hash=b"\xcc" * 32)
        prover = SimulatedZKBridgeProver()
        p1 = prover.prove_sth_signature(sth)
        p2 = prover.prove_sth_signature(sth)

        assert p1.proof_id != p2.proof_id

    def test_backend_property(self):
        prover = SimulatedZKBridgeProver()
        assert prover.backend == ZKBridgeBackend.SIMULATED


# ---------------------------------------------------------------------------
# ZKBridgeVerifier
# ---------------------------------------------------------------------------


class TestZKBridgeVerifier:
    def test_verify_valid_proof(self, operator):
        sth = _make_sth(operator, sequence=1)
        prover = SimulatedZKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        assert ZKBridgeVerifier.verify(proof) is True

    def test_verify_tampered_proof_rejected(self, operator):
        sth = _make_sth(operator, sequence=1)
        prover = SimulatedZKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        # Tamper with verification tag
        tampered = proof.proof_bytes[:32] + b"\x00" * 32
        tampered_proof = ZKBridgeProof(
            proof_bytes=tampered,
            backend=proof.backend,
            public_inputs=proof.public_inputs,
            proof_id="tampered",
        )
        assert ZKBridgeVerifier.verify(tampered_proof) is False

    def test_verify_wrong_inputs_rejected(self, operator):
        sth = _make_sth(operator, sequence=1, root_hash=b"\xdd" * 32)
        prover = SimulatedZKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        # Change the public inputs
        wrong_inputs = ZKBridgePublicInputs(
            sth_root_hash=b"\xee" * 32,  # different root
            operator_vk_hash=proof.public_inputs.operator_vk_hash,
            tree_size=proof.public_inputs.tree_size,
            sth_sequence=proof.public_inputs.sth_sequence,
        )
        wrong_proof = ZKBridgeProof(
            proof_bytes=proof.proof_bytes,
            backend=proof.backend,
            public_inputs=wrong_inputs,
            proof_id=proof.proof_id,
        )
        assert ZKBridgeVerifier.verify(wrong_proof) is False

    def test_verify_short_proof_rejected(self, operator):
        sth = _make_sth(operator)
        inputs = ZKBridgePublicInputs.from_sth(sth)
        short_proof = ZKBridgeProof(
            proof_bytes=b"\x00" * 32,  # 32B, not 64B
            backend=ZKBridgeBackend.SIMULATED,
            public_inputs=inputs,
            proof_id="short",
        )
        assert ZKBridgeVerifier.verify(short_proof) is False

    def test_verify_is_pure(self, operator):
        sth = _make_sth(operator)
        proof = SimulatedZKBridgeProver().prove_sth_signature(sth)
        r1 = ZKBridgeVerifier.verify(proof)
        r2 = ZKBridgeVerifier.verify(proof)
        assert r1 == r2 is True


# ---------------------------------------------------------------------------
# Verification SDK
# ---------------------------------------------------------------------------


class TestVerifySDK:
    def test_valid_proof_returns_valid(self, operator):
        sth = _make_sth(operator)
        proof = SimulatedZKBridgeProver().prove_sth_signature(sth)
        result = verify_zk_bridge_proof(proof)

        assert result.valid is True
        assert result.artifact == "zk-bridge-proof"
        assert result.details["backend"] == "simulated"
        assert "proof_id" in result.details

    def test_invalid_proof_returns_invalid(self, operator):
        sth = _make_sth(operator)
        inputs = ZKBridgePublicInputs.from_sth(sth)
        bad_proof = ZKBridgeProof(
            proof_bytes=b"\x00" * 64,
            backend=ZKBridgeBackend.SIMULATED,
            public_inputs=inputs,
            proof_id="bad",
        )
        result = verify_zk_bridge_proof(bad_proof)
        assert result.valid is False
        assert result.artifact == "zk-bridge-proof"


# ---------------------------------------------------------------------------
# ChallengeManager ZK resolution
# ---------------------------------------------------------------------------


class TestChallengeManagerZK:
    def test_resolve_open_window_with_proof(self, operator):
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("ent-zk1", b"\x01" * 32)

        sth = _make_sth(operator)
        proof = SimulatedZKBridgeProver().prove_sth_signature(sth)

        rec = mgr.resolve_with_proof("ent-zk1", proof)
        assert rec.status == ChallengeStatus.FINALIZED
        assert rec.resolution == "zk_proof"

    def test_resolve_challenged_window_with_proof(self, operator):
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("ent-zk2", b"\x02" * 32)

        # File a challenge first
        fraud = InvalidSignatureFraudProof(
            anchor_digest=b"\x02" * 32,
            claimed_signer_vk=operator.vk,
            signed_data=b"data",
            signature=b"\x00" * 64,
        )
        mgr.submit_challenge("ent-zk2", fraud)
        assert mgr.get("ent-zk2").status == ChallengeStatus.CHALLENGED

        # ZK proof resolves the challenge
        sth = _make_sth(operator)
        proof = SimulatedZKBridgeProver().prove_sth_signature(sth)
        rec = mgr.resolve_with_proof("ent-zk2", proof)
        assert rec.status == ChallengeStatus.FINALIZED

    def test_invalid_proof_rejected(self, operator):
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("ent-zk3", b"\x03" * 32)

        sth = _make_sth(operator)
        inputs = ZKBridgePublicInputs.from_sth(sth)
        bad_proof = ZKBridgeProof(
            proof_bytes=b"\x00" * 64,
            backend=ZKBridgeBackend.SIMULATED,
            public_inputs=inputs,
            proof_id="bad",
        )
        with pytest.raises(ValueError, match="verification failed"):
            mgr.resolve_with_proof("ent-zk3", bad_proof)

        # Status should be unchanged
        assert mgr.get("ent-zk3").status == ChallengeStatus.OPEN


# ---------------------------------------------------------------------------
# LiveBridge ZK integration
# ---------------------------------------------------------------------------


class _MockEntityState(IntEnum):
    UNKNOWN = 0
    ANCHORED = 2


class _MockClient:
    def __init__(self):
        self._anchored = set()
        self._sequence = 0

    def anchor(self, sub):
        self._anchored.add(sub.anchor_digest)
        self._sequence = sub.sequence
        return f"0x{'ab' * 32}"

    def is_anchored(self, d):
        return d in self._anchored

    def entity_state(self, e):
        return _MockEntityState.ANCHORED

    def signer_sequence(self, v):
        return self._sequence

    def get_block_number(self):
        return 100


class TestLiveBridgeZK:
    def _make_bridge(self, challenge_manager=None, zk_prover=None):
        net = CommitmentNetwork()
        for nid, region in [
            ("zk-1", "US-East"),
            ("zk-2", "US-West"),
            ("zk-3", "EU-West"),
            ("zk-4", "EU-East"),
            ("zk-5", "AP-East"),
            ("zk-6", "AP-South"),
        ]:
            net.add_node(nid, region)
        protocol = LTPProtocol(net)
        op = KeyPair.generate("zk-bridge-op")
        vf = KeyPair.generate("zk-bridge-vf")
        client = _MockClient()

        from src.ltp.bridge.live import LiveBridge

        return LiveBridge(
            protocol=protocol,
            l1_client=client,
            operator_keypair=op,
            l2_verifier_keypair=vf,
            l1_chain_id=31337,
            challenge_manager=challenge_manager,
            zk_prover=zk_prover,
        )

    def _make_msg(self, nonce=0):
        from src.ltp.bridge.message import BridgeMessage

        return BridgeMessage(
            msg_type="token_lock",
            source_chain="ethereum",
            dest_chain="optimism",
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 100},
            nonce=nonce,
        )

    def test_transfer_without_zk_prover_unchanged(self):
        """Backward compat: no zk_prover, no ZK fields."""
        bridge = self._make_bridge()
        result = bridge.transfer(self._make_msg())
        assert result is not None
        assert result.zk_proof_id is None
        assert result.zk_finalized is False

    def test_transfer_with_zk_prover_instant_finality(self):
        """With zk_prover + challenge_manager: instant finality via ZK proof."""
        mgr = ChallengeManager(challenge_period=604800.0)
        prover = SimulatedZKBridgeProver()
        bridge = self._make_bridge(challenge_manager=mgr, zk_prover=prover)

        result = bridge.transfer(self._make_msg())
        assert result is not None
        assert result.zk_finalized is True
        assert result.zk_proof_id is not None
        assert result.challenge_status == "finalized"
        assert result.challenge_deadline is None

    def test_transfer_zk_prover_only_no_challenge_manager(self):
        """With zk_prover but no challenge_manager: proof generated, zk_finalized=True."""
        prover = SimulatedZKBridgeProver()
        bridge = self._make_bridge(zk_prover=prover)

        result = bridge.transfer(self._make_msg())
        assert result is not None
        assert result.zk_finalized is True
        assert result.zk_proof_id is not None
        assert result.challenge_status is None  # no challenge manager


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_full_commit_prove_verify_finalize(self, operator, verifier):
        """Complete flow: commit -> get STH -> prove -> verify -> finalize."""
        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"e2e-{i}", ["US-East", "US-West", "EU-West"][i % 3])
        protocol = LTPProtocol(net)

        # Commit an entity
        from src.ltp.entity import Entity

        entity = Entity(content=b"ZK end-to-end test data " * 10, shape="text/plain")
        entity_id, record, cek = protocol.commit(entity, operator)

        # Get the latest STH
        sth = protocol.network.log.latest_sth
        assert sth is not None

        # Generate ZK proof
        prover = SimulatedZKBridgeProver()
        proof = prover.prove_sth_signature(sth)

        # Verify the proof
        assert ZKBridgeVerifier.verify(proof) is True

        # SDK verification
        result = verify_zk_bridge_proof(proof)
        assert result.valid is True
        assert result.details["sth_sequence"] == sth.sequence

        # ChallengeManager resolution
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window(entity_id, b"\xff" * 32)
        rec = mgr.resolve_with_proof(entity_id, proof)
        assert rec.status == ChallengeStatus.FINALIZED
        assert rec.resolution == "zk_proof"
