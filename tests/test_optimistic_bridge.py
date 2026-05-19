"""
Optimistic bridge integration tests.

Tests fraud proof types, challenge manager lifecycle, watcher service
fraud detection, and LiveBridge integration with challenge windows.

All tests are deterministic — clock is injected, no threads, no sleeps.
"""

from __future__ import annotations

import struct
import time
from enum import IntEnum
from unittest.mock import MagicMock

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge.challenge import (
    ChallengeManager,
    ChallengeRecord,
    ChallengeStatus,
)
from src.ltp.bridge.fraud_proof import (
    FraudProofType,
    InconsistentSTHFraudProof,
    InvalidMerkleProofFraudProof,
    InvalidSignatureFraudProof,
)
from src.ltp.bridge.watcher import STHStore, WatcherService, WatcherTickResult
from src.ltp.primitives import MLDSA

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sth(keypair: KeyPair, sequence: int, root_hash: bytes):
    """Create a SignedTreeHead with a real ML-DSA signature."""
    from src.ltp.merkle_log.sth import SignedTreeHead

    sth = SignedTreeHead(
        sequence=sequence,
        tree_size=sequence,
        timestamp=time.time(),
        root_hash=root_hash,
        operator_vk=keypair.vk,
        signature=b"",  # placeholder
    )
    # Sign with real ML-DSA
    payload = sth.signable_payload()
    sig = MLDSA.sign(keypair.sk, payload)
    # SignedTreeHead is a frozen dataclass — recreate with signature
    return SignedTreeHead(
        sequence=sth.sequence,
        tree_size=sth.tree_size,
        timestamp=sth.timestamp,
        root_hash=sth.root_hash,
        operator_vk=sth.operator_vk,
        signature=sig,
    )


def _make_bad_sth(keypair: KeyPair, sequence: int, root_hash: bytes):
    """Create an STH with an invalid signature."""
    from src.ltp.merkle_log.sth import SignedTreeHead

    return SignedTreeHead(
        sequence=sequence,
        tree_size=sequence,
        timestamp=time.time(),
        root_hash=root_hash,
        operator_vk=keypair.vk,
        signature=b"\x00" * 64,  # invalid signature
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def operator_kp() -> KeyPair:
    return KeyPair.generate("4f-operator")


@pytest.fixture(scope="session")
def verifier_kp() -> KeyPair:
    return KeyPair.generate("4f-verifier")


# ---------------------------------------------------------------------------
# Fraud Proof Tests
# ---------------------------------------------------------------------------


class TestInvalidSignatureFraudProof:
    """InvalidSignatureFraudProof: ML-DSA signature doesn't verify."""

    def test_valid_fraud_proof(self, operator_kp):
        """A bad signature produces a valid fraud proof (verify() == True)."""
        data = b"commitment record data"
        bad_sig = b"\x00" * 64  # invalid signature

        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\xaa" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=data,
            signature=bad_sig,
        )
        assert proof.verify() is True
        assert proof.proof_type == FraudProofType.INVALID_SIGNATURE

    def test_good_signature_not_fraud(self, operator_kp):
        """A valid signature means no fraud (verify() == False)."""
        data = b"legitimate commitment record"
        sig = MLDSA.sign(operator_kp.sk, data)

        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\xbb" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=data,
            signature=sig,
        )
        assert proof.verify() is False

    def test_proof_hash_deterministic(self, operator_kp):
        """proof_hash() returns consistent 32-byte hash."""
        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\xcc" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=b"data",
            signature=b"\x00" * 64,
        )
        h1 = proof.proof_hash()
        h2 = proof.proof_hash()
        assert h1 == h2
        assert len(h1) == 32

    def test_to_bytes_includes_domain(self, operator_kp):
        """Canonical encoding starts with the fraud proof domain tag."""
        from src.ltp.domain import DOMAIN_FRAUD_PROOF

        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\xdd" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=b"data",
            signature=b"\x00" * 64,
        )
        assert proof.to_bytes().startswith(DOMAIN_FRAUD_PROOF)


class TestInconsistentSTHFraudProof:
    """InconsistentSTHFraudProof: two valid STHs at same sequence, different roots."""

    def test_valid_fork_fraud_proof(self, operator_kp):
        """Two valid STHs at same sequence with different roots = valid fraud."""
        sth_a = _make_sth(operator_kp, sequence=5, root_hash=b"\x11" * 32)
        sth_b = _make_sth(operator_kp, sequence=5, root_hash=b"\x22" * 32)

        proof = InconsistentSTHFraudProof(sth_a=sth_a, sth_b=sth_b)
        assert proof.verify() is True

    def test_same_root_not_fraud(self, operator_kp):
        """Same root at same sequence = not a fork."""
        root = b"\x33" * 32
        sth_a = _make_sth(operator_kp, sequence=5, root_hash=root)
        sth_b = _make_sth(operator_kp, sequence=5, root_hash=root)

        proof = InconsistentSTHFraudProof(sth_a=sth_a, sth_b=sth_b)
        assert proof.verify() is False

    def test_different_sequence_not_fraud(self, operator_kp):
        """Different sequences = not a fork, just normal progress."""
        sth_a = _make_sth(operator_kp, sequence=5, root_hash=b"\x44" * 32)
        sth_b = _make_sth(operator_kp, sequence=6, root_hash=b"\x55" * 32)

        proof = InconsistentSTHFraudProof(sth_a=sth_a, sth_b=sth_b)
        assert proof.verify() is False

    def test_different_operators_not_fraud(self, operator_kp, verifier_kp):
        """Different operators = not equivocation from a single operator."""
        sth_a = _make_sth(operator_kp, sequence=5, root_hash=b"\x66" * 32)
        sth_b = _make_sth(verifier_kp, sequence=5, root_hash=b"\x77" * 32)

        proof = InconsistentSTHFraudProof(sth_a=sth_a, sth_b=sth_b)
        assert proof.verify() is False


class TestInvalidMerkleProofFraudProof:
    """InvalidMerkleProofFraudProof: Merkle proof doesn't verify."""

    def test_bad_proof_is_valid_fraud(self):
        """A Merkle proof that fails verification is valid fraud."""
        from src.ltp.merkle_log.portable_proof import PortableMerkleProof, TreeType

        bad_proof = PortableMerkleProof(
            version=1,
            tree_type=TreeType.COMMITMENT_LOG,
            leaf_index=0,
            tree_size=4,
            leaf_hash=b"\xaa" * 32,
            root_hash=b"\xbb" * 32,  # Doesn't match
            path=[b"\xcc" * 32],
            path_directions=[True],
        )

        fraud = InvalidMerkleProofFraudProof(
            anchor_digest=b"\xdd" * 32,
            claimed_root=b"\xbb" * 32,
            proof=bad_proof,
        )
        assert fraud.verify() is True


# ---------------------------------------------------------------------------
# Challenge Manager Tests
# ---------------------------------------------------------------------------


class TestChallengeManager:
    """ChallengeManager: challenge period lifecycle."""

    def test_open_and_finalize(self):
        """Open window, advance clock past deadline, tick auto-finalizes."""
        now = 1000000.0
        clock = lambda: now

        mgr = ChallengeManager(challenge_period=100.0, clock=clock)
        rec = mgr.open_challenge_window("entity-1", b"\x01" * 32)
        assert rec.status == ChallengeStatus.OPEN
        assert rec.challenge_deadline == now + 100.0

        # Advance past deadline
        now = 1000101.0
        finalized = mgr.tick(now)
        assert "entity-1" in finalized
        assert mgr.get("entity-1").status == ChallengeStatus.FINALIZED

    def test_open_challenge_resolve(self, operator_kp):
        """Open → challenge with fraud proof → resolve as valid fraud."""
        now = 1000000.0
        clock = lambda: now

        mgr = ChallengeManager(challenge_period=100.0, clock=clock)
        mgr.open_challenge_window("entity-2", b"\x02" * 32)

        # Submit a valid fraud proof
        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\x02" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=b"data",
            signature=b"\x00" * 64,
        )
        rec = mgr.submit_challenge("entity-2", proof, challenger_id="watcher-1")
        assert rec.status == ChallengeStatus.CHALLENGED
        assert rec.fraud_proof_type == "invalid_signature"

        # Resolve
        rec = mgr.resolve_challenge("entity-2", "valid_fraud")
        assert rec.status == ChallengeStatus.RESOLVED
        assert rec.resolution == "valid_fraud"

    def test_duplicate_open_rejected(self):
        """Opening a second window for the same entity raises ValueError."""
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("entity-3", b"\x03" * 32)

        with pytest.raises(ValueError, match="already active"):
            mgr.open_challenge_window("entity-3", b"\x03" * 32)

    def test_challenge_after_deadline_rejected(self, operator_kp):
        """Submitting a challenge after deadline raises ValueError."""
        now = 1000000.0
        clock = lambda: now

        mgr = ChallengeManager(challenge_period=100.0, clock=clock)
        mgr.open_challenge_window("entity-4", b"\x04" * 32)

        now = 1000200.0  # way past deadline

        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\x04" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=b"data",
            signature=b"\x00" * 64,
        )
        with pytest.raises(ValueError, match="expired"):
            mgr.submit_challenge("entity-4", proof)

    def test_invalid_fraud_proof_rejected(self, operator_kp):
        """A fraud proof that fails verify() is rejected."""
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("entity-5", b"\x05" * 32)

        # Create a "fraud proof" with a VALID signature (not actual fraud)
        data = b"legitimate data"
        sig = MLDSA.sign(operator_kp.sk, data)
        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\x05" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=data,
            signature=sig,
        )
        with pytest.raises(ValueError, match="verification failed"):
            mgr.submit_challenge("entity-5", proof)

    def test_tick_expires_unresolved_challenges(self, operator_kp):
        """Challenged but unresolved windows expire after deadline."""
        now = 1000000.0
        clock = lambda: now

        mgr = ChallengeManager(challenge_period=100.0, clock=clock)
        mgr.open_challenge_window("entity-6", b"\x06" * 32)

        proof = InvalidSignatureFraudProof(
            anchor_digest=b"\x06" * 32,
            claimed_signer_vk=operator_kp.vk,
            signed_data=b"data",
            signature=b"\x00" * 64,
        )
        mgr.submit_challenge("entity-6", proof)

        now = 1000200.0
        expired = mgr.tick(now)
        assert "entity-6" in expired
        assert mgr.get("entity-6").status == ChallengeStatus.EXPIRED

    def test_stats(self):
        """stats() returns correct counts by status."""
        mgr = ChallengeManager(challenge_period=1000.0)
        mgr.open_challenge_window("a", b"\x0a" * 32)
        mgr.open_challenge_window("b", b"\x0b" * 32)

        stats = mgr.stats()
        assert stats["open"] == 2
        assert stats["finalized"] == 0


# ---------------------------------------------------------------------------
# Watcher Service Tests
# ---------------------------------------------------------------------------


class TestSTHStore:
    """STHStore: fork detection via duplicate STH tracking."""

    def test_no_fork_on_first_record(self, operator_kp):
        """First STH at a sequence is stored, no fork detected."""
        store = STHStore()
        sth = _make_sth(operator_kp, sequence=1, root_hash=b"\x11" * 32)
        result = store.record(sth)
        assert result is None
        assert store.size == 1

    def test_fork_detected(self, operator_kp):
        """Two STHs at same sequence with different roots returns fraud proof."""
        store = STHStore()
        sth_a = _make_sth(operator_kp, sequence=1, root_hash=b"\x11" * 32)
        sth_b = _make_sth(operator_kp, sequence=1, root_hash=b"\x22" * 32)

        store.record(sth_a)
        proof = store.record(sth_b)
        assert proof is not None
        assert proof.verify() is True

    def test_same_root_no_fork(self, operator_kp):
        """Same root at same sequence is not a fork."""
        store = STHStore()
        root = b"\x33" * 32
        sth_a = _make_sth(operator_kp, sequence=1, root_hash=root)
        sth_b = _make_sth(operator_kp, sequence=1, root_hash=root)

        store.record(sth_a)
        proof = store.record(sth_b)
        assert proof is None


class TestWatcherService:
    """WatcherService: off-chain verification daemon."""

    def test_clean_anchor_passes(self, operator_kp):
        """Valid STH with good signature passes verification."""
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("ent-w1", b"\x01" * 32)

        watcher = WatcherService(challenge_manager=mgr)
        sth = _make_sth(operator_kp, sequence=1, root_hash=b"\x11" * 32)
        watcher.submit_for_verification(b"\x01" * 32, sth, "ent-w1")

        result = watcher.tick(1)
        assert result.anchors_checked == 1
        assert result.signatures_verified == 1
        assert result.signatures_invalid == 0
        assert result.fraud_proofs_submitted == 0

    def test_bad_signature_detected(self, operator_kp):
        """Invalid ML-DSA signature triggers fraud proof submission."""
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("ent-w2", b"\x02" * 32)

        watcher = WatcherService(challenge_manager=mgr)
        bad_sth = _make_bad_sth(operator_kp, sequence=1, root_hash=b"\x22" * 32)
        watcher.submit_for_verification(b"\x02" * 32, bad_sth, "ent-w2")

        result = watcher.tick(1)
        assert result.signatures_invalid == 1
        assert result.fraud_proofs_submitted == 1

        # Challenge should now be filed
        rec = mgr.get("ent-w2")
        assert rec.status == ChallengeStatus.CHALLENGED

    def test_fork_detected(self, operator_kp):
        """Two valid STHs at same sequence with different roots triggers fraud proof."""
        mgr = ChallengeManager(challenge_period=100.0)
        mgr.open_challenge_window("ent-w3", b"\x03" * 32)

        store = STHStore()
        watcher = WatcherService(challenge_manager=mgr, sth_store=store)

        # First STH is clean
        sth_a = _make_sth(operator_kp, sequence=5, root_hash=b"\x33" * 32)
        watcher.submit_for_verification(b"\x03" * 32, sth_a, "ent-w3")
        result1 = watcher.tick(1)
        assert result1.forks_detected == 0

        # Need new challenge window for same entity (re-open after first was consumed)
        # The first tick passed without challenge, so window is still OPEN
        # Submit second STH with different root at same sequence
        sth_b = _make_sth(operator_kp, sequence=5, root_hash=b"\x44" * 32)
        watcher.submit_for_verification(b"\x03" * 32, sth_b, "ent-w3")
        result2 = watcher.tick(2)
        assert result2.forks_detected == 1
        assert result2.fraud_proofs_submitted == 1


# ---------------------------------------------------------------------------
# LiveBridge Integration Tests
# ---------------------------------------------------------------------------


class _MockEntityState(IntEnum):
    UNKNOWN = 0
    COMMITTED = 1
    ANCHORED = 2


class _MockClient:
    """Minimal mock for LiveBridge tests."""

    def __init__(self, chain_id=1, block_height=100):
        self._anchored = set()
        self._sequence = 0
        self._block_height = block_height

    def anchor(self, submission):
        self._anchored.add(submission.anchor_digest)
        self._sequence = submission.sequence
        return f"0x{'ab' * 32}"

    def is_anchored(self, digest):
        return digest in self._anchored

    def entity_state(self, eid_hash):
        return _MockEntityState.ANCHORED

    def signer_sequence(self, vk_hash):
        return self._sequence

    def get_block_number(self):
        return self._block_height


class TestOptimisticLiveBridge:
    """LiveBridge with ChallengeManager integration."""

    def _make_bridge(self, challenge_manager=None):
        net = CommitmentNetwork()
        for nid, region in [
            ("ob-1", "US-East"),
            ("ob-2", "US-West"),
            ("ob-3", "EU-West"),
            ("ob-4", "EU-East"),
            ("ob-5", "AP-East"),
            ("ob-6", "AP-South"),
        ]:
            net.add_node(nid, region)

        protocol = LTPProtocol(net)
        operator = KeyPair.generate("ob-operator")
        verifier = KeyPair.generate("ob-verifier")
        client = _MockClient()

        from src.ltp.bridge.live import LiveBridge

        bridge = LiveBridge(
            protocol=protocol,
            l1_client=client,
            operator_keypair=operator,
            l2_verifier_keypair=verifier,
            l1_chain_id=31337,
            challenge_manager=challenge_manager,
        )
        return bridge

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

    def test_transfer_without_challenge_manager(self):
        """Without challenge_manager, challenge fields are None (backward compat)."""
        bridge = self._make_bridge()
        result = bridge.transfer(self._make_msg())
        assert result is not None
        assert result.challenge_status is None
        assert result.challenge_deadline is None

    def test_transfer_with_challenge_manager(self):
        """With challenge_manager, transfer opens a challenge window."""
        mgr = ChallengeManager(challenge_period=604800.0)
        bridge = self._make_bridge(challenge_manager=mgr)

        result = bridge.transfer(self._make_msg())
        assert result is not None
        assert result.challenge_status == "open"
        assert result.challenge_deadline is not None
        assert result.challenge_deadline > time.time()

        # Challenge record exists in manager
        rec = mgr.get(result.entity_id)
        assert rec is not None
        assert rec.status == ChallengeStatus.OPEN

    def test_challenge_window_lifecycle_with_transfer(self):
        """Transfer opens window, clock advances, tick finalizes."""
        now = 1000000.0
        clock = lambda: now

        mgr = ChallengeManager(challenge_period=100.0, clock=clock)
        bridge = self._make_bridge(challenge_manager=mgr)

        result = bridge.transfer(self._make_msg())
        assert result.challenge_status == "open"

        # Advance past challenge period
        now = 1000200.0
        finalized = mgr.tick(now)
        assert result.entity_id in finalized
        assert mgr.get(result.entity_id).status == ChallengeStatus.FINALIZED
