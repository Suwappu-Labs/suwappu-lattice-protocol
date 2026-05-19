"""Tests for Sequence Tracker (sequencing.py)."""

import time

import pytest

from src.ltp import KeyPair, reset_poc_state
from src.ltp.sequencing import SequenceTracker


@pytest.fixture(autouse=True)
def fresh_state():
    reset_poc_state()
    yield
    reset_poc_state()


@pytest.fixture
def alice():
    return KeyPair.generate("alice")


@pytest.fixture
def bob():
    return KeyPair.generate("bob")


@pytest.fixture
def tracker():
    return SequenceTracker(chain_id="base-testnet")


class TestMonotonicEnforcement:
    """Test monotonic sequence enforcement."""

    def test_first_sequence_accepted(self, tracker, alice):
        ok, reason = tracker.validate_and_advance(
            alice.vk,
            0,
            "base-testnet",
            time.time() + 3600,
        )
        assert ok
        assert reason == ""

    def test_increasing_sequence_accepted(self, tracker, alice):
        future = time.time() + 3600
        ok, _ = tracker.validate_and_advance(alice.vk, 0, "base-testnet", future)
        assert ok
        ok, _ = tracker.validate_and_advance(alice.vk, 1, "base-testnet", future)
        assert ok
        ok, _ = tracker.validate_and_advance(alice.vk, 5, "base-testnet", future)
        assert ok

    def test_replay_rejected(self, tracker, alice):
        future = time.time() + 3600
        ok, _ = tracker.validate_and_advance(alice.vk, 5, "base-testnet", future)
        assert ok
        ok, reason = tracker.validate_and_advance(alice.vk, 5, "base-testnet", future)
        assert not ok
        assert "replay" in reason

    def test_lower_sequence_rejected(self, tracker, alice):
        future = time.time() + 3600
        ok, _ = tracker.validate_and_advance(alice.vk, 5, "base-testnet", future)
        assert ok
        ok, reason = tracker.validate_and_advance(alice.vk, 3, "base-testnet", future)
        assert not ok
        assert "replay" in reason


class TestChainBinding:
    """Test chain binding enforcement."""

    def test_wrong_chain_rejected(self, tracker, alice):
        future = time.time() + 3600
        ok, reason = tracker.validate_and_advance(
            alice.vk,
            0,
            "wrong-chain",
            future,
        )
        assert not ok
        assert "chain mismatch" in reason

    def test_correct_chain_accepted(self, tracker, alice):
        future = time.time() + 3600
        ok, _ = tracker.validate_and_advance(
            alice.vk,
            0,
            "base-testnet",
            future,
        )
        assert ok


class TestTemporalExpiry:
    """Test temporal expiry enforcement."""

    def test_expired_rejected(self, tracker, alice):
        past = time.time() - 1  # Already expired
        ok, reason = tracker.validate_and_advance(
            alice.vk,
            0,
            "base-testnet",
            past,
        )
        assert not ok
        assert "expired" in reason

    def test_future_accepted(self, tracker, alice):
        future = time.time() + 3600
        ok, _ = tracker.validate_and_advance(
            alice.vk,
            0,
            "base-testnet",
            future,
        )
        assert ok


class TestMultipleSigners:
    """Test independent tracking per signer."""

    def test_independent_signers(self, tracker, alice, bob):
        future = time.time() + 3600
        # Alice at seq 0
        ok, _ = tracker.validate_and_advance(alice.vk, 0, "base-testnet", future)
        assert ok
        # Bob at seq 0 (independent)
        ok, _ = tracker.validate_and_advance(bob.vk, 0, "base-testnet", future)
        assert ok
        # Alice at seq 1
        ok, _ = tracker.validate_and_advance(alice.vk, 1, "base-testnet", future)
        assert ok

    def test_next_sequence(self, tracker, alice, bob):
        future = time.time() + 3600
        assert tracker.next_sequence(alice.vk) == 0
        tracker.validate_and_advance(alice.vk, 0, "base-testnet", future)
        assert tracker.next_sequence(alice.vk) == 1
        assert tracker.next_sequence(bob.vk) == 0  # Bob unseen

    def test_current_sequence(self, tracker, alice):
        assert tracker.current_sequence(alice.vk) == -1  # Unseen
        future = time.time() + 3600
        tracker.validate_and_advance(alice.vk, 0, "base-testnet", future)
        assert tracker.current_sequence(alice.vk) == 0


class TestBatchValidation:
    """Test batch validation."""

    def test_batch_all_valid(self, tracker, alice):
        future = time.time() + 3600
        items = [
            (alice.vk, 0, "base-testnet", future),
            (alice.vk, 1, "base-testnet", future),
            (alice.vk, 2, "base-testnet", future),
        ]
        results = tracker.validate_batch(items)
        assert all(ok for ok, _ in results)

    def test_batch_with_replay(self, tracker, alice):
        future = time.time() + 3600
        items = [
            (alice.vk, 0, "base-testnet", future),
            (alice.vk, 0, "base-testnet", future),  # Replay
        ]
        results = tracker.validate_batch(items)
        assert results[0][0] is True
        assert results[1][0] is False

    def test_batch_mixed(self, tracker, alice, bob):
        future = time.time() + 3600
        past = time.time() - 1
        items = [
            (alice.vk, 0, "base-testnet", future),  # OK
            (bob.vk, 0, "wrong-chain", future),  # Chain mismatch
            (alice.vk, 1, "base-testnet", past),  # Expired
        ]
        results = tracker.validate_batch(items)
        assert results[0][0] is True
        assert results[1][0] is False
        assert results[2][0] is False
