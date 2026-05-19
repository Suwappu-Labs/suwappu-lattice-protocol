"""Tests for Signed Message Envelope (envelope.py)."""

import time

import pytest

from src.ltp import CommitmentRecord, KeyPair, reset_poc_state
from src.ltp.domain import (
    DOMAIN_COMMIT_RECORD,
    DOMAIN_SIGNED_ENVELOPE,
    DOMAIN_STH_SIGN,
    signer_fingerprint,
)
from src.ltp.envelope import SignedEnvelope


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
def sample_payload():
    return b"sample-canonical-payload-bytes"


class TestSignedEnvelopeCreateVerify:
    """Test envelope creation and verification."""

    def test_create_and_verify(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="commitment-record",
            payload=sample_payload,
        )
        assert env.verify()

    def test_create_at_deterministic(self, alice, sample_payload):
        ts = 1700000000.0
        env1 = SignedEnvelope.create_at(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
            timestamp=ts,
        )
        env2 = SignedEnvelope.create_at(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
            timestamp=ts,
        )
        assert env1.timestamp == env2.timestamp == ts
        assert env1.signable_content() == env2.signable_content()

    def test_version_is_one(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        assert env.version == 1

    def test_signer_kid_matches_fingerprint(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        assert env.signer_kid == signer_fingerprint(alice.vk)


class TestSignedEnvelopeRejection:
    """Test that invalid envelopes are rejected."""

    def test_wrong_signer_fails(self, alice, bob, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        # Tamper: change signer_vk to bob's
        env.signer_vk = bob.vk
        assert not env.verify()

    def test_tampered_payload_fails(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        env.payload = b"tampered-payload"
        assert not env.verify()

    def test_domain_binding(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        # Change domain after signing
        env.domain = DOMAIN_STH_SIGN
        assert not env.verify()

    def test_max_drift_rejects_stale(self, alice, sample_payload):
        ts = time.time() - 120  # 2 minutes ago
        env = SignedEnvelope.create_at(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
            timestamp=ts,
        )
        # Without max_drift, should be valid
        assert env.verify()
        # With 60s max_drift, should fail (envelope is 120s old)
        assert not env.verify(max_drift=60.0)

    def test_max_drift_accepts_fresh(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        assert env.verify(max_drift=60.0)


class TestSignedEnvelopeUtilities:
    """Test peek_payload and extract_signer_kid."""

    def test_peek_payload(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="commitment-record",
            payload=sample_payload,
        )
        pt, p = SignedEnvelope.peek_payload(env)
        assert pt == "commitment-record"
        assert p == sample_payload

    def test_extract_signer_kid(self, alice, sample_payload):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        kid = SignedEnvelope.extract_signer_kid(env)
        assert kid == signer_fingerprint(alice.vk)

    def test_fingerprint_stable_and_unique(self, alice, bob, sample_payload):
        env1 = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=sample_payload,
        )
        env2 = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=bob.vk,
            signer_sk=bob.sk,
            signer_id="bob",
            payload_type="test",
            payload=sample_payload,
        )
        # Different signers → different fingerprints
        assert env1.fingerprint() != env2.fingerprint()
        # Same envelope → stable fingerprint
        assert env1.fingerprint() == env1.fingerprint()


class TestSignedEnvelopeIntegration:
    """Test with real protocol objects."""

    def test_commitment_record_to_envelope(self, alice):
        record = CommitmentRecord(
            entity_id="a" * 64,
            sender_id="alice",
            shard_map_root="b" * 64,
            content_hash="c" * 64,
            encoding_params={"n": "8", "k": "4"},
            shape="text/plain",
            shape_hash="d" * 64,
            timestamp=1234567890.123,
        )
        env = record.to_envelope(alice.vk, alice.sk, "alice")
        assert env.verify()
        assert env.payload_type == "commitment-record"
        assert env.signer_id == "alice"

    def test_sth_sign_envelope(self, alice):
        from src.ltp.merkle_log.sth import SignedTreeHead

        env = SignedTreeHead.sign_envelope(
            sequence=1,
            tree_size=5,
            root_hash=b"\x00" * 32,
            operator_vk=alice.vk,
            operator_sk=alice.sk,
        )
        assert env.verify()
        assert env.payload_type == "sth"
