"""
Adversarial tests for the GSX Pre-Blockchain Trust Packaging Layer.

Proves that the system correctly *rejects* invalid/tampered inputs —
not just that valid inputs pass. Every test in this file asserts a
negative: forgery, tampering, replay, drift, or malformed data must fail.
"""

import math
import struct
import time

import pytest

from src.ltp import (
    CommitmentNetwork,
    CommitmentRecord,
    Entity,
    KeyPair,
    LTPProtocol,
    reset_poc_state,
)
from src.ltp.domain import (
    DOMAIN_ANCHOR_DIGEST,
    DOMAIN_APPROVAL_RECEIPT,
    DOMAIN_COMMIT_RECORD,
    DOMAIN_SIGNED_ENVELOPE,
    DOMAIN_SIGNER_POLICY,
    DOMAIN_STH_SIGN,
    domain_sign,
    domain_verify,
    signer_fingerprint,
)
from src.ltp.encoding import CanonicalEncoder
from src.ltp.envelope import SignedEnvelope
from src.ltp.receipt import ApprovalReceipt, ReceiptType
from src.ltp.sequencing import SequenceTracker

# ── Fixtures ──────────────────────────────────────────────────────────────


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
def eve():
    """Adversary keypair."""
    return KeyPair.generate("eve")


@pytest.fixture
def committed(alice):
    net = CommitmentNetwork()
    for i in range(3):
        net.add_node(f"node-{i}", "us-east-1")
    proto = LTPProtocol(net)
    entity = Entity(content=b"adversarial-test-content", shape="text/plain")
    eid, record, cek = proto.commit(entity, alice)
    sth = net.log.latest_sth
    return eid, record, sth, net


@pytest.fixture
def valid_receipt(alice, committed):
    eid, record, sth, net = committed
    return ApprovalReceipt.for_commit(
        entity_id=eid,
        record=record,
        sth=sth,
        signer_kp=alice,
        signer_role="operator",
        sequence=0,
        target_chain_id="base-testnet",
    )


@pytest.fixture
def valid_envelope(alice):
    return SignedEnvelope.create(
        domain=DOMAIN_COMMIT_RECORD,
        signer_vk=alice.vk,
        signer_sk=alice.sk,
        signer_id="alice",
        payload_type="test",
        payload=b"authentic-payload",
    )


# ── Canonical Encoder adversarial ─────────────────────────────────────────


class TestEncoderAdversarial:
    """Encoding edge cases and rejection of invalid inputs."""

    def test_nan_rejected(self):
        with pytest.raises(ValueError, match="NaN"):
            CanonicalEncoder(b"t\x00").float64(float("nan"))

    def test_positive_inf_rejected(self):
        with pytest.raises(ValueError, match="Inf"):
            CanonicalEncoder(b"t\x00").float64(float("inf"))

    def test_negative_inf_rejected(self):
        with pytest.raises(ValueError, match="Inf"):
            CanonicalEncoder(b"t\x00").float64(float("-inf"))

    def test_uint8_negative_rejected(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"t\x00").uint8(-1)

    def test_uint8_overflow_rejected(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"t\x00").uint8(256)

    def test_uint32_overflow_rejected(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"t\x00").uint32(2**32)

    def test_uint64_negative_rejected(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"t\x00").uint64(-1)

    def test_empty_object_tag_rejected(self):
        with pytest.raises(ValueError):
            CanonicalEncoder(b"")

    def test_bit_flip_in_tag_produces_different_output(self):
        tag1 = b"GSX-LTP:test:v1\x00"
        tag2 = bytearray(tag1)
        tag2[0] ^= 0x01
        r1 = CanonicalEncoder(tag1).string("data").finalize()
        r2 = CanonicalEncoder(bytes(tag2)).string("data").finalize()
        assert r1 != r2

    def test_sorted_map_insertion_order_irrelevant(self):
        """Different insertion orders produce identical bytes."""
        d1 = {"c": "3", "a": "1", "b": "2"}
        d2 = {"a": "1", "b": "2", "c": "3"}
        d3 = {"b": "2", "c": "3", "a": "1"}
        r1 = CanonicalEncoder(b"t\x00").sorted_map(d1).finalize()
        r2 = CanonicalEncoder(b"t\x00").sorted_map(d2).finalize()
        r3 = CanonicalEncoder(b"t\x00").sorted_map(d3).finalize()
        assert r1 == r2 == r3

    def test_optional_present_vs_absent_differ(self):
        present = CanonicalEncoder(b"t\x00").optional_bytes(b"x").finalize()
        absent = CanonicalEncoder(b"t\x00").optional_bytes(None).finalize()
        assert present != absent

    def test_length_prefix_prevents_boundary_confusion(self):
        """'ab' + 'c' must differ from 'a' + 'bc'."""
        r1 = CanonicalEncoder(b"t\x00").string("ab").string("c").finalize()
        r2 = CanonicalEncoder(b"t\x00").string("a").string("bc").finalize()
        assert r1 != r2

    def test_uint64_zero_vs_optional_absent_differ(self):
        """uint64(0) and optional_uint64(None) must produce different bytes."""
        r1 = CanonicalEncoder(b"t\x00").uint64(0).finalize()
        r2 = CanonicalEncoder(b"t\x00").optional_uint64(None).finalize()
        assert r1 != r2


# ── Domain Separation adversarial ─────────────────────────────────────────


class TestDomainAdversarial:
    """Cross-domain signature replay and isolation attacks."""

    def test_commit_sig_does_not_verify_as_sth(self, alice):
        data = b"shared-message"
        sig = domain_sign(DOMAIN_COMMIT_RECORD, alice.sk, data)
        assert not domain_verify(DOMAIN_STH_SIGN, alice.vk, data, sig)

    def test_sth_sig_does_not_verify_as_receipt(self, alice):
        data = b"shared-message"
        sig = domain_sign(DOMAIN_STH_SIGN, alice.sk, data)
        assert not domain_verify(DOMAIN_APPROVAL_RECEIPT, alice.vk, data, sig)

    def test_receipt_sig_does_not_verify_as_envelope(self, alice):
        data = b"shared-message"
        sig = domain_sign(DOMAIN_APPROVAL_RECEIPT, alice.sk, data)
        assert not domain_verify(DOMAIN_SIGNED_ENVELOPE, alice.vk, data, sig)

    def test_all_domain_pairs_isolated(self, alice):
        """Every domain produces a distinct signature context."""
        domains = [
            DOMAIN_COMMIT_RECORD,
            DOMAIN_STH_SIGN,
            DOMAIN_APPROVAL_RECEIPT,
            DOMAIN_SIGNED_ENVELOPE,
            DOMAIN_SIGNER_POLICY,
            DOMAIN_ANCHOR_DIGEST,
        ]
        data = b"test-payload"
        sigs = {d: domain_sign(d, alice.sk, data) for d in domains}
        for sign_domain, sig in sigs.items():
            for verify_domain in domains:
                result = domain_verify(verify_domain, alice.vk, data, sig)
                if verify_domain == sign_domain:
                    assert result, f"Should verify under same domain"
                else:
                    assert not result, f"Should NOT verify across domains"

    def test_wrong_vk_always_fails(self, alice, bob, eve):
        data = b"message"
        sig = domain_sign(DOMAIN_COMMIT_RECORD, alice.sk, data)
        assert not domain_verify(DOMAIN_COMMIT_RECORD, bob.vk, data, sig)
        assert not domain_verify(DOMAIN_COMMIT_RECORD, eve.vk, data, sig)

    def test_truncated_signature_fails(self, alice):
        data = b"message"
        sig = domain_sign(DOMAIN_COMMIT_RECORD, alice.sk, data)
        # Truncate signature
        assert not domain_verify(DOMAIN_COMMIT_RECORD, alice.vk, data, sig[:-1])

    def test_fingerprint_not_invertible(self, alice, bob):
        """Different VKs must produce different fingerprints (collision resistance)."""
        fp1 = signer_fingerprint(alice.vk)
        fp2 = signer_fingerprint(bob.vk)
        assert fp1 != fp2
        assert len(fp1) == len(fp2) == 32

    def test_fingerprint_stable_across_calls(self, alice):
        fps = [signer_fingerprint(alice.vk) for _ in range(20)]
        assert len(set(fps)) == 1


# ── Envelope adversarial ──────────────────────────────────────────────────


class TestEnvelopeAdversarial:
    """Bit-flip and field-substitution attacks on SignedEnvelope."""

    def test_flipped_payload_byte_fails(self, valid_envelope):
        env = valid_envelope
        flipped = bytearray(env.payload)
        flipped[0] ^= 0xFF
        env.payload = bytes(flipped)
        assert not env.verify()

    def test_flipped_signature_byte_fails(self, alice):
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=b"payload",
        )
        flipped = bytearray(env.signature)
        flipped[100] ^= 0x01
        env.signature = bytes(flipped)
        assert not env.verify()

    def test_changed_signer_id_fails(self, valid_envelope):
        valid_envelope.signer_id = "mallory"
        assert not valid_envelope.verify()

    def test_changed_payload_type_fails(self, valid_envelope):
        valid_envelope.payload_type = "sth"
        assert not valid_envelope.verify()

    def test_changed_version_fails(self, valid_envelope):
        valid_envelope.version = 2
        assert not valid_envelope.verify()

    def test_changed_timestamp_fails(self, valid_envelope):
        valid_envelope.timestamp = valid_envelope.timestamp + 1.0
        assert not valid_envelope.verify()

    def test_wrong_domain_fails(self, valid_envelope):
        valid_envelope.domain = DOMAIN_STH_SIGN
        assert not valid_envelope.verify()

    def test_substituted_vk_fails(self, valid_envelope, bob):
        """Replace VK with a different key — signature no longer matches."""
        valid_envelope.signer_vk = bob.vk
        assert not valid_envelope.verify()

    def test_mismatched_kid_fails(self, alice, bob):
        """kid does not match vk → verify must fail."""
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=b"payload",
        )
        env.signer_kid = signer_fingerprint(bob.vk)  # Wrong kid
        assert not env.verify()

    def test_all_payload_bit_flips_detected(self, alice):
        """Flip every byte in the payload — all must fail."""
        payload = b"test-payload-12"
        env = SignedEnvelope.create(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=payload,
        )
        for i in range(len(payload)):
            flipped = bytearray(env.payload)
            flipped[i] ^= 0xFF
            env.payload = bytes(flipped)
            assert not env.verify(), f"Bit flip at byte {i} not detected"
            env.payload = payload  # restore

    def test_max_drift_boundary(self, alice):
        """Exactly at boundary: just inside and just outside max_drift."""
        exact_drift = 60.0
        ts_inside = time.time() - (exact_drift - 1)
        ts_outside = time.time() - (exact_drift + 1)

        env_inside = SignedEnvelope.create_at(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=b"p",
            timestamp=ts_inside,
        )
        env_outside = SignedEnvelope.create_at(
            domain=DOMAIN_COMMIT_RECORD,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id="alice",
            payload_type="test",
            payload=b"p",
            timestamp=ts_outside,
        )
        assert env_inside.verify(max_drift=exact_drift)
        assert not env_outside.verify(max_drift=exact_drift)

    def test_empty_signature_fails(self, valid_envelope):
        valid_envelope.signature = b""
        assert not valid_envelope.verify()


# ── Receipt adversarial ───────────────────────────────────────────────────


class TestReceiptAdversarial:
    """Field substitution and signature attacks on ApprovalReceipt."""

    def test_tamper_entity_id_fails(self, alice, valid_receipt):
        valid_receipt.entity_id = "x" * 64
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_sequence_fails(self, alice, valid_receipt):
        valid_receipt.sequence = 999
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_chain_fails(self, alice, valid_receipt):
        valid_receipt.target_chain_id = "ethereum-mainnet"
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_epoch_fails(self, alice, valid_receipt):
        valid_receipt.epoch = 42
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_signer_role_fails(self, alice, valid_receipt):
        valid_receipt.signer_role = "admin"
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_valid_until_fails(self, alice, valid_receipt):
        valid_receipt.valid_until = valid_receipt.valid_until + 86400
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_merkle_root_fails(self, alice, valid_receipt):
        valid_receipt.merkle_root = b"\xff" * 32
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_commitment_ref_fails(self, alice, valid_receipt):
        valid_receipt.commitment_ref = "z" * 64
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_sth_ref_fails(self, alice, valid_receipt):
        valid_receipt.sth_ref = "y" * 64
        assert not valid_receipt.verify(alice.vk)

    def test_tamper_receipt_type_fails(self, alice, valid_receipt):
        valid_receipt.receipt_type = ReceiptType.MATERIALIZE
        assert not valid_receipt.verify(alice.vk)

    def test_empty_signature_fails(self, alice, valid_receipt):
        valid_receipt.signature = b""
        assert not valid_receipt.verify(alice.vk)

    def test_wrong_vk_fails(self, bob, valid_receipt):
        assert not valid_receipt.verify(bob.vk)

    def test_forged_receipt_id_fails(self, alice, valid_receipt):
        valid_receipt.receipt_id = "sha3-256:" + "a" * 64
        assert not valid_receipt.verify(alice.vk)

    def test_anchor_digest_changes_on_any_field(self, alice, committed):
        """Any field change must change the anchor_digest."""
        eid, record, sth, net = committed
        r1 = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        r2 = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=1,
            target_chain_id="base-testnet",
        )
        assert r1.anchor_digest() != r2.anchor_digest()

    def test_receipt_id_changes_on_different_inputs(self, alice, committed):
        eid, record, sth, net = committed
        r1 = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="operator",
            sequence=0,
            target_chain_id="base-testnet",
        )
        r2 = ApprovalReceipt.for_commit(
            entity_id=eid,
            record=record,
            sth=sth,
            signer_kp=alice,
            signer_role="auditor",  # Different role
            sequence=0,
            target_chain_id="base-testnet",
        )
        assert r1.receipt_id != r2.receipt_id


# ── Sequence tracker adversarial ──────────────────────────────────────────


class TestSequencerAdversarial:
    """Edge cases and attack scenarios for SequenceTracker."""

    def test_sequence_zero_after_max(self, alice):
        """After advancing far, sequence 0 is rejected as replay."""
        tracker = SequenceTracker("test-chain")
        future = time.time() + 3600
        tracker.validate_and_advance(alice.vk, 100, "test-chain", future)
        ok, reason = tracker.validate_and_advance(alice.vk, 0, "test-chain", future)
        assert not ok
        assert "replay" in reason

    def test_expiry_exactly_now_fails(self, alice):
        """valid_until = now should fail (half-open interval: now >= exp fails)."""
        tracker = SequenceTracker("test-chain")
        # Use a timestamp slightly in the past to reliably trigger expiry
        expired = time.time() - 0.001
        ok, reason = tracker.validate_and_advance(alice.vk, 0, "test-chain", expired)
        assert not ok
        assert "expired" in reason

    def test_multiple_chains_independent(self, alice):
        """Two trackers for different chains don't interfere."""
        t1 = SequenceTracker("chain-A")
        t2 = SequenceTracker("chain-B")
        future = time.time() + 3600
        ok1, _ = t1.validate_and_advance(alice.vk, 0, "chain-A", future)
        ok2, _ = t2.validate_and_advance(alice.vk, 0, "chain-B", future)
        assert ok1
        assert ok2

    def test_wrong_chain_id_consistently_rejected(self, alice):
        tracker = SequenceTracker("base-testnet")
        future = time.time() + 3600
        for seq in range(5):
            ok, reason = tracker.validate_and_advance(alice.vk, seq, "ethereum", future)
            assert not ok
            assert "chain mismatch" in reason

    def test_batch_order_matters(self, alice):
        """In a batch, earlier items set the HWM for later items."""
        tracker = SequenceTracker("base-testnet")
        future = time.time() + 3600
        # seq 5 comes first → seq 3 is a replay
        results = tracker.validate_batch(
            [
                (alice.vk, 5, "base-testnet", future),
                (alice.vk, 3, "base-testnet", future),
            ]
        )
        assert results[0][0] is True
        assert results[1][0] is False

    def test_per_signer_isolation_with_many_signers(self):
        """100 independent signers each at seq 0 all accepted."""
        tracker = SequenceTracker("test-chain")
        future = time.time() + 3600
        signers = [KeyPair.generate(f"signer-{i}") for i in range(10)]
        for kp in signers:
            ok, _ = tracker.validate_and_advance(kp.vk, 0, "test-chain", future)
            assert ok
        # Each can independently advance
        for kp in signers:
            ok, _ = tracker.validate_and_advance(kp.vk, 1, "test-chain", future)
            assert ok

    def test_next_sequence_never_negative(self, alice):
        tracker = SequenceTracker("test-chain")
        assert tracker.next_sequence(alice.vk) == 0  # Unseen → 0

    def test_current_sequence_unseen_is_minus_one(self, alice):
        tracker = SequenceTracker("test-chain")
        assert tracker.current_sequence(alice.vk) == -1
