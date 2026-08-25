"""
Unit tests for SealedBoxV2 — the Theorem 9 revised sealed-key
construction (whitepaper §3.3.6). The rejection tests mirror the SKB
game's attack cases and the Verifpal model's mutation traces: wrong
receiver, wrong entity, replayed session, tampered delivery.
"""

import pytest

from src.ltp.keypair import KeyPair
from src.ltp.sealed_key_v2 import (
    ETA_SIZE,
    SealedBoxV2,
    receiver_fingerprint,
)

ENTITY_ID = bytes(range(32))
ENTITY_ID_2 = bytes(range(1, 33))
ETA = bytes(16)
ETA_2 = bytes([1]) * 16
PAYLOAD = b'{"cek":"00ff","entity_id":"...","commitment_ref":"..."}'


@pytest.fixture(scope="module")
def receiver():
    return KeyPair.generate("receiver")


@pytest.fixture(scope="module")
def other_receiver():
    return KeyPair.generate("other-receiver")


class TestRoundtrip:
    def test_seal_unseal(self, receiver):
        sealed = SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)
        assert SealedBoxV2.unseal(sealed, receiver, ENTITY_ID, ETA) == PAYLOAD

    def test_fresh_encapsulation_per_seal(self, receiver):
        a = SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)
        b = SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)
        assert a != b  # fresh KEM ct + nonce every call
        assert SealedBoxV2.unseal(a, receiver, ENTITY_ID, ETA) == PAYLOAD
        assert SealedBoxV2.unseal(b, receiver, ENTITY_ID, ETA) == PAYLOAD

    def test_constant_payload_independent_overhead(self, receiver):
        for size in (0, 32, 4096):
            sealed = SealedBoxV2.seal(bytes(size), receiver.ek, ENTITY_ID, ETA)
            assert len(sealed) == size + SealedBoxV2.OVERHEAD

    def test_generate_eta_size(self):
        assert len(SealedBoxV2.generate_eta()) == ETA_SIZE


class TestSKBGameRejections:
    """The Theorem 9 / SKB game attack cases, each of which MUST fail."""

    def _sealed(self, receiver):
        return SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)

    def test_wrong_receiver_rejected(self, receiver, other_receiver):
        # Misbinding: a sealed key addressed to receiver A must not
        # unseal at receiver B. ML-KEM implicit rejection yields a
        # garbage shared secret; the context check catches it.
        with pytest.raises(ValueError):
            SealedBoxV2.unseal(self._sealed(receiver), other_receiver, ENTITY_ID, ETA)

    def test_wrong_entity_rejected(self, receiver):
        # Entity substitution: the TIMM step-4 move — redirect the
        # receiver onto a different (even honestly committed) entity.
        with pytest.raises(ValueError, match="context verification FAILED"):
            SealedBoxV2.unseal(self._sealed(receiver), receiver, ENTITY_ID_2, ETA)

    def test_replayed_session_rejected(self, receiver):
        # Cross-session replay: the Verifpal `authentication?
        # sealed_key` finding against v1 — a sealed key from session
        # eta must not be accepted in session eta'.
        with pytest.raises(ValueError, match="context verification FAILED"):
            SealedBoxV2.unseal(self._sealed(receiver), receiver, ENTITY_ID, ETA_2)

    def test_same_context_still_unseals(self, receiver):
        # Sanity: the three rejections above are context-driven, not
        # noise — the genuine context still works.
        assert SealedBoxV2.unseal(self._sealed(receiver), receiver, ENTITY_ID, ETA) == PAYLOAD


class TestTamperDetection:
    @staticmethod
    def _flip(data: bytes, index: int) -> bytes:
        return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]

    def test_tampered_kem_ciphertext_rejected(self, receiver):
        sealed = SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)
        with pytest.raises(ValueError):
            SealedBoxV2.unseal(self._flip(sealed, 0), receiver, ENTITY_ID, ETA)

    def test_tampered_payload_ciphertext_rejected(self, receiver):
        sealed = SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)
        with pytest.raises(ValueError):
            SealedBoxV2.unseal(self._flip(sealed, len(sealed) - 60), receiver, ENTITY_ID, ETA)

    def test_tampered_commit_tag_rejected(self, receiver):
        sealed = SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, ETA)
        with pytest.raises(ValueError, match="context verification FAILED"):
            SealedBoxV2.unseal(self._flip(sealed, len(sealed) - 1), receiver, ENTITY_ID, ETA)

    def test_truncated_rejected(self, receiver):
        with pytest.raises(ValueError, match="too short"):
            SealedBoxV2.unseal(bytes(SealedBoxV2.OVERHEAD - 1), receiver, ENTITY_ID, ETA)


class TestContextComponents:
    def test_fingerprint_deterministic_and_key_sensitive(self, receiver, other_receiver):
        assert receiver_fingerprint(receiver.ek) == receiver_fingerprint(receiver.ek)
        assert receiver_fingerprint(receiver.ek) != receiver_fingerprint(other_receiver.ek)
        assert len(receiver_fingerprint(receiver.ek)) == 32

    def test_entity_id_size_enforced(self, receiver):
        with pytest.raises(ValueError, match="entity_id must be 32B"):
            SealedBoxV2.seal(PAYLOAD, receiver.ek, b"short", ETA)

    def test_eta_size_enforced(self, receiver):
        with pytest.raises(ValueError, match="eta must be 16B"):
            SealedBoxV2.seal(PAYLOAD, receiver.ek, ENTITY_ID, b"short")
