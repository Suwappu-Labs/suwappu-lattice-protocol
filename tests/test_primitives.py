"""
Unit tests for cryptographic primitives (canonical_hash, AEAD, MLKEM, MLDSA).
"""

import os

import pytest

from src.ltp.primitives import AEAD, MLDSA, MLKEM, canonical_hash, canonical_hash_bytes

# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------


class TestHashFunctions:
    def test_canonical_hash_returns_prefixed_string(self):
        result = canonical_hash(b"hello")
        assert result.startswith("sha3-256:")

    def test_canonical_hash_hex_length(self):
        result = canonical_hash(b"hello")
        prefix, hex_part = result.split(":", 1)
        assert len(hex_part) == 64  # 32 bytes × 2 hex chars

    def test_canonical_hash_deterministic(self):
        assert canonical_hash(b"data") == canonical_hash(b"data")

    def test_canonical_hash_different_inputs_differ(self):
        assert canonical_hash(b"a") != canonical_hash(b"b")

    def test_canonical_hash_bytes_returns_32_bytes(self):
        result = canonical_hash_bytes(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_canonical_hash_bytes_deterministic(self):
        assert canonical_hash_bytes(b"data") == canonical_hash_bytes(b"data")

    def test_canonical_hash_bytes_matches_hex(self):
        data = b"consistency check"
        hex_part = canonical_hash(data).split(":", 1)[1]
        assert canonical_hash_bytes(data).hex() == hex_part


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------


class TestAEAD:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        plaintext = b"secret payload"
        ciphertext = AEAD.encrypt(key, plaintext, nonce)
        assert AEAD.decrypt(key, ciphertext, nonce) == plaintext

    def test_ciphertext_larger_than_plaintext(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        plaintext = b"hello"
        ct = AEAD.encrypt(key, plaintext, nonce)
        assert len(ct) == len(plaintext) + AEAD._tag_size()

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"authentic data", nonce)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(ValueError, match="FAILED"):
            AEAD.decrypt(key, bytes(tampered), nonce)

    def test_wrong_key_raises(self):
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"data", nonce)
        with pytest.raises(ValueError):
            AEAD.decrypt(wrong_key, ct, nonce)

    def test_wrong_nonce_raises(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"data", nonce)
        with pytest.raises(ValueError):
            AEAD.decrypt(key, ct, os.urandom(AEAD.NONCE_SIZE))

    def test_empty_ciphertext_raises(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        with pytest.raises(ValueError):
            AEAD.decrypt(key, b"short", nonce)

    def test_encrypt_empty_plaintext(self):
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct = AEAD.encrypt(key, b"", nonce)
        assert AEAD.decrypt(key, ct, nonce) == b""

    def test_different_nonces_produce_different_ciphertexts(self):
        key = os.urandom(32)
        plaintext = b"same plaintext"
        ct1 = AEAD.encrypt(key, plaintext, os.urandom(AEAD.NONCE_SIZE))
        ct2 = AEAD.encrypt(key, plaintext, os.urandom(AEAD.NONCE_SIZE))
        assert ct1 != ct2


# ---------------------------------------------------------------------------
# MLKEM
# ---------------------------------------------------------------------------


class TestMLKEM:
    def test_keygen_sizes(self):
        ek, dk = MLKEM.keygen()
        assert len(ek) == MLKEM.EK_SIZE
        assert len(dk) == MLKEM.DK_SIZE

    def test_encaps_sizes(self):
        ek, _ = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        assert len(ss) == MLKEM.SS_SIZE
        assert len(ct) == MLKEM.CT_SIZE

    def test_encaps_fresh_each_call(self):
        ek, _ = MLKEM.keygen()
        ss1, ct1 = MLKEM.encaps(ek)
        ss2, ct2 = MLKEM.encaps(ek)
        assert ss1 != ss2
        assert ct1 != ct2

    def test_decaps_recovers_shared_secret(self):
        ek, dk = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        recovered = MLKEM.decaps(dk, ct)
        assert recovered == ss

    def test_decaps_wrong_dk_fails(self):
        ek1, dk1 = MLKEM.keygen()
        ek2, dk2 = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek1)
        # Real ML-KEM uses implicit rejection (returns different ss, no exception).
        # PoC backend raises ValueError. Either way, correct ss must not be recovered.
        try:
            recovered = MLKEM.decaps(dk2, ct)
            assert recovered != ss, "Wrong dk must not recover correct shared secret"
        except ValueError:
            pass  # PoC backend raises

    def test_encaps_wrong_ek_size_raises(self):
        with pytest.raises(ValueError, match="Invalid ek size"):
            MLKEM.encaps(b"too short")


# ---------------------------------------------------------------------------
# MLDSA
# ---------------------------------------------------------------------------


class TestMLDSA:
    def test_keygen_sizes(self):
        vk, sk = MLDSA.keygen()
        assert len(vk) == MLDSA.VK_SIZE
        assert len(sk) == MLDSA.SK_SIZE

    def test_sign_size(self):
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"message")
        assert len(sig) == MLDSA.SIG_SIZE

    def test_verify_valid_signature(self):
        vk, sk = MLDSA.keygen()
        msg = b"authentic message"
        sig = MLDSA.sign(sk, msg)
        assert MLDSA.verify(vk, msg, sig) is True

    def test_verify_wrong_message_fails(self):
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"original")
        assert MLDSA.verify(vk, b"modified", sig) is False

    def test_verify_wrong_vk_fails(self):
        vk1, sk1 = MLDSA.keygen()
        vk2, sk2 = MLDSA.keygen()
        sig = MLDSA.sign(sk1, b"message")
        assert MLDSA.verify(vk2, b"message", sig) is False

    def test_verify_wrong_signature_fails(self):
        vk, sk = MLDSA.keygen()
        msg = b"message"
        MLDSA.sign(sk, msg)
        bad_sig = os.urandom(MLDSA.SIG_SIZE)
        assert MLDSA.verify(vk, msg, bad_sig) is False

    def test_verify_wrong_sig_length_fails(self):
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"msg")
        assert MLDSA.verify(vk, b"msg", sig[:-1]) is False
