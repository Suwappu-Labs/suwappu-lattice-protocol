"""
Unit tests for the CTX committing-AEAD wrapper (whitepaper §3.3.3
committing-AEAD requirement; Chan–Rogaway CTX, black-box variant).
"""

import pytest

from src.ltp.committing_aead import (
    COMMIT_TAG_SIZE,
    CTX_DST,
    OVERHEAD,
    _commit_tag,
    _frame,
    commit_decrypt,
    commit_encrypt,
)
from src.ltp.primitives import AEAD

KEY = bytes(range(32))
KEY2 = bytes(range(1, 33))
NONCE = bytes(range(100, 124))
NONCE2 = bytes(range(101, 125))
AAD = b"context"


class TestRoundtrip:
    def test_roundtrip_with_aad(self):
        blob = commit_encrypt(KEY, b"attack at dawn", NONCE, AAD)
        assert commit_decrypt(KEY, blob, NONCE, AAD) == b"attack at dawn"

    def test_roundtrip_without_aad(self):
        blob = commit_encrypt(KEY, b"payload", NONCE)
        assert commit_decrypt(KEY, blob, NONCE) == b"payload"

    def test_roundtrip_empty_plaintext(self):
        blob = commit_encrypt(KEY, b"", NONCE, AAD)
        assert commit_decrypt(KEY, blob, NONCE, AAD) == b""

    def test_roundtrip_large_plaintext(self):
        pt = bytes(191) * 1024
        blob = commit_encrypt(KEY, pt, NONCE, AAD)
        assert commit_decrypt(KEY, blob, NONCE, AAD) == pt

    def test_overhead_is_constant(self):
        for size in (0, 1, 13, 4096):
            blob = commit_encrypt(KEY, bytes(size), NONCE, AAD)
            assert len(blob) == size + OVERHEAD
        assert OVERHEAD == AEAD.TAG_SIZE + COMMIT_TAG_SIZE

    def test_deterministic_given_nonce(self):
        assert commit_encrypt(KEY, b"m", NONCE, AAD) == commit_encrypt(KEY, b"m", NONCE, AAD)


class TestContextBinding:
    """The point of CTX: the blob is bound to its full decryption
    context. A wrong key, nonce, or AD must be rejected by the
    commitment check — before the non-committing Poly1305 tag votes."""

    def _blob(self):
        return commit_encrypt(KEY, b"attack at dawn", NONCE, AAD)

    def test_wrong_key_rejected_by_commitment(self):
        with pytest.raises(ValueError, match="context verification FAILED"):
            commit_decrypt(KEY2, self._blob(), NONCE, AAD)

    def test_wrong_nonce_rejected_by_commitment(self):
        with pytest.raises(ValueError, match="context verification FAILED"):
            commit_decrypt(KEY, self._blob(), NONCE2, AAD)

    def test_wrong_aad_rejected_by_commitment(self):
        with pytest.raises(ValueError, match="context verification FAILED"):
            commit_decrypt(KEY, self._blob(), NONCE, b"other context")

    def test_commit_tag_binds_each_input(self):
        base = _commit_tag(KEY, NONCE, AAD, bytes(16))
        assert _commit_tag(KEY2, NONCE, AAD, bytes(16)) != base
        assert _commit_tag(KEY, NONCE2, AAD, bytes(16)) != base
        assert _commit_tag(KEY, NONCE, b"x", bytes(16)) != base
        assert _commit_tag(KEY, NONCE, AAD, bytes([1]) + bytes(15)) != base


class TestTamperDetection:
    def _blob(self):
        return commit_encrypt(KEY, b"attack at dawn", NONCE, AAD)

    @staticmethod
    def _flip(blob: bytes, index: int) -> bytes:
        return blob[:index] + bytes([blob[index] ^ 0x01]) + blob[index + 1 :]

    def test_tampered_ciphertext_core_rejected(self):
        with pytest.raises(ValueError):
            commit_decrypt(KEY, self._flip(self._blob(), 0), NONCE, AAD)

    def test_tampered_legacy_tag_rejected_by_commitment(self):
        blob = self._blob()
        tampered = self._flip(blob, len(blob) - COMMIT_TAG_SIZE - 1)
        with pytest.raises(ValueError, match="context verification FAILED"):
            commit_decrypt(KEY, tampered, NONCE, AAD)

    def test_tampered_commit_tag_rejected(self):
        blob = self._blob()
        with pytest.raises(ValueError, match="context verification FAILED"):
            commit_decrypt(KEY, self._flip(blob, len(blob) - 1), NONCE, AAD)

    def test_truncated_blob_rejected(self):
        with pytest.raises(ValueError, match="too short"):
            commit_decrypt(KEY, bytes(OVERHEAD - 1), NONCE, AAD)

    def test_commit_tag_transplant_rejected(self):
        # A commitment tag lifted from a different context must not
        # validate another ciphertext — the misbinding move.
        blob_a = commit_encrypt(KEY, b"message a", NONCE, AAD)
        blob_b = commit_encrypt(KEY2, b"message b", NONCE, AAD)
        franken = blob_a[:-COMMIT_TAG_SIZE] + blob_b[-COMMIT_TAG_SIZE:]
        with pytest.raises(ValueError, match="context verification FAILED"):
            commit_decrypt(KEY, franken, NONCE, AAD)


class TestFraming:
    def test_length_prefix_is_injective_at_boundaries(self):
        # The classic concatenation ambiguity the framing exists to kill.
        assert _frame(b"AB", b"C") != _frame(b"A", b"BC")
        assert _frame(b"", b"AB") != _frame(b"AB", b"")

    def test_dst_is_byte_exact(self):
        # Audit LTP-A-022 discipline: the DST never changes shape.
        assert CTX_DST == b"LTP-CTX-v1"


class TestVector:
    def test_pinned_vector(self):
        # Interop pin: XChaCha20-Poly1305 + SHA3-256 CTX tag. If this
        # moves, the wire construction changed.
        blob = commit_encrypt(KEY, b"attack at dawn", NONCE, AAD)
        assert blob.hex() == (
            "1d078dd19c45a9e3f310f95ed1018439c1a564c9c8061e9e470e1134"
            "6459cf8c986720f3ea2b3d2d999bf61731496c4129145f5e2bbb9e39"
            "1d13c759580d"
        )
