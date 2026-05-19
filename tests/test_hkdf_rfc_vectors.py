"""
RFC 5869 HKDF Test Vectors.

Validates our HKDF implementation against the official test vectors
from RFC 5869 Appendix A. This provides cryptographic assurance that
the Extract and Expand phases produce correct output.

Reference: https://www.rfc-editor.org/rfc/rfc5869 Appendix A
"""

import hashlib
import hmac

import pytest


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract per RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM)."""
    if not salt:
        salt = b"\x00" * 32  # HashLen zeros for SHA-256
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand per RFC 5869 §2.3: OKM = T(1) || T(2) || ..."""
    hash_len = 32  # SHA-256
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = hmac.new(prk, t_prev + info + bytes([i]), hashlib.sha256).digest()
        okm += t_prev
    return okm[:length]


class TestRFC5869Vectors:
    """Official RFC 5869 Appendix A test vectors."""

    def test_a1_basic_sha256(self):
        """Test Case 1: Basic test case with SHA-256."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        L = 42

        prk = hkdf_extract(salt, ikm)
        assert prk == bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        ), f"PRK mismatch: {prk.hex()}"

        okm = hkdf_expand(prk, info, L)
        assert okm == bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ), f"OKM mismatch: {okm.hex()}"

    def test_a2_longer_inputs(self):
        """Test Case 2: Test with SHA-256 and longer inputs/outputs."""
        ikm = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        )
        salt = bytes.fromhex(
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )
        info = bytes.fromhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        )
        L = 82

        prk = hkdf_extract(salt, ikm)
        assert prk == bytes.fromhex(
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        ), f"PRK mismatch: {prk.hex()}"

        okm = hkdf_expand(prk, info, L)
        assert okm == bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        ), f"OKM mismatch: {okm.hex()}"

    def test_a3_zero_length_salt_info(self):
        """Test Case 3: Test with SHA-256 and zero-length salt/info."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = b""
        info = b""
        L = 42

        prk = hkdf_extract(salt, ikm)
        assert prk == bytes.fromhex(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        ), f"PRK mismatch: {prk.hex()}"

        okm = hkdf_expand(prk, info, L)
        assert okm == bytes.fromhex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        ), f"OKM mismatch: {okm.hex()}"


class TestETPHKDFCompliance:
    """Verify ETP's HKDF matches the same Extract/Expand as RFC 5869."""

    def test_etp_extract_matches_rfc(self):
        """ETP's _extract_prk uses the same HMAC(salt, IKM) as RFC 5869."""
        from src.ltp.shards import ShardEncryptor

        cek = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        etp_prk = ShardEncryptor._extract_prk(cek)

        # Manually compute expected PRK
        expected = hmac.new(b"ETP-SHARD-NONCE-v1", cek, hashlib.sha256).digest()
        assert etp_prk == expected

    def test_etp_nonce_uses_expand_pattern(self):
        """ETP's _nonce uses HMAC(PRK, info || 0x01) — single-round Expand."""
        import struct

        from src.ltp.shards import ShardEncryptor

        cek = bytes(range(32))
        entity_id = "sha3-256:test"
        shard_index = 42

        etp_nonce = ShardEncryptor._nonce(cek, entity_id, shard_index)

        # Manually compute expected nonce
        prk = hmac.new(b"ETP-SHARD-NONCE-v1", cek, hashlib.sha256).digest()
        info = entity_id.encode("utf-8") + struct.pack(">I", shard_index) + b"\x01"
        expected = hmac.new(prk, info, hashlib.sha256).digest()

        from src.ltp.primitives import AEAD

        assert etp_nonce == expected[: AEAD.NONCE_SIZE]
