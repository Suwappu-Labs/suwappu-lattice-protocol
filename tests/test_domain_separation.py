"""Tests for Domain Separation Registry (domain.py)."""

import pytest

from src.ltp.domain import (
    DOMAIN_ENTITY_ID, DOMAIN_COMMIT_SIGN, DOMAIN_COMMIT_RECORD,
    DOMAIN_STH_SIGN, DOMAIN_SHARD_NONCE, DOMAIN_APPROVAL_RECEIPT,
    DOMAIN_ANCHOR_DIGEST, DOMAIN_SIGNED_ENVELOPE, DOMAIN_SIGNER_POLICY,
    DOMAIN_LATTICE_KEY, DOMAIN_BRIDGE_MSG,
    _ALL_TAGS,
    domain_hash, domain_hash_bytes,
    domain_sign, domain_verify,
    signer_fingerprint,
)
from src.ltp import KeyPair, reset_poc_state


@pytest.fixture(autouse=True)
def fresh_state():
    reset_poc_state()
    yield
    reset_poc_state()


class TestTagRegistry:
    """Verify tag uniqueness and format."""

    def test_no_tag_collisions(self):
        values = list(_ALL_TAGS.values())
        assert len(values) == len(set(values)), "Duplicate tag bytes detected"

    def test_no_name_collisions(self):
        names = list(_ALL_TAGS.keys())
        assert len(names) == len(set(names)), "Duplicate tag names detected"

    def test_all_tags_have_null_terminator(self):
        for name, tag in _ALL_TAGS.items():
            assert tag.endswith(b'\x00'), f"{name} missing null terminator"

    def test_new_tags_follow_gsx_format(self):
        new_tags = {k: v for k, v in _ALL_TAGS.items() if k.startswith("DOMAIN_")}
        for name, tag in new_tags.items():
            assert tag.startswith(b"GSX-LTP:"), f"{name} doesn't start with GSX-LTP:"
            # Should contain version marker
            assert b":v" in tag, f"{name} missing version marker"

    def test_tag_count(self):
        assert len(_ALL_TAGS) == 31


class TestDomainHash:
    """Test domain-separated hashing."""

    def test_domain_hash_returns_string(self):
        result = domain_hash(DOMAIN_ENTITY_ID, b"test-data")
        assert isinstance(result, str)
        assert ":" in result  # algo:hex format

    def test_domain_hash_bytes_returns_bytes(self):
        result = domain_hash_bytes(DOMAIN_ENTITY_ID, b"test-data")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_domain_isolation(self):
        """Same data under different domains produces different hashes."""
        data = b"same-data"
        h1 = domain_hash_bytes(DOMAIN_ENTITY_ID, data)
        h2 = domain_hash_bytes(DOMAIN_COMMIT_SIGN, data)
        h3 = domain_hash_bytes(DOMAIN_STH_SIGN, data)
        assert h1 != h2
        assert h1 != h3
        assert h2 != h3

    def test_domain_hash_deterministic(self):
        for _ in range(5):
            assert domain_hash_bytes(DOMAIN_ENTITY_ID, b"x") == \
                   domain_hash_bytes(DOMAIN_ENTITY_ID, b"x")

    def test_different_data_different_hash(self):
        h1 = domain_hash_bytes(DOMAIN_ENTITY_ID, b"data1")
        h2 = domain_hash_bytes(DOMAIN_ENTITY_ID, b"data2")
        assert h1 != h2


class TestDomainSignVerify:
    """Test domain-separated signing and verification."""

    def test_sign_verify_roundtrip(self):
        kp = KeyPair.generate("test-signer")
        data = b"message to sign"
        sig = domain_sign(DOMAIN_COMMIT_SIGN, kp.sk, data)
        assert domain_verify(DOMAIN_COMMIT_SIGN, kp.vk, data, sig)

    def test_wrong_domain_rejects(self):
        """Signature under domain A fails verification under domain B."""
        kp = KeyPair.generate("test-signer")
        data = b"message"
        sig = domain_sign(DOMAIN_COMMIT_SIGN, kp.sk, data)
        # Verify under different domain should fail
        assert not domain_verify(DOMAIN_STH_SIGN, kp.vk, data, sig)

    def test_wrong_signer_rejects(self):
        kp1 = KeyPair.generate("signer-1")
        kp2 = KeyPair.generate("signer-2")
        data = b"message"
        sig = domain_sign(DOMAIN_COMMIT_SIGN, kp1.sk, data)
        assert not domain_verify(DOMAIN_COMMIT_SIGN, kp2.vk, data, sig)

    def test_tampered_data_rejects(self):
        kp = KeyPair.generate("test-signer")
        data = b"original message"
        sig = domain_sign(DOMAIN_COMMIT_SIGN, kp.sk, data)
        assert not domain_verify(DOMAIN_COMMIT_SIGN, kp.vk, b"tampered", sig)


class TestGatewayVMDomainTags:
    """Verify gateway VM domain tags exist and follow conventions."""

    def test_gateway_attest_domain_tag_exists(self):
        from src.ltp.domain import DOMAIN_GATEWAY_ATTEST
        assert DOMAIN_GATEWAY_ATTEST == b"GSX-LTP:gateway-attest:v1\x00"

    def test_external_event_domain_tag_exists(self):
        from src.ltp.domain import DOMAIN_EXTERNAL_EVENT
        assert DOMAIN_EXTERNAL_EVENT == b"GSX-LTP:external-event:v1\x00"


class TestSignerFingerprint:
    """Test signer fingerprint computation."""

    def test_fingerprint_is_32_bytes(self):
        kp = KeyPair.generate("test")
        fp = signer_fingerprint(kp.vk)
        assert isinstance(fp, bytes)
        assert len(fp) == 32

    def test_fingerprint_stability(self):
        kp = KeyPair.generate("test")
        fp1 = signer_fingerprint(kp.vk)
        fp2 = signer_fingerprint(kp.vk)
        assert fp1 == fp2

    def test_different_vk_different_fingerprint(self):
        kp1 = KeyPair.generate("signer-1")
        kp2 = KeyPair.generate("signer-2")
        fp1 = signer_fingerprint(kp1.vk)
        fp2 = signer_fingerprint(kp2.vk)
        assert fp1 != fp2

    def test_fingerprint_uses_sha3_not_sha256(self):
        """Verify fingerprint uses canonical_hash_bytes (SHA3-256)."""
        from src.ltp.primitives import canonical_hash_bytes
        kp = KeyPair.generate("test")
        expected = canonical_hash_bytes(kp.vk)
        assert signer_fingerprint(kp.vk) == expected
