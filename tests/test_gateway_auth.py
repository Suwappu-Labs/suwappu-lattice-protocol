"""
Tests for ML-DSA-65 JWT authentication.
"""

from __future__ import annotations

import json
import time

import pytest

from src.ltp.domain import DOMAIN_JWT_TOKEN, domain_sign, signer_fingerprint
from src.ltp.gateway.auth import JWTClaims, _b64url_decode, _b64url_encode, create_jwt, verify_jwt
from src.ltp.keypair import KeyPair

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alice():
    return KeyPair.generate("alice")


@pytest.fixture
def bob():
    return KeyPair.generate("bob")


@pytest.fixture
def alice_vks(alice):
    kid = signer_fingerprint(alice.vk).hex()
    return {kid: alice.vk}


# ---------------------------------------------------------------------------
# Token Creation
# ---------------------------------------------------------------------------


class TestCreateJWT:
    def test_returns_three_part_token(self, alice):
        token = create_jwt(alice, "alice-node")
        parts = token.split(".")
        assert len(parts) == 3

    def test_header_contains_mldsa65(self, alice):
        token = create_jwt(alice, "alice-node")
        header_b64 = token.split(".")[0]
        header = json.loads(_b64url_decode(header_b64))
        assert header["alg"] == "ML-DSA-65"
        assert header["typ"] == "JWT"

    def test_claims_contain_required_fields(self, alice):
        token = create_jwt(alice, "alice-node", ttl_seconds=600)
        claims_b64 = token.split(".")[1]
        claims = json.loads(_b64url_decode(claims_b64))
        assert claims["sub"] == "alice-node"
        assert claims["iss"] == signer_fingerprint(alice.vk).hex()
        assert isinstance(claims["exp"], float)
        assert isinstance(claims["iat"], float)
        assert claims["exp"] > claims["iat"]

    def test_different_keypairs_different_signatures(self, alice, bob):
        t1 = create_jwt(alice, "alice-node")
        t2 = create_jwt(bob, "bob-node")
        sig1 = t1.split(".")[2]
        sig2 = t2.split(".")[2]
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# Token Verification
# ---------------------------------------------------------------------------


class TestVerifyJWT:
    def test_valid_token_verifies(self, alice, alice_vks):
        token = create_jwt(alice, "alice-node")
        claims = verify_jwt(token, known_vks=alice_vks)
        assert claims is not None
        assert claims.sub == "alice-node"
        assert claims.iss == signer_fingerprint(alice.vk).hex()

    def test_expired_token_rejected(self, alice, alice_vks):
        token = create_jwt(alice, "alice-node", ttl_seconds=-10)
        claims = verify_jwt(token, known_vks=alice_vks, max_clock_skew=0.0)
        assert claims is None

    def test_wrong_key_rejected(self, alice, bob):
        """Token signed by alice, verified against bob's VK."""
        token = create_jwt(alice, "alice-node")
        bob_vks = {signer_fingerprint(bob.vk).hex(): bob.vk}
        claims = verify_jwt(token, known_vks=bob_vks)
        assert claims is None

    def test_tampered_claims_rejected(self, alice, alice_vks):
        token = create_jwt(alice, "alice-node")
        parts = token.split(".")
        # Tamper with claims
        claims_bytes = _b64url_decode(parts[1])
        claims = json.loads(claims_bytes)
        claims["sub"] = "evil-node"
        parts[1] = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        tampered = ".".join(parts)
        result = verify_jwt(tampered, known_vks=alice_vks)
        assert result is None

    def test_tampered_signature_rejected(self, alice, alice_vks):
        token = create_jwt(alice, "alice-node")
        parts = token.split(".")
        # Flip a byte in the signature
        sig_bytes = bytearray(_b64url_decode(parts[2]))
        sig_bytes[0] ^= 0xFF
        parts[2] = _b64url_encode(bytes(sig_bytes))
        tampered = ".".join(parts)
        result = verify_jwt(tampered, known_vks=alice_vks)
        assert result is None

    def test_unknown_issuer_rejected(self, alice):
        token = create_jwt(alice, "alice-node")
        result = verify_jwt(token, known_vks={})
        assert result is None

    def test_invalid_format_rejected(self):
        assert verify_jwt("not.a.jwt.at.all") is None
        assert verify_jwt("onlytwoparts.here") is None
        assert verify_jwt("") is None

    def test_wrong_algorithm_rejected(self, alice, alice_vks):
        """Token with wrong alg header should fail."""
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {"sub": "alice-node", "iss": "fake", "exp": time.time() + 3600, "iat": time.time()}
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        claims_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        sig_b64 = _b64url_encode(b"\x00" * 64)
        token = f"{header_b64}.{claims_b64}.{sig_b64}"
        assert verify_jwt(token, known_vks=alice_vks) is None

    def test_clock_skew_tolerance(self, alice, alice_vks):
        """Token expired 10s ago but within 30s skew should pass."""
        token = create_jwt(alice, "alice-node", ttl_seconds=-10)
        claims = verify_jwt(token, known_vks=alice_vks, max_clock_skew=30.0)
        assert claims is not None


# ---------------------------------------------------------------------------
# Domain Separation
# ---------------------------------------------------------------------------


class TestDomainSeparation:
    def test_jwt_token_domain_tag_unique(self):
        from src.ltp.domain import _ALL_TAGS

        assert "DOMAIN_JWT_TOKEN" in _ALL_TAGS
        assert _ALL_TAGS["DOMAIN_JWT_TOKEN"] == b"SUWAPPU-LTP:jwt-token:v1\x00"

    def test_peer_gossip_domain_tag_unique(self):
        from src.ltp.domain import _ALL_TAGS

        assert "DOMAIN_PEER_GOSSIP" in _ALL_TAGS
        assert _ALL_TAGS["DOMAIN_PEER_GOSSIP"] == b"SUWAPPU-LTP:peer-gossip:v1\x00"


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------


class TestBase64Helpers:
    def test_roundtrip(self):
        data = b"hello world"
        encoded = _b64url_encode(data)
        decoded = _b64url_decode(encoded)
        assert decoded == data

    def test_padding_stripped(self):
        encoded = _b64url_encode(b"a")
        assert "=" not in encoded

    def test_binary_data_roundtrip(self):
        data = bytes(range(256))
        encoded = _b64url_encode(data)
        decoded = _b64url_decode(encoded)
        assert decoded == data
