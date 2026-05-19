"""
ML-DSA-65 Bearer JWT authentication for the ETP API Gateway.

Token format: base64url(header) . base64url(claims) . base64url(ml_dsa_sig)
Header:  {"alg": "ML-DSA-65", "typ": "JWT"}
Claims:  {"sub": node_id, "iss": signer_kid_hex, "exp": unix_ts, "iat": unix_ts}

The signature covers the domain-separated signing input:
    DOMAIN_JWT_TOKEN || header_b64 || "." || claims_b64

This ensures JWT signatures are bound to the ETP domain and cannot be
replayed against other signing contexts.
"""

from __future__ import annotations

import base64
import json
import time as _time
from dataclasses import dataclass
from typing import Optional

from ..domain import DOMAIN_JWT_TOKEN, domain_sign, domain_verify, signer_fingerprint

__all__ = ["JWTClaims", "create_jwt", "verify_jwt"]


@dataclass
class JWTClaims:
    """Decoded JWT claims."""

    sub: str  # node_id
    iss: str  # signer kid hex (32-byte fingerprint)
    exp: float  # expiry timestamp
    iat: float  # issued-at timestamp


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_jwt(
    keypair,
    node_id: str,
    ttl_seconds: int = 3600,
) -> str:
    """Create an ML-DSA-65 signed JWT token.

    Args:
        keypair: KeyPair with .sk (signing key) and .vk (verification key)
        node_id: Subject claim (identifies the caller)
        ttl_seconds: Token time-to-live in seconds

    Returns:
        JWT string: header_b64.claims_b64.signature_b64
    """
    now = _time.time()
    kid_hex = signer_fingerprint(keypair.vk).hex()

    header = {"alg": "ML-DSA-65", "typ": "JWT"}
    claims = {
        "sub": node_id,
        "iss": kid_hex,
        "exp": now + ttl_seconds,
        "iat": now,
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    signature = domain_sign(DOMAIN_JWT_TOKEN, keypair, signing_input)
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{claims_b64}.{sig_b64}"


def verify_jwt(
    token: str,
    key_registry=None,
    known_vks: Optional[dict[str, bytes]] = None,
    max_clock_skew: float = 30.0,
) -> Optional[JWTClaims]:
    """Verify a JWT token's signature and expiry.

    Args:
        token: JWT string (header.claims.signature)
        key_registry: Optional KeyRegistry for VK lookup by iterating keys
        known_vks: Optional dict mapping kid_hex -> vk bytes (direct lookup)
        max_clock_skew: Maximum allowed clock drift in seconds

    Returns:
        JWTClaims on success, None on any failure (invalid format, bad sig,
        expired, unknown issuer).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header_b64, claims_b64, sig_b64 = parts
        header_bytes = _b64url_decode(header_b64)
        claims_bytes = _b64url_decode(claims_b64)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception:
        return None

    # Validate header
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError:
        return None

    if header.get("alg") != "ML-DSA-65" or header.get("typ") != "JWT":
        return None

    # Parse claims
    try:
        claims = json.loads(claims_bytes)
    except json.JSONDecodeError:
        return None

    sub = claims.get("sub")
    iss = claims.get("iss")
    exp = claims.get("exp")
    iat = claims.get("iat")

    if not all(isinstance(v, str) for v in (sub, iss)):
        return None
    if not all(isinstance(v, (int, float)) for v in (exp, iat)):
        return None

    # Check expiry
    now = _time.time()
    if now > exp + max_clock_skew:
        return None

    # Look up VK by issuer kid
    vk = _resolve_vk(iss, key_registry, known_vks)
    if vk is None:
        return None

    # Verify domain-separated signature
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    if not domain_verify(DOMAIN_JWT_TOKEN, vk, signing_input, sig_bytes):
        return None

    return JWTClaims(sub=sub, iss=iss, exp=exp, iat=iat)


def _resolve_vk(
    kid_hex: str,
    key_registry=None,
    known_vks: Optional[dict[str, bytes]] = None,
) -> Optional[bytes]:
    """Resolve a verification key from kid hex."""
    # Direct lookup first
    if known_vks and kid_hex in known_vks:
        return known_vks[kid_hex]

    # KeyRegistry scan
    if key_registry is not None:
        for kp in getattr(key_registry, "_keys", {}).values():
            vk = kp.vk if hasattr(kp, "vk") else kp
            if signer_fingerprint(vk).hex() == kid_hex:
                return vk

    return None
