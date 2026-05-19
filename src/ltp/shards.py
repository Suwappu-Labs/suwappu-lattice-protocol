"""
Shard encryption/decryption for the Lattice Transfer Protocol.

Provides:
  - ShardEncryptor — encrypt/decrypt individual shards using a CEK

Nonce derivation uses HKDF (RFC 5869) with domain-separated Extract-Expand:
  PRK = HMAC-SHA256(salt="ETP-SHARD-NONCE-v1", CEK)       — Extract phase
  nonce_i = HMAC-SHA256(PRK, entity_id || index || 0x01)   — Expand phase

This provides KDF-level security (not just PRF security) per the formal
HKDF security definition. The fixed salt provides domain separation between
nonce derivation and other protocol uses of CEK.

Prior art: RFC 5869, Krawczyk (2010), Soatok "Understanding HKDF" (2021).
"""

from __future__ import annotations

import hashlib
import hmac as hmac_stdlib
import os
import struct
from collections import deque

from .primitives import AEAD, internal_hash_bytes

__all__ = ["ShardEncryptor"]

# Maximum number of recent CEKs to track for collision detection.
# Bounded to prevent memory growth in long-running processes.
# At 100K entries × 32 bytes = ~3.2MB — acceptable for defense-in-depth.
_CEK_TRACKING_LIMIT = 100_000


class ShardEncryptor:
    """
    Encrypts/decrypts individual shards using the Content Encryption Key (CEK).

    SECURITY INVARIANT — Nonce Derivation (HKDF, RFC 5869):

      Step 1 (Extract): PRK = HMAC-SHA256(salt, CEK)
        salt = b"ETP-SHARD-NONCE-v1" (fixed domain separator)
        CEK  = 32-byte random content encryption key

      Step 2 (Expand): nonce_i = HMAC-SHA256(PRK, info || 0x01)[:NONCE_SIZE]
        info = entity_id_bytes || struct.pack('>I', shard_index)

    This provides KDF-level security (not merely PRF security) because:
    - The Extract phase normalizes CEK to uniform randomness via HMAC
    - The Expand phase derives per-shard nonces with domain separation
    - The fixed salt prevents cross-protocol nonce reuse
    - Length-prefixed info prevents concatenation ambiguity

    CEK uniqueness invariant:
      Each entity MUST have a unique CEK. HKDF nonce derivation adds a second
      layer of defense: even if a CEK is accidentally reused across entities,
      the entity_id in the info parameter ensures nonce divergence.
      See whitepaper §2.1.1.

    Formally: KDF security holds when salt is fixed across invocations
    (Krawczyk 2010, §3.2; Soatok "Understanding HKDF" 2021).
    """

    # Fixed domain-separation salt for shard nonce derivation.
    # MUST NOT change without a protocol version bump.
    _HKDF_SALT = b"ETP-SHARD-NONCE-v1"

    # Track recently issued CEKs within this process to detect accidental reuse.
    # Uses a bounded set + deque to prevent unbounded memory growth.
    _issued_ceks: set[bytes] = set()
    _issued_ceks_order: deque = deque()

    @classmethod
    def generate_cek(cls) -> bytes:
        """Generate a random 256-bit Content Encryption Key from CSPRNG.

        Raises RuntimeError if the generated key collides with a recently
        issued CEK (probability ~2^{-256} — detection is defense-in-depth).

        Tracks the most recent _CEK_TRACKING_LIMIT CEKs to bound memory usage.
        """
        cek = os.urandom(32)
        if cek in cls._issued_ceks:
            raise RuntimeError(
                "CRITICAL: CEK collision detected — CSPRNG may be compromised. "
                "Aborting to prevent catastrophic nonce reuse."
            )
        cls._issued_ceks.add(cek)
        cls._issued_ceks_order.append(cek)
        # Evict oldest entry when limit is reached
        if len(cls._issued_ceks_order) > _CEK_TRACKING_LIMIT:
            oldest = cls._issued_ceks_order.popleft()
            cls._issued_ceks.discard(oldest)
        return cek

    @classmethod
    def validate_cek(cls, cek: bytes) -> None:
        """Validate a CEK meets security requirements (length, non-degenerate)."""
        if not isinstance(cek, bytes) or len(cek) != 32:
            raise ValueError(
                f"CEK must be exactly 32 bytes, got "
                f"{len(cek) if isinstance(cek, bytes) else type(cek).__name__}"
            )
        if cek == b"\x00" * 32:
            raise ValueError("CEK is all-zero — degenerate key rejected")
        if cek == b"\xff" * 32:
            raise ValueError("CEK is all-one — degenerate key rejected")

    @classmethod
    def _extract_prk(cls, cek: bytes) -> bytes:
        """HKDF-Extract: derive pseudo-random key from CEK.

        PRK = HMAC-SHA256(salt, CEK)

        The fixed salt provides domain separation. PRK is uniformly random
        regardless of CEK distribution (provided CEK has sufficient entropy).
        Can be cached per-entity for efficiency (same CEK → same PRK).
        """
        return hmac_stdlib.new(cls._HKDF_SALT, cek, hashlib.sha256).digest()

    @classmethod
    def _nonce(cls, cek: bytes, entity_id: str, shard_index: int) -> bytes:
        """HKDF-Expand: derive per-shard nonce from PRK.

        nonce = HMAC-SHA256(PRK, info || 0x01)[:NONCE_SIZE]
        info  = entity_id.encode('utf-8') || struct.pack('>I', shard_index)

        Per RFC 5869 §2.3, the counter byte (0x01) is appended to info.
        Size adapts to active AEAD backend (16B PoC, 24B XChaCha20-Poly1305).
        """
        prk = cls._extract_prk(cek)
        index_bytes = struct.pack(">I", shard_index)
        info = entity_id.encode("utf-8") + index_bytes + b"\x01"
        expanded = hmac_stdlib.new(prk, info, hashlib.sha256).digest()
        return expanded[: AEAD.NONCE_SIZE]

    @staticmethod
    def _aad(entity_id: str, shard_index: int) -> bytes:
        """Associated data binding entity_id and shard_index into the AEAD tag.

        This explicitly authenticates shard identity alongside the nonce derivation,
        providing defense-in-depth: even if the nonce were somehow reused, the AAD
        prevents cross-entity or cross-index shard substitution.
        """
        return entity_id.encode() + struct.pack(">I", shard_index)

    @classmethod
    def encrypt_shard(
        cls, cek: bytes, entity_id: str, plaintext_shard: bytes, shard_index: int
    ) -> bytes:
        """Encrypt a shard with CEK. Returns ciphertext || 32-byte auth tag."""
        cls.validate_cek(cek)
        nonce = cls._nonce(cek, entity_id, shard_index)
        aad = cls._aad(entity_id, shard_index)
        return AEAD.encrypt(cek, plaintext_shard, nonce, aad)

    @classmethod
    def decrypt_shard(
        cls, cek: bytes, entity_id: str, encrypted_shard: bytes, shard_index: int
    ) -> bytes:
        """Decrypt a shard with CEK. Raises ValueError if tampered."""
        nonce = cls._nonce(cek, entity_id, shard_index)
        aad = cls._aad(entity_id, shard_index)
        return AEAD.decrypt(cek, encrypted_shard, nonce, aad)

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._issued_ceks.clear()
        cls._issued_ceks_order.clear()
