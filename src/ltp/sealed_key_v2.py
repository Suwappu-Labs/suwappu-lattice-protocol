"""
Sealed key, revised construction — reference implementation of
whitepaper Theorem 9 (§3.3.6).

The v1 sealed key (``SealedBox`` in ``keypair.py``) encrypts the
lattice payload under the ML-KEM shared secret with **no associated
data**: nothing binds a sealed key to the receiver it was addressed to,
the entity it unlocks, or the transfer session it belongs to. That gap
is the identity-misbinding / cross-session-replay weakness disclosed in
whitepaper §3.3.3, formalized as the Theorem 8 fourth attack path, and
found independently by the Verifpal analysis (§3.3.8).

This module implements the revised construction exactly as Theorem 9
specifies it — the same construction modeled symbolically in
``docs/formal/etp-protocol-revised.vp``:

- **Receiver binding** — the AEAD associated data carries the
  receiver's encapsulation-key fingerprint. A sealed key addressed to
  a different receiver fails context verification at this one.
- **Entity binding** — the associated data carries the entity_id. A
  sealed key for a different entity fails at a receiver expecting this
  one.
- **Freshness** — the associated data carries a per-transfer nonce
  ``eta`` (Theorem 9's η; receiver-generated challenge, or otherwise
  agreed per session). A sealed key replayed from another session
  carries the wrong η and fails. At |η| = 128 bits, the replay term of
  Theorem 9's bound is q_s²/2¹²⁹.
- **Committing AEAD** — the payload is encrypted with the CTX wrapper
  (``committing_aead``), because plain XChaCha20-Poly1305 is
  CMT-insecure and associated data alone cannot bind a ciphertext to
  one context against an adversary who knows the keys (§3.3.3's
  normative requirement; the symbolic model's ideal AEAD assumes
  exactly this property).

Context verification happens in constant time BEFORE the ordinary
AEAD tag is consulted, and unsealing reconstructs the expected
associated data from the receiver's OWN key material and session
state — never from attacker-controlled delivery.

Wire format::

    kem_ct(1088) || nonce(24) || C || poly1305_tag(16) || ctx_tag(32)

Constant overhead over the payload: 1088 + 24 + 16 + 32 = 1,160 bytes,
independent of the payload — the O(1) sealed-key property
(machine-checked for v1 sizes as ``lattice_key_size_payload_independent``
in ``formal/lean/``) is preserved.

Status: reference implementation for the **planned** protocol
revision. NOT wired into the LTP-corridor-v1 wire format; the v1
``SealedBox`` remains the implemented protocol until a coordinated
revision ships.
"""

from __future__ import annotations

import hashlib
import os

from .committing_aead import commit_decrypt, commit_encrypt
from .keypair import KeyPair
from .primitives import AEAD, MLKEM

__all__ = [
    "ETA_SIZE",
    "SKB_DST",
    "SealedBoxV2",
    "receiver_fingerprint",
]

# Domain-separation tag for the sealed-key context. Byte-exact across
# implementations (LTP-A-022 discipline).
SKB_DST = b"LTP-SKB-v2"

# Per-transfer freshness nonce (Theorem 9's η): 128 bits.
ETA_SIZE = 16

# Entity identity is a 32-byte content hash (§1.2).
_ENTITY_ID_SIZE = 32


def _frame(*parts: bytes) -> bytes:
    """Length-prefixed encoding (4-byte big-endian per part) —
    injective, per the Theorem 4 / LTP-A-022 framing discipline."""
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def receiver_fingerprint(receiver_ek: bytes) -> bytes:
    """SHA3-256 fingerprint of the receiver's encapsulation key —
    the fp(ek_R) of Theorem 9's associated data. Canonical-lane hash,
    deliberately fixed (verified cross-party)."""
    return hashlib.sha3_256(_frame(SKB_DST + b"-fp", receiver_ek)).digest()


def _context_ad(receiver_ek: bytes, entity_id: bytes, eta: bytes) -> bytes:
    """The Theorem 9 associated data: (fp(ek_R), entity_id, η)."""
    if len(entity_id) != _ENTITY_ID_SIZE:
        raise ValueError(f"entity_id must be {_ENTITY_ID_SIZE}B, got {len(entity_id)}")
    if len(eta) != ETA_SIZE:
        raise ValueError(f"eta must be {ETA_SIZE}B, got {len(eta)}")
    return _frame(SKB_DST, receiver_fingerprint(receiver_ek), entity_id, eta)


class SealedBoxV2:
    """
    Context-bound post-quantum envelope: ML-KEM-768 + CTX-committing
    XChaCha20-Poly1305, with the Theorem 9 associated data.
    """

    #: Constant wire overhead over the sealed payload.
    OVERHEAD = MLKEM.CT_SIZE + AEAD.NONCE_SIZE + AEAD.TAG_SIZE + 32

    @staticmethod
    def generate_eta() -> bytes:
        """Fresh per-transfer nonce (receiver-side challenge)."""
        return os.urandom(ETA_SIZE)

    @classmethod
    def seal(cls, plaintext: bytes, receiver_ek: bytes, entity_id: bytes, eta: bytes) -> bytes:
        """
        Seal ``plaintext`` to ``receiver_ek``, bound to
        (receiver fingerprint, entity_id, η).

        Fresh ML-KEM encapsulation per call (forward secrecy); the
        shared secret is used once and discarded.
        """
        if len(receiver_ek) != MLKEM.EK_SIZE:
            raise ValueError(f"Invalid ek size: {len(receiver_ek)} (expected {MLKEM.EK_SIZE})")

        aad = _context_ad(receiver_ek, entity_id, eta)
        shared_secret, kem_ct = MLKEM.encaps(receiver_ek)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        blob = commit_encrypt(shared_secret, plaintext, nonce, aad)
        del shared_secret
        return kem_ct + nonce + blob

    @classmethod
    def unseal(
        cls, sealed_data: bytes, receiver_keypair: KeyPair, entity_id: bytes, eta: bytes
    ) -> bytes:
        """
        Unseal, enforcing the full context.

        The expected associated data is rebuilt from the receiver's OWN
        encapsulation key, the entity_id the receiver resolved, and the
        receiver's OWN η — a sealed key addressed to another receiver,
        another entity, or another session fails context verification
        (constant-time) before the ordinary AEAD tag is consulted.

        Raises ValueError on any mismatch or tampering. Note that
        ML-KEM decapsulation uses implicit rejection (FIPS 203): a
        wrong-receiver ciphertext yields a garbage shared secret rather
        than an error, and is then caught by the context check.
        """
        if len(sealed_data) < cls.OVERHEAD:
            raise ValueError(f"Sealed data too short ({len(sealed_data)} < {cls.OVERHEAD})")

        aad = _context_ad(receiver_keypair.ek, entity_id, eta)

        kem_ct = sealed_data[: MLKEM.CT_SIZE]
        nonce = sealed_data[MLKEM.CT_SIZE : MLKEM.CT_SIZE + AEAD.NONCE_SIZE]
        blob = sealed_data[MLKEM.CT_SIZE + AEAD.NONCE_SIZE :]

        try:
            shared_secret = receiver_keypair.decaps(kem_ct)
        except ValueError:
            raise ValueError(
                "Cannot unseal — ML-KEM decapsulation failed "
                "(malformed ciphertext for this decapsulation key)"
            )

        try:
            return commit_decrypt(shared_secret, blob, nonce, aad)
        finally:
            del shared_secret
