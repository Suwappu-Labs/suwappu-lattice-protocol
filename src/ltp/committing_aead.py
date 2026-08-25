"""
Committing AEAD — CTX wrapper over XChaCha20-Poly1305.

Reference implementation of the committing-AEAD requirement that
whitepaper §3.3.3 places on the planned sealed-key revision (and that
Theorem 9's bound depends on): XChaCha20-Poly1305, like every scheme in
the GCM/Poly1305 family, is NOT committing — a single ciphertext–tag
pair can be crafted to decrypt validly under two different keys, so its
tag alone cannot bind a sealed key to one (key, nonce, AD) context
against an adversary who knows the keys involved.

Construction: **CTX** (Chan–Rogaway, "On Committing
Authenticated-Encryption", ESORICS 2022, ePrint 2022/1260), in the
black-box variant. CTX replaces the legacy tag T with
``T* = H(K, N, A, T)``; because libsodium's AEAD API verifies T
internally and offers no "recompute tag" entry point, this
implementation *retains* T and appends T*::

    blob = C || T || T*        T* = SHA3-256(framed(DST, K, N, A, T))

Security is the CTX argument unchanged: T* commits to (K, N, A, T)
under collision resistance of H (random-oracle in the original proof);
T is a MAC over (A, C) under the committed K, and (K, N, C) determine
M for a stream-cipher AEAD — so the blob commits to the full input
tuple (CMT-4 in the Bellare–Hoang taxonomy, ePrint 2022/268). The cost
over the base AEAD is one short hash and ``COMMIT_TAG_SIZE`` bytes,
independent of plaintext length.

Decryption verifies T* FIRST (constant-time), then runs the normal
AEAD decryption — so a blob that fails the commitment check is
rejected before the non-committing tag gets a vote.

Design notes:

- H is **SHA3-256 via hashlib**, deliberately fixed rather than routed
  through the dual-lane profile: a commitment tag is verified by the
  *other* party, so it belongs to the canonical (cross-party) lane and
  must not vary with a local security profile.
- Hash inputs are length-prefixed (4-byte big-endian) per component —
  the same concatenation-injectivity discipline the whitepaper's
  Theorem 4 framing note and audit LTP-A-022 require. The DST string
  must remain byte-identical across implementations.
- This module is the reference implementation for the **planned**
  protocol revision (whitepaper §3.3.3, §3.3.6 Theorem 9, §3.3.8). It
  is NOT wired into the LTP-corridor-v1 wire format; adopting it on a
  wire path is a protocol-revision decision, not a drop-in change.

References: Chan–Rogaway ePrint 2022/1260 (CTX); Bellare–Hoang ePrint
2022/268 (CMT taxonomy; GCM/Poly1305 family CMT-insecure); Albertini
et al., USENIX Security 2022 (practical key-commitment abuses);
Len–Grubbs–Ristenpart, USENIX Security 2021 (partitioning oracles).
"""

from __future__ import annotations

import hashlib
import hmac

from .primitives import AEAD

# Domain-separation tag for the commitment hash. Byte-exact across
# implementations — never normalized, trimmed, or re-encoded.
CTX_DST = b"LTP-CTX-v1"

# SHA3-256 commitment tag.
COMMIT_TAG_SIZE = 32

# Total overhead over the plaintext: Poly1305 tag + commitment tag.
OVERHEAD = AEAD.TAG_SIZE + COMMIT_TAG_SIZE


def _frame(*parts: bytes) -> bytes:
    """Length-prefixed encoding: 4-byte big-endian length before each
    part. Injective — no two distinct tuples encode identically."""
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def _commit_tag(key: bytes, nonce: bytes, aad: bytes, legacy_tag: bytes) -> bytes:
    """T* = SHA3-256(framed(DST, K, N, A, T)) — the CTX commitment."""
    return hashlib.sha3_256(_frame(CTX_DST, key, nonce, aad, legacy_tag)).digest()


def commit_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """
    Encrypt with a committing wrapper: ``C || T || T*``.

    Args:
        key: 32-byte symmetric key
        plaintext: data to encrypt
        nonce: 24 bytes, unique per (key, message) pair
        aad: associated data, authenticated and committed but not encrypted

    Returns:
        AEAD ciphertext-with-tag, followed by the 32-byte CTX commitment
        tag. ``len(result) == len(plaintext) + OVERHEAD``.
    """
    ct_with_tag = AEAD.encrypt(key, plaintext, nonce, aad)
    legacy_tag = ct_with_tag[-AEAD.TAG_SIZE :]
    return ct_with_tag + _commit_tag(key, nonce, aad, legacy_tag)


def commit_decrypt(key: bytes, blob: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """
    Verify the CTX commitment tag (constant-time), then AEAD-decrypt.

    The commitment check runs FIRST: a blob whose (key, nonce, AD,
    legacy-tag) context does not match is rejected before the
    non-committing Poly1305 tag is ever consulted.

    Raises:
        ValueError: on truncated input, commitment mismatch, or AEAD
        authentication failure.
    """
    if len(blob) < OVERHEAD:
        raise ValueError(f"Committing AEAD blob too short: {len(blob)}B < {OVERHEAD}B minimum")

    ct_with_tag, commit_tag = blob[:-COMMIT_TAG_SIZE], blob[-COMMIT_TAG_SIZE:]
    legacy_tag = ct_with_tag[-AEAD.TAG_SIZE :]

    expected = _commit_tag(key, nonce, aad, legacy_tag)
    if not hmac.compare_digest(commit_tag, expected):
        raise ValueError(
            "Committing AEAD context verification FAILED — "
            "key, nonce, associated data, or tag does not match this ciphertext"
        )

    return AEAD.decrypt(key, ct_with_tag, nonce, aad)
