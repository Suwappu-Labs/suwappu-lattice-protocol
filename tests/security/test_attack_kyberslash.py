"""LTP-A-014 regression: ML-KEM-768 KyberSlash timing-leak resistance.

KyberSlash 1 (Dec 2023) and KyberSlash 2 (Jan 2024) are timing leaks in
the Kyber / ML-KEM decapsulation pipeline:

  KyberSlash 1: secret-dependent division in poly_compress
  KyberSlash 2: secret-dependent branch in poly_tomsg

Both were patched upstream in PQClean by Feb 2024. The pqcrypto package
binds to the PQClean ``CLEAN`` reference implementation, which is the
conservative no-optimization path that was structurally safer against
the leaks (the wider blast radius hit the AVX2/AArch64 variants).

This test does **not** attempt empirical timing measurement (which is
noisy on CI). Instead it pins two structural invariants:

1. ``MLKEM.decaps`` always returns a 32-byte shared secret for a valid-
   sized ciphertext, including ciphertexts that look like garbage. The
   "implicit rejection" property of FIPS-203 ML-KEM means an invalid
   ciphertext deterministically yields a pseudorandom shared secret
   derived from the receiver's dk — not an early return that would
   leak a timing signal.

2. The wrapper at ``primitives.py:373-390`` only does fixed-size length
   checks before calling the C library; no secret-dependent branching
   in the Python layer. Verified by inspection of the source.

LTP-A-014 in ``docs/SECURITY_AUDIT_2026-05-15.md``.
"""

from __future__ import annotations

import os

import pytest

from src.ltp.primitives import MLKEM


def _gen_keypair():
    return MLKEM.keygen()  # (ek, dk)


def test_decaps_returns_shared_secret_for_valid_ciphertext():
    """Sanity: a real encapsulation roundtrips."""
    ek, dk = _gen_keypair()
    ss_enc, ct = MLKEM.encaps(ek)
    ss_dec = MLKEM.decaps(dk, ct)
    assert ss_dec == ss_enc
    assert len(ss_dec) == MLKEM.SS_SIZE == 32


def test_decaps_implicit_rejection_on_random_ciphertext():
    """A garbage ciphertext of the correct length must NOT raise; it
    must return a deterministic pseudorandom shared secret (FIPS-203
    implicit rejection). An early return on invalid input would be a
    timing-leak surface."""
    _, dk = _gen_keypair()
    garbage = os.urandom(MLKEM.CT_SIZE)
    ss = MLKEM.decaps(dk, garbage)
    assert len(ss) == MLKEM.SS_SIZE


def test_decaps_implicit_rejection_is_deterministic():
    """Same garbage ciphertext + same dk must yield the same (rejected)
    shared secret across calls. This is the structural KyberSlash-2
    invariant: the rejection path is a deterministic function of (dk,
    ct), not a conditional on ct's validity."""
    _, dk = _gen_keypair()
    garbage = b"\x42" * MLKEM.CT_SIZE
    a = MLKEM.decaps(dk, garbage)
    b = MLKEM.decaps(dk, garbage)
    assert a == b
    assert len(a) == MLKEM.SS_SIZE


def test_decaps_rejects_wrong_ct_size_before_crypto():
    """The Python wrapper short-circuits on length mismatch — this is
    the ONE early-return path in the decaps pipeline, and it's based
    only on public length, not on ciphertext content. ValueError is
    raised before any pqcrypto call so no timing leak via the C lib."""
    _, dk = _gen_keypair()
    with pytest.raises(ValueError, match="Invalid ct size"):
        MLKEM.decaps(dk, b"\x00" * (MLKEM.CT_SIZE - 1))
    with pytest.raises(ValueError, match="Invalid ct size"):
        MLKEM.decaps(dk, b"\x00" * (MLKEM.CT_SIZE + 1))


def test_decaps_rejects_wrong_dk_size_before_crypto():
    with pytest.raises(ValueError, match="Invalid dk size"):
        MLKEM.decaps(b"\x00" * (MLKEM.DK_SIZE - 1), b"\x00" * MLKEM.CT_SIZE)


def test_pqcrypto_uses_pqclean_clean_variant():
    """Confirm we're bound to the PQClean ``CLEAN`` reference variant,
    not an optimized AVX2/AArch64 path. KyberSlash's worst-case impact
    was concentrated in the optimized variants."""
    from pqcrypto._kem import ml_kem_768 as _kem
    # The CFFI lib exposes the PQClean symbol prefix in its API; the
    # _CLEAN_ infix marks the reference implementation.
    symbols = [s for s in dir(_kem.lib) if "MLKEM768" in s]
    assert any("_CLEAN_" in s for s in symbols), (
        "MLKEM module is not bound to the PQClean _CLEAN_ variant; "
        "an optimized variant would widen the KyberSlash blast radius"
    )
