"""
BLS12-381 cryptographic backend for the Lattice Transfer Protocol.

Dual-backend design (Spec C1 §2):
  - blst (primary) — C-compiled, production-grade, used by Ethereum 2.0
  - py_ecc (fallback) — Pure Python, EVM-compatible

Backend detection follows the same pattern as ML-KEM/ML-DSA in primitives.py.
"""

from __future__ import annotations

import os

__all__ = [
    "BLS",
    "_blst_available",
    "_py_ecc_bls_available",
    "assert_bls_crypto",
    "assert_bls_production",
]

# ---------------------------------------------------------------------------
# Backend detection (same pattern as primitives.py)
# ---------------------------------------------------------------------------

_blst_available = False
try:
    import blst as _blst_mod
    _blst_available = True
except ImportError:
    pass

_py_ecc_bls_available = False
try:
    from py_ecc.bls import G2ProofOfPossession as _py_ecc_bls
    from py_ecc.optimized_bls12_381 import curve_order as _BLS_CURVE_ORDER
    _py_ecc_bls_available = True
except ImportError:
    pass


def assert_bls_crypto() -> None:
    """Assert that at least one BLS12-381 backend is available.

    In production, blst is required (enforced separately).
    For dev/testing, py_ecc is sufficient.
    Raises RuntimeError if neither backend is available.
    """
    if not _blst_available and not _py_ecc_bls_available:
        raise RuntimeError(
            "No BLS12-381 backend available. "
            "Install blst (production) or py-ecc (development): "
            "pip install blst  OR  pip install py-ecc"
        )


def assert_bls_production() -> None:
    """Assert that the production BLS backend (blst) is available.

    Call this in production deployments where performance matters AND
    where the py_ecc fallback's lack of documented constant-time
    guarantees would be a security regression. The py_ecc path is fine
    for dev / CI but should never run in production.
    """
    if not _blst_available:
        raise RuntimeError(
            "Production BLS backend (blst) not available. "
            "Install with: pip install blst"
        )


# Fail-fast at import time when LTP_ENV signals a production deployment
# but the production-grade backend is missing. Catches the case where
# `pip install -e .[crypto]` was used without `blst` and a production
# operator never noticed until a signing hot path silently downgraded
# to the constant-time-unverified py_ecc fallback.
if os.environ.get("LTP_ENV", "").lower() == "production":
    assert_bls_production()


class BLS:
    """BLS12-381 aggregate signature scheme.

    Provides keygen, sign, verify, and aggregate operations.
    Delegates to blst (preferred) or py_ecc (fallback).
    Backend selection is transparent to callers.

    Sizes (BLS12-381 compressed):
      PK:  48 bytes (compressed G1 point)
      SK:  32 bytes (scalar)
      SIG: 96 bytes (compressed G2 point)
    """

    PK_SIZE = 48   # Compressed G1 public key
    SK_SIZE = 32   # Scalar signing key
    SIG_SIZE = 96  # G2 signature

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """Generate a BLS12-381 keypair.

        Returns: (pk, sk) where pk is 48 bytes and sk is 32 bytes.
        """
        if _blst_available:
            return cls._keygen_blst()
        if _py_ecc_bls_available:
            return cls._keygen_py_ecc()
        raise RuntimeError("No BLS backend available")

    @classmethod
    def sign(cls, sk: bytes, message: bytes) -> bytes:
        """Sign a message with a BLS12-381 signing key.

        Args:
            sk: 32-byte signing key
            message: arbitrary bytes to sign

        Returns: 96-byte G2 signature
        """
        if len(sk) != cls.SK_SIZE:
            raise ValueError(f"Invalid sk size: {len(sk)} (expected {cls.SK_SIZE})")
        if _blst_available:
            return cls._sign_blst(sk, message)
        if _py_ecc_bls_available:
            return cls._sign_py_ecc(sk, message)
        raise RuntimeError("No BLS backend available")

    @classmethod
    def verify(cls, pk: bytes, message: bytes, sig: bytes) -> bool:
        """Verify a BLS12-381 signature.

        Args:
            pk: 48-byte public key
            message: the signed message
            sig: 96-byte signature

        Returns: True if valid, False otherwise
        """
        if len(pk) != cls.PK_SIZE:
            return False
        if len(sig) != cls.SIG_SIZE:
            return False
        if _blst_available:
            return cls._verify_blst(pk, message, sig)
        if _py_ecc_bls_available:
            return cls._verify_py_ecc(pk, message, sig)
        raise RuntimeError("No BLS backend available")

    @classmethod
    def aggregate_signatures(cls, sigs: list[bytes]) -> bytes:
        """Aggregate N BLS signatures into one constant-size 96-byte signature."""
        if not sigs:
            raise ValueError("Cannot aggregate empty signature list")
        for i, s in enumerate(sigs):
            if len(s) != cls.SIG_SIZE:
                raise ValueError(f"Signature {i} has invalid size: {len(s)}")
        if _blst_available:
            return cls._aggregate_blst(sigs)
        if _py_ecc_bls_available:
            return cls._aggregate_py_ecc(sigs)
        raise RuntimeError("No BLS backend available")

    @classmethod
    def aggregate_verify(cls, pks: list[bytes], messages: list[bytes], agg_sig: bytes) -> bool:
        """Verify an aggregate signature against multiple (pk, message) pairs."""
        if len(pks) != len(messages):
            return False
        if len(agg_sig) != cls.SIG_SIZE:
            return False
        if _blst_available:
            return cls._aggregate_verify_blst(pks, messages, agg_sig)
        if _py_ecc_bls_available:
            return cls._aggregate_verify_py_ecc(pks, messages, agg_sig)
        raise RuntimeError("No BLS backend available")

    @classmethod
    def aggregate_verify_same_message(cls, pks: list[bytes], message: bytes, agg_sig: bytes) -> bool:
        """Fast-path: verify aggregate when all signers signed the same message."""
        if len(agg_sig) != cls.SIG_SIZE:
            return False
        if _blst_available:
            return cls._fast_aggregate_verify_blst(pks, message, agg_sig)
        if _py_ecc_bls_available:
            return cls._fast_aggregate_verify_py_ecc(pks, message, agg_sig)
        raise RuntimeError("No BLS backend available")

    # -------------------------------------------------------------------
    # py_ecc backend implementation
    # -------------------------------------------------------------------

    @classmethod
    def _keygen_py_ecc(cls) -> tuple[bytes, bytes]:
        sk_bytes = os.urandom(cls.SK_SIZE)
        sk_int = int.from_bytes(sk_bytes, "big") % (_BLS_CURVE_ORDER - 1) + 1
        sk_out = sk_int.to_bytes(cls.SK_SIZE, "big")
        pk = _py_ecc_bls.SkToPk(sk_int)
        return bytes(pk), sk_out

    @classmethod
    def _sign_py_ecc(cls, sk: bytes, message: bytes) -> bytes:
        sk_int = int.from_bytes(sk, "big")
        sig = _py_ecc_bls.Sign(sk_int, message)
        return bytes(sig)

    @classmethod
    def _verify_py_ecc(cls, pk: bytes, message: bytes, sig: bytes) -> bool:
        try:
            return _py_ecc_bls.Verify(pk, message, sig)
        except Exception:
            return False

    @classmethod
    def _aggregate_py_ecc(cls, sigs: list[bytes]) -> bytes:
        agg = _py_ecc_bls.Aggregate(sigs)
        return bytes(agg)

    @classmethod
    def _aggregate_verify_py_ecc(cls, pks: list[bytes], messages: list[bytes], agg_sig: bytes) -> bool:
        try:
            return _py_ecc_bls.AggregateVerify(pks, messages, agg_sig)
        except Exception:
            return False

    @classmethod
    def _fast_aggregate_verify_py_ecc(cls, pks: list[bytes], message: bytes, agg_sig: bytes) -> bool:
        try:
            return _py_ecc_bls.FastAggregateVerify(pks, message, agg_sig)
        except Exception:
            return False

    # -------------------------------------------------------------------
    # blst backend implementation (activated when blst is installed)
    # -------------------------------------------------------------------

    @classmethod
    def _keygen_blst(cls) -> tuple[bytes, bytes]:
        sk = _blst_mod.SecretKey()
        sk.from_random()
        pk = _blst_mod.P1(sk).compress()
        return bytes(pk), sk.to_bytes()

    @classmethod
    def _sign_blst(cls, sk_bytes: bytes, message: bytes) -> bytes:
        sk = _blst_mod.SecretKey.from_bytes(sk_bytes)
        sig = _blst_mod.P2()
        sig.hash_to(message).sign_with(sk)
        return sig.compress()

    @classmethod
    def _verify_blst(cls, pk: bytes, message: bytes, sig: bytes) -> bool:
        try:
            p1 = _blst_mod.P1_Affine(pk)
            p2 = _blst_mod.P2_Affine(sig)
            return p2.core_verify(p1, True, message) == _blst_mod.BLST_SUCCESS
        except Exception:
            return False

    @classmethod
    def _aggregate_blst(cls, sigs: list[bytes]) -> bytes:
        agg = _blst_mod.P2_Affine(sigs[0]).to_jacobian()
        for s in sigs[1:]:
            agg.aggregate(_blst_mod.P2_Affine(s))
        return agg.compress()

    @classmethod
    def _aggregate_verify_blst(cls, pks: list[bytes], messages: list[bytes], agg_sig: bytes) -> bool:
        try:
            sig_affine = _blst_mod.P2_Affine(agg_sig)
            ctx = _blst_mod.Pairing(True)
            for pk_bytes, msg in zip(pks, messages):
                pk_affine = _blst_mod.P1_Affine(pk_bytes)
                ctx.aggregate(pk_affine, sig_affine, msg)
            ctx.commit()
            return ctx.finalverify()
        except Exception:
            return False

    @classmethod
    def _fast_aggregate_verify_blst(cls, pks: list[bytes], message: bytes, agg_sig: bytes) -> bool:
        try:
            sig_affine = _blst_mod.P2_Affine(agg_sig)
            agg_pk = _blst_mod.P1_Affine(pks[0]).to_jacobian()
            for pk_bytes in pks[1:]:
                agg_pk.aggregate(_blst_mod.P1_Affine(pk_bytes))
            agg_pk_affine = agg_pk.to_affine()
            return sig_affine.core_verify(agg_pk_affine, True, message) == _blst_mod.BLST_SUCCESS
        except Exception:
            return False
