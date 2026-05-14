"""BLS shim that signs and verifies under the corridor DST.

`src/ltp/bls.py::BLS` signs under py_ecc's `G2ProofOfPossession` ciphersuite,
whose hash-to-curve DST is `BLS_SIG_BLS12381G2_XMD:SHA-256_POP_`. The cross-
repo corridor surface in `gsx-dag/crates/gsx-crypto/src/bls.rs` uses
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`. Signatures produced under one
DST will never verify under the other, so the corridor pipeline cannot route
through the existing `BLS` class.

This module wraps the same backend libraries (`blst` preferred, `py_ecc`
fallback via `G2Basic`, which uses the matching `_NUL_` DST) and exposes a
minimal `corridor_sign` / `corridor_verify` / `corridor_aggregate_*` surface
keyed to `BLS_CORRIDOR_DST`.
"""

from __future__ import annotations

import os

from .constants import BLS_CORRIDOR_DST

try:  # pragma: no cover — backend detection
    import blst as _blst
    _blst_available = True
except ImportError:
    _blst = None
    _blst_available = False

try:  # pragma: no cover — backend detection
    from py_ecc.bls import G2Basic as _py_ecc_basic
    _py_ecc_available = True
except ImportError:
    _py_ecc_basic = None
    _py_ecc_available = False

PK_SIZE = 48
SK_SIZE = 32
SIG_SIZE = 96

_BLS_CURVE_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001


class CorridorBlsBackendMissing(RuntimeError):
    """Raised when neither blst nor py_ecc.G2Basic is importable."""


def _require_backend() -> None:
    if not _blst_available and not _py_ecc_available:
        raise CorridorBlsBackendMissing(
            "corridor BLS requires blst or py_ecc with G2Basic ciphersuite"
        )


def keygen() -> tuple[bytes, bytes]:
    """Generate a (compressed-G1 pk, scalar sk) BLS12-381 keypair."""
    _require_backend()
    if _blst_available:
        sk = _blst.SecretKey()
        sk.from_random()
        pk = _blst.P1(sk).compress()
        return bytes(pk), sk.to_bytes()
    sk_bytes = os.urandom(SK_SIZE)
    sk_int = int.from_bytes(sk_bytes, "big") % (_BLS_CURVE_ORDER - 1) + 1
    pk = bytes(_py_ecc_basic.SkToPk(sk_int))
    return pk, sk_int.to_bytes(SK_SIZE, "big")


def corridor_sign(sk: bytes, digest: bytes) -> bytes:
    """Sign `digest` under the corridor DST. Returns 96-byte compressed G2."""
    _require_backend()
    if len(sk) != SK_SIZE:
        raise ValueError(f"sk must be {SK_SIZE} bytes")
    if _blst_available:
        sk_obj = _blst.SecretKey.from_bytes(sk)
        sig = _blst.P2()
        sig.hash_to(digest, BLS_CORRIDOR_DST).sign_with(sk_obj)
        return sig.compress()
    sk_int = int.from_bytes(sk, "big")
    return bytes(_py_ecc_basic.Sign(sk_int, digest))


def corridor_verify(pk: bytes, digest: bytes, sig: bytes) -> bool:
    """Verify a single corridor signature."""
    if len(pk) != PK_SIZE or len(sig) != SIG_SIZE:
        return False
    _require_backend()
    if _blst_available:
        try:
            p1 = _blst.P1_Affine(pk)
            p2 = _blst.P2_Affine(sig)
            return p2.core_verify(p1, True, digest, BLS_CORRIDOR_DST) == _blst.BLST_SUCCESS
        except Exception:
            return False
    return bool(_py_ecc_basic.Verify(pk, digest, sig))


def corridor_aggregate_signatures(sigs: list[bytes]) -> bytes:
    """Aggregate N signatures into a single 96-byte compressed G2 point."""
    if not sigs:
        raise ValueError("cannot aggregate empty signature list")
    for i, s in enumerate(sigs):
        if len(s) != SIG_SIZE:
            raise ValueError(f"signature {i} has invalid size {len(s)}")
    _require_backend()
    if _blst_available:
        agg = _blst.P2_Affine(sigs[0]).to_jacobian()
        for s in sigs[1:]:
            agg.aggregate(_blst.P2_Affine(s))
        return agg.compress()
    return bytes(_py_ecc_basic.Aggregate(sigs))


def corridor_aggregate_verify(pks: list[bytes], digest: bytes, agg_sig: bytes) -> bool:
    """Fast-aggregate verify: all signers signed the same `digest`.

    Note: `py_ecc.bls.G2Basic.AggregateVerify` rejects same-message
    aggregates (Basic ciphersuite requires distinct messages to defend
    against rogue-key attacks). For the same-message corridor case, we
    manually aggregate the public keys into a single G1 point and call
    `G2Basic.Verify` against it — that uses the matching `_NUL_` DST and
    works under the Basic scheme as long as the signer set is fixed
    (which it is for a corridor).
    """
    if not pks or len(agg_sig) != SIG_SIZE:
        return False
    for pk in pks:
        if len(pk) != PK_SIZE:
            return False
    _require_backend()
    if _blst_available:
        try:
            sig_affine = _blst.P2_Affine(agg_sig)
            agg_pk = _blst.P1_Affine(pks[0]).to_jacobian()
            for pk in pks[1:]:
                agg_pk.aggregate(_blst.P1_Affine(pk))
            return (
                sig_affine.core_verify(
                    agg_pk.to_affine(), True, digest, BLS_CORRIDOR_DST
                )
                == _blst.BLST_SUCCESS
            )
        except Exception:
            return False
    # py_ecc fallback: aggregate pubkeys manually, then single-key verify.
    try:
        from py_ecc.bls.point_compression import compress_G1, decompress_G1
        from py_ecc.optimized_bls12_381 import add

        agg_point = decompress_G1(int.from_bytes(pks[0], "big"))
        for pk in pks[1:]:
            agg_point = add(agg_point, decompress_G1(int.from_bytes(pk, "big")))
        agg_pk_bytes = compress_G1(agg_point).to_bytes(PK_SIZE, "big")
        return bool(_py_ecc_basic.Verify(agg_pk_bytes, digest, agg_sig))
    except Exception:
        return False
