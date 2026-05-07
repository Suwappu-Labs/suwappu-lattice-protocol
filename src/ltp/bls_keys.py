"""
BLS12-381 key management — three modes (Spec C1 §3).

Modes:
  1. Composite — BLS fields added to existing KeyPair (see keypair.py Task 4)
  2. Standalone — BLSKeyPair manages BLS keys independently
  3. Derived — Deterministic BLS key from ML-DSA signing key via HKDF

All modes produce BLSIdentity for uniform consumption by the attestation engine
and future writer registry (Spec C2).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Callable

from .bls import BLS
from .keypair import KeyState
from .primitives import canonical_hash_bytes


__all__ = [
    "BLSKeyPair",
    "BLSIdentity",
    "bls_fingerprint",
    "composite_fingerprint",
]


def bls_fingerprint(pk: bytes) -> bytes:
    """Compute a 32-byte fingerprint from a BLS public key.

    Uses SHA3-256 (via canonical_hash_bytes) for consistency with
    the existing signer_fingerprint() in domain.py.
    """
    return canonical_hash_bytes(pk)


def composite_fingerprint(mldsa_vk: bytes, bls_pk: bytes) -> bytes:
    """Compute composite fingerprint: SHA3(mldsa_vk || bls_pk).

    Used when a KeyPair has both ML-DSA and BLS keys.
    The identity is bound to both keys.
    """
    return canonical_hash_bytes(mldsa_vk + bls_pk)


@dataclass(frozen=True)
class BLSIdentity:
    """Unified BLS identity interface (Spec C1 §3.4).

    Consumed by the attestation engine and writer registry regardless
    of how the key was produced. The sk_accessor is callable to support
    HSM-backed keys where the signing key never leaves the secure element.
    """
    pk: bytes              # 48-byte compressed G1 public key
    sk_accessor: Callable  # Returns sk bytes when called
    fingerprint: bytes     # 32-byte SHA3 identity
    mode: str              # "composite" | "standalone" | "derived"
    label: str             # Human-readable label


@dataclass
class BLSKeyPair:
    """Standalone BLS12-381 keypair (Mode 2) or derived keypair (Mode 3).

    For Mode 1 (composite), see KeyPair.generate(with_bls=True) in keypair.py.
    """
    pk: bytes
    sk: bytes
    label: str = ""
    state: KeyState = KeyState.ACTIVE
    _mode: str = "standalone"

    @classmethod
    def generate(cls, label: str = "") -> BLSKeyPair:
        """Generate a fresh BLS12-381 keypair (Mode 2: standalone)."""
        pk, sk = BLS.keygen()
        return cls(pk=pk, sk=sk, label=label, _mode="standalone")

    @classmethod
    def derive_from(
        cls,
        mldsa_sk: bytes,
        context: bytes = b"GSX-BLS-DERIVE:v1",
        label: str = "",
    ) -> BLSKeyPair:
        """Derive a BLS keypair from an ML-DSA signing key (Mode 3).

        Uses HKDF-SHA3-256 to derive a 32-byte BLS scalar from the
        ML-DSA signing key. Same input always produces the same BLS key.

        The context parameter allows multiple derived BLS keys from one
        ML-DSA root (e.g., different chain IDs).

        Caution: ML-DSA compromise implies BLS compromise when using derivation.
        """
        # HKDF-Extract: PRK = HMAC-SHA3-256(salt=context, IKM=mldsa_sk)
        prk = hmac.new(context, mldsa_sk, hashlib.sha3_256).digest()
        # HKDF-Expand: OKM = HMAC-SHA3-256(PRK, info || 0x01)
        info = b"GSX-BLS-KEY" + b"\x01"
        okm = hmac.new(prk, info, hashlib.sha3_256).digest()

        # Reduce to valid BLS scalar range
        from .bls import _py_ecc_bls_available, _blst_available
        if _py_ecc_bls_available:
            from py_ecc.optimized_bls12_381 import curve_order
            sk_int = int.from_bytes(okm, "big") % (curve_order - 1) + 1
            sk_bytes = sk_int.to_bytes(BLS.SK_SIZE, "big")
        else:
            # blst handles scalar reduction internally
            sk_bytes = okm

        # Derive pk from sk using the BLS backend
        if _blst_available:
            import blst as _blst_mod
            secret = _blst_mod.SecretKey()
            secret.from_bytes(sk_bytes)
            pk = bytes(_blst_mod.P1(secret).compress())
        elif _py_ecc_bls_available:
            from py_ecc.bls import G2ProofOfPossession as _bls
            pk = bytes(_bls.SkToPk(sk_int))
        else:
            raise RuntimeError("No BLS backend available for key derivation")

        return cls(pk=pk, sk=sk_bytes, label=label, _mode="derived")

    def to_identity(self) -> BLSIdentity:
        """Convert to a BLSIdentity for uniform consumption."""
        sk_bytes = self.sk  # capture for closure
        return BLSIdentity(
            pk=self.pk,
            sk_accessor=lambda: sk_bytes,
            fingerprint=bls_fingerprint(self.pk),
            mode=self._mode,
            label=self.label,
        )
