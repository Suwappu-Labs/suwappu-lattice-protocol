"""
Cryptographic primitives for the Lattice Transfer Protocol.

Real post-quantum primitives (mandatory at import time — see
``assert_real_crypto()``):
  - AEAD   — XChaCha20-Poly1305 via pynacl
  - MLKEM  — ML-KEM-768/1024 (FIPS 203) via pqcrypto
  - MLDSA  — ML-DSA-65/87   (FIPS 204) via pqcrypto

Dual-lane hashing (canonical_hash, internal_hash, etc.) is provided by
the ``dual_lane`` subpackage and re-exported here for backward compatibility.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Re-export dual-lane architecture (backward compatibility)
# ---------------------------------------------------------------------------

from .dual_lane import (
    HashFunction,
    CryptoLane,
    SecurityProfile,
    COMPLIANCE_APPROVED as _COMPLIANCE_APPROVED,
    _blake3_available,
    _hash_digest,
    canonical_hash,
    canonical_hash_bytes,
    internal_hash,
    internal_hash_bytes,
    set_compliance_strict,
    get_compliance_strict,
)
from .dual_lane import hashing as _dl_hashing


# ---------------------------------------------------------------------------
# Real backend detection
# ---------------------------------------------------------------------------

# ML-KEM fixed sizes per security level
_REAL_KEM_EK = 1184      # Level 3: ML-KEM-768
_REAL_KEM_DK = 2400
_REAL_KEM_CT = 1088
_REAL_KEM5_EK = 1568     # Level 5: ML-KEM-1024
_REAL_KEM5_DK = 3168
_REAL_KEM5_CT = 1568

# Level 3: ML-KEM-768
_pqcrypto_kem_available = False
try:
    from pqcrypto.kem.ml_kem_768 import (
        generate_keypair as _kem_keygen,
        encrypt as _kem_encrypt,       # returns (ct, ss) — note order!
        decrypt as _kem_decrypt,
    )
    _pqcrypto_kem_available = True
except ImportError:
    pass

# Level 5: ML-KEM-1024
_pqcrypto_kem5_available = False
try:
    from pqcrypto.kem.ml_kem_1024 import (
        generate_keypair as _kem5_keygen,
        encrypt as _kem5_encrypt,
        decrypt as _kem5_decrypt,
    )
    _pqcrypto_kem5_available = True
except ImportError:
    pass

# ML-DSA fixed sizes per security level
_REAL_DSA_VK = 1952      # Level 3: ML-DSA-65
_REAL_DSA_SK = 4032
_REAL_DSA_SIG = 3309
_REAL_DSA5_VK = 2592     # Level 5: ML-DSA-87
_REAL_DSA5_SK = 4896
_REAL_DSA5_SIG = 4627

# Level 3: ML-DSA-65
_pqcrypto_sign_available = False
try:
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as _dsa_keygen,
        sign as _dsa_sign,
        verify as _dsa_verify,
    )
    _pqcrypto_sign_available = True
except ImportError:
    pass

# Level 5: ML-DSA-87
_pqcrypto_sign5_available = False
try:
    from pqcrypto.sign.ml_dsa_87 import (
        generate_keypair as _dsa5_keygen,
        sign as _dsa5_sign,
        verify as _dsa5_verify,
    )
    _pqcrypto_sign5_available = True
except ImportError:
    pass

_pynacl_available = False
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt as _nacl_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt as _nacl_decrypt,
    )
    _pynacl_available = True
except ImportError:
    pass

# BLS12-381 availability (delegated to bls.py for implementation)
from .bls import _blst_available, _py_ecc_bls_available


__all__ = [
    "SecurityProfile", "HashFunction", "CryptoLane",
    "canonical_hash", "canonical_hash_bytes",
    "internal_hash", "internal_hash_bytes",
    "AEAD", "MLKEM", "MLDSA",
    "get_security_profile", "set_security_profile",
    "set_crypto_provider", "get_crypto_provider",
    "set_compliance_strict", "get_compliance_strict",
    "_pqcrypto_kem_available", "_pqcrypto_kem5_available",
    "_pqcrypto_sign_available", "_pqcrypto_sign5_available",
    "_pynacl_available",
    "_blst_available",
    "_py_ecc_bls_available",
    "assert_real_crypto",
]


# ---------------------------------------------------------------------------
# Configurable crypto provider (FIPS 140-3 compliance)
# ---------------------------------------------------------------------------

# Global crypto provider override. When set to a FIPSCryptoProvider in FIPS
# mode, canonical_hash/canonical_hash_bytes delegate to SHA3-256, and AEAD
# delegates to AES-256-GCM. Default (None) uses the dual-lane primitives.
_crypto_provider = None


def set_crypto_provider(provider) -> None:
    """Set the global crypto provider (e.g., FIPSCryptoProvider for FIPS mode)."""
    global _crypto_provider
    _crypto_provider = provider


def get_crypto_provider():
    """Get the current crypto provider (None = default primitives)."""
    return _crypto_provider



def assert_real_crypto() -> None:
    """Assert that all production crypto backends are available.

    Checks ML-KEM-768/1024 (pqcrypto), ML-DSA-65/87 (pqcrypto), and
    XChaCha20-Poly1305 (pynacl). Raises RuntimeError listing any
    missing backends.

    Called automatically at import time.
    """
    missing = []
    if not _pqcrypto_kem_available:
        missing.append("ML-KEM-768 (pqcrypto.kem.ml_kem_768)")
    if not _pqcrypto_kem5_available:
        missing.append("ML-KEM-1024 (pqcrypto.kem.ml_kem_1024)")
    if not _pqcrypto_sign_available:
        missing.append("ML-DSA-65 (pqcrypto.sign.ml_dsa_65)")
    if not _pqcrypto_sign5_available:
        missing.append("ML-DSA-87 (pqcrypto.sign.ml_dsa_87)")
    if not _pynacl_available:
        missing.append("XChaCha20-Poly1305 (pynacl)")
    if missing:
        raise RuntimeError(
            "Production crypto backends missing: " + ", ".join(missing)
            + ". Install with: pip install -e '.[production]'"
        )


# Real PQ crypto is MANDATORY for both Level 3 (ML-KEM-768 / ML-DSA-65)
# and Level 5 (ML-KEM-1024 / ML-DSA-87). All backends (pqcrypto Level 3+5
# + pynacl) must be installed.
assert_real_crypto()


# ---------------------------------------------------------------------------
# SecurityProfile state management
# ---------------------------------------------------------------------------

# Module-level active profile (default: Level 3 / SHA3-256 + BLAKE3)
_active_profile: SecurityProfile = SecurityProfile.level3()


def get_security_profile() -> SecurityProfile:
    """Get the active security profile."""
    return _active_profile


def set_security_profile(profile: SecurityProfile) -> SecurityProfile:
    """
    Set the active security profile. Returns the previous profile.

    WARNING: Changing the profile mid-session will cause key size mismatches
    with existing keys. Only call this at initialization time.
    """
    global _active_profile
    previous = _active_profile
    _active_profile = profile
    # Update MLKEM/MLDSA class-level sizes to match
    MLKEM._sync_profile(profile)
    MLDSA._sync_profile(profile)
    return previous


# ---------------------------------------------------------------------------
# Patch dual_lane.hashing hooks to access state owned by this module
# ---------------------------------------------------------------------------

_dl_hashing._get_active_profile = get_security_profile
_dl_hashing._get_crypto_provider = get_crypto_provider


# ---------------------------------------------------------------------------
# AEAD: Authenticated Encryption with Associated Data
#
# XChaCha20-Poly1305 via pynacl (24-byte nonce, 16-byte Poly1305 tag).
# ---------------------------------------------------------------------------

class AEAD:
    """
    XChaCha20-Poly1305 authenticated encryption.

    Used for shard-level and envelope-level encryption on the materialization
    path. NOT a canonical trust anchor — trust roots are commitment records,
    ML-DSA signatures, the append-only log, and approval receipts.
    """

    NONCE_SIZE = 24  # XChaCha20 nonce
    TAG_SIZE = 16    # Poly1305 tag

    @classmethod
    def _tag_size(cls) -> int:
        """Poly1305 tag size."""
        return cls.TAG_SIZE

    @classmethod
    def encrypt(cls, key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt plaintext → ciphertext || Poly1305 tag.

        Args:
            key: 32-byte symmetric key
            plaintext: data to encrypt
            nonce: 24 bytes, unique per (key, message) pair
            aad: associated data authenticated but not encrypted
        """
        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"Nonce must be {cls.NONCE_SIZE}B, got {len(nonce)}")

        ct = _nacl_encrypt(plaintext, aad or None, nonce, key)
        if len(ct) != len(plaintext) + cls.TAG_SIZE:
            raise RuntimeError(
                f"AEAD output size mismatch: {len(ct)} != {len(plaintext) + cls.TAG_SIZE}"
            )
        return ct

    @classmethod
    def decrypt(cls, key: bytes, ciphertext_with_tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Verify tag, then decrypt → plaintext. Raises ValueError if tampered.

        IMPORTANT: Tag is verified BEFORE decryption (authenticate-then-decrypt).
        """
        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError(f"Nonce must be {cls.NONCE_SIZE}B, got {len(nonce)}")

        try:
            return _nacl_decrypt(ciphertext_with_tag, aad or None, nonce, key)
        except Exception:
            raise ValueError("AEAD authentication FAILED — data has been tampered with")


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203): Key Encapsulation Mechanism
#
# Backed by pqcrypto:
#   Level 3 (ML-KEM-768):  ek=1184, dk=2400, ct=1088, ss=32
#   Level 5 (ML-KEM-1024): ek=1568, dk=3168, ct=1568, ss=32
# ---------------------------------------------------------------------------

class MLKEM:
    """
    ML-KEM Key Encapsulation Mechanism (FIPS 203 / Kyber).

    Supports ML-KEM-768 (Level 3) and ML-KEM-1024 (Level 5) via
    SecurityProfile. Real backend is pqcrypto (mandatory).

    Provides:
      - KeyGen() → (encapsulation_key, decapsulation_key)
      - Encaps(ek) → (shared_secret, ciphertext)
      - Decaps(dk, ciphertext) → shared_secret
    """

    # Default Level 3 sizes (updated by _sync_profile)
    EK_SIZE = 1184   # Encapsulation key size (bytes)
    DK_SIZE = 2400   # Decapsulation key size (bytes)
    CT_SIZE = 1088   # Ciphertext size (bytes)
    SS_SIZE = 32     # Shared secret size (bytes)

    @classmethod
    def _sync_profile(cls, profile: SecurityProfile) -> None:
        """Sync class-level sizes with the active security profile."""
        cls.EK_SIZE = profile.kem_ek_size
        cls.DK_SIZE = profile.kem_dk_size
        cls.CT_SIZE = profile.kem_ct_size
        cls.SS_SIZE = profile.kem_ss_size

    @classmethod
    def _is_level5(cls) -> bool:
        return cls.EK_SIZE == _REAL_KEM5_EK

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-KEM keypair (768 or 1024 depending on profile).

        Returns: (encapsulation_key, decapsulation_key)
        The ek is public; dk MUST remain secret.
        """
        if cls._is_level5():
            ek, dk = _kem5_keygen()
        else:
            ek, dk = _kem_keygen()
        if len(ek) != cls.EK_SIZE:
            raise RuntimeError(f"ML-KEM ek size mismatch: {len(ek)} != {cls.EK_SIZE}")
        if len(dk) != cls.DK_SIZE:
            raise RuntimeError(f"ML-KEM dk size mismatch: {len(dk)} != {cls.DK_SIZE}")
        return ek, dk

    @classmethod
    def encaps(cls, ek: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret and ciphertext.

        Args:
            ek: Encapsulation key (public key of receiver)
        Returns:
            (shared_secret, ciphertext) — ss is 32 bytes, ct size per profile

        The ciphertext is sent to the receiver; only the holder of dk can
        recover the shared secret from it. Each call produces a FRESH
        (shared_secret, ciphertext) pair — this is the basis for forward secrecy.
        """
        if len(ek) != cls.EK_SIZE:
            raise ValueError(f"Invalid ek size: {len(ek)} (expected {cls.EK_SIZE})")

        if cls._is_level5():
            ct, ss = _kem5_encrypt(ek)
        else:
            ct, ss = _kem_encrypt(ek)   # pqcrypto order: (ct, ss)
        if len(ct) != cls.CT_SIZE:
            raise RuntimeError(f"ML-KEM ct size mismatch: {len(ct)} != {cls.CT_SIZE}")
        if len(ss) != cls.SS_SIZE:
            raise RuntimeError(f"ML-KEM ss size mismatch: {len(ss)} != {cls.SS_SIZE}")
        return ss, ct                    # our order: (ss, ct)

    @classmethod
    def decaps(cls, dk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext using dk.

        Uses real ML-KEM lattice decryption via pqcrypto.
        """
        if len(dk) != cls.DK_SIZE:
            raise ValueError(f"Invalid dk size: {len(dk)} (expected {cls.DK_SIZE})")
        if len(ciphertext) != cls.CT_SIZE:
            raise ValueError(f"Invalid ct size: {len(ciphertext)} (expected {cls.CT_SIZE})")

        if cls._is_level5():
            ss = _kem5_decrypt(dk, ciphertext)
        else:
            ss = _kem_decrypt(dk, ciphertext)
        if len(ss) != cls.SS_SIZE:
            raise RuntimeError(f"ML-KEM ss size mismatch: {len(ss)} != {cls.SS_SIZE}")
        return ss

    @classmethod
    def reset_poc_state(cls) -> None:
        """No-op — kept for backward compatibility with pre-production tests."""


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204): Digital Signatures
#
# Backed by pqcrypto:
#   Level 3 (ML-DSA-65): vk=1952, sk=4032, sig=3309
#   Level 5 (ML-DSA-87): vk=2592, sk=4896, sig=4627
# ---------------------------------------------------------------------------

class MLDSA:
    """
    ML-DSA Digital Signature Algorithm (FIPS 204 / Dilithium).

    Supports ML-DSA-65 (Level 3) and ML-DSA-87 (Level 5) via
    SecurityProfile. Real backend is pqcrypto (mandatory).

    Provides:
      - KeyGen() → (verification_key, signing_key)
      - Sign(sk, message) → signature
      - Verify(vk, message, signature) → bool
    """

    VK_SIZE = 1952   # Verification key (public) size
    SK_SIZE = 4032   # Signing key (private) size
    SIG_SIZE = 3309  # Signature size

    @classmethod
    def _sync_profile(cls, profile: SecurityProfile) -> None:
        """Sync class-level sizes with the active security profile."""
        cls.VK_SIZE = profile.dsa_vk_size
        cls.SK_SIZE = profile.dsa_sk_size
        cls.SIG_SIZE = profile.dsa_sig_size

    @classmethod
    def _is_level5(cls) -> bool:
        return cls.VK_SIZE == _REAL_DSA5_VK

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-DSA keypair (65 or 87 depending on profile).

        Returns: (verification_key, signing_key)
        """
        if cls._is_level5():
            vk, sk = _dsa5_keygen()
        else:
            vk, sk = _dsa_keygen()
        if len(vk) != cls.VK_SIZE:
            raise RuntimeError(f"ML-DSA vk size mismatch: {len(vk)} != {cls.VK_SIZE}")
        if len(sk) != cls.SK_SIZE:
            raise RuntimeError(f"ML-DSA sk size mismatch: {len(sk)} != {cls.SK_SIZE}")
        return vk, sk

    @classmethod
    def sign(cls, sk: bytes, message: bytes) -> bytes:
        """
        Sign a message with sk.

        Returns: signature (size depends on active profile)
        """
        if len(sk) != cls.SK_SIZE:
            raise ValueError(f"Invalid sk size: {len(sk)} (expected {cls.SK_SIZE})")

        if cls._is_level5():
            sig = _dsa5_sign(sk, message)
        else:
            sig = _dsa_sign(sk, message)
        if len(sig) != cls.SIG_SIZE:
            raise RuntimeError(f"ML-DSA sig size mismatch: {len(sig)} != {cls.SIG_SIZE}")
        return sig

    @classmethod
    def verify(cls, vk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against vk and message.

        Returns: True if valid, False if forgery/tamper detected.
        """
        if len(vk) != cls.VK_SIZE:
            raise ValueError(f"Invalid vk size: {len(vk)} (expected {cls.VK_SIZE})")
        if len(signature) != cls.SIG_SIZE:
            return False

        if cls._is_level5():
            return bool(_dsa5_verify(vk, message, signature))
        return bool(_dsa_verify(vk, message, signature))

    @classmethod
    def reset_poc_state(cls) -> None:
        """No-op — kept for backward compatibility with pre-production tests."""
