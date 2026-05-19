"""
SecurityProfile: configurable NIST security levels with dual-lane hash support.

Dual-lane model:
  - canonical_hash: algorithm for settlement-valid, compliance-facing artifacts
  - internal_hash:  algorithm for performance-optimized internal operations
"""

from __future__ import annotations

from typing import Optional

from .hashing import HashFunction


class SecurityProfile:
    """
    Configurable security parameter set for LTP.

    Dual-lane model:
      - canonical_hash: algorithm for settlement-valid, compliance-facing artifacts
      - internal_hash:  algorithm for performance-optimized internal operations

    Level 3 (default): ML-KEM-768 + ML-DSA-65 — NIST Level 3 (~AES-192)
      Meets civilian federal, PCI DSS, SOC 2, HIPAA, FedRAMP, GDPR, eIDAS.

    Level 5: ML-KEM-1024 + ML-DSA-87 — NIST Level 5 (~AES-256)
      Required for CNSA 2.0 / NSS / DoD IL5+ by January 2027.

    Each profile specifies:
      - KEM parameters (ek, dk, ct, ss sizes)
      - DSA parameters (vk, sk, sig sizes)
      - Canonical hash function (compliance lane)
      - Internal hash function (performance lane)
      - Security level label
    """

    def __init__(
        self,
        level: int = 3,
        *,
        canonical_hash: Optional[HashFunction] = None,
        internal_hash: Optional[HashFunction] = None,
    ) -> None:
        if level not in (3, 5):
            raise ValueError(f"Security level must be 3 or 5, got {level}")

        self.level = level
        self._canonical_hash = canonical_hash or HashFunction.SHA3_256
        self._internal_hash = internal_hash or HashFunction.BLAKE3_256

        if level == 3:
            # ML-KEM-768 (FIPS 203)
            self.kem_ek_size = 1184
            self.kem_dk_size = 2400
            self.kem_ct_size = 1088
            self.kem_ss_size = 32
            # ML-DSA-65 (FIPS 204)
            self.dsa_vk_size = 1952
            self.dsa_sk_size = 4032
            self.dsa_sig_size = 3309
        else:  # level == 5
            # ML-KEM-1024 (FIPS 203)
            self.kem_ek_size = 1568
            self.kem_dk_size = 3168
            self.kem_ct_size = 1568
            self.kem_ss_size = 32
            # ML-DSA-87 (FIPS 204)
            self.dsa_vk_size = 2592
            self.dsa_sk_size = 4896
            self.dsa_sig_size = 4627

    @property
    def canonical_hash_fn(self) -> HashFunction:
        """Hash function for the canonical (compliance) lane."""
        return self._canonical_hash

    @property
    def internal_hash_fn(self) -> HashFunction:
        """Hash function for the internal (performance) lane."""
        return self._internal_hash

    @property
    def label(self) -> str:
        return f"Level-{self.level}/{self._canonical_hash.value}+{self._internal_hash.value}"

    def __repr__(self) -> str:
        return (
            f"SecurityProfile(level={self.level}, "
            f"canonical={self._canonical_hash.value}, "
            f"internal={self._internal_hash.value}, "
            f"kem_ek={self.kem_ek_size}B, dsa_vk={self.dsa_vk_size}B)"
        )

    # Convenience constructors
    @classmethod
    def level3(cls) -> "SecurityProfile":
        """NIST Level 3: ML-KEM-768 + ML-DSA-65 (civilian/commercial)."""
        return cls(level=3)

    @classmethod
    def level5(cls) -> "SecurityProfile":
        """NIST Level 5: ML-KEM-1024 + ML-DSA-87 (CNSA 2.0 / NSS)."""
        return cls(level=5, canonical_hash=HashFunction.SHA_384)

    @classmethod
    def cnsa2(cls):
        """CNSA 2.0 Suite: Level 5 + SHA-384 (NSA requirement by 2027)."""
        return cls(level=5, canonical_hash=HashFunction.SHA_384, internal_hash=HashFunction.SHA_384)

    @classmethod
    def defi(cls):
        """DeFi profile: SHA3-256 canonical + BLAKE3-256 internal."""
        return cls(
            level=3, canonical_hash=HashFunction.SHA3_256, internal_hash=HashFunction.BLAKE3_256
        )

    @classmethod
    def cefi(cls):
        """CeFi profile: SHA3-256 canonical + SHA3-256 internal (fully auditable)."""
        return cls(
            level=3, canonical_hash=HashFunction.SHA3_256, internal_hash=HashFunction.SHA3_256
        )
