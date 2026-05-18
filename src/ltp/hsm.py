"""
Hardware Security Module (HSM) interface for the Lattice Transfer Protocol.

Provides:
  - HSMBackend    — abstract interface for key storage and crypto operations
  - SoftwareHSM   — in-memory software implementation (PoC / development)

Production: Replace SoftwareHSM with PKCS#11 adapter for FIPS 140-3 Level 3
hardware modules (AWS KMS, Thales Luna, Entrust nShield 5s).

The HSM interface isolates key material from the protocol layer. Private keys
(dk, sk) never leave the HSM boundary in plaintext; operations (sign, decaps)
are performed inside the HSM and only results are returned.

Standards alignment:
  - FIPS 140-3 Level 3: tamper-resistant, identity-based auth, encrypted export
  - NIST SP 800-57: key lifecycle (generation, use, destruction)
  - PCI DSS 4.0 Req 3: key separation, dual control
  - HIPAA: keys stored separately from encrypted data
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional

from .primitives import canonical_hash, MLKEM, MLDSA

__all__ = ["HSMBackend", "SoftwareHSM"]


class HSMBackend(ABC):
    """
    Abstract HSM interface for regulated key management.

    All private key operations are performed through this interface.
    The protocol layer never directly touches dk or sk bytes.

    Implementations:
      - SoftwareHSM: In-memory (PoC/development)
      - PKCS11HSM:   Hardware via PKCS#11 (production, not yet implemented)
      - CloudHSM:    AWS KMS / Azure Key Vault (production, not yet implemented)
    """

    @abstractmethod
    def generate_kem_keypair(self, key_id: str) -> bytes:
        """
        Generate ML-KEM keypair inside HSM. Returns encapsulation key (public).

        The decapsulation key (private) is stored internally, referenced by key_id.
        The dk NEVER leaves the HSM in plaintext.
        """
        ...

    @abstractmethod
    def generate_dsa_keypair(self, key_id: str) -> bytes:
        """
        Generate ML-DSA keypair inside HSM. Returns verification key (public).

        The signing key (private) is stored internally, referenced by key_id.
        The sk NEVER leaves the HSM in plaintext.
        """
        ...

    @abstractmethod
    def sign(self, key_id: str, message: bytes) -> bytes:
        """Sign message using the DSA signing key identified by key_id."""
        ...

    @abstractmethod
    def kem_decaps(self, key_id: str, kem_ciphertext: bytes) -> bytes:
        """
        Decapsulate using the KEM decapsulation key identified by key_id.

        Returns the shared secret. The dk never leaves the HSM.
        """
        ...

    @abstractmethod
    def destroy_key(self, key_id: str) -> bool:
        """
        Securely destroy a key from the HSM (zeroize).

        Returns True if key was found and destroyed, False if not found.
        Implements NIST SP 800-57 key destruction requirements.
        """
        ...

    @abstractmethod
    def has_key(self, key_id: str) -> bool:
        """Check if a key exists in the HSM."""
        ...

    @abstractmethod
    def list_keys(self) -> list[dict]:
        """
        List all keys in the HSM with metadata.

        Returns list of dicts with at minimum: {"key_id", "type", "algorithm"}.
        """
        ...

    @abstractmethod
    def derive_kek(self, label: str) -> bytes:
        """
        Derive a 32-byte Key Encryption Key (KEK) from a stable HSM secret.

        Used by `ltp.keyvault.KeyVault` to obtain a wrapping key when no
        env var or OS keychain entry resolves. Real HSMs derive KEKs in
        hardware (e.g., PKCS#11 C_DeriveKey + HKDF inside the module).
        """
        ...


class SoftwareHSM(HSMBackend):
    """
    Software-based HSM implementation for PoC and development.

    Stores keys in memory. NOT suitable for production regulated environments.
    Implements the full HSMBackend interface for testing and development.

    Production: Replace with PKCS11HSM wrapping a FIPS 140-3 Level 3 module.
    """

    def __init__(self) -> None:
        # LTP-A-004: refuse instantiation when LTP_ENV signals a production
        # deployment AND the operator explicitly asked for the software
        # backend. The PoC keystore is fine for dev/CI but lacks the
        # constant-time and tamper-resistance guarantees expected in prod.
        import os as _os
        env = _os.environ.get("LTP_ENV", "").lower()
        provider = _os.environ.get("ETP_HSM_PROVIDER", "").lower()
        if env == "production" and provider == "software":
            raise RuntimeError(
                "SoftwareHSM cannot be used in production "
                "(LTP_ENV=production + ETP_HSM_PROVIDER=software). "
                "Configure a PKCS#11 HSM or cloud KMS backend; see "
                "docs/compliance/fedramp-high/trust-boundary.md."
            )
        # key_id → {"type": "kem"|"dsa", "public": bytes, "private": bytes}
        self._keys: dict[str, dict] = {}
        # Per-instance secret seed for derive_kek(). Random per process;
        # production deployments override this by configuring a real HSM
        # whose KEK derivation happens in hardware.
        self._kek_seed: bytes = os.urandom(32)

    def generate_kem_keypair(self, key_id: str) -> bytes:
        """Generate ML-KEM keypair, store privately, return public ek."""
        if key_id in self._keys:
            raise ValueError(f"Key ID '{key_id}' already exists in HSM")
        ek, dk = MLKEM.keygen()
        self._keys[key_id] = {
            "type": "kem",
            "algorithm": f"ML-KEM-{get_security_profile().level * 256 + 256}",
            "public": ek,
            "private": dk,
        }
        return ek

    def generate_dsa_keypair(self, key_id: str) -> bytes:
        """Generate ML-DSA keypair, store privately, return public vk."""
        if key_id in self._keys:
            raise ValueError(f"Key ID '{key_id}' already exists in HSM")
        vk, sk = MLDSA.keygen()
        self._keys[key_id] = {
            "type": "dsa",
            "algorithm": f"ML-DSA-{get_security_profile().level * 22 + 21}",
            "public": vk,
            "private": sk,
        }
        return vk

    def sign(self, key_id: str, message: bytes) -> bytes:
        """Sign using stored DSA key."""
        entry = self._keys.get(key_id)
        if entry is None:
            raise KeyError(f"Key ID '{key_id}' not found in HSM")
        if entry["type"] != "dsa":
            raise TypeError(f"Key '{key_id}' is type '{entry['type']}', not 'dsa'")
        return MLDSA.sign(entry["private"], message)

    def kem_decaps(self, key_id: str, kem_ciphertext: bytes) -> bytes:
        """Decapsulate using stored KEM key."""
        entry = self._keys.get(key_id)
        if entry is None:
            raise KeyError(f"Key ID '{key_id}' not found in HSM")
        if entry["type"] != "kem":
            raise TypeError(f"Key '{key_id}' is type '{entry['type']}', not 'kem'")
        return MLKEM.decaps(entry["private"], kem_ciphertext)

    def destroy_key(self, key_id: str) -> bool:
        """Zeroize and remove key from memory."""
        entry = self._keys.pop(key_id, None)
        if entry is None:
            return False
        # Zeroize private key material (best-effort in Python)
        if "private" in entry:
            priv = bytearray(entry["private"])
            for i in range(len(priv)):
                priv[i] = 0
            entry["private"] = bytes(priv)
        return True

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def list_keys(self) -> list[dict]:
        return [
            {
                "key_id": kid,
                "type": info["type"],
                "algorithm": info["algorithm"],
                "public_size": len(info["public"]),
            }
            for kid, info in self._keys.items()
        ]

    def derive_kek(self, label: str) -> bytes:
        """Derive a 32-byte KEK from the per-instance seed.

        HMAC-SHA3-256(seed, label). Software-only — production HSMs
        derive in hardware. Used by `ltp.keyvault.KeyVault.from_environment`
        when no env var or OS keychain entry resolves and the caller
        passed this HSM as the fallback source.
        """
        from .keyvault import _derive_kek_from_seed
        return _derive_kek_from_seed(self._kek_seed, label)

    def get_public_key(self, key_id: str) -> bytes:
        """Get the public component of a stored key."""
        entry = self._keys.get(key_id)
        if entry is None:
            raise KeyError(f"Key ID '{key_id}' not found in HSM")
        return entry["public"]

    def generate_keypair(self, label: str) -> dict:
        """Generate both KEM and DSA keypairs. Returns key metadata.

        This is a convenience method for KeyPair.generate(hsm=...).
        Private keys stay inside the HSM; only public material is returned.
        """
        kem_id = f"{label}-kem"
        dsa_id = f"{label}-dsa"
        ek = self.generate_kem_keypair(kem_id)
        vk = self.generate_dsa_keypair(dsa_id)
        return {
            "key_id": label,
            "kem_key_id": kem_id,
            "dsa_key_id": dsa_id,
            "ek": ek,
            "vk": vk,
        }


# Import here to avoid circular dependency at module level
def get_security_profile():
    from .primitives import get_security_profile as _gsp
    return _gsp()
