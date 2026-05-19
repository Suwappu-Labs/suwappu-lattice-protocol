"""
AWS KMS Backend — envelope encryption for PQ key material.

AWS KMS does not natively support ML-DSA-65 or ML-KEM-768. This backend
uses KMS for envelope encryption: PQ key material is generated locally,
then the private key is encrypted using a KMS-managed master key
(GenerateDataKey / Decrypt pattern).

Security model:
  - Private key material (sk/dk) is always encrypted at rest via KMS
  - KMS master key is FIPS 140-3 Level 3 hardware-backed
  - Signing requires a KMS Decrypt call to unwrap the private key
  - Decrypted key material is zeroized after use

Requires: boto3 (pip install boto3)
"""

from __future__ import annotations

import logging
import threading
import time as _time
from typing import Optional

from .kms import KMSBackend

logger = logging.getLogger(__name__)

__all__ = ["AWSKMSBackend"]


class AWSKMSBackend(KMSBackend):
    """AWS KMS backend using envelope encryption for PQ key material.

    The KMS master key (key_arn) is used to encrypt/decrypt PQ private keys.
    Public keys are stored in plaintext (they are public by definition).

    Thread-safe via internal lock.
    """

    def __init__(
        self,
        key_arn: str,
        region: str = "us-east-1",
        endpoint_url: str = "",
        profile: str = "",
    ) -> None:
        """
        Args:
            key_arn: AWS KMS master key ARN for envelope encryption.
            region: AWS region name.
            endpoint_url: Custom endpoint (for moto/localstack testing).
            profile: AWS CLI profile name (optional).
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required for AWS KMS backend: pip install boto3")

        self._key_arn = key_arn
        self._region = region

        client_kwargs = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        if profile:
            session = boto3.Session(profile_name=profile)
            self._client = session.client("kms", **client_kwargs)
        else:
            self._client = boto3.client("kms", **client_kwargs)

        # Local key store: key_id → {public, encrypted_private, algorithm, created_at, state, versions}
        self._keys: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create_key(self, key_id: str, algorithm: str = "ML-DSA-65") -> bytes:
        """Create a PQ key, encrypt private material with KMS, return public key."""
        from ..primitives import MLDSA, MLKEM

        with self._lock:
            if key_id in self._keys:
                raise ValueError(f"Key {key_id!r} already exists")

            # Generate PQ keypair locally
            if algorithm == "ML-DSA-65":
                vk, sk = MLDSA.keygen()
                public_key = vk
                private_key = sk
            elif algorithm == "ML-KEM-768":
                ek, dk = MLKEM.keygen()
                public_key = ek
                private_key = dk
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            # Encrypt private key with KMS master key
            encrypted_private = self._encrypt_with_kms(private_key)

            # Zeroize plaintext private key
            private_key = b"\x00" * len(private_key)
            del private_key

            self._keys[key_id] = {
                "public": public_key,
                "encrypted_private": encrypted_private,
                "algorithm": algorithm,
                "created_at": _time.time(),
                "state": "active",
                "versions": [1],
            }
            logger.info("AWSKMSBackend: created key %s (%s)", key_id, algorithm)
            return public_key

    def get_public_key(self, key_id: str) -> bytes:
        """Return the public key (not encrypted — public by definition)."""
        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                raise KeyError(f"Key {key_id!r} not found")
            return entry["public"]

    def sign(self, key_id: str, message: bytes) -> bytes:
        """Decrypt private key via KMS, sign locally, zeroize decrypted key."""
        from ..primitives import MLDSA

        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                raise KeyError(f"Key {key_id!r} not found")
            if entry["algorithm"] != "ML-DSA-65":
                raise ValueError(
                    f"Key {key_id!r} is not a signing key (algorithm={entry['algorithm']})"
                )
            encrypted_private = entry["encrypted_private"]

        # Decrypt outside lock to avoid holding lock during KMS call
        sk = self._decrypt_with_kms(encrypted_private)
        try:
            signature = MLDSA.sign(sk, message)
        finally:
            # Zeroize decrypted key material
            sk = b"\x00" * len(sk)
            del sk

        return signature

    def destroy_key(self, key_id: str) -> bool:
        """Remove key material. Returns True if key existed."""
        with self._lock:
            if key_id in self._keys:
                # Overwrite encrypted material before deletion
                entry = self._keys[key_id]
                entry["encrypted_private"] = b"\x00" * len(entry.get("encrypted_private", b""))
                del self._keys[key_id]
                logger.info("AWSKMSBackend: destroyed key %s", key_id)
                return True
            return False

    def get_key_metadata(self, key_id: str) -> dict:
        """Return key metadata."""
        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                raise KeyError(f"Key {key_id!r} not found")
            return {
                "key_id": key_id,
                "algorithm": entry["algorithm"],
                "created_at": entry["created_at"],
                "state": entry["state"],
                "versions": list(entry["versions"]),
                "kms_key_arn": self._key_arn,
            }

    def list_keys(self, prefix: str = "") -> list[str]:
        """List key IDs, optionally filtered by prefix."""
        with self._lock:
            if not prefix:
                return list(self._keys.keys())
            return [k for k in self._keys if k.startswith(prefix)]

    def rotate_key(self, key_id: str) -> str:
        """Generate new key material, encrypt with KMS, increment version."""
        from ..primitives import MLDSA, MLKEM

        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                raise KeyError(f"Key {key_id!r} not found")

            new_version = max(entry["versions"]) + 1
            algorithm = entry["algorithm"]

        # Generate new keypair outside lock
        if algorithm == "ML-DSA-65":
            vk, sk = MLDSA.keygen()
            public_key = vk
            private_key = sk
        elif algorithm == "ML-KEM-768":
            ek, dk = MLKEM.keygen()
            public_key = ek
            private_key = dk
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        encrypted_private = self._encrypt_with_kms(private_key)
        private_key = b"\x00" * len(private_key)
        del private_key

        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                raise KeyError(f"Key {key_id!r} rotated but disappeared")
            # Detect concurrent rotation
            current_max = max(entry["versions"])
            if current_max >= new_version:
                raise RuntimeError(
                    f"Concurrent rotation detected on {key_id!r}: "
                    f"expected version {new_version} but {current_max} exists"
                )
            entry["public"] = public_key
            entry["encrypted_private"] = encrypted_private
            entry["versions"].append(new_version)

        version_id = f"{key_id}-v{new_version}"
        logger.info("AWSKMSBackend: rotated key %s → %s", key_id, version_id)
        return version_id

    # ------------------------------------------------------------------
    # KMS envelope encryption helpers
    # ------------------------------------------------------------------

    def _encrypt_with_kms(self, plaintext: bytes) -> bytes:
        """Encrypt data using the KMS master key."""
        try:
            response = self._client.encrypt(
                KeyId=self._key_arn,
                Plaintext=plaintext,
            )
            return response["CiphertextBlob"]
        except Exception as e:
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
            logger.error("KMS encrypt failed: %s (%s)", error_code, e)
            raise RuntimeError(f"KMS encrypt error: {error_code}") from e

    def _decrypt_with_kms(self, ciphertext: bytes) -> bytes:
        """Decrypt data using the KMS master key."""
        try:
            response = self._client.decrypt(
                KeyId=self._key_arn,
                CiphertextBlob=ciphertext,
            )
            return response["Plaintext"]
        except Exception as e:
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
            logger.error("KMS decrypt failed: %s (%s)", error_code, e)
            raise RuntimeError(f"KMS decrypt error: {error_code}") from e
