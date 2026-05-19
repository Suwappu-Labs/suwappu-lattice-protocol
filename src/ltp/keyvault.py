"""
KeyVault — AEAD wrapper for at-rest and in-memory key material.

Closes the at-rest / in-memory plaintext exposure for sensitive key
bytes (ML-DSA-65 sk, ML-KEM dk, future persistence) by wrapping every
sensitive byte string with XChaCha20-Poly1305 under a Key Encryption
Key (KEK). The KEK itself is sourced from one of three places (first
match wins):

  1. Environment variable LTP_KEY_ENCRYPTION_KEY (base64 32-byte key).
  2. OS keychain via the `keyring` library (entry: service="ltp",
     username="kek").
  3. HSM-derived via HSMBackend.derive_kek("ltp-master").

If none of the above resolve and LTP_ENV=production, KeyVault refuses
to start. In non-production environments the missing-source path
generates an ephemeral process-local KEK with a logged warning —
useful for tests and dev but with the obvious caveat that wrapped
material is lost on restart.

Tracked finding: LTP-A-032 (HIGH) — Key material at rest in SQLite
(`CommitmentLogStore.store_operator_keypair`) and in SoftwareHSM
(`SoftwareHSM._keys[...]["private"]`) was stored unencrypted before
this module landed.

This module reuses the existing AEAD wrapper from `ltp.primitives`
(XChaCha20-Poly1305 via pynacl) — no new primitive is introduced.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from typing import TYPE_CHECKING, Optional

from .primitives import AEAD

if TYPE_CHECKING:
    from .hsm import HSMBackend

__all__ = ["KeyVault", "KeyVaultError"]

_LOG = logging.getLogger(__name__)

_ENV_VAR = "LTP_KEY_ENCRYPTION_KEY"
_KEYRING_SERVICE = "ltp"
_KEYRING_USERNAME = "kek"
_HSM_LABEL = "ltp-master"


class KeyVaultError(RuntimeError):
    """Raised when KeyVault cannot resolve a KEK or unwrap fails."""


class KeyVault:
    """AEAD wrapper for sensitive key bytes.

    Construct via `KeyVault.from_environment()` in normal use. Direct
    construction with a raw KEK is provided for tests and migrations.
    """

    KEK_SIZE = 32
    NONCE_SIZE = AEAD.NONCE_SIZE  # 24
    TAG_SIZE = AEAD.TAG_SIZE  # 16

    def __init__(self, kek: bytes) -> None:
        if not isinstance(kek, (bytes, bytearray)):
            raise TypeError("KEK must be bytes")
        if len(kek) != self.KEK_SIZE:
            raise ValueError(f"KEK must be {self.KEK_SIZE} bytes, got {len(kek)}")
        self._kek = bytes(kek)

    @classmethod
    def from_environment(
        cls,
        hsm: Optional["HSMBackend"] = None,
    ) -> "KeyVault":
        """Resolve a KEK from env / keychain / HSM. Fail-closed in prod."""
        # 1. Environment variable. If the variable is *set but empty*
        # we refuse to silently fall through to keychain/HSM — an empty
        # secret-injection is almost certainly a misconfiguration that
        # would otherwise switch the active KEK source and break
        # previously-wrapped material (Codex P2).
        if _ENV_VAR in os.environ:
            env_kek = os.environ[_ENV_VAR]
            if not env_kek:
                raise KeyVaultError(
                    f"{_ENV_VAR} is set but empty — refusing to fall back "
                    "to keychain/HSM. Either unset the variable or "
                    "provide a base64 32-byte KEK."
                )
            try:
                kek = base64.b64decode(env_kek, validate=True)
            except Exception as exc:
                raise KeyVaultError(f"{_ENV_VAR} is not valid base64") from exc
            if len(kek) != cls.KEK_SIZE:
                raise KeyVaultError(
                    f"{_ENV_VAR} must decode to {cls.KEK_SIZE} bytes, got {len(kek)}"
                )
            return cls(kek)

        # 2. OS keychain. `keyring` raises a variety of runtime errors
        # when no backend is configured or the backend is unavailable;
        # catch broadly so we fall through to HSM / fail-closed / dev
        # ephemeral path instead of crashing init (Codex P1).
        try:
            import keyring  # type: ignore[import-not-found]

            try:
                kek_b64 = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
            except Exception as exc:  # noqa: BLE001 — keyring backends raise many types
                _LOG.warning(
                    "KeyVault: OS keychain lookup failed (%s); falling through to next KEK source.",
                    exc,
                )
                kek_b64 = None
            if kek_b64:
                try:
                    kek = base64.b64decode(kek_b64, validate=True)
                except Exception as exc:
                    raise KeyVaultError("OS keychain KEK is not valid base64") from exc
                if len(kek) != cls.KEK_SIZE:
                    raise KeyVaultError(
                        f"OS keychain KEK must decode to {cls.KEK_SIZE} bytes, got {len(kek)}"
                    )
                return cls(kek)
        except ImportError:
            pass

        if hsm is not None:
            kek = hsm.derive_kek(_HSM_LABEL)
            if len(kek) != cls.KEK_SIZE:
                raise KeyVaultError(
                    f"HSM derive_kek returned {len(kek)} bytes, expected {cls.KEK_SIZE}"
                )
            return cls(kek)

        env = os.environ.get("LTP_ENV", "").lower()
        if env == "production":
            raise KeyVaultError(
                "KeyVault: no KEK source resolved in production "
                f"(set {_ENV_VAR}, configure OS keychain, or pass an HSM). "
                "See docs/OPERATOR_RUNBOOK.md §13."
            )

        _LOG.warning(
            "KeyVault: no KEK source resolved; using ephemeral dev-only "
            "KEK (wrapped material will not survive process restart). "
            "Set %s for stable wrapping.",
            _ENV_VAR,
        )
        return cls(os.urandom(cls.KEK_SIZE))

    def wrap(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Wrap plaintext → nonce(24) || ciphertext || tag(16).

        AAD is authenticated but not encrypted. Callers should pass a
        domain separator (e.g. b"log_operator", b"hsm:" + key_id) so
        wrapped bytes from one site cannot be unwrapped at another.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = AEAD.encrypt(self._kek, bytes(plaintext), nonce, aad)
        return nonce + ciphertext

    def unwrap(self, wrapped: bytes, aad: bytes = b"") -> bytes:
        """Inverse of wrap. Raises KeyVaultError on tag failure."""
        if not isinstance(wrapped, (bytes, bytearray)):
            raise TypeError("wrapped must be bytes")
        if len(wrapped) < self.NONCE_SIZE + self.TAG_SIZE:
            raise KeyVaultError(
                f"wrapped blob too short: {len(wrapped)} < {self.NONCE_SIZE + self.TAG_SIZE}"
            )
        nonce = bytes(wrapped[: self.NONCE_SIZE])
        ciphertext = bytes(wrapped[self.NONCE_SIZE :])
        try:
            return AEAD.decrypt(self._kek, ciphertext, nonce, aad)
        except ValueError as exc:
            raise KeyVaultError(
                "KeyVault.unwrap: AEAD authentication failed "
                "(wrong KEK, wrong AAD, or tampered blob)"
            ) from exc

    @staticmethod
    def zeroize(*buffers: object) -> None:
        """Best-effort in-place zero of bytearray buffers.

        Python provides no guarantee that immutable `bytes` objects can
        be cleared; callers that care should hold key material in
        `bytearray` and pass it here. Mirrors the best-effort pattern
        at `keypair.py:340-345` and `hsm.py:182-188`.
        """
        for buf in buffers:
            if isinstance(buf, bytearray):
                for i in range(len(buf)):
                    buf[i] = 0


def _derive_kek_from_seed(seed: bytes, label: str) -> bytes:
    """HMAC-SHA3-256 KDF for SoftwareHSM.derive_kek.

    Exposed at module scope so SoftwareHSM can call it without a
    circular import. Real HSMs derive KEKs in hardware.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty str")
    return hmac.new(bytes(seed), label.encode("utf-8"), hashlib.sha3_256).digest()
