"""Tests for ltp.keyvault — at-rest key material wrapping (LTP-A-032).

Verifies:
- Direct construction validates KEK size.
- wrap/unwrap roundtrip under various plaintext sizes and AAD.
- Tamper detection raises KeyVaultError.
- Wrong KEK fails to unwrap.
- AAD mismatch fails to unwrap.
- Each wrap produces a fresh nonce (probabilistic — large bytes count).
- Environment-variable KEK source resolves.
- HSM-derived KEK source resolves via SoftwareHSM.derive_kek.
- Production mode with no KEK source fails closed.
- Non-production mode with no KEK source warns and uses an ephemeral KEK.
- zeroize clears a bytearray in place.
"""

from __future__ import annotations

import base64
import logging
import os

import pytest

from ltp.hsm import SoftwareHSM
from ltp.keyvault import KeyVault, KeyVaultError, _derive_kek_from_seed


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with no KEK env var and a non-production LTP_ENV."""
    monkeypatch.delenv("LTP_KEY_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("LTP_ENV", raising=False)


def _kek_b64(seed: bytes = b"\x42" * 32) -> str:
    return base64.b64encode(seed).decode("ascii")


# ---------------------------------------------------------------------------
# Direct construction
# ---------------------------------------------------------------------------


def test_direct_construction_requires_32_bytes():
    KeyVault(b"\x01" * 32)  # ok
    with pytest.raises(ValueError, match="32 bytes"):
        KeyVault(b"\x01" * 16)
    with pytest.raises(ValueError, match="32 bytes"):
        KeyVault(b"")


def test_direct_construction_rejects_non_bytes():
    with pytest.raises(TypeError):
        KeyVault("not bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# wrap / unwrap roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"a",
        b"ML-DSA-65 sk would be ~4032 bytes; test something representative",
        os.urandom(32),
        os.urandom(2400),  # ML-KEM-768 dk size
        os.urandom(4032),  # ML-DSA-65 sk size
    ],
)
def test_wrap_unwrap_roundtrip(plaintext):
    vault = KeyVault(os.urandom(32))
    wrapped = vault.wrap(plaintext)
    assert vault.unwrap(wrapped) == plaintext


def test_wrap_unwrap_with_aad():
    vault = KeyVault(os.urandom(32))
    plaintext = b"secret-key-bytes"
    aad = b"log_operator"
    wrapped = vault.wrap(plaintext, aad=aad)
    assert vault.unwrap(wrapped, aad=aad) == plaintext


def test_wrap_unwrap_aad_mismatch_fails():
    vault = KeyVault(os.urandom(32))
    wrapped = vault.wrap(b"secret", aad=b"domain-a")
    with pytest.raises(KeyVaultError, match="authentication failed"):
        vault.unwrap(wrapped, aad=b"domain-b")


def test_wrap_produces_fresh_nonce_per_call():
    vault = KeyVault(os.urandom(32))
    plaintext = b"identical input"
    w1 = vault.wrap(plaintext)
    w2 = vault.wrap(plaintext)
    assert w1 != w2  # different nonces
    assert vault.unwrap(w1) == plaintext
    assert vault.unwrap(w2) == plaintext


def test_wrapped_blob_is_longer_than_plaintext():
    """nonce(24) + tag(16) = 40 byte overhead."""
    vault = KeyVault(os.urandom(32))
    plaintext = b"x" * 100
    wrapped = vault.wrap(plaintext)
    assert len(wrapped) == len(plaintext) + 40


# ---------------------------------------------------------------------------
# Tamper / wrong-key detection
# ---------------------------------------------------------------------------


def test_tampered_ciphertext_fails():
    vault = KeyVault(os.urandom(32))
    wrapped = bytearray(vault.wrap(b"secret"))
    wrapped[30] ^= 0xFF  # flip a bit in the ciphertext region
    with pytest.raises(KeyVaultError, match="authentication failed"):
        vault.unwrap(bytes(wrapped))


def test_tampered_nonce_fails():
    vault = KeyVault(os.urandom(32))
    wrapped = bytearray(vault.wrap(b"secret"))
    wrapped[0] ^= 0xFF  # flip a bit in the nonce
    with pytest.raises(KeyVaultError, match="authentication failed"):
        vault.unwrap(bytes(wrapped))


def test_wrong_kek_fails():
    v1 = KeyVault(b"\x01" * 32)
    v2 = KeyVault(b"\x02" * 32)
    wrapped = v1.wrap(b"secret")
    with pytest.raises(KeyVaultError, match="authentication failed"):
        v2.unwrap(wrapped)


def test_truncated_blob_fails():
    vault = KeyVault(os.urandom(32))
    with pytest.raises(KeyVaultError, match="too short"):
        vault.unwrap(b"x" * 10)


# ---------------------------------------------------------------------------
# from_environment — KEK source chain
# ---------------------------------------------------------------------------


def test_from_environment_uses_env_var(monkeypatch):
    raw = b"\x10" * 32
    monkeypatch.setenv("LTP_KEY_ENCRYPTION_KEY", base64.b64encode(raw).decode())
    vault = KeyVault.from_environment()
    # Round-trip with the same raw KEK to confirm vault holds the right one.
    direct = KeyVault(raw)
    wrapped = direct.wrap(b"check")
    assert vault.unwrap(wrapped) == b"check"


def test_from_environment_rejects_bad_base64(monkeypatch):
    monkeypatch.setenv("LTP_KEY_ENCRYPTION_KEY", "not-valid-base64!!!")
    with pytest.raises(KeyVaultError, match="not valid base64"):
        KeyVault.from_environment()


def test_from_environment_rejects_wrong_length(monkeypatch):
    monkeypatch.setenv(
        "LTP_KEY_ENCRYPTION_KEY", base64.b64encode(b"too short").decode()
    )
    with pytest.raises(KeyVaultError, match="must decode to 32 bytes"):
        KeyVault.from_environment()


def test_from_environment_uses_hsm_when_env_absent():
    hsm = SoftwareHSM()
    vault = KeyVault.from_environment(hsm=hsm)
    # Deterministic: same HSM seed → same KEK → cross-vault unwrap works.
    expected_kek = hsm.derive_kek("ltp-master")
    direct = KeyVault(expected_kek)
    wrapped = direct.wrap(b"hsm-derived")
    assert vault.unwrap(wrapped) == b"hsm-derived"


def test_from_environment_production_no_source_fails(monkeypatch):
    monkeypatch.setenv("LTP_ENV", "production")
    with pytest.raises(KeyVaultError, match="no KEK source resolved"):
        KeyVault.from_environment()


def test_from_environment_dev_no_source_warns_and_returns_ephemeral(
    monkeypatch, caplog
):
    monkeypatch.setenv("LTP_ENV", "development")
    with caplog.at_level(logging.WARNING):
        vault = KeyVault.from_environment()
    assert any(
        "no KEK source resolved" in rec.message for rec in caplog.records
    )
    # Ephemeral KEK still works for wrap/unwrap within process lifetime.
    wrapped = vault.wrap(b"dev")
    assert vault.unwrap(wrapped) == b"dev"


def test_env_var_takes_precedence_over_hsm(monkeypatch):
    raw = b"\x33" * 32
    monkeypatch.setenv("LTP_KEY_ENCRYPTION_KEY", base64.b64encode(raw).decode())
    hsm = SoftwareHSM()
    vault = KeyVault.from_environment(hsm=hsm)
    # vault should hold the env-var KEK, not the HSM-derived one.
    direct_env = KeyVault(raw)
    wrapped = direct_env.wrap(b"env-wins")
    assert vault.unwrap(wrapped) == b"env-wins"


# ---------------------------------------------------------------------------
# SoftwareHSM.derive_kek
# ---------------------------------------------------------------------------


def test_software_hsm_derive_kek_is_deterministic():
    hsm = SoftwareHSM()
    k1 = hsm.derive_kek("ltp-master")
    k2 = hsm.derive_kek("ltp-master")
    assert k1 == k2
    assert len(k1) == 32


def test_software_hsm_derive_kek_label_isolation():
    hsm = SoftwareHSM()
    assert hsm.derive_kek("a") != hsm.derive_kek("b")


def test_software_hsm_derive_kek_per_instance_isolation():
    a = SoftwareHSM()
    b = SoftwareHSM()
    assert a.derive_kek("ltp-master") != b.derive_kek("ltp-master")


def test_derive_kek_from_seed_rejects_empty_label():
    with pytest.raises(ValueError):
        _derive_kek_from_seed(b"\x00" * 32, "")


# ---------------------------------------------------------------------------
# zeroize
# ---------------------------------------------------------------------------


def test_zeroize_clears_bytearray():
    buf = bytearray(b"\xaa" * 32)
    KeyVault.zeroize(buf)
    assert bytes(buf) == b"\x00" * 32


def test_zeroize_skips_bytes_no_crash():
    # Immutable bytes can't be cleared; should not raise.
    KeyVault.zeroize(b"immutable")
    KeyVault.zeroize(None)  # type: ignore[arg-type]


def test_zeroize_multiple_buffers():
    a = bytearray(b"\x01\x02\x03")
    b = bytearray(b"\xff\xff")
    KeyVault.zeroize(a, b)
    assert bytes(a) == b"\x00\x00\x00"
    assert bytes(b) == b"\x00\x00"
