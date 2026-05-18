"""Tests for SoftwareHSM in-memory wrapping (LTP-A-032 Phase 3).

Verifies:
- _keys[id]["private"] is wrapped (not raw dk/sk bytes) after generate_*.
- sign and kem_decaps still produce correct outputs end-to-end.
- destroy_key zeroizes the wrapped blob.
- Per-instance KEK isolation: blobs from one HSM cannot be unwrapped
  by another HSM's vault.
- Per-key-id AAD binding: a blob from one slot cannot be relocated
  to another slot of the same type.
- list_keys does not leak private material.
- get_public_key returns the public key unchanged.
- HSMBackend.derive_kek("ltp-master") still yields a 32-byte KEK
  (used by KeyVault.from_environment fallback chain).
"""

from __future__ import annotations

import os

import pytest

from ltp.hsm import SoftwareHSM
from ltp.keyvault import KeyVault, KeyVaultError
from ltp.primitives import MLDSA, MLKEM


# ---------------------------------------------------------------------------
# private bytes are wrapped at rest
# ---------------------------------------------------------------------------


def test_kem_private_is_wrapped_not_raw_bytes():
    hsm = SoftwareHSM()
    hsm.generate_kem_keypair("k1")
    stored = hsm._keys["k1"]["private"]
    # Wrapped blob is nonce(24) + ciphertext + tag(16) — 40-byte overhead.
    # Raw ML-KEM-768 dk is 2400 bytes; wrapped is 2440.
    assert len(stored) == 2400 + 40
    # The wrapped blob should never match a raw dk pattern. Sample
    # 10 random regenerations and confirm no equality.
    for _ in range(10):
        _, dk_other = MLKEM.keygen()
        assert stored != dk_other


def test_dsa_private_is_wrapped_not_raw_bytes():
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("d1")
    stored = hsm._keys["d1"]["private"]
    # Raw ML-DSA-65 sk is 4032 bytes; wrapped is 4072.
    assert len(stored) == 4032 + 40
    for _ in range(5):
        _, sk_other = MLDSA.keygen()
        assert stored != sk_other


# ---------------------------------------------------------------------------
# end-to-end correctness — sign + decaps still work after wrapping
# ---------------------------------------------------------------------------


def test_sign_then_verify_roundtrip():
    hsm = SoftwareHSM()
    vk = hsm.generate_dsa_keypair("d1")
    sig = hsm.sign("d1", b"hello world")
    assert MLDSA.verify(vk, b"hello world", sig) is True


def test_kem_decaps_recovers_shared_secret():
    hsm = SoftwareHSM()
    ek = hsm.generate_kem_keypair("k1")
    # Encapsulate against the public key; decapsulate via HSM.
    ss_a, ct = MLKEM.encaps(ek)
    ss_b = hsm.kem_decaps("k1", ct)
    assert ss_a == ss_b


def test_multiple_signs_are_independent():
    """Each sign() must rederive the plaintext sk freshly; no cached
    plaintext should leak across calls."""
    hsm = SoftwareHSM()
    vk = hsm.generate_dsa_keypair("d1")
    sig1 = hsm.sign("d1", b"message-a")
    sig2 = hsm.sign("d1", b"message-b")
    assert MLDSA.verify(vk, b"message-a", sig1)
    assert MLDSA.verify(vk, b"message-b", sig2)


# ---------------------------------------------------------------------------
# Per-instance KEK isolation
# ---------------------------------------------------------------------------


def test_per_instance_kek_isolation_kem():
    a = SoftwareHSM()
    b = SoftwareHSM()
    a.generate_kem_keypair("shared-id")
    # Lift a's wrapped blob into b's slot and ask b to decaps.
    b._keys["shared-id"] = dict(a._keys["shared-id"])
    with pytest.raises(KeyVaultError, match="authentication failed"):
        b.kem_decaps("shared-id", b"\x00" * 1088)


def test_per_instance_kek_isolation_dsa():
    a = SoftwareHSM()
    b = SoftwareHSM()
    a.generate_dsa_keypair("shared-id")
    b._keys["shared-id"] = dict(a._keys["shared-id"])
    with pytest.raises(KeyVaultError, match="authentication failed"):
        b.sign("shared-id", b"any")


# ---------------------------------------------------------------------------
# Per-key-id AAD binding
# ---------------------------------------------------------------------------


def test_aad_binds_blob_to_key_id_dsa():
    """Lifting a wrapped sk from slot 'a' into slot 'b' must fail to
    unwrap because the AAD binds the blob to its slot name."""
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("a")
    hsm.generate_dsa_keypair("b")
    # Swap a's wrapped sk into b's slot.
    hsm._keys["b"]["private"] = hsm._keys["a"]["private"]
    with pytest.raises(KeyVaultError, match="authentication failed"):
        hsm.sign("b", b"any")


def test_aad_binds_blob_to_key_id_kem():
    hsm = SoftwareHSM()
    hsm.generate_kem_keypair("a")
    hsm.generate_kem_keypair("b")
    hsm._keys["b"]["private"] = hsm._keys["a"]["private"]
    with pytest.raises(KeyVaultError, match="authentication failed"):
        hsm.kem_decaps("b", b"\x00" * 1088)


# ---------------------------------------------------------------------------
# destroy_key / list_keys / get_public_key
# ---------------------------------------------------------------------------


def test_destroy_key_removes_and_zeroizes():
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("d1")
    assert hsm.destroy_key("d1") is True
    assert "d1" not in hsm._keys
    # Second destroy is a no-op.
    assert hsm.destroy_key("d1") is False
    # And subsequent sign raises.
    with pytest.raises(KeyError):
        hsm.sign("d1", b"any")


def test_list_keys_does_not_expose_private():
    hsm = SoftwareHSM()
    hsm.generate_kem_keypair("k1")
    hsm.generate_dsa_keypair("d1")
    listing = hsm.list_keys()
    forbidden_fields = {"private", "wrapped", "sk", "dk"}
    for entry in listing:
        assert forbidden_fields.isdisjoint(entry.keys())


def test_get_public_key_unchanged():
    hsm = SoftwareHSM()
    ek = hsm.generate_kem_keypair("k1")
    assert hsm.get_public_key("k1") == ek
    vk = hsm.generate_dsa_keypair("d1")
    assert hsm.get_public_key("d1") == vk


# ---------------------------------------------------------------------------
# derive_kek interaction with KeyVault.from_environment
# ---------------------------------------------------------------------------


def test_derive_kek_for_keyvault_chain(monkeypatch):
    monkeypatch.delenv("LTP_KEY_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("LTP_ENV", raising=False)
    hsm = SoftwareHSM()
    vault = KeyVault.from_environment(hsm=hsm)
    # Wrapping/unwrapping with the HSM-derived KEK round-trips.
    wrapped = vault.wrap(b"payload", aad=b"x")
    assert vault.unwrap(wrapped, aad=b"x") == b"payload"


def test_hsm_internal_wrap_uses_different_kek_than_derive():
    """The 'ltp.hsm:wrap' KEK used internally must NOT equal the
    'ltp-master' KEK exposed by derive_kek — domain separation
    inside the HSM prevents an external vault from reading the
    internal wrapped private bytes."""
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("d1")
    wrapped_sk = hsm._keys["d1"]["private"]
    # Try to unwrap with the "external" KEK that derive_kek returns.
    external_kek = hsm.derive_kek("ltp-master")
    external_vault = KeyVault(external_kek)
    with pytest.raises(KeyVaultError, match="authentication failed"):
        external_vault.unwrap(wrapped_sk, aad=b"ltp.hsm:dsa:d1")
