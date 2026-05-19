"""SCN-011 — Lazarus-tier sustained key compromise.

Red-team scenario verifying LTP's HSM-backed signing path is the
correct trust boundary for sustained adversarial pressure of the kind
the Lazarus Group (DPRK) has demonstrated across:

  - Ronin (Mar 2022, $625M, SCN-008)
  - Harmony (Jun 2022, $100M, SCN-009)
  - Atomic Wallet (Jun 2023, $100M)
  - DMM Bitcoin (May 2024, $305M)
  - WazirX (Jul 2024, $230M)

The common thread: a well-resourced attacker maintains operational
access to a signing environment over weeks or months. Defense is
not "make compromise impossible" — that's beyond any cryptographic
boundary — but **bound the blast radius**:

  - Private keys never leave the HSM in plaintext (L2).
  - Sign / decaps are gated on the operator generating the key
    inside the HSM first (L3, L4).
  - The software backend refuses to run in production at all
    (L1, LTP-A-004 fail-closed).
  - Compromised keys can be zeroized and the slot reused (L5).
  - Key-ID generation cannot silently overwrite an existing slot
    (L7), so an attacker with sign capability cannot stealth-rotate
    to a key they control while keeping the old key_id.

LTP-A-004 (single-custody operator signing key) is the audit
finding most directly addressed; LTP-A-013 (operator key format
validated at boot) is a related operational defense.

Maps to LTP-A-004 + LTP-A-013.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from ltp.hsm import HSMBackend, SoftwareHSM

# ---------------------------------------------------------------------------
# L1 — SoftwareHSM refuses production
# ---------------------------------------------------------------------------


def test_L1_software_hsm_refuses_production_when_explicitly_selected():
    """LTP_ENV=production + ETP_HSM_PROVIDER=software must fail-close."""
    with mock.patch.dict(
        os.environ,
        {"LTP_ENV": "production", "ETP_HSM_PROVIDER": "software"},
        clear=False,
    ):
        with pytest.raises(RuntimeError, match="production"):
            SoftwareHSM()


def test_L1_software_hsm_allowed_outside_production():
    """Dev / CI / staging environments may use SoftwareHSM."""
    for env in ["development", "dev", "ci", "staging", ""]:
        with mock.patch.dict(
            os.environ,
            {"LTP_ENV": env, "ETP_HSM_PROVIDER": "software"},
            clear=False,
        ):
            # Must not raise.
            hsm = SoftwareHSM()
            assert hsm is not None


def test_L1_software_hsm_allowed_production_with_different_provider():
    """LTP_ENV=production + ETP_HSM_PROVIDER=pkcs11 → SoftwareHSM
    may still be INSTANTIATED for test purposes; the production-
    refusal is specifically against the (production, software)
    combo. This documents the boundary."""
    with mock.patch.dict(
        os.environ,
        {"LTP_ENV": "production", "ETP_HSM_PROVIDER": "pkcs11"},
        clear=False,
    ):
        # Must not raise.
        hsm = SoftwareHSM()
        assert hsm is not None


# ---------------------------------------------------------------------------
# L2 — private keys never leave the HSM via the public interface
# ---------------------------------------------------------------------------


def test_L2_HSMBackend_abstract_interface_has_no_export_method():
    """The abstract HSMBackend defines: generate_kem_keypair,
    generate_dsa_keypair, sign, kem_decaps, destroy_key, has_key,
    list_keys, get_public_key, generate_keypair. None of these
    return private key material.
    """
    forbidden = {
        "export_private",
        "export_sk",
        "export_dk",
        "get_private_key",
        "raw_sk",
        "raw_dk",
        "dump_keys",
    }
    public_methods = {name for name in dir(HSMBackend) if not name.startswith("_")}
    assert public_methods.isdisjoint(forbidden), (
        f"HSMBackend leaks a private-key export method: {public_methods & forbidden}"
    )


# ---------------------------------------------------------------------------
# L3 — sign requires the key to exist
# ---------------------------------------------------------------------------


def test_L3_sign_unknown_key_id_raises():
    hsm = SoftwareHSM()
    with pytest.raises(KeyError, match="not found"):
        hsm.sign("nonexistent-key", b"any-message")


# ---------------------------------------------------------------------------
# L4 — sign requires the key TYPE to match
# ---------------------------------------------------------------------------


def test_L4_sign_with_kem_key_raises_typeerror():
    """Attacker tries to use the KEM dk as a signing key."""
    hsm = SoftwareHSM()
    hsm.generate_kem_keypair("kem-1")
    with pytest.raises(TypeError, match="not 'dsa'"):
        hsm.sign("kem-1", b"forged-message")


def test_L4_kem_decaps_with_dsa_key_raises_typeerror():
    """And the symmetric: trying to decapsulate with a DSA key."""
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("dsa-1")
    with pytest.raises(TypeError, match="not 'kem'"):
        hsm.kem_decaps("dsa-1", b"x" * 32)


# ---------------------------------------------------------------------------
# L5 — destroy_key zeroizes the private material
# ---------------------------------------------------------------------------


def test_L5_destroy_key_returns_true_then_false():
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("dsa-1")
    assert hsm.destroy_key("dsa-1") is True
    # Second call: key already removed → False.
    assert hsm.destroy_key("dsa-1") is False


def test_L5_destroyed_key_cannot_sign():
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("dsa-1")
    hsm.sign("dsa-1", b"pre-destroy-ok")  # works
    hsm.destroy_key("dsa-1")
    with pytest.raises(KeyError, match="not found"):
        hsm.sign("dsa-1", b"post-destroy-fails")


# ---------------------------------------------------------------------------
# L7 — key_id collisions are rejected (no silent stealth-rotation)
# ---------------------------------------------------------------------------


def test_L7_generate_dsa_keypair_rejects_duplicate_key_id():
    """Lazarus-tier attack pattern: attacker with operational HSM
    access generates a new DSA keypair with the SAME key_id as a
    legitimate key. If the SDK silently overwrote, the new private
    key would be attacker-controlled while the key_id stayed
    identical. Defense: reject the second generate."""
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("dsa-1")
    with pytest.raises(ValueError, match="already exists"):
        hsm.generate_dsa_keypair("dsa-1")


def test_L7_generate_kem_keypair_rejects_duplicate_key_id():
    hsm = SoftwareHSM()
    hsm.generate_kem_keypair("kem-1")
    with pytest.raises(ValueError, match="already exists"):
        hsm.generate_kem_keypair("kem-1")


def test_L7_generate_dsa_and_kem_share_same_id_space():
    """One key_id can hold only one entry — even across types.
    Prevents stealth-rotation by 'changing the key type' under the
    same name."""
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("shared-id")
    with pytest.raises(ValueError, match="already exists"):
        hsm.generate_kem_keypair("shared-id")


# ---------------------------------------------------------------------------
# L8 — has_key is a safe pre-check (no key-material leakage on miss)
# ---------------------------------------------------------------------------


def test_L8_has_key_distinguishes_present_vs_absent():
    hsm = SoftwareHSM()
    hsm.generate_dsa_keypair("present")
    assert hsm.has_key("present") is True
    assert hsm.has_key("absent") is False
