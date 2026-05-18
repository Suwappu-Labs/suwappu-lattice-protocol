"""Tests for KeyPair.sign / KeyPair.decaps and implicit-HSM mode
(LTP-A-032 Phase 4a).

Verifies:
- KeyPair.sign works in both HSM and non-HSM modes; output verifies.
- KeyPair.decaps works in both modes; round-trips the shared secret.
- LTP_KEYPAIR_IMPLICIT_HSM=1 makes generate(hsm=None) return a
  sentinel-backed KeyPair (kp.dk / kp.sk = b"\\xfe"*32).
- Flag-off default keeps the existing behavior (plaintext dk / sk).
- hsm_sign / hsm_decaps still work (deprecated aliases).
- is_hsm_backed reflects implicit-HSM state.
- with_bls=True still works in both flag states.
"""

from __future__ import annotations

import os

import pytest

from ltp.keypair import KeyPair
from ltp.hsm import SoftwareHSM
from ltp.primitives import MLDSA, MLKEM


_SENTINEL = b"\xfe" * 32


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("LTP_KEYPAIR_IMPLICIT_HSM", raising=False)


# ---------------------------------------------------------------------------
# Default (flag off) — plaintext dk/sk preserved
# ---------------------------------------------------------------------------


def test_default_mode_keeps_plaintext_dk_sk():
    kp = KeyPair.generate(label="alice")
    assert kp.dk != _SENTINEL
    assert kp.sk != _SENTINEL
    assert kp.is_hsm_backed is False
    # The dk / sk lengths match active ML-KEM / ML-DSA profile.
    assert len(kp.dk) == 2400
    assert len(kp.sk) == 4032


def test_sign_works_without_hsm():
    kp = KeyPair.generate(label="alice")
    sig = kp.sign(b"hello")
    assert MLDSA.verify(kp.vk, b"hello", sig) is True


def test_decaps_works_without_hsm():
    kp = KeyPair.generate(label="alice")
    ss_a, ct = MLKEM.encaps(kp.ek)
    ss_b = kp.decaps(ct)
    assert ss_a == ss_b


def test_hsm_sign_alias_works_without_hsm():
    """Deprecated alias now routes through sign() instead of raising."""
    kp = KeyPair.generate(label="alice")
    sig = kp.hsm_sign(b"hi")
    assert MLDSA.verify(kp.vk, b"hi", sig) is True


def test_hsm_decaps_alias_works_without_hsm():
    kp = KeyPair.generate(label="alice")
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.hsm_decaps(ct) == ss_a


# ---------------------------------------------------------------------------
# Explicit HSM mode (unchanged) — sentinels
# ---------------------------------------------------------------------------


def test_explicit_hsm_returns_sentinels():
    hsm = SoftwareHSM()
    kp = KeyPair.generate(label="alice", hsm=hsm)
    assert kp.dk == _SENTINEL
    assert kp.sk == _SENTINEL
    assert kp.is_hsm_backed is True


def test_explicit_hsm_sign_and_decaps():
    hsm = SoftwareHSM()
    kp = KeyPair.generate(label="alice", hsm=hsm)
    sig = kp.sign(b"hello")
    assert MLDSA.verify(kp.vk, b"hello", sig) is True
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.decaps(ct) == ss_a


# ---------------------------------------------------------------------------
# Implicit-HSM flag — opt-in
# ---------------------------------------------------------------------------


def test_implicit_hsm_flag_returns_sentinels(monkeypatch):
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", "1")
    kp = KeyPair.generate(label="alice")
    assert kp.dk == _SENTINEL
    assert kp.sk == _SENTINEL
    assert kp.is_hsm_backed is True
    # Label is suffixed to flag HSM-backing — same convention as
    # explicit-HSM mode.
    assert kp.label.endswith("[hsm]")


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE", "Yes"])
def test_implicit_hsm_flag_accepts_truthy_values(monkeypatch, val):
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", val)
    kp = KeyPair.generate(label="bob")
    assert kp.is_hsm_backed is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "random"])
def test_implicit_hsm_flag_rejects_falsy_values(monkeypatch, val):
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", val)
    kp = KeyPair.generate(label="bob")
    assert kp.is_hsm_backed is False
    assert kp.dk != _SENTINEL


def test_implicit_hsm_sign_and_decaps_roundtrip(monkeypatch):
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", "1")
    kp = KeyPair.generate(label="alice")
    sig = kp.sign(b"payload")
    assert MLDSA.verify(kp.vk, b"payload", sig) is True
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.decaps(ct) == ss_a


def test_implicit_hsm_isolated_per_keypair(monkeypatch):
    """Each implicit-HSM KeyPair gets its own SoftwareHSM, so cross-
    instance signing must fail."""
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", "1")
    a = KeyPair.generate(label="alice")
    b = KeyPair.generate(label="bob")
    # a's HSM should not have b's key_id.
    with pytest.raises(KeyError):
        a._hsm.sign(b._hsm_dsa_key_id, b"x")


# ---------------------------------------------------------------------------
# with_bls support across both modes
# ---------------------------------------------------------------------------


def test_with_bls_default_mode():
    kp = KeyPair.generate(label="alice", with_bls=True)
    assert kp.bls_pk is not None
    assert kp.bls_sk is not None


def test_with_bls_implicit_hsm_mode(monkeypatch):
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", "1")
    kp = KeyPair.generate(label="alice", with_bls=True)
    assert kp.bls_pk is not None
    assert kp.bls_sk is not None
    # Still sentinel-backed for ML-KEM / ML-DSA.
    assert kp.dk == _SENTINEL
    assert kp.sk == _SENTINEL
