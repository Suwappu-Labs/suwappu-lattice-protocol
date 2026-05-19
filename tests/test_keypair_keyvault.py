"""Tests for KeyPair.sign / KeyPair.decaps and the implicit-HSM
default-on policy (LTP-A-032 Phases 4a + 4c).

Phase 4c flipped the implicit-HSM flag from opt-in to opt-out:
- Default: KeyPair.generate(hsm=None) returns a sentinel-backed kp
  with a per-instance SoftwareHSM.
- LTP_KEYPAIR_IMPLICIT_HSM=0 (or false/no/off) opts out → plaintext
  dk/sk on the dataclass (legacy behavior for tests that probe bytes).

The repo-wide `tests/conftest.py` sets LTP_KEYPAIR_IMPLICIT_HSM=0 for
the legacy test suite. This file unsets it per-test where the new
default behavior is what we are asserting.
"""

from __future__ import annotations

import os

import pytest

from ltp.hsm import SoftwareHSM
from ltp.keypair import KeyPair
from ltp.primitives import MLDSA, MLKEM

_SENTINEL = b"\xfe" * 32


@pytest.fixture
def implicit_hsm_on(monkeypatch):
    """Unset the opt-out so the production default applies."""
    monkeypatch.delenv("LTP_KEYPAIR_IMPLICIT_HSM", raising=False)


@pytest.fixture
def implicit_hsm_off(monkeypatch):
    """Explicit opt-out — legacy plaintext kp.sk / kp.dk path."""
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", "0")


# ---------------------------------------------------------------------------
# Default (Phase 4c: implicit-HSM on)
# ---------------------------------------------------------------------------


def test_default_returns_sentinels(implicit_hsm_on):
    kp = KeyPair.generate(label="alice")
    assert kp.dk == _SENTINEL
    assert kp.sk == _SENTINEL
    assert kp.is_hsm_backed is True
    # Phase 4c: label no longer carries an `[hsm]` suffix.
    assert kp.label == "alice"


def test_default_sign_and_decaps_roundtrip(implicit_hsm_on):
    kp = KeyPair.generate(label="alice")
    sig = kp.sign(b"payload")
    assert MLDSA.verify(kp.vk, b"payload", sig) is True
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.decaps(ct) == ss_a


def test_default_per_keypair_hsm_isolation(implicit_hsm_on):
    a = KeyPair.generate(label="alice")
    b = KeyPair.generate(label="bob")
    with pytest.raises(KeyError):
        a._hsm.sign(b._hsm_dsa_key_id, b"x")


# ---------------------------------------------------------------------------
# Opt-out (legacy plaintext path)
# ---------------------------------------------------------------------------


def test_opt_out_keeps_plaintext_dk_sk(implicit_hsm_off):
    kp = KeyPair.generate(label="alice")
    assert kp.dk != _SENTINEL
    assert kp.sk != _SENTINEL
    assert kp.is_hsm_backed is False
    assert len(kp.dk) == 2400
    assert len(kp.sk) == 4032


def test_opt_out_sign_works(implicit_hsm_off):
    kp = KeyPair.generate(label="alice")
    sig = kp.sign(b"hello")
    assert MLDSA.verify(kp.vk, b"hello", sig) is True


def test_opt_out_decaps_works(implicit_hsm_off):
    kp = KeyPair.generate(label="alice")
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.decaps(ct) == ss_a


def test_hsm_sign_alias_works_both_modes(implicit_hsm_off):
    """Deprecated alias still routes through sign()."""
    kp = KeyPair.generate(label="alice")
    sig = kp.hsm_sign(b"hi")
    assert MLDSA.verify(kp.vk, b"hi", sig) is True


def test_hsm_decaps_alias_works_both_modes(implicit_hsm_off):
    kp = KeyPair.generate(label="alice")
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.hsm_decaps(ct) == ss_a


# ---------------------------------------------------------------------------
# Explicit-HSM path (unaffected by flag)
# ---------------------------------------------------------------------------


def test_explicit_hsm_returns_sentinels():
    hsm = SoftwareHSM()
    kp = KeyPair.generate(label="alice", hsm=hsm)
    assert kp.dk == _SENTINEL
    assert kp.sk == _SENTINEL
    assert kp.is_hsm_backed is True
    # Phase 4c: no `[hsm]` suffix on the label.
    assert kp.label == "alice"


def test_explicit_hsm_sign_and_decaps():
    hsm = SoftwareHSM()
    kp = KeyPair.generate(label="alice", hsm=hsm)
    sig = kp.sign(b"hello")
    assert MLDSA.verify(kp.vk, b"hello", sig) is True
    ss_a, ct = MLKEM.encaps(kp.ek)
    assert kp.decaps(ct) == ss_a


# ---------------------------------------------------------------------------
# Opt-out flag parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "FALSE", "Off"])
def test_opt_out_flag_accepts_falsy_values(monkeypatch, val):
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", val)
    kp = KeyPair.generate(label="bob")
    assert kp.is_hsm_backed is False
    assert kp.dk != _SENTINEL


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "", "random"])
def test_anything_not_opt_out_keeps_implicit_hsm_on(monkeypatch, val):
    """The opt-out check is conservative: only the documented falsy
    spellings disable. Anything else (including empty string or typos)
    keeps the production default ON."""
    monkeypatch.setenv("LTP_KEYPAIR_IMPLICIT_HSM", val)
    kp = KeyPair.generate(label="bob")
    assert kp.is_hsm_backed is True
    assert kp.dk == _SENTINEL


# ---------------------------------------------------------------------------
# Label stays clean — no [hsm] suffix
# ---------------------------------------------------------------------------


def test_label_has_no_hsm_suffix_after_rotation(implicit_hsm_on):
    """Phase 4c dropped the `[hsm]` label marker (Codex P1 made it
    idempotent, then the team voted to drop it entirely). Lookup keys
    in KeyRotationManager / KeyRegistry stay stable."""
    kp1 = KeyPair.generate(label="alice")
    assert kp1.label == "alice"
    kp2 = KeyPair.generate(label=kp1.label)
    assert kp2.label == "alice"


def test_explicit_hsm_label_has_no_hsm_suffix():
    kp = KeyPair.generate(label="bob", hsm=SoftwareHSM())
    assert kp.label == "bob"


# ---------------------------------------------------------------------------
# with_bls support
# ---------------------------------------------------------------------------


def test_with_bls_default_mode(implicit_hsm_on):
    kp = KeyPair.generate(label="alice", with_bls=True)
    assert kp.bls_pk is not None
    assert kp.bls_sk is not None
    assert kp.is_hsm_backed is True


def test_with_bls_opt_out(implicit_hsm_off):
    kp = KeyPair.generate(label="alice", with_bls=True)
    assert kp.bls_pk is not None
    assert kp.bls_sk is not None
    assert kp.is_hsm_backed is False


# ---------------------------------------------------------------------------
# from_persisted — operator-identity reload path
# ---------------------------------------------------------------------------


def test_from_persisted_default_routes_through_hsm(implicit_hsm_on):
    """Phase 4c: persisted (vk, sk) bytes are re-imported into a fresh
    SoftwareHSM so the rebuilt KeyPair is sentinel-backed. The on-disk
    storage layer (log_store) keeps the bytes KeyVault-wrapped."""
    ek, dk = MLKEM.keygen()
    vk, sk = MLDSA.keygen()
    kp = KeyPair.from_persisted(ek=ek, dk=dk, vk=vk, sk=sk, label="op")
    assert kp.is_hsm_backed is True
    assert kp.dk == _SENTINEL
    assert kp.sk == _SENTINEL
    # And sign() still works via the imported key.
    sig = kp.sign(b"hello")
    assert MLDSA.verify(vk, b"hello", sig) is True


def test_from_persisted_opt_out_keeps_plaintext(implicit_hsm_off):
    ek, dk = MLKEM.keygen()
    vk, sk = MLDSA.keygen()
    kp = KeyPair.from_persisted(ek=ek, dk=dk, vk=vk, sk=sk, label="op")
    assert kp.is_hsm_backed is False
    assert kp.dk == dk
    assert kp.sk == sk
