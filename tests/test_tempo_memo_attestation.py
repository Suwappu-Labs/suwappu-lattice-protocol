"""Tests for the Tempo memo <-> LTP attestation prototype.

Offline by default: the network-touching path is exercised through a stubbed
JSON-RPC layer so the suite stays hermetic. The live end-to-end run is recorded
in docs/design-decisions/TEMPO_INTEGRATION.md with its transaction hash.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "examples" / "tempo_memo_attestation.py"

_spec = importlib.util.spec_from_file_location("tempo_memo_attestation", MODULE_PATH)
assert _spec and _spec.loader
tma = importlib.util.module_from_spec(_spec)
sys.modules["tempo_memo_attestation"] = tma
_spec.loader.exec_module(tma)


# --- memo normalisation ----------------------------------------------------


def test_normalize_accepts_prefixed_and_bare_hex():
    h = "c6e6fbd7965cec5914849d9cb74c00614fce15671f2beac06dda042d64cc1183"
    assert tma.normalize_memo("0x" + h) == tma.normalize_memo(h)
    assert len(tma.normalize_memo(h)) == 32


@pytest.mark.parametrize("bad", ["0x1234", "0x" + "ab" * 33, "0xzz" + "00" * 31])
def test_normalize_rejects_wrong_size_or_non_hex(bad):
    """A Tempo memo is exactly bytes32. Anything else must fail loudly."""
    with pytest.raises(SystemExit):
        tma.normalize_memo(bad)


# --- text-memo diagnostic --------------------------------------------------


def test_tempo_text_memo_is_recognised_as_text():
    """`pad(stringToHex("INV-2026-0042"), {size:32})` — Tempo's own encoding."""
    memo = b"INV-2026-0042" + b"\x00" * (32 - len("INV-2026-0042"))
    assert tma.looks_like_text_memo(memo)


def test_digest_is_not_mistaken_for_text():
    digest = bytes.fromhex(
        "c6e6fbd7965cec5914849d9cb74c00614fce15671f2beac06dda042d64cc1183"
    )
    assert not tma.looks_like_text_memo(digest)


def test_full_width_ascii_is_not_treated_as_text():
    """No trailing zero padding means it is not the Tempo text shape."""
    assert not tma.looks_like_text_memo(b"A" * 32)


# --- selectors -------------------------------------------------------------


def test_selectors_match_the_registry_abi():
    """Guards against a hand-edited selector silently returning empty data.

    Values produced by `cast sig`; see the module docstring.
    """
    assert tma.SEL_GET_ENTITY_STATE == "0xe490c513"
    assert tma.SEL_ENTITY_SIGNERS == "0xc5db24b8"


# --- verification against a stubbed chain ----------------------------------


def _stub_rpc(monkeypatch, state_word: str, signer_word: str | None = None):
    calls: list[str] = []

    def fake_eth_call(rpc_url: str, to: str, data: str) -> str:
        calls.append(data[:10])
        if data.startswith(tma.SEL_GET_ENTITY_STATE):
            return state_word
        if data.startswith(tma.SEL_ENTITY_SIGNERS):
            assert signer_word is not None, "signer lookup should not happen here"
            return signer_word
        raise AssertionError(f"unexpected selector {data[:10]}")

    monkeypatch.setattr(tma, "_eth_call", fake_eth_call)
    return calls


ANCHORED = "0x" + "00" * 31 + "02"
UNKNOWN = "0x" + "00" * 32
SIGNER = "0x4212a67b46dd5fea793af0b980911ab6656313eb2ffb7d68b858187464ed2541"
MEMO = "0xc6e6fbd7965cec5914849d9cb74c00614fce15671f2beac06dda042d64cc1183"


def test_anchored_memo_reports_attestation_and_signer(monkeypatch):
    _stub_rpc(monkeypatch, ANCHORED, SIGNER)
    out = tma.verify_memo(MEMO, "http://stub", "0xregistry")
    assert out["is_ltp_attestation"] is True
    assert out["entity_state"] == "ANCHORED"
    assert out["signer_vk_hash"] == SIGNER


def test_unknown_memo_is_not_an_attestation_and_skips_signer_lookup(monkeypatch):
    """A miss is a legitimate answer, not an error — and costs one call."""
    calls = _stub_rpc(monkeypatch, UNKNOWN)
    out = tma.verify_memo(MEMO, "http://stub", "0xregistry")
    assert out["is_ltp_attestation"] is False
    assert out["entity_state"] == "UNKNOWN"
    assert "signer_vk_hash" not in out
    assert calls == [tma.SEL_GET_ENTITY_STATE]


def test_text_memo_miss_explains_why(monkeypatch):
    _stub_rpc(monkeypatch, UNKNOWN)
    text_memo = "0x" + (b"INV-2026-0042" + b"\x00" * 19).hex()
    out = tma.verify_memo(text_memo, "http://stub", "0xregistry")
    assert out["is_ltp_attestation"] is False
    assert out["looks_like_text_memo"] == "INV-2026-0042"


def test_unrecognised_state_code_is_surfaced_not_swallowed(monkeypatch):
    """A future state value must not be silently reported as a known one."""
    _stub_rpc(monkeypatch, "0x" + "00" * 31 + "63", SIGNER)
    out = tma.verify_memo(MEMO, "http://stub", "0xregistry")
    assert "UNRECOGNISED(99)" in out["entity_state"]


# --- derivation matches the on-chain convention ----------------------------


def test_derived_memo_matches_bridge_entity_id_hash_convention():
    """The memo must equal spec_hash_bytes(entity_id_string).

    src/ltp/bridge/live.py derives the on-chain bytes32 that way. Deriving the
    raw digest after the "sha3-256:" prefix instead yields a memo that never
    resolves — this test pins the distinction.
    """
    pytest.importorskip("pqcrypto")
    sys.path.insert(0, str(PROJECT_ROOT))
    from src.ltp.dual_lane.hashing import spec_hash_bytes

    out = tma.derive_memo(b'{"invoice":"INV-1"}', "application/json")
    expected = spec_hash_bytes(out["entity_id"].encode())

    assert out["tempo_memo"] == "0x" + expected.hex()
    assert out["entity_id"].startswith("sha3-256:")
    # The naive derivation must NOT accidentally agree.
    naive = out["entity_id"].split(":", 1)[1]
    assert out["tempo_memo"][2:] != naive


def test_derived_memo_is_exactly_32_bytes():
    pytest.importorskip("pqcrypto")
    out = tma.derive_memo(b"x", "text/plain")
    assert len(bytes.fromhex(out["tempo_memo"][2:])) == tma.MEMO_BYTES
