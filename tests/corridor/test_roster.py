"""Roster loading — the hardened trusted-membership boundary.

``load_corridor_roster`` / ``validate_roster`` are what a node operator
uses to install the corridor membership from an onboarding packet.
Unlike raw ``corridor_from_dict``, the loader enforces structure
(size, distinct authorities, distinct keys, corridor-id consistency)
and verifies Proof-of-Possession by default (LTP-A-015).
"""

from __future__ import annotations

import json

import pytest

from src.ltp.corridor.attestation import (
    BadCorridorSize,
    Corridor,
    CorridorPopVerificationFailed,
    SuperNode,
)
from src.ltp.corridor.constants import (
    DOMAIN_TAG_CORRIDOR_POP,
    LTP_ATTESTATION_QUORUM_SIZE,
)
from src.ltp.corridor.roster import (
    RosterValidationError,
    load_corridor_roster,
    validate_roster,
)
from src.ltp.corridor.wire import WireFormatError, corridor_to_dict

try:
    from src.ltp.corridor.bls import _blst_available, _py_ecc_available, corridor_sign, keygen

    _HAS_BLS_BACKEND = _blst_available or _py_ecc_available
except (ImportError, AttributeError):
    _HAS_BLS_BACKEND = False

needs_bls = pytest.mark.skipif(not _HAS_BLS_BACKEND, reason="no BLS backend available")


def _fake_member(authority: int, corridor: int = 0, key_byte: int | None = None) -> SuperNode:
    """Structurally valid member with a fabricated (non-verifying) key."""
    b = key_byte if key_byte is not None else authority + 1
    return SuperNode(
        authority=authority,
        corridor=corridor,
        bls_public_key=bytes([b]) * 48,
        pop=b"",
    )


def _fake_roster(n: int = LTP_ATTESTATION_QUORUM_SIZE) -> Corridor:
    return Corridor(id=0, members=tuple(_fake_member(i) for i in range(n)))


def _real_member(authority: int) -> SuperNode:
    pk, sk = keygen()
    pop = corridor_sign(sk, DOMAIN_TAG_CORRIDOR_POP + pk)
    return SuperNode(authority=authority, corridor=0, bls_public_key=pk, pop=pop)


# --- structural validation (no BLS backend needed) -----------------------


def test_wrong_size_rejected():
    with pytest.raises(BadCorridorSize):
        validate_roster(_fake_roster(n=8), require_pop=False)


def test_duplicate_authority_rejected():
    members = [_fake_member(i) for i in range(LTP_ATTESTATION_QUORUM_SIZE)]
    members[8] = _fake_member(0, key_byte=99)  # duplicate authority id 0
    with pytest.raises(RosterValidationError, match="duplicate authority"):
        validate_roster(Corridor(id=0, members=tuple(members)), require_pop=False)


def test_duplicate_pubkey_rejected():
    members = [_fake_member(i) for i in range(LTP_ATTESTATION_QUORUM_SIZE)]
    members[8] = _fake_member(8, key_byte=1)  # same key bytes as authority 0
    with pytest.raises(RosterValidationError, match="duplicate BLS public keys"):
        validate_roster(Corridor(id=0, members=tuple(members)), require_pop=False)


def test_corridor_id_mismatch_rejected():
    members = [_fake_member(i) for i in range(LTP_ATTESTATION_QUORUM_SIZE)]
    members[3] = _fake_member(3, corridor=7)
    with pytest.raises(RosterValidationError, match="corridor id"):
        validate_roster(Corridor(id=0, members=tuple(members)), require_pop=False)


def test_missing_pop_rejected_by_default():
    """The default path demands PoP — a fixture-style roster must not load."""
    with pytest.raises(CorridorPopVerificationFailed):
        validate_roster(_fake_roster())


def test_legacy_opt_out_loads_structurally_valid_roster():
    validate_roster(_fake_roster(), require_pop=False)


# --- file loading ---------------------------------------------------------


def test_load_rejects_invalid_json(tmp_path):
    p = tmp_path / "roster.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(WireFormatError, match="not valid JSON"):
        load_corridor_roster(p)


def test_load_rejects_non_object(tmp_path):
    p = tmp_path / "roster.json"
    p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(WireFormatError, match="JSON object"):
        load_corridor_roster(p)


def test_template_never_loads():
    """The committed template must always fail validation (identical keys)."""
    with pytest.raises((RosterValidationError, CorridorPopVerificationFailed)):
        load_corridor_roster("config/corridor-roster.template.json", require_pop=False)
    with pytest.raises((RosterValidationError, CorridorPopVerificationFailed)):
        load_corridor_roster("config/corridor-roster.template.json")


def test_load_ignores_unknown_keys(tmp_path):
    """A ``_comment`` key (as in the template) must not break parsing."""
    d = corridor_to_dict(_fake_roster())
    d["_comment"] = "hello"
    p = tmp_path / "roster.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    assert load_corridor_roster(p, require_pop=False).id == 0


# --- PoP path (needs a real BLS backend) ----------------------------------


@needs_bls
def test_real_roster_with_pops_loads(tmp_path):
    corridor = Corridor(
        id=0,
        members=tuple(_real_member(i) for i in range(LTP_ATTESTATION_QUORUM_SIZE)),
    )
    p = tmp_path / "roster.json"
    p.write_text(json.dumps(corridor_to_dict(corridor)), encoding="utf-8")
    loaded = load_corridor_roster(p)  # require_pop defaults to True
    assert loaded == corridor


@needs_bls
def test_tampered_pop_rejected(tmp_path):
    members = [_real_member(i) for i in range(LTP_ATTESTATION_QUORUM_SIZE)]
    bad = members[4]
    members[4] = SuperNode(
        authority=bad.authority,
        corridor=bad.corridor,
        bls_public_key=bad.bls_public_key,
        pop=bytes(96),  # zeroed signature
    )
    p = tmp_path / "roster.json"
    p.write_text(
        json.dumps(corridor_to_dict(Corridor(id=0, members=tuple(members)))),
        encoding="utf-8",
    )
    with pytest.raises(CorridorPopVerificationFailed):
        load_corridor_roster(p)
