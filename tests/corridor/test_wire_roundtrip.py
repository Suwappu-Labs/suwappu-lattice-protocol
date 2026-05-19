"""Wire-format round-trip tests for the corridor JSON encoding."""

from __future__ import annotations

import json

from ltp.corridor import (
    DA_SLA_DEFAULT,
    AttestationPayload,
    AuthScheme,
    Cid,
    Commitment,
    CorridorAttestation,
    DidRotationStatement,
    StateAnchor,
    WitnessSignature,
)
from ltp.corridor.wire import (
    attestation_payload_from_dict,
    attestation_payload_to_dict,
    attestation_payload_to_serde_default_dict,
    cid_from_dict,
    cid_to_dict,
    commitment_from_dict,
    commitment_to_dict,
    corridor_attestation_from_dict,
    corridor_attestation_to_dict,
    did_rotation_statement_from_dict,
    did_rotation_statement_to_dict,
    state_anchor_from_dict,
    state_anchor_to_dict,
    witness_signature_from_dict,
    witness_signature_to_dict,
)


def _payload() -> AttestationPayload:
    return AttestationPayload(
        source_chain=1,
        target_chain=100,
        source_height=42,
        state_root=bytes([0xAB] * 32),
        timestamp_round=7,
    )


def test_attestation_payload_round_trip() -> None:
    p = _payload()
    d = attestation_payload_to_dict(p)
    assert json.loads(json.dumps(d)) == d
    assert attestation_payload_from_dict(d) == p


def test_attestation_payload_hex_encoding() -> None:
    d = attestation_payload_to_dict(_payload())
    assert d["state_root"] == "ab" * 32
    assert d["source_chain"] == 1


def test_witness_signature_round_trip() -> None:
    ws = WitnessSignature(witness=3, signature=bytes(96))
    d = witness_signature_to_dict(ws)
    assert d["witness"] == 3
    assert d["signature"] == "00" * 96
    assert witness_signature_from_dict(d) == ws


def test_corridor_attestation_round_trip() -> None:
    att = CorridorAttestation(
        payload=_payload(),
        aggregate_signature=bytes(96),
        signers=frozenset({0, 1, 2, 3, 4, 5, 6}),
    )
    d = corridor_attestation_to_dict(att)
    # Signers must be a sorted list, not a set (JSON-safe).
    assert d["signers"] == [0, 1, 2, 3, 4, 5, 6]
    assert corridor_attestation_from_dict(d) == att


def test_cid_round_trip() -> None:
    cid = Cid.of(b"alpha")
    s = cid_to_dict(cid)
    assert isinstance(s, str)
    assert len(s) == 64
    assert cid_from_dict(s) == cid


def test_commitment_round_trip() -> None:
    cid = Cid.of(b"payload")
    c = Commitment(cid=cid, size_bytes=7, stored_at=10, sla=DA_SLA_DEFAULT)
    d = commitment_to_dict(c)
    assert d["sla"]["retention_rounds"] == 100_000
    assert commitment_from_dict(d) == c


def test_did_rotation_statement_round_trip() -> None:
    s = DidRotationStatement(
        did=bytes(32),
        old_doc_hash=bytes([1]) * 32,
        new_doc_hash=bytes([2]) * 32,
        source_chain=1,
        target_chain=2,
        source_height=10,
    )
    d = did_rotation_statement_to_dict(s)
    assert d["old_doc_hash"] == "01" * 32
    assert did_rotation_statement_from_dict(d) == s


def test_state_anchor_round_trip() -> None:
    a = StateAnchor(
        chain_id=103_115_120,
        height=0,
        state_root=bytes([7] * 32),
        parent=bytes(32),
        mac=bytes(32),
        auth_scheme=AuthScheme.ML_DSA_65_HYBRID,
    )
    d = state_anchor_to_dict(a)
    assert d["auth_scheme"] == 3  # u8 discriminant, not variant name
    assert state_anchor_from_dict(d) == a


def test_serde_default_emits_byte_arrays() -> None:
    d = attestation_payload_to_serde_default_dict(_payload())
    assert d["state_root"] == [0xAB] * 32
    assert isinstance(d["state_root"], list)
