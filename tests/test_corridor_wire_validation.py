"""Corridor wire-format input validation.

Every ``*_from_dict`` deserializer must raise ``WireFormatError`` on
malformed input rather than propagating bare KeyError / ValueError to
the caller. This is the boundary between untrusted JSON (HTTP / gossip)
and the typed cryptographic surface; bare exceptions there leak schema
and stack information to attackers.
"""

from __future__ import annotations

import pytest

from src.ltp.corridor.wire import (
    WireFormatError,
    attestation_payload_from_dict,
    corridor_attestation_from_dict,
    did_rotation_statement_from_dict,
    state_anchor_from_dict,
    super_node_from_dict,
    witness_signature_from_dict,
)

# ---------------------------------------------------------------------------
# AttestationPayload
# ---------------------------------------------------------------------------


def _valid_payload() -> dict:
    return {
        "source_chain": 1,
        "target_chain": 2,
        "source_height": 100,
        "state_root": "00" * 32,
        "timestamp_round": 50,
    }


class TestAttestationPayloadFromDict:
    def test_valid(self):
        attestation_payload_from_dict(_valid_payload())

    def test_missing_state_root(self):
        d = _valid_payload()
        del d["state_root"]
        with pytest.raises(WireFormatError, match="state_root"):
            attestation_payload_from_dict(d)

    def test_state_root_wrong_length(self):
        d = _valid_payload()
        d["state_root"] = "deadbeef"  # only 4 bytes
        with pytest.raises(WireFormatError, match="state_root.*32 bytes"):
            attestation_payload_from_dict(d)

    def test_state_root_not_hex(self):
        d = _valid_payload()
        d["state_root"] = "not-hex-data"
        with pytest.raises(WireFormatError, match="state_root.*not valid hex"):
            attestation_payload_from_dict(d)

    def test_state_root_not_string(self):
        d = _valid_payload()
        d["state_root"] = 12345
        with pytest.raises(WireFormatError, match="state_root.*hex string"):
            attestation_payload_from_dict(d)

    def test_source_chain_not_int(self):
        d = _valid_payload()
        d["source_chain"] = "not-a-number"
        with pytest.raises(WireFormatError, match="source_chain.*not an integer"):
            attestation_payload_from_dict(d)

    def test_negative_source_height(self):
        d = _valid_payload()
        d["source_height"] = -1
        with pytest.raises(WireFormatError, match="source_height.*non-negative"):
            attestation_payload_from_dict(d)


# ---------------------------------------------------------------------------
# WitnessSignature
# ---------------------------------------------------------------------------


def _valid_witness() -> dict:
    return {"witness": 0, "signature": "00" * 96}


class TestWitnessSignatureFromDict:
    def test_valid(self):
        witness_signature_from_dict(_valid_witness())

    def test_signature_wrong_length(self):
        d = _valid_witness()
        d["signature"] = "deadbeef"  # only 4 bytes, BLS sig is 96
        with pytest.raises(WireFormatError, match="signature.*96 bytes"):
            witness_signature_from_dict(d)

    def test_signature_not_hex(self):
        d = _valid_witness()
        d["signature"] = "not-hex"
        with pytest.raises(WireFormatError, match="signature.*not valid hex"):
            witness_signature_from_dict(d)

    def test_missing_witness_field(self):
        d = _valid_witness()
        del d["witness"]
        with pytest.raises(WireFormatError, match="witness"):
            witness_signature_from_dict(d)


# ---------------------------------------------------------------------------
# CorridorAttestation
# ---------------------------------------------------------------------------


def _valid_corridor_attestation() -> dict:
    return {
        "payload": _valid_payload(),
        "aggregate_signature": "00" * 96,
        "signers": [0, 1, 2],
    }


class TestCorridorAttestationFromDict:
    def test_valid(self):
        corridor_attestation_from_dict(_valid_corridor_attestation())

    def test_aggregate_signature_wrong_length(self):
        d = _valid_corridor_attestation()
        d["aggregate_signature"] = "00" * 32  # too short
        with pytest.raises(WireFormatError, match="aggregate_signature.*96 bytes"):
            corridor_attestation_from_dict(d)

    def test_signers_not_list(self):
        d = _valid_corridor_attestation()
        d["signers"] = "not-a-list"
        with pytest.raises(WireFormatError, match="signers.*list"):
            corridor_attestation_from_dict(d)

    def test_signers_not_integers(self):
        d = _valid_corridor_attestation()
        d["signers"] = [0, "string-not-int", 2]
        with pytest.raises(WireFormatError, match="signers.*list of integers"):
            corridor_attestation_from_dict(d)

    def test_payload_not_object(self):
        d = _valid_corridor_attestation()
        d["payload"] = "not-an-object"
        with pytest.raises(WireFormatError, match="payload.*object"):
            corridor_attestation_from_dict(d)

    def test_missing_payload(self):
        d = _valid_corridor_attestation()
        del d["payload"]
        with pytest.raises(WireFormatError, match="payload"):
            corridor_attestation_from_dict(d)


# ---------------------------------------------------------------------------
# SuperNode
# ---------------------------------------------------------------------------


class TestSuperNodeFromDict:
    def test_valid(self):
        super_node_from_dict({"authority": 0, "corridor": 0, "bls_public_key": "00" * 48})

    def test_bls_pk_wrong_length(self):
        with pytest.raises(WireFormatError, match="bls_public_key.*48 bytes"):
            super_node_from_dict({"authority": 0, "corridor": 0, "bls_public_key": "deadbeef"})


# ---------------------------------------------------------------------------
# StateAnchor
# ---------------------------------------------------------------------------


def _valid_state_anchor() -> dict:
    return {
        "chain_id": 1,
        "height": 100,
        "state_root": "11" * 32,
        "parent": "22" * 32,
        "mac": "33" * 32,
        "auth_scheme": 0,
    }


class TestStateAnchorFromDict:
    def test_valid(self):
        state_anchor_from_dict(_valid_state_anchor())

    def test_state_root_wrong_length(self):
        d = _valid_state_anchor()
        d["state_root"] = "abcd"
        with pytest.raises(WireFormatError, match="state_root.*32 bytes"):
            state_anchor_from_dict(d)

    def test_parent_wrong_length(self):
        d = _valid_state_anchor()
        d["parent"] = "abcd"
        with pytest.raises(WireFormatError, match="parent.*32 bytes"):
            state_anchor_from_dict(d)

    def test_auth_scheme_out_of_range(self):
        d = _valid_state_anchor()
        d["auth_scheme"] = 999
        with pytest.raises(WireFormatError, match="auth_scheme.*not a valid AuthScheme"):
            state_anchor_from_dict(d)


# ---------------------------------------------------------------------------
# DidRotationStatement
# ---------------------------------------------------------------------------


class TestDidRotationStatementFromDict:
    def test_valid(self):
        did_rotation_statement_from_dict(
            {
                "did": "00" * 32,
                "old_doc_hash": "11" * 32,
                "new_doc_hash": "22" * 32,
                "source_chain": 1,
                "target_chain": 2,
                "source_height": 100,
            }
        )

    def test_did_wrong_length(self):
        with pytest.raises(WireFormatError, match="did.*32 bytes"):
            did_rotation_statement_from_dict(
                {
                    "did": "00" * 16,
                    "old_doc_hash": "11" * 32,
                    "new_doc_hash": "22" * 32,
                    "source_chain": 1,
                    "target_chain": 2,
                    "source_height": 100,
                }
            )

    def test_old_doc_hash_wrong_length(self):
        with pytest.raises(WireFormatError, match="old_doc_hash.*32 bytes"):
            did_rotation_statement_from_dict(
                {
                    "did": "00" * 32,
                    "old_doc_hash": "abcd",
                    "new_doc_hash": "22" * 32,
                    "source_chain": 1,
                    "target_chain": 2,
                    "source_height": 100,
                }
            )
