"""Corridor → gsx-db state anchor submission bridge tests."""

from __future__ import annotations

import pytest

from ltp.corridor import (
    AttestationPayload,
    AuthScheme,
    CorridorAnchorError,
    CorridorAttestation,
    GENESIS_PARENT,
    build_state_anchor_blake3,
    build_state_anchor_keccak256,
    hash_anchor_keccak256,
)


def _attestation(target_chain: int = 103_115_120) -> CorridorAttestation:
    payload = AttestationPayload(
        source_chain=1,
        target_chain=target_chain,
        source_height=0,
        state_root=bytes([7] * 32),
        timestamp_round=1_700_000_000,
    )
    return CorridorAttestation(
        payload=payload,
        aggregate_signature=bytes(96),
        signers=frozenset({0, 1, 2, 3, 4, 5, 6}),
    )


def test_keccak256_build_matches_state_anchor_fixture() -> None:
    """The Solidity-keccak path on this attestation should match the
    `fixture_valid_anchor_acceptance` fixture from gsx-db's parity tests.
    """
    att = _attestation()
    build = build_state_anchor_keccak256(att, chain_key=bytes([1] * 32))
    assert build.anchor.chain_id == 103_115_120
    assert build.anchor.height == 0
    assert build.anchor.state_root == bytes([7] * 32)
    assert build.anchor.parent == GENESIS_PARENT
    assert build.anchor.mac.hex() == (
        "f70120a7b5c85c4be4b147b152e0284b30aa7ba49530e9aeb481561d38199c7d"
    )
    assert build.canonical_hash.hex() == (
        "f661f063e589f3241c1855e28368fa8daa16de51afb6335ec3340a52bb941fee"
    )


def test_blake3_build_uses_rust_canonical_mac() -> None:
    blake3 = pytest.importorskip("blake3")
    att = _attestation()
    build = build_state_anchor_blake3(att, chain_key=bytes([1] * 32))
    assert build.anchor.mac.hex() == (
        "047ac7c1dbc9e323e244d3a20e537b4c0ad2709d4712762b067c83a3751cbe4d"
    )


def test_chain_id_overflow_rejected() -> None:
    att = _attestation(target_chain=(1 << 32))
    with pytest.raises(CorridorAnchorError):
        build_state_anchor_keccak256(att, chain_key=bytes(32))


def test_parent_chain_link() -> None:
    """The second anchor on a chain must reference the first anchor's hash."""
    att1 = _attestation()
    b1 = build_state_anchor_keccak256(att1, chain_key=bytes([1] * 32))

    # Second anchor at height 1 with previous as parent.
    payload2 = AttestationPayload(
        source_chain=1,
        target_chain=att1.payload.target_chain,
        source_height=1,
        state_root=bytes([8] * 32),
        timestamp_round=1_700_000_010,
    )
    att2 = CorridorAttestation(
        payload=payload2,
        aggregate_signature=bytes(96),
        signers=att1.signers,
    )
    b2 = build_state_anchor_keccak256(
        att2, chain_key=bytes([1] * 32), parent=b1.canonical_hash
    )
    assert b2.anchor.parent == b1.canonical_hash
    # Re-hashing must match canonical_hash returned by the builder.
    assert hash_anchor_keccak256(b2.anchor) == b2.canonical_hash


def test_auth_scheme_override() -> None:
    att = _attestation()
    build = build_state_anchor_keccak256(
        att, chain_key=bytes([1] * 32), auth_scheme=AuthScheme.ML_DSA_65_HYBRID
    )
    assert build.anchor.auth_scheme == AuthScheme.ML_DSA_65_HYBRID
