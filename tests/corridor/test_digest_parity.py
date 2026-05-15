"""Golden-vector parity tests for the cross-repo SHA3-256 domain digest.

These fixtures pin the byte layout the Python `corridor` package shares with
`gsx-dag/crates/gsx-ltp` (Rust). If a Rust-side change moves a field, the
hashes here must be regenerated and the change recorded in
`docs/design-decisions/GSX_DAG_DB_INTEGRATION.md`.
"""

from __future__ import annotations

from ltp.corridor import (
    DOMAIN_TAG_ATTEST,
    DOMAIN_TAG_CID,
    DOMAIN_TAG_DID_STARK,
    LTP_ATTESTATION_QUORUM_SIZE,
    LTP_ATTESTATION_QUORUM_THRESHOLD,
    ON_CHAIN_COMMITMENT_BYTES,
    AttestationPayload,
    Cid,
    DidRotationStatement,
    sha3_256_domain,
)


# Reference digests reproduced from the byte layout of
# `gsx-dag/crates/gsx-ltp` (see attestation.rs, da.rs, did_stark.rs). The
# values come from the Python sha3_256_domain implementation, which is the
# byte-exact mirror of `gsx_crypto::hash::sha3_256_domain` —
# `H(len(tag) as u32 BE || tag || data)`.
ATTEST_DIGEST_HEX = "b1dc6381728e0d2c78bbc3176ece95917eede7303ffffc940a13d7c865aa2b30"
CID_ALPHA_HEX = "a03450af1b7cbb3bc9b074a7ef2e8d29144af0aa1954c2076f4e299a0a0388cc"
CID_BETA_HEX = "910f3f97fc8d14500ff55b7bb7d0164f1fad74ff56793c042b2fe6c2d5931ca0"
DID_STARK_DIGEST_HEX = "dea522015bc0da44dafa77e5216e53d48f10707e29b5da7b8d363ca863f71c52"


def test_constants_match_paper() -> None:
    assert ON_CHAIN_COMMITMENT_BYTES == 1_600
    assert LTP_ATTESTATION_QUORUM_THRESHOLD == 7
    assert LTP_ATTESTATION_QUORUM_SIZE == 9


def test_attestation_payload_digest_matches_reference() -> None:
    payload = AttestationPayload(
        source_chain=1,
        target_chain=100,
        source_height=42,
        state_root=bytes([0xAB] * 32),
        timestamp_round=7,
    )
    assert payload.canonical_digest().hex() == ATTEST_DIGEST_HEX


def test_cid_matches_reference() -> None:
    assert Cid.of(b"alpha").value.hex() == CID_ALPHA_HEX
    assert Cid.of(b"beta").value.hex() == CID_BETA_HEX
    assert Cid.of(b"alpha") != Cid.of(b"beta")


def test_did_rotation_statement_digest_matches_reference() -> None:
    statement = DidRotationStatement(
        did=bytes(32),
        old_doc_hash=bytes([1]) * 32,
        new_doc_hash=bytes([2]) * 32,
        source_chain=1,
        target_chain=2,
        source_height=10,
    )
    assert statement.digest().hex() == DID_STARK_DIGEST_HEX


def test_sha3_256_domain_length_prefixes_tag() -> None:
    # The boundary-shift attack a naive concatenation is vulnerable to:
    # H("ab" || "c") != H("a" || "bc") under our scheme, because the tag
    # length is folded into the digest input.
    assert sha3_256_domain(b"ab", b"c") != sha3_256_domain(b"a", b"bc")
