"""DID rotation STARK statement tests."""

from __future__ import annotations

import pytest

from ltp.corridor import (
    DidRotationStatement,
    DidStarkInvalidSignature,
    OldDocHashMismatch,
    prove_rotation,
    verify_rotation_proof,
)
from ltp.primitives import MLDSA


def _statement(old_hash: bytes) -> DidRotationStatement:
    return DidRotationStatement(
        did=bytes(32),
        old_doc_hash=old_hash,
        new_doc_hash=bytes([0xCD] * 32),
        source_chain=1,
        target_chain=100,
        source_height=42,
    )


def test_round_trip_works() -> None:
    old_hash = bytes([0xAB] * 32)
    pk, sk = MLDSA.keygen()
    stmt = _statement(old_hash)
    proof = prove_rotation(stmt, expected_old_doc_hash=old_hash, signing_method_id=0, sk=sk)
    recovered = verify_rotation_proof(proof, expected_old_doc_hash=old_hash, method_pk=pk)
    assert recovered == stmt


def test_old_doc_hash_mismatch_rejected() -> None:
    old_hash = bytes([0xAB] * 32)
    pk, sk = MLDSA.keygen()
    stmt = _statement(old_hash)
    with pytest.raises(OldDocHashMismatch):
        prove_rotation(
            stmt, expected_old_doc_hash=bytes([0xFF] * 32), signing_method_id=0, sk=sk
        )


def test_tampered_new_hash_breaks_verification() -> None:
    old_hash = bytes([0xAB] * 32)
    pk, sk = MLDSA.keygen()
    stmt = _statement(old_hash)
    proof = prove_rotation(stmt, expected_old_doc_hash=old_hash, signing_method_id=0, sk=sk)

    tampered_stmt = DidRotationStatement(
        did=stmt.did,
        old_doc_hash=stmt.old_doc_hash,
        new_doc_hash=bytes([stmt.new_doc_hash[0] ^ 1]) + stmt.new_doc_hash[1:],
        source_chain=stmt.source_chain,
        target_chain=stmt.target_chain,
        source_height=stmt.source_height,
    )
    tampered_proof = proof.__class__(
        statement=tampered_stmt,
        signing_method_id=proof.signing_method_id,
        signature=proof.signature,
        fri_proof=proof.fri_proof,
    )
    with pytest.raises(DidStarkInvalidSignature):
        verify_rotation_proof(tampered_proof, expected_old_doc_hash=old_hash, method_pk=pk)


def test_cross_chain_binding_in_digest() -> None:
    # Changing target_chain must change the digest so the signature won't
    # cross-validate. This mirrors the Rust `cross_chain_binding_in_digest`
    # test.
    a = _statement(bytes(32))
    b = DidRotationStatement(
        did=a.did,
        old_doc_hash=a.old_doc_hash,
        new_doc_hash=a.new_doc_hash,
        source_chain=a.source_chain,
        target_chain=a.target_chain + 1,
        source_height=a.source_height,
    )
    assert a.digest() != b.digest()
