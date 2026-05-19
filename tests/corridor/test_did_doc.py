"""DID document canonical-hash parity with `gsx-precompiles::DidDocument`."""

from __future__ import annotations

import pytest

from ltp.corridor import (
    DidDocument,
    KeyAlgorithm,
    Service,
    VerificationMethod,
    VerificationRelationship,
    prove_rotation_with_doc,
    verify_rotation_proof_with_doc,
)
from ltp.corridor.did_doc import (
    CrossDidController,
    DanglingRelationship,
    DuplicateMethodId,
    NullDid,
)
from ltp.corridor.did_stark import (
    DidRotationStatement,
    OldDocHashMismatch,
    UnauthorizedMethod,
    UnknownMethod,
)
from ltp.primitives import MLDSA


def _blake3_available() -> bool:
    try:
        import blake3  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(not _blake3_available(), reason="blake3 library not installed")


def _make_doc_with_ci_method(did_seed: int) -> tuple[DidDocument, bytes, bytes]:
    did = bytes([did_seed] * 32)
    pk, sk = MLDSA.keygen()
    doc = DidDocument(
        id=did,
        verification_methods=(
            VerificationMethod(
                id=0,
                controller=did,
                algorithm=KeyAlgorithm.ML_DSA_65,
                public_key=pk,
            ),
        ),
        relationships={
            VerificationRelationship.CAPABILITY_INVOCATION: frozenset({0}),
        },
    )
    return doc, pk, sk


def test_canonical_hash_is_deterministic() -> None:
    doc, _, _ = _make_doc_with_ci_method(1)
    assert doc.canonical_hash() == doc.canonical_hash()


def test_canonical_hash_changes_with_methods() -> None:
    doc1, _, _ = _make_doc_with_ci_method(1)
    doc2, _, _ = _make_doc_with_ci_method(2)
    # Different DID seed → different doc id and method controller → different hash.
    assert doc1.canonical_hash() != doc2.canonical_hash()


def test_canonical_hash_changes_with_services() -> None:
    doc, _, _ = _make_doc_with_ci_method(1)
    with_service = DidDocument(
        id=doc.id,
        verification_methods=doc.verification_methods,
        relationships=doc.relationships,
        services=(Service(id=0, service_type="LinkedDomains", endpoint="https://gsn.com"),),
    )
    assert doc.canonical_hash() != with_service.canonical_hash()


def test_validate_rejects_null_did() -> None:
    doc = DidDocument(id=bytes(32))
    with pytest.raises(NullDid):
        doc.validate()


def test_validate_rejects_duplicate_method_id() -> None:
    did = bytes([1] * 32)
    pk, _ = MLDSA.keygen()
    pk2, _ = MLDSA.keygen()
    doc = DidDocument(
        id=did,
        verification_methods=(
            VerificationMethod(
                id=0, controller=did, algorithm=KeyAlgorithm.ML_DSA_65, public_key=pk
            ),
            VerificationMethod(
                id=0, controller=did, algorithm=KeyAlgorithm.ML_DSA_65, public_key=pk2
            ),
        ),
    )
    with pytest.raises(DuplicateMethodId):
        doc.validate()


def test_validate_rejects_cross_did_controller() -> None:
    did = bytes([1] * 32)
    other = bytes([2] * 32)
    pk, _ = MLDSA.keygen()
    doc = DidDocument(
        id=did,
        verification_methods=(
            VerificationMethod(
                id=0, controller=other, algorithm=KeyAlgorithm.ML_DSA_65, public_key=pk
            ),
        ),
    )
    with pytest.raises(CrossDidController):
        doc.validate()


def test_validate_rejects_dangling_relationship() -> None:
    did = bytes([1] * 32)
    pk, _ = MLDSA.keygen()
    doc = DidDocument(
        id=did,
        verification_methods=(
            VerificationMethod(
                id=0, controller=did, algorithm=KeyAlgorithm.ML_DSA_65, public_key=pk
            ),
        ),
        relationships={
            VerificationRelationship.CAPABILITY_INVOCATION: frozenset({99}),
        },
    )
    with pytest.raises(DanglingRelationship):
        doc.validate()


def test_prove_and_verify_rotation_with_doc() -> None:
    old_doc, _pk, sk = _make_doc_with_ci_method(1)
    new_hash = bytes([0xCD] * 32)
    stmt = DidRotationStatement(
        did=old_doc.id,
        old_doc_hash=old_doc.canonical_hash(),
        new_doc_hash=new_hash,
        source_chain=1,
        target_chain=100,
        source_height=42,
    )
    proof = prove_rotation_with_doc(stmt, old_doc, signing_method_id=0, sk=sk)
    recovered = verify_rotation_proof_with_doc(proof, old_doc)
    assert recovered == stmt


def test_unknown_method_rejected() -> None:
    old_doc, _pk, sk = _make_doc_with_ci_method(1)
    stmt = DidRotationStatement(
        did=old_doc.id,
        old_doc_hash=old_doc.canonical_hash(),
        new_doc_hash=bytes([0xCD] * 32),
        source_chain=1,
        target_chain=100,
        source_height=42,
    )
    with pytest.raises(UnknownMethod):
        prove_rotation_with_doc(stmt, old_doc, signing_method_id=99, sk=sk)


def test_method_without_capability_invocation_rejected() -> None:
    did = bytes([1] * 32)
    pk, sk = MLDSA.keygen()
    doc = DidDocument(
        id=did,
        verification_methods=(
            VerificationMethod(
                id=0, controller=did, algorithm=KeyAlgorithm.ML_DSA_65, public_key=pk
            ),
        ),
        # Authentication, but NOT CapabilityInvocation.
        relationships={
            VerificationRelationship.AUTHENTICATION: frozenset({0}),
        },
    )
    stmt = DidRotationStatement(
        did=doc.id,
        old_doc_hash=doc.canonical_hash(),
        new_doc_hash=bytes([0xCD] * 32),
        source_chain=1,
        target_chain=100,
        source_height=42,
    )
    with pytest.raises(UnauthorizedMethod):
        prove_rotation_with_doc(stmt, doc, signing_method_id=0, sk=sk)


def test_stale_old_doc_hash_rejected() -> None:
    old_doc, _pk, sk = _make_doc_with_ci_method(1)
    stmt = DidRotationStatement(
        did=old_doc.id,
        old_doc_hash=bytes([0xFF] * 32),  # wrong
        new_doc_hash=bytes([0xCD] * 32),
        source_chain=1,
        target_chain=100,
        source_height=42,
    )
    with pytest.raises(OldDocHashMismatch):
        prove_rotation_with_doc(stmt, old_doc, signing_method_id=0, sk=sk)
