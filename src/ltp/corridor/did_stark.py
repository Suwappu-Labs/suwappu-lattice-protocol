"""Cross-chain DID rotation STARK statement (paper §10.3).

Wire-compatible Python mirror of `suwappu-dag/crates/suwappu-ltp/src/did_stark.rs`.
The load-bearing part for the cross-repo wire is `DidRotationStatement.digest()`
— SHA3-256 with the `SUWAPPU-DID-STARK-V1` domain tag over a fixed byte layout.

The DID-document object graph (verification methods, relationships) lives in
`suwappu-precompiles` on the Rust side and has no Python mirror yet, so this
module exposes a minimal phase-1 proof that carries an ML-DSA-65 detached
signature over the statement digest. Caller is responsible for binding
`old_doc_hash`/`new_doc_hash` to the documents the rotation installs; a future
`ltp.did` module will own the document graph once suwappu-precompiles is ported.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..primitives import MLDSA
from .constants import DOMAIN_TAG_DID_STARK
from .did_doc import (
    DidDocument,
    VerificationMethodId,
    VerificationRelationship,
)
from .digest import sha3_256_domain


class DidStarkError(Exception):
    """Base class for DID rotation proof errors."""


class OldDocHashMismatch(DidStarkError):
    def __init__(self) -> None:
        super().__init__("old document hash in statement does not match supplied hash")


class InvalidSignature(DidStarkError):
    def __init__(self) -> None:
        super().__init__("signature verification failed")


@dataclass(frozen=True)
class DidRotationStatement:
    """Public input to the rotation proof — byte layout matches the Rust crate."""

    did: bytes  # exactly 32 bytes
    old_doc_hash: bytes  # exactly 32 bytes
    new_doc_hash: bytes  # exactly 32 bytes
    source_chain: int
    target_chain: int
    source_height: int

    def __post_init__(self) -> None:
        for name, value in (
            ("did", self.did),
            ("old_doc_hash", self.old_doc_hash),
            ("new_doc_hash", self.new_doc_hash),
        ):
            if len(value) != 32:
                raise ValueError(f"{name} must be 32 bytes")
        for name in ("source_chain", "target_chain", "source_height"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")

    def digest(self) -> bytes:
        """SHA3-256(len(tag) || tag || did || old || new || src || tgt || height)."""
        blob = b"".join(
            [
                self.did,
                self.old_doc_hash,
                self.new_doc_hash,
                self.source_chain.to_bytes(8, "big"),
                self.target_chain.to_bytes(8, "big"),
                self.source_height.to_bytes(8, "big"),
            ]
        )
        return sha3_256_domain(DOMAIN_TAG_DID_STARK, blob)


@dataclass(frozen=True)
class DidStarkProof:
    """Phase-1 proof: ML-DSA-65 detached signature over the statement digest.

    Production replaces `signature` with an SP1/Plonky3 FRI proof; the public
    statement remains identical.
    """

    statement: DidRotationStatement
    signing_method_id: int
    signature: bytes
    fri_proof: bytes = b""


def prove_rotation(
    statement: DidRotationStatement,
    expected_old_doc_hash: bytes,
    signing_method_id: int,
    sk: bytes,
) -> DidStarkProof:
    """Sign `statement.digest()` with `sk` once the old-doc binding holds.

    Caller supplies `expected_old_doc_hash` (the canonical hash of the old
    DID document) and the ML-DSA-65 secret key of the verification method
    selected. Method-id authorization (`CapabilityInvocation` membership) is
    the caller's responsibility on the Python side until the suwappu-precompiles
    document graph is mirrored.
    """
    if statement.old_doc_hash != expected_old_doc_hash:
        raise OldDocHashMismatch()
    sig = MLDSA.sign(sk, statement.digest())
    return DidStarkProof(
        statement=statement,
        signing_method_id=signing_method_id,
        signature=sig,
        fri_proof=b"",
    )


def verify_rotation_proof(
    proof: DidStarkProof,
    expected_old_doc_hash: bytes,
    method_pk: bytes,
) -> DidRotationStatement:
    """Verify the rotation proof against the old document's method public key."""
    if proof.statement.old_doc_hash != expected_old_doc_hash:
        raise OldDocHashMismatch()
    if not MLDSA.verify(method_pk, proof.statement.digest(), proof.signature):
        raise InvalidSignature()
    return proof.statement


class UnknownMethod(DidStarkError):
    def __init__(self, method_id: VerificationMethodId) -> None:
        super().__init__(f"signing method id {method_id} not in old document")
        self.method_id = method_id


class UnauthorizedMethod(DidStarkError):
    def __init__(self, method_id: VerificationMethodId) -> None:
        super().__init__(f"signing method id {method_id} lacks CapabilityInvocation")
        self.method_id = method_id


def prove_rotation_with_doc(
    statement: DidRotationStatement,
    old_doc: DidDocument,
    signing_method_id: VerificationMethodId,
    sk: bytes,
) -> DidStarkProof:
    """Convenience wrapper that derives `old_doc_hash` from `old_doc` and
    enforces the suwappu-precompiles authorization predicates (method existence +
    CapabilityInvocation membership).
    """
    if statement.old_doc_hash != old_doc.canonical_hash():
        raise OldDocHashMismatch()
    if old_doc.public_key(signing_method_id) is None:
        raise UnknownMethod(signing_method_id)
    if not old_doc.has_relationship(
        signing_method_id, VerificationRelationship.CAPABILITY_INVOCATION
    ):
        raise UnauthorizedMethod(signing_method_id)
    sig = MLDSA.sign(sk, statement.digest())
    return DidStarkProof(
        statement=statement,
        signing_method_id=signing_method_id,
        signature=sig,
        fri_proof=b"",
    )


def verify_rotation_proof_with_doc(
    proof: DidStarkProof,
    old_doc: DidDocument,
) -> DidRotationStatement:
    """Verify against an `old_doc` that derives the public key and authorization
    predicates itself.
    """
    if proof.statement.old_doc_hash != old_doc.canonical_hash():
        raise OldDocHashMismatch()
    pk = old_doc.public_key(proof.signing_method_id)
    if pk is None:
        raise UnknownMethod(proof.signing_method_id)
    if not old_doc.has_relationship(
        proof.signing_method_id, VerificationRelationship.CAPABILITY_INVOCATION
    ):
        raise UnauthorizedMethod(proof.signing_method_id)
    if not MLDSA.verify(pk, proof.statement.digest(), proof.signature):
        raise InvalidSignature()
    return proof.statement
