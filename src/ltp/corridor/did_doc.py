"""DID document mirror — byte-compatible with `gsx-dag/crates/gsx-precompiles/src/did.rs`.

Phase-1 implements the canonical-hash and relationship-membership subset of
the gsx-precompiles DID document so `did_stark.prove_rotation` /
`verify_rotation_proof` can derive `old_doc_hash` themselves instead of
relying on the caller. Validation logic is provided in a minimal form;
production parity with the full Rust validator lands when the gsx-precompiles
crate is fully ported.

The canonical hash uses BLAKE3 (matching the Rust crate) with the
`GSX-DID-DOC-V1` domain tag and big-endian u32 length prefixes for every
variable-length field. Discriminant bytes for relationships and key
algorithms are pinned:

| Field | Byte |
|---|---|
| `KeyAlgorithm::MlDsa65` | `0x01` |
| `VerificationRelationship::Authentication` | `0x01` |
| `VerificationRelationship::AssertionMethod` | `0x02` |
| `VerificationRelationship::KeyAgreement` | `0x03` |
| `VerificationRelationship::CapabilityInvocation` | `0x04` |
| `VerificationRelationship::CapabilityDelegation` | `0x05` |
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

try:  # pragma: no cover — optional dependency
    import blake3 as _blake3
    _blake3_available = True
except ImportError:
    _blake3 = None
    _blake3_available = False


VerificationMethodId = int  # u32


class KeyAlgorithm(IntEnum):
    ML_DSA_65 = 0x01


class VerificationRelationship(IntEnum):
    AUTHENTICATION = 0x01
    ASSERTION_METHOD = 0x02
    KEY_AGREEMENT = 0x03
    CAPABILITY_INVOCATION = 0x04
    CAPABILITY_DELEGATION = 0x05


class DidError(Exception):
    """Base class for DID document validation errors."""


class NullDid(DidError):
    pass


class DuplicateMethodId(DidError):
    def __init__(self, method_id: VerificationMethodId) -> None:
        super().__init__(f"duplicate verification method id {method_id}")
        self.method_id = method_id


class CrossDidController(DidError):
    def __init__(self, method: VerificationMethodId, controller: bytes) -> None:
        super().__init__(
            f"method {method} has controller {controller.hex()} that is not the document id"
        )
        self.method = method
        self.controller = controller


class DanglingRelationship(DidError):
    def __init__(self, relationship: VerificationRelationship, method: VerificationMethodId) -> None:
        super().__init__(
            f"relationship {relationship.name} references unknown method {method}"
        )
        self.relationship = relationship
        self.method = method


@dataclass(frozen=True)
class VerificationMethod:
    """A public-key verification method on the DID."""

    id: VerificationMethodId
    controller: bytes  # 32-byte DID
    algorithm: KeyAlgorithm
    public_key: bytes

    def __post_init__(self) -> None:
        if len(self.controller) != 32:
            raise ValueError("controller must be 32 bytes")
        if self.id < 0 or self.id >= (1 << 32):
            raise ValueError("method id must fit in u32")


@dataclass(frozen=True)
class Service:
    id: int  # u32
    service_type: str
    endpoint: str


@dataclass(frozen=True)
class DidDocument:
    """W3C DID Core document; canonical-hash compatible with the Rust crate."""

    id: bytes  # 32-byte DID
    verification_methods: tuple[VerificationMethod, ...] = ()
    relationships: dict[VerificationRelationship, frozenset[VerificationMethodId]] = field(
        default_factory=dict
    )
    services: tuple[Service, ...] = ()

    def __post_init__(self) -> None:
        if len(self.id) != 32:
            raise ValueError("DID id must be 32 bytes")

    def canonical_hash(self) -> bytes:
        """BLAKE3 canonical hash matching `gsx-precompiles::DidDocument::canonical_hash`."""
        if not _blake3_available:
            raise RuntimeError(
                "blake3 library not installed; install with `pip install blake3`"
            )
        h = _blake3.blake3()
        h.update(b"GSX-DID-DOC-V1")
        h.update(self.id)

        # Verification methods (insertion order preserved on Python side;
        # caller is responsible for matching Rust insertion order).
        h.update(len(self.verification_methods).to_bytes(4, "big"))
        for vm in self.verification_methods:
            h.update(vm.id.to_bytes(4, "big"))
            h.update(vm.controller)
            h.update(bytes([int(vm.algorithm)]))
            h.update(len(vm.public_key).to_bytes(4, "big"))
            h.update(vm.public_key)

        # Relationships — BTreeMap iteration is sorted by key. Iterate the
        # Python dict in the canonical enum-discriminant order to match.
        sorted_rels = sorted(self.relationships.items(), key=lambda kv: int(kv[0]))
        h.update(len(sorted_rels).to_bytes(4, "big"))
        for rel, ids in sorted_rels:
            h.update(bytes([int(rel)]))
            h.update(len(ids).to_bytes(4, "big"))
            for method_id in sorted(ids):  # BTreeSet iteration is sorted
                h.update(method_id.to_bytes(4, "big"))

        # Services — Vec iteration is insertion order.
        h.update(len(self.services).to_bytes(4, "big"))
        for service in self.services:
            h.update(service.id.to_bytes(4, "big"))
            service_type_bytes = service.service_type.encode("utf-8")
            h.update(len(service_type_bytes).to_bytes(4, "big"))
            h.update(service_type_bytes)
            endpoint_bytes = service.endpoint.encode("utf-8")
            h.update(len(endpoint_bytes).to_bytes(4, "big"))
            h.update(endpoint_bytes)

        return h.digest()

    def public_key(self, method_id: VerificationMethodId) -> Optional[bytes]:
        for vm in self.verification_methods:
            if vm.id == method_id:
                return vm.public_key
        return None

    def has_relationship(
        self,
        method_id: VerificationMethodId,
        relationship: VerificationRelationship,
    ) -> bool:
        return method_id in self.relationships.get(relationship, frozenset())

    def validate(self) -> None:
        """Structural validation. Raises a `DidError` subclass on failure."""
        if self.id == bytes(32):
            raise NullDid("DID id cannot be all zeros")
        seen: set[VerificationMethodId] = set()
        for vm in self.verification_methods:
            if vm.id in seen:
                raise DuplicateMethodId(vm.id)
            seen.add(vm.id)
            if vm.controller != self.id:
                raise CrossDidController(vm.id, vm.controller)
        for rel, ids in self.relationships.items():
            for method_id in ids:
                if method_id not in seen:
                    raise DanglingRelationship(rel, method_id)

    @classmethod
    def empty(cls, did: bytes) -> "DidDocument":
        return cls(id=did)
