"""Cross-language JSON wire format for corridor types.

This is the canonical encoding used when transmitting `CorridorAttestation`,
`StateAnchor`, `Commitment`, `DidRotationStatement`, and `DidStarkProof`
between Python LTP and Rust suwappu-dag/suwappu-db over a JSON transport.

Design choices:

- **Bytes are hex-encoded strings** (no `0x` prefix). Avoids serde_json's
  default of encoding `Vec<u8>` as an array of u8 numbers, which is verbose
  (~3x bloat) and hard to read. The Rust side must wire its byte fields
  with `#[serde(with = "hex")]` or use `serde_bytes` + a base16 wrapper.
- **Sets are sorted JSON arrays** of u32 ids (`BTreeSet<u32>` → `[0,1,2]`).
- **Enums are integer discriminants** (matching `#[repr(u8)]` order),
  not variant-name strings. This pins the wire byte for `AuthScheme` and
  makes Solidity/Rust/Python all agree on `0=Blake3Mac`, `1=Sp1ZkProof`,
  etc.
- **Field names are snake_case** — matches Rust defaults and Python style.

If you need to interop with a Rust serializer that uses serde_json defaults
(byte arrays, variant names), call `*_to_serde_default_dict` instead — those
mirror serde's out-of-the-box format and are provided for completeness.
"""

from __future__ import annotations

from typing import Any

from .attestation import (
    AttestationPayload,
    Corridor,
    CorridorAttestation,
    SuperNode,
    WitnessSignature,
)
from .da import Cid, Commitment, DaSla
from .did_stark import DidRotationStatement, DidStarkProof
from .state_anchor import AuthScheme, StateAnchor


class WireFormatError(ValueError):
    """Raised when a JSON wire-format dict fails validation.

    All ``*_from_dict`` deserializers raise this on malformed input
    (missing fields, non-hex strings, wrong-length byte fields,
    out-of-range integers) so callers can distinguish wire-format
    errors from downstream cryptographic failures.
    """


# Fixed-size byte fields per the cross-language protocol (see
# `src/ltp/corridor/constants.py` and the matching Rust crate).
_SIZE_BLS_SIGNATURE = 96
_SIZE_BLS_PUBLIC_KEY = 48
_SIZE_DIGEST_32 = 32


def _hex_bytes(d: dict[str, Any], field: str, expected: int | None = None) -> bytes:
    """Decode ``d[field]`` as hex; raise WireFormatError on any failure."""
    try:
        value = d[field]
    except KeyError as e:
        raise WireFormatError(f"missing field {field!r}") from e
    if not isinstance(value, str):
        raise WireFormatError(f"field {field!r} must be a hex string, got {type(value).__name__}")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as e:
        raise WireFormatError(f"field {field!r} is not valid hex: {e}") from e
    if expected is not None and len(decoded) != expected:
        raise WireFormatError(
            f"field {field!r} must decode to {expected} bytes, got {len(decoded)}"
        )
    return decoded


def _int_field(d: dict[str, Any], field: str, *, non_negative: bool = True) -> int:
    """Coerce ``d[field]`` to int; raise WireFormatError on failure."""
    try:
        raw = d[field]
    except KeyError as e:
        raise WireFormatError(f"missing field {field!r}") from e
    try:
        value = int(raw)
    except (TypeError, ValueError) as e:
        raise WireFormatError(f"field {field!r} is not an integer: {raw!r}") from e
    if non_negative and value < 0:
        raise WireFormatError(f"field {field!r} must be non-negative, got {value}")
    return value


def _dict_field(d: dict[str, Any], field: str) -> dict[str, Any]:
    try:
        value = d[field]
    except KeyError as e:
        raise WireFormatError(f"missing field {field!r}") from e
    if not isinstance(value, dict):
        raise WireFormatError(f"field {field!r} must be an object, got {type(value).__name__}")
    return value


def _list_field(d: dict[str, Any], field: str) -> list[Any]:
    try:
        value = d[field]
    except KeyError as e:
        raise WireFormatError(f"missing field {field!r}") from e
    if not isinstance(value, list):
        raise WireFormatError(f"field {field!r} must be a list, got {type(value).__name__}")
    return value


# ---------------------------------------------------------------------------
# Hex-string canonical wire (preferred)
# ---------------------------------------------------------------------------


def attestation_payload_to_dict(p: AttestationPayload) -> dict[str, Any]:
    return {
        "source_chain": p.source_chain,
        "target_chain": p.target_chain,
        "source_height": p.source_height,
        "state_root": p.state_root.hex(),
        "timestamp_round": p.timestamp_round,
    }


def attestation_payload_from_dict(d: dict[str, Any]) -> AttestationPayload:
    return AttestationPayload(
        source_chain=_int_field(d, "source_chain"),
        target_chain=_int_field(d, "target_chain"),
        source_height=_int_field(d, "source_height"),
        state_root=_hex_bytes(d, "state_root", _SIZE_DIGEST_32),
        timestamp_round=_int_field(d, "timestamp_round"),
    )


def witness_signature_to_dict(w: WitnessSignature) -> dict[str, Any]:
    return {"witness": w.witness, "signature": w.signature.hex()}


def witness_signature_from_dict(d: dict[str, Any]) -> WitnessSignature:
    return WitnessSignature(
        witness=_int_field(d, "witness"),
        signature=_hex_bytes(d, "signature", _SIZE_BLS_SIGNATURE),
    )


def corridor_attestation_to_dict(a: CorridorAttestation) -> dict[str, Any]:
    return {
        "payload": attestation_payload_to_dict(a.payload),
        "aggregate_signature": a.aggregate_signature.hex(),
        "signers": sorted(a.signers),
    }


def corridor_attestation_from_dict(d: dict[str, Any]) -> CorridorAttestation:
    signers_raw = _list_field(d, "signers")
    try:
        signers = frozenset(int(s) for s in signers_raw)
    except (TypeError, ValueError) as e:
        raise WireFormatError(f"signers must be a list of integers: {e}") from e
    return CorridorAttestation(
        payload=attestation_payload_from_dict(_dict_field(d, "payload")),
        aggregate_signature=_hex_bytes(d, "aggregate_signature", _SIZE_BLS_SIGNATURE),
        signers=signers,
    )


def super_node_to_dict(s: SuperNode) -> dict[str, Any]:
    return {
        "authority": s.authority,
        "corridor": s.corridor,
        "bls_public_key": s.bls_public_key.hex(),
        "pop": s.pop.hex(),
    }


def super_node_from_dict(d: dict[str, Any]) -> SuperNode:
    # ``pop`` is optional for backwards compatibility with pre-LTP-A-015
    # fixtures; supplied wires of length 96 are validated, missing or
    # empty ``pop`` defaults to ``b""``.
    pop_field: bytes = b""
    if "pop" in d and d["pop"]:
        pop_field = _hex_bytes(d, "pop", _SIZE_BLS_SIGNATURE)
    return SuperNode(
        authority=_int_field(d, "authority"),
        corridor=_int_field(d, "corridor"),
        bls_public_key=_hex_bytes(d, "bls_public_key", _SIZE_BLS_PUBLIC_KEY),
        pop=pop_field,
    )


def corridor_to_dict(c: Corridor) -> dict[str, Any]:
    return {"id": c.id, "members": [super_node_to_dict(m) for m in c.members]}


def corridor_from_dict(d: dict[str, Any]) -> Corridor:
    members_raw = _list_field(d, "members")
    members = []
    for i, m in enumerate(members_raw):
        if not isinstance(m, dict):
            raise WireFormatError(f"members[{i}] must be an object, got {type(m).__name__}")
        members.append(super_node_from_dict(m))
    return Corridor(id=_int_field(d, "id"), members=tuple(members))


def cid_to_dict(c: Cid) -> str:
    return c.value.hex()


def cid_from_dict(s: str) -> Cid:
    if not isinstance(s, str):
        raise WireFormatError(f"cid must be a hex string, got {type(s).__name__}")
    try:
        return Cid(bytes.fromhex(s))
    except ValueError as e:
        raise WireFormatError(f"cid is not valid hex: {e}") from e


def da_sla_to_dict(s: DaSla) -> dict[str, Any]:
    return {
        "retention_rounds": s.retention_rounds,
        "max_retrieval_latency_rounds": s.max_retrieval_latency_rounds,
    }


def da_sla_from_dict(d: dict[str, Any]) -> DaSla:
    return DaSla(
        retention_rounds=_int_field(d, "retention_rounds"),
        max_retrieval_latency_rounds=_int_field(d, "max_retrieval_latency_rounds"),
    )


def commitment_to_dict(c: Commitment) -> dict[str, Any]:
    return {
        "cid": cid_to_dict(c.cid),
        "size_bytes": c.size_bytes,
        "stored_at": c.stored_at,
        "sla": da_sla_to_dict(c.sla),
    }


def commitment_from_dict(d: dict[str, Any]) -> Commitment:
    if "cid" not in d:
        raise WireFormatError("missing field 'cid'")
    return Commitment(
        cid=cid_from_dict(d["cid"]),
        size_bytes=_int_field(d, "size_bytes"),
        stored_at=_int_field(d, "stored_at"),
        sla=da_sla_from_dict(_dict_field(d, "sla")),
    )


def did_rotation_statement_to_dict(s: DidRotationStatement) -> dict[str, Any]:
    return {
        "did": s.did.hex(),
        "old_doc_hash": s.old_doc_hash.hex(),
        "new_doc_hash": s.new_doc_hash.hex(),
        "source_chain": s.source_chain,
        "target_chain": s.target_chain,
        "source_height": s.source_height,
    }


def did_rotation_statement_from_dict(d: dict[str, Any]) -> DidRotationStatement:
    return DidRotationStatement(
        did=_hex_bytes(d, "did", _SIZE_DIGEST_32),
        old_doc_hash=_hex_bytes(d, "old_doc_hash", _SIZE_DIGEST_32),
        new_doc_hash=_hex_bytes(d, "new_doc_hash", _SIZE_DIGEST_32),
        source_chain=_int_field(d, "source_chain"),
        target_chain=_int_field(d, "target_chain"),
        source_height=_int_field(d, "source_height"),
    )


def did_stark_proof_to_dict(p: DidStarkProof) -> dict[str, Any]:
    return {
        "statement": did_rotation_statement_to_dict(p.statement),
        "signing_method_id": p.signing_method_id,
        "signature": p.signature.hex(),
        "fri_proof": p.fri_proof.hex(),
    }


def did_stark_proof_from_dict(d: dict[str, Any]) -> DidStarkProof:
    return DidStarkProof(
        statement=did_rotation_statement_from_dict(_dict_field(d, "statement")),
        signing_method_id=_int_field(d, "signing_method_id"),
        signature=_hex_bytes(d, "signature"),
        fri_proof=_hex_bytes(d, "fri_proof"),
    )


def state_anchor_to_dict(a: StateAnchor) -> dict[str, Any]:
    return {
        "chain_id": a.chain_id,
        "height": a.height,
        "state_root": a.state_root.hex(),
        "parent": a.parent.hex(),
        "mac": a.mac.hex(),
        # Integer discriminant — matches the Rust `#[repr(u8)]` wire byte
        # and the Solidity uint8 field.
        "auth_scheme": int(a.auth_scheme),
    }


def state_anchor_from_dict(d: dict[str, Any]) -> StateAnchor:
    auth_scheme_raw = _int_field(d, "auth_scheme")
    try:
        auth_scheme = AuthScheme(auth_scheme_raw)
    except ValueError as e:
        raise WireFormatError(f"auth_scheme {auth_scheme_raw} is not a valid AuthScheme") from e
    return StateAnchor(
        chain_id=_int_field(d, "chain_id"),
        height=_int_field(d, "height"),
        state_root=_hex_bytes(d, "state_root", _SIZE_DIGEST_32),
        parent=_hex_bytes(d, "parent", _SIZE_DIGEST_32),
        mac=_hex_bytes(d, "mac"),
        auth_scheme=auth_scheme,
    )


# ---------------------------------------------------------------------------
# Serde-default mirrors (byte arrays, variant names)
# ---------------------------------------------------------------------------


def attestation_payload_to_serde_default_dict(p: AttestationPayload) -> dict[str, Any]:
    """Mirror of `serde_json::to_string(&AttestationPayload)` defaults.

    Byte fields are emitted as JSON arrays of u8 numbers. Use this only when
    interoperating with a Rust serializer that has not opted into the
    `#[serde(with = "hex")]` annotation.
    """
    return {
        "source_chain": p.source_chain,
        "target_chain": p.target_chain,
        "source_height": p.source_height,
        "state_root": list(p.state_root),
        "timestamp_round": p.timestamp_round,
    }


def corridor_attestation_to_serde_default_dict(a: CorridorAttestation) -> dict[str, Any]:
    return {
        "payload": attestation_payload_to_serde_default_dict(a.payload),
        "aggregate_signature": list(a.aggregate_signature),
        "signers": sorted(a.signers),
    }
