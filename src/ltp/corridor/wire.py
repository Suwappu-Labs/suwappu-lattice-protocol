"""Cross-language JSON wire format for corridor types.

This is the canonical encoding used when transmitting `CorridorAttestation`,
`StateAnchor`, `Commitment`, `DidRotationStatement`, and `DidStarkProof`
between Python LTP and Rust gsx-dag/gsx-db over a JSON transport.

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
        source_chain=int(d["source_chain"]),
        target_chain=int(d["target_chain"]),
        source_height=int(d["source_height"]),
        state_root=bytes.fromhex(d["state_root"]),
        timestamp_round=int(d["timestamp_round"]),
    )


def witness_signature_to_dict(w: WitnessSignature) -> dict[str, Any]:
    return {"witness": w.witness, "signature": w.signature.hex()}


def witness_signature_from_dict(d: dict[str, Any]) -> WitnessSignature:
    return WitnessSignature(
        witness=int(d["witness"]),
        signature=bytes.fromhex(d["signature"]),
    )


def corridor_attestation_to_dict(a: CorridorAttestation) -> dict[str, Any]:
    return {
        "payload": attestation_payload_to_dict(a.payload),
        "aggregate_signature": a.aggregate_signature.hex(),
        "signers": sorted(a.signers),
    }


def corridor_attestation_from_dict(d: dict[str, Any]) -> CorridorAttestation:
    return CorridorAttestation(
        payload=attestation_payload_from_dict(d["payload"]),
        aggregate_signature=bytes.fromhex(d["aggregate_signature"]),
        signers=frozenset(int(s) for s in d["signers"]),
    )


def super_node_to_dict(s: SuperNode) -> dict[str, Any]:
    return {
        "authority": s.authority,
        "corridor": s.corridor,
        "bls_public_key": s.bls_public_key.hex(),
    }


def super_node_from_dict(d: dict[str, Any]) -> SuperNode:
    return SuperNode(
        authority=int(d["authority"]),
        corridor=int(d["corridor"]),
        bls_public_key=bytes.fromhex(d["bls_public_key"]),
    )


def corridor_to_dict(c: Corridor) -> dict[str, Any]:
    return {"id": c.id, "members": [super_node_to_dict(m) for m in c.members]}


def corridor_from_dict(d: dict[str, Any]) -> Corridor:
    return Corridor(
        id=int(d["id"]),
        members=tuple(super_node_from_dict(m) for m in d["members"]),
    )


def cid_to_dict(c: Cid) -> str:
    return c.value.hex()


def cid_from_dict(s: str) -> Cid:
    return Cid(bytes.fromhex(s))


def da_sla_to_dict(s: DaSla) -> dict[str, Any]:
    return {
        "retention_rounds": s.retention_rounds,
        "max_retrieval_latency_rounds": s.max_retrieval_latency_rounds,
    }


def da_sla_from_dict(d: dict[str, Any]) -> DaSla:
    return DaSla(
        retention_rounds=int(d["retention_rounds"]),
        max_retrieval_latency_rounds=int(d["max_retrieval_latency_rounds"]),
    )


def commitment_to_dict(c: Commitment) -> dict[str, Any]:
    return {
        "cid": cid_to_dict(c.cid),
        "size_bytes": c.size_bytes,
        "stored_at": c.stored_at,
        "sla": da_sla_to_dict(c.sla),
    }


def commitment_from_dict(d: dict[str, Any]) -> Commitment:
    return Commitment(
        cid=cid_from_dict(d["cid"]),
        size_bytes=int(d["size_bytes"]),
        stored_at=int(d["stored_at"]),
        sla=da_sla_from_dict(d["sla"]),
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
        did=bytes.fromhex(d["did"]),
        old_doc_hash=bytes.fromhex(d["old_doc_hash"]),
        new_doc_hash=bytes.fromhex(d["new_doc_hash"]),
        source_chain=int(d["source_chain"]),
        target_chain=int(d["target_chain"]),
        source_height=int(d["source_height"]),
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
        statement=did_rotation_statement_from_dict(d["statement"]),
        signing_method_id=int(d["signing_method_id"]),
        signature=bytes.fromhex(d["signature"]),
        fri_proof=bytes.fromhex(d["fri_proof"]),
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
    return StateAnchor(
        chain_id=int(d["chain_id"]),
        height=int(d["height"]),
        state_root=bytes.fromhex(d["state_root"]),
        parent=bytes.fromhex(d["parent"]),
        mac=bytes.fromhex(d["mac"]),
        auth_scheme=AuthScheme(int(d["auth_scheme"])),
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
