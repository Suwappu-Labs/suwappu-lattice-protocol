"""LTP corridor super-node attestation (paper §10).

Wire-compatible Python mirror of `suwappu-dag/crates/suwappu-ltp/src/attestation.rs`.
A `CorridorAttestation` produced here serializes to the same canonical digest
the Rust crate signs and verifies against, so a Python corridor witness can
participate in a 7-of-9 attestation alongside Rust validators.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .bls import (
    corridor_aggregate_signatures,
    corridor_aggregate_verify,
    corridor_verify,
)
from .constants import (
    DOMAIN_TAG_ATTEST,
    LTP_ATTESTATION_QUORUM_SIZE,
    LTP_ATTESTATION_QUORUM_THRESHOLD,
)
from .digest import sha3_256_domain

CorridorId = int
ChainId = int
AuthorityId = int


class LtpError(Exception):
    """Base error for corridor attestation."""


class BadCorridorSize(LtpError):
    def __init__(self, expected: int, got: int) -> None:
        super().__init__(f"corridor must have exactly {expected} members, got {got}")
        self.expected = expected
        self.got = got


class BelowQuorum(LtpError):
    def __init__(self, have: int, need: int) -> None:
        super().__init__(f"ltp quorum below threshold: have {have}, need {need}")
        self.have = have
        self.need = need


class UnknownWitness(LtpError):
    def __init__(self, witness: AuthorityId) -> None:
        super().__init__(f"signature from unknown witness {witness}")
        self.witness = witness


class InvalidSignature(LtpError):
    def __init__(self, witness: AuthorityId) -> None:
        super().__init__(f"invalid signature from witness {witness}")
        self.witness = witness


class AggregateVerificationFailed(LtpError):
    def __init__(self) -> None:
        super().__init__("aggregate signature verification failed")


@dataclass(frozen=True)
class SuperNode:
    """A corridor super-node — paper §9 Definition 4 role 2.

    `bls_public_key` is the compressed G1 (48-byte) BLS12-381 public key.
    `pop` is the Proof-of-Possession: a 96-byte BLS signature over the
    `bls_public_key` bytes under ``DOMAIN_TAG_CORRIDOR_POP``. Default is
    empty for backwards compatibility with existing test fixtures; new
    deployments MUST supply a real PoP and call ``Corridor.verify_pops()``
    before trusting the member set. See LTP-A-015 in the security audit.
    """

    authority: AuthorityId
    corridor: CorridorId
    bls_public_key: bytes
    pop: bytes = b""


class CorridorPopVerificationFailed(LtpError):
    def __init__(self, authority: AuthorityId) -> None:
        super().__init__(f"PoP verification failed for super-node {authority}")
        self.authority = authority


@dataclass(frozen=True)
class Corridor:
    """Exactly `LTP_ATTESTATION_QUORUM_SIZE` super-nodes with distinct ids."""

    id: CorridorId
    members: tuple[SuperNode, ...]

    def member_pubkey(self, authority: AuthorityId) -> Optional[bytes]:
        for m in self.members:
            if m.authority == authority:
                return m.bls_public_key
        return None

    def verify_pops(self) -> None:
        """Verify every member's Proof-of-Possession.

        Closes LTP-A-015 at the *registration* surface (the verify-time
        manual G1 aggregation in ``corridor/bls.py`` is the static-set
        defense; this is the adaptive-attacker defense).

        Raises ``CorridorPopVerificationFailed`` on the first bad PoP.
        A member with an empty ``pop`` is rejected — this method is the
        opt-in security gate, callers can skip it for legacy test fixtures.
        """
        from .bls import corridor_verify
        from .constants import DOMAIN_TAG_CORRIDOR_POP

        for m in self.members:
            if not m.pop or len(m.pop) != 96:
                raise CorridorPopVerificationFailed(m.authority)
            # The PoP signs (DOMAIN_TAG_CORRIDOR_POP || pk_bytes) so a
            # rogue key can't reuse a non-PoP signature for this slot.
            msg = DOMAIN_TAG_CORRIDOR_POP + m.bls_public_key
            ok = corridor_verify(m.bls_public_key, msg, m.pop)
            if not ok:
                raise CorridorPopVerificationFailed(m.authority)


@dataclass(frozen=True)
class AttestationPayload:
    """Source-chain finality observation signed by the corridor."""

    source_chain: ChainId
    target_chain: ChainId
    source_height: int
    state_root: bytes  # exactly 32 bytes
    timestamp_round: int

    def __post_init__(self) -> None:
        if len(self.state_root) != 32:
            raise ValueError("state_root must be 32 bytes")
        for name in ("source_chain", "target_chain", "source_height", "timestamp_round"):
            v = getattr(self, name)
            if v < 0:
                raise ValueError(f"{name} must be non-negative")

    def canonical_digest(self) -> bytes:
        """SHA3-256(len(tag) || tag || src||tgt||height||state_root||ts) — byte-exact match for the Rust crate."""
        blob = b"".join(
            [
                self.source_chain.to_bytes(8, "big"),
                self.target_chain.to_bytes(8, "big"),
                self.source_height.to_bytes(8, "big"),
                self.state_root,
                self.timestamp_round.to_bytes(8, "big"),
            ]
        )
        return sha3_256_domain(DOMAIN_TAG_ATTEST, blob)


@dataclass(frozen=True)
class WitnessSignature:
    """A single witness's 96-byte BLS12-381 signature over the canonical digest."""

    witness: AuthorityId
    signature: bytes


@dataclass(frozen=True)
class CorridorAttestation:
    """7-of-9 aggregated corridor attestation."""

    payload: AttestationPayload
    aggregate_signature: bytes
    signers: frozenset[AuthorityId] = field(default_factory=frozenset)


def _require_corridor_size(corridor: Corridor) -> None:
    if len(corridor.members) != LTP_ATTESTATION_QUORUM_SIZE:
        raise BadCorridorSize(LTP_ATTESTATION_QUORUM_SIZE, len(corridor.members))


def attest(
    corridor: Corridor,
    payload: AttestationPayload,
    signatures: Iterable[WitnessSignature],
) -> CorridorAttestation:
    """Aggregate per-witness signatures into a `CorridorAttestation`.

    Validation order (matches the Rust crate):
      1. Corridor size is 9.
      2. Every signing witness is a corridor member.
      3. Distinct signer count meets the 7 threshold.
      4. Each individual signature verifies over `payload.canonical_digest()`.
      5. Aggregate signature is computed and re-verified.
    """
    _require_corridor_size(corridor)

    digest = payload.canonical_digest()

    seen: set[AuthorityId] = set()
    sigs: list[bytes] = []
    pks: list[bytes] = []
    for ws in signatures:
        if ws.witness in seen:
            continue
        pk = corridor.member_pubkey(ws.witness)
        if pk is None:
            raise UnknownWitness(ws.witness)
        if not corridor_verify(pk, digest, ws.signature):
            raise InvalidSignature(ws.witness)
        seen.add(ws.witness)
        sigs.append(ws.signature)
        pks.append(pk)

    if len(seen) < LTP_ATTESTATION_QUORUM_THRESHOLD:
        raise BelowQuorum(len(seen), LTP_ATTESTATION_QUORUM_THRESHOLD)

    agg = corridor_aggregate_signatures(sigs)
    if not corridor_aggregate_verify(pks, digest, agg):
        raise AggregateVerificationFailed()

    return CorridorAttestation(
        payload=payload,
        aggregate_signature=agg,
        signers=frozenset(seen),
    )


def verify_attestation(corridor: Corridor, attestation: CorridorAttestation) -> None:
    """Verify a `CorridorAttestation` against the corridor membership.

    Raises an `LtpError` subclass on any failure; returns `None` on success.
    """
    _require_corridor_size(corridor)
    if len(attestation.signers) < LTP_ATTESTATION_QUORUM_THRESHOLD:
        raise BelowQuorum(len(attestation.signers), LTP_ATTESTATION_QUORUM_THRESHOLD)

    pks: list[bytes] = []
    for signer in sorted(attestation.signers):
        pk = corridor.member_pubkey(signer)
        if pk is None:
            raise UnknownWitness(signer)
        pks.append(pk)

    digest = attestation.payload.canonical_digest()
    if not corridor_aggregate_verify(pks, digest, attestation.aggregate_signature):
        raise AggregateVerificationFailed()
