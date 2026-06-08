"""LTP Commitment-Node data-availability SLA (paper §10.2).

Wire-compatible Python mirror of `suwappu-dag/crates/suwappu-ltp/src/da.rs`. The
constant 1,600-byte on-chain commitment of paper §10.2 leaves the variable-
size payload off-chain on Commitment Nodes addressed by SHA3-256 CID. The SLA
predicate bounds retention and retrieval latency, and surfaces breach reasons
that downstream slashing can consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .constants import DOMAIN_TAG_CID
from .digest import sha3_256_domain


class DaError(Exception):
    """Base class for DA SLA errors."""


class CommitmentNotFound(DaError):
    def __init__(self) -> None:
        super().__init__("commitment not found for cid")


class PayloadMismatch(DaError):
    def __init__(self) -> None:
        super().__init__("payload mismatch: cid disagreement")


class RetentionExpired(DaError):
    def __init__(self, expired_at: int) -> None:
        super().__init__(f"retention expired at round {expired_at}")
        self.expired_at = expired_at


class LatencyExceeded(DaError):
    def __init__(self, requested_at: int, responded_at: int, max_latency: int) -> None:
        super().__init__(
            f"retrieval latency exceeded: responded {responded_at}, "
            f"requested {requested_at}, max latency {max_latency}"
        )
        self.requested_at = requested_at
        self.responded_at = responded_at
        self.max_latency = max_latency


@dataclass(frozen=True, order=True)
class Cid:
    """SHA3-256 content identifier under the SUWAPPU-LTP-CID-V1 tag."""

    value: bytes

    def __post_init__(self) -> None:
        if len(self.value) != 32:
            raise ValueError("CID must be 32 bytes")

    @classmethod
    def of(cls, payload: bytes) -> "Cid":
        return cls(sha3_256_domain(DOMAIN_TAG_CID, payload))

    def hex(self) -> str:
        return self.value.hex()


@dataclass(frozen=True)
class DaSla:
    """Per-commitment DA service-level agreement."""

    retention_rounds: int
    max_retrieval_latency_rounds: int


# Default phase-1 SLA — matches `DaSla::DEFAULT` in the Rust crate.
DA_SLA_DEFAULT = DaSla(retention_rounds=100_000, max_retrieval_latency_rounds=16)


@dataclass(frozen=True)
class Commitment:
    """A commitment hosted on the Commitment Node network."""

    cid: Cid
    size_bytes: int
    stored_at: int
    sla: DaSla

    def retention_until(self) -> int:
        # Saturating add — mirror the Rust `saturating_add` behavior.
        s = self.stored_at + self.sla.retention_rounds
        return min(s, (1 << 64) - 1)

    def retention_expired(self, now: int) -> bool:
        return now > self.retention_until()


def verify_sla(
    commitment: Commitment,
    requested_at: int,
    responded_at: int,
    payload_returned: bytes,
) -> None:
    """Verify a retrieval response against the commitment's SLA.

    SLA pass iff:
      - `responded_at` is within the retention window,
      - `responded_at - requested_at <= sla.max_retrieval_latency_rounds`, and
      - `Cid.of(payload_returned) == commitment.cid`.
    """
    if responded_at > commitment.retention_until():
        raise RetentionExpired(commitment.retention_until())
    latency = max(0, responded_at - requested_at)
    if latency > commitment.sla.max_retrieval_latency_rounds:
        raise LatencyExceeded(
            requested_at, responded_at, commitment.sla.max_retrieval_latency_rounds
        )
    if Cid.of(payload_returned) != commitment.cid:
        raise PayloadMismatch()


@dataclass
class CommitmentNetwork:
    """In-memory Commitment Node network for tests and phase-1 deployments."""

    _commitments: dict[Cid, Commitment] = field(default_factory=dict)
    _payloads: dict[Cid, bytes] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self._commitments)

    def is_empty(self) -> bool:
        return not self._commitments

    def store(self, payload: bytes, sla: DaSla, now: int) -> Cid:
        cid = Cid.of(payload)
        self._payloads[cid] = bytes(payload)
        self._commitments[cid] = Commitment(
            cid=cid,
            size_bytes=len(payload),
            stored_at=now,
            sla=sla,
        )
        return cid

    def retrieve(self, cid: Cid) -> tuple[Commitment, bytes]:
        commitment = self._commitments.get(cid)
        payload = self._payloads.get(cid)
        if commitment is None or payload is None:
            raise CommitmentNotFound()
        return commitment, payload

    def prune_expired(self, now: int) -> int:
        expired = [c for c, m in self._commitments.items() if m.retention_expired(now)]
        for c in expired:
            self._commitments.pop(c, None)
            self._payloads.pop(c, None)
        return len(expired)

    def get(self, cid: Cid) -> Optional[Commitment]:
        return self._commitments.get(cid)
