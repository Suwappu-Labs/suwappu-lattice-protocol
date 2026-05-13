"""DAG data structures for Mysticeti consensus (Spec D1a §1)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def _compute_block_digest(
    author: int,
    round: int,
    payload: tuple[bytes, ...],
    parents: frozenset[bytes],
) -> bytes:
    """SHA3-256(author || round || len(payload) || sorted(payload) || sorted(parents))."""
    h = hashlib.sha3_256()
    h.update(author.to_bytes(4, "big"))
    h.update(round.to_bytes(8, "big"))
    h.update(len(payload).to_bytes(4, "big"))
    for p in sorted(payload):
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    for parent in sorted(parents):
        h.update(len(parent).to_bytes(4, "big"))
        h.update(parent)
    return h.digest()


@dataclass(frozen=True)
class Block:
    """A single proposal from a validator."""

    author: int
    round: int
    payload: tuple[bytes, ...]
    parents: frozenset[bytes]
    timestamp_ms: int
    digest: bytes = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _compute_block_digest(self.author, self.round, self.payload, self.parents),
        )


@dataclass(frozen=True)
class Certificate:
    """A block with 2f+1 acknowledgments."""

    block: Block
    signers: frozenset[int]
    digest: bytes = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "digest", self.block.digest)


@dataclass(frozen=True)
class CommitDecision:
    """Output of the commit rule — a leader and its causal history."""

    leader_certificate: Certificate
    committed_blocks: list[Block]
    round: int


@dataclass(frozen=True)
class EquivocationProof:
    """Evidence that a validator proposed two conflicting blocks."""

    author: int
    block_a: Block
    block_b: Block
    round: int


@dataclass
class RoundState:
    """Tracks per-round progress within a validator's local view."""

    round: int
    proposals: dict[int, Block] = field(default_factory=dict)
    acks: dict[bytes, set[int]] = field(default_factory=dict)
    certificates: dict[int, Certificate] = field(default_factory=dict)
    timed_out: bool = False
