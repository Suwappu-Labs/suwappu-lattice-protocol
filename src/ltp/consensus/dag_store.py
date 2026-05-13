"""DAGStore — indexed block and certificate storage (Spec D1a §2)."""

from __future__ import annotations

from collections import defaultdict

from .types import Block, Certificate


class DAGStore:
    """Per-validator indexed storage for DAG blocks and certificates.

    Blocks indexed by digest and by (round, author).
    Certificates indexed by (round, author) for commit rule lookups.
    """

    def __init__(self) -> None:
        self._blocks_by_digest: dict[bytes, Block] = {}
        self._blocks_by_round: dict[int, dict[int, Block]] = defaultdict(dict)
        self._certs_by_round: dict[int, dict[int, Certificate]] = defaultdict(dict)

    def add_block(self, block: Block) -> bool:
        """Store a block. Returns False if a block from same (round, author) already exists."""
        if block.author in self._blocks_by_round[block.round]:
            return False
        self._blocks_by_digest[block.digest] = block
        self._blocks_by_round[block.round][block.author] = block
        return True

    def get_block(self, digest: bytes) -> Block | None:
        """Retrieve a block by its digest."""
        return self._blocks_by_digest.get(digest)

    def blocks_at_round(self, round: int) -> list[Block]:
        """All blocks stored for a given round."""
        return list(self._blocks_by_round.get(round, {}).values())

    def add_certificate(self, cert: Certificate) -> None:
        """Store a certificate, indexed by (round, author)."""
        self._certs_by_round[cert.block.round][cert.block.author] = cert

    def get_certificate(self, author: int, round: int) -> Certificate | None:
        """Retrieve a certificate by (author, round)."""
        return self._certs_by_round.get(round, {}).get(author)

    def certificates_at_round(self, round: int) -> list[Certificate]:
        """All certificates at a given round."""
        return list(self._certs_by_round.get(round, {}).values())

    def has_quorum_certificates(self, round: int, quorum_threshold: int) -> bool:
        """Whether the round has at least quorum_threshold certificates."""
        return len(self._certs_by_round.get(round, {})) >= quorum_threshold
