"""MysticetiProtocol — pure protocol logic for a single validator (Spec D1a §2)."""

from __future__ import annotations

import time

from .types import Block, Certificate, CommitDecision, EquivocationProof, RoundState
from .dag_store import DAGStore
from .commit_rule import evaluate_direct_commit, evaluate_indirect_commit, collect_causal_history


class MysticetiProtocol:
    """Mysticeti DAG-BFT protocol state for one validator.

    Pure logic — receives messages, produces messages. No I/O.
    """

    def __init__(
        self,
        validator_index: int,
        num_validators: int,
        fault_tolerance: int | None = None,
    ) -> None:
        self._index = validator_index
        self._n = num_validators
        self._f = fault_tolerance if fault_tolerance is not None else (num_validators - 1) // 3
        self._quorum = 2 * self._f + 1
        self._dag = DAGStore()
        self._rounds: dict[int, RoundState] = {}
        self._equivocators: set[int] = set()
        self._committed_digests: set[bytes] = set()
        self._committed_rounds: set[int] = set()
        self._current_round = 0

    @property
    def dag_store(self) -> DAGStore:
        return self._dag

    @property
    def current_round(self) -> int:
        return self._current_round

    def _get_round_state(self, round: int) -> RoundState:
        if round not in self._rounds:
            self._rounds[round] = RoundState(round=round)
        return self._rounds[round]

    def leader_for_round(self, round: int) -> int:
        """Deterministic leader: round % n."""
        return round % self._n

    def propose(self, round: int, payload: tuple[bytes, ...] = ()) -> Block:
        """Create a block for this round, referencing known parent certs."""
        parents: frozenset[bytes]
        if round == 0:
            parents = frozenset()
        else:
            parent_certs = self._dag.certificates_at_round(round - 1)
            parents = frozenset(c.digest for c in parent_certs)
        block = Block(
            author=self._index,
            round=round,
            payload=payload,
            parents=parents,
            timestamp_ms=int(time.time() * 1000),
        )
        self._dag.add_block(block)
        rs = self._get_round_state(round)
        rs.proposals[self._index] = block
        # Author implicitly acks own block
        if block.digest not in rs.acks:
            rs.acks[block.digest] = set()
        rs.acks[block.digest].add(self._index)
        if round > self._current_round:
            self._current_round = round
        return block

    def receive_block(self, block: Block) -> int | None:
        """Validate and store block. Returns own index as ack, or None."""
        if block.author in self._equivocators:
            return None
        # Check for equivocation
        proof = self.detect_equivocation(block)
        if proof is not None:
            self._equivocators.add(block.author)
            return None
        added = self._dag.add_block(block)
        if not added:
            return None  # duplicate
        rs = self._get_round_state(block.round)
        rs.proposals[block.author] = block
        if block.digest not in rs.acks:
            rs.acks[block.digest] = set()
        rs.acks[block.digest].add(self._index)
        if block.round > self._current_round:
            self._current_round = block.round
        return self._index

    def receive_ack(self, block_digest: bytes, signer: int) -> Certificate | None:
        """Accumulate ack. Return Certificate when quorum reached."""
        block = self._dag.get_block(block_digest)
        if block is None:
            return None
        rs = self._get_round_state(block.round)
        if block_digest not in rs.acks:
            rs.acks[block_digest] = set()
        rs.acks[block_digest].add(signer)
        if len(rs.acks[block_digest]) >= self._quorum and block.author not in rs.certificates:
            cert = Certificate(block=block, signers=frozenset(rs.acks[block_digest]))
            rs.certificates[block.author] = cert
            self._dag.add_certificate(cert)
            return cert
        return None

    def receive_certificate(self, cert: Certificate) -> CommitDecision | None:
        """Store certificate and check commit rule."""
        rs = self._get_round_state(cert.block.round)
        rs.certificates[cert.block.author] = cert
        self._dag.add_certificate(cert)
        if cert.block.round > self._current_round:
            self._current_round = cert.block.round
        return self._try_commit_from(cert.block.round)

    def _try_commit_from(self, trigger_round: int) -> CommitDecision | None:
        """Try to commit the leader for the round before trigger_round."""
        if trigger_round > 0:
            target_round = trigger_round - 1
            if target_round not in self._committed_rounds:
                leader = self.leader_for_round(target_round)
                if not self.is_equivocator(leader):
                    decision = evaluate_direct_commit(
                        self._dag, target_round, leader, self._quorum,
                    )
                    if decision is not None:
                        self._committed_rounds.add(target_round)
                        for b in decision.committed_blocks:
                            self._committed_digests.add(b.digest)
                        return decision
        return None

    def check_commit(self, round: int) -> CommitDecision | None:
        """Evaluate commit rule for a specific round's leader."""
        if round in self._committed_rounds:
            return None
        leader = self.leader_for_round(round)
        if self.is_equivocator(leader):
            return None
        decision = evaluate_direct_commit(self._dag, round, leader, self._quorum)
        if decision is not None:
            self._committed_rounds.add(round)
            for b in decision.committed_blocks:
                self._committed_digests.add(b.digest)
            return decision
        decision = evaluate_indirect_commit(
            self._dag, round, leader, self._committed_rounds,
        )
        if decision is not None:
            self._committed_rounds.add(round)
            for b in decision.committed_blocks:
                self._committed_digests.add(b.digest)
            return decision
        return None

    def detect_equivocation(self, block: Block) -> EquivocationProof | None:
        """Check if author already proposed a different block at this round."""
        existing = self._dag.get_block(block.digest)
        if existing is not None and existing.digest == block.digest:
            return None  # exact same block, not equivocation
        round_blocks = self._dag.blocks_at_round(block.round)
        for b in round_blocks:
            if b.author == block.author and b.digest != block.digest:
                return EquivocationProof(
                    author=block.author,
                    block_a=b,
                    block_b=block,
                    round=block.round,
                )
        return None

    def skip_round(self, round: int) -> None:
        """Mark a round as timed out."""
        rs = self._get_round_state(round)
        rs.timed_out = True

    def is_equivocator(self, author: int) -> bool:
        """Check if an author has been flagged for equivocation."""
        return author in self._equivocators
