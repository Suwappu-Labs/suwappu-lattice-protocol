"""Direct and indirect commit rule evaluation (Spec D1a §2)."""

from __future__ import annotations

from collections import deque

from .types import Block, Certificate, CommitDecision
from .dag_store import DAGStore


def collect_causal_history(
    dag: DAGStore,
    certificate: Certificate,
    already_committed: set[bytes],
) -> list[Block]:
    """BFS through parent links to collect uncommitted blocks in causal order.

    Returns blocks ordered by (round, author).
    """
    visited: set[bytes] = set()
    result: list[Block] = []
    queue: deque[bytes] = deque([certificate.digest])

    while queue:
        digest = queue.popleft()
        if digest in visited or digest in already_committed:
            continue
        visited.add(digest)
        block = dag.get_block(digest)
        if block is None:
            continue
        result.append(block)
        for parent_digest in block.parents:
            if parent_digest not in visited and parent_digest not in already_committed:
                queue.append(parent_digest)

    result.sort(key=lambda b: (b.round, b.author))
    return result


def evaluate_direct_commit(
    dag: DAGStore,
    round: int,
    leader: int,
    quorum_threshold: int,
) -> CommitDecision | None:
    """Check if the leader at `round` has a direct commit.

    Direct commit: 2f+1 certificates at round+1 include the leader cert's
    digest in their parents.
    """
    leader_cert = dag.get_certificate(leader, round)
    if leader_cert is None:
        return None

    next_round_certs = dag.certificates_at_round(round + 1)
    referencing = 0
    for cert in next_round_certs:
        if leader_cert.digest in cert.block.parents:
            referencing += 1

    if referencing < quorum_threshold:
        return None

    committed = collect_causal_history(dag, leader_cert, already_committed=set())
    return CommitDecision(
        leader_certificate=leader_cert,
        committed_blocks=committed,
        round=round,
    )


def evaluate_indirect_commit(
    dag: DAGStore,
    round: int,
    leader: int,
    committed_rounds: set[int],
) -> CommitDecision | None:
    """Check if the leader at `round` can be indirectly committed.

    Indirect: if a later committed leader's causal history includes this
    leader's certificate, then this leader is also committed transitively.
    """
    if round in committed_rounds:
        return None

    leader_cert = dag.get_certificate(leader, round)
    if leader_cert is None:
        return None

    for committed_round in sorted(committed_rounds):
        if committed_round <= round:
            continue
        n_validators = max(
            (b.author + 1 for b in dag.blocks_at_round(0)),
            default=1,
        )
        committed_leader = committed_round % n_validators
        committed_cert = dag.get_certificate(committed_leader, committed_round)
        if committed_cert is None:
            continue
        history = collect_causal_history(dag, committed_cert, already_committed=set())
        history_digests = {b.digest for b in history}
        if leader_cert.block.digest in history_digests:
            committed_blocks = collect_causal_history(dag, leader_cert, already_committed=set())
            return CommitDecision(
                leader_certificate=leader_cert,
                committed_blocks=committed_blocks,
                round=round,
            )

    return None
