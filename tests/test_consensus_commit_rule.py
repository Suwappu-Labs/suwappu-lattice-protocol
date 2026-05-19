"""Tests for commit rule evaluation (Spec D1a §2)."""

from ltp.consensus.commit_rule import (
    collect_causal_history,
    evaluate_direct_commit,
    evaluate_indirect_commit,
)
from ltp.consensus.dag_store import DAGStore
from ltp.consensus.types import Block, Certificate, CommitDecision


def _block(author: int, round: int, parents: frozenset[bytes] = frozenset()) -> Block:
    return Block(author=author, round=round, payload=(), parents=parents, timestamp_ms=1000)


def _cert(block: Block, n: int = 4) -> Certificate:
    """Certificate signed by all n validators."""
    return Certificate(block=block, signers=frozenset(range(n)))


def _build_dag_with_direct_commit(n: int = 4) -> tuple[DAGStore, int, int]:
    """Build a DAG where leader at round 0 has a direct commit.

    Round 0: all n validators propose. Leader = 0 % n = 0.
    All blocks certified.
    Round 1: all n validators propose with parents referencing round 0 certs.
    All blocks certified. The leader cert at round 0 is referenced by >=2f+1 at round 1.

    Returns (dag, leader_round=0, leader_author=0).
    """
    dag = DAGStore()
    f = (n - 1) // 3
    quorum = 2 * f + 1

    # Round 0: all propose, all certified
    r0_certs = {}
    for author in range(n):
        b = _block(author, 0)
        dag.add_block(b)
        c = _cert(b, n)
        dag.add_certificate(c)
        r0_certs[author] = c

    # Round 1: all propose referencing all round 0 certs
    parent_digests = frozenset(c.digest for c in r0_certs.values())
    for author in range(n):
        b = _block(author, 1, parents=parent_digests)
        dag.add_block(b)
        c = _cert(b, n)
        dag.add_certificate(c)

    return dag, 0, 0  # leader_round=0, leader_author=0


class TestDirectCommit:
    """Direct commit: 2f+1 certs at round+1 reference the leader cert."""

    def test_direct_commit_succeeds(self):
        dag, leader_round, leader_author = _build_dag_with_direct_commit(n=4)
        f = 1
        quorum = 2 * f + 1
        decision = evaluate_direct_commit(dag, leader_round, leader_author, quorum)
        assert decision is not None
        assert isinstance(decision, CommitDecision)
        assert decision.round == leader_round
        assert decision.leader_certificate.block.author == leader_author

    def test_direct_commit_fails_below_quorum(self):
        """Only 1 cert at round+1 references the leader — not enough."""
        dag = DAGStore()
        n = 4
        # Round 0: leader proposes, gets certified
        leader_block = _block(0, 0)
        dag.add_block(leader_block)
        dag.add_certificate(_cert(leader_block, n))

        # Round 1: only 1 validator proposes referencing leader
        child = _block(1, 1, parents=frozenset({leader_block.digest}))
        dag.add_block(child)
        dag.add_certificate(_cert(child, n))

        decision = evaluate_direct_commit(dag, 0, 0, quorum_threshold=3)
        assert decision is None

    def test_direct_commit_with_7_validators(self):
        """n=7, f=2, quorum=5. All 7 certs at round 1 reference leader at round 0."""
        dag, leader_round, leader_author = _build_dag_with_direct_commit(n=7)
        decision = evaluate_direct_commit(dag, leader_round, leader_author, quorum_threshold=5)
        assert decision is not None


class TestCausalHistory:
    """Causal history collection — BFS through parent links."""

    def test_causal_history_includes_all_reachable(self):
        dag = DAGStore()
        n = 4
        # Round 0: 4 blocks, all certified
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        # Round 1: leader references all round 0 certs
        parent_digests = frozenset(c.digest for c in r0_certs.values())
        leader_block = _block(1, 1, parents=parent_digests)
        dag.add_block(leader_block)
        leader_cert = _cert(leader_block, n)
        dag.add_certificate(leader_cert)

        history = collect_causal_history(dag, leader_cert, already_committed=set())
        digests = {b.digest for b in history}
        for author in range(n):
            r0_block = dag.blocks_at_round(0)
            assert any(b.author == author for b in r0_block)
        assert leader_block.digest in digests

    def test_causal_history_excludes_already_committed(self):
        dag = DAGStore()
        b0 = _block(0, 0)
        dag.add_block(b0)
        dag.add_certificate(_cert(b0, 4))

        b1 = _block(1, 1, parents=frozenset({b0.digest}))
        dag.add_block(b1)
        cert1 = _cert(b1, 4)
        dag.add_certificate(cert1)

        history = collect_causal_history(dag, cert1, already_committed={b0.digest})
        digests = {b.digest for b in history}
        assert b0.digest not in digests
        assert b1.digest in digests

    def test_causal_history_ordered_by_round_then_author(self):
        dag = DAGStore()
        n = 4
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        parent_digests = frozenset(c.digest for c in r0_certs.values())
        leader = _block(0, 1, parents=parent_digests)
        dag.add_block(leader)
        leader_cert = _cert(leader, n)
        dag.add_certificate(leader_cert)

        history = collect_causal_history(dag, leader_cert, already_committed=set())
        for i in range(1, len(history)):
            prev, curr = history[i - 1], history[i]
            assert (prev.round, prev.author) <= (curr.round, curr.author)


class TestIndirectCommit:
    """Indirect commit: skipped leader committed through later leader's causal history."""

    def test_indirect_commit_through_later_leader(self):
        dag = DAGStore()
        n = 4
        f = 1
        quorum = 2 * f + 1

        # Round 0: all propose, all certified
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        # Round 1: all propose referencing all round 0 certs
        r1_certs = {}
        r0_parents = frozenset(c.digest for c in r0_certs.values())
        for author in range(n):
            b = _block(author, 1, parents=r0_parents)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r1_certs[author] = c

        # Round 2: all propose referencing round 1 certs
        r1_parents = frozenset(c.digest for c in r1_certs.values())
        for author in range(n):
            b = _block(author, 2, parents=r1_parents)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)

        # Leader at round 0 = validator 0. It's in causal history of leader at round 2.
        decision = evaluate_indirect_commit(
            dag,
            round=0,
            leader=0,
            committed_rounds={2},
        )
        assert decision is not None
        assert decision.round == 0

    def test_indirect_commit_not_in_causal_history(self):
        dag = DAGStore()
        decision = evaluate_indirect_commit(dag, round=0, leader=0, committed_rounds=set())
        assert decision is None

    def test_no_double_commit(self):
        dag = DAGStore()
        n = 4
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        r0_parents = frozenset(c.digest for c in r0_certs.values())
        for author in range(n):
            b = _block(author, 1, parents=r0_parents)
            dag.add_block(b)
            dag.add_certificate(_cert(b, n))

        decision = evaluate_indirect_commit(dag, round=0, leader=0, committed_rounds={0})
        assert decision is None
