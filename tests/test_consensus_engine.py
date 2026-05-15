"""Tests for LocalMysticetiEngine (Spec D1a §3)."""

from ltp.consensus.engine import LocalMysticetiEngine, to_ordered_batch
from ltp.consensus.types import CommitDecision
from ltp.execution.types import OrderedBatch


class TestEngineLifecycle:
    """Engine creation and basic properties."""

    def test_create_engine(self):
        engine = LocalMysticetiEngine(num_validators=4)
        assert len(engine.validators) == 4

    def test_validators_have_correct_indices(self):
        engine = LocalMysticetiEngine(num_validators=4)
        for i, v in enumerate(engine.validators):
            assert v._index == i

    def test_get_dag_store(self):
        engine = LocalMysticetiEngine(num_validators=4)
        dag = engine.get_dag_store(0)
        assert dag is engine.validators[0].dag_store


class TestSynchronousMode:
    """Step-by-step round execution."""

    def test_advance_round_returns_round_number(self):
        engine = LocalMysticetiEngine(num_validators=4)
        r = engine.advance_round()
        assert r == 0

    def test_advance_round_increments(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.advance_round()
        r = engine.advance_round()
        assert r == 1

    def test_run_rounds_produces_commits(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        assert len(decisions) > 0
        for d in decisions:
            assert isinstance(d, CommitDecision)

    def test_commit_rounds_are_monotonic(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(10)
        rounds = [d.round for d in decisions]
        assert rounds == sorted(rounds)

    def test_submit_transactions_appear_in_commits(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx_hello", b"tx_world"])
        decisions = engine.run_rounds(5)
        all_payloads: list[bytes] = []
        for d in decisions:
            for block in d.committed_blocks:
                all_payloads.extend(block.payload)
        assert b"tx_hello" in all_payloads
        assert b"tx_world" in all_payloads

    def test_deterministic_same_result(self):
        """Same initial state + same operations = same result."""
        def run():
            engine = LocalMysticetiEngine(num_validators=4)
            engine.submit_transactions([b"tx1"])
            return engine.run_rounds(5)
        d1 = run()
        d2 = run()
        assert len(d1) == len(d2)
        for a, b in zip(d1, d2):
            assert a.round == b.round


class TestToOrderedBatch:
    """Conversion from CommitDecision to OrderedBatch."""

    def test_to_ordered_batch_basic(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx1", b"tx2"])
        decisions = engine.run_rounds(5)
        assert len(decisions) > 0
        batch = to_ordered_batch(decisions[0], epoch=42)
        assert isinstance(batch, OrderedBatch)
        assert batch.epoch == 42
        assert batch.consensus_type == "dag"
        assert batch.round == decisions[0].round

    def test_to_ordered_batch_leader_authority(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=1)
            assert batch.leader_authority == d.leader_certificate.block.author

    def test_to_ordered_batch_collects_all_txs(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx_a", b"tx_b", b"tx_c"])
        decisions = engine.run_rounds(5)
        all_txs: list[bytes] = []
        for d in decisions:
            batch = to_ordered_batch(d, epoch=1)
            all_txs.extend(batch.transactions)
        assert b"tx_a" in all_txs
        assert b"tx_b" in all_txs
        assert b"tx_c" in all_txs
