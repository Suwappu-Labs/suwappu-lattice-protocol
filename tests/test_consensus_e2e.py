"""End-to-end consensus pipeline tests (Spec D1a §5)."""

import time

from ltp.consensus.engine import LocalMysticetiEngine, to_ordered_batch
from ltp.execution.types import OrderedBatch


class TestE2EFourValidators:
    """4-validator pipeline: submit -> run -> collect OrderedBatches."""

    def test_txs_appear_in_ordered_batches(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx_a", b"tx_b", b"tx_c"])
        decisions = engine.run_rounds(5)
        batches = [to_ordered_batch(d, epoch=1) for d in decisions]
        all_txs: list[bytes] = []
        for batch in batches:
            all_txs.extend(batch.transactions)
        assert b"tx_a" in all_txs
        assert b"tx_b" in all_txs
        assert b"tx_c" in all_txs

    def test_ordered_batches_have_correct_fields(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=10)
            assert isinstance(batch, OrderedBatch)
            assert batch.consensus_type == "dag"
            assert batch.epoch == 10
            assert batch.round >= 0
            assert batch.leader_authority >= 0

    def test_leader_authority_matches_leader(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=1)
            expected_leader = d.round % 4
            assert batch.leader_authority == expected_leader


class TestE2ESevenValidators:
    """7-validator pipeline — higher fault tolerance."""

    def test_7_validators_produce_commits(self):
        engine = LocalMysticetiEngine(num_validators=7)
        decisions = engine.run_rounds(10)
        assert len(decisions) > 0

    def test_7_validators_correctness(self):
        engine = LocalMysticetiEngine(num_validators=7)
        engine.submit_transactions([b"big_tx"])
        decisions = engine.run_rounds(5)
        batches = [to_ordered_batch(d, epoch=1) for d in decisions]
        all_txs = [tx for b in batches for tx in b.transactions]
        assert b"big_tx" in all_txs


class TestE2EEdgeCases:
    """Edge cases and ordering guarantees."""

    def test_empty_rounds_still_commit(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        assert len(decisions) > 0

    def test_large_batch_1000_txs(self):
        engine = LocalMysticetiEngine(num_validators=4)
        txs = [f"tx_{i}".encode() for i in range(1000)]
        engine.submit_transactions(txs)
        decisions = engine.run_rounds(10)
        batches = [to_ordered_batch(d, epoch=1) for d in decisions]
        all_txs = set()
        for batch in batches:
            all_txs.update(batch.transactions)
        for tx in txs:
            assert tx in all_txs, f"Missing transaction: {tx}"

    def test_epoch_propagation(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(3)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=42)
            assert batch.epoch == 42


class TestAsyncMode:
    """Async mode — engine runs on background thread."""

    def test_async_start_stop(self):
        engine = LocalMysticetiEngine(num_validators=4, round_timeout_ms=50)
        engine.start()
        time.sleep(0.3)
        engine.stop()
        commits = list(engine.stream_commits())
        assert len(commits) > 0

    def test_async_submit_and_commit(self):
        engine = LocalMysticetiEngine(num_validators=4, round_timeout_ms=50)
        engine.submit_transactions([b"async_tx"])
        engine.start()
        time.sleep(0.3)
        engine.stop()
        commits = list(engine.stream_commits())
        all_txs: list[bytes] = []
        for d in commits:
            for block in d.committed_blocks:
                all_txs.extend(block.payload)
        assert b"async_tx" in all_txs
