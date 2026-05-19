"""Tests for ConsensusAdapter protocol and FakeConsensusAdapter."""

import pytest


class TestFakeConsensusAdapter:
    def test_stream_batches(self):
        from src.ltp.execution.consensus import FakeConsensusAdapter
        from src.ltp.execution.types import OrderedBatch

        batches = [
            OrderedBatch(
                round=1,
                epoch=0,
                transactions=[b"\x01tx1"],
                leader_authority=0,
                timestamp_ms=100,
                consensus_type="dag",
            ),
            OrderedBatch(
                round=2,
                epoch=0,
                transactions=[b"\x10tx2"],
                leader_authority=1,
                timestamp_ms=200,
                consensus_type="dag",
            ),
        ]
        adapter = FakeConsensusAdapter(batches=batches)
        adapter.start()

        received = list(adapter.stream_batches())
        assert len(received) == 2
        assert received[0].round == 1
        assert received[1].round == 2

    def test_consensus_type(self):
        from src.ltp.execution.consensus import FakeConsensusAdapter

        adapter = FakeConsensusAdapter(batches=[], consensus_type="bft")
        assert adapter.consensus_type() == "bft"

    def test_current_round_advances(self):
        from src.ltp.execution.consensus import FakeConsensusAdapter
        from src.ltp.execution.types import OrderedBatch

        batches = [
            OrderedBatch(
                round=5,
                epoch=0,
                transactions=[],
                leader_authority=0,
                timestamp_ms=100,
                consensus_type="dag",
            ),
        ]
        adapter = FakeConsensusAdapter(batches=batches)
        assert adapter.current_round() == 0
        list(adapter.stream_batches())
        assert adapter.current_round() == 5

    def test_satisfies_protocol(self):
        from src.ltp.execution.consensus import ConsensusAdapter, FakeConsensusAdapter

        adapter = FakeConsensusAdapter(batches=[])
        assert isinstance(adapter, ConsensusAdapter)

    def test_stop(self):
        from src.ltp.execution.consensus import FakeConsensusAdapter

        adapter = FakeConsensusAdapter(batches=[])
        adapter.start()
        adapter.stop()  # should not raise
