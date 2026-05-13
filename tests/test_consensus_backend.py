"""Tests for ConsensusBackend ABC and LocalConsensusBackend (Spec D1b §4)."""

import pytest
from abc import ABC

from src.ltp.consensus.backend import ConsensusBackend, LocalConsensusBackend
from src.ltp.consensus.types import CommitDecision
from src.ltp.consensus.faults import FaultConfig, FaultType


class TestConsensusBackendABC:
    """ConsensusBackend abstract base class tests."""

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            ConsensusBackend()  # type: ignore[abstract]

    def test_is_abstract(self):
        assert issubclass(ConsensusBackend, ABC)


class TestLocalConsensusBackend:
    """LocalConsensusBackend delegation tests."""

    def test_creation_with_validator_count(self):
        backend = LocalConsensusBackend(4)
        assert backend.get_validator_count() == 4

    def test_advance_round_returns_round_number(self):
        backend = LocalConsensusBackend(4)
        r = backend.advance_round()
        assert r == 0
        r = backend.advance_round()
        assert r == 1

    def test_current_round_tracks(self):
        backend = LocalConsensusBackend(4)
        assert backend.current_round() == -1
        backend.advance_round()
        assert backend.current_round() == 0

    def test_run_rounds_produces_commit_decisions(self):
        backend = LocalConsensusBackend(4)
        decisions = backend.run_rounds(5)
        assert isinstance(decisions, list)
        for d in decisions:
            assert isinstance(d, CommitDecision)

    def test_submit_transactions_forwarded(self):
        backend = LocalConsensusBackend(4)
        backend.submit_transactions([b"tx1", b"tx2"])
        decisions = backend.run_rounds(5)
        all_payloads = []
        for d in decisions:
            for block in d.committed_blocks:
                all_payloads.extend(block.payload)
        assert b"tx1" in all_payloads
        assert b"tx2" in all_payloads

    def test_inject_fault_crash(self):
        backend = LocalConsensusBackend(4)
        fault = FaultConfig(validator=0, fault_type=FaultType.CRASH, start_round=0)
        backend.inject_fault(fault)
        backend.run_rounds(3)

    def test_rebuild_creates_new_engine(self):
        backend = LocalConsensusBackend(4)
        backend.advance_round()
        assert backend.current_round() == 0
        backend.rebuild(7)
        assert backend.get_validator_count() == 7
        assert backend.current_round() == -1

    def test_rebuild_preserves_round_timeout(self):
        backend = LocalConsensusBackend(4, round_timeout_ms=500)
        backend.rebuild(7)
        assert backend._round_timeout_ms == 500

    def test_start_stop_lifecycle(self):
        backend = LocalConsensusBackend(4, round_timeout_ms=50)
        backend.start()
        assert backend._engine._running is True
        backend.stop()
        assert backend._engine._running is False

    def test_stream_commits_yields_decisions(self):
        backend = LocalConsensusBackend(4, round_timeout_ms=10)
        backend.submit_transactions([b"tx-stream"])
        backend.start()
        commits = []
        for decision in backend.stream_commits():
            commits.append(decision)
            if len(commits) >= 1:
                backend.stop()
                break
        assert len(commits) >= 1
        assert isinstance(commits[0], CommitDecision)
