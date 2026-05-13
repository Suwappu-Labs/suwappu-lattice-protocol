"""Byzantine fault injection tests (Spec D1a §3)."""

from ltp.consensus.engine import LocalMysticetiEngine
from ltp.consensus.faults import FaultType, FaultConfig, PartitionConfig


class TestEquivocation:
    """Equivocating validator detected and excluded."""

    def test_equivocator_detected(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.EQUIVOCATE, start_round=0,
        ))
        engine.run_rounds(3)
        for v_idx in [0, 2, 3]:
            assert engine.validators[v_idx].is_equivocator(1) is True

    def test_equivocator_blocks_excluded_from_commit(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.EQUIVOCATE, start_round=0,
        ))
        decisions = engine.run_rounds(5)
        for d in decisions:
            for block in d.committed_blocks:
                assert block.author != 1, "Equivocator blocks should not be in committed history"


class TestCrashFaults:
    """Crash fault tolerance."""

    def test_f_crash_faults_protocol_continues(self):
        """n=4, f=1. One crash fault — protocol should still commit."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=3, fault_type=FaultType.CRASH, start_round=0,
        ))
        decisions = engine.run_rounds(8)
        assert len(decisions) > 0, "Should still produce commits with f crash faults"

    def test_f_plus_1_crash_faults_halts(self):
        """n=4, f=1. Two crash faults — liveness lost."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=2, fault_type=FaultType.CRASH, start_round=0,
        ))
        engine.inject_fault(FaultConfig(
            validator=3, fault_type=FaultType.CRASH, start_round=0,
        ))
        decisions = engine.run_rounds(8)
        assert len(decisions) == 0, "Should not produce commits with f+1 crash faults"

    def test_crash_after_round_3(self):
        """Validator crashes after round 3 — commits before crash are fine."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.CRASH, start_round=4,
        ))
        decisions = engine.run_rounds(10)
        assert len(decisions) > 0


class TestWithhold:
    """Withholding validator — sends to some but not others."""

    def test_withhold_still_forms_certs(self):
        """Validator 1 withholds from validator 3. With n=4, quorum=3,
        the other 3 honest validators can still form certificates."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.WITHHOLD, start_round=0,
            params={"withhold_targets": [3]},
        ))
        decisions = engine.run_rounds(8)
        assert len(decisions) > 0


class TestDelay:
    """Delayed acknowledgments."""

    def test_delayed_acks_still_commits(self):
        """Delayed acks slow things down but don't prevent eventual commits
        (other validators compensate)."""
        engine = LocalMysticetiEngine(num_validators=7)  # n=7, f=2
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.DELAY, start_round=0,
        ))
        decisions = engine.run_rounds(10)
        assert len(decisions) > 0


class TestCensor:
    """Censoring validator proposes empty blocks."""

    def test_censored_txs_included_by_others(self):
        """Validator 0 censors, but other validators include txs."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=0, fault_type=FaultType.CENSOR, start_round=0,
        ))
        engine.submit_transactions([b"important_tx"])
        decisions = engine.run_rounds(5)
        all_txs: list[bytes] = []
        for d in decisions:
            for block in d.committed_blocks:
                all_txs.extend(block.payload)
        assert b"important_tx" in all_txs


class TestNetworkPartition:
    """Network partition — two groups cannot communicate."""

    def test_partition_halts_commits(self):
        """n=4 partitioned into {0,1} and {2,3}. Neither group has quorum (3)."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine._bus.set_partition(PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        ))
        decisions = engine.run_rounds(5)
        assert len(decisions) == 0, "No commits during partition (neither side has quorum)"

    def test_partition_heal_resumes_commits(self):
        """Partition heals after round 3, commits resume."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine._bus.set_partition(PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        ))
        for _ in range(3):
            engine.advance_round()
        engine._bus.clear_partition()
        for _ in range(5):
            engine.advance_round()
        decisions = list(engine.stream_commits())
        assert len(decisions) > 0, "Commits should resume after partition heals"


class TestMixedFaults:
    """Combined Byzantine behaviors."""

    def test_equivocate_plus_crash_within_f(self):
        """n=7, f=2. One equivocator + one crash = 2 Byzantine, exactly f.
        Protocol should survive."""
        engine = LocalMysticetiEngine(num_validators=7)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.EQUIVOCATE, start_round=0,
        ))
        engine.inject_fault(FaultConfig(
            validator=2, fault_type=FaultType.CRASH, start_round=0,
        ))
        decisions = engine.run_rounds(10)
        assert len(decisions) > 0, "Should survive f total Byzantine faults"
