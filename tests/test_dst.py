"""
Deterministic Simulation Testing Tests.

Verifies the DST harness: seeded reproducibility, fault injection,
property checking, and event logging.
"""

import pytest

from src.simulator.dst import DSTResult, DSTRunner, FaultType


class TestDSTBasic:
    """Basic DST functionality."""

    def test_run_completes(self):
        """DST run completes without error."""
        result = DSTRunner(seed=42, fault_rate=0.0).run(steps=100)
        assert result.steps_executed == 100
        assert result.seed == 42

    def test_deterministic_same_seed(self):
        """Same seed produces identical results."""
        r1 = DSTRunner(seed=123, fault_rate=0.05).run(steps=200)
        r2 = DSTRunner(seed=123, fault_rate=0.05).run(steps=200)

        assert r1.events_processed == r2.events_processed
        assert r1.faults_injected == r2.faults_injected
        assert r1.properties_checked == r2.properties_checked
        assert len(r1.violations) == len(r2.violations)

    def test_different_seeds_differ(self):
        """Different seeds produce different results."""
        r1 = DSTRunner(seed=1, fault_rate=0.1).run(steps=200)
        r2 = DSTRunner(seed=2, fault_rate=0.1).run(steps=200)

        # With fault injection, fault counts will almost certainly differ
        assert (
            r1.faults_injected != r2.faults_injected or r1.events_processed != r2.events_processed
        )


class TestDSTFaultInjection:
    """Fault injection tests."""

    def test_no_faults_with_zero_rate(self):
        """fault_rate=0 means no faults injected."""
        result = DSTRunner(seed=42, fault_rate=0.0).run(steps=100)
        assert result.faults_injected == 0

    def test_faults_injected_with_rate(self):
        """fault_rate>0 injects faults."""
        result = DSTRunner(seed=42, fault_rate=0.5).run(steps=200)
        assert result.faults_injected > 0

    def test_node_crash_and_recovery(self):
        """Nodes can crash and recover during simulation."""
        runner = DSTRunner(seed=42, fault_rate=0.0)
        online_before = len(runner.online_nodes)

        runner.inject_fault(FaultType.NODE_CRASH)
        assert len(runner.online_nodes) == online_before - 1

        runner.inject_fault(FaultType.NODE_RECOVERY)
        assert len(runner.online_nodes) == online_before

    def test_network_partition(self):
        """Regions can be partitioned and healed."""
        runner = DSTRunner(seed=42, fault_rate=0.0)
        active_before = sum(1 for r in runner.regions if r.active)

        runner.inject_fault(FaultType.NETWORK_PARTITION)
        active_after = sum(1 for r in runner.regions if r.active)
        assert active_after == active_before - 1

        runner.inject_fault(FaultType.PARTITION_HEAL)
        active_healed = sum(1 for r in runner.regions if r.active)
        assert active_healed == active_before


class TestDSTProperties:
    """Property invariant checking."""

    def test_default_properties_pass(self):
        """Default properties pass without fault injection."""
        result = DSTRunner(seed=42, fault_rate=0.0).run(steps=100)
        assert result.passed

    def test_custom_property(self):
        """Custom properties are checked."""
        runner = DSTRunner(seed=42, fault_rate=0.0)
        runner.add_property("always_true", lambda r: True)
        result = runner.run(steps=50)
        assert result.passed

    def test_failing_property_detected(self):
        """Property violations are captured."""
        runner = DSTRunner(seed=42, fault_rate=0.0)
        runner.add_property("always_false", lambda r: False)
        result = runner.run(steps=10)
        assert not result.passed
        assert len(result.violations) == 10  # Fails every step
        assert result.violations[0].property_name == "always_false"

    def test_property_with_high_fault_rate(self):
        """Properties checked even under heavy faults."""
        result = DSTRunner(seed=42, fault_rate=0.8).run(steps=100)
        assert result.properties_checked > 0
        # at_least_one_node_online may fail under extreme faults
        # but that's a valid finding


class TestDSTEventLog:
    """Event logging and trace replay."""

    def test_event_log_populated(self):
        """Event log captures every step."""
        result = DSTRunner(seed=42, fault_rate=0.0).run(steps=50)
        assert len(result.event_log) == 50

    def test_event_log_has_step_info(self):
        """Step log entries have required fields; fault entries have fault info."""
        result = DSTRunner(seed=42, fault_rate=0.1).run(steps=20)
        step_entries = [e for e in result.event_log if "online_nodes" in e]
        fault_entries = [e for e in result.event_log if "fault" in e]
        assert len(step_entries) > 0
        for entry in step_entries:
            assert "time_ms" in entry
            assert "online_nodes" in entry
        for entry in fault_entries:
            assert "target" in entry

    def test_replay_matches(self):
        """Replay with same seed produces same violation count."""
        r1 = DSTRunner(seed=777, fault_rate=0.2).run(steps=100)
        r2 = DSTRunner(seed=777, fault_rate=0.2).run(steps=100)
        # Same seed → same topology → same RNG sequence → same results
        assert len(r1.violations) == len(r2.violations)
        assert r1.faults_injected == r2.faults_injected


class TestDSTResult:
    """DSTResult structure tests."""

    def test_result_has_timing(self):
        result = DSTRunner(seed=42).run(steps=50)
        assert result.duration_ms > 0

    def test_result_counts_nodes(self):
        result = DSTRunner(seed=42, fault_rate=0.0).run(steps=10)
        assert result.nodes_online + result.nodes_offline == 6  # default 6 nodes
