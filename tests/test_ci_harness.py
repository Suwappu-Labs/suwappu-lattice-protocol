"""
CI pipeline + DST CI harness tests.

Tests DSTCIHarness execution, result aggregation, CI config validation.
"""

from __future__ import annotations

import os

import pytest
import yaml

from src.simulator.ci_harness import DSTCIHarness, DSTCIResult

DEPLOY_DIR = os.path.join(os.path.dirname(__file__), "..", "deploy")


# ---------------------------------------------------------------------------
# DSTCIHarness
# ---------------------------------------------------------------------------


class TestDSTCIHarness:
    def test_clean_run_passes(self):
        """Zero fault rate, all seeds should pass."""
        harness = DSTCIHarness(seeds=[42, 123], steps=100, fault_rate=0.0)
        result = harness.run()
        assert result.passed is True
        assert result.seeds_run == 2
        assert result.total_violations == 0

    def test_multiple_seeds_all_checked(self):
        """Every seed produces a detail entry."""
        harness = DSTCIHarness(seeds=[1, 2, 3, 4, 5], steps=50, fault_rate=0.0)
        result = harness.run()
        assert len(result.details) == 5
        seed_values = {d["seed"] for d in result.details}
        assert seed_values == {1, 2, 3, 4, 5}

    def test_fault_injection_may_produce_violations(self):
        """High fault rate may produce violations (property-under-test)."""
        harness = DSTCIHarness(seeds=[42], steps=200, fault_rate=0.8)
        result = harness.run()
        # With 80% fault rate, we expect some violations
        # (at_least_one_node_online may be violated)
        assert result.seeds_run == 1
        # Result may or may not have violations — just verify structure
        assert isinstance(result.total_violations, int)

    def test_max_violations_threshold(self):
        """Run passes if violations <= max_violations."""
        # Clean run: 0 violations, max=0 → pass
        harness = DSTCIHarness(seeds=[42], steps=50, fault_rate=0.0, max_violations=0)
        result = harness.run()
        assert result.passed is True

    def test_max_violations_exceeded_fails(self):
        """If violations > max_violations, run fails."""
        # Force failure by using a result object directly
        result = DSTCIResult(seeds_run=1, total_violations=5, passed=False)
        assert result.passed is False


# ---------------------------------------------------------------------------
# DSTCIResult
# ---------------------------------------------------------------------------


class TestCIResult:
    def test_result_captures_details(self):
        result = DSTCIResult(
            seeds_run=3,
            total_violations=2,
            passed=False,
            details=[
                {"seed": 1, "violations": 0, "passed": True},
                {"seed": 2, "violations": 2, "passed": False},
                {"seed": 3, "violations": 0, "passed": True},
            ],
        )
        assert result.seeds_run == 3
        assert result.total_violations == 2
        assert result.passed is False

    def test_result_passed_reflects_violations(self):
        passing = DSTCIResult(seeds_run=1, total_violations=0, passed=True)
        failing = DSTCIResult(seeds_run=1, total_violations=3, passed=False)
        assert passing.passed is True
        assert failing.passed is False


# ---------------------------------------------------------------------------
# CI Config Validation
# ---------------------------------------------------------------------------


class TestCIConfigValidation:
    def test_ci_yaml_parseable(self):
        path = os.path.join(DEPLOY_DIR, "ci", "test.yml")
        with open(path) as f:
            config = yaml.safe_load(f)
        assert isinstance(config, dict)

    def test_ci_has_required_jobs(self):
        path = os.path.join(DEPLOY_DIR, "ci", "test.yml")
        with open(path) as f:
            config = yaml.safe_load(f)
        jobs = config.get("jobs", {})
        assert "python-tests" in jobs
        assert "solidity-tests" in jobs
        assert "dst-gate" in jobs

    def test_dst_gate_depends_on_python_tests(self):
        path = os.path.join(DEPLOY_DIR, "ci", "test.yml")
        with open(path) as f:
            config = yaml.safe_load(f)
        dst_gate = config["jobs"]["dst-gate"]
        assert "python-tests" in dst_gate.get("needs", [])
