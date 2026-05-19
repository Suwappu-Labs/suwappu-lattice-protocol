"""
DST CI Harness — CI-compatible deterministic simulation testing runner.

Runs DSTRunner across multiple seeds with configurable parameters.
Exits non-zero if any seed produces violations exceeding the threshold.

Usage:
    python -m src.simulator.ci_harness --seeds 42,123,777 --steps 500
    python -m src.simulator.ci_harness --seeds 42 --steps 1000 --fault-rate 0.2

"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

from .dst import DSTRunner

__all__ = ["DSTCIHarness", "DSTCIResult"]


@dataclass
class DSTCIResult:
    """Result of a CI DST run across multiple seeds."""

    seeds_run: int
    total_violations: int
    passed: bool
    details: list[dict] = field(default_factory=list)


class DSTCIHarness:
    """CI-compatible DST runner with configurable parameters.

    Runs DSTRunner for each seed and aggregates results. A run passes
    if total violations across all seeds <= max_violations.
    """

    def __init__(
        self,
        seeds: list[int],
        steps: int = 500,
        fault_rate: float = 0.1,
        max_violations: int = 0,
        num_nodes: int = 6,
    ) -> None:
        self._seeds = seeds
        self._steps = steps
        self._fault_rate = fault_rate
        self._max_violations = max_violations
        self._num_nodes = num_nodes

    def run(self) -> DSTCIResult:
        """Execute DST across all seeds. Returns aggregated result."""
        total_violations = 0
        details = []

        for seed in self._seeds:
            runner = DSTRunner(
                seed=seed,
                fault_rate=self._fault_rate,
                num_nodes=self._num_nodes,
            )
            result = runner.run(steps=self._steps)

            seed_detail = {
                "seed": seed,
                "steps": result.steps_executed,
                "violations": len(result.violations),
                "faults_injected": result.faults_injected,
                "passed": result.passed,
            }
            details.append(seed_detail)
            total_violations += len(result.violations)

        passed = total_violations <= self._max_violations

        return DSTCIResult(
            seeds_run=len(self._seeds),
            total_violations=total_violations,
            passed=passed,
            details=details,
        )


def main() -> int:
    """CLI entry point. Returns exit code (0 = pass, 1 = fail)."""
    parser = argparse.ArgumentParser(description="ETP DST CI Harness")
    parser.add_argument(
        "--seeds",
        type=str,
        default="42",
        help="Comma-separated seed list (default: 42)",
    )
    parser.add_argument(
        "--steps",
        type=int,
        default=500,
        help="Steps per seed (default: 500)",
    )
    parser.add_argument(
        "--fault-rate",
        type=float,
        default=0.1,
        help="Fault injection rate (default: 0.1)",
    )
    parser.add_argument(
        "--max-violations",
        type=int,
        default=0,
        help="Max allowed violations across all seeds (default: 0)",
    )
    args = parser.parse_args()

    seeds = [int(s.strip()) for s in args.seeds.split(",")]

    harness = DSTCIHarness(
        seeds=seeds,
        steps=args.steps,
        fault_rate=args.fault_rate,
        max_violations=args.max_violations,
    )

    result = harness.run()

    # Print summary
    print(f"DST CI Harness: {result.seeds_run} seeds, {result.total_violations} violations")
    for detail in result.details:
        status = "PASS" if detail["passed"] else "FAIL"
        print(
            f"  Seed {detail['seed']}: {status} ({detail['violations']} violations, {detail['faults_injected']} faults)"
        )

    if result.passed:
        print("RESULT: PASS")
        return 0
    else:
        print(f"RESULT: FAIL ({result.total_violations} > {args.max_violations} max)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
