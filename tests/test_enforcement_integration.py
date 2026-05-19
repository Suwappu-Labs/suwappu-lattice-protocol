"""
Enforcement pipeline integration with MessageQueue + Orchestrator.

End-to-end: audit violation → queue → finalize → slash → bond reduction.
Tests both queue-routed and legacy (batch_accumulator) paths.
"""

from __future__ import annotations

import pytest

from src.ltp.cloud.orchestrator import InMemoryOrchestrator, WorkflowStep
from src.ltp.cloud.queue import InMemoryQueue
from src.ltp.economics import (
    WEI_PER_LTP,
    EconomicsConfig,
    EconomicsEngine,
    NodeEconomics,
)
from src.ltp.enforcement_pipeline import (
    EnforcementPipeline,
    EnforcementPipelineConfig,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine() -> EconomicsEngine:
    return EconomicsEngine(EconomicsConfig())


def _make_node(node_id: str = "node-1", stake: int = 1000 * WEI_PER_LTP) -> NodeEconomics:
    return NodeEconomics(
        node_id=node_id,
        stake=stake,
        shards_stored=10,
        audit_score=100,
    )


def _make_audit_failure(node_id: str = "node-1", strikes: int = 4) -> dict:
    """Create an audit result dict that triggers a condition violation."""
    return {
        "node_id": node_id,
        "result": "FAIL",
        "challenged": 10,
        "passed": 5,
        "failed": 5,
        "missing": 3,
        "strikes": strikes,
        "burst_size": 2,
        "avg_response_us": 500.0,
        "suspicious_latency": 0,
        "corrupt_shards": [("entity-1", 0), ("entity-1", 1)],
    }


# ---------------------------------------------------------------------------
# Enforcement with MessageQueue
# ---------------------------------------------------------------------------


class TestEnforcementWithQueue:
    def test_violation_enqueued_to_message_queue(self):
        """When message_queue is set, violations go through it."""
        queue = InMemoryQueue()
        pipeline = EnforcementPipeline(message_queue=queue)
        engine = _make_engine()
        node = _make_node()

        audit = _make_audit_failure()
        pipeline.handle_audit_result(audit, node, engine, epoch=100)

        # Violation should be in the queue, not batch_accumulator
        assert queue.queue_depth("100") >= 1
        assert pipeline.batch_accumulator.pending_for_epoch(100) == []

    def test_finalize_drains_queue(self):
        """finalize_epoch drains messages from queue and creates pending slashes."""
        queue = InMemoryQueue()
        pipeline = EnforcementPipeline(message_queue=queue)
        engine = _make_engine()
        node = _make_node()

        audit = _make_audit_failure()
        pipeline.handle_audit_result(audit, node, engine, epoch=100)
        assert queue.queue_depth("100") >= 1

        result = pipeline.finalize_epoch(100, [node], engine)
        assert result["batch_entries"] >= 1
        assert result["pending_created"] >= 1

        # Queue should be drained
        assert queue.queue_depth("100") == 0

    def test_batch_accumulator_still_works_without_queue(self):
        """Without message_queue, pipeline uses batch_accumulator (backward compat)."""
        pipeline = EnforcementPipeline()  # No queue
        engine = _make_engine()
        node = _make_node()

        audit = _make_audit_failure()
        pipeline.handle_audit_result(audit, node, engine, epoch=100)

        # Should be in batch_accumulator
        pending = pipeline.batch_accumulator.pending_for_epoch(100)
        assert len(pending) >= 1

        result = pipeline.finalize_epoch(100, [node], engine)
        assert result["batch_entries"] >= 1


# ---------------------------------------------------------------------------
# Enforcement with Orchestrator
# ---------------------------------------------------------------------------


class TestEnforcementWithOrchestrator:
    def test_orchestrator_can_wrap_finalization(self):
        """Demonstrate that finalize_epoch can be wrapped as a workflow step."""
        queue = InMemoryQueue()
        orch = InMemoryOrchestrator()
        pipeline = EnforcementPipeline(message_queue=queue, orchestrator=orch)
        engine = _make_engine()
        node = _make_node()

        # Enqueue a violation
        audit = _make_audit_failure()
        pipeline.handle_audit_result(audit, node, engine, epoch=200)

        # Register finalize as a workflow step
        def finalize_step(ctx: dict) -> dict:
            result = pipeline.finalize_epoch(
                ctx["epoch"],
                ctx["nodes"],
                ctx["engine"],
            )
            ctx["finalize_result"] = result
            return ctx

        orch.register_workflow(
            "enforcement-finalize",
            [
                WorkflowStep("finalize", finalize_step, "Finalize epoch enforcement"),
            ],
        )

        # Execute workflow
        wf_result = orch.execute(
            "enforcement-finalize",
            {
                "epoch": 200,
                "nodes": [node],
                "engine": engine,
            },
        )
        assert wf_result.success is True
        assert wf_result.steps_completed == 1
        assert wf_result.final_context["finalize_result"]["batch_entries"] >= 1

    def test_orchestrator_tracks_execution(self):
        """Orchestrator metadata shows execution count."""
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "test-wf",
            [
                WorkflowStep("noop", lambda ctx: ctx),
            ],
        )
        orch.execute("test-wf", {})
        orch.execute("test-wf", {})

        meta = orch.get_workflow("test-wf")
        assert meta["executions"] == 2


# ---------------------------------------------------------------------------
# End-to-end: Violation → Queue → Slash → Bond Reduction
# ---------------------------------------------------------------------------


class TestEndToEndViolationToSlash:
    def test_full_violation_to_stake_deduction(self):
        """Complete flow: audit failure → queue → finalize → pending slash → stake deducted."""
        queue = InMemoryQueue()
        pipeline = EnforcementPipeline(message_queue=queue)
        engine = _make_engine()

        initial_stake = 1000 * WEI_PER_LTP
        node = _make_node(stake=initial_stake)

        # Step 1: Audit failure triggers violation
        audit = _make_audit_failure(strikes=4)
        pipeline.handle_audit_result(audit, node, engine, epoch=100)
        assert queue.queue_depth("100") >= 1

        # Step 2: Finalize epoch 100 → creates pending slash
        result_100 = pipeline.finalize_epoch(100, [node], engine)
        assert result_100["pending_created"] >= 1

        # Step 3: Advance past grace period (168 epochs) and finalize again
        # The pending slash has a grace period; finalize at epoch 300 to expire it
        result_300 = pipeline.finalize_epoch(300, [node], engine)
        assert result_300["slashes_finalized"] >= 1
        assert result_300["stake_deducted"] > 0

        # Step 4: Verify stake was reduced
        assert node.stake < initial_stake
        assert node.total_slashed > 0

    def test_multiple_violations_batched(self):
        """Multiple violations in same epoch are batched and finalized together."""
        queue = InMemoryQueue()
        pipeline = EnforcementPipeline(message_queue=queue)
        engine = _make_engine()
        node = _make_node()

        # Two violations in same epoch
        pipeline.handle_audit_result(_make_audit_failure(strikes=4), node, engine, epoch=50)
        pipeline.handle_audit_result(_make_audit_failure(strikes=5), node, engine, epoch=50)

        assert queue.queue_depth("50") >= 2

        result = pipeline.finalize_epoch(50, [node], engine)
        assert result["batch_entries"] >= 2

    def test_queue_isolation_between_epochs(self):
        """Violations in different epochs don't cross-contaminate."""
        queue = InMemoryQueue()
        pipeline = EnforcementPipeline(message_queue=queue)
        engine = _make_engine()
        node = _make_node()

        pipeline.handle_audit_result(_make_audit_failure(), node, engine, epoch=10)
        pipeline.handle_audit_result(_make_audit_failure(), node, engine, epoch=20)

        # Finalize epoch 10 only
        result = pipeline.finalize_epoch(10, [node], engine)
        assert result["batch_entries"] >= 1

        # Epoch 20 still has its message
        assert queue.queue_depth("20") >= 1
