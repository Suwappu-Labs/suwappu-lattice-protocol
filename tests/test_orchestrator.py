"""
WorkflowOrchestrator ABC + InMemoryOrchestrator tests.

Tests multi-step workflow execution, context flow between steps,
error handling, and multi-workflow management.
"""

from __future__ import annotations

import pytest

from src.ltp.cloud.orchestrator import (
    InMemoryOrchestrator,
    WorkflowResult,
    WorkflowStep,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _step_add_x(ctx: dict) -> dict:
    ctx["x"] = ctx.get("x", 0) + 1
    return ctx


def _step_add_y(ctx: dict) -> dict:
    ctx["y"] = ctx.get("y", 0) + 10
    return ctx


def _step_multiply(ctx: dict) -> dict:
    ctx["result"] = ctx.get("x", 0) * ctx.get("y", 0)
    return ctx


def _step_fail(ctx: dict) -> dict:
    raise RuntimeError("step failure")


# ---------------------------------------------------------------------------
# Basic Orchestrator
# ---------------------------------------------------------------------------


class TestInMemoryOrchestrator:
    def test_register_workflow(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "wf-1",
            [
                WorkflowStep("s1", _step_add_x),
            ],
        )
        assert "wf-1" in orch.list_workflows()

    def test_execute_three_step_workflow(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "calc",
            [
                WorkflowStep("add_x", _step_add_x),
                WorkflowStep("add_y", _step_add_y),
                WorkflowStep("multiply", _step_multiply),
            ],
        )

        result = orch.execute("calc", {"x": 5, "y": 3})
        assert result.success is True
        assert result.steps_completed == 3
        assert result.steps_total == 3
        assert result.final_context["x"] == 6  # 5 + 1
        assert result.final_context["y"] == 13  # 3 + 10
        assert result.final_context["result"] == 78  # 6 * 13

    def test_context_flows_between_steps(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "flow",
            [
                WorkflowStep("s1", lambda ctx: {**ctx, "a": 1}),
                WorkflowStep("s2", lambda ctx: {**ctx, "b": ctx["a"] + 1}),
                WorkflowStep("s3", lambda ctx: {**ctx, "c": ctx["b"] + 1}),
            ],
        )
        result = orch.execute("flow", {})
        assert result.final_context == {"a": 1, "b": 2, "c": 3}

    def test_result_step_counts(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "count",
            [
                WorkflowStep("s1", _step_add_x),
                WorkflowStep("s2", _step_add_y),
            ],
        )
        result = orch.execute("count", {})
        assert result.steps_completed == 2
        assert result.steps_total == 2

    def test_execute_unknown_workflow_raises(self):
        orch = InMemoryOrchestrator()
        with pytest.raises(KeyError, match="not registered"):
            orch.execute("nonexistent", {})

    def test_duplicate_registration_rejected(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow("dup", [WorkflowStep("s1", _step_add_x)])
        with pytest.raises(ValueError, match="already registered"):
            orch.register_workflow("dup", [WorkflowStep("s1", _step_add_x)])


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------


class TestWorkflowErrorHandling:
    def test_step_failure_stops_execution(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "fail-mid",
            [
                WorkflowStep("s1", _step_add_x),
                WorkflowStep("s2", _step_fail),
                WorkflowStep("s3", _step_add_y),
            ],
        )
        result = orch.execute("fail-mid", {})
        assert result.success is False
        assert result.steps_completed == 1  # Only s1 completed
        assert result.steps_total == 3

    def test_error_captured_in_result(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow("err", [WorkflowStep("s1", _step_fail)])
        result = orch.execute("err", {})
        assert "step failure" in result.error

    def test_partial_context_preserved(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "partial",
            [
                WorkflowStep("s1", lambda ctx: {**ctx, "done": True}),
                WorkflowStep("s2", _step_fail),
            ],
        )
        result = orch.execute("partial", {"start": True})
        assert result.final_context["start"] is True
        assert result.final_context["done"] is True


# ---------------------------------------------------------------------------
# Multi-Workflow Management
# ---------------------------------------------------------------------------


class TestOrchestratorMultiWorkflow:
    def test_multiple_workflows_registered(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow("wf-a", [WorkflowStep("s1", _step_add_x)])
        orch.register_workflow("wf-b", [WorkflowStep("s1", _step_add_y)])
        assert sorted(orch.list_workflows()) == ["wf-a", "wf-b"]

    def test_workflows_execute_independently(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow("add", [WorkflowStep("s1", _step_add_x)])
        orch.register_workflow(
            "mul",
            [
                WorkflowStep("s1", lambda ctx: {**ctx, "val": ctx.get("val", 1) * 2}),
            ],
        )

        r1 = orch.execute("add", {"x": 10})
        r2 = orch.execute("mul", {"val": 5})

        assert r1.final_context["x"] == 11
        assert r2.final_context["val"] == 10

    def test_get_workflow_metadata(self):
        orch = InMemoryOrchestrator()
        orch.register_workflow(
            "meta",
            [
                WorkflowStep("step-a", _step_add_x, description="Add X"),
                WorkflowStep("step-b", _step_add_y, description="Add Y"),
            ],
        )
        orch.execute("meta", {})
        orch.execute("meta", {})

        meta = orch.get_workflow("meta")
        assert meta is not None
        assert meta["step_count"] == 2
        assert meta["executions"] == 2
        assert meta["steps"] == ["step-a", "step-b"]

    def test_get_unknown_workflow_returns_none(self):
        orch = InMemoryOrchestrator()
        assert orch.get_workflow("nope") is None
