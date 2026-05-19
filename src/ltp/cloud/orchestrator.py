"""
Workflow orchestration abstraction for ETP enforcement pipeline.

Production: AWS Step Functions, Temporal, Argo Workflows.
Development/Test: InMemoryOrchestrator.

Models multi-step enforcement workflows where each step receives a
context dict, performs work, and returns an updated context for the
next step. Execution stops on first error.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional

__all__ = [
    "WorkflowStep",
    "WorkflowResult",
    "WorkflowOrchestrator",
    "InMemoryOrchestrator",
]


@dataclass
class WorkflowStep:
    """A single step in a multi-step workflow."""

    step_id: str
    handler: Callable[[dict], dict]  # Takes context, returns updated context
    description: str = ""


@dataclass
class WorkflowResult:
    """Result of a workflow execution."""

    workflow_id: str
    success: bool
    steps_completed: int
    steps_total: int
    final_context: dict = field(default_factory=dict)
    error: str = ""


class WorkflowOrchestrator(ABC):
    """Abstract workflow orchestration interface.

    Production: AWS Step Functions, Temporal, Argo Workflows.
    Development/Test: InMemoryOrchestrator.
    """

    @abstractmethod
    def register_workflow(
        self,
        workflow_id: str,
        steps: list[WorkflowStep],
    ) -> None:
        """Register a multi-step workflow definition."""
        ...

    @abstractmethod
    def execute(self, workflow_id: str, context: dict) -> WorkflowResult:
        """Execute a registered workflow with initial context."""
        ...

    @abstractmethod
    def get_workflow(self, workflow_id: str) -> Optional[dict]:
        """Get workflow metadata (steps, execution count). None if not found."""
        ...

    @abstractmethod
    def list_workflows(self) -> list[str]:
        """List all registered workflow IDs."""
        ...


class InMemoryOrchestrator(WorkflowOrchestrator):
    """Deterministic in-memory workflow orchestrator.

    Executes workflow steps sequentially, passing context between steps.
    Stops on first error. Thread-safe via threading.Lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._workflows: dict[str, list[WorkflowStep]] = {}
        self._execution_counts: dict[str, int] = {}

    def register_workflow(
        self,
        workflow_id: str,
        steps: list[WorkflowStep],
    ) -> None:
        with self._lock:
            if workflow_id in self._workflows:
                raise ValueError(f"Workflow {workflow_id!r} already registered")
            self._workflows[workflow_id] = list(steps)
            self._execution_counts[workflow_id] = 0

    def execute(self, workflow_id: str, context: dict) -> WorkflowResult:
        with self._lock:
            steps = self._workflows.get(workflow_id)
            if steps is None:
                raise KeyError(f"Workflow {workflow_id!r} not registered")
            # Copy steps list to release lock during execution
            steps = list(steps)

        current_context = dict(context)
        steps_completed = 0

        for step in steps:
            try:
                current_context = step.handler(current_context)
                steps_completed += 1
            except Exception as e:
                with self._lock:
                    self._execution_counts[workflow_id] = (
                        self._execution_counts.get(workflow_id, 0) + 1
                    )
                return WorkflowResult(
                    workflow_id=workflow_id,
                    success=False,
                    steps_completed=steps_completed,
                    steps_total=len(steps),
                    final_context=current_context,
                    error=str(e),
                )

        with self._lock:
            self._execution_counts[workflow_id] = self._execution_counts.get(workflow_id, 0) + 1

        return WorkflowResult(
            workflow_id=workflow_id,
            success=True,
            steps_completed=steps_completed,
            steps_total=len(steps),
            final_context=current_context,
        )

    def get_workflow(self, workflow_id: str) -> Optional[dict]:
        with self._lock:
            steps = self._workflows.get(workflow_id)
            if steps is None:
                return None
            return {
                "workflow_id": workflow_id,
                "steps": [s.step_id for s in steps],
                "step_count": len(steps),
                "executions": self._execution_counts.get(workflow_id, 0),
            }

    def list_workflows(self) -> list[str]:
        with self._lock:
            return sorted(self._workflows.keys())
