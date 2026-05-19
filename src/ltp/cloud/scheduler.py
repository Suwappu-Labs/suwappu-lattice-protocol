"""
Scheduled task execution abstraction for ETP.

Production: Kubernetes CronJob, AWS EventBridge, CloudWatch Events.
Development/Test: InMemoryScheduler with deterministic tick().

Models periodic task execution for key rotation triggers, audit
scheduling, and other time-based operations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, Optional

__all__ = ["ScheduledTaskRunner", "InMemoryScheduler"]


class ScheduledTaskRunner(ABC):
    """Abstract scheduled task execution interface."""

    @abstractmethod
    def schedule(
        self,
        task_id: str,
        callback: Callable[[], None],
        interval_seconds: float,
    ) -> None:
        """Schedule a recurring task."""
        ...

    @abstractmethod
    def cancel(self, task_id: str) -> bool:
        """Cancel a scheduled task. Returns True if task existed."""
        ...

    @abstractmethod
    def list_tasks(self) -> list[dict]:
        """List all scheduled tasks with metadata."""
        ...

    @abstractmethod
    def trigger_now(self, task_id: str) -> bool:
        """Manually trigger a task immediately. Returns True if task exists."""
        ...


class InMemoryScheduler(ScheduledTaskRunner):
    """In-memory scheduler for deterministic testing.

    Does NOT use real timers or threads. Tasks are triggered via
    explicit tick(current_time) calls, enabling fully deterministic
    testing with no sleeps.

    Follows the AuditScheduler.tick() pattern from
    src/ltp/node/audit_scheduler.py.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, dict] = {}
        self._execution_log: list[dict] = []

    def schedule(
        self,
        task_id: str,
        callback: Callable[[], None],
        interval_seconds: float,
    ) -> None:
        if task_id in self._tasks:
            raise ValueError(f"Task {task_id!r} already scheduled")
        self._tasks[task_id] = {
            "callback": callback,
            "interval": interval_seconds,
            "next_at": 0.0,  # Will fire on first tick
            "executions": 0,
            "cancelled": False,
        }

    def cancel(self, task_id: str) -> bool:
        if task_id in self._tasks:
            self._tasks[task_id]["cancelled"] = True
            return True
        return False

    def list_tasks(self) -> list[dict]:
        return [
            {
                "task_id": tid,
                "interval": t["interval"],
                "executions": t["executions"],
                "cancelled": t["cancelled"],
                "next_at": t["next_at"],
            }
            for tid, t in self._tasks.items()
        ]

    def trigger_now(self, task_id: str) -> bool:
        task = self._tasks.get(task_id)
        if task is None or task["cancelled"]:
            return False
        task["callback"]()
        task["executions"] += 1
        self._execution_log.append({"task_id": task_id, "trigger": "manual"})
        return True

    def tick(self, current_time: float) -> list[str]:
        """Advance the scheduler clock and fire due tasks.

        Returns list of task_ids that were executed.
        """
        fired: list[str] = []
        for task_id, task in self._tasks.items():
            if task["cancelled"]:
                continue
            if current_time >= task["next_at"]:
                task["callback"]()
                task["executions"] += 1
                task["next_at"] = current_time + task["interval"]
                fired.append(task_id)
                self._execution_log.append(
                    {
                        "task_id": task_id,
                        "trigger": "tick",
                        "time": current_time,
                    }
                )
        return fired

    @property
    def execution_log(self) -> list[dict]:
        return list(self._execution_log)
