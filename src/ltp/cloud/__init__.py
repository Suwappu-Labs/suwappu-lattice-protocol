"""
Cloud infrastructure abstractions for ETP.

Provides pluggable interfaces for:
  - KMS (Key Management Service) — key lifecycle in cloud HSMs
  - ScheduledTaskRunner — periodic task execution (CronJob, EventBridge)

Each interface has an in-memory implementation for testing and development.
Production implementations delegate to AWS KMS, GCP Cloud KMS, or
Kubernetes CronJobs.
"""

from .aws_kms import AWSKMSBackend
from .backup import (
    BackupManager,
    BackupMetadata,
    BackupSchedule,
    ETPBackupStrategy,
    InMemoryBackupManager,
)
from .kms import InMemoryKMSBackend, KMSBackend
from .orchestrator import InMemoryOrchestrator, WorkflowOrchestrator, WorkflowResult, WorkflowStep
from .queue import InMemoryQueue, MessageQueue
from .scheduler import InMemoryScheduler, ScheduledTaskRunner

__all__ = [
    "KMSBackend",
    "InMemoryKMSBackend",
    "AWSKMSBackend",
    "ScheduledTaskRunner",
    "InMemoryScheduler",
    "MessageQueue",
    "InMemoryQueue",
    "WorkflowOrchestrator",
    "InMemoryOrchestrator",
    "WorkflowStep",
    "WorkflowResult",
    "BackupManager",
    "InMemoryBackupManager",
    "BackupMetadata",
    "BackupSchedule",
    "ETPBackupStrategy",
]
