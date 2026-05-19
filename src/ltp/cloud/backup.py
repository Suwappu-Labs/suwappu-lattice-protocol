"""
Backup/restore abstraction for ETP.

Production: RocksDB snapshots to S3, STH audit trails.
Development/Test: InMemoryBackupManager.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "BackupMetadata",
    "BackupSchedule",
    "BackupManager",
    "InMemoryBackupManager",
    "ETPBackupStrategy",
]


@dataclass(frozen=True)
class BackupMetadata:
    """Immutable metadata for a backup artifact."""

    backup_id: str
    service_id: str
    timestamp: float
    size_bytes: int
    backup_type: str  # "snapshot", "incremental", "audit_trail"
    storage_path: str


@dataclass(frozen=True)
class BackupSchedule:
    """Declarative backup schedule for a service."""

    service_id: str
    interval_seconds: float  # 86400 = daily
    backup_type: str = "snapshot"
    retention_count: int = 7  # Keep N most recent


class BackupManager(ABC):
    """Abstract backup/restore interface.

    Production: S3-backed with RocksDB snapshot integration.
    Development/Test: InMemoryBackupManager.
    """

    @abstractmethod
    def create_backup(
        self,
        service_id: str,
        backup_type: str = "snapshot",
    ) -> BackupMetadata:
        """Create a backup for a service. Returns metadata."""
        ...

    @abstractmethod
    def restore_backup(self, backup_id: str) -> bool:
        """Restore from a backup. Returns True on success."""
        ...

    @abstractmethod
    def list_backups(self, service_id: str = "") -> list[BackupMetadata]:
        """List backups, optionally filtered by service_id."""
        ...

    @abstractmethod
    def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup. Returns True if it existed."""
        ...


class InMemoryBackupManager(BackupManager):
    """In-memory backup manager for testing.

    Simulates backup creation/restore/deletion without actual data.
    Tracks metadata and restore history.
    """

    def __init__(self) -> None:
        self._backups: dict[str, BackupMetadata] = {}
        self._restore_history: list[str] = []

    def create_backup(
        self,
        service_id: str,
        backup_type: str = "snapshot",
    ) -> BackupMetadata:
        backup_id = str(uuid.uuid4())[:12]
        meta = BackupMetadata(
            backup_id=backup_id,
            service_id=service_id,
            timestamp=time.time(),
            size_bytes=1024 * 1024,  # Simulated 1MB
            backup_type=backup_type,
            storage_path=f"s3://etp-backups/{service_id}/{backup_id}.tar.gz",
        )
        self._backups[backup_id] = meta
        return meta

    def restore_backup(self, backup_id: str) -> bool:
        if backup_id not in self._backups:
            return False
        self._restore_history.append(backup_id)
        return True

    def list_backups(self, service_id: str = "") -> list[BackupMetadata]:
        if not service_id:
            return list(self._backups.values())
        return [b for b in self._backups.values() if b.service_id == service_id]

    def delete_backup(self, backup_id: str) -> bool:
        if backup_id in self._backups:
            del self._backups[backup_id]
            return True
        return False

    def apply_retention(self, service_id: str, retention_count: int) -> int:
        """Delete oldest backups for a service, keeping only retention_count.

        Returns number of backups deleted.
        """
        service_backups = sorted(
            [b for b in self._backups.values() if b.service_id == service_id],
            key=lambda b: b.timestamp,
        )
        if len(service_backups) <= retention_count:
            return 0

        to_delete = service_backups[: len(service_backups) - retention_count]
        for b in to_delete:
            del self._backups[b.backup_id]
        return len(to_delete)

    @property
    def restore_history(self) -> list[str]:
        return list(self._restore_history)


class ETPBackupStrategy:
    """Pre-configured backup schedules for ETP services.

    Defines per-service backup schedules:
      - log-service: daily snapshots, 30-day retention
      - shard-node: daily snapshots, 7-day retention
      - sth-chain: daily audit trail, indefinite retention (365)
    """

    def __init__(
        self,
        backup_manager: Optional[BackupManager] = None,
    ) -> None:
        self.backup_manager = backup_manager or InMemoryBackupManager()
        self.schedules = self._default_schedules()

    @staticmethod
    def _default_schedules() -> list[BackupSchedule]:
        return [
            BackupSchedule(
                service_id="log-service",
                interval_seconds=86400.0,
                backup_type="snapshot",
                retention_count=30,
            ),
            BackupSchedule(
                service_id="shard-node",
                interval_seconds=86400.0,
                backup_type="snapshot",
                retention_count=7,
            ),
            BackupSchedule(
                service_id="sth-chain",
                interval_seconds=86400.0,
                backup_type="audit_trail",
                retention_count=365,
            ),
        ]

    def run_scheduled_backups(self) -> list[BackupMetadata]:
        """Execute backups for all scheduled services. Returns metadata list."""
        results = []
        for schedule in self.schedules:
            meta = self.backup_manager.create_backup(
                schedule.service_id,
                schedule.backup_type,
            )
            results.append(meta)
            self.backup_manager.apply_retention(
                schedule.service_id,
                schedule.retention_count,
            )
        return results

    def get_schedule(self, service_id: str) -> Optional[BackupSchedule]:
        """Look up the backup schedule for a service."""
        for s in self.schedules:
            if s.service_id == service_id:
                return s
        return None

    @property
    def service_ids(self) -> list[str]:
        return [s.service_id for s in self.schedules]
