"""
Backup/restore abstraction tests.

Tests InMemoryBackupManager lifecycle, retention policies,
and BackupSchedule data structures.
"""

from __future__ import annotations

import pytest

from src.ltp.cloud.backup import (
    BackupMetadata,
    BackupSchedule,
    InMemoryBackupManager,
)

# ---------------------------------------------------------------------------
# BackupMetadata + BackupSchedule
# ---------------------------------------------------------------------------


class TestBackupDataStructures:
    def test_metadata_is_frozen(self):
        meta = BackupMetadata(
            backup_id="b1",
            service_id="svc",
            timestamp=1.0,
            size_bytes=1024,
            backup_type="snapshot",
            storage_path="s3://x",
        )
        with pytest.raises(AttributeError):
            meta.backup_id = "changed"

    def test_schedule_fields(self):
        sched = BackupSchedule(
            service_id="log-service",
            interval_seconds=86400.0,
            backup_type="snapshot",
            retention_count=7,
        )
        assert sched.service_id == "log-service"
        assert sched.retention_count == 7


# ---------------------------------------------------------------------------
# InMemoryBackupManager
# ---------------------------------------------------------------------------


class TestInMemoryBackupManager:
    def test_create_backup(self):
        mgr = InMemoryBackupManager()
        meta = mgr.create_backup("log-service")
        assert meta.service_id == "log-service"
        assert meta.backup_type == "snapshot"
        assert meta.backup_id != ""
        assert "s3://" in meta.storage_path

    def test_list_backups(self):
        mgr = InMemoryBackupManager()
        mgr.create_backup("svc-a")
        mgr.create_backup("svc-b")
        mgr.create_backup("svc-a")
        assert len(mgr.list_backups()) == 3
        assert len(mgr.list_backups("svc-a")) == 2
        assert len(mgr.list_backups("svc-b")) == 1

    def test_restore_backup(self):
        mgr = InMemoryBackupManager()
        meta = mgr.create_backup("svc")
        assert mgr.restore_backup(meta.backup_id) is True
        assert meta.backup_id in mgr.restore_history

    def test_restore_nonexistent_returns_false(self):
        mgr = InMemoryBackupManager()
        assert mgr.restore_backup("nonexistent") is False

    def test_delete_backup(self):
        mgr = InMemoryBackupManager()
        meta = mgr.create_backup("svc")
        assert mgr.delete_backup(meta.backup_id) is True
        assert len(mgr.list_backups()) == 0

    def test_delete_nonexistent_returns_false(self):
        mgr = InMemoryBackupManager()
        assert mgr.delete_backup("nope") is False

    def test_backup_type_audit_trail(self):
        mgr = InMemoryBackupManager()
        meta = mgr.create_backup("sth-chain", backup_type="audit_trail")
        assert meta.backup_type == "audit_trail"


# ---------------------------------------------------------------------------
# Retention Policy
# ---------------------------------------------------------------------------


class TestRetentionPolicy:
    def test_apply_retention_deletes_oldest(self):
        mgr = InMemoryBackupManager()
        for _ in range(5):
            mgr.create_backup("svc")
        assert len(mgr.list_backups("svc")) == 5

        deleted = mgr.apply_retention("svc", retention_count=3)
        assert deleted == 2
        assert len(mgr.list_backups("svc")) == 3

    def test_retention_no_action_when_under_limit(self):
        mgr = InMemoryBackupManager()
        mgr.create_backup("svc")
        mgr.create_backup("svc")
        deleted = mgr.apply_retention("svc", retention_count=5)
        assert deleted == 0
        assert len(mgr.list_backups("svc")) == 2

    def test_retention_per_service(self):
        mgr = InMemoryBackupManager()
        for _ in range(3):
            mgr.create_backup("svc-a")
        for _ in range(3):
            mgr.create_backup("svc-b")

        mgr.apply_retention("svc-a", retention_count=1)
        assert len(mgr.list_backups("svc-a")) == 1
        assert len(mgr.list_backups("svc-b")) == 3  # Unaffected
