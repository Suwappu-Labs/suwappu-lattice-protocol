"""
Infrastructure integration tests.

Tests ETPBackupStrategy schedules, validates Helm/K8s config consistency,
and proves the full infrastructure stack (observability + security + backup)
can coexist.
"""

from __future__ import annotations

import os

import pytest
import yaml

from src.ltp.cloud.backup import ETPBackupStrategy
from src.ltp.observability.endpoint import ETPObservability
from src.ltp.observability.tls import ETPSecurityConfig

DEPLOY_DIR = os.path.join(os.path.dirname(__file__), "..", "deploy")


# ---------------------------------------------------------------------------
# ETPBackupStrategy
# ---------------------------------------------------------------------------


class TestETPBackupStrategy:
    def test_default_schedules(self):
        strategy = ETPBackupStrategy()
        assert len(strategy.schedules) == 3
        ids = strategy.service_ids
        assert "log-service" in ids
        assert "shard-node" in ids
        assert "sth-chain" in ids

    def test_log_service_schedule(self):
        strategy = ETPBackupStrategy()
        sched = strategy.get_schedule("log-service")
        assert sched is not None
        assert sched.interval_seconds == 86400.0
        assert sched.retention_count == 30

    def test_run_scheduled_backups(self):
        strategy = ETPBackupStrategy()
        results = strategy.run_scheduled_backups()
        assert len(results) == 3
        service_ids = {r.service_id for r in results}
        assert service_ids == {"log-service", "shard-node", "sth-chain"}

    def test_retention_applied_after_backup(self):
        strategy = ETPBackupStrategy()
        # Run many backup cycles
        for _ in range(10):
            strategy.run_scheduled_backups()
        # shard-node retention is 7 — should have at most 7
        shard_backups = strategy.backup_manager.list_backups("shard-node")
        assert len(shard_backups) <= 7


# ---------------------------------------------------------------------------
# Config Consistency
# ---------------------------------------------------------------------------


class TestConfigConsistency:
    def test_k8s_manifests_reference_etp_namespace(self):
        """All K8s manifests reference the 'etp' namespace."""
        k8s_dir = os.path.join(DEPLOY_DIR, "k8s")
        for filename in os.listdir(k8s_dir):
            if not filename.endswith(".yaml"):
                continue
            with open(os.path.join(k8s_dir, filename)) as f:
                for doc in yaml.safe_load_all(f):
                    if doc is None:
                        continue
                    ns = doc.get("metadata", {}).get(
                        "namespace", doc.get("metadata", {}).get("name")
                    )
                    assert ns == "etp", f"{filename} references namespace {ns!r}, expected 'etp'"

    def test_helm_service_count_matches_deployment_plan(self):
        """Helm values define 4 core services + key rotation + anchor."""
        path = os.path.join(DEPLOY_DIR, "helm", "values.yaml")
        with open(path) as f:
            values = yaml.safe_load(f)
        # 4 core services
        assert "apiGateway" in values
        assert "protocolService" in values
        assert "logService" in values
        assert "shardNode" in values
        # Key rotation
        assert "keyRotation" in values


# ---------------------------------------------------------------------------
# Full Infrastructure Stack
# ---------------------------------------------------------------------------


class TestFullInfraStack:
    def test_all_components_coexist(self):
        """Observability + Security + Backup all initialize together."""
        obs = ETPObservability(node_id="infra-test", region="US-East")
        sec = ETPSecurityConfig.default()
        backup = ETPBackupStrategy()

        # Metrics work
        obs.metrics["sth_publish_gap"].set(10.0)
        assert obs.check_alerts() == []  # 10s < 60s threshold

        # Security works
        assert sec.policies.check_access("shard-node", "protocol-service") is True

        # Backup works
        results = backup.run_scheduled_backups()
        assert len(results) == 3

        # Prometheus endpoint includes metrics
        _, _, body = obs.metrics_handler.handle_metrics_request()
        assert "etp_sth_publish_gap_seconds 10" in body
