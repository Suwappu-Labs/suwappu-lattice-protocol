"""
Hardening and observability gate closure test.

Single scenario proving all components work together:
  Metrics + Alerts + Logging + Security + Backup + CI Harness.
"""

from __future__ import annotations

import json
import logging

import pytest

from src.ltp.cloud.backup import ETPBackupStrategy
from src.ltp.observability.endpoint import ETPObservability
from src.ltp.observability.tls import ETPSecurityConfig
from src.simulator.ci_harness import DSTCIHarness

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(self.format(record))


# ---------------------------------------------------------------------------
# Full Integration
# ---------------------------------------------------------------------------


class TestPhase7FullIntegration:
    def test_all_phase7_components_in_single_scenario(self):
        """
        1. ETPObservability: metrics + alerts + logging
        2. ETPSecurityConfig: mTLS + network policies
        3. ETPBackupStrategy: scheduled backups + retention
        4. DSTCIHarness: regression gate
        """
        # 1. Observability
        obs = ETPObservability(node_id="gate-node", region="US-East")
        handler = _CaptureHandler()
        obs.logger.attach_handler(handler)
        obs.logger._logger.setLevel(logging.DEBUG)

        obs.metrics["sth_publish_gap"].set(30.0)
        obs.metrics["rest_5xx"].inc(2)
        obs.logger.info("Gate closure test", phase=7)

        # Metrics endpoint works
        status, content_type, body = obs.metrics_handler.handle_metrics_request()
        assert status == 200
        assert "etp_sth_publish_gap_seconds 30" in body

        # Alerts: 30s < 60s threshold, so STH gap should NOT fire
        firing = obs.check_alerts()
        sth_alerts = [a for a in firing if a.rule_name == "sth_publish_gap"]
        assert len(sth_alerts) == 0

        # Logger emitted JSON
        assert len(handler.records) >= 1
        parsed = json.loads(handler.records[0])
        assert parsed["node_id"] == "gate-node"

        # 2. Security
        sec = ETPSecurityConfig.default()
        assert sec.policies.check_access("shard-node", "protocol-service") is True
        assert sec.policies.check_access("shard-node", "attacker") is False

        # 3. Backup
        backup = ETPBackupStrategy()
        results = backup.run_scheduled_backups()
        assert len(results) == 3

        # 4. DST Gate
        harness = DSTCIHarness(seeds=[42], steps=100, fault_rate=0.0)
        dst_result = harness.run()
        assert dst_result.passed is True


# ---------------------------------------------------------------------------
# Individual Gate Checks
# ---------------------------------------------------------------------------


class TestPhase7GateChecklist:
    def test_metrics_endpoint_returns_prometheus(self):
        obs = ETPObservability()
        obs.metrics["rest_5xx"].inc(1)
        _, ct, body = obs.metrics_handler.handle_metrics_request()
        assert "text/plain" in ct
        assert "etp_rest_5xx_total 1" in body

    def test_alerts_evaluate_correctly(self):
        obs = ETPObservability()
        obs.metrics["sth_publish_gap"].set(120.0)  # Over 60s
        firing = obs.check_alerts()
        names = [a.rule_name for a in firing]
        assert "sth_publish_gap" in names

    def test_network_policy_enforces(self):
        sec = ETPSecurityConfig.default()
        assert sec.policies.check_access("log-service", "api-gateway") is True
        assert sec.policies.check_access("log-service", "random") is False

    def test_backup_retention_works(self):
        strategy = ETPBackupStrategy()
        for _ in range(10):
            strategy.run_scheduled_backups()
        shard_backups = strategy.backup_manager.list_backups("shard-node")
        assert len(shard_backups) <= 7

    def test_dst_harness_clean_pass(self):
        harness = DSTCIHarness(seeds=[42, 123], steps=50, fault_rate=0.0)
        result = harness.run()
        assert result.passed is True
        assert result.seeds_run == 2
