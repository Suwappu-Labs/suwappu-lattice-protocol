"""
Alert + mTLS integration tests.

Tests ETPObservability alert checking, ETPSecurityConfig default policies,
and combined metrics + alerts + security working together.
"""

from __future__ import annotations

import json
import logging

import pytest

from src.ltp.observability.endpoint import ETPObservability
from src.ltp.observability.tls import ETPSecurityConfig

# ---------------------------------------------------------------------------
# Observability with Alerts
# ---------------------------------------------------------------------------


class TestObservabilityAlerts:
    def test_no_alerts_firing_on_init(self):
        """Fresh observability has no firing alerts (all metrics at zero)."""
        obs = ETPObservability(node_id="alert-test")
        firing = obs.check_alerts()
        assert len(firing) == 0

    def test_alert_fires_when_metric_exceeds_threshold(self):
        """Setting STH gap above 60s triggers the critical alert."""
        obs = ETPObservability(node_id="alert-test")
        obs.metrics["sth_publish_gap"].set(120.0)  # Above 60s threshold
        firing = obs.check_alerts()
        names = [a.rule_name for a in firing]
        assert "sth_publish_gap" in names

    def test_alert_evaluator_pre_configured(self):
        """ETPObservability has 10 pre-configured alert rules."""
        obs = ETPObservability()
        assert obs.alert_evaluator.rule_count == 10

    def test_multiple_alerts_can_fire(self):
        """Multiple metrics over threshold triggers multiple alerts."""
        obs = ETPObservability()
        obs.metrics["sth_publish_gap"].set(100.0)  # > 60s → CRITICAL
        obs.metrics["bridge_message_age"].set(7200.0)  # > 3600s → WARNING
        firing = obs.check_alerts()
        assert len(firing) >= 2


# ---------------------------------------------------------------------------
# ETPSecurityConfig
# ---------------------------------------------------------------------------


class TestETPSecurityConfig:
    def test_default_creates_policies(self):
        """Default config has policies for shard-node, log-service, api-gateway."""
        sec = ETPSecurityConfig.default()
        assert sec.policies.policy_count == 3

    def test_shard_node_denies_unknown(self):
        sec = ETPSecurityConfig.default()
        assert sec.policies.check_access("shard-node", "protocol-service") is True
        assert sec.policies.check_access("shard-node", "unknown-caller") is False

    def test_log_service_allows_protocol_and_gateway(self):
        sec = ETPSecurityConfig.default()
        assert sec.policies.check_access("log-service", "protocol-service") is True
        assert sec.policies.check_access("log-service", "api-gateway") is True
        assert sec.policies.check_access("log-service", "random") is False

    def test_api_gateway_allows_all(self):
        sec = ETPSecurityConfig.default()
        assert sec.policies.check_access("api-gateway", "any-client") is True

    def test_cert_manager_available(self):
        sec = ETPSecurityConfig.default()
        assert sec.cert_manager is not None


# ---------------------------------------------------------------------------
# Combined Integration
# ---------------------------------------------------------------------------


class TestCombinedIntegration:
    def test_metrics_alerts_and_security_together(self):
        """All three systems work together from a single node setup."""
        obs = ETPObservability(node_id="integrated-node", region="US-East")
        sec = ETPSecurityConfig.default()

        # Record some metrics
        obs.metrics["rest_5xx"].inc(5)
        obs.metrics["sth_publish_gap"].set(90.0)

        # Check alerts
        firing = obs.check_alerts()
        assert len(firing) >= 1  # At least sth_publish_gap

        # Check security
        assert sec.policies.check_access("shard-node", "protocol-service") is True
        assert sec.policies.check_access("shard-node", "attacker") is False

        # Metrics endpoint still works
        status, _, body = obs.metrics_handler.handle_metrics_request()
        assert status == 200
        assert "etp_rest_5xx_total 5" in body
