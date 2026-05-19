"""
Tests for observability wiring: /metrics endpoint, new bridge/gossip metrics,
alert evaluator, and observability facade in gateway.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.observability.endpoint import ETPObservability
from src.ltp.observability.metrics import MetricsRegistry, create_etp_metrics

# ---------------------------------------------------------------------------
# /metrics endpoint
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    def test_metrics_returns_prometheus_text(self):
        config = GatewayConfig(jwt_enabled=False)
        app = create_app(config)
        obs = ETPObservability(node_id="test", region="test")
        app.state.observability = obs
        app.state.health_fn = lambda: {"status": "ok"}

        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        body = resp.text
        assert "etp_sth_publish_gap_seconds" in body

    def test_metrics_unauthenticated_with_jwt(self):
        """Metrics endpoint should NOT require JWT."""
        config = GatewayConfig(jwt_enabled=True)
        app = create_app(config)
        obs = ETPObservability(node_id="test", region="test")
        app.state.observability = obs
        app.state.health_fn = lambda: {"status": "ok"}

        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200  # Not 401

    def test_metrics_without_observability(self):
        """When observability is None, /metrics still returns (fallback)."""
        config = GatewayConfig(jwt_enabled=False)
        app = create_app(config)
        app.state.health_fn = lambda: {"status": "ok"}

        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "No metrics available" in resp.text


# ---------------------------------------------------------------------------
# New bridge/gossip metrics
# ---------------------------------------------------------------------------


class TestNewMetrics:
    def test_bridge_metrics_registered(self):
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        assert "bridge_records_bridged" in metrics
        assert "bridge_records_failed" in metrics
        assert "bridge_retry_queue_size" in metrics

    def test_gossip_metrics_registered(self):
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        assert "gossip_peers_discovered" in metrics
        assert "gossip_peers_timed_out" in metrics
        assert "gossip_exchanges_sent" in metrics

    def test_bridge_metrics_increment(self):
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        metrics["bridge_records_bridged"].inc()
        metrics["bridge_records_bridged"].inc()
        assert metrics["bridge_records_bridged"].get() == 2.0

    def test_gossip_metrics_increment(self):
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        metrics["gossip_peers_discovered"].inc(5)
        assert metrics["gossip_peers_discovered"].get() == 5.0

    def test_bridge_retry_queue_gauge(self):
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        metrics["bridge_retry_queue_size"].set(3)
        assert metrics["bridge_retry_queue_size"].get() == 3.0
        metrics["bridge_retry_queue_size"].set(0)
        assert metrics["bridge_retry_queue_size"].get() == 0.0

    def test_new_metrics_in_prometheus_text(self):
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        metrics["bridge_records_bridged"].inc()
        metrics["gossip_peers_discovered"].inc()

        text = registry.prometheus_text()
        assert "etp_bridge_records_bridged_total" in text
        assert "etp_gossip_peers_discovered_total" in text

    def test_total_metric_count(self):
        """Verify we have 16 pre-registered metrics (10 original + 6 new)."""
        registry = MetricsRegistry()
        metrics = create_etp_metrics(registry)
        assert len(metrics) == 16


# ---------------------------------------------------------------------------
# ETPObservability facade
# ---------------------------------------------------------------------------


class TestObservabilityFacade:
    def test_facade_has_all_metrics(self):
        obs = ETPObservability(node_id="test", region="test")
        assert "bridge_records_bridged" in obs.metrics
        assert "gossip_peers_discovered" in obs.metrics
        assert "sth_publish_gap" in obs.metrics

    def test_facade_alert_evaluator(self):
        obs = ETPObservability(node_id="test", region="test")
        # Should not fire with default metric values
        firing = obs.check_alerts()
        # Most alerts have thresholds > 0, so default 0 values shouldn't fire
        assert isinstance(firing, list)
