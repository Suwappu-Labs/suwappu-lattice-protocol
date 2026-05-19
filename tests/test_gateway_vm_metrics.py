"""Tests for gateway VM metrics registration."""

import pytest


class TestGatewayMetrics:
    def test_create_registers_all_metrics(self):
        from src.ltp.gateway_vm.metrics import create_gateway_metrics
        from src.ltp.observability.metrics import MetricsRegistry

        registry = MetricsRegistry()
        metrics = create_gateway_metrics(registry)

        assert "etp_gateway_events_observed" in metrics
        assert "etp_gateway_events_accepted" in metrics
        assert "etp_gateway_events_rejected" in metrics
        assert "etp_gateway_anchor_latency" in metrics
        assert "etp_gateway_finality_wait" in metrics
        assert "etp_gateway_replay_rejections" in metrics

    def test_counters_increment(self):
        from src.ltp.gateway_vm.metrics import create_gateway_metrics
        from src.ltp.observability.metrics import MetricsRegistry

        registry = MetricsRegistry()
        m = create_gateway_metrics(registry)
        m["etp_gateway_events_observed"].inc()
        m["etp_gateway_events_observed"].inc()
        assert m["etp_gateway_events_observed"].get() == 2.0

    def test_rejected_counter_accepts_labels(self):
        from src.ltp.gateway_vm.metrics import create_gateway_metrics
        from src.ltp.observability.metrics import MetricsRegistry

        registry = MetricsRegistry()
        m = create_gateway_metrics(registry)
        m["etp_gateway_events_rejected"].inc(labels={"reason": "replay"})
        m["etp_gateway_events_rejected"].inc(labels={"reason": "finality"})
        assert m["etp_gateway_events_rejected"].get(labels={"reason": "replay"}) == 1.0
        assert m["etp_gateway_events_rejected"].get(labels={"reason": "finality"}) == 1.0

    def test_histogram_observes(self):
        from src.ltp.gateway_vm.metrics import create_gateway_metrics
        from src.ltp.observability.metrics import MetricsRegistry

        registry = MetricsRegistry()
        m = create_gateway_metrics(registry)
        m["etp_gateway_anchor_latency"].observe(0.5)
        m["etp_gateway_anchor_latency"].observe(1.2)
        # Histogram exists and accepted observations
        assert registry.get("etp_gateway_anchor_latency") is not None
