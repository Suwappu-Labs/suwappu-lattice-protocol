"""
Observability integration tests.

Tests /metrics endpoint, ETPObservability facade, and combined
metrics + logging working together.
"""

from __future__ import annotations

import json
import logging

import pytest

from src.ltp.observability.endpoint import (
    PROMETHEUS_CONTENT_TYPE,
    ETPObservability,
    MetricsRequestHandler,
)
from src.ltp.observability.logging import CorrelationContext
from src.ltp.observability.metrics import MetricsRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[str] = []

    def emit(self, record):
        self.records.append(self.format(record))


# ---------------------------------------------------------------------------
# /metrics endpoint
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    def test_returns_200(self):
        reg = MetricsRegistry()
        handler = MetricsRequestHandler(reg)
        status, _, _ = handler.handle_metrics_request()
        assert status == 200

    def test_correct_content_type(self):
        reg = MetricsRegistry()
        handler = MetricsRequestHandler(reg)
        _, content_type, _ = handler.handle_metrics_request()
        assert content_type == PROMETHEUS_CONTENT_TYPE
        assert "text/plain" in content_type

    def test_contains_prometheus_text(self):
        reg = MetricsRegistry()
        c = reg.counter("test_requests_total", "Test counter")
        c.inc(42)
        handler = MetricsRequestHandler(reg)
        _, _, body = handler.handle_metrics_request()
        assert "test_requests_total 42" in body
        assert "# TYPE test_requests_total counter" in body

    def test_empty_registry(self):
        reg = MetricsRegistry()
        handler = MetricsRequestHandler(reg)
        _, _, body = handler.handle_metrics_request()
        assert body == ""


# ---------------------------------------------------------------------------
# ETPObservability facade
# ---------------------------------------------------------------------------


class TestETPObservability:
    def test_creates_metrics_and_logger(self):
        obs = ETPObservability(node_id="node-1", region="US-East")
        assert obs.registry is not None
        assert obs.logger is not None
        assert obs.metrics_handler is not None
        assert (
            len(obs.metrics) == 16
        )  # 16 pre-registered ETP metrics (10 original + 6 bridge/gossip)

    def test_metrics_usable(self):
        obs = ETPObservability(node_id="test")
        obs.metrics["sth_publish_gap"].set(3.5)
        obs.metrics["materialize_failures"].inc()
        obs.metrics["rest_latency"].observe(0.045)

        _, _, body = obs.metrics_handler.handle_metrics_request()
        assert "etp_sth_publish_gap_seconds 3.5" in body
        assert "etp_materialize_failure_total 1" in body

    def test_logger_includes_node_id(self):
        obs = ETPObservability(node_id="node-42", region="EU-West")
        handler = _CaptureHandler()
        obs.logger.attach_handler(handler)
        obs.logger._logger.setLevel(logging.DEBUG)

        obs.logger.info("Test event", entity_id="abc")
        parsed = json.loads(handler.records[0])
        assert parsed["node_id"] == "node-42"
        assert parsed["region"] == "EU-West"
        assert parsed["entity_id"] == "abc"


# ---------------------------------------------------------------------------
# Combined metrics + logging
# ---------------------------------------------------------------------------


class TestMetricsAndLoggingTogether:
    def setup_method(self):
        CorrelationContext.clear()

    def test_record_metric_and_log(self):
        """Metrics and logs work simultaneously from the same facade."""
        obs = ETPObservability(node_id="combined-test")
        handler = _CaptureHandler()
        obs.logger.attach_handler(handler)
        obs.logger._logger.setLevel(logging.DEBUG)

        # Record a metric
        obs.metrics["rest_5xx"].inc(1, labels={"endpoint": "/v1/commit"})

        # Log the event
        with obs.logger.correlation_scope("req-500"):
            obs.logger.error("Server error", endpoint="/v1/commit", status=500)

        # Verify metric
        _, _, body = obs.metrics_handler.handle_metrics_request()
        assert "etp_rest_5xx_total" in body

        # Verify log
        parsed = json.loads(handler.records[0])
        assert parsed["level"] == "ERROR"
        assert parsed["correlation_id"] == "req-500"
        assert parsed["endpoint"] == "/v1/commit"
        assert parsed["status"] == 500
