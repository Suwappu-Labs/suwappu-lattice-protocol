"""
Prometheus-compatible metrics collector tests.

Tests Counter, Gauge, Histogram metric types, label support,
Prometheus text export, and pre-registered ETP metrics.
"""

from __future__ import annotations

import threading

import pytest

from src.ltp.observability.metrics import (
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    MetricType,
    create_etp_metrics,
)

# ---------------------------------------------------------------------------
# Counter
# ---------------------------------------------------------------------------


class TestCounter:
    def test_increment(self):
        c = Counter("test_counter")
        c.inc()
        assert c.get() == 1.0
        c.inc(5)
        assert c.get() == 6.0

    def test_negative_increment_rejected(self):
        c = Counter("test_counter")
        with pytest.raises(ValueError, match="must be >= 0"):
            c.inc(-1)

    def test_labels(self):
        c = Counter("http_requests")
        c.inc(1, labels={"method": "GET"})
        c.inc(3, labels={"method": "POST"})
        assert c.get(labels={"method": "GET"}) == 1.0
        assert c.get(labels={"method": "POST"}) == 3.0


# ---------------------------------------------------------------------------
# Gauge
# ---------------------------------------------------------------------------


class TestGauge:
    def test_set_and_get(self):
        g = Gauge("temperature")
        g.set(42.5)
        assert g.get() == 42.5

    def test_inc_and_dec(self):
        g = Gauge("connections")
        g.inc()
        g.inc()
        g.dec()
        assert g.get() == 1.0

    def test_labels(self):
        g = Gauge("queue_size")
        g.set(10, labels={"queue": "alpha"})
        g.set(20, labels={"queue": "beta"})
        assert g.get(labels={"queue": "alpha"}) == 10.0
        assert g.get(labels={"queue": "beta"}) == 20.0


# ---------------------------------------------------------------------------
# Histogram
# ---------------------------------------------------------------------------


class TestHistogram:
    def test_observe_and_count(self):
        h = Histogram("latency", buckets=(0.1, 0.5, 1.0))
        h.observe(0.05)
        h.observe(0.3)
        h.observe(0.8)
        assert h.get_count() == 3
        assert h.get_sum() == pytest.approx(1.15, abs=0.001)

    def test_bucket_distribution(self):
        h = Histogram("latency", buckets=(0.1, 0.5, 1.0))
        h.observe(0.05)  # fits in 0.1, 0.5, 1.0
        h.observe(0.3)  # fits in 0.5, 1.0
        h.observe(0.8)  # fits in 1.0
        samples = h._samples()
        assert len(samples) == 1
        buckets = samples[0][1]["buckets"]
        assert buckets[0.1] == 1  # 0.05 <= 0.1
        assert buckets[0.5] == 2  # 0.05, 0.3 <= 0.5
        assert buckets[1.0] == 3  # all three <= 1.0


# ---------------------------------------------------------------------------
# MetricsRegistry
# ---------------------------------------------------------------------------


class TestMetricsRegistry:
    def test_register_counter(self):
        reg = MetricsRegistry()
        c = reg.counter("requests_total", "Total requests")
        c.inc()
        assert reg.get("requests_total") is c

    def test_register_gauge(self):
        reg = MetricsRegistry()
        g = reg.gauge("connections", "Active connections")
        g.set(5)
        assert reg.get("connections") is g

    def test_register_histogram(self):
        reg = MetricsRegistry()
        h = reg.histogram("latency_seconds", "Request latency")
        h.observe(0.1)
        assert reg.get("latency_seconds") is h

    def test_duplicate_returns_same_instance(self):
        reg = MetricsRegistry()
        c1 = reg.counter("my_counter")
        c2 = reg.counter("my_counter")
        assert c1 is c2

    def test_type_mismatch_rejected(self):
        reg = MetricsRegistry()
        reg.counter("my_metric")
        with pytest.raises(TypeError, match="already registered"):
            reg.gauge("my_metric")

    def test_metric_names(self):
        reg = MetricsRegistry()
        reg.counter("z_counter")
        reg.gauge("a_gauge")
        assert reg.metric_names == ["a_gauge", "z_counter"]


# ---------------------------------------------------------------------------
# Prometheus Text Export
# ---------------------------------------------------------------------------


class TestPrometheusExport:
    def test_counter_export(self):
        reg = MetricsRegistry()
        c = reg.counter("http_requests_total", "Total HTTP requests")
        c.inc(42)
        text = reg.prometheus_text()
        assert "# HELP http_requests_total Total HTTP requests" in text
        assert "# TYPE http_requests_total counter" in text
        assert "http_requests_total 42" in text

    def test_gauge_export(self):
        reg = MetricsRegistry()
        g = reg.gauge("temperature", "Current temp")
        g.set(36.6)
        text = reg.prometheus_text()
        assert "# TYPE temperature gauge" in text
        assert "temperature 36.6" in text

    def test_histogram_export(self):
        reg = MetricsRegistry()
        h = reg.histogram("latency", "Latency", buckets=(0.1, 0.5))
        h.observe(0.05)
        h.observe(0.3)
        text = reg.prometheus_text()
        assert "# TYPE latency histogram" in text
        assert "latency_bucket" in text
        assert "latency_sum" in text
        assert "latency_count 2" in text

    def test_labeled_counter_export(self):
        reg = MetricsRegistry()
        c = reg.counter("requests", "Requests")
        c.inc(10, labels={"method": "GET"})
        text = reg.prometheus_text()
        assert 'method="GET"' in text

    def test_empty_registry_export(self):
        reg = MetricsRegistry()
        assert reg.prometheus_text() == ""


# ---------------------------------------------------------------------------
# Pre-registered ETP Metrics
# ---------------------------------------------------------------------------


class TestETPMetrics:
    def test_create_etp_metrics(self):
        reg = MetricsRegistry()
        metrics = create_etp_metrics(reg)
        assert "sth_publish_gap" in metrics
        assert "audit_failure_rate" in metrics
        assert "materialize_failures" in metrics
        assert "rest_5xx" in metrics
        assert "rest_latency" in metrics
        assert "shard_fetch_latency" in metrics
        assert "key_rotation_failures" in metrics
        assert "bridge_message_age" in metrics
        assert len(reg.metric_names) == 16

    def test_etp_metrics_usable(self):
        reg = MetricsRegistry()
        m = create_etp_metrics(reg)
        m["sth_publish_gap"].set(5.0)
        m["materialize_failures"].inc()
        m["rest_latency"].observe(0.045)
        text = reg.prometheus_text()
        assert "etp_sth_publish_gap_seconds 5" in text
        assert "etp_materialize_failure_total 1" in text
        assert "etp_rest_latency_seconds_count 1" in text
