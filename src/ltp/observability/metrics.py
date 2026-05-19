"""
Prometheus-compatible metrics collector for ETP.

Provides Counter, Gauge, and Histogram metric types with label support
and Prometheus text exposition format export.

No external dependencies — pure Python implementation. Production
deployments can swap in the official prometheus_client library.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from enum import Enum
from typing import Optional

__all__ = [
    "MetricType",
    "Counter",
    "Gauge",
    "Histogram",
    "MetricsRegistry",
]


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class Counter:
    """Monotonically increasing counter. Thread-safe."""

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description
        self.type = MetricType.COUNTER
        self._lock = threading.Lock()
        self._values: dict[str, float] = defaultdict(float)

    def inc(self, value: float = 1.0, labels: Optional[dict[str, str]] = None) -> None:
        """Increment the counter. Value must be >= 0."""
        if value < 0:
            raise ValueError("Counter can only be incremented (value must be >= 0)")
        key = _labels_key(labels)
        with self._lock:
            self._values[key] += value

    def get(self, labels: Optional[dict[str, str]] = None) -> float:
        """Get the current counter value."""
        key = _labels_key(labels)
        with self._lock:
            return self._values[key]

    def _samples(self) -> list[tuple[str, float]]:
        """Return all (label_key, value) pairs."""
        with self._lock:
            return list(self._values.items())


class Gauge:
    """Value that can go up and down. Thread-safe."""

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description
        self.type = MetricType.GAUGE
        self._lock = threading.Lock()
        self._values: dict[str, float] = defaultdict(float)

    def set(self, value: float, labels: Optional[dict[str, str]] = None) -> None:
        """Set the gauge to a specific value."""
        key = _labels_key(labels)
        with self._lock:
            self._values[key] = value

    def inc(self, value: float = 1.0, labels: Optional[dict[str, str]] = None) -> None:
        """Increment the gauge."""
        key = _labels_key(labels)
        with self._lock:
            self._values[key] += value

    def dec(self, value: float = 1.0, labels: Optional[dict[str, str]] = None) -> None:
        """Decrement the gauge."""
        key = _labels_key(labels)
        with self._lock:
            self._values[key] -= value

    def get(self, labels: Optional[dict[str, str]] = None) -> float:
        """Get the current gauge value."""
        key = _labels_key(labels)
        with self._lock:
            return self._values[key]

    def _samples(self) -> list[tuple[str, float]]:
        with self._lock:
            return list(self._values.items())


# Default histogram buckets (matching Prometheus defaults)
DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class Histogram:
    """Distribution of observed values. Thread-safe."""

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> None:
        self.name = name
        self.description = description
        self.type = MetricType.HISTOGRAM
        self._buckets = tuple(sorted(buckets))
        self._lock = threading.Lock()
        # label_key → {bucket_bound: count}
        self._bucket_counts: dict[str, dict[float, int]] = {}
        self._sums: dict[str, float] = defaultdict(float)
        self._counts: dict[str, int] = defaultdict(int)

    def observe(self, value: float, labels: Optional[dict[str, str]] = None) -> None:
        """Record an observed value."""
        key = _labels_key(labels)
        with self._lock:
            if key not in self._bucket_counts:
                self._bucket_counts[key] = {b: 0 for b in self._buckets}
            for bound in self._buckets:
                if value <= bound:
                    self._bucket_counts[key][bound] += 1
            self._sums[key] += value
            self._counts[key] += 1

    def get_count(self, labels: Optional[dict[str, str]] = None) -> int:
        """Get total observation count."""
        key = _labels_key(labels)
        with self._lock:
            return self._counts[key]

    def get_sum(self, labels: Optional[dict[str, str]] = None) -> float:
        """Get sum of all observations."""
        key = _labels_key(labels)
        with self._lock:
            return self._sums[key]

    def _samples(self) -> list[tuple[str, dict]]:
        """Return all (label_key, {buckets, sum, count}) pairs."""
        with self._lock:
            result = []
            for key in self._counts:
                result.append(
                    (
                        key,
                        {
                            "buckets": dict(self._bucket_counts.get(key, {})),
                            "sum": self._sums[key],
                            "count": self._counts[key],
                        },
                    )
                )
            return result


class MetricsRegistry:
    """Prometheus-compatible metrics registry.

    Collects counters, gauges, and histograms and exports them
    in Prometheus text exposition format.
    """

    def __init__(self) -> None:
        self._metrics: dict[str, Counter | Gauge | Histogram] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, description: str = "") -> Counter:
        """Register and return a counter metric."""
        with self._lock:
            if name in self._metrics:
                existing = self._metrics[name]
                if not isinstance(existing, Counter):
                    raise TypeError(f"Metric {name!r} already registered as {existing.type.value}")
                return existing
            c = Counter(name, description)
            self._metrics[name] = c
            return c

    def gauge(self, name: str, description: str = "") -> Gauge:
        """Register and return a gauge metric."""
        with self._lock:
            if name in self._metrics:
                existing = self._metrics[name]
                if not isinstance(existing, Gauge):
                    raise TypeError(f"Metric {name!r} already registered as {existing.type.value}")
                return existing
            g = Gauge(name, description)
            self._metrics[name] = g
            return g

    def histogram(
        self,
        name: str,
        description: str = "",
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ) -> Histogram:
        """Register and return a histogram metric."""
        with self._lock:
            if name in self._metrics:
                existing = self._metrics[name]
                if not isinstance(existing, Histogram):
                    raise TypeError(f"Metric {name!r} already registered as {existing.type.value}")
                return existing
            h = Histogram(name, description, buckets)
            self._metrics[name] = h
            return h

    def get(self, name: str) -> Optional[Counter | Gauge | Histogram]:
        """Look up a metric by name."""
        with self._lock:
            return self._metrics.get(name)

    def prometheus_text(self) -> str:
        """Export all metrics in Prometheus text exposition format.

        Format: https://prometheus.io/docs/instrumenting/exposition_formats/
        """
        lines: list[str] = []
        with self._lock:
            metrics = list(self._metrics.values())

        for metric in metrics:
            lines.append(f"# HELP {metric.name} {metric.description}")
            lines.append(f"# TYPE {metric.name} {metric.type.value}")

            if isinstance(metric, (Counter, Gauge)):
                for label_key, value in metric._samples():
                    if label_key:
                        lines.append(f"{metric.name}{{{label_key}}} {value}")
                    else:
                        lines.append(f"{metric.name} {value}")

            elif isinstance(metric, Histogram):
                for label_key, data in metric._samples():
                    for bound, count in sorted(data["buckets"].items()):
                        lines.append(
                            f'{metric.name}_bucket{{{label_key + "," if label_key else ""}le="{bound}"}} {count}'
                        )
                    lines.append(
                        f'{metric.name}_bucket{{{label_key + "," if label_key else ""}le="+Inf"}} {data["count"]}'
                    )
                    if label_key:
                        lines.append(f"{metric.name}_sum{{{label_key}}} {data['sum']}")
                        lines.append(f"{metric.name}_count{{{label_key}}} {data['count']}")
                    else:
                        lines.append(f"{metric.name}_sum {data['sum']}")
                        lines.append(f"{metric.name}_count {data['count']}")

        return "\n".join(lines) + "\n" if lines else ""

    @property
    def metric_names(self) -> list[str]:
        with self._lock:
            return sorted(self._metrics.keys())


def _labels_key(labels: Optional[dict[str, str]]) -> str:
    """Convert labels dict to a sorted key string for Prometheus format."""
    if not labels:
        return ""
    return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))


def create_etp_metrics(registry: MetricsRegistry) -> dict[str, Counter | Gauge | Histogram]:
    """Pre-register all ETP metrics matching the deployment plan alert table."""
    return {
        "sth_publish_gap": registry.gauge(
            "etp_sth_publish_gap_seconds",
            "Seconds since last STH was published",
        ),
        "audit_failure_rate": registry.gauge(
            "etp_audit_failure_rate",
            "Current audit failure rate (0-1)",
        ),
        "materialize_failures": registry.counter(
            "etp_materialize_failure_total",
            "Total materialization failures",
        ),
        "rest_5xx": registry.counter(
            "etp_rest_5xx_total",
            "Total REST API 5xx responses",
        ),
        "rest_latency": registry.histogram(
            "etp_rest_latency_seconds",
            "REST API request latency",
            buckets=(0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0),
        ),
        "shard_fetch_latency": registry.histogram(
            "etp_shard_fetch_latency_seconds",
            "Shard fetch latency",
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
        ),
        "key_rotation_failures": registry.counter(
            "etp_key_rotation_failures_total",
            "Key rotation task failures",
        ),
        "bridge_message_age": registry.gauge(
            "etp_bridge_message_age_seconds",
            "Age of oldest unfinalized bridge message",
        ),
        "nonce_violations": registry.counter(
            "etp_nonce_violation_total",
            "Total nonce monotonicity violations",
        ),
        "dst_regressions": registry.counter(
            "etp_dst_regression_total",
            "DST nightly regression failures",
        ),
        # Bridge operator metrics
        "bridge_records_bridged": registry.counter(
            "etp_bridge_records_bridged_total",
            "Records successfully bridged cross-chain",
        ),
        "bridge_records_failed": registry.counter(
            "etp_bridge_records_failed_total",
            "Bridge transfer failures",
        ),
        "bridge_retry_queue_size": registry.gauge(
            "etp_bridge_retry_queue_size",
            "Current bridge retry queue depth",
        ),
        # Gossip metrics
        "gossip_peers_discovered": registry.counter(
            "etp_gossip_peers_discovered_total",
            "Peers discovered via gossip exchange",
        ),
        "gossip_peers_timed_out": registry.counter(
            "etp_gossip_peers_timed_out_total",
            "Peers marked disconnected by liveness timeout",
        ),
        "gossip_exchanges_sent": registry.counter(
            "etp_gossip_exchanges_sent_total",
            "Peer exchange messages sent",
        ),
    }
