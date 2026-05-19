"""
Observability endpoint and facade for ETP nodes.

Provides:
  - MetricsRequestHandler: HTTP handler returning Prometheus text format
  - ETPObservability: Facade combining metrics + logging for node init
"""

from __future__ import annotations

import logging
from typing import Optional

from .alerts import AlertEvaluator, AlertResult, create_etp_alert_rules
from .logging import StructuredLogger
from .metrics import Counter, Gauge, Histogram, MetricsRegistry, create_etp_metrics

__all__ = [
    "MetricsRequestHandler",
    "ETPObservability",
]

# Prometheus content type per exposition format spec
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class MetricsRequestHandler:
    """HTTP request handler for /metrics endpoint.

    Returns MetricsRegistry.prometheus_text() with correct content type.
    Designed to integrate into existing HealthServer or run standalone.
    """

    def __init__(self, registry: MetricsRegistry) -> None:
        self._registry = registry

    def handle_metrics_request(self) -> tuple[int, str, str]:
        """Handle a /metrics request.

        Returns (status_code, content_type, body).
        """
        body = self._registry.prometheus_text()
        return 200, PROMETHEUS_CONTENT_TYPE, body


class ETPObservability:
    """Facade combining metrics + structured logging for ETP node initialization.

    Creates a MetricsRegistry with all pre-registered ETP metrics and
    a StructuredLogger with node identity default fields.

    Usage:
        obs = ETPObservability(node_id="node-us-east-1", region="US-East")
        obs.metrics["sth_publish_gap"].set(5.0)
        obs.logger.info("Entity committed", entity_id="abc123")
        status, content_type, body = obs.metrics_handler.handle_metrics_request()
    """

    def __init__(
        self,
        node_id: str = "",
        region: str = "",
        log_level: int = logging.DEBUG,
    ) -> None:
        self.registry = MetricsRegistry()
        self.metrics = create_etp_metrics(self.registry)
        self.logger = StructuredLogger(
            f"etp.{node_id}" if node_id else "etp",
            default_fields={"node_id": node_id, "region": region},
            level=log_level,
        )
        self.metrics_handler = MetricsRequestHandler(self.registry)
        self.alert_rules = create_etp_alert_rules()
        self.alert_evaluator = AlertEvaluator(self.alert_rules, self.registry)

    def check_alerts(self) -> list[AlertResult]:
        """Evaluate all alert rules. Returns only firing alerts."""
        return self.alert_evaluator.firing_alerts()
