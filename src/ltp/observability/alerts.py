"""
Alert rule definitions for ETP observability.

Declarative alert rules that can be evaluated against a MetricsRegistry.
Production: export to Prometheus Alertmanager rules or PagerDuty conditions.
Development/Test: evaluate in-process via AlertEvaluator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .metrics import Counter, Gauge, Histogram, MetricsRegistry

__all__ = [
    "AlertSeverity",
    "AlertCondition",
    "AlertRule",
    "AlertResult",
    "AlertEvaluator",
    "create_etp_alert_rules",
]


class AlertSeverity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"


class AlertCondition(Enum):
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    EQUALS = "eq"
    ANY_OCCURRENCE = "any"


@dataclass(frozen=True)
class AlertRule:
    """Declarative alert rule definition."""

    name: str
    metric_name: str
    condition: AlertCondition
    threshold: float
    severity: AlertSeverity
    description: str
    for_seconds: float = 0.0


@dataclass
class AlertResult:
    """Result of evaluating a single alert rule."""

    rule_name: str
    firing: bool
    severity: str
    metric_value: float = 0.0
    description: str = ""


class AlertEvaluator:
    """Evaluates alert rules against a MetricsRegistry.

    For each rule, reads the metric value from the registry and
    compares against the threshold using the specified condition.
    """

    def __init__(
        self,
        rules: list[AlertRule],
        registry: MetricsRegistry,
    ) -> None:
        self._rules = list(rules)
        self._registry = registry

    def evaluate_all(self) -> list[AlertResult]:
        """Evaluate all rules and return results (both firing and OK)."""
        results = []
        for rule in self._rules:
            result = self._evaluate_rule(rule)
            results.append(result)
        return results

    def firing_alerts(self) -> list[AlertResult]:
        """Return only alerts that are currently firing."""
        return [r for r in self.evaluate_all() if r.firing]

    def _evaluate_rule(self, rule: AlertRule) -> AlertResult:
        """Evaluate a single rule against the registry."""
        metric = self._registry.get(rule.metric_name)
        if metric is None:
            return AlertResult(
                rule_name=rule.name,
                firing=False,
                severity=rule.severity.value,
                description=f"Metric {rule.metric_name!r} not found",
            )

        value = self._get_metric_value(metric)
        firing = self._check_condition(rule.condition, value, rule.threshold)

        return AlertResult(
            rule_name=rule.name,
            firing=firing,
            severity=rule.severity.value,
            metric_value=value,
            description=rule.description,
        )

    def _get_metric_value(self, metric) -> float:
        """Extract the current scalar value from a metric."""
        if isinstance(metric, (Counter, Gauge)):
            return metric.get()
        elif isinstance(metric, Histogram):
            return float(metric.get_count())
        return 0.0

    def _check_condition(
        self,
        condition: AlertCondition,
        value: float,
        threshold: float,
    ) -> bool:
        """Evaluate a condition against a value."""
        if condition == AlertCondition.GREATER_THAN:
            return value > threshold
        elif condition == AlertCondition.LESS_THAN:
            return value < threshold
        elif condition == AlertCondition.EQUALS:
            return value == threshold
        elif condition == AlertCondition.ANY_OCCURRENCE:
            return value > 0
        return False

    @property
    def rule_count(self) -> int:
        return len(self._rules)


def create_etp_alert_rules() -> list[AlertRule]:
    """Pre-defined ETP alert rules.

    Note: Rate-based alerts (e.g., '>10% of requests') are simplified
    to count-based thresholds here. Production Prometheus Alertmanager
    would use PromQL rate() expressions for proper rate calculation.
    Histogram percentile alerts (p99) are similarly simplified to
    observation count — production uses histogram_quantile().
    """
    return [
        AlertRule(
            name="sth_publish_gap",
            metric_name="etp_sth_publish_gap_seconds",
            condition=AlertCondition.GREATER_THAN,
            threshold=60.0,
            severity=AlertSeverity.CRITICAL,
            description="STH publishing gap > 60s",
        ),
        AlertRule(
            name="audit_failure_rate",
            metric_name="etp_audit_failure_rate",
            condition=AlertCondition.GREATER_THAN,
            threshold=0.05,
            severity=AlertSeverity.CRITICAL,
            description="Node audit failure rate > 5%",
        ),
        AlertRule(
            name="nonce_violation",
            metric_name="etp_nonce_violation_total",
            condition=AlertCondition.ANY_OCCURRENCE,
            threshold=0.0,
            severity=AlertSeverity.CRITICAL,
            description="Nonce monotonicity violation (replay attack)",
        ),
        AlertRule(
            name="materialize_failure_spike",
            metric_name="etp_materialize_failure_total",
            condition=AlertCondition.GREATER_THAN,
            threshold=10.0,
            severity=AlertSeverity.WARNING,
            description="Materialize failure count > 10 (simplified from >10% rate)",
        ),
        AlertRule(
            name="rest_5xx_rate",
            metric_name="etp_rest_5xx_total",
            condition=AlertCondition.GREATER_THAN,
            threshold=5.0,
            severity=AlertSeverity.CRITICAL,
            description="REST API 5xx count > 5 (simplified from >1% rate over 5 min)",
        ),
        AlertRule(
            name="rest_latency_p99",
            metric_name="etp_rest_latency_seconds",
            condition=AlertCondition.GREATER_THAN,
            threshold=100.0,
            severity=AlertSeverity.WARNING,
            description="REST API observations > 100 (simplified from p99 > 200ms)",
            for_seconds=300.0,
        ),
        AlertRule(
            name="shard_fetch_latency_p99",
            metric_name="etp_shard_fetch_latency_seconds",
            condition=AlertCondition.GREATER_THAN,
            threshold=100.0,
            severity=AlertSeverity.WARNING,
            description="Shard fetch observations > 100 (simplified from p99 > 500ms)",
            for_seconds=300.0,
        ),
        AlertRule(
            name="key_rotation_failure",
            metric_name="etp_key_rotation_failures_total",
            condition=AlertCondition.ANY_OCCURRENCE,
            threshold=0.0,
            severity=AlertSeverity.CRITICAL,
            description="Key rotation task failure",
        ),
        AlertRule(
            name="bridge_message_age",
            metric_name="etp_bridge_message_age_seconds",
            condition=AlertCondition.GREATER_THAN,
            threshold=3600.0,
            severity=AlertSeverity.WARNING,
            description="Bridge message age > finality threshold",
        ),
        AlertRule(
            name="dst_regression",
            metric_name="etp_dst_regression_total",
            condition=AlertCondition.ANY_OCCURRENCE,
            threshold=0.0,
            severity=AlertSeverity.CRITICAL,
            description="DST nightly regression — state transition failure",
        ),
    ]
