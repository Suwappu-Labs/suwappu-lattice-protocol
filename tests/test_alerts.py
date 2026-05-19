"""
Alert rule definitions + evaluator tests.

Tests alert rule data structures, AlertEvaluator against MetricsRegistry,
and pre-defined ETP alert rules.
"""

from __future__ import annotations

import pytest

from src.ltp.observability.alerts import (
    AlertCondition,
    AlertEvaluator,
    AlertResult,
    AlertRule,
    AlertSeverity,
    create_etp_alert_rules,
)
from src.ltp.observability.metrics import MetricsRegistry, create_etp_metrics

# ---------------------------------------------------------------------------
# AlertRule
# ---------------------------------------------------------------------------


class TestAlertRule:
    def test_rule_is_frozen(self):
        rule = AlertRule(
            name="test",
            metric_name="m",
            condition=AlertCondition.GREATER_THAN,
            threshold=10.0,
            severity=AlertSeverity.CRITICAL,
            description="Test",
        )
        with pytest.raises(AttributeError):
            rule.name = "changed"

    def test_rule_fields(self):
        rule = AlertRule(
            name="sth_gap",
            metric_name="etp_sth_gap",
            condition=AlertCondition.GREATER_THAN,
            threshold=60.0,
            severity=AlertSeverity.CRITICAL,
            description="STH gap",
            for_seconds=30.0,
        )
        assert rule.name == "sth_gap"
        assert rule.threshold == 60.0
        assert rule.for_seconds == 30.0


# ---------------------------------------------------------------------------
# AlertEvaluator
# ---------------------------------------------------------------------------


class TestAlertEvaluator:
    def test_counter_above_threshold_fires(self):
        reg = MetricsRegistry()
        c = reg.counter("errors_total", "Error count")
        c.inc(10)

        rule = AlertRule(
            name="high_errors",
            metric_name="errors_total",
            condition=AlertCondition.GREATER_THAN,
            threshold=5.0,
            severity=AlertSeverity.CRITICAL,
            description="Too many errors",
        )
        evaluator = AlertEvaluator([rule], reg)
        results = evaluator.evaluate_all()
        assert len(results) == 1
        assert results[0].firing is True
        assert results[0].metric_value == 10.0

    def test_counter_below_threshold_ok(self):
        reg = MetricsRegistry()
        c = reg.counter("errors_total")
        c.inc(2)

        rule = AlertRule(
            name="high_errors",
            metric_name="errors_total",
            condition=AlertCondition.GREATER_THAN,
            threshold=5.0,
            severity=AlertSeverity.WARNING,
            description="Too many errors",
        )
        evaluator = AlertEvaluator([rule], reg)
        results = evaluator.evaluate_all()
        assert results[0].firing is False

    def test_gauge_threshold(self):
        reg = MetricsRegistry()
        g = reg.gauge("temperature")
        g.set(75.0)

        rule = AlertRule(
            name="hot",
            metric_name="temperature",
            condition=AlertCondition.GREATER_THAN,
            threshold=70.0,
            severity=AlertSeverity.WARNING,
            description="Temperature high",
        )
        evaluator = AlertEvaluator([rule], reg)
        assert evaluator.firing_alerts()[0].firing is True

    def test_any_occurrence(self):
        reg = MetricsRegistry()
        c = reg.counter("violations_total")
        c.inc(1)

        rule = AlertRule(
            name="violation",
            metric_name="violations_total",
            condition=AlertCondition.ANY_OCCURRENCE,
            threshold=0.0,
            severity=AlertSeverity.CRITICAL,
            description="Any violation",
        )
        evaluator = AlertEvaluator([rule], reg)
        assert evaluator.firing_alerts()[0].firing is True

    def test_any_occurrence_zero_not_firing(self):
        reg = MetricsRegistry()
        reg.counter("violations_total")  # Never incremented

        rule = AlertRule(
            name="violation",
            metric_name="violations_total",
            condition=AlertCondition.ANY_OCCURRENCE,
            threshold=0.0,
            severity=AlertSeverity.CRITICAL,
            description="Any violation",
        )
        evaluator = AlertEvaluator([rule], reg)
        assert len(evaluator.firing_alerts()) == 0

    def test_missing_metric_not_firing(self):
        reg = MetricsRegistry()
        rule = AlertRule(
            name="missing",
            metric_name="nonexistent_metric",
            condition=AlertCondition.GREATER_THAN,
            threshold=0.0,
            severity=AlertSeverity.WARNING,
            description="Missing metric",
        )
        evaluator = AlertEvaluator([rule], reg)
        results = evaluator.evaluate_all()
        assert results[0].firing is False

    def test_multiple_rules(self):
        reg = MetricsRegistry()
        reg.counter("a").inc(10)
        reg.counter("b").inc(1)

        rules = [
            AlertRule(
                "high_a", "a", AlertCondition.GREATER_THAN, 5.0, AlertSeverity.CRITICAL, "A high"
            ),
            AlertRule(
                "high_b", "b", AlertCondition.GREATER_THAN, 5.0, AlertSeverity.WARNING, "B high"
            ),
        ]
        evaluator = AlertEvaluator(rules, reg)
        firing = evaluator.firing_alerts()
        assert len(firing) == 1
        assert firing[0].rule_name == "high_a"

    def test_rule_count(self):
        evaluator = AlertEvaluator(
            [
                AlertRule("r1", "m1", AlertCondition.GREATER_THAN, 0, AlertSeverity.WARNING, ""),
                AlertRule("r2", "m2", AlertCondition.GREATER_THAN, 0, AlertSeverity.CRITICAL, ""),
            ],
            MetricsRegistry(),
        )
        assert evaluator.rule_count == 2


# ---------------------------------------------------------------------------
# Pre-defined ETP Alert Rules
# ---------------------------------------------------------------------------


class TestETPAlertRules:
    def test_create_returns_10_rules(self):
        rules = create_etp_alert_rules()
        assert len(rules) == 10

    def test_rules_have_required_fields(self):
        for rule in create_etp_alert_rules():
            assert rule.name != ""
            assert rule.metric_name != ""
            assert rule.description != ""
            assert isinstance(rule.severity, AlertSeverity)
            assert isinstance(rule.condition, AlertCondition)

    def test_rules_evaluate_against_etp_metrics(self):
        """ETP alert rules can evaluate against ETP metrics registry."""
        reg = MetricsRegistry()
        create_etp_metrics(reg)  # Register all 8 ETP metrics
        rules = create_etp_alert_rules()

        evaluator = AlertEvaluator(rules, reg)
        results = evaluator.evaluate_all()
        assert len(results) == 10
        # With default (zero) values, no alerts should fire
        firing = [r for r in results if r.firing]
        assert len(firing) == 0


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_all_alert_metrics_registered(self):
        """Every alert rule references a metric that exists in the ETP registry."""
        reg = MetricsRegistry()
        create_etp_metrics(reg)
        rules = create_etp_alert_rules()
        for rule in rules:
            metric = reg.get(rule.metric_name)
            assert metric is not None, (
                f"Alert rule {rule.name!r} references unregistered metric {rule.metric_name!r}"
            )

    def test_no_zero_threshold_greater_than_rules(self):
        """No GREATER_THAN rule should have threshold=0 (fires on any value)."""
        rules = create_etp_alert_rules()
        for rule in rules:
            if rule.condition == AlertCondition.GREATER_THAN:
                assert rule.threshold > 0, (
                    f"Rule {rule.name!r} has GREATER_THAN with threshold=0 "
                    f"(fires on any value — should use ANY_OCCURRENCE or raise threshold)"
                )

    def test_single_observation_does_not_trigger_latency_alerts(self):
        """A single fast observation should NOT trigger latency alerts."""
        reg = MetricsRegistry()
        create_etp_metrics(reg)
        # One 1ms observation
        reg.get("etp_rest_latency_seconds").observe(0.001)

        rules = create_etp_alert_rules()
        evaluator = AlertEvaluator(rules, reg)
        firing = evaluator.firing_alerts()
        latency_alerts = [a for a in firing if "latency" in a.rule_name]
        assert len(latency_alerts) == 0, (
            f"Single fast observation should not fire: {[a.rule_name for a in latency_alerts]}"
        )
