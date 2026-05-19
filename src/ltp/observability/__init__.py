"""
Observability infrastructure for ETP.

Provides Prometheus-compatible metrics collection, structured JSON logging,
and alert rule definitions.
"""

from .alerts import AlertCondition, AlertEvaluator, AlertResult, AlertRule, AlertSeverity
from .endpoint import ETPObservability, MetricsRequestHandler
from .logging import CorrelationContext, JSONFormatter, StructuredLogger
from .metrics import Counter, Gauge, Histogram, MetricsRegistry, MetricType
from .tls import (
    CertificateManager,
    ETPSecurityConfig,
    InMemoryCertManager,
    NetworkPolicy,
    NetworkPolicyRegistry,
    TLSConfig,
)

__all__ = [
    "MetricsRegistry",
    "Counter",
    "Gauge",
    "Histogram",
    "MetricType",
    "StructuredLogger",
    "CorrelationContext",
    "JSONFormatter",
    "MetricsRequestHandler",
    "ETPObservability",
    "AlertSeverity",
    "AlertCondition",
    "AlertRule",
    "AlertResult",
    "AlertEvaluator",
    "TLSConfig",
    "CertificateManager",
    "InMemoryCertManager",
    "NetworkPolicy",
    "NetworkPolicyRegistry",
    "ETPSecurityConfig",
]
