"""
Structured JSON logging for ETP.

Provides JSON-formatted log output with correlation ID tracking
for distributed tracing. No external dependencies.

Production: forward JSON logs to Loki, Splunk, or CloudWatch.
Development: human-readable JSON lines to stdout.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Optional

__all__ = [
    "StructuredLogger",
    "CorrelationContext",
    "JSONFormatter",
]


class CorrelationContext:
    """Thread-local correlation ID tracking for distributed tracing.

    Each request/operation gets a unique correlation ID that is
    automatically included in all log lines within that context.
    """

    _local = threading.local()

    @classmethod
    def set(cls, correlation_id: str) -> None:
        """Set the correlation ID for the current thread."""
        cls._local.correlation_id = correlation_id

    @classmethod
    def get(cls) -> Optional[str]:
        """Get the current correlation ID, or None if not set."""
        return getattr(cls._local, "correlation_id", None)

    @classmethod
    def clear(cls) -> None:
        """Clear the correlation ID for the current thread."""
        cls._local.correlation_id = None

    @classmethod
    def generate(cls) -> str:
        """Generate and set a new UUID correlation ID. Returns the ID."""
        cid = str(uuid.uuid4())
        cls.set(cid)
        return cid


class JSONFormatter(logging.Formatter):
    """Logging formatter that outputs one JSON object per log line.

    Fields: timestamp, level, logger, message, correlation_id, + extras.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if present
        cid = CorrelationContext.get()
        if cid is not None:
            entry["correlation_id"] = cid

        # Add extra fields (set via StructuredLogger)
        if hasattr(record, "_extra_fields"):
            entry.update(record._extra_fields)

        return json.dumps(entry, default=str)


class StructuredLogger:
    """JSON-structured logger with correlation ID tracking.

    Wraps Python's standard logging with JSON output and automatic
    correlation ID injection.

    Usage:
        log = StructuredLogger("etp.protocol")
        log.info("Entity committed", entity_id="abc123", shard_count=8)

        with log.correlation_scope("req-001"):
            log.info("Processing request")  # includes correlation_id
    """

    def __init__(
        self,
        name: str,
        default_fields: Optional[dict] = None,
        level: int = logging.DEBUG,
    ) -> None:
        self._logger = logging.getLogger(name)
        self._default_fields = default_fields or {}
        self._handler: Optional[logging.Handler] = None

    def attach_handler(self, handler: logging.Handler) -> None:
        """Attach a handler with JSONFormatter."""
        handler.setFormatter(JSONFormatter())
        self._logger.addHandler(handler)
        self._handler = handler

    def info(self, msg: str, **extra) -> None:
        self._log(logging.INFO, msg, extra)

    def warning(self, msg: str, **extra) -> None:
        self._log(logging.WARNING, msg, extra)

    def error(self, msg: str, **extra) -> None:
        self._log(logging.ERROR, msg, extra)

    def debug(self, msg: str, **extra) -> None:
        self._log(logging.DEBUG, msg, extra)

    @contextmanager
    def correlation_scope(self, correlation_id: Optional[str] = None):
        """Context manager that sets a correlation ID for the scope.

        If no ID is provided, generates a new UUID.
        Restores the previous ID on exit.
        """
        previous = CorrelationContext.get()
        cid = correlation_id or str(uuid.uuid4())
        CorrelationContext.set(cid)
        try:
            yield cid
        finally:
            if previous is not None:
                CorrelationContext.set(previous)
            else:
                CorrelationContext.clear()

    def _log(self, level: int, msg: str, extra: dict) -> None:
        """Emit a structured log record."""
        merged = {**self._default_fields, **extra}
        record = self._logger.makeRecord(
            self._logger.name,
            level,
            "(structured)",
            0,
            msg,
            (),
            None,
        )
        record._extra_fields = merged
        self._logger.handle(record)

    @property
    def name(self) -> str:
        return self._logger.name
