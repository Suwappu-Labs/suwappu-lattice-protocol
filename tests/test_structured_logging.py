"""
Structured JSON logging tests.

Tests JSONFormatter output, CorrelationContext thread-local tracking,
StructuredLogger with extra fields, and correlation scope management.
"""

from __future__ import annotations

import json
import logging

import pytest

from src.ltp.observability.logging import (
    CorrelationContext,
    JSONFormatter,
    StructuredLogger,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CaptureHandler(logging.Handler):
    """Handler that captures formatted log output for testing."""

    def __init__(self):
        super().__init__()
        self.records: list[str] = []

    def emit(self, record):
        self.records.append(self.format(record))


def _make_logger(name: str = "test") -> tuple[StructuredLogger, _CaptureHandler]:
    slog = StructuredLogger(name)
    handler = _CaptureHandler()
    slog.attach_handler(handler)
    slog._logger.setLevel(logging.DEBUG)
    return slog, handler


# ---------------------------------------------------------------------------
# JSONFormatter
# ---------------------------------------------------------------------------


class TestJSONFormatter:
    def test_output_is_valid_json(self):
        slog, handler = _make_logger("json-test")
        slog.info("Hello world")
        assert len(handler.records) == 1
        parsed = json.loads(handler.records[0])
        assert parsed["message"] == "Hello world"

    def test_standard_fields_present(self):
        slog, handler = _make_logger("fields-test")
        slog.info("Test message")
        parsed = json.loads(handler.records[0])
        assert "timestamp" in parsed
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "fields-test"
        assert parsed["message"] == "Test message"

    def test_timestamp_format(self):
        slog, handler = _make_logger()
        slog.info("ts test")
        parsed = json.loads(handler.records[0])
        # Should be ISO-ish: 2026-04-07T...Z
        assert "T" in parsed["timestamp"]
        assert parsed["timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# CorrelationContext
# ---------------------------------------------------------------------------


class TestCorrelationContext:
    def setup_method(self):
        CorrelationContext.clear()

    def test_set_and_get(self):
        CorrelationContext.set("req-001")
        assert CorrelationContext.get() == "req-001"

    def test_clear(self):
        CorrelationContext.set("req-002")
        CorrelationContext.clear()
        assert CorrelationContext.get() is None

    def test_generate_returns_uuid(self):
        cid = CorrelationContext.generate()
        assert len(cid) == 36  # UUID format: 8-4-4-4-12
        assert CorrelationContext.get() == cid

    def test_default_is_none(self):
        assert CorrelationContext.get() is None


# ---------------------------------------------------------------------------
# StructuredLogger
# ---------------------------------------------------------------------------


class TestStructuredLogger:
    def setup_method(self):
        CorrelationContext.clear()

    def test_extra_fields_in_output(self):
        slog, handler = _make_logger("extra-test")
        slog.info("Entity committed", entity_id="abc123", shard_count=8)
        parsed = json.loads(handler.records[0])
        assert parsed["entity_id"] == "abc123"
        assert parsed["shard_count"] == 8

    def test_correlation_id_in_output(self):
        slog, handler = _make_logger("corr-test")
        CorrelationContext.set("trace-xyz")
        slog.info("Processing")
        parsed = json.loads(handler.records[0])
        assert parsed["correlation_id"] == "trace-xyz"

    def test_no_correlation_id_when_unset(self):
        slog, handler = _make_logger()
        slog.info("No trace")
        parsed = json.loads(handler.records[0])
        assert "correlation_id" not in parsed

    def test_correlation_scope(self):
        slog, handler = _make_logger("scope-test")
        with slog.correlation_scope("req-100"):
            slog.info("Inside scope")
        slog.info("Outside scope")

        inside = json.loads(handler.records[0])
        outside = json.loads(handler.records[1])
        assert inside["correlation_id"] == "req-100"
        assert "correlation_id" not in outside

    def test_correlation_scope_restores_previous(self):
        slog, handler = _make_logger()
        CorrelationContext.set("outer")
        with slog.correlation_scope("inner"):
            assert CorrelationContext.get() == "inner"
        assert CorrelationContext.get() == "outer"

    def test_default_fields(self):
        slog = StructuredLogger("defaults", default_fields={"service": "etp-node"})
        handler = _CaptureHandler()
        slog.attach_handler(handler)
        slog._logger.setLevel(logging.DEBUG)
        slog.info("Test")
        parsed = json.loads(handler.records[0])
        assert parsed["service"] == "etp-node"

    def test_all_log_levels(self):
        slog, handler = _make_logger("levels")
        slog.debug("debug msg")
        slog.info("info msg")
        slog.warning("warn msg")
        slog.error("error msg")
        assert len(handler.records) == 4
        levels = [json.loads(r)["level"] for r in handler.records]
        assert levels == ["DEBUG", "INFO", "WARNING", "ERROR"]
