"""Tests for ExecutionMonitor — rolling failure window and halt logic (Spec D1c §5)."""

import pytest

from src.ltp.execution.execution_monitor import ExecutionMonitor
from src.ltp.execution.execution_config import ExecutionConfig
from src.ltp.execution.execution_events import ExecutionEventType
from src.ltp.execution.types import BatchResult, TxResult


def _success_result(round_num: int = 0, n_tx: int = 3) -> BatchResult:
    return BatchResult(
        round=round_num,
        tx_results=[TxResult.accepted(gas_used=100) for _ in range(n_tx)],
        state_root=object(),
    )


def _mixed_result(round_num: int = 0, successes: int = 2, failures: int = 1) -> BatchResult:
    results = (
        [TxResult.accepted(gas_used=100) for _ in range(successes)]
        + [TxResult.rejected("fail") for _ in range(failures)]
    )
    return BatchResult(round=round_num, tx_results=results, state_root=object())


def _all_fail_result(round_num: int = 0, n_tx: int = 3) -> BatchResult:
    return BatchResult(
        round=round_num,
        tx_results=[TxResult.rejected("fail") for _ in range(n_tx)],
        state_root=object(),
    )


class TestMonitorBasic:

    def test_record_success_no_events(self):
        monitor = ExecutionMonitor(ExecutionConfig())
        events = monitor.record(_success_result(), catastrophic=False)
        assert len(events) == 0

    def test_total_counters_increment(self):
        monitor = ExecutionMonitor(ExecutionConfig())
        monitor.record(_success_result(n_tx=3), catastrophic=False)
        assert monitor.total_batches == 1
        assert monitor.total_tx_success == 3
        assert monitor.total_tx_failure == 0

    def test_mixed_results_tracked(self):
        monitor = ExecutionMonitor(ExecutionConfig())
        monitor.record(_mixed_result(successes=2, failures=1), catastrophic=False)
        assert monitor.total_tx_success == 2
        assert monitor.total_tx_failure == 1

    def test_empty_batch_rate_stays_zero(self):
        monitor = ExecutionMonitor(ExecutionConfig())
        empty = BatchResult(round=0, tx_results=[], state_root=None)
        monitor.record(empty, catastrophic=False)
        assert monitor.failure_rate() == 0.0
        assert monitor.total_batches == 1


class TestMonitorFailureRate:

    def test_failure_rate_calculation(self):
        monitor = ExecutionMonitor(ExecutionConfig(failure_window=10))
        monitor.record(_mixed_result(successes=7, failures=3), catastrophic=False)
        assert abs(monitor.failure_rate() - 0.3) < 0.01

    def test_rolling_window_evicts_old_entries(self):
        cfg = ExecutionConfig(failure_window=3)
        monitor = ExecutionMonitor(cfg)
        for i in range(3):
            monitor.record(_all_fail_result(round_num=i, n_tx=1), catastrophic=False)
        assert monitor.failure_rate() == 1.0
        monitor.record(_success_result(round_num=3, n_tx=1), catastrophic=False)
        assert abs(monitor.failure_rate() - 2.0 / 3.0) < 0.01

    def test_window_size_respected(self):
        cfg = ExecutionConfig(failure_window=2)
        monitor = ExecutionMonitor(cfg)
        monitor.record(_all_fail_result(n_tx=1), catastrophic=False)
        monitor.record(_all_fail_result(n_tx=1), catastrophic=False)
        monitor.record(_success_result(n_tx=1), catastrophic=False)
        assert abs(monitor.failure_rate() - 0.5) < 0.01


class TestMonitorThresholdWarning:

    def test_warning_emitted_when_exceeded(self):
        cfg = ExecutionConfig(failure_threshold_pct=30.0, failure_window=10)
        monitor = ExecutionMonitor(cfg)
        monitor.record(_mixed_result(successes=5, failures=5), catastrophic=False)
        events = monitor.record(_mixed_result(successes=5, failures=5), catastrophic=False)
        warnings = [e for e in events if e.event_type == ExecutionEventType.FAILURE_THRESHOLD_WARNING]
        assert len(warnings) >= 1

    def test_no_warning_below_threshold(self):
        cfg = ExecutionConfig(failure_threshold_pct=50.0, failure_window=10)
        monitor = ExecutionMonitor(cfg)
        events = monitor.record(_mixed_result(successes=8, failures=2), catastrophic=False)
        warnings = [e for e in events if e.event_type == ExecutionEventType.FAILURE_THRESHOLD_WARNING]
        assert len(warnings) == 0

    def test_multiple_warnings_on_consecutive_breaches(self):
        cfg = ExecutionConfig(failure_threshold_pct=10.0, failure_window=10)
        monitor = ExecutionMonitor(cfg)
        all_warnings = []
        for i in range(3):
            events = monitor.record(_all_fail_result(round_num=i, n_tx=5), catastrophic=False)
            all_warnings.extend(
                e for e in events if e.event_type == ExecutionEventType.FAILURE_THRESHOLD_WARNING
            )
        assert len(all_warnings) == 3


class TestMonitorHalt:

    def test_catastrophic_with_halt_config(self):
        cfg = ExecutionConfig(halt_on_catastrophic=True)
        monitor = ExecutionMonitor(cfg)
        empty = BatchResult(round=0, tx_results=[], state_root=None)
        events = monitor.record(empty, catastrophic=True)
        assert monitor.should_halt() is True
        halts = [e for e in events if e.event_type == ExecutionEventType.EXECUTION_HALTED]
        assert len(halts) == 1

    def test_catastrophic_without_halt_config(self):
        cfg = ExecutionConfig(halt_on_catastrophic=False)
        monitor = ExecutionMonitor(cfg)
        empty = BatchResult(round=0, tx_results=[], state_root=None)
        events = monitor.record(empty, catastrophic=True)
        assert monitor.should_halt() is False
        halts = [e for e in events if e.event_type == ExecutionEventType.EXECUTION_HALTED]
        assert len(halts) == 0


class TestMonitorReset:

    def test_reset_clears_counters(self):
        monitor = ExecutionMonitor(ExecutionConfig())
        monitor.record(_success_result(n_tx=5), catastrophic=False)
        assert monitor.total_batches == 1
        events = monitor.reset(old_epoch=1, new_epoch=2)
        assert monitor.total_batches == 0
        assert monitor.total_tx_success == 0
        assert monitor.total_tx_failure == 0
        assert monitor.failure_rate() == 0.0

    def test_reset_emits_epoch_metrics_reset(self):
        monitor = ExecutionMonitor(ExecutionConfig())
        monitor.record(_success_result(n_tx=3), catastrophic=False)
        events = monitor.reset(old_epoch=1, new_epoch=2)
        assert len(events) == 1
        assert events[0].event_type == ExecutionEventType.EPOCH_METRICS_RESET
        assert events[0].payload["old_epoch"] == 1
        assert events[0].payload["new_epoch"] == 2
        assert events[0].payload["total_batches_prev"] == 1
