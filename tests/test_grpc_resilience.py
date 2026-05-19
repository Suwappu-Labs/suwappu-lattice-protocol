"""
Tests for gRPC connection resilience: circuit breaker, backoff, retry policy.
"""

from __future__ import annotations

import time

import pytest

from src.ltp.network.resilience import (
    ExponentialBackoff,
    PeerCircuitBreaker,
    RetryPolicy,
)

# ---------------------------------------------------------------------------
# PeerCircuitBreaker
# ---------------------------------------------------------------------------


class TestPeerCircuitBreaker:
    def test_starts_closed(self):
        cb = PeerCircuitBreaker(peer_id="node-1", failure_threshold=3)
        assert cb.state == "closed"
        assert cb.is_open is False
        assert cb.allow_request() is True

    def test_trips_after_threshold(self):
        cb = PeerCircuitBreaker(peer_id="node-1", failure_threshold=3, cooldown_seconds=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "open"
        assert cb.is_open is True
        assert cb.allow_request() is False

    def test_below_threshold_stays_closed(self):
        cb = PeerCircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "closed"
        assert cb.allow_request() is True

    def test_success_resets(self):
        cb = PeerCircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        # Wait for cooldown, then test half-open
        cb._last_failure_at = time.time() - 61
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"
        assert cb.failure_count == 0

    def test_half_open_after_cooldown(self):
        cb = PeerCircuitBreaker(failure_threshold=2, cooldown_seconds=1)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(1.1)
        assert cb.state == "half_open"
        assert cb.allow_request() is True  # First test request allowed

    def test_half_open_blocks_second_request(self):
        cb = PeerCircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        assert cb.allow_request() is True  # First test
        assert cb.allow_request() is False  # Second blocked

    def test_failure_count(self):
        cb = PeerCircuitBreaker(failure_threshold=10)
        assert cb.failure_count == 0
        cb.record_failure()
        cb.record_failure()
        assert cb.failure_count == 2

    def test_peer_id(self):
        cb = PeerCircuitBreaker(peer_id="node-42")
        assert cb.peer_id == "node-42"

    def test_thread_safety(self):
        import threading

        cb = PeerCircuitBreaker(failure_threshold=100, cooldown_seconds=60)
        errors = []

        def worker():
            try:
                for _ in range(50):
                    cb.record_failure()
                    cb.allow_request()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# ExponentialBackoff
# ---------------------------------------------------------------------------


class TestExponentialBackoff:
    def test_first_attempt_is_base(self):
        eb = ExponentialBackoff(base_delay=1.0, max_delay=60.0, jitter=0.0)
        assert eb.delay_for(0) == 1.0

    def test_exponential_growth(self):
        eb = ExponentialBackoff(base_delay=1.0, max_delay=60.0, jitter=0.0)
        assert eb.delay_for(0) == 1.0
        assert eb.delay_for(1) == 2.0
        assert eb.delay_for(2) == 4.0
        assert eb.delay_for(3) == 8.0

    def test_capped_at_max(self):
        eb = ExponentialBackoff(base_delay=1.0, max_delay=10.0, jitter=0.0)
        assert eb.delay_for(10) == 10.0  # 2^10 = 1024 > 10

    def test_jitter_adds_randomness(self):
        eb = ExponentialBackoff(base_delay=1.0, max_delay=60.0, jitter=1.0)
        delays = {eb.delay_for(0) for _ in range(20)}
        assert len(delays) > 1  # Should not all be identical


# ---------------------------------------------------------------------------
# RetryPolicy
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    def test_allows_when_breaker_closed(self):
        policy = RetryPolicy(peer_id="node-1", max_attempts=3)
        assert policy.should_attempt() is True

    def test_blocks_when_breaker_open(self):
        policy = RetryPolicy(
            peer_id="node-1",
            max_attempts=3,
            failure_threshold=2,
            cooldown_seconds=60,
        )
        policy.record_failure(0)
        policy.record_failure(1)
        assert policy.should_attempt() is False

    def test_success_resets_breaker(self):
        policy = RetryPolicy(failure_threshold=2, cooldown_seconds=0.01)
        policy.record_failure(0)
        policy.record_failure(1)
        time.sleep(0.02)  # Cooldown expires → half-open
        assert policy.should_attempt() is True
        policy.record_success()
        assert policy.should_attempt() is True  # Back to closed
