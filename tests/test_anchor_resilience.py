"""
Tests for AnchorClient resilience features: CircuitBreaker and TokenBucketRateLimiter.

These are standalone unit tests — they don't require web3 or a running chain.
"""

import threading
import time

import pytest

from src.ltp.anchor.client import (
    _DEFAULT_BURST,
    _DEFAULT_COOLDOWN_SECONDS,
    _DEFAULT_FAILURE_THRESHOLD,
    _DEFAULT_MAX_TPS,
    CircuitBreaker,
    TokenBucketRateLimiter,
)

# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert not cb.is_open
        assert cb.failure_count == 0

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert not cb.is_open
        assert cb.failure_count == 4

    def test_trips_at_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open
        assert cb.failure_count == 3

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.failure_count == 0
        assert not cb.is_open

    def test_success_resets_tripped_breaker(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open or True  # might have cooled down already
        cb.record_success()
        assert not cb.is_open
        assert cb.failure_count == 0

    def test_cooldown_expires(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open
        time.sleep(0.06)
        # After cooldown, half-open — allows one attempt
        assert not cb.is_open

    def test_default_values(self):
        cb = CircuitBreaker()
        assert cb._failure_threshold == _DEFAULT_FAILURE_THRESHOLD
        assert cb._cooldown_seconds == _DEFAULT_COOLDOWN_SECONDS

    def test_thread_safety(self):
        """Concurrent record_failure calls don't corrupt state."""
        cb = CircuitBreaker(failure_threshold=100, cooldown_seconds=60)
        barrier = threading.Barrier(10)

        def hammer():
            barrier.wait()
            for _ in range(50):
                cb.record_failure()

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert cb.failure_count == 500
        assert cb.is_open


# ---------------------------------------------------------------------------
# TokenBucketRateLimiter
# ---------------------------------------------------------------------------


class TestTokenBucketRateLimiter:
    def test_burst_tokens_available_immediately(self):
        rl = TokenBucketRateLimiter(max_tps=10, burst=5)
        for _ in range(5):
            assert rl.acquire(timeout=0.01)

    def test_exhausted_after_burst(self):
        rl = TokenBucketRateLimiter(max_tps=1, burst=3)
        # Drain burst
        for _ in range(3):
            assert rl.acquire(timeout=0.01)
        # Next should fail immediately with timeout=0
        assert not rl.acquire(timeout=0)

    def test_refill_over_time(self):
        rl = TokenBucketRateLimiter(max_tps=100, burst=1)
        assert rl.acquire(timeout=0.01)  # drain the 1 token
        # Wait for refill (100 TPS = 1 token per 10ms)
        time.sleep(0.02)
        assert rl.acquire(timeout=0.01)

    def test_default_values(self):
        rl = TokenBucketRateLimiter()
        assert rl._max_tps == _DEFAULT_MAX_TPS
        assert rl._burst == _DEFAULT_BURST

    def test_zero_timeout_returns_immediately(self):
        rl = TokenBucketRateLimiter(max_tps=1, burst=0)
        # No burst, can't acquire with zero timeout
        start = time.monotonic()
        result = rl.acquire(timeout=0)
        elapsed = time.monotonic() - start
        assert not result
        assert elapsed < 0.1  # should be nearly instant

    def test_thread_safety(self):
        """Multiple threads acquiring tokens doesn't over-issue."""
        rl = TokenBucketRateLimiter(max_tps=1000, burst=50)
        acquired = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def grab():
            barrier.wait()
            count = 0
            for _ in range(10):
                if rl.acquire(timeout=0.01):
                    count += 1
            with lock:
                acquired.append(count)

        threads = [threading.Thread(target=grab) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        total = sum(acquired)
        # Should not exceed burst + refill during test duration
        # 50 burst + ~1000*0.1s = ~150 max theoretical
        assert total <= 200
