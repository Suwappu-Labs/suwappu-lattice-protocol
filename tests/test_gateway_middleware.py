"""
Tests for gateway middleware: rate limiting.
"""

from __future__ import annotations

import time

import pytest

from src.ltp.gateway.middleware import RateLimiter


class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(max_per_minute=10)
        for _ in range(10):
            assert rl.allow("user1") is True

    def test_rejects_over_limit(self):
        rl = RateLimiter(max_per_minute=3)
        results = [rl.allow("user1") for _ in range(6)]
        assert False in results

    def test_per_caller_isolation(self):
        rl = RateLimiter(max_per_minute=2)
        assert rl.allow("user1") is True
        assert rl.allow("user1") is True
        assert rl.allow("user2") is True  # Different caller, fresh bucket
        assert rl.allow("user2") is True

    def test_tokens_refill_over_time(self):
        rl = RateLimiter(max_per_minute=60)  # 1 per second
        # Exhaust initial burst
        for _ in range(60):
            rl.allow("user1")
        # Should be empty now
        assert rl.allow("user1") is False
        # Wait for refill
        time.sleep(1.1)
        assert rl.allow("user1") is True

    def test_max_per_minute_property(self):
        rl = RateLimiter(max_per_minute=42)
        assert rl.max_per_minute == 42

    def test_thread_safety(self):
        """Multiple threads should not corrupt internal state."""
        import threading

        rl = RateLimiter(max_per_minute=1000)
        results = []

        def worker():
            for _ in range(100):
                results.append(rl.allow(f"thread-{threading.current_thread().name}"))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 400
        # Most should be True (1000 tokens per caller, 100 requests each)
        assert results.count(True) > 350
