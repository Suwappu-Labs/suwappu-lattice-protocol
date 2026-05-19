"""
Gateway middleware: rate limiting and structured request logging.
"""

from __future__ import annotations

import logging
import threading
import time as _time
from dataclasses import dataclass, field

__all__ = ["RateLimiter"]

logger = logging.getLogger(__name__)


@dataclass
class _TokenBucket:
    """Simple token bucket for per-caller rate limiting."""

    tokens: float
    max_tokens: float
    refill_rate: float  # tokens per second
    last_refill: float = 0.0

    def allow(self) -> bool:
        now = _time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """In-memory token bucket rate limiter.

    Thread-safe. Keyed by caller identity (JWT sub or IP).
    """

    def __init__(self, max_per_minute: int = 60) -> None:
        self._max_per_minute = max_per_minute
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def allow(self, caller_id: str) -> bool:
        """Check if a request from caller_id is allowed."""
        with self._lock:
            bucket = self._buckets.get(caller_id)
            if bucket is None:
                bucket = _TokenBucket(
                    tokens=float(self._max_per_minute),
                    max_tokens=float(self._max_per_minute),
                    refill_rate=self._max_per_minute / 60.0,
                    last_refill=_time.time(),
                )
                self._buckets[caller_id] = bucket
            return bucket.allow()

    @property
    def max_per_minute(self) -> int:
        return self._max_per_minute
