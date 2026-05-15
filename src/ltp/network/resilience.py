"""
gRPC connection resilience: circuit breaker and exponential backoff.

PeerCircuitBreaker extends the AnchorClient's CircuitBreaker pattern
with half-open test via Ping RPC. ExponentialBackoff provides configurable
delay with jitter. RetryPolicy combines both for peer connections.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time as _time

_secure_random = secrets.SystemRandom()
from dataclasses import dataclass
from typing import Optional

__all__ = ["PeerCircuitBreaker", "ExponentialBackoff", "RetryPolicy"]

logger = logging.getLogger(__name__)


class PeerCircuitBreaker:
    """Circuit breaker for peer gRPC connections.

    States:
      CLOSED  — normal operation, requests pass through
      OPEN    — after N consecutive failures, all requests rejected
      HALF_OPEN — after cooldown, one test request allowed to check recovery

    Extends the AnchorClient CircuitBreaker with:
    - Half-open test mechanism (allows one probe after cooldown)
    - Per-peer identity tracking
    """

    def __init__(
        self,
        peer_id: str = "",
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self._peer_id = peer_id
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._consecutive_failures = 0
        self._last_failure_at: float = 0.0
        self._lock = threading.Lock()
        self._half_open_attempted = False

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def is_open(self) -> bool:
        """True if breaker is tripped and cooldown has not expired."""
        with self._lock:
            if self._consecutive_failures < self._failure_threshold:
                return False
            elapsed = _time.time() - self._last_failure_at
            if elapsed >= self._cooldown_seconds:
                return False  # Cooldown expired → half-open
            return True

    @property
    def is_half_open(self) -> bool:
        """True if breaker tripped but cooldown expired (allow one test)."""
        with self._lock:
            if self._consecutive_failures < self._failure_threshold:
                return False
            elapsed = _time.time() - self._last_failure_at
            return elapsed >= self._cooldown_seconds

    @property
    def state(self) -> str:
        """Current state: 'closed', 'open', or 'half_open'."""
        with self._lock:
            if self._consecutive_failures < self._failure_threshold:
                return "closed"
            elapsed = _time.time() - self._last_failure_at
            if elapsed >= self._cooldown_seconds:
                return "half_open"
            return "open"

    def allow_request(self) -> bool:
        """Check if a request should be allowed.

        In CLOSED state: always allows.
        In OPEN state: rejects.
        In HALF_OPEN state: allows one test request, then blocks until result.
        """
        with self._lock:
            if self._consecutive_failures < self._failure_threshold:
                return True  # CLOSED
            elapsed = _time.time() - self._last_failure_at
            if elapsed < self._cooldown_seconds:
                return False  # OPEN
            # HALF_OPEN: allow one test
            if not self._half_open_attempted:
                self._half_open_attempted = True
                return True
            return False

    def record_success(self) -> None:
        """Record a successful request. Resets breaker to CLOSED."""
        with self._lock:
            self._consecutive_failures = 0
            self._half_open_attempted = False

    def record_failure(self) -> None:
        """Record a failed request. May trip breaker to OPEN."""
        with self._lock:
            self._consecutive_failures += 1
            self._last_failure_at = _time.time()
            self._half_open_attempted = False
            if self._consecutive_failures >= self._failure_threshold:
                logger.warning(
                    "PeerCircuitBreaker: tripped for %s (%d failures, cooldown=%.0fs)",
                    self._peer_id, self._consecutive_failures, self._cooldown_seconds,
                )

    @property
    def failure_count(self) -> int:
        return self._consecutive_failures


@dataclass
class ExponentialBackoff:
    """Exponential backoff with jitter for retry delays.

    delay = min(max_delay, base_delay * 2^attempt) + random_jitter
    """
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = 0.5  # Max jitter in seconds

    def delay_for(self, attempt: int) -> float:
        """Calculate delay for the given attempt number (0-indexed)."""
        delay = min(self.max_delay, self.base_delay * (2 ** attempt))
        if self.jitter > 0:
            delay += _secure_random.uniform(0, self.jitter)
        return delay

    def wait(self, attempt: int) -> None:
        """Sleep for the calculated delay."""
        _time.sleep(self.delay_for(attempt))


class RetryPolicy:
    """Combines circuit breaker and exponential backoff for peer connections.

    Usage:
        policy = RetryPolicy(peer_id="node-2", max_attempts=3)
        for attempt in range(policy.max_attempts):
            if not policy.should_attempt():
                break
            try:
                result = connect_to_peer()
                policy.record_success()
                break
            except Exception:
                policy.record_failure(attempt)
    """

    def __init__(
        self,
        peer_id: str = "",
        max_attempts: int = 3,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        backoff: Optional[ExponentialBackoff] = None,
    ) -> None:
        self.max_attempts = max_attempts
        self.breaker = PeerCircuitBreaker(
            peer_id=peer_id,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self.backoff = backoff or ExponentialBackoff()

    def should_attempt(self) -> bool:
        """Check if a connection attempt should proceed."""
        return self.breaker.allow_request()

    def record_success(self) -> None:
        """Record successful connection."""
        self.breaker.record_success()

    def record_failure(self, attempt: int = 0, sleep: bool = True) -> None:
        """Record failed connection and wait with backoff.

        Args:
            attempt: Zero-indexed attempt number.
            sleep: If True, sleep for the backoff delay. Set False in tests.
        """
        self.breaker.record_failure()
        if attempt < self.max_attempts - 1:
            delay = self.backoff.delay_for(attempt)
            logger.info(
                "RetryPolicy: attempt %d failed for %s, backoff %.1fs",
                attempt + 1, self.breaker.peer_id, delay,
            )
            if sleep:
                _time.sleep(delay)
