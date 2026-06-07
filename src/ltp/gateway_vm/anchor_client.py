"""DevnetAnchorClient — gateway-specific submission to LTPAnchorRegistry.

Converts GatewayAttestation → AnchorSubmission and submits via an
injectable submit_fn. In production the submit_fn wraps AnchorClient.anchor();
in tests it can be a mock.

Includes a token-bucket rate limiter and circuit breaker to protect dest-chain
RPC from overload and stop hammering broken endpoints.

The from_gateway_config() factory creates the real AnchorClient connection
when RPC is available.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Callable, Optional

from ..anchor.submission import AnchorSubmission
from .config import GatewayVMConfig
from .writer import GatewayAttestation

# Receipt type string registered for gateway attestations.
_RECEIPT_TYPE = "GATEWAY_ATTEST"


class CircuitOpenError(Exception):
    """Raised when the circuit breaker is open and calls are rejected."""


class RateLimitedError(Exception):
    """Raised when the rate limiter rejects a call."""


class CircuitBreaker:
    """Three-state circuit breaker: CLOSED → OPEN → HALF_OPEN → CLOSED.

    Opens after `failure_threshold` consecutive failures.
    Transitions to half-open after `cooldown_seconds`.
    Closes on first success in half-open state.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._state = self.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == self.OPEN:
                if self._clock() - self._opened_at >= self._cooldown:
                    self._state = self.HALF_OPEN
            return self._state

    def before_call(self) -> None:
        """Check if the call is allowed. Raises CircuitOpenError if not."""
        state = self.state
        if state == self.OPEN:
            raise CircuitOpenError(f"circuit open, cooldown {self._cooldown}s")

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._state = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold:
                self._state = self.OPEN
                self._opened_at = self._clock()


class TokenBucketRateLimiter:
    """Token-bucket rate limiter. Stdlib-only, thread-safe.

    Allows up to `rate` calls per second with a burst capacity of `burst`.
    """

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 20,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._rate = rate
        self._burst = burst
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._tokens = float(burst)
        self._last_refill = self._clock()

    def acquire(self) -> bool:
        """Try to consume one token. Returns True if allowed."""
        with self._lock:
            now = self._clock()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class DevnetAnchorClient:
    """Submits gateway attestations to the SUWAPPU devnet LTPAnchorRegistry.

    Uses composition over inheritance — inject submit_fn for testability,
    use from_gateway_config() for real RPC connections.

    Wraps submissions with a circuit breaker (stops hammering broken RPC)
    and token-bucket rate limiter (prevents dest-chain overload).
    """

    def __init__(
        self,
        submit_fn: Callable[[AnchorSubmission], str],
        circuit_breaker: Optional[CircuitBreaker] = None,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        initial_sequence: int = 0,
    ) -> None:
        self._submit_fn = submit_fn
        self._circuit_breaker = circuit_breaker
        self._rate_limiter = rate_limiter
        self._sequence_lock = threading.Lock()
        self._next_sequence = initial_sequence + 1

    @classmethod
    def from_gateway_config(
        cls,
        config: GatewayVMConfig,
        operator_private_key: str,
        signer_vk_hash: bytes = b"",
    ) -> DevnetAnchorClient:
        """Create from gateway config with a real AnchorClient backend."""
        if not config.dest_rpc_url:
            raise ValueError("dest_rpc_url is required for DevnetAnchorClient")
        if not config.dest_registry_address:
            raise ValueError("dest_registry_address is required for DevnetAnchorClient")

        from ..anchor.client import AnchorClient

        client = AnchorClient(
            rpc_url=config.dest_rpc_url,
            contract_address=config.dest_registry_address,
            private_key=operator_private_key,
            chain_id=config.dest_chain_id,
        )

        # Query on-chain sequence to resume monotonically
        initial_sequence = 0
        if signer_vk_hash:
            try:
                initial_sequence = client.signer_sequence(signer_vk_hash)
            except Exception:
                pass

        return cls(
            submit_fn=client.anchor,
            circuit_breaker=CircuitBreaker(),
            rate_limiter=TokenBucketRateLimiter(),
            initial_sequence=initial_sequence,
        )

    def _next_seq(self) -> int:
        """Atomically get and increment the sequence counter."""
        with self._sequence_lock:
            seq = self._next_sequence
            self._next_sequence += 1
            return seq

    def submit_attestation(self, attestation: GatewayAttestation) -> str:
        """Convert attestation to AnchorSubmission and submit. Returns tx hash."""
        if self._circuit_breaker is not None:
            self._circuit_breaker.before_call()

        if self._rate_limiter is not None and not self._rate_limiter.acquire():
            raise RateLimitedError("anchor submission rate limit exceeded")

        seq = self._next_seq()
        submission = _attestation_to_submission(attestation, seq)
        try:
            result = self._submit_fn(submission)
        except Exception:
            if self._circuit_breaker is not None:
                self._circuit_breaker.record_failure()
            raise

        if self._circuit_breaker is not None:
            self._circuit_breaker.record_success()
        return result

    def as_anchor_fn(self) -> Callable[[GatewayAttestation], str]:
        """Return a callable compatible with GatewayVMService.anchor_fn."""
        return self.submit_attestation


def _attestation_to_submission(attestation: GatewayAttestation, sequence: int) -> AnchorSubmission:
    """Map gateway attestation fields to AnchorSubmission fields."""
    digest = attestation.digest
    # Ensure exactly 32 bytes — truncate or pad
    anchor_digest = digest[:32] if len(digest) >= 32 else digest.ljust(32, b"\x00")

    # Use event_id hash as entity_id_hash (deterministic 32B identifier)
    entity_id_hash = hashlib.sha3_256(attestation.event_id.encode()).digest()

    # Merkle root: hash of the signed event bytes (single-leaf "tree")
    merkle_root = hashlib.sha3_256(attestation.event_bytes).digest()

    # Policy hash: hash of the receipt type (gateway attestation policy)
    policy_hash = hashlib.sha3_256(_RECEIPT_TYPE.encode()).digest()

    return AnchorSubmission(
        anchor_digest=anchor_digest,
        entity_id_hash=entity_id_hash,
        merkle_root=merkle_root,
        policy_hash=policy_hash,
        signer_vk_hash=attestation.signer_vk_fingerprint,
        sequence=sequence,
        valid_until=int(time.time()) + 86400,
        target_chain_id=attestation.dest_chain_id,
        receipt_type=_RECEIPT_TYPE,
    )
