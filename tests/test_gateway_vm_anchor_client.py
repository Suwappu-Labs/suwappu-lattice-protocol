"""Tests for DevnetAnchorClient — gateway-specific AnchorClient extension."""

from unittest.mock import MagicMock, patch

import pytest

from src.ltp.gateway_vm.anchor_client import (
    CircuitBreaker,
    CircuitOpenError,
    DevnetAnchorClient,
    RateLimitedError,
    TokenBucketRateLimiter,
)
from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def gateway_kp():
    return KeyPair.generate("anchor-client-test")


def _make_attestation(gateway_kp, tx_hash="0xabc123"):
    from src.ltp.gateway_vm.events import BridgeEvent
    from src.ltp.gateway_vm.writer import AttestationWriter

    event = BridgeEvent(
        source_chain_id=84532,
        bridge_contract="0x5083",
        tx_hash=tx_hash,
        block_number=100,
        log_index=0,
        event_name="AnchorCreated",
        sender="0xaa",
        recipient="0xbb",
        payload_hash="sha3-256:ff00",
        amount=100,
        nonce=1,
        timestamp=1700000000.0,
    )
    writer = AttestationWriter(operator_keypair=gateway_kp, dest_chain_id=103115120)
    return writer.create_attestation(event)


class TestDevnetAnchorClientConstruction:
    def test_create_with_injected_submit(self):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient

        mock_submit = MagicMock(return_value="0xtxhash")
        client = DevnetAnchorClient(submit_fn=mock_submit)
        assert client is not None

    def test_from_gateway_config_requires_rpc_url(self):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient
        from src.ltp.gateway_vm.config import GatewayVMConfig

        config = GatewayVMConfig(dest_rpc_url="")
        with pytest.raises(ValueError, match="dest_rpc_url"):
            DevnetAnchorClient.from_gateway_config(
                config=config,
                operator_private_key="0xdeadbeef",
            )

    def test_from_gateway_config_requires_registry_address(self):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient
        from src.ltp.gateway_vm.config import GatewayVMConfig

        config = GatewayVMConfig(
            dest_rpc_url="https://rpc.example.com",
            dest_registry_address="",
        )
        with pytest.raises(ValueError, match="dest_registry_address"):
            DevnetAnchorClient.from_gateway_config(
                config=config,
                operator_private_key="0xdeadbeef",
            )


class TestSubmitAttestation:
    def test_submit_calls_submit_fn(self, gateway_kp):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient

        mock_submit = MagicMock(return_value="0xtxhash123")
        client = DevnetAnchorClient(submit_fn=mock_submit)

        attestation = _make_attestation(gateway_kp)
        tx_hash = client.submit_attestation(attestation)

        assert tx_hash == "0xtxhash123"
        mock_submit.assert_called_once()

    def test_submit_raises_on_failure(self, gateway_kp):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient

        client = DevnetAnchorClient(
            submit_fn=MagicMock(side_effect=RuntimeError("Circuit breaker OPEN"))
        )

        attestation = _make_attestation(gateway_kp)
        with pytest.raises(RuntimeError, match="Circuit breaker"):
            client.submit_attestation(attestation)


class TestAnchorFnAdapter:
    def test_as_anchor_fn_returns_callable(self, gateway_kp):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient

        client = DevnetAnchorClient(submit_fn=MagicMock(return_value="0xtx"))
        fn = client.as_anchor_fn()
        assert callable(fn)

        attestation = _make_attestation(gateway_kp)
        result = fn(attestation)
        assert result == "0xtx"


class TestAttestationToSubmission:
    def test_converts_attestation_fields(self, gateway_kp):
        from src.ltp.gateway_vm.anchor_client import DevnetAnchorClient

        captured = {}

        def capture_submit(submission):
            captured["submission"] = submission
            return "0xtx"

        client = DevnetAnchorClient(submit_fn=capture_submit)
        attestation = _make_attestation(gateway_kp)
        client.submit_attestation(attestation)

        sub = captured["submission"]
        # anchor_digest is the first 32 bytes of attestation digest
        assert len(sub.anchor_digest) == 32
        assert sub.signer_vk_hash == attestation.signer_vk_fingerprint
        assert sub.target_chain_id == attestation.dest_chain_id
        assert sub.receipt_type == "GATEWAY_ATTEST"


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state == CircuitBreaker.CLOSED

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreaker.CLOSED

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        assert cb.state == CircuitBreaker.CLOSED

    def test_before_call_raises_when_open(self):
        cb = CircuitBreaker(failure_threshold=1)
        cb.record_failure()
        with pytest.raises(CircuitOpenError):
            cb.before_call()

    def test_transitions_to_half_open_after_cooldown(self):
        t = [0.0]
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=10.0, clock=lambda: t[0])
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN

        t[0] = 10.0
        assert cb.state == CircuitBreaker.HALF_OPEN

    def test_half_open_allows_call(self):
        t = [0.0]
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=5.0, clock=lambda: t[0])
        cb.record_failure()
        t[0] = 5.0
        cb.before_call()  # should not raise

    def test_half_open_closes_on_success(self):
        t = [0.0]
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=5.0, clock=lambda: t[0])
        cb.record_failure()
        t[0] = 5.0
        cb.record_success()
        assert cb.state == CircuitBreaker.CLOSED

    def test_half_open_reopens_on_failure(self):
        t = [0.0]
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=5.0, clock=lambda: t[0])
        cb.record_failure()
        t[0] = 5.0
        assert cb.state == CircuitBreaker.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN


class TestTokenBucketRateLimiter:
    def test_allows_up_to_burst(self):
        rl = TokenBucketRateLimiter(rate=10.0, burst=5, clock=lambda: 0.0)
        results = [rl.acquire() for _ in range(5)]
        assert all(results)
        assert not rl.acquire()

    def test_refills_over_time(self):
        t = [0.0]
        rl = TokenBucketRateLimiter(rate=10.0, burst=5, clock=lambda: t[0])
        for _ in range(5):
            rl.acquire()

        t[0] = 0.5  # 0.5s * 10/s = 5 tokens refilled
        results = [rl.acquire() for _ in range(5)]
        assert all(results)

    def test_rejects_when_empty(self):
        rl = TokenBucketRateLimiter(rate=1.0, burst=1, clock=lambda: 0.0)
        assert rl.acquire()
        assert not rl.acquire()


class TestClientWithCircuitBreaker:
    def test_circuit_opens_after_failures(self, gateway_kp):
        cb = CircuitBreaker(failure_threshold=2)
        client = DevnetAnchorClient(
            submit_fn=MagicMock(side_effect=RuntimeError("rpc down")),
            circuit_breaker=cb,
        )
        attestation = _make_attestation(gateway_kp)

        for _ in range(2):
            with pytest.raises(RuntimeError):
                client.submit_attestation(attestation)

        with pytest.raises(CircuitOpenError):
            client.submit_attestation(attestation)

    def test_circuit_closes_on_success(self, gateway_kp):
        call_count = {"n": 0}

        def flaky(submission):
            call_count["n"] += 1
            if call_count["n"] <= 2:
                raise RuntimeError("fail")
            return "0xtx"

        t = [0.0]
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=5.0, clock=lambda: t[0])
        client = DevnetAnchorClient(submit_fn=flaky, circuit_breaker=cb)
        attestation = _make_attestation(gateway_kp)

        # Two failures open the circuit
        for _ in range(2):
            with pytest.raises(RuntimeError):
                client.submit_attestation(attestation)
        assert cb.state == CircuitBreaker.OPEN

        # After cooldown, half-open allows a probe
        t[0] = 5.0
        result = client.submit_attestation(attestation)
        assert result == "0xtx"
        assert cb.state == CircuitBreaker.CLOSED


class TestClientWithRateLimiter:
    def test_rate_limited_raises(self, gateway_kp):
        rl = TokenBucketRateLimiter(rate=1.0, burst=1, clock=lambda: 0.0)
        client = DevnetAnchorClient(
            submit_fn=MagicMock(return_value="0xtx"),
            rate_limiter=rl,
        )
        attestation = _make_attestation(gateway_kp)

        assert client.submit_attestation(attestation) == "0xtx"
        with pytest.raises(RateLimitedError):
            client.submit_attestation(attestation)
