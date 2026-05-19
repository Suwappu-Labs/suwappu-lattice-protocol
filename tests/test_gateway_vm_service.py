"""Tests for GatewayVMService — full daemon tick loop integration."""

import json
import logging
from unittest.mock import MagicMock

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def gateway_kp():
    return KeyPair.generate("gateway-service-test")


def _make_raw_log(tx_hash="0xabc", block_number=100, log_index=0):
    return {
        "transactionHash": tx_hash,
        "blockNumber": block_number,
        "logIndex": log_index,
        "address": "0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        "event": "AnchorCreated",
        "args": {
            "sender": "0xdeadbeef",
            "recipient": "0xcafebabe",
            "payloadHash": "sha3-256:abcd1234",
            "amount": 100_000_000,
            "nonce": 1,
        },
    }


def _make_service(
    gateway_kp,
    *,
    raw_logs=None,
    current_block=200,
    anchor_fn=None,
    signer_authorized=True,
    challenge_period=None,
    clock=None,
    challenge_mode="optimistic",
):
    from src.ltp.gateway_vm.config import GatewayVMConfig
    from src.ltp.gateway_vm.service import GatewayVMService

    config = GatewayVMConfig(
        enabled=True,
        source_chain_id=84532,
        source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        finality_depth=12,
        dest_chain_id=103115120,
        replay_db_path=":memory:",
        challenge_mode=challenge_mode,
        challenge_period_seconds=challenge_period if challenge_period is not None else 3600.0,
    )

    if raw_logs is None:
        raw_logs = []

    if anchor_fn is None:
        anchor_fn = MagicMock(return_value="0xtxhash")

    return GatewayVMService(
        config=config,
        operator_keypair=gateway_kp,
        fetch_logs=lambda fb, tb: raw_logs,
        get_source_block_number=lambda: current_block,
        get_dest_block_number=lambda: 999,
        anchor_fn=anchor_fn,
        is_signer_authorized=lambda: signer_authorized,
        clock=clock,
    )


class TestTickNoEvents:
    def test_tick_with_no_events(self, gateway_kp):
        svc = _make_service(gateway_kp, raw_logs=[])
        result = svc.tick()
        assert result.epoch == 1
        assert result.events_observed == 0
        assert result.events_accepted == 0
        assert result.events_rejected == 0
        assert result.error == ""


class TestTickProcessesEvent:
    def test_tick_processes_valid_event(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        anchor_fn = MagicMock(return_value="0xtxhash")
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200, anchor_fn=anchor_fn)
        result = svc.tick()
        assert result.events_observed == 1
        assert result.events_accepted == 1
        assert result.events_rejected == 0
        assert anchor_fn.call_count == 1


class TestReplayRejection:
    def test_same_event_rejected_on_second_tick(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        anchor_fn = MagicMock(return_value="0xtxhash")
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200, anchor_fn=anchor_fn)
        # First tick: processes event
        r1 = svc.tick()
        assert r1.events_accepted == 1
        # Second tick: same event, rejected as replay
        r2 = svc.tick()
        assert r2.events_observed == 1
        assert r2.events_accepted == 0
        assert r2.events_rejected == 1


class TestFinalityRejection:
    def test_event_rejected_before_finality(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 195, 0)]  # block 195
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200)
        # depth = 200 - 195 = 5, need 12
        result = svc.tick()
        assert result.events_rejected == 1
        assert result.events_accepted == 0


class TestAnchorFailure:
    def test_anchor_failure_recorded(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        anchor_fn = MagicMock(side_effect=RuntimeError("RPC timeout"))
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200, anchor_fn=anchor_fn)
        result = svc.tick()
        assert result.events_observed == 1
        assert result.events_accepted == 0
        assert result.anchor_failures == 1


class TestRetryQueue:
    def test_failed_anchor_retried_next_tick(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        call_count = {"n": 0}

        def failing_then_succeeding(attestation):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("temporary failure")
            return "0xtxhash"

        svc = _make_service(
            gateway_kp, raw_logs=logs, current_block=200, anchor_fn=failing_then_succeeding
        )
        # First tick: fails
        r1 = svc.tick()
        assert r1.anchor_failures == 1
        assert svc.retry_queue_size == 1
        # Second tick: retries and succeeds
        r2 = svc.tick()
        assert r2.retries_attempted == 1
        assert svc.retry_queue_size == 0


class TestMultipleEvents:
    def test_multiple_events_in_one_tick(self, gateway_kp):
        logs = [
            _make_raw_log("0xaaa", 100, 0),
            _make_raw_log("0xbbb", 101, 0),
            _make_raw_log("0xccc", 102, 0),
        ]
        anchor_fn = MagicMock(return_value="0xtxhash")
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200, anchor_fn=anchor_fn)
        result = svc.tick()
        assert result.events_observed == 3
        assert result.events_accepted == 3
        assert anchor_fn.call_count == 3


class TestServiceProperties:
    def test_epoch_increments(self, gateway_kp):
        svc = _make_service(gateway_kp)
        assert svc.epoch == 0
        svc.tick()
        assert svc.epoch == 1
        svc.tick()
        assert svc.epoch == 2

    def test_running_property(self, gateway_kp):
        svc = _make_service(gateway_kp)
        assert svc.running is False

    def test_requires_keypair(self):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        with pytest.raises(TypeError):
            GatewayVMService(
                config=GatewayVMConfig(),
                operator_keypair=None,
                fetch_logs=lambda fb, tb: [],
                get_source_block_number=lambda: 0,
                get_dest_block_number=lambda: 0,
                anchor_fn=lambda a: "0x",
                is_signer_authorized=lambda: True,
            )


class TestChallengeIntegration:
    def test_optimistic_mode_opens_challenge_window(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        anchor_fn = MagicMock(return_value="0xtxhash")
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200, anchor_fn=anchor_fn)
        result = svc.tick()
        assert result.events_accepted == 1
        # Challenge window should be open for the anchored event
        assert svc.challenge_manager is not None
        stats = svc.challenge_manager.stats()
        assert stats["open"] == 1

    def test_challenge_tick_auto_finalizes(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        anchor_fn = MagicMock(return_value="0xtxhash")
        t = [1000.0]
        svc = _make_service(
            gateway_kp,
            raw_logs=logs,
            current_block=200,
            anchor_fn=anchor_fn,
            challenge_period=60.0,
            clock=lambda: t[0],
        )
        svc.tick()
        assert svc.challenge_manager.stats()["open"] == 1
        # Advance past challenge period
        t[0] = 1070.0
        svc.tick()  # tick calls challenge_manager.tick() internally
        assert svc.challenge_manager.stats()["finalized"] == 1

    def test_disabled_challenge_mode_skips_manager(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
            challenge_mode="disabled",
        )
        svc = GatewayVMService(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0x"),
            is_signer_authorized=lambda: True,
        )
        assert svc.challenge_manager is None


class _CapturingHandler(logging.Handler):
    """Captures formatted log output for assertion."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.outputs: list[str] = []

    def emit(self, record):
        self.outputs.append(self.format(record))


class TestStructuredLogging:
    def test_tick_produces_correlation_id(self, gateway_kp):
        logs = [_make_raw_log("0xaaa", 100, 0)]
        anchor_fn = MagicMock(return_value="0xtxhash")
        svc = _make_service(gateway_kp, raw_logs=logs, current_block=200, anchor_fn=anchor_fn)

        handler = _CapturingHandler()
        svc._log.attach_handler(handler)

        svc.tick()

        # At least one log output should contain correlation_id
        assert len(handler.outputs) > 0
        has_correlation = any("correlation_id" in out for out in handler.outputs)
        assert has_correlation, "Expected correlation_id in structured log output"

    def test_each_tick_gets_unique_correlation_id(self, gateway_kp):
        import json

        svc = _make_service(gateway_kp, raw_logs=[])
        handler = _CapturingHandler()
        svc._log.attach_handler(handler)

        svc.tick()
        svc.tick()

        # Extract correlation IDs from JSON outputs
        cids = set()
        for out in handler.outputs:
            try:
                data = json.loads(out)
                if "correlation_id" in data:
                    cids.add(data["correlation_id"])
            except (json.JSONDecodeError, KeyError):
                pass
        assert len(cids) >= 2, f"Each tick should produce a unique correlation ID, got {cids}"
