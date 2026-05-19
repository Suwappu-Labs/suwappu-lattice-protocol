"""Stress scenarios 3, 9: RPC downtime and devnet write failures."""

from unittest.mock import MagicMock

import pytest

from tests.stress.conftest import make_raw_log, make_service


class TestScenario3_SourceRPCDowntime:
    """Source RPC goes down — gateway handles poll failure gracefully."""

    def test_source_rpc_failure_returns_error_result(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )

        def failing_fetch(fb, tb):
            raise ConnectionError("RPC node unreachable")

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=failing_fetch,
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0xtx"),
            is_signer_authorized=lambda: True,
        )

        result = svc.tick()
        assert "poll failed" in result.error
        assert result.events_observed == 0

    def test_source_rpc_recovers_after_failure(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )

        rpc_up = [False]

        def conditional_fetch(fb, tb):
            if not rpc_up[0]:
                raise ConnectionError("RPC down")
            return [make_raw_log("0xrecovery", 100, 0)]

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=conditional_fetch,
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0xtx"),
            is_signer_authorized=lambda: True,
        )

        # RPC down
        r1 = svc.tick()
        assert "poll failed" in r1.error

        # RPC recovers
        rpc_up[0] = True
        r2 = svc.tick()
        assert r2.events_accepted == 1
        assert r2.error == ""


class TestScenario9_DevnetWriteFailure:
    """Devnet RPC returns error — gateway retries with backoff."""

    def test_anchor_failure_enters_retry_queue(self, stress_kp):
        log = make_raw_log("0xfail_anchor", 100, 0)
        anchor_fn = MagicMock(side_effect=RuntimeError("devnet RPC timeout"))
        svc = make_service(stress_kp, raw_logs=[log], anchor_fn=anchor_fn)

        r1 = svc.tick()
        assert r1.anchor_failures == 1
        assert svc.retry_queue_size == 1

    def test_retry_succeeds_after_devnet_recovery(self, stress_kp):
        """Anchor fails initially, then succeeds on a later tick."""
        log = make_raw_log("0xretry_ok", 100, 0)
        call_count = {"n": 0}

        def flaky_anchor(att):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("devnet timeout")
            return "0xsuccess"

        svc = make_service(stress_kp, raw_logs=[log], anchor_fn=flaky_anchor, max_retries=5)

        # Tick 1: event observed, anchor fails → enters retry queue
        r1 = svc.tick()
        assert r1.anchor_failures == 1
        assert svc.retry_queue_size == 1

        # Tick 2: retry succeeds (call_count becomes 2+)
        r2 = svc.tick()
        assert r2.retries_attempted >= 1
        assert svc.retry_queue_size == 0

    def test_exceeds_max_retries_drops_event(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        delivered = [False]

        def one_shot_fetch(fb, tb):
            if not delivered[0]:
                delivered[0] = True
                return [make_raw_log("0xperm_fail", 100, 0)]
            return []

        anchor_fn = MagicMock(side_effect=RuntimeError("permanent failure"))
        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
            max_retries=2,
        )

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=one_shot_fetch,
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        svc.tick()  # fail → retry queue
        assert svc.retry_queue_size >= 1

        # Tick until retries exhausted and queue drains
        for _ in range(10):
            svc.tick()
            if svc.retry_queue_size == 0:
                break
        assert svc.retry_queue_size == 0
