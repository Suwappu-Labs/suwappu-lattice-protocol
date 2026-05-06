"""Stress scenarios 2, 7, 8: Chain conditions."""

import pytest
from unittest.mock import MagicMock
from tests.stress.conftest import make_raw_log


class TestScenario2_ChainReorg:
    """Source chain reorg after event seen but before finality."""

    def test_reorg_causes_finality_rejection(self, stress_kp):
        """Event at block 100 when head=95 (reorg) → rejected due to negative depth."""
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        block_head = [95]  # head behind the event block → reorg scenario

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=lambda fb, tb: [make_raw_log("0xreorg", 100, 0)],
            get_source_block_number=lambda: block_head[0],
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0xtx"),
            is_signer_authorized=lambda: True,
        )

        # Head=95, event at block 100 → depth=-5 → rejected (reorg)
        r1 = svc.tick()
        assert r1.events_rejected == 1
        assert r1.events_accepted == 0

        # Chain recovers to head=200 → depth=100 → now accepted
        block_head[0] = 200
        r2 = svc.tick()
        assert r2.events_accepted == 1


class TestScenario7_DelayedFinality:
    """Source chain slow to produce blocks — gateway waits."""

    def test_event_waits_for_finality(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        log = make_raw_log("0xslow", 100, 0)
        block_head = [105]  # only 5 blocks deep, need 12

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )

        # Realistic mock: only return logs when they fall within the queried range
        def realistic_fetch(from_block, to_block):
            if from_block <= 100 <= to_block:
                return [log]
            return []

        anchor_fn = MagicMock(return_value="0xtx")
        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=realistic_fetch,
            get_source_block_number=lambda: block_head[0],
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        # Tick 1: safe_block = 105-12 = 93. Event at 100 is outside scan range.
        # No events observed (listener caps at safe_block).
        r1 = svc.tick()
        assert r1.events_observed == 0
        assert anchor_fn.call_count == 0

        # Chain advances to 108 — safe_block = 96. Still can't see event at 100.
        block_head[0] = 108
        r2 = svc.tick()
        assert r2.events_observed == 0

        # Chain reaches 112 — safe_block = 100. Event at 100 now in range and final.
        block_head[0] = 112
        r3 = svc.tick()
        assert r3.events_accepted == 1
        assert anchor_fn.call_count == 1


class TestScenario8_BridgeContractPause:
    """Source bridge contract paused — gateway detects empty event stream."""

    def test_paused_bridge_produces_no_events(self, stress_kp):
        from tests.stress.conftest import make_service

        paused = [False]

        def mock_fetch(fb, tb):
            if paused[0]:
                return []
            return [make_raw_log("0xpre_pause", 100, 0)]

        svc = make_service(stress_kp, raw_logs=[])
        svc._listener._fetch_logs = mock_fetch

        # Before pause: event processed
        r1 = svc.tick()
        assert r1.events_accepted == 1

        # Pause bridge
        paused[0] = True
        r2 = svc.tick()
        assert r2.events_observed == 0
        assert r2.events_accepted == 0

        # Multiple ticks during pause
        for _ in range(5):
            r = svc.tick()
            assert r.events_observed == 0
