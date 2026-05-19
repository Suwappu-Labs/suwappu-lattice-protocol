"""Stress scenarios 12, 13: Challenge period and ZK proof fallback."""

from unittest.mock import MagicMock

import pytest

from tests.stress.conftest import make_raw_log


class TestScenario12_ChallengeExpiration:
    """Optimistic mode: challenge window expires — auto-finalizes."""

    def test_challenge_window_auto_finalizes(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        t = [1000.0]
        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
            challenge_mode="optimistic",
            challenge_period_seconds=60.0,
        )

        log = make_raw_log("0xchallenge", 100, 0)
        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=lambda fb, tb: [log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0xtx"),
            is_signer_authorized=lambda: True,
            clock=lambda: t[0],
        )

        r1 = svc.tick()
        assert r1.events_accepted == 1
        assert svc.challenge_manager is not None
        stats = svc.challenge_manager.stats()
        assert stats["open"] == 1

        # Advance time past challenge period
        t[0] = 1070.0
        svc.tick()
        stats = svc.challenge_manager.stats()
        assert stats["finalized"] == 1
        assert stats["open"] == 0


class TestScenario13_ZKProofFallback:
    """ZK mode: gateway uses ZK proof for instant finality."""

    def test_zk_mode_skips_challenge_window(self, stress_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
            challenge_mode="zk",
        )

        log = make_raw_log("0xzk_event", 100, 0)
        anchor_fn = MagicMock(return_value="0xtx")
        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=lambda fb, tb: [log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        r = svc.tick()
        assert r.events_accepted == 1
        assert svc.challenge_manager is None
