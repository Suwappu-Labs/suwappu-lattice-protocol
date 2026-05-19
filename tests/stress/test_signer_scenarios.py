"""Stress scenario 4: Signer revocation mid-operation."""

from unittest.mock import MagicMock

import pytest

from tests.stress.conftest import make_raw_log


class TestScenario4_SignerRevocation:
    """Gateway signer revoked on devnet mid-operation — anchor rejected."""

    def test_signer_revoked_mid_tick(self, stress_kp):
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

        authorized = [True]

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=lambda fb, tb: [make_raw_log("0xpre_revoke", 100, 0)],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0xtx"),
            is_signer_authorized=lambda: authorized[0],
        )

        # Before revocation: accepted
        r1 = svc.tick()
        assert r1.events_accepted == 1

        # Revoke signer
        authorized[0] = False

        # New event: rejected at signer check
        svc._listener._fetch_logs = lambda fb, tb: [make_raw_log("0xpost_revoke", 101, 0)]
        r2 = svc.tick()
        assert r2.events_rejected == 1
        assert r2.events_accepted == 0
