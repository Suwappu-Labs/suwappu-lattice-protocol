"""Stress scenario 14: Multiple gateways processing same event stream."""

import os
import tempfile
from unittest.mock import MagicMock

import pytest

from src.ltp.keypair import KeyPair
from tests.stress.conftest import make_raw_log


class TestScenario14_MultipleGateways:
    """Two gateway VMs process same event stream — replay DB prevents duplicates."""

    def test_two_gateways_same_events_different_replay_dbs(self, stress_kp):
        """Independent gateways each accept the same event (separate replay DBs)."""
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        log = make_raw_log("0xshared", 100, 0)
        kp2 = KeyPair.generate("gateway-2")

        def make_gw(kp, gw_id):
            config = GatewayVMConfig(
                enabled=True,
                source_chain_id=84532,
                source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
                finality_depth=12,
                dest_chain_id=103115120,
                replay_db_path=":memory:",
                gateway_id=gw_id,
            )
            return GatewayVMService(
                config=config,
                operator_keypair=kp,
                fetch_logs=lambda fb, tb: [log],
                get_source_block_number=lambda: 200,
                get_dest_block_number=lambda: 999,
                anchor_fn=MagicMock(return_value="0xtx"),
                is_signer_authorized=lambda: True,
            )

        gw1 = make_gw(stress_kp, "gw-1")
        gw2 = make_gw(kp2, "gw-2")

        r1 = gw1.tick()
        r2 = gw2.tick()

        # Both accept (independent replay DBs)
        assert r1.events_accepted == 1
        assert r2.events_accepted == 1

    def test_shared_replay_db_prevents_duplicate_anchor(self):
        """Shared replay DB ensures only first gateway anchors the event."""
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        kp1 = KeyPair.generate("shared-gw-1")
        kp2 = KeyPair.generate("shared-gw-2")
        log = make_raw_log("0xcontested", 100, 0)

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            shared_db = f.name

        try:

            def make_gw(kp, gw_id):
                config = GatewayVMConfig(
                    enabled=True,
                    source_chain_id=84532,
                    source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
                    finality_depth=12,
                    dest_chain_id=103115120,
                    replay_db_path=shared_db,
                    gateway_id=gw_id,
                )
                return GatewayVMService(
                    config=config,
                    operator_keypair=kp,
                    fetch_logs=lambda fb, tb: [log],
                    get_source_block_number=lambda: 200,
                    get_dest_block_number=lambda: 999,
                    anchor_fn=MagicMock(return_value="0xtx"),
                    is_signer_authorized=lambda: True,
                )

            gw1 = make_gw(kp1, "shared-gw-1")
            gw2 = make_gw(kp2, "shared-gw-2")

            r1 = gw1.tick()
            assert r1.events_accepted == 1

            r2 = gw2.tick()
            assert r2.events_rejected == 1
            assert r2.events_accepted == 0
        finally:
            os.unlink(shared_db)
