"""Stress scenario 11: Out-of-order events."""

from unittest.mock import MagicMock

import pytest

from tests.stress.conftest import make_raw_log


class TestScenario11_OutOfOrderEvents:
    """Events arrive non-sequentially — gateway processes all valid ones."""

    def test_out_of_order_blocks_all_processed(self, stress_kp):
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

        # Events out of block order
        logs = [
            make_raw_log("0xevent_c", 102, 0),
            make_raw_log("0xevent_a", 100, 0),
            make_raw_log("0xevent_b", 101, 0),
        ]
        anchor_fn = MagicMock(return_value="0xtx")

        svc = GatewayVMService(
            config=config,
            operator_keypair=stress_kp,
            fetch_logs=lambda fb, tb: logs,
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=anchor_fn,
            is_signer_authorized=lambda: True,
        )

        result = svc.tick()
        assert result.events_observed == 3
        assert result.events_accepted == 3
        assert anchor_fn.call_count == 3
