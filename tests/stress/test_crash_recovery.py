"""Stress scenario 15: Gateway crash recovery."""

import os
import tempfile
from unittest.mock import MagicMock

import pytest

from tests.stress.conftest import make_raw_log


class TestScenario15_CrashRecovery:
    """Gateway killed mid-operation — restarts and reconciles."""

    def test_replay_db_survives_crash(self, stress_kp):
        """Events processed before crash are remembered after restart."""
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            log1 = make_raw_log("0xpre_crash", 100, 0)

            config = GatewayVMConfig(
                enabled=True,
                source_chain_id=84532,
                source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
                finality_depth=12,
                dest_chain_id=103115120,
                replay_db_path=db_path,
            )

            # Instance 1: process event, then "crash"
            svc1 = GatewayVMService(
                config=config,
                operator_keypair=stress_kp,
                fetch_logs=lambda fb, tb: [log1],
                get_source_block_number=lambda: 200,
                get_dest_block_number=lambda: 999,
                anchor_fn=MagicMock(return_value="0xtx"),
                is_signer_authorized=lambda: True,
            )
            r1 = svc1.tick()
            assert r1.events_accepted == 1
            svc1.stop()

            # Instance 2: new process, same replay DB
            svc2 = GatewayVMService(
                config=config,
                operator_keypair=stress_kp,
                fetch_logs=lambda fb, tb: [log1],
                get_source_block_number=lambda: 200,
                get_dest_block_number=lambda: 999,
                anchor_fn=MagicMock(return_value="0xtx"),
                is_signer_authorized=lambda: True,
            )
            r2 = svc2.tick()
            assert r2.events_rejected == 1  # replay DB remembers
            assert r2.events_accepted == 0
            svc2.stop()
        finally:
            os.unlink(db_path)

    def test_new_events_processed_after_recovery(self, stress_kp):
        """New events after crash are processed normally."""
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            config = GatewayVMConfig(
                enabled=True,
                source_chain_id=84532,
                source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
                finality_depth=12,
                dest_chain_id=103115120,
                replay_db_path=db_path,
            )

            # Pre-crash: process event A
            svc1 = GatewayVMService(
                config=config,
                operator_keypair=stress_kp,
                fetch_logs=lambda fb, tb: [make_raw_log("0xevent_A", 100, 0)],
                get_source_block_number=lambda: 200,
                get_dest_block_number=lambda: 999,
                anchor_fn=MagicMock(return_value="0xtx"),
                is_signer_authorized=lambda: True,
            )
            svc1.tick()
            svc1.stop()

            # Post-crash: event B (new) accepted, event A (old) rejected
            anchor_fn2 = MagicMock(return_value="0xtx2")
            svc2 = GatewayVMService(
                config=config,
                operator_keypair=stress_kp,
                fetch_logs=lambda fb, tb: [
                    make_raw_log("0xevent_A", 100, 0),
                    make_raw_log("0xevent_B", 101, 0),
                ],
                get_source_block_number=lambda: 200,
                get_dest_block_number=lambda: 999,
                anchor_fn=anchor_fn2,
                is_signer_authorized=lambda: True,
            )
            r2 = svc2.tick()
            assert r2.events_observed == 2
            assert r2.events_accepted == 1  # only event B
            assert r2.events_rejected == 1  # event A is replay
            svc2.stop()
        finally:
            os.unlink(db_path)
