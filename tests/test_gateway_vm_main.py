"""Tests for GatewayVM entry point — lifecycle, signal handling, teardown."""

import signal
from unittest.mock import MagicMock, patch

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def gateway_kp():
    return KeyPair.generate("gateway-main-test")


class TestGatewayVMLifecycle:
    def test_start_and_stop(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.main import GatewayVM

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083",
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )
        vm = GatewayVM(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0x"),
            is_signer_authorized=lambda: True,
        )
        vm.start()
        assert vm.running is True
        vm.stop()
        assert vm.running is False

    def test_stop_is_idempotent(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.main import GatewayVM

        config = GatewayVMConfig(
            enabled=True,
            replay_db_path=":memory:",
        )
        vm = GatewayVM(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [],
            get_source_block_number=lambda: 0,
            get_dest_block_number=lambda: 0,
            anchor_fn=MagicMock(return_value="0x"),
            is_signer_authorized=lambda: True,
        )
        vm.start()
        vm.stop()
        vm.stop()  # second stop should not raise
        assert vm.running is False

    def test_teardown_order_is_reverse_startup(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.main import GatewayVM

        config = GatewayVMConfig(
            enabled=True,
            replay_db_path=":memory:",
        )
        teardown_order = []

        vm = GatewayVM(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [],
            get_source_block_number=lambda: 0,
            get_dest_block_number=lambda: 0,
            anchor_fn=MagicMock(return_value="0x"),
            is_signer_authorized=lambda: True,
        )
        vm.start()

        # Patch stop methods to record teardown order
        original_svc_stop = vm._service.stop
        original_db_close = vm._replay_db.close

        def mock_svc_stop():
            teardown_order.append("service")
            original_svc_stop()

        def mock_db_close():
            teardown_order.append("replay_db")
            original_db_close()

        vm._service.stop = mock_svc_stop
        vm._replay_db.close = mock_db_close

        vm.stop()
        # Service stops before replay DB closes (reverse of startup)
        assert teardown_order == ["service", "replay_db"]

    def test_signal_handler_triggers_stop(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.main import GatewayVM

        config = GatewayVMConfig(
            enabled=True,
            replay_db_path=":memory:",
        )
        vm = GatewayVM(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [],
            get_source_block_number=lambda: 0,
            get_dest_block_number=lambda: 0,
            anchor_fn=MagicMock(return_value="0x"),
            is_signer_authorized=lambda: True,
        )
        vm.start()
        assert vm.running is True
        # Simulate SIGTERM
        vm._signal_handler(signal.SIGTERM, None)
        assert vm.running is False
