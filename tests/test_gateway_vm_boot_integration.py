"""Boot integration test — full pipeline from config through live HTTP.

Exercises: config → validate_config → create_app → TestClient → /gateway/health
No real RPC, web3, or crypto required.
"""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.ltp.gateway_vm.app import create_app
from src.ltp.gateway_vm.boot import validate_config
from src.ltp.gateway_vm.config import GatewayVMConfig
from src.ltp.gateway_vm.tracker import GatewayTracker


@pytest.fixture
def valid_config():
    return GatewayVMConfig(
        enabled=True,
        gateway_id="boot-test-gw",
        source_rpc_url="http://source:8545",
        source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        dest_rpc_url="http://dest:8545",
        dest_registry_address="0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
        source_chain_id=84532,
        dest_chain_id=103115120,
        replay_db_path=":memory:",
    )


@pytest.fixture
def mock_service():
    svc = MagicMock()
    svc.running = True
    svc.epoch = 0
    svc.retry_queue_size = 0
    return svc


class TestBootIntegration:
    """End-to-end boot pipeline without real RPC."""

    def test_valid_config_passes_validation(self, valid_config):
        assert validate_config(valid_config) == []

    def test_app_boots_and_serves_health(self, valid_config, mock_service):
        tracker = GatewayTracker()
        app = create_app(valid_config, mock_service, tracker)

        with TestClient(app) as client:
            mock_service.start.assert_called_once()

            resp = client.get("/gateway/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

        mock_service.stop.assert_called_once()

    def test_app_status_reflects_config(self, valid_config, mock_service):
        tracker = GatewayTracker()
        app = create_app(valid_config, mock_service, tracker)

        with TestClient(app) as client:
            resp = client.get("/gateway/status")
            assert resp.status_code == 200
            body = resp.json()
            assert body["gateway_id"] == "boot-test-gw"
            assert body["source_chain_id"] == 84532
            assert body["dest_chain_id"] == 103115120
            assert body["status"] == "active"

    def test_invalid_config_caught_before_app(self):
        bad_config = GatewayVMConfig()  # all RPC fields empty
        missing = validate_config(bad_config)
        assert len(missing) == 4

    def test_degraded_status_with_large_retry_queue(self, valid_config):
        svc = MagicMock()
        svc.running = True
        svc.epoch = 42
        svc.retry_queue_size = 15  # above threshold of 10
        tracker = GatewayTracker()
        app = create_app(valid_config, svc, tracker)

        with TestClient(app) as client:
            resp = client.get("/gateway/status")
            assert resp.json()["status"] == "degraded"

            resp = client.get("/gateway/health")
            assert resp.json()["checks"]["retry_queue"] == "degraded"
