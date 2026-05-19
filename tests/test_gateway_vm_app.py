"""Tests for the Gateway VM FastAPI app factory."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.ltp.gateway_vm.app import create_app
from src.ltp.gateway_vm.config import GatewayVMConfig
from src.ltp.gateway_vm.tracker import GatewayTracker


@pytest.fixture
def test_config():
    return GatewayVMConfig(
        enabled=True,
        gateway_id="test-gw-0",
        source_chain_id=84532,
        source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        finality_depth=12,
        dest_chain_id=103115120,
        replay_db_path=":memory:",
    )


@pytest.fixture
def mock_service():
    svc = MagicMock()
    svc.running = True
    svc.epoch = 5
    svc.retry_queue_size = 0
    return svc


@pytest.fixture
def test_tracker():
    return GatewayTracker()


@pytest.fixture
def test_app(test_config, mock_service, test_tracker):
    return create_app(test_config, mock_service, test_tracker)


class TestCreateApp:
    def test_app_title(self, test_app):
        assert test_app.title == "ETP Gateway VM"

    def test_health_returns_200_when_running(self, test_app):
        client = TestClient(test_app)
        resp = client.get("/gateway/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_returns_503_when_stopped(self, test_config, test_tracker):
        svc = MagicMock()
        svc.running = False
        svc.epoch = 0
        svc.retry_queue_size = 0
        app = create_app(test_config, svc, test_tracker)
        client = TestClient(app)
        resp = client.get("/gateway/health")
        assert resp.status_code == 503

    def test_status_returns_gateway_info(self, test_app):
        client = TestClient(test_app)
        resp = client.get("/gateway/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["gateway_id"] == "test-gw-0"
        assert body["source_chain_id"] == 84532
        assert body["dest_chain_id"] == 103115120

    def test_events_returns_empty_list(self, test_app):
        client = TestClient(test_app)
        resp = client.get("/gateway/events")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_events_tx_hash_404(self, test_app):
        client = TestClient(test_app)
        resp = client.get("/gateway/events/0xnonexistent")
        assert resp.status_code == 404

    def test_lifespan_starts_service(self, test_config, test_tracker):
        svc = MagicMock()
        svc.running = True
        svc.epoch = 0
        svc.retry_queue_size = 0
        app = create_app(test_config, svc, test_tracker)
        with TestClient(app):
            svc.start.assert_called_once()

    def test_lifespan_stops_service_on_shutdown(self, test_config, test_tracker):
        svc = MagicMock()
        svc.running = True
        svc.epoch = 0
        svc.retry_queue_size = 0
        app = create_app(test_config, svc, test_tracker)
        with TestClient(app):
            pass
        svc.stop.assert_called_once()
