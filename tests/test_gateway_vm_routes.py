"""Tests for gateway REST endpoints — status, health, events."""

from unittest.mock import MagicMock

import pytest


def _make_test_app():
    """Create a FastAPI test app with gateway routers."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.ltp.gateway_vm.routers.events import router as events_router
    from src.ltp.gateway_vm.routers.status import router as status_router
    from src.ltp.gateway_vm.tracker import GatewayTracker

    app = FastAPI()
    app.include_router(status_router)
    app.include_router(events_router)

    tracker = GatewayTracker()
    app.state.gateway_tracker = tracker
    app.state.gateway_service = MagicMock(
        running=True,
        epoch=42,
        retry_queue_size=0,
    )
    app.state.gateway_config = MagicMock(
        source_chain_id=84532,
        dest_chain_id=103115120,
        gateway_id="gw-test",
        challenge_mode="optimistic",
    )

    return TestClient(app), tracker


class TestGatewayStatus:
    def test_status_returns_ok(self):
        client, _ = _make_test_app()
        resp = client.get("/gateway/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "active"
        assert data["epoch"] == 42
        assert data["source_chain_id"] == 84532
        assert data["dest_chain_id"] == 103115120

    def test_status_degraded_when_retry_queue_large(self):
        client, _ = _make_test_app()
        client.app.state.gateway_service.retry_queue_size = 50
        resp = client.get("/gateway/status")
        data = resp.json()
        assert data["status"] == "degraded"

    def test_status_stopped_when_not_running(self):
        client, _ = _make_test_app()
        client.app.state.gateway_service.running = False
        resp = client.get("/gateway/status")
        data = resp.json()
        assert data["status"] == "stopped"


class TestGatewayHealth:
    def test_health_ok(self):
        client, _ = _make_test_app()
        resp = client.get("/gateway/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["checks"]["service"] == "running"

    def test_health_503_when_stopped(self):
        client, _ = _make_test_app()
        client.app.state.gateway_service.running = False
        resp = client.get("/gateway/health")
        assert resp.status_code == 503


class TestGatewayEvents:
    def _seed_tracker(self, tracker, gateway_kp):
        from src.ltp.gateway_vm.events import BridgeEvent
        from src.ltp.gateway_vm.writer import AttestationWriter

        writer = AttestationWriter(operator_keypair=gateway_kp, dest_chain_id=103115120)
        events = []
        for i, suffix in enumerate(["aaa", "bbb", "ccc"]):
            event = BridgeEvent(
                source_chain_id=84532,
                bridge_contract="0x5083",
                tx_hash=f"0x{suffix}",
                block_number=100 + i,
                log_index=0,
                event_name="AnchorCreated",
                sender="0xaa",
                recipient="0xbb",
                payload_hash="sha3-256:ff",
                amount=0,
                nonce=i,
                timestamp=1700000000.0,
            )
            att = writer.create_attestation(event)
            tracker.mark_pending(att)
            events.append((event, att))
        # Submit first, fail third
        tracker.mark_submitted(events[0][1].event_id, tx_hash="0xaaa")
        tracker.mark_failed(events[2][1].event_id, error="timeout")
        return events

    def test_list_all_events(self):
        from src.ltp.keypair import KeyPair

        client, tracker = _make_test_app()
        kp = KeyPair.generate("events-test")
        self._seed_tracker(tracker, kp)
        resp = client.get("/gateway/events")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) == 3

    def test_filter_by_status(self):
        from src.ltp.keypair import KeyPair

        client, tracker = _make_test_app()
        kp = KeyPair.generate("filter-test")
        self._seed_tracker(tracker, kp)
        resp = client.get("/gateway/events?status=failed")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) == 1
        assert data["events"][0]["status"] == "failed"

    def test_lookup_by_tx_hash(self):
        from src.ltp.keypair import KeyPair

        client, tracker = _make_test_app()
        kp = KeyPair.generate("lookup-test")
        self._seed_tracker(tracker, kp)
        resp = client.get("/gateway/events/0xaaa")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tx_hash"] == "0xaaa"

    def test_lookup_missing_tx_hash_404(self):
        client, _ = _make_test_app()
        resp = client.get("/gateway/events/0xnonexistent")
        assert resp.status_code == 404
