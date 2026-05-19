"""Tests for GatewayTracker — attestation lifecycle tracking."""

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def gateway_kp():
    return KeyPair.generate("tracker-test")


def _make_attestation(gateway_kp, event_id_suffix="aaa"):
    from src.ltp.gateway_vm.events import BridgeEvent
    from src.ltp.gateway_vm.writer import AttestationWriter

    event = BridgeEvent(
        source_chain_id=84532,
        bridge_contract="0x5083",
        tx_hash=f"0x{event_id_suffix}",
        block_number=100,
        log_index=0,
        event_name="AnchorCreated",
        sender="0xaa",
        recipient="0xbb",
        payload_hash="sha3-256:ff00",
        amount=100,
        nonce=1,
        timestamp=1700000000.0,
    )
    writer = AttestationWriter(operator_keypair=gateway_kp, dest_chain_id=103115120)
    return writer.create_attestation(event)


class TestGatewayTracker:
    def test_track_new_attestation(self, gateway_kp):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        att = _make_attestation(gateway_kp)
        tracker.mark_pending(att)
        rec = tracker.get(att.event_id)
        assert rec is not None
        assert rec["status"] == "pending"

    def test_lifecycle_pending_to_finalized(self, gateway_kp):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        att = _make_attestation(gateway_kp)
        tracker.mark_pending(att)
        tracker.mark_submitted(att.event_id, tx_hash="0xtx1")
        tracker.mark_confirmed(att.event_id, block_number=500, gas_used=21000)
        tracker.mark_finalized(att.event_id)
        rec = tracker.get(att.event_id)
        assert rec["status"] == "finalized"
        assert rec["tx_hash"] == "0xtx1"

    def test_mark_failed(self, gateway_kp):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        att = _make_attestation(gateway_kp)
        tracker.mark_pending(att)
        tracker.mark_failed(att.event_id, error="RPC timeout")
        rec = tracker.get(att.event_id)
        assert rec["status"] == "failed"
        assert rec["error"] == "RPC timeout"

    def test_stats(self, gateway_kp):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        a1 = _make_attestation(gateway_kp, "111")
        a2 = _make_attestation(gateway_kp, "222")
        a3 = _make_attestation(gateway_kp, "333")
        tracker.mark_pending(a1)
        tracker.mark_pending(a2)
        tracker.mark_pending(a3)
        tracker.mark_submitted(a1.event_id, tx_hash="0xt1")
        tracker.mark_failed(a3.event_id, error="err")
        stats = tracker.stats()
        assert stats["pending"] == 1
        assert stats["submitted"] == 1
        assert stats["failed"] == 1

    def test_get_by_status(self, gateway_kp):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        a1 = _make_attestation(gateway_kp, "aaa")
        a2 = _make_attestation(gateway_kp, "bbb")
        tracker.mark_pending(a1)
        tracker.mark_pending(a2)
        tracker.mark_submitted(a1.event_id, tx_hash="0xt1")
        pending = tracker.get_by_status("pending")
        assert len(pending) == 1
        submitted = tracker.get_by_status("submitted")
        assert len(submitted) == 1

    def test_get_missing_returns_none(self):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        assert tracker.get("nonexistent") is None

    def test_lookup_by_tx_hash(self, gateway_kp):
        from src.ltp.gateway_vm.tracker import GatewayTracker

        tracker = GatewayTracker()
        att = _make_attestation(gateway_kp)
        tracker.mark_pending(att)
        tracker.mark_submitted(att.event_id, tx_hash="0xdeadbeef")
        rec = tracker.lookup_by_tx_hash("0xdeadbeef")
        assert rec is not None
        assert rec["event_id"] == att.event_id
