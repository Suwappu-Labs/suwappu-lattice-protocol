"""Tests for BridgeEvent — normalized external chain event."""

import time

import pytest


class TestBridgeEventConstruction:
    def test_create_bridge_event(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        event = BridgeEvent(
            source_chain_id=84532,
            bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            tx_hash="0xabc123",
            block_number=100,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xdeadbeef",
            recipient="0xcafebabe",
            payload_hash="sha3-256:abcd1234",
            amount=100_000_000,
            nonce=1,
            timestamp=1700000000.0,
        )
        assert event.source_chain_id == 84532
        assert event.tx_hash == "0xabc123"
        assert event.block_number == 100
        assert event.nonce == 1

    def test_event_id_is_deterministic(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        kwargs = dict(
            source_chain_id=84532,
            bridge_contract="0xabc",
            tx_hash="0x123",
            block_number=50,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xaa",
            recipient="0xbb",
            payload_hash="sha3-256:ff",
            amount=0,
            nonce=0,
            timestamp=1700000000.0,
        )
        e1 = BridgeEvent(**kwargs)
        e2 = BridgeEvent(**kwargs)
        assert e1.event_id == e2.event_id
        assert len(e1.event_id) > 0

    def test_different_events_different_ids(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        base = dict(
            source_chain_id=84532,
            bridge_contract="0xabc",
            tx_hash="0x123",
            block_number=50,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xaa",
            recipient="0xbb",
            payload_hash="sha3-256:ff",
            amount=0,
            nonce=0,
            timestamp=1700000000.0,
        )
        e1 = BridgeEvent(**base)
        e2 = BridgeEvent(**{**base, "tx_hash": "0x456"})
        assert e1.event_id != e2.event_id

    def test_to_signable_bytes(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        event = BridgeEvent(
            source_chain_id=84532,
            bridge_contract="0xabc",
            tx_hash="0x123",
            block_number=50,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xaa",
            recipient="0xbb",
            payload_hash="sha3-256:ff",
            amount=0,
            nonce=0,
            timestamp=1700000000.0,
        )
        payload = event.to_signable_bytes()
        assert isinstance(payload, bytes)
        assert len(payload) > 0
        # Deterministic
        assert payload == event.to_signable_bytes()
