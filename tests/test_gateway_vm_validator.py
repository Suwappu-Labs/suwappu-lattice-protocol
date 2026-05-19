"""Tests for EventValidator — 12-point validation checklist."""

import pytest


def _make_valid_event():
    from src.ltp.gateway_vm.events import BridgeEvent

    return BridgeEvent(
        source_chain_id=84532,
        bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        tx_hash="0xabc123def456",
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


def _make_validator(*, current_block=200, signer_authorized=True):
    from src.ltp.gateway_vm.config import GatewayVMConfig
    from src.ltp.gateway_vm.replay import ReplayDB
    from src.ltp.gateway_vm.validator import EventValidator

    config = GatewayVMConfig(
        source_chain_id=84532,
        source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        finality_depth=12,
        dest_chain_id=103115120,
    )
    replay_db = ReplayDB(":memory:")
    return EventValidator(
        config=config,
        replay_db=replay_db,
        get_block_number=lambda: current_block,
        is_signer_authorized=lambda: signer_authorized,
    )


class TestValidEventPasses:
    def test_valid_event_passes_all_checks(self):
        v = _make_validator(current_block=200)
        event = _make_valid_event()
        ok, reason = v.validate(event)
        assert ok is True, f"Expected pass, got: {reason}"
        assert reason == ""


class TestChainIdCheck:
    def test_wrong_source_chain_rejected(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        v = _make_validator()
        event = BridgeEvent(
            source_chain_id=1,  # wrong — expected 84532
            bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            tx_hash="0xabc",
            block_number=100,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xaa",
            recipient="0xbb",
            payload_hash="sha3-256:ff",
            amount=0,
            nonce=0,
            timestamp=1700000000.0,
        )
        ok, reason = v.validate(event)
        assert ok is False
        assert "chain" in reason.lower()


class TestBridgeContractCheck:
    def test_wrong_bridge_contract_rejected(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        v = _make_validator()
        event = BridgeEvent(
            source_chain_id=84532,
            bridge_contract="0xUNAUTHORIZED",  # wrong contract
            tx_hash="0xabc",
            block_number=100,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xaa",
            recipient="0xbb",
            payload_hash="sha3-256:ff",
            amount=0,
            nonce=0,
            timestamp=1700000000.0,
        )
        ok, reason = v.validate(event)
        assert ok is False
        assert "contract" in reason.lower()


class TestFinalityCheck:
    def test_insufficient_finality_rejected(self):
        v = _make_validator(current_block=105)  # only 5 blocks deep, need 12
        event = _make_valid_event()  # block 100
        ok, reason = v.validate(event)
        assert ok is False
        assert "finality" in reason.lower()

    def test_exact_finality_passes(self):
        v = _make_validator(current_block=112)  # exactly 12 blocks deep
        event = _make_valid_event()  # block 100
        ok, reason = v.validate(event)
        assert ok is True


class TestReplayCheck:
    def test_already_processed_rejected(self):
        v = _make_validator()
        event = _make_valid_event()
        # Pre-mark as processed
        v._replay_db.mark_processed(
            event.event_id, tx_hash=event.tx_hash, block_number=event.block_number
        )
        ok, reason = v.validate(event)
        assert ok is False
        assert "replay" in reason.lower()


class TestSignerAuthCheck:
    def test_unauthorized_signer_rejected(self):
        v = _make_validator(signer_authorized=False)
        event = _make_valid_event()
        ok, reason = v.validate(event)
        assert ok is False
        assert "signer" in reason.lower() or "authorized" in reason.lower()


class TestPayloadHashCheck:
    def test_empty_payload_hash_rejected(self):
        from src.ltp.gateway_vm.events import BridgeEvent

        v = _make_validator()
        event = BridgeEvent(
            source_chain_id=84532,
            bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            tx_hash="0xabc",
            block_number=100,
            log_index=0,
            event_name="AnchorCreated",
            sender="0xaa",
            recipient="0xbb",
            payload_hash="",  # empty — invalid
            amount=0,
            nonce=0,
            timestamp=1700000000.0,
        )
        ok, reason = v.validate(event)
        assert ok is False
        assert "payload" in reason.lower()
