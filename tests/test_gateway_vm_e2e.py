"""End-to-end integration test: event → validate → attest → anchor → track.

Exercises the full gateway VM pipeline with mock RPC but real
cryptography, real SQLite replay DB, and real attestation signing.
"""

from unittest.mock import MagicMock

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def gateway_kp():
    return KeyPair.generate("e2e-gateway")


def _make_raw_log(tx_hash="0xabc", block_number=100, log_index=0):
    return {
        "transactionHash": tx_hash,
        "blockNumber": block_number,
        "logIndex": log_index,
        "address": "0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        "event": "AnchorCreated",
        "args": {
            "sender": "0xdeadbeef",
            "recipient": "0xcafebabe",
            "payloadHash": "sha3-256:abcd1234",
            "amount": 100_000_000,
            "nonce": 1,
        },
    }


class TestEndToEndSingleEvent:
    """One event flows through the entire pipeline."""

    def test_single_event_end_to_end(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService
        from src.ltp.gateway_vm.tracker import GatewayTracker

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
        )

        tracker = GatewayTracker()
        anchored_attestations = []

        def mock_anchor(attestation):
            """Simulate successful anchor and track lifecycle."""
            tracker.mark_pending(attestation)
            tracker.mark_submitted(attestation.event_id, tx_hash="0xdevnet_tx_001")
            anchored_attestations.append(attestation)
            return "0xdevnet_tx_001"

        svc = GatewayVMService(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [_make_raw_log("0xsource_tx_001", 100, 0)],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=mock_anchor,
            is_signer_authorized=lambda: True,
        )

        result = svc.tick()

        # Verify pipeline results
        assert result.events_observed == 1
        assert result.events_accepted == 1
        assert result.events_rejected == 0
        assert result.anchor_failures == 0

        # Verify attestation was created with valid signature
        assert len(anchored_attestations) == 1
        att = anchored_attestations[0]
        assert att.source_chain_id == 84532
        assert att.dest_chain_id == 103115120
        assert att.verify(gateway_kp.vk) is True

        # Verify tracker recorded the lifecycle
        stats = tracker.stats()
        assert stats["submitted"] == 1

        # Verify replay protection prevents re-processing
        result2 = svc.tick()
        assert result2.events_observed == 1
        assert result2.events_rejected == 1
        assert result2.events_accepted == 0


class TestEndToEndMultiEvent:
    """Multiple events in rapid succession."""

    def test_three_events_batch(self, gateway_kp):
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

        logs = [
            _make_raw_log("0xevent_001", 100, 0),
            _make_raw_log("0xevent_002", 101, 0),
            _make_raw_log("0xevent_003", 102, 0),
        ]
        anchor_fn = MagicMock(return_value="0xdevnet_tx")

        svc = GatewayVMService(
            config=config,
            operator_keypair=gateway_kp,
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

        # All three signatures verify
        for call_args in anchor_fn.call_args_list:
            att = call_args[0][0]
            assert att.verify(gateway_kp.vk)


class TestEndToEndAnchorFailureAndRetry:
    """Anchor failure → retry queue → successful retry."""

    def test_failure_and_retry(self, gateway_kp):
        from src.ltp.gateway_vm.config import GatewayVMConfig
        from src.ltp.gateway_vm.service import GatewayVMService

        config = GatewayVMConfig(
            enabled=True,
            source_chain_id=84532,
            source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
            finality_depth=12,
            dest_chain_id=103115120,
            replay_db_path=":memory:",
            max_retries=3,
        )

        call_count = {"n": 0}

        def flaky_anchor(attestation):
            call_count["n"] += 1
            if call_count["n"] <= 1:
                raise RuntimeError("RPC timeout")
            return "0xdevnet_tx"

        svc = GatewayVMService(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [_make_raw_log("0xflaky", 100, 0)],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=flaky_anchor,
            is_signer_authorized=lambda: True,
        )

        # Tick 1: event observed, anchor fails, enters retry queue
        r1 = svc.tick()
        assert r1.events_observed == 1
        assert r1.anchor_failures == 1
        assert svc.retry_queue_size == 1

        # Tick 2: retry succeeds
        r2 = svc.tick()
        assert r2.retries_attempted == 1
        assert svc.retry_queue_size == 0


class TestEndToEndValidationRejections:
    """Events rejected for various validation failures."""

    def test_wrong_contract_rejected(self, gateway_kp):
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

        bad_log = _make_raw_log("0xbad", 100, 0)
        bad_log["address"] = "0xWRONGCONTRACT"

        svc = GatewayVMService(
            config=config,
            operator_keypair=gateway_kp,
            fetch_logs=lambda fb, tb: [bad_log],
            get_source_block_number=lambda: 200,
            get_dest_block_number=lambda: 999,
            anchor_fn=MagicMock(return_value="0x"),
            is_signer_authorized=lambda: True,
        )

        result = svc.tick()
        assert result.events_observed == 1
        assert result.events_rejected == 1
        assert result.events_accepted == 0
