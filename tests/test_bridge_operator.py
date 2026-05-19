"""
Tests for BridgeOperatorService — persistent cross-chain bridge daemon.
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest

from src.ltp.bridge.challenge import ChallengeManager
from src.ltp.bridge.live import LiveBridgeResult
from src.ltp.bridge.message import BridgeMessage
from src.ltp.bridge.operator import BridgeOperatorService, BridgeOperatorTickResult
from src.ltp.commitment import CommitmentNetwork, CommitmentRecord
from src.ltp.keypair import KeyPair, KeyRegistry
from src.ltp.node.config import NodeConfig
from src.ltp.protocol import LTPProtocol

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    return KeyPair.generate("operator")


@pytest.fixture
def network(keypair):
    kr = KeyRegistry()
    kr.register(keypair)
    cn = CommitmentNetwork()
    for i in range(8):
        cn.register_node(f"node-{i}", f"region-{i}", stake=1000.0)
    return cn


@pytest.fixture
def protocol(network, keypair):
    kr = KeyRegistry()
    kr.register(keypair)
    return LTPProtocol(network=network, key_registry=kr)


@pytest.fixture
def mock_bridge():
    """Mock LiveBridge that returns a successful result."""
    bridge = MagicMock()
    bridge.transfer.return_value = LiveBridgeResult(
        message=BridgeMessage(
            msg_type="state_update",
            source_chain="gsx",
            dest_chain="base",
            sender="0xabc",
            recipient="0xdef",
            payload={},
            nonce=1,
        ),
        entity_id="test-entity",
        l1_anchor_tx_hash="0xdeadbeef" * 8,
        is_anchored_on_l1=True,
        l1_entity_state=2,
        source_chain="gsx",
        dest_chain="base",
        l1_block_height=100,
        l1_chain_id=103115120,
        sequence=1,
    )
    return bridge


@pytest.fixture
def mock_bridge_failing():
    """Mock LiveBridge that raises on transfer()."""
    bridge = MagicMock()
    bridge.transfer.side_effect = RuntimeError("RPC timeout")
    return bridge


@pytest.fixture
def operator(network, mock_bridge, keypair):
    return BridgeOperatorService(
        network=network,
        live_bridge=mock_bridge,
        operator_keypair=keypair,
        source_chain="gsx_testnet",
        dest_chain="base_sepolia",
        interval_seconds=1.0,
    )


def _commit_entity(protocol, keypair, content=b"test payload"):
    """Helper: commit an entity via protocol and return entity_id."""
    from src.ltp.entity import Entity

    entity = Entity(content=content, shape="application/octet-stream")
    entity_id, record, cek = protocol.commit(entity, keypair)
    return entity_id


# ---------------------------------------------------------------------------
# tick() with no records
# ---------------------------------------------------------------------------


class TestTickNoRecords:
    def test_tick_empty_network(self, operator):
        result = operator.tick()
        assert result.records_polled == 0
        assert result.records_bridged == 0
        assert result.records_failed == 0

    def test_epoch_increments(self, operator):
        assert operator.epoch == 0
        operator.tick()
        assert operator.epoch == 1
        operator.tick()
        assert operator.epoch == 2


# ---------------------------------------------------------------------------
# tick() bridges new records
# ---------------------------------------------------------------------------


class TestTickBridgesRecords:
    def test_bridges_new_record(self, network, mock_bridge, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
        )
        _commit_entity(protocol, keypair)
        result = op.tick()
        assert result.records_polled == 1
        assert result.records_bridged == 1
        assert mock_bridge.transfer.call_count == 1

    def test_bridges_multiple_records(self, network, mock_bridge, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
        )
        _commit_entity(protocol, keypair, b"payload-1")
        _commit_entity(protocol, keypair, b"payload-2")
        _commit_entity(protocol, keypair, b"payload-3")
        result = op.tick()
        assert result.records_polled == 3
        assert result.records_bridged == 3
        assert mock_bridge.transfer.call_count == 3

    def test_bridge_message_contains_entity_id(self, network, mock_bridge, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
            source_chain="gsx",
            dest_chain="base",
        )
        entity_id = _commit_entity(protocol, keypair)
        op.tick()
        call_args = mock_bridge.transfer.call_args
        msg = call_args[0][0]
        assert isinstance(msg, BridgeMessage)
        assert msg.source_chain == "gsx"
        assert msg.dest_chain == "base"
        assert entity_id in msg.payload.get("entity_id", "")


# ---------------------------------------------------------------------------
# Idempotency — skip already-bridged
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_skips_already_bridged(self, network, mock_bridge, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
        )
        _commit_entity(protocol, keypair)

        r1 = op.tick()
        assert r1.records_bridged == 1

        r2 = op.tick()
        assert r2.records_polled == 0
        assert r2.records_bridged == 0
        assert r2.records_skipped == 0  # Not polled again since index advanced

    def test_bridged_count_tracks(self, network, mock_bridge, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
        )
        _commit_entity(protocol, keypair)
        op.tick()
        assert op.bridged_count == 1


# ---------------------------------------------------------------------------
# Failure handling + retry
# ---------------------------------------------------------------------------


class TestFailureAndRetry:
    def test_handles_transfer_failure(self, network, mock_bridge_failing, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge_failing,
            operator_keypair=keypair,
            max_retries=3,
        )
        _commit_entity(protocol, keypair)
        result = op.tick()
        assert result.records_failed == 1
        assert result.records_bridged == 0
        assert op.retry_queue_size == 1

    def test_retries_on_next_tick(self, network, protocol, keypair):
        bridge = MagicMock()
        # Fail first, succeed on retry
        bridge.transfer.side_effect = [
            RuntimeError("fail"),
            LiveBridgeResult(
                message=BridgeMessage("x", "a", "b", "s", "r", {}, 1),
                entity_id="e",
                l1_anchor_tx_hash="0x1",
                is_anchored_on_l1=True,
                l1_entity_state=2,
                source_chain="a",
                dest_chain="b",
                l1_block_height=1,
                l1_chain_id=1,
                sequence=1,
            ),
        ]

        op = BridgeOperatorService(
            network=network,
            live_bridge=bridge,
            operator_keypair=keypair,
            max_retries=3,
        )
        _commit_entity(protocol, keypair)

        r1 = op.tick()
        assert r1.records_failed == 1
        assert op.retry_queue_size == 1

        r2 = op.tick()
        assert r2.retries_attempted == 1
        assert r2.records_bridged == 1
        assert op.retry_queue_size == 0

    def test_drops_after_max_retries(self, network, mock_bridge_failing, protocol, keypair):
        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge_failing,
            operator_keypair=keypair,
            max_retries=2,
        )
        _commit_entity(protocol, keypair)

        op.tick()  # Attempt 1 (initial)
        assert op.retry_queue_size == 1

        op.tick()  # Attempt 2 (retry #1)
        assert op.retry_queue_size == 1

        op.tick()  # Attempt 3 (retry #2 → exceeds max_retries=2)
        assert op.retry_queue_size == 0  # Dropped


# ---------------------------------------------------------------------------
# Challenge manager integration
# ---------------------------------------------------------------------------


class TestChallengeIntegration:
    def test_ticks_challenge_manager(self, network, mock_bridge, keypair):
        cm = MagicMock(spec=ChallengeManager)
        cm.tick.return_value = []

        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
            challenge_manager=cm,
        )
        op.tick()
        cm.tick.assert_called_once()

    def test_challenge_tick_failure_non_fatal(self, network, mock_bridge, keypair):
        cm = MagicMock(spec=ChallengeManager)
        cm.tick.side_effect = RuntimeError("challenge error")

        op = BridgeOperatorService(
            network=network,
            live_bridge=mock_bridge,
            operator_keypair=keypair,
            challenge_manager=cm,
        )
        result = op.tick()  # Should not raise
        assert result.epoch == 1


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_start_stop(self, operator):
        operator.start()
        assert operator.running is True
        operator.stop()
        assert operator.running is False

    def test_double_start_safe(self, operator):
        operator.start()
        operator.start()
        assert operator.running is True
        operator.stop()

    def test_stop_without_start_safe(self, operator):
        operator.stop()  # Should not crash


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults(self):
        config = NodeConfig()
        assert config.bridge_operator_enabled is False
        assert config.bridge_operator_interval_seconds == 30.0
        assert config.bridge_operator_direction == "gsx_to_base"
        assert config.bridge_operator_max_retries == 3
        assert config.bridge_operator_challenge_period == 3600.0
        assert config.bridge_operator_zk_mode == "simulated"

    def test_from_env(self):
        env = {
            "ETP_BRIDGE_OPERATOR_ENABLED": "true",
            "ETP_BRIDGE_OPERATOR_INTERVAL": "15.0",
            "ETP_BRIDGE_OPERATOR_DIRECTION": "base_to_gsx",
            "ETP_BRIDGE_OPERATOR_MAX_RETRIES": "5",
            "ETP_BRIDGE_OPERATOR_CHALLENGE_PERIOD": "7200.0",
            "ETP_BRIDGE_OPERATOR_ZK_MODE": "stark",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            config = NodeConfig.from_env()
            assert config.bridge_operator_enabled is True
            assert config.bridge_operator_interval_seconds == 15.0
            assert config.bridge_operator_direction == "base_to_gsx"
            assert config.bridge_operator_max_retries == 5
            assert config.bridge_operator_challenge_period == 7200.0
            assert config.bridge_operator_zk_mode == "stark"
        finally:
            for k in env:
                os.environ.pop(k, None)
