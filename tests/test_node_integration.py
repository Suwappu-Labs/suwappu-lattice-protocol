"""
Tests for ETPNode full integration: gateway, gossip, bridge operator,
observability conditional startup and shutdown.
"""

from __future__ import annotations

import os

import pytest

from src.ltp.node.config import NodeConfig
from src.ltp.node.main import ETPNode

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def base_config():
    """Minimal config with everything disabled for fast startup."""
    return NodeConfig(
        node_id="test-node",
        region="test",
        listen_port=0,  # Ephemeral
        rest_port=0,  # Ephemeral
        diagnostics_port=0,  # Ephemeral — avoid port collisions
        require_real_crypto=False,
        storage_backend="memory",
        seed_peers=[],
        # All optional components disabled
        gateway_enabled=False,
        gossip_enabled=False,
        bridge_operator_enabled=False,
        anchor_enabled=False,
        observability_enabled=True,
    )


# ---------------------------------------------------------------------------
# Legacy mode (all new components disabled)
# ---------------------------------------------------------------------------


class TestLegacyMode:
    def test_legacy_startup_shutdown(self, base_config):
        """Node starts and stops cleanly with only legacy components."""
        node = ETPNode(base_config)
        node.start()
        assert node._running is True
        assert node._health_server is not None
        assert node._grpc_server is not None
        assert node._gateway_server is None
        assert node._gossip_protocol is None
        assert node._bridge_operator is None
        node.stop()
        assert node._running is False


# ---------------------------------------------------------------------------
# Gateway integration
# ---------------------------------------------------------------------------


class TestGatewayIntegration:
    def test_gateway_enabled_starts_server(self, base_config):
        base_config.gateway_enabled = True
        base_config.gateway_port = 0  # Ephemeral
        node = ETPNode(base_config)
        node.start()
        try:
            assert node._gateway_server is not None
            assert node._gateway_server.port > 0
        finally:
            node.stop()

    def test_gateway_disabled_no_server(self, base_config):
        base_config.gateway_enabled = False
        node = ETPNode(base_config)
        node.start()
        try:
            assert node._gateway_server is None
        finally:
            node.stop()


# ---------------------------------------------------------------------------
# Gossip integration
# ---------------------------------------------------------------------------


class TestGossipIntegration:
    def test_gossip_enabled_starts_protocol(self, base_config):
        base_config.gossip_enabled = True
        node = ETPNode(base_config)
        node.start()
        try:
            assert node._gossip_protocol is not None
            assert node._gossip_protocol.running is True
        finally:
            node.stop()

    def test_gossip_disabled_no_protocol(self, base_config):
        base_config.gossip_enabled = False
        node = ETPNode(base_config)
        node.start()
        try:
            assert node._gossip_protocol is None
        finally:
            node.stop()

    def test_gossip_stops_cleanly(self, base_config):
        base_config.gossip_enabled = True
        node = ETPNode(base_config)
        node.start()
        assert node._gossip_protocol.running is True
        node.stop()
        assert node._gossip_protocol is None


# ---------------------------------------------------------------------------
# Observability integration
# ---------------------------------------------------------------------------


class TestObservabilityIntegration:
    def test_observability_initialized_by_default(self, base_config):
        """observability_enabled=True by default."""
        node = ETPNode(base_config)
        node.start()
        try:
            assert node._observability is not None
        finally:
            node.stop()

    def test_observability_disabled(self, base_config):
        base_config.observability_enabled = False
        node = ETPNode(base_config)
        node.start()
        try:
            assert node._observability is None
        finally:
            node.stop()


# ---------------------------------------------------------------------------
# Shutdown order
# ---------------------------------------------------------------------------


class TestShutdownOrder:
    def test_all_components_stop(self, base_config):
        """Enable everything and verify clean shutdown."""
        base_config.gateway_enabled = True
        base_config.gateway_port = 0
        base_config.gossip_enabled = True
        node = ETPNode(base_config)
        node.start()
        assert node._gateway_server is not None
        assert node._gossip_protocol is not None
        assert node._observability is not None
        node.stop()
        assert node._gateway_server is None
        assert node._gossip_protocol is None
        assert node._running is False

    def test_double_stop_safe(self, base_config):
        node = ETPNode(base_config)
        node.start()
        node.stop()
        node.stop()  # Should not crash


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class TestNodeConfigIntegration:
    def test_observability_default_on(self):
        config = NodeConfig()
        assert config.observability_enabled is True
