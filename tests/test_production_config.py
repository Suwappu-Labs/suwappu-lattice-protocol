"""
Tests for production (mainnet) configuration profile.

Validates that config/mainnet.toml parses correctly and has all
security hardening flags enabled. This is a turnkey validation —
the config template is ready for the node team to fill in
deployment-specific values (RPC URLs, keys, addresses).
"""

from __future__ import annotations

import os

import pytest

from src.ltp.node.config import NodeConfig

MAINNET_TOML = os.path.join(os.path.dirname(__file__), "..", "config", "mainnet.toml")


@pytest.fixture
def mainnet_config():
    """Load the mainnet config template."""
    return NodeConfig.from_toml(MAINNET_TOML)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestMainnetConfigParsing:
    def test_toml_parses_without_error(self, mainnet_config):
        """mainnet.toml is valid TOML and produces a NodeConfig."""
        assert isinstance(mainnet_config, NodeConfig)

    def test_all_fields_populated(self, mainnet_config):
        """No critical fields are left at their default testnet values."""
        # These should be explicitly set in mainnet.toml (even if to REPLACE_*)
        assert mainnet_config.require_real_crypto is True
        assert mainnet_config.gateway_enabled is True
        assert mainnet_config.tls_enabled is True
        assert mainnet_config.gossip_enabled is True
        assert mainnet_config.anchor_enabled is True
        assert mainnet_config.bridge_operator_enabled is True


# ---------------------------------------------------------------------------
# Security Hardening Flags
# ---------------------------------------------------------------------------


class TestSecurityHardening:
    def test_require_real_crypto(self, mainnet_config):
        """PoC simulation fallback must be blocked."""
        assert mainnet_config.require_real_crypto is True

    def test_jwt_auth_enabled(self, mainnet_config):
        """REST endpoints must require JWT authentication."""
        assert mainnet_config.gateway_jwt_enabled is True

    def test_tls_enabled(self, mainnet_config):
        """mTLS must be enabled on gRPC channels."""
        assert mainnet_config.tls_enabled is True
        assert mainnet_config.tls_require_client_cert is True

    def test_kms_is_aws(self, mainnet_config):
        """Key management must use AWS KMS (FIPS 140-3 Level 3)."""
        assert mainnet_config.kms_backend == "aws"

    def test_zk_mode_is_stark(self, mainnet_config):
        """Bridge must use STARK (post-quantum hash-only proofs)."""
        assert mainnet_config.bridge_operator_zk_mode == "stark"

    def test_challenge_period_7_days(self, mainnet_config):
        """Challenge window must be 7 days (604800 seconds)."""
        assert mainnet_config.bridge_operator_challenge_period == 604800.0

    def test_storage_is_persistent(self, mainnet_config):
        """Storage must NOT be in-memory for production."""
        assert mainnet_config.storage_backend != "memory"

    def test_diagnostics_public_mode(self, mainnet_config):
        """Public-facing diagnostics must redact sensitive data."""
        assert mainnet_config.diagnostics_public_mode is True

    def test_observability_enabled(self, mainnet_config):
        """Observability must be enabled for production metrics."""
        assert mainnet_config.observability_enabled is True

    def test_anchor_enabled(self, mainnet_config):
        """On-chain anchoring must be enabled."""
        assert mainnet_config.anchor_enabled is True

    def test_gossip_enabled(self, mainnet_config):
        """Gossip peer discovery must be enabled."""
        assert mainnet_config.gossip_enabled is True

    def test_bridge_operator_enabled(self, mainnet_config):
        """Bridge operator must be enabled."""
        assert mainnet_config.bridge_operator_enabled is True

    def test_gateway_enabled(self, mainnet_config):
        """Gateway must be enabled."""
        assert mainnet_config.gateway_enabled is True


# ---------------------------------------------------------------------------
# Operational Parameters
# ---------------------------------------------------------------------------


class TestOperationalParams:
    def test_confirmation_depth_production(self, mainnet_config):
        """Anchor confirmation depth should be >= 6 for mainnet."""
        assert mainnet_config.anchor_confirmation_depth >= 6

    def test_finality_depth_production(self, mainnet_config):
        """Anchor finality depth should be >= 2 for mainnet."""
        assert mainnet_config.anchor_finality_depth >= 2

    def test_rate_limit_stricter(self, mainnet_config):
        """Rate limit should be stricter than testnet default (60)."""
        assert mainnet_config.gateway_rate_limit_per_minute <= 30

    def test_gossip_mesh_larger(self, mainnet_config):
        """Gossip max peers should be >= 50 for production mesh."""
        assert mainnet_config.gossip_max_peers >= 50

    def test_log_level_production(self, mainnet_config):
        """Log level should be WARN or ERROR for production."""
        assert mainnet_config.log_level in ("WARN", "WARNING", "ERROR")
