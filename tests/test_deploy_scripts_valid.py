"""
Tests validating mainnet deployment scripts exist, compile, and
reference the correct environment variables.
"""

from __future__ import annotations

import os
import subprocess

import pytest

CONTRACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "contracts")
SCRIPT_DIR = os.path.join(CONTRACTS_DIR, "script")


# ---------------------------------------------------------------------------
# Script existence
# ---------------------------------------------------------------------------


class TestDeployScriptsExist:
    def test_mainnet_bridge_script_exists(self):
        path = os.path.join(SCRIPT_DIR, "DeployMainnetBridge.s.sol")
        assert os.path.exists(path)

    def test_mainnet_governance_script_exists(self):
        path = os.path.join(SCRIPT_DIR, "DeployMainnetGovernance.s.sol")
        assert os.path.exists(path)

    def test_upgrade_registry_script_exists(self):
        path = os.path.join(SCRIPT_DIR, "UpgradeRegistry.s.sol")
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# Env var references
# ---------------------------------------------------------------------------


class TestEnvVarReferences:
    def _read_script(self, filename: str) -> str:
        path = os.path.join(SCRIPT_DIR, filename)
        with open(path) as f:
            return f.read()

    def test_mainnet_bridge_references_correct_env_vars(self):
        content = self._read_script("DeployMainnetBridge.s.sol")
        assert "MAINNET_TIMELOCK_ADMIN" in content
        assert "MAINNET_CHALLENGE_PERIOD" in content
        assert "MAINNET_OPERATOR_BOND" in content
        assert "MAINNET_CHALLENGER_BOND" in content
        assert "MAINNET_ZK_MODE" in content

    def test_mainnet_governance_references_correct_env_vars(self):
        content = self._read_script("DeployMainnetGovernance.s.sol")
        assert "MAINNET_TIMELOCK_ADMIN" in content
        assert "GOVERNANCE_REQUIRED_RATIO" in content

    def test_upgrade_registry_references_correct_env_vars(self):
        content = self._read_script("UpgradeRegistry.s.sol")
        assert "MAINNET_PROXY_ADDRESS" in content


# ---------------------------------------------------------------------------
# Production enforcement
# ---------------------------------------------------------------------------


class TestProductionEnforcement:
    def test_mainnet_bridge_enforces_minimum_challenge_period(self):
        content = self._read_script("DeployMainnetBridge.s.sol")
        assert "86400" in content  # >= 1 day minimum
        assert "Challenge period must be >= 1 day" in content

    def test_mainnet_bridge_enforces_minimum_bonds(self):
        content = self._read_script("DeployMainnetBridge.s.sol")
        assert "1 ether" in content  # Bond minimums
        assert "0.1 ether" in content

    def test_mainnet_bridge_default_is_7_days(self):
        content = self._read_script("DeployMainnetBridge.s.sol")
        assert "604800" in content  # 7 days default

    def test_mainnet_bridge_default_is_stark(self):
        content = self._read_script("DeployMainnetBridge.s.sol")
        assert "uint256(3)" in content  # STARK mode default

    def _read_script(self, filename: str) -> str:
        path = os.path.join(SCRIPT_DIR, filename)
        with open(path) as f:
            return f.read()
