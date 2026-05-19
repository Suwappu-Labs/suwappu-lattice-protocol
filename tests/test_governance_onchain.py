"""
Tests for on-chain governance client and ETPGovernance contract integration.

Tests the Python OnChainGovernanceClient against the Solidity contract
patterns without requiring a live chain (unit tests for client structure,
integration tests require anvil).
"""

from __future__ import annotations

import pytest

from src.ltp.governance_client import (
    _PHASE_NAMES,
    PHASE_BOOTSTRAP,
    PHASE_GROWTH,
    PHASE_MATURITY,
    OnChainGovernanceClient,
    _keccak256,
    _make_transition_key,
)

# ---------------------------------------------------------------------------
# Phase Constants
# ---------------------------------------------------------------------------


class TestPhaseConstants:
    def test_bootstrap_hash(self):
        expected = _keccak256(b"bootstrap")
        assert PHASE_BOOTSTRAP == expected
        assert len(PHASE_BOOTSTRAP) == 32

    def test_growth_hash(self):
        expected = _keccak256(b"growth")
        assert PHASE_GROWTH == expected

    def test_maturity_hash(self):
        expected = _keccak256(b"maturity")
        assert PHASE_MATURITY == expected

    def test_phase_names_complete(self):
        assert _PHASE_NAMES[PHASE_BOOTSTRAP] == "bootstrap"
        assert _PHASE_NAMES[PHASE_GROWTH] == "growth"
        assert _PHASE_NAMES[PHASE_MATURITY] == "maturity"

    def test_phases_are_distinct(self):
        assert PHASE_BOOTSTRAP != PHASE_GROWTH
        assert PHASE_GROWTH != PHASE_MATURITY
        assert PHASE_BOOTSTRAP != PHASE_MATURITY


# ---------------------------------------------------------------------------
# Transition Key
# ---------------------------------------------------------------------------


class TestTransitionKey:
    def test_key_is_32_bytes(self):
        key = _make_transition_key("bootstrap", "growth")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_different_transitions_different_keys(self):
        k1 = _make_transition_key("bootstrap", "growth")
        k2 = _make_transition_key("growth", "maturity")
        assert k1 != k2

    def test_same_transition_same_key(self):
        k1 = _make_transition_key("bootstrap", "growth")
        k2 = _make_transition_key("bootstrap", "growth")
        assert k1 == k2

    def test_reverse_transition_different_key(self):
        k1 = _make_transition_key("bootstrap", "growth")
        k2 = _make_transition_key("growth", "bootstrap")
        assert k1 != k2


# ---------------------------------------------------------------------------
# Client Construction
# ---------------------------------------------------------------------------


class TestClientConstruction:
    def test_read_only_client(self):
        """Client without operator key should work for view calls."""
        # This will fail to connect but should construct fine
        client = OnChainGovernanceClient(
            rpc_url="http://localhost:8545",
            contract_address="0x0000000000000000000000000000000000000001",
        )
        assert client._account is None

    def test_write_client(self):
        """Client with operator key should have account set."""
        client = OnChainGovernanceClient(
            rpc_url="http://localhost:8545",
            contract_address="0x0000000000000000000000000000000000000001",
            operator_key="0x" + "ab" * 32,
        )
        assert client._account is not None

    def test_write_without_key_raises(self):
        """Write operations without key should raise."""
        client = OnChainGovernanceClient(
            rpc_url="http://localhost:8545",
            contract_address="0x0000000000000000000000000000000000000001",
        )
        with pytest.raises(ValueError, match="No operator key"):
            client.cast_vote_on_chain(b"\x00" * 32, b"\x00" * 32, 1, 9999999999)

    def test_execute_without_key_raises(self):
        client = OnChainGovernanceClient(
            rpc_url="http://localhost:8545",
            contract_address="0x0000000000000000000000000000000000000001",
        )
        with pytest.raises(ValueError, match="No operator key"):
            client.execute_transition_on_chain("bootstrap", "growth")
