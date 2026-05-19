"""
Tests for KMS + Governance integration into ETPNode.
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock

import pytest

from src.ltp.cloud.kms import InMemoryKMSBackend
from src.ltp.governance import TransitionVote, TransitionVoteManager, create_transition_vote
from src.ltp.keypair import KeyPair
from src.ltp.node.config import NodeConfig
from src.ltp.node.main import ETPNode

# ---------------------------------------------------------------------------
# KMS Factory
# ---------------------------------------------------------------------------


class TestKMSFactory:
    def test_memory_backend_from_config(self):
        """kms_backend="memory" creates InMemoryKMSBackend."""
        config = NodeConfig(
            node_id="kms-test",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            kms_backend="memory",
        )
        node = ETPNode(config)
        node.start()
        try:
            assert node._kms_backend is not None
            assert isinstance(node._kms_backend, InMemoryKMSBackend)
        finally:
            node.stop()

    def test_empty_backend_is_none(self):
        """kms_backend="" results in no KMS."""
        config = NodeConfig(
            node_id="kms-none",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            kms_backend="",
        )
        node = ETPNode(config)
        node.start()
        try:
            assert node._kms_backend is None
        finally:
            node.stop()

    def test_aws_without_arn_is_none(self):
        """kms_backend="aws" without kms_key_arn skips initialization."""
        config = NodeConfig(
            node_id="kms-aws-no-arn",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            kms_backend="aws",
            kms_key_arn="",
        )
        node = ETPNode(config)
        node.start()
        try:
            assert node._kms_backend is None
        finally:
            node.stop()


# ---------------------------------------------------------------------------
# TransitionVoteManager with on_chain_client
# ---------------------------------------------------------------------------


class TestTransitionVoteManagerOnChain:
    def test_accepts_on_chain_client(self):
        """Constructor accepts on_chain_client parameter."""
        mock_client = MagicMock()
        mgr = TransitionVoteManager(on_chain_client=mock_client)
        assert mgr._on_chain_client is mock_client

    def test_cast_vote_calls_on_chain(self):
        """When on_chain_client is set, cast_vote syncs on-chain."""
        mock_client = MagicMock()
        mgr = TransitionVoteManager(on_chain_client=mock_client)

        kp = KeyPair.generate("voter-1")
        mgr.register_operator("op-1", "vkhash-1")

        vote = TransitionVote(
            voter_vk_hash="vkhash-1",
            from_phase="bootstrap",
            to_phase="growth",
            signature=b"\x00" * 64,
            timestamp=time.time(),
        )
        mgr.cast_vote("bootstrap->growth", vote)

        mock_client.cast_vote_on_chain.assert_called_once()

    def test_cast_vote_works_without_on_chain(self):
        """Without on_chain_client, cast_vote works normally."""
        mgr = TransitionVoteManager()

        mgr.register_operator("op-1", "vkhash-1")
        vote = TransitionVote(
            voter_vk_hash="vkhash-1",
            from_phase="bootstrap",
            to_phase="growth",
            signature=b"\x00" * 64,
            timestamp=time.time(),
        )
        tally = mgr.cast_vote("bootstrap->growth", vote)
        assert tally["votes"] == 1

    def test_on_chain_failure_is_nonfatal(self):
        """If on_chain_client raises, cast_vote still succeeds locally."""
        mock_client = MagicMock()
        mock_client.cast_vote_on_chain.side_effect = RuntimeError("RPC timeout")

        mgr = TransitionVoteManager(on_chain_client=mock_client)
        mgr.register_operator("op-1", "vkhash-1")

        vote = TransitionVote(
            voter_vk_hash="vkhash-1",
            from_phase="bootstrap",
            to_phase="growth",
            signature=b"\x00" * 64,
            timestamp=time.time(),
        )
        tally = mgr.cast_vote("bootstrap->growth", vote)
        assert tally["votes"] == 1  # Local vote succeeded despite on-chain failure


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class TestGovernanceConfig:
    def test_defaults(self):
        config = NodeConfig()
        assert config.governance_contract_address == ""
        assert config.governance_chain_rpc == ""
        assert config.governance_chain_id == 0
        assert config.kms_backend == "memory"
        assert config.kms_region == ""
        assert config.kms_key_arn == ""

    def test_governance_from_env(self):
        env = {
            "ETP_GOVERNANCE_CONTRACT": "0x1234567890abcdef1234567890abcdef12345678",
            "ETP_GOVERNANCE_RPC": "http://localhost:8545",
            "ETP_GOVERNANCE_CHAIN_ID": "103115120",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            config = NodeConfig.from_env()
            assert (
                config.governance_contract_address == "0x1234567890abcdef1234567890abcdef12345678"
            )
            assert config.governance_chain_rpc == "http://localhost:8545"
            assert config.governance_chain_id == 103115120
        finally:
            for k in env:
                os.environ.pop(k, None)

    def test_kms_from_env(self):
        env = {
            "ETP_KMS_BACKEND": "aws",
            "ETP_KMS_REGION": "us-east-1",
            "ETP_KMS_KEY_ARN": "arn:aws:kms:us-east-1:123456:key/abc",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            config = NodeConfig.from_env()
            assert config.kms_backend == "aws"
            assert config.kms_region == "us-east-1"
            assert config.kms_key_arn == "arn:aws:kms:us-east-1:123456:key/abc"
        finally:
            for k in env:
                os.environ.pop(k, None)
