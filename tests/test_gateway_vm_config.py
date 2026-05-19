"""Tests for GatewayVMConfig."""

import os

import pytest


class TestGatewayVMConfigDefaults:
    def test_defaults(self):
        from src.ltp.gateway_vm.config import GatewayVMConfig

        cfg = GatewayVMConfig()
        assert cfg.enabled is False
        assert cfg.mode == "poa-attestation"
        assert cfg.source_chain_id == 84532
        assert cfg.source_rpc_url == ""
        assert cfg.source_bridge_contract == ""
        assert cfg.finality_depth == 12
        assert cfg.poll_interval_seconds == 5.0
        assert cfg.dest_chain_id == 103115120
        assert cfg.dest_rpc_url == ""
        assert cfg.dest_registry_address == ""
        assert cfg.replay_db_path == ":memory:"
        assert cfg.max_retries == 5
        assert cfg.retry_interval_seconds == 30.0
        assert cfg.challenge_mode == "optimistic"
        assert cfg.challenge_period_seconds == 3600.0
        assert cfg.metrics_port == 9090
        assert cfg.log_level == "info"
        assert cfg.gateway_id == "gateway-vm-0"


class TestGatewayVMConfigFromEnv:
    def test_from_env_overrides(self):
        from src.ltp.gateway_vm.config import GatewayVMConfig

        env = {
            "ETP_GATEWAY_VM_ENABLED": "true",
            "ETP_GATEWAY_VM_SOURCE_CHAIN_ID": "1",
            "ETP_GATEWAY_VM_SOURCE_RPC_URL": "https://rpc.example.com",
            "ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT": "0xabc123",
            "ETP_GATEWAY_VM_FINALITY_DEPTH": "20",
            "ETP_GATEWAY_VM_POLL_INTERVAL": "10",
            "ETP_GATEWAY_VM_DEST_CHAIN_ID": "42",
            "ETP_GATEWAY_VM_DEST_RPC_URL": "https://devnet.example.com",
            "ETP_GATEWAY_VM_DEST_REGISTRY": "0xdef456",
            "ETP_GATEWAY_VM_REPLAY_DB_PATH": "/tmp/replay.db",
            "ETP_GATEWAY_VM_MAX_RETRIES": "3",
            "ETP_GATEWAY_VM_CHALLENGE_MODE": "zk",
            "ETP_GATEWAY_VM_GATEWAY_ID": "gw-1",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            cfg = GatewayVMConfig.from_env()
            assert cfg.enabled is True
            assert cfg.source_chain_id == 1
            assert cfg.source_rpc_url == "https://rpc.example.com"
            assert cfg.source_bridge_contract == "0xabc123"
            assert cfg.finality_depth == 20
            assert cfg.poll_interval_seconds == 10.0
            assert cfg.dest_chain_id == 42
            assert cfg.dest_rpc_url == "https://devnet.example.com"
            assert cfg.dest_registry_address == "0xdef456"
            assert cfg.replay_db_path == "/tmp/replay.db"
            assert cfg.max_retries == 3
            assert cfg.challenge_mode == "zk"
            assert cfg.gateway_id == "gw-1"
        finally:
            for k in env:
                os.environ.pop(k, None)

    def test_from_env_defaults_when_unset(self):
        from src.ltp.gateway_vm.config import GatewayVMConfig

        # Clear any gateway env vars
        for k in list(os.environ):
            if k.startswith("ETP_GATEWAY_VM_"):
                del os.environ[k]

        cfg = GatewayVMConfig.from_env()
        assert cfg.enabled is False
        assert cfg.source_chain_id == 84532
