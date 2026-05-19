"""
Tests for ChainConfig dataclass and create_anchor_client factory.

Multi-chain configuration foundation.
"""

import pytest

from src.ltp.anchor.chain_config import ChainConfig, create_anchor_client

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID = {
    "chain_id": 84532,
    "label": "base_sepolia",
    "rpc_url": "https://sepolia.base.org",
    "registry_address": "0x" + "aB" * 20,
    "operator_key": "0xdeadbeef",
}


# ---------------------------------------------------------------------------
# from_dict
# ---------------------------------------------------------------------------


class TestChainConfigFromDict:
    def test_from_dict(self):
        """Round-trip: from_dict produces correct ChainConfig."""
        cfg = ChainConfig.from_dict(_VALID)
        assert cfg.chain_id == 84532
        assert cfg.label == "base_sepolia"
        assert cfg.rpc_url == "https://sepolia.base.org"
        assert cfg.registry_address == "0x" + "aB" * 20
        assert cfg.operator_key == "0xdeadbeef"
        # Defaults
        assert cfg.confirmation_depth == 3
        assert cfg.finality_depth == 1
        assert cfg.max_tps == 10.0
        assert cfg.burst == 20
        assert cfg.failure_threshold == 5
        assert cfg.cooldown_seconds == 30.0
        assert cfg.tx_timeout == 120
        assert cfg.max_rpc_retries == 5

    def test_from_dict_missing_chain_id(self):
        data = {k: v for k, v in _VALID.items() if k != "chain_id"}
        with pytest.raises(ValueError, match="chain_id is required"):
            ChainConfig.from_dict(data)

    def test_from_dict_zero_chain_id(self):
        data = {**_VALID, "chain_id": 0}
        with pytest.raises(ValueError, match="chain_id must be a positive integer"):
            ChainConfig.from_dict(data)

    def test_from_dict_negative_chain_id(self):
        data = {**_VALID, "chain_id": -1}
        with pytest.raises(ValueError, match="chain_id must be a positive integer"):
            ChainConfig.from_dict(data)

    def test_from_dict_missing_rpc_url(self):
        data = {**_VALID, "rpc_url": ""}
        with pytest.raises(ValueError, match="rpc_url is required"):
            ChainConfig.from_dict(data)

    def test_from_dict_empty_rpc_url(self):
        data = {**_VALID}
        del data["rpc_url"]
        with pytest.raises(ValueError, match="rpc_url is required"):
            ChainConfig.from_dict(data)

    def test_from_dict_invalid_registry_address(self):
        data = {**_VALID, "registry_address": "not_an_address"}
        with pytest.raises(ValueError, match="invalid registry_address"):
            ChainConfig.from_dict(data)

    def test_from_dict_short_registry_address(self):
        data = {**_VALID, "registry_address": "0x1234"}
        with pytest.raises(ValueError, match="invalid registry_address"):
            ChainConfig.from_dict(data)


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------


class TestChainConfigFromEnv:
    def test_from_env(self, monkeypatch):
        prefix = "TEST_CHAIN_"
        monkeypatch.setenv(f"{prefix}CHAIN_ID", "84532")
        monkeypatch.setenv(f"{prefix}LABEL", "base_sepolia")
        monkeypatch.setenv(f"{prefix}RPC_URL", "https://sepolia.base.org")
        monkeypatch.setenv(f"{prefix}REGISTRY_ADDRESS", "0x" + "aB" * 20)
        monkeypatch.setenv(f"{prefix}OPERATOR_KEY", "0xkey")
        monkeypatch.setenv(f"{prefix}CONFIRMATION_DEPTH", "6")

        cfg = ChainConfig.from_env(prefix)
        assert cfg.chain_id == 84532
        assert cfg.rpc_url == "https://sepolia.base.org"
        assert cfg.confirmation_depth == 6
        assert cfg.finality_depth == 1  # default

    def test_from_env_missing_required(self, monkeypatch):
        # No env vars set at all for the prefix
        with pytest.raises(EnvironmentError, match="Missing required env var"):
            ChainConfig.from_env("MISSING_")


# ---------------------------------------------------------------------------
# Frozen / repr
# ---------------------------------------------------------------------------


class TestChainConfigProperties:
    def test_frozen(self):
        cfg = ChainConfig.from_dict(_VALID)
        with pytest.raises(AttributeError):
            cfg.chain_id = 999  # type: ignore[misc]

    def test_repr_redacts_key(self):
        cfg = ChainConfig.from_dict(_VALID)
        r = repr(cfg)
        assert "0xdeadbeef" not in r
        assert "REDACTED" in r
        # Other fields present
        assert "base_sepolia" in r
        assert "84532" in r

    def test_defaults(self):
        cfg = ChainConfig.from_dict(_VALID)
        assert cfg.max_tps == 10.0
        assert cfg.burst == 20
        assert cfg.failure_threshold == 5
        assert cfg.cooldown_seconds == 30.0
        assert cfg.tx_timeout == 120
        assert cfg.max_rpc_retries == 5


# ---------------------------------------------------------------------------
# create_anchor_client factory
# ---------------------------------------------------------------------------


class TestCreateAnchorClient:
    def test_create_anchor_client(self, monkeypatch):
        """Factory produces an AnchorClient with correct chain params (mock web3)."""
        # Mock web3 import to avoid dependency
        import types

        mock_web3_mod = types.ModuleType("web3")

        class _MockProvider:
            def __init__(self, url):
                self.url = url

        class _MockEth:
            def __init__(self):
                pass

            @property
            def account(self):
                return self

            def from_key(self, key):
                class _Acct:
                    address = "0x" + "00" * 20

                return _Acct()

            def contract(self, address, abi):
                return None

        class _MockW3:
            HTTPProvider = _MockProvider

            def __init__(self, provider):
                self.eth = _MockEth()
                self.provider = provider

            @staticmethod
            def to_checksum_address(addr):
                return addr

        mock_web3_mod.Web3 = _MockW3  # type: ignore[attr-defined]

        import sys

        monkeypatch.setitem(sys.modules, "web3", mock_web3_mod)

        cfg = ChainConfig.from_dict(_VALID)
        client = create_anchor_client(cfg)
        assert client is not None
        assert client._chain_id == 84532
        assert client._tx_timeout == 120
