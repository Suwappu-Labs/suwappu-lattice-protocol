"""
Tests for built-in chain profiles (Ethereum mainnet <> Hyperliquid HyperEVM).

Pins the numeric chain IDs, finality postures, and the ChainProfile →
ChainConfig merge used by the Hyperliquid corridor.
"""

import pytest

from src.ltp.anchor.chain_profiles import (
    CHAIN_PROFILES,
    ETHEREUM_MAINNET,
    HYPEREVM_MAINNET,
    HYPEREVM_TESTNET,
    ChainProfile,
    FinalityModel,
    get_chain_profile,
    profile_for_chain_id,
)

# ---------------------------------------------------------------------------
# Registry contents
# ---------------------------------------------------------------------------


class TestProfileRegistry:
    def test_chain_ids_pinned(self):
        """The numeric chain IDs are protocol facts — pin them."""
        expected = {
            "ethereum_mainnet": 1,
            "ethereum_sepolia": 11_155_111,
            "hyperevm_mainnet": 999,
            "hyperevm_testnet": 998,
            "base_sepolia": 84_532,
            "suwappu_testnet": 103_115_120,
        }
        assert {label: p.chain_id for label, p in CHAIN_PROFILES.items()} == expected

    def test_registry_keys_match_labels(self):
        for label, profile in CHAIN_PROFILES.items():
            assert profile.label == label

    def test_chain_ids_unique(self):
        ids = [p.chain_id for p in CHAIN_PROFILES.values()]
        assert len(ids) == len(set(ids))

    def test_all_chain_ids_fit_u32(self):
        """The corridor wire format keys chains by u32."""
        for profile in CHAIN_PROFILES.values():
            assert 0 < profile.chain_id < (1 << 32)

    def test_get_chain_profile(self):
        assert get_chain_profile("hyperevm_mainnet") is HYPEREVM_MAINNET

    def test_get_chain_profile_unknown(self):
        with pytest.raises(KeyError, match="unknown chain profile"):
            get_chain_profile("dogechain")

    def test_profile_for_chain_id(self):
        assert profile_for_chain_id(1) is ETHEREUM_MAINNET
        assert profile_for_chain_id(999) is HYPEREVM_MAINNET
        assert profile_for_chain_id(998) is HYPEREVM_TESTNET

    def test_profile_for_chain_id_unknown(self):
        with pytest.raises(KeyError, match="unknown chain_id"):
            profile_for_chain_id(31337)


# ---------------------------------------------------------------------------
# Finality postures
# ---------------------------------------------------------------------------


class TestFinalityPostures:
    def test_ethereum_is_probabilistic_two_epochs(self):
        assert ETHEREUM_MAINNET.finality_model is FinalityModel.PROBABILISTIC
        assert ETHEREUM_MAINNET.recommended_confirmation_depth == 32  # ~1 epoch
        assert ETHEREUM_MAINNET.recommended_finality_depth == 64  # 2 epochs

    def test_hyperevm_is_single_slot_depth_one(self):
        """HyperBFT commit is final — depth 1 on both HyperEVM networks."""
        for profile in (HYPEREVM_MAINNET, HYPEREVM_TESTNET):
            assert profile.finality_model is FinalityModel.SINGLE_SLOT
            assert profile.recommended_confirmation_depth == 1
            assert profile.recommended_finality_depth == 1

    def test_hyperevm_native_symbol(self):
        assert HYPEREVM_MAINNET.native_symbol == "HYPE"

    def test_testnet_flags(self):
        assert not ETHEREUM_MAINNET.testnet
        assert not HYPEREVM_MAINNET.testnet
        assert HYPEREVM_TESTNET.testnet


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _profile(**overrides):
    params = {
        "label": "test_chain",
        "chain_id": 12345,
        "display_name": "Test Chain",
        "native_symbol": "TST",
        "finality_model": FinalityModel.SINGLE_SLOT,
        "block_time_seconds": 1.0,
        "recommended_confirmation_depth": 1,
        "recommended_finality_depth": 1,
    }
    params.update(overrides)
    return ChainProfile(**params)


class TestProfileValidation:
    def test_valid(self):
        assert _profile().chain_id == 12345

    def test_rejects_zero_chain_id(self):
        with pytest.raises(ValueError, match="chain_id must be a positive integer"):
            _profile(chain_id=0)

    def test_rejects_chain_id_over_u32(self):
        with pytest.raises(ValueError, match="exceeds u32"):
            _profile(chain_id=1 << 32)

    def test_accepts_max_u32(self):
        assert _profile(chain_id=(1 << 32) - 1).chain_id == (1 << 32) - 1

    def test_rejects_empty_label(self):
        with pytest.raises(ValueError, match="label is required"):
            _profile(label="")

    def test_rejects_zero_block_time(self):
        with pytest.raises(ValueError, match="block_time_seconds must be positive"):
            _profile(block_time_seconds=0)

    def test_rejects_zero_confirmation_depth(self):
        with pytest.raises(ValueError, match="recommended_confirmation_depth"):
            _profile(recommended_confirmation_depth=0)

    def test_rejects_finality_below_confirmation(self):
        with pytest.raises(ValueError, match="recommended_finality_depth"):
            _profile(recommended_confirmation_depth=3, recommended_finality_depth=2)

    def test_frozen(self):
        with pytest.raises(AttributeError):
            ETHEREUM_MAINNET.chain_id = 2  # type: ignore[misc]


# ---------------------------------------------------------------------------
# to_chain_config merge
# ---------------------------------------------------------------------------


class TestToChainConfig:
    _REGISTRY = "0x" + "aB" * 20

    def test_merge_defaults_from_profile(self):
        cfg = HYPEREVM_MAINNET.to_chain_config(
            rpc_url="https://rpc.hyperliquid.xyz/evm",
            registry_address=self._REGISTRY,
            operator_key="0xdeadbeef",
        )
        assert cfg.chain_id == 999
        assert cfg.label == "hyperevm_mainnet"
        assert cfg.confirmation_depth == 1
        assert cfg.finality_depth == 1

    def test_overrides_win(self):
        cfg = ETHEREUM_MAINNET.to_chain_config(
            rpc_url="https://eth.example.org",
            registry_address=self._REGISTRY,
            operator_key="0xdeadbeef",
            confirmation_depth=12,
            max_tps=2.0,
        )
        assert cfg.confirmation_depth == 12
        assert cfg.finality_depth == 64  # still from the profile
        assert cfg.max_tps == 2.0

    def test_chain_config_validation_still_applies(self):
        with pytest.raises(ValueError, match="invalid registry_address"):
            HYPEREVM_MAINNET.to_chain_config(
                rpc_url="https://rpc.hyperliquid.xyz/evm",
                registry_address="not_an_address",
                operator_key="0xdeadbeef",
            )

    def test_requires_credentials(self):
        with pytest.raises(ValueError, match="operator_key or operator_kms_key_id"):
            HYPEREVM_MAINNET.to_chain_config(
                rpc_url="https://rpc.hyperliquid.xyz/evm",
                registry_address=self._REGISTRY,
            )
