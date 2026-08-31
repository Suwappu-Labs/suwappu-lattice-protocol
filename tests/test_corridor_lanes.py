"""
Tests for corridor lanes (Ethereum mainnet <> Hyperliquid HyperEVM).

Pins the lane registry, the asymmetric confirmation policy, the payload
construction path into `LTP-corridor-v1`, and the cross-module chain-ID
consistency with `src/ltp/anchor/chain_profiles.py`.
"""

import pytest

from src.ltp.anchor.chain_profiles import get_chain_profile
from src.ltp.corridor.attestation import AttestationPayload
from src.ltp.corridor.lanes import (
    CORRIDOR_LANES,
    ETHEREUM_MAINNET_TO_HYPEREVM,
    HYPEREVM_TO_ETHEREUM_MAINNET,
    CorridorLane,
    get_lane,
    lane_between,
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestLaneRegistry:
    def test_registered_lane_pairs(self):
        pairs = {(lane.source_chain, lane.target_chain) for lane in CORRIDOR_LANES.values()}
        assert pairs == {
            (1, 999),
            (999, 1),
            (11_155_111, 998),
            (998, 11_155_111),
        }

    def test_registry_keys_match_names(self):
        for name, lane in CORRIDOR_LANES.items():
            assert lane.name == name

    def test_get_lane(self):
        assert get_lane("eth-mainnet:hyperevm") is ETHEREUM_MAINNET_TO_HYPEREVM

    def test_get_lane_unknown(self):
        with pytest.raises(KeyError, match="unknown corridor lane"):
            get_lane("eth-mainnet:dogechain")

    def test_lane_between(self):
        assert lane_between(1, 999) is ETHEREUM_MAINNET_TO_HYPEREVM
        assert lane_between(999, 1) is HYPEREVM_TO_ETHEREUM_MAINNET

    def test_lane_between_unknown(self):
        with pytest.raises(KeyError, match="no registered corridor lane"):
            lane_between(1, 84_532)

    def test_every_lane_has_a_reverse(self):
        pairs = {(lane.source_chain, lane.target_chain) for lane in CORRIDOR_LANES.values()}
        for source, target in pairs:
            assert (target, source) in pairs

    def test_labels_match_chain_profiles(self):
        """Lane labels and chain IDs must agree with the anchor profiles."""
        for lane in CORRIDOR_LANES.values():
            assert get_chain_profile(lane.source_label).chain_id == lane.source_chain
            assert get_chain_profile(lane.target_label).chain_id == lane.target_chain

    def test_confirmation_policy_matches_source_finality(self):
        """min_source_confirmations is pinned to the source profile's
        recommended finality depth — the corridor never signs earlier than
        the chain's own value-grade depth."""
        for lane in CORRIDOR_LANES.values():
            profile = get_chain_profile(lane.source_label)
            assert lane.min_source_confirmations == profile.recommended_finality_depth


# ---------------------------------------------------------------------------
# Confirmation policy
# ---------------------------------------------------------------------------


class TestConfirmationPolicy:
    def test_asymmetric_depths(self):
        """Ethereum side waits for PoS finality; HyperBFT commit is final."""
        assert ETHEREUM_MAINNET_TO_HYPEREVM.min_source_confirmations == 64
        assert HYPEREVM_TO_ETHEREUM_MAINNET.min_source_confirmations == 1

    def test_is_attestable_depth_one(self):
        lane = HYPEREVM_TO_ETHEREUM_MAINNET
        assert lane.is_attestable(source_height=100, source_head=100)

    def test_is_attestable_deep_lane_boundary(self):
        lane = ETHEREUM_MAINNET_TO_HYPEREVM
        # head - height + 1 == 64 exactly at head = height + 63
        assert not lane.is_attestable(source_height=1_000, source_head=1_062)
        assert lane.is_attestable(source_height=1_000, source_head=1_063)

    def test_is_attestable_rejects_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            ETHEREUM_MAINNET_TO_HYPEREVM.is_attestable(-1, 10)


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------


class TestLanePayload:
    def test_payload_fields(self):
        payload = ETHEREUM_MAINNET_TO_HYPEREVM.payload(
            source_height=23_456_789,
            state_root=b"\x11" * 32,
            timestamp_round=42,
        )
        assert isinstance(payload, AttestationPayload)
        assert payload.source_chain == 1
        assert payload.target_chain == 999
        assert payload.source_height == 23_456_789
        assert payload.state_root == b"\x11" * 32
        assert payload.timestamp_round == 42

    def test_payload_digest_is_direction_sensitive(self):
        """Deposit and withdrawal lanes over the same root sign different
        digests — a withdrawal attestation can never replay as a deposit."""
        deposit = ETHEREUM_MAINNET_TO_HYPEREVM.payload(100, b"\x22" * 32, 7)
        withdrawal = HYPEREVM_TO_ETHEREUM_MAINNET.payload(100, b"\x22" * 32, 7)
        assert deposit.canonical_digest() != withdrawal.canonical_digest()

    def test_payload_validation_applies(self):
        with pytest.raises(ValueError, match="state_root must be 32 bytes"):
            ETHEREUM_MAINNET_TO_HYPEREVM.payload(100, b"\x22" * 31, 7)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _lane(**overrides):
    params = {
        "name": "test:lane",
        "source_chain": 1,
        "target_chain": 999,
        "source_label": "ethereum_mainnet",
        "target_label": "hyperevm_mainnet",
        "min_source_confirmations": 1,
    }
    params.update(overrides)
    return CorridorLane(**params)


class TestLaneValidation:
    def test_valid(self):
        assert _lane().source_chain == 1

    def test_rejects_empty_name(self):
        with pytest.raises(ValueError, match="name is required"):
            _lane(name="")

    def test_rejects_same_chain(self):
        with pytest.raises(ValueError, match="must differ"):
            _lane(source_chain=999, target_chain=999)

    def test_rejects_zero_chain(self):
        with pytest.raises(ValueError, match="positive integer"):
            _lane(source_chain=0)

    def test_rejects_chain_over_u32(self):
        with pytest.raises(ValueError, match="exceeds u32"):
            _lane(target_chain=1 << 32)

    def test_rejects_zero_confirmations(self):
        with pytest.raises(ValueError, match="min_source_confirmations"):
            _lane(min_source_confirmations=0)

    def test_frozen(self):
        with pytest.raises(AttributeError):
            ETHEREUM_MAINNET_TO_HYPEREVM.source_chain = 2  # type: ignore[misc]
