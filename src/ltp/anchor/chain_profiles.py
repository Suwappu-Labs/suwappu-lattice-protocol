"""
Built-in chain profiles for LTP anchor deployments.

A ChainProfile captures the *protocol-level* facts about a target chain —
chain ID, finality model, block cadence, and the confirmation depths LTP
recommends before treating an anchor as settled. It deliberately excludes
everything deployment-specific (RPC URL, registry address, operator key):
those stay in `ChainConfig`, and `ChainProfile.to_chain_config()` merges
the two.

Profiles exist so that every corridor lane, gateway, and relayer that
targets "ethereum_mainnet" or "hyperevm_mainnet" agrees on the same chain
ID and finality posture, instead of re-deriving them per call site.

Finality models:
  - PROBABILISTIC — Ethereum PoS: a block is "safe" after ~2/3 attestation
    (~1 epoch) and "finalized" after 2 epochs (~12.8 min). Reorgs before
    finality are rare but protocol-legal, so value transfers wait for the
    finalized depth.
  - SINGLE_SLOT — HyperBFT-style BFT consensus (Hyperliquid): a committed
    block is final; there are no reorgs after commit. Depth 1 is safe.

Chain IDs must fit in a u32 — the suwappu-db anchor registry and the
`LTP-corridor-v1` attestation payload both key chains by u32 (see
`src/ltp/corridor/submission.py`). Adding a profile is NOT a wire-format
change: `source_chain` / `target_chain` are payload values in the existing
format, so no corridor version bump is involved.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .chain_config import ChainConfig

__all__ = [
    "FinalityModel",
    "ChainProfile",
    "CHAIN_PROFILES",
    "get_chain_profile",
    "profile_for_chain_id",
    "ETHEREUM_MAINNET",
    "ETHEREUM_SEPOLIA",
    "HYPEREVM_MAINNET",
    "HYPEREVM_TESTNET",
    "BASE_SEPOLIA",
    "SUWAPPU_TESTNET",
]

# Corridor attestations and the suwappu-db anchor registry key chains by u32.
_MAX_CHAIN_ID = (1 << 32) - 1


class FinalityModel(str, Enum):
    """How a chain reaches irreversibility (mirrors `backends/base.py`)."""

    PROBABILISTIC = "probabilistic"  # Ethereum PoS: finalized after 2 epochs
    SINGLE_SLOT = "single_slot"  # BFT commit is final (HyperBFT, SUWAPPU)


@dataclass(frozen=True)
class ChainProfile:
    """Immutable protocol-level facts about one anchor target chain."""

    label: str
    chain_id: int
    display_name: str
    native_symbol: str
    finality_model: FinalityModel
    block_time_seconds: float
    # Depth at which LTP treats an anchor as unlikely to reorg (UX-grade).
    recommended_confirmation_depth: int
    # Depth at which LTP treats an anchor as irreversible (value-grade).
    recommended_finality_depth: int
    testnet: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("label is required")
        if not isinstance(self.chain_id, int) or self.chain_id <= 0:
            raise ValueError("chain_id must be a positive integer")
        if self.chain_id > _MAX_CHAIN_ID:
            raise ValueError(
                f"chain_id {self.chain_id} exceeds u32; the corridor wire "
                f"format and suwappu-db anchor registry key chains by u32"
            )
        if self.block_time_seconds <= 0:
            raise ValueError("block_time_seconds must be positive")
        if self.recommended_confirmation_depth < 1:
            raise ValueError("recommended_confirmation_depth must be >= 1")
        if self.recommended_finality_depth < self.recommended_confirmation_depth:
            raise ValueError("recommended_finality_depth must be >= recommended_confirmation_depth")

    def to_chain_config(
        self,
        rpc_url: str,
        registry_address: str,
        operator_key: str = "",
        operator_kms_key_id: str = "",
        **overrides,
    ) -> ChainConfig:
        """Merge this profile with deployment-specific settings.

        Profile facts (chain_id, label, confirmation/finality depths) become
        the ChainConfig defaults; any keyword override wins. Credentials are
        validated by ChainConfig itself.
        """
        params = {
            "chain_id": self.chain_id,
            "label": self.label,
            "rpc_url": rpc_url,
            "registry_address": registry_address,
            "operator_key": operator_key,
            "operator_kms_key_id": operator_kms_key_id,
            "confirmation_depth": self.recommended_confirmation_depth,
            "finality_depth": self.recommended_finality_depth,
        }
        params.update(overrides)
        return ChainConfig(**params)


ETHEREUM_MAINNET = ChainProfile(
    label="ethereum_mainnet",
    chain_id=1,
    display_name="Ethereum Mainnet",
    native_symbol="ETH",
    finality_model=FinalityModel.PROBABILISTIC,
    block_time_seconds=12.0,
    # ~1 epoch (32 slots) covers the "safe" head; 2 epochs is "finalized".
    recommended_confirmation_depth=32,
    recommended_finality_depth=64,
    notes=(
        "PoS finality: 'safe' after ~1 epoch, 'finalized' after 2 epochs "
        "(~12.8 min). Value-grade decisions wait for the finality depth."
    ),
)

ETHEREUM_SEPOLIA = ChainProfile(
    label="ethereum_sepolia",
    chain_id=11_155_111,
    display_name="Ethereum Sepolia",
    native_symbol="ETH",
    finality_model=FinalityModel.PROBABILISTIC,
    block_time_seconds=12.0,
    recommended_confirmation_depth=32,
    recommended_finality_depth=64,
    testnet=True,
    notes="Same PoS finality schedule as mainnet.",
)

HYPEREVM_MAINNET = ChainProfile(
    label="hyperevm_mainnet",
    chain_id=999,
    display_name="Hyperliquid HyperEVM",
    native_symbol="HYPE",
    finality_model=FinalityModel.SINGLE_SLOT,
    block_time_seconds=1.0,
    recommended_confirmation_depth=1,
    recommended_finality_depth=1,
    notes=(
        "HyperEVM shares HyperBFT consensus with HyperCore — a committed "
        "block is final, no reorgs after commit. Dual-block cadence: small "
        "blocks (~1s, low gas limit) interleaved with big blocks (~1min, "
        "high gas limit); contract DEPLOYMENT transactions generally need "
        "the big-block lane, steady-state anchor writes fit small blocks."
    ),
)

HYPEREVM_TESTNET = ChainProfile(
    label="hyperevm_testnet",
    chain_id=998,
    display_name="Hyperliquid HyperEVM Testnet",
    native_symbol="HYPE",
    finality_model=FinalityModel.SINGLE_SLOT,
    block_time_seconds=1.0,
    recommended_confirmation_depth=1,
    recommended_finality_depth=1,
    testnet=True,
    notes="Same HyperBFT single-slot finality and dual-block cadence as mainnet.",
)

BASE_SEPOLIA = ChainProfile(
    label="base_sepolia",
    chain_id=84_532,
    display_name="Base Sepolia",
    native_symbol="ETH",
    finality_model=FinalityModel.PROBABILISTIC,
    block_time_seconds=2.0,
    recommended_confirmation_depth=3,
    recommended_finality_depth=6,
    testnet=True,
    notes="Existing LTP registry + bridge deployment (see docs/DEPLOYED_CONTRACTS.md).",
)

SUWAPPU_TESTNET = ChainProfile(
    label="suwappu_testnet",
    chain_id=103_115_120,
    display_name="SUWAPPU Testnet",
    native_symbol="SWP",
    finality_model=FinalityModel.SINGLE_SLOT,
    block_time_seconds=0.5,
    recommended_confirmation_depth=1,
    recommended_finality_depth=1,
    testnet=True,
    notes="Existing LTP registry + bridge deployment (see docs/DEPLOYED_CONTRACTS.md).",
)

CHAIN_PROFILES: dict[str, ChainProfile] = {
    p.label: p
    for p in (
        ETHEREUM_MAINNET,
        ETHEREUM_SEPOLIA,
        HYPEREVM_MAINNET,
        HYPEREVM_TESTNET,
        BASE_SEPOLIA,
        SUWAPPU_TESTNET,
    )
}

_PROFILES_BY_CHAIN_ID: dict[int, ChainProfile] = {p.chain_id: p for p in CHAIN_PROFILES.values()}


def get_chain_profile(label: str) -> ChainProfile:
    """Look up a built-in profile by label. Raises KeyError with the known set."""
    try:
        return CHAIN_PROFILES[label]
    except KeyError:
        known = ", ".join(sorted(CHAIN_PROFILES))
        raise KeyError(f"unknown chain profile {label!r}; known: {known}") from None


def profile_for_chain_id(chain_id: int) -> ChainProfile:
    """Look up a built-in profile by numeric chain ID."""
    try:
        return _PROFILES_BY_CHAIN_ID[chain_id]
    except KeyError:
        known = ", ".join(str(c) for c in sorted(_PROFILES_BY_CHAIN_ID))
        raise KeyError(f"unknown chain_id {chain_id}; known: {known}") from None
