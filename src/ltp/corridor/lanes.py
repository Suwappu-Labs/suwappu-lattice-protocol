"""Corridor lanes — named (source_chain, target_chain) attestation pairs.

A lane pins down the two u32 chain IDs a corridor attestation moves state
between, plus the source-side confirmation policy the corridor enforces
before signing. Lanes are directional: the Ethereum→HyperEVM lane waits
for Ethereum PoS finality (2 epochs) before attesting, while the reverse
lane can attest at depth 1 because HyperBFT commit is final.

Adding a lane is NOT a wire-format change. `source_chain` and
`target_chain` are ordinary payload values in the existing
`LTP-corridor-v1` attestation format (see `attestation.AttestationPayload`
and `docs/CORRIDOR_INTEGRATION.md`); no corridor version bump and no new
domain tag are involved. The u32 bound mirrors
`submission.build_state_anchor_*`, which rejects >u32 chain IDs at the
suwappu-db handoff.

The registered lanes below cover the Ethereum mainnet ↔ Hyperliquid
HyperEVM corridor (and its Sepolia ↔ HyperEVM-testnet staging pair).
Chain facts live in `src/ltp/anchor/chain_profiles.py`; this module
intentionally repeats only the numeric IDs so the corridor package keeps
zero imports from the anchor package (tests pin the two in sync).
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import AttestationPayload, ChainId

__all__ = [
    "CorridorLane",
    "CORRIDOR_LANES",
    "get_lane",
    "lane_between",
    "ETHEREUM_MAINNET_TO_HYPEREVM",
    "HYPEREVM_TO_ETHEREUM_MAINNET",
    "ETHEREUM_SEPOLIA_TO_HYPEREVM_TESTNET",
    "HYPEREVM_TESTNET_TO_ETHEREUM_SEPOLIA",
]

_MAX_CHAIN_ID = (1 << 32) - 1


@dataclass(frozen=True)
class CorridorLane:
    """One direction of a cross-chain corridor.

    `min_source_confirmations` is the depth the observed `source_height`
    must sit below the source chain's head before a super-node signs a
    partial over it. It is a corridor *policy* input, not a wire field —
    the attestation payload carries only the observed height.
    """

    name: str
    source_chain: ChainId
    target_chain: ChainId
    source_label: str
    target_label: str
    min_source_confirmations: int
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name is required")
        for field_name in ("source_chain", "target_chain"):
            v = getattr(self, field_name)
            if not isinstance(v, int) or v <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
            if v > _MAX_CHAIN_ID:
                raise ValueError(
                    f"{field_name} {v} exceeds u32; the corridor wire format "
                    f"and suwappu-db anchor registry key chains by u32"
                )
        if self.source_chain == self.target_chain:
            raise ValueError("source_chain and target_chain must differ")
        if self.min_source_confirmations < 1:
            raise ValueError("min_source_confirmations must be >= 1")

    def payload(
        self,
        source_height: int,
        state_root: bytes,
        timestamp_round: int,
    ) -> AttestationPayload:
        """Build the attestation payload for this lane.

        The payload is what the 7-of-9 quorum signs; field validation
        (32-byte root, non-negative ints) happens in AttestationPayload.
        """
        return AttestationPayload(
            source_chain=self.source_chain,
            target_chain=self.target_chain,
            source_height=source_height,
            state_root=state_root,
            timestamp_round=timestamp_round,
        )

    def is_attestable(self, source_height: int, source_head: int) -> bool:
        """True once `source_height` has this lane's confirmation depth.

        A height is attestable when at least `min_source_confirmations`
        blocks exist at-or-above it, counting the block itself — so on a
        depth-1 lane (single-slot finality) a height equal to the head is
        already attestable.
        """
        if source_height < 0 or source_head < 0:
            raise ValueError("heights must be non-negative")
        return source_head - source_height + 1 >= self.min_source_confirmations


# --- Ethereum mainnet <> Hyperliquid HyperEVM ------------------------------
#
# Confirmation policy is asymmetric on purpose:
#   - Ethereum→HyperEVM waits 64 blocks (2 PoS epochs, "finalized") so the
#     corridor never attests an Ethereum height that can legally reorg.
#   - HyperEVM→Ethereum attests at depth 1: HyperEVM shares HyperBFT
#     consensus with HyperCore, and a committed block is final.

ETHEREUM_MAINNET_TO_HYPEREVM = CorridorLane(
    name="eth-mainnet:hyperevm",
    source_chain=1,
    target_chain=999,
    source_label="ethereum_mainnet",
    target_label="hyperevm_mainnet",
    min_source_confirmations=64,
    description=(
        "Deposit lane: Ethereum mainnet state attested into Hyperliquid "
        "HyperEVM after PoS finality (2 epochs)."
    ),
)

HYPEREVM_TO_ETHEREUM_MAINNET = CorridorLane(
    name="hyperevm:eth-mainnet",
    source_chain=999,
    target_chain=1,
    source_label="hyperevm_mainnet",
    target_label="ethereum_mainnet",
    min_source_confirmations=1,
    description=(
        "Withdrawal lane: HyperEVM state attested into Ethereum mainnet at "
        "depth 1 (HyperBFT single-slot finality)."
    ),
)

ETHEREUM_SEPOLIA_TO_HYPEREVM_TESTNET = CorridorLane(
    name="eth-sepolia:hyperevm-testnet",
    source_chain=11_155_111,
    target_chain=998,
    source_label="ethereum_sepolia",
    target_label="hyperevm_testnet",
    min_source_confirmations=64,
    description="Staging pair for the mainnet deposit lane.",
)

HYPEREVM_TESTNET_TO_ETHEREUM_SEPOLIA = CorridorLane(
    name="hyperevm-testnet:eth-sepolia",
    source_chain=998,
    target_chain=11_155_111,
    source_label="hyperevm_testnet",
    target_label="ethereum_sepolia",
    min_source_confirmations=1,
    description="Staging pair for the mainnet withdrawal lane.",
)

CORRIDOR_LANES: dict[str, CorridorLane] = {
    lane.name: lane
    for lane in (
        ETHEREUM_MAINNET_TO_HYPEREVM,
        HYPEREVM_TO_ETHEREUM_MAINNET,
        ETHEREUM_SEPOLIA_TO_HYPEREVM_TESTNET,
        HYPEREVM_TESTNET_TO_ETHEREUM_SEPOLIA,
    )
}

_LANES_BY_PAIR: dict[tuple[ChainId, ChainId], CorridorLane] = {
    (lane.source_chain, lane.target_chain): lane for lane in CORRIDOR_LANES.values()
}


def get_lane(name: str) -> CorridorLane:
    """Look up a registered lane by name. Raises KeyError with the known set."""
    try:
        return CORRIDOR_LANES[name]
    except KeyError:
        known = ", ".join(sorted(CORRIDOR_LANES))
        raise KeyError(f"unknown corridor lane {name!r}; known: {known}") from None


def lane_between(source_chain: ChainId, target_chain: ChainId) -> CorridorLane:
    """Look up a registered lane by its (source, target) chain-ID pair."""
    try:
        return _LANES_BY_PAIR[(source_chain, target_chain)]
    except KeyError:
        raise KeyError(f"no registered corridor lane {source_chain} -> {target_chain}") from None
