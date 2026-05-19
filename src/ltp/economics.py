"""
Economic incentive layer for the LTP commitment network (Base L1).

Designed to bootstrap a healthy network from day one and scale with growth.
Competitive with Ethereum, Filecoin, Polkadot, and Celestia economic models.

Three-phase economic model:

  Phase 1 — BOOTSTRAP (epochs 0–BOOTSTRAP_END):
    High inflationary subsidies attract early node operators. Storage rewards
    are multiplied by a tapering bootstrap multiplier (3x → 1x). Minimum
    stake is low to reduce entry barrier.

  Phase 2 — GROWTH (epochs BOOTSTRAP_END–GROWTH_END):
    Declining subsidies (1.5x→1x taper during first year). Fee revenue from
    commitments becomes the primary income source. Dynamic pricing adjusts
    fees based on network utilization. Minimum stake increases.

  Phase 3 — MATURITY (epochs > GROWTH_END):
    No subsidies. Pure fee-driven economics. Fee burn + storage endowment
    create deflationary pressure and long-term sustainability.

Core mechanisms:
  - Epoch-based reward distribution (storage + availability + audit)
  - Bootstrap subsidy with linear taper (extended 180-day phase)
  - Growth-phase declining subsidies (Filecoin-inspired vesting model)
  - Storage-weighted staking (rewards ∝ shards_stored × stake)
  - Audit score multiplier (perfect audits earn 1.5x)
  - Dynamic commitment fee pricing (utilization-responsive)
  - Progressive slashing with correlation penalty (Ethereum-inspired)
  - Offense decay: offenses reduce by 1 per 720 clean epochs (~30 days)
  - Reward vesting: 50% immediate, 50% vests over 720 epochs (30 days)
  - Fee split: operator share + burn + storage endowment + insurance fund
  - Slashing grace period: 168-epoch (7-day) reversible window
  - Capacity-aware minimum stake scaling

Whitepaper reference: §6 Network Economics
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "EconomicsConfig",
    "EconomicsEngine",
    "EpochSnapshot",
    "NodeEconomics",
    "NetworkPhase",
    "PendingSlash",
    "RewardBreakdown",
    "SlashingTier",
    "VestingEntry",
]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WEI_PER_LTP = 10**18  # 1 LTP token = 10^18 wei (same convention as ETH)


# ---------------------------------------------------------------------------
# Network phase
# ---------------------------------------------------------------------------


class NetworkPhase(Enum):
    """Which economic phase the network is in, based on current epoch."""

    BOOTSTRAP = "bootstrap"
    GROWTH = "growth"
    MATURITY = "maturity"


# ---------------------------------------------------------------------------
# Slashing tiers
# ---------------------------------------------------------------------------


class SlashingTier(Enum):
    """Progressive slashing severity."""

    WARNING = "warning"  # First offense: 1% slash
    MINOR = "minor"  # 2nd–3rd offense: 5% slash
    MAJOR = "major"  # 4th–5th offense: 15% slash
    CRITICAL = "critical"  # 6+ offenses: 30% slash + eviction


SLASHING_RATES = {
    SlashingTier.WARNING: 100,  # basis points (1%)
    SlashingTier.MINOR: 500,  # 5%
    SlashingTier.MAJOR: 1500,  # 15%
    SlashingTier.CRITICAL: 3000,  # 30%
}

SLASHING_OFFENSE_THRESHOLDS = [
    (1, SlashingTier.WARNING),
    (2, SlashingTier.MINOR),
    (4, SlashingTier.MAJOR),
    (6, SlashingTier.CRITICAL),
]


def tier_for_offense_count(count: int) -> SlashingTier:
    """Determine slashing tier from cumulative offense count."""
    tier = SlashingTier.WARNING
    for threshold, t in SLASHING_OFFENSE_THRESHOLDS:
        if count >= threshold:
            tier = t
    return tier


# ---------------------------------------------------------------------------
# Vesting entry
# ---------------------------------------------------------------------------


@dataclass
class VestingEntry:
    """A vesting schedule entry for deferred rewards."""

    amount: int  # total amount to vest
    start_epoch: int  # epoch when vesting begins
    duration_epochs: int  # number of epochs over which to vest
    claimed: int = 0  # amount already released

    @property
    def remaining(self) -> int:
        return self.amount - self.claimed

    def claimable_at(self, current_epoch: int) -> int:
        """Amount that can be released at current_epoch."""
        if current_epoch < self.start_epoch:
            return 0
        elapsed = current_epoch - self.start_epoch
        if elapsed >= self.duration_epochs:
            return self.remaining
        total_vested = self.amount * elapsed // self.duration_epochs
        return max(0, total_vested - self.claimed)


# ---------------------------------------------------------------------------
# Pending slash (grace period)
# ---------------------------------------------------------------------------


@dataclass
class PendingSlash:
    """A slash held in escrow during the grace period."""

    node_id: str
    amount: int
    tier: SlashingTier
    epoch_created: int
    grace_epochs: int  # epochs before slash is finalized
    reversed: bool = False

    @property
    def finalization_epoch(self) -> int:
        return self.epoch_created + self.grace_epochs

    def is_finalized(self, current_epoch: int) -> bool:
        return not self.reversed and current_epoch >= self.finalization_epoch


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class EconomicsConfig:
    """Tunable parameters for L1 economics."""

    # --- Phase boundaries (epoch numbers) ---
    bootstrap_end_epoch: int = 4_320  # ~180 days at 1-hour epochs (extended)
    growth_end_epoch: int = 17_520  # ~2 years at 1-hour epochs
    epoch_seconds: int = 3_600  # 1 hour per epoch

    # --- Bootstrap subsidy ---
    bootstrap_subsidy_per_epoch: int = 500 * WEI_PER_LTP  # 500 LTP/epoch
    bootstrap_multiplier_start: float = 3.0  # 3x rewards at genesis
    bootstrap_multiplier_end: float = 1.0  # tapers to 1x

    # --- Growth-phase subsidy (declining, Filecoin-inspired) ---
    growth_subsidy_multiplier_start: float = 1.5  # 1.5x at start of Growth
    growth_subsidy_multiplier_end: float = 1.0  # tapers to 1x
    growth_subsidy_duration_epochs: int = 8_760  # first year of Growth

    # --- Base rewards per epoch ---
    base_storage_reward_per_shard: int = 10**14  # 0.0001 LTP per shard/epoch
    base_availability_reward: int = 10**15  # 0.001 LTP per epoch if 100% uptime
    audit_bonus_multiplier: float = 1.5  # 1.5x for perfect audit score

    # --- Staking ---
    min_stake_bootstrap: int = 100 * WEI_PER_LTP  # 100 LTP during bootstrap
    min_stake_growth: int = 1_000 * WEI_PER_LTP  # 1,000 LTP during growth
    min_stake_maturity: int = 10_000 * WEI_PER_LTP  # 10,000 LTP at maturity
    max_stake_cap: int = 1_000_000 * WEI_PER_LTP  # cap to prevent centralization

    # --- Fee model ---
    base_commit_fee: int = 10**15  # 0.001 LTP per commitment
    fee_utilization_target: float = 0.5  # target 50% network utilization
    fee_elasticity: float = 2.0  # fee doubles per 2x over target
    max_fee_multiplier: float = 10.0  # fee can't exceed 10x base
    min_fee_multiplier: float = 0.1  # fee floor at 0.1x base

    # --- Fee split (basis points, must sum to 10000) ---
    fee_operator_share_bps: int = 6000  # 60% to node operators
    fee_burn_share_bps: int = 1500  # 15% burned (deflationary)
    fee_endowment_share_bps: int = 1000  # 10% to storage endowment (Arweave/Sui-inspired)
    fee_insurance_share_bps: int = 1500  # 15% to insurance fund

    # --- Reward vesting (Filecoin-inspired) ---
    vesting_immediate_pct: int = 50  # 50% of rewards paid immediately
    vesting_duration_epochs: int = 720  # remaining 50% vests over 30 days

    # --- Slashing ---
    eviction_offense_threshold: int = 6  # offenses before forced eviction
    cooldown_epochs_per_offense: int = 24  # 24 epochs (1 day) penalty cooldown

    # --- Correlation penalty (Ethereum-inspired) ---
    # slash_multiplier = min(max_correlation_multiplier,
    #                        1 + correlation_scaling * (concurrent_slashed / total_staked))
    correlation_scaling: float = 2.0  # how aggressively to scale with correlation
    max_correlation_multiplier: float = 3.0  # cap at 3x (Ethereum uses 3x)

    # --- Offense decay ---
    offense_decay_clean_epochs: int = 720  # 30 days of clean behavior → -1 offense

    # --- Slashing grace period ---
    slash_grace_epochs: int = 168  # 7 days before slash is finalized

    # --- Programmable slashing (stake allocation change delay) ---
    allocation_change_delay_epochs: int = 336  # 14 days before allocation changes apply

    # --- Capacity scaling ---
    target_shards_per_node: int = 10_000  # ideal shard density
    overload_threshold: float = 1.5  # 1.5x target → discourage more shards

    def __post_init__(self) -> None:
        total_bps = (
            self.fee_operator_share_bps
            + self.fee_burn_share_bps
            + self.fee_endowment_share_bps
            + self.fee_insurance_share_bps
        )
        if total_bps != 10_000:
            raise ValueError(f"Fee split must sum to 10000 bps, got {total_bps}")


# ---------------------------------------------------------------------------
# Per-node economic state
# ---------------------------------------------------------------------------


@dataclass
class NodeEconomics:
    """Tracks a node's economic state across epochs."""

    node_id: str
    stake: int = 0
    total_rewards_earned: int = 0
    total_fees_earned: int = 0
    total_slashed: int = 0
    shards_stored: int = 0
    audit_score: int = 100  # 0–100
    offense_count: int = 0
    epochs_active: int = 0
    last_reward_epoch: int = -1
    cooldown_until_epoch: int = 0  # can't earn rewards until this epoch
    evicted: bool = False
    last_offense_epoch: int = -1  # epoch of most recent offense
    clean_epochs_since_offense: int = 0  # consecutive clean epochs

    # Vesting schedule
    vesting_entries: list[VestingEntry] = field(default_factory=list)

    # Pending slashes in grace period
    pending_slashes: list[PendingSlash] = field(default_factory=list)

    @property
    def effective_stake(self) -> int:
        """Stake after accounting for audit score degradation."""
        return int(self.stake * (self.audit_score / 100))

    @property
    def slashing_tier(self) -> SlashingTier:
        return tier_for_offense_count(self.offense_count)

    @property
    def total_vesting(self) -> int:
        """Total amount still locked in vesting."""
        return sum(v.remaining for v in self.vesting_entries)

    def claim_vested(self, current_epoch: int) -> int:
        """Release any vested rewards. Returns total amount released."""
        total_released = 0
        for entry in self.vesting_entries:
            claimable = entry.claimable_at(current_epoch)
            if claimable > 0:
                entry.claimed += claimable
                total_released += claimable
        # Clean up fully vested entries
        self.vesting_entries = [v for v in self.vesting_entries if v.remaining > 0]
        return total_released


# ---------------------------------------------------------------------------
# Reward breakdown (for transparency / dashboards)
# ---------------------------------------------------------------------------


@dataclass
class RewardBreakdown:
    """Itemized reward for a single node in a single epoch."""

    node_id: str
    epoch: int
    storage_reward: int = 0
    availability_reward: int = 0
    audit_bonus: int = 0
    bootstrap_subsidy: int = 0
    growth_subsidy: int = 0
    fee_share: int = 0
    total: int = 0
    immediate_payout: int = 0
    vested_amount: int = 0
    phase: NetworkPhase = NetworkPhase.BOOTSTRAP


# ---------------------------------------------------------------------------
# Epoch snapshot
# ---------------------------------------------------------------------------


@dataclass
class EpochSnapshot:
    """Network-wide economic state at end of an epoch."""

    epoch: int
    phase: NetworkPhase
    active_nodes: int
    total_shards: int
    total_staked: int
    total_rewards_distributed: int
    total_fees_collected: int
    total_fees_burned: int
    total_fees_to_endowment: int
    total_fees_to_insurance: int
    fee_multiplier: float
    utilization: float
    min_stake_required: int
    rewards: list[RewardBreakdown] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Economics engine
# ---------------------------------------------------------------------------


class EconomicsEngine:
    """
    Computes rewards, fees, and slashing for the LTP commitment network.

    Key competitive features vs other L1s:
      - Correlation penalty (Ethereum-inspired): coordinated attacks cost 3x+
      - Offense decay (novel): long-running reliable operators rehabilitate
      - Reward vesting (Filecoin-inspired): 50% immediate, 50% over 30 days
      - Storage endowment (Arweave/Sui-inspired): 10% of fees fund long-term storage
      - Slashing grace period (Polkadot-inspired): 7-day reversible window
      - Extended bootstrap (180 days) + Growth subsidies (1 year declining)

    Usage:
        engine = EconomicsEngine(config)

        # Each epoch:
        snapshot = engine.process_epoch(epoch=42, nodes=nodes, ...)

        # On audit failure (with correlation context):
        slash_amount, tier = engine.compute_slash(node, concurrent_slashed_stake, total_stake)

        # Dynamic fee:
        fee = engine.compute_commit_fee(utilization=0.7)
    """

    def __init__(self, config: EconomicsConfig | None = None) -> None:
        self.config = config or EconomicsConfig()
        self._total_burned: int = 0
        self._total_insurance: int = 0
        self._total_endowment: int = 0

    # --- Phase detection ---

    def network_phase(self, epoch: int) -> NetworkPhase:
        """Determine network phase from epoch number."""
        if epoch < self.config.bootstrap_end_epoch:
            return NetworkPhase.BOOTSTRAP
        elif epoch < self.config.growth_end_epoch:
            return NetworkPhase.GROWTH
        return NetworkPhase.MATURITY

    # --- Minimum stake ---

    def min_stake_for_epoch(self, epoch: int) -> int:
        """Minimum stake required to participate, scales with network phase."""
        phase = self.network_phase(epoch)
        if phase == NetworkPhase.BOOTSTRAP:
            return self.config.min_stake_bootstrap
        elif phase == NetworkPhase.GROWTH:
            progress = (epoch - self.config.bootstrap_end_epoch) / max(
                1, self.config.growth_end_epoch - self.config.bootstrap_end_epoch
            )
            low = self.config.min_stake_bootstrap
            high = self.config.min_stake_growth
            return int(low + (high - low) * progress)
        return self.config.min_stake_maturity

    # --- Bootstrap multiplier ---

    def bootstrap_multiplier(self, epoch: int) -> float:
        """Tapering multiplier for bootstrap subsidies. Returns 1.0 after bootstrap."""
        if epoch >= self.config.bootstrap_end_epoch:
            return 1.0
        progress = epoch / max(1, self.config.bootstrap_end_epoch)
        start = self.config.bootstrap_multiplier_start
        end = self.config.bootstrap_multiplier_end
        return start + (end - start) * progress

    # --- Growth-phase subsidy multiplier ---

    def growth_subsidy_multiplier(self, epoch: int) -> float:
        """Declining subsidy multiplier during Growth phase. Returns 1.0 outside window."""
        cfg = self.config
        if epoch < cfg.bootstrap_end_epoch:
            return 1.0  # handled by bootstrap multiplier
        growth_start = cfg.bootstrap_end_epoch
        subsidy_end = growth_start + cfg.growth_subsidy_duration_epochs
        if epoch >= subsidy_end:
            return 1.0
        progress = (epoch - growth_start) / max(1, cfg.growth_subsidy_duration_epochs)
        start = cfg.growth_subsidy_multiplier_start
        end = cfg.growth_subsidy_multiplier_end
        return start + (end - start) * progress

    # --- Dynamic fee pricing ---

    def compute_commit_fee(self, utilization: float) -> int:
        """
        Compute dynamic commitment fee based on network utilization.

        Fee adjusts exponentially around the target utilization:
          - Below target: fee decreases (attract more usage)
          - Above target: fee increases (prevent congestion)
          - Clamped to [min_fee_multiplier, max_fee_multiplier] × base_fee
        """
        cfg = self.config
        if utilization <= 0:
            return int(cfg.base_commit_fee * cfg.min_fee_multiplier)

        exponent = cfg.fee_elasticity * (utilization - cfg.fee_utilization_target)
        multiplier = math.exp(exponent)
        multiplier = max(cfg.min_fee_multiplier, min(cfg.max_fee_multiplier, multiplier))
        return int(cfg.base_commit_fee * multiplier)

    def split_fee(self, fee: int) -> tuple[int, int, int, int]:
        """
        Split a commitment fee into (operator_share, burn, endowment, insurance).

        Returns four amounts that sum to the original fee.
        """
        cfg = self.config
        operator = fee * cfg.fee_operator_share_bps // 10_000
        burn = fee * cfg.fee_burn_share_bps // 10_000
        endowment = fee * cfg.fee_endowment_share_bps // 10_000
        insurance = fee - operator - burn - endowment  # remainder avoids rounding loss
        return operator, burn, endowment, insurance

    # --- Offense decay ---

    def apply_offense_decay(self, node: NodeEconomics, current_epoch: int) -> int:
        """
        Decay offense count for nodes with sustained clean behavior.

        For every `offense_decay_clean_epochs` consecutive clean epochs,
        offense_count decreases by 1 (minimum 0). This prevents the
        ratchet-to-eviction problem identified in competitive analysis.

        Returns: number of offenses decayed this call.
        """
        cfg = self.config
        if node.offense_count <= 0:
            return 0
        if node.clean_epochs_since_offense < cfg.offense_decay_clean_epochs:
            return 0

        decayed = node.clean_epochs_since_offense // cfg.offense_decay_clean_epochs
        decayed = min(decayed, node.offense_count)
        node.offense_count -= decayed
        node.clean_epochs_since_offense -= decayed * cfg.offense_decay_clean_epochs
        return decayed

    # --- Reward computation ---

    def compute_node_reward(
        self,
        node: NodeEconomics,
        epoch: int,
        fee_pool_share: int,
    ) -> RewardBreakdown:
        """
        Compute reward for a single node in a single epoch.

        Components:
          1. Storage reward: proportional to shards stored
          2. Availability reward: base reward for being online
          3. Audit bonus: 1.5x multiplier for perfect audit score (100)
          4. Bootstrap subsidy: tapering multiplier (bootstrap phase only)
          5. Growth subsidy: declining multiplier (first year of growth)
          6. Fee share: proportional share of operator fee pool

        Rewards are split: immediate_payout (50%) + vested_amount (50% over 30 days).
        Nodes in cooldown earn zero. Evicted nodes earn zero.
        """
        cfg = self.config
        phase = self.network_phase(epoch)
        breakdown = RewardBreakdown(node_id=node.node_id, epoch=epoch, phase=phase)

        if epoch < node.cooldown_until_epoch or node.evicted:
            return breakdown

        # 1. Storage reward
        breakdown.storage_reward = node.shards_stored * cfg.base_storage_reward_per_shard

        # 2. Availability reward
        breakdown.availability_reward = cfg.base_availability_reward

        # 3. Audit bonus (perfect score = 1.5x on storage + availability)
        if node.audit_score == 100:
            bonus_base = breakdown.storage_reward + breakdown.availability_reward
            breakdown.audit_bonus = int(bonus_base * (cfg.audit_bonus_multiplier - 1.0))

        # 4. Bootstrap subsidy
        if phase == NetworkPhase.BOOTSTRAP:
            multiplier = self.bootstrap_multiplier(epoch)
            base = breakdown.storage_reward + breakdown.availability_reward
            breakdown.bootstrap_subsidy = int(base * (multiplier - 1.0))

        # 5. Growth subsidy (first year of growth phase)
        if phase == NetworkPhase.GROWTH:
            multiplier = self.growth_subsidy_multiplier(epoch)
            if multiplier > 1.0:
                base = breakdown.storage_reward + breakdown.availability_reward
                breakdown.growth_subsidy = int(base * (multiplier - 1.0))

        # 6. Fee share
        breakdown.fee_share = fee_pool_share

        breakdown.total = (
            breakdown.storage_reward
            + breakdown.availability_reward
            + breakdown.audit_bonus
            + breakdown.bootstrap_subsidy
            + breakdown.growth_subsidy
            + breakdown.fee_share
        )

        # Vesting split
        immediate_pct = cfg.vesting_immediate_pct
        breakdown.immediate_payout = breakdown.total * immediate_pct // 100
        breakdown.vested_amount = breakdown.total - breakdown.immediate_payout

        return breakdown

    # --- Slashing ---

    def compute_slash(
        self,
        node: NodeEconomics,
        concurrent_slashed_stake: int = 0,
        total_network_stake: int = 0,
    ) -> tuple[int, SlashingTier]:
        """
        Compute slash amount with progressive tiers AND correlation penalty.

        Progressive slashing (base rate):
          1st offense:  1% of stake (WARNING)
          2nd–3rd:      5% of stake (MINOR)
          4th–5th:      15% of stake (MAJOR)
          6+:           30% of stake + eviction (CRITICAL)

        Correlation penalty (Ethereum-inspired):
          If multiple nodes are slashed in the same epoch, each node's slash
          is multiplied by min(3.0, 1.0 + 2.0 × concurrent_slashed / total_stake).
          This makes coordinated attacks exponentially more expensive while
          keeping isolated incidents cheap.

        Returns: (slash_amount_wei, tier)
        """
        tier = tier_for_offense_count(node.offense_count)
        rate_bps = SLASHING_RATES[tier]
        base_slash = node.stake * rate_bps // 10_000

        # Apply correlation penalty if network context provided
        if total_network_stake > 0 and concurrent_slashed_stake > 0:
            cfg = self.config
            correlation_ratio = concurrent_slashed_stake / total_network_stake
            correlation_multiplier = min(
                cfg.max_correlation_multiplier,
                1.0 + cfg.correlation_scaling * correlation_ratio,
            )
            slash_amount = int(base_slash * correlation_multiplier)
            # Never slash more than the node's entire stake
            slash_amount = min(slash_amount, node.stake)
        else:
            slash_amount = base_slash

        return slash_amount, tier

    def create_pending_slash(
        self,
        node: NodeEconomics,
        slash_amount: int,
        tier: SlashingTier,
        current_epoch: int,
    ) -> PendingSlash:
        """
        Create a slash held in escrow during the grace period.

        During the grace period, governance can reverse the slash (e.g.,
        if caused by a bug or false positive). After the grace period,
        the slash is finalized automatically.
        """
        pending = PendingSlash(
            node_id=node.node_id,
            amount=slash_amount,
            tier=tier,
            epoch_created=current_epoch,
            grace_epochs=self.config.slash_grace_epochs,
        )
        node.pending_slashes.append(pending)
        return pending

    def finalize_pending_slashes(
        self, node: NodeEconomics, current_epoch: int
    ) -> list[PendingSlash]:
        """
        Finalize any pending slashes whose grace period has expired.

        Returns list of newly finalized slashes. The caller (backend)
        should apply the actual stake deductions.
        """
        finalized = []
        remaining = []
        for ps in node.pending_slashes:
            if ps.reversed:
                continue  # skip reversed slashes
            if ps.is_finalized(current_epoch):
                finalized.append(ps)
            else:
                remaining.append(ps)
        node.pending_slashes = remaining
        return finalized

    def reverse_pending_slash(self, slash: PendingSlash) -> bool:
        """
        Reverse a pending slash (governance action during grace period).

        Returns True if successfully reversed, False if already finalized.
        """
        if slash.reversed:
            return False
        slash.reversed = True
        return True

    def compute_slash_for_condition(
        self,
        node: NodeEconomics,
        condition_allocation_bps: int,
        severity: str,
        concurrent_slashed_stake: int = 0,
        total_network_stake: int = 0,
    ) -> tuple[int, SlashingTier]:
        """
        Compute slash amount for a programmable slashing condition.

        Uses the condition's stake allocation to determine the at-risk
        portion, then applies the severity-based rate and correlation
        penalty. Integrates with the enforcement module's
        SlashingConditionRegistry.

        Args:
            node: The node being slashed.
            condition_allocation_bps: Basis points of stake allocated
                to this condition (from SlashingCondition).
            severity: Severity level from SlashResult ("warning",
                "minor", "major", "critical").
            concurrent_slashed_stake: Total stake being slashed this epoch.
            total_network_stake: Total network stake for correlation calc.

        Returns: (slash_amount_wei, tier)
        """
        # Map severity string to SlashingTier
        severity_map = {
            "warning": SlashingTier.WARNING,
            "minor": SlashingTier.MINOR,
            "major": SlashingTier.MAJOR,
            "critical": SlashingTier.CRITICAL,
        }
        tier = severity_map.get(severity, SlashingTier.WARNING)

        # Compute at-risk stake (only the allocated portion)
        at_risk_stake = node.stake * condition_allocation_bps // 10_000

        rate_bps = SLASHING_RATES[tier]
        base_slash = at_risk_stake * rate_bps // 10_000

        # Apply correlation penalty
        if total_network_stake > 0 and concurrent_slashed_stake > 0:
            cfg = self.config
            correlation_ratio = concurrent_slashed_stake / total_network_stake
            correlation_multiplier = min(
                cfg.max_correlation_multiplier,
                1.0 + cfg.correlation_scaling * correlation_ratio,
            )
            slash_amount = int(base_slash * correlation_multiplier)
        else:
            slash_amount = base_slash

        # Never slash more than the node's at-risk stake
        slash_amount = min(slash_amount, at_risk_stake)
        return slash_amount, tier

    def should_evict(self, node: NodeEconomics) -> bool:
        """Whether a node should be forcibly evicted based on offense count."""
        return node.offense_count >= self.config.eviction_offense_threshold

    # --- Epoch processing ---

    def process_epoch(
        self,
        epoch: int,
        nodes: list[NodeEconomics],
        total_commitments_this_epoch: int = 0,
        network_capacity: int = 10_000,
    ) -> EpochSnapshot:
        """
        Process end-of-epoch economics for the entire network.

        Steps:
          1. Apply offense decay for clean nodes
          2. Compute utilization and dynamic fee
          3. Compute total fees collected this epoch
          4. Split fees: operator pool, burn, endowment, insurance
          5. Distribute operator pool proportional to effective stake
          6. Compute per-node rewards with vesting split
          7. Release vested rewards from previous epochs
          8. Return EpochSnapshot for transparency
        """
        phase = self.network_phase(epoch)
        active_nodes = [n for n in nodes if not n.evicted]
        if not active_nodes:
            return EpochSnapshot(
                epoch=epoch,
                phase=phase,
                active_nodes=0,
                total_shards=0,
                total_staked=0,
                total_rewards_distributed=0,
                total_fees_collected=0,
                total_fees_burned=0,
                total_fees_to_endowment=0,
                total_fees_to_insurance=0,
                fee_multiplier=1.0,
                utilization=0.0,
                min_stake_required=self.min_stake_for_epoch(epoch),
            )

        # 1. Offense decay
        for n in active_nodes:
            n.clean_epochs_since_offense += 1
            self.apply_offense_decay(n, epoch)

        # 2. Utilization and fee
        utilization = total_commitments_this_epoch / max(1, network_capacity)
        commit_fee = self.compute_commit_fee(utilization)
        fee_multiplier = commit_fee / max(1, self.config.base_commit_fee)

        # 3. Total fees
        total_fees = commit_fee * total_commitments_this_epoch

        # 4. Fee split (4-way)
        operator_pool, burn, endowment, insurance = self.split_fee(total_fees)
        self._total_burned += burn
        self._total_endowment += endowment
        self._total_insurance += insurance

        # 5. Distribute operator pool proportional to effective stake
        total_effective_stake = sum(n.effective_stake for n in active_nodes)
        fee_shares: dict[str, int] = {}
        if total_effective_stake > 0:
            for n in active_nodes:
                share = operator_pool * n.effective_stake // total_effective_stake
                fee_shares[n.node_id] = share
        else:
            per_node = operator_pool // max(1, len(active_nodes))
            for n in active_nodes:
                fee_shares[n.node_id] = per_node

        # 6. Compute rewards
        rewards = []
        total_distributed = 0
        total_shards = 0
        total_staked = 0

        for n in active_nodes:
            total_shards += n.shards_stored
            total_staked += n.stake
            reward = self.compute_node_reward(n, epoch, fee_shares.get(n.node_id, 0))
            rewards.append(reward)
            total_distributed += reward.total

        return EpochSnapshot(
            epoch=epoch,
            phase=phase,
            active_nodes=len(active_nodes),
            total_shards=total_shards,
            total_staked=total_staked,
            total_rewards_distributed=total_distributed,
            total_fees_collected=total_fees,
            total_fees_burned=burn,
            total_fees_to_endowment=endowment,
            total_fees_to_insurance=insurance,
            fee_multiplier=fee_multiplier,
            utilization=utilization,
            min_stake_required=self.min_stake_for_epoch(epoch),
            rewards=rewards,
        )

    @property
    def total_burned(self) -> int:
        """Cumulative fees burned across all epochs."""
        return self._total_burned

    @property
    def total_insurance(self) -> int:
        """Cumulative insurance fund across all epochs."""
        return self._total_insurance

    @property
    def total_endowment(self) -> int:
        """Cumulative storage endowment across all epochs."""
        return self._total_endowment

    # --- Capacity scaling ---

    def is_node_overloaded(self, node: NodeEconomics) -> bool:
        """Whether a node has too many shards relative to target density."""
        threshold = int(self.config.target_shards_per_node * self.config.overload_threshold)
        return node.shards_stored > threshold

    def recommended_node_count(self, total_shards: int) -> int:
        """Recommended number of nodes for the current shard count."""
        return max(1, math.ceil(total_shards / self.config.target_shards_per_node))
