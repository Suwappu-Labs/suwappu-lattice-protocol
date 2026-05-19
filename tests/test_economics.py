"""
Tests for the LTP economic incentive layer.

Covers:
  - Network phase detection (extended bootstrap)
  - Bootstrap subsidy tapering (180 days)
  - Growth-phase declining subsidies
  - Dynamic fee pricing
  - Fee split (operator / burn / endowment / insurance)
  - Reward computation with vesting
  - Progressive slashing tiers
  - Correlation penalty (Ethereum-inspired)
  - Offense decay (30-day clean window)
  - Slashing grace period (7-day reversible)
  - Storage endowment accumulation
  - Epoch processing end-to-end
  - Minimum stake scaling across phases
  - Capacity scaling recommendations
  - Base L1 backend integration with economics engine
"""

import pytest

from src.ltp.backends import BackendConfig, create_backend
from src.ltp.economics import (
    SLASHING_RATES,
    WEI_PER_LTP,
    EconomicsConfig,
    EconomicsEngine,
    EpochSnapshot,
    NetworkPhase,
    NodeEconomics,
    PendingSlash,
    RewardBreakdown,
    SlashingTier,
    VestingEntry,
    tier_for_offense_count,
)

# ---------------------------------------------------------------------------
# Network phase detection (extended bootstrap = 180 days)
# ---------------------------------------------------------------------------


class TestNetworkPhase:
    def test_bootstrap_phase(self):
        engine = EconomicsEngine()
        assert engine.network_phase(0) == NetworkPhase.BOOTSTRAP
        assert engine.network_phase(100) == NetworkPhase.BOOTSTRAP
        assert engine.network_phase(4319) == NetworkPhase.BOOTSTRAP

    def test_growth_phase(self):
        engine = EconomicsEngine()
        assert engine.network_phase(4320) == NetworkPhase.GROWTH
        assert engine.network_phase(10000) == NetworkPhase.GROWTH
        assert engine.network_phase(17519) == NetworkPhase.GROWTH

    def test_maturity_phase(self):
        engine = EconomicsEngine()
        assert engine.network_phase(17520) == NetworkPhase.MATURITY
        assert engine.network_phase(100000) == NetworkPhase.MATURITY

    def test_custom_boundaries(self):
        cfg = EconomicsConfig(bootstrap_end_epoch=10, growth_end_epoch=50)
        engine = EconomicsEngine(cfg)
        assert engine.network_phase(5) == NetworkPhase.BOOTSTRAP
        assert engine.network_phase(10) == NetworkPhase.GROWTH
        assert engine.network_phase(50) == NetworkPhase.MATURITY


# ---------------------------------------------------------------------------
# Bootstrap subsidy multiplier (180-day taper)
# ---------------------------------------------------------------------------


class TestBootstrapMultiplier:
    def test_starts_at_3x(self):
        engine = EconomicsEngine()
        assert engine.bootstrap_multiplier(0) == 3.0

    def test_tapers_to_1x(self):
        engine = EconomicsEngine()
        assert engine.bootstrap_multiplier(4320) == 1.0

    def test_midpoint_is_between(self):
        engine = EconomicsEngine()
        mid = engine.bootstrap_multiplier(2160)
        assert 1.0 < mid < 3.0

    def test_after_bootstrap_always_1x(self):
        engine = EconomicsEngine()
        assert engine.bootstrap_multiplier(5000) == 1.0
        assert engine.bootstrap_multiplier(100000) == 1.0

    def test_monotonically_decreasing(self):
        engine = EconomicsEngine()
        prev = engine.bootstrap_multiplier(0)
        for epoch in range(100, 4400, 100):
            curr = engine.bootstrap_multiplier(epoch)
            assert curr <= prev
            prev = curr


# ---------------------------------------------------------------------------
# Growth-phase declining subsidies
# ---------------------------------------------------------------------------


class TestGrowthSubsidy:
    def test_starts_at_1_5x(self):
        engine = EconomicsEngine()
        # At start of growth phase
        mult = engine.growth_subsidy_multiplier(4320)
        assert mult == pytest.approx(1.5, abs=0.01)

    def test_tapers_to_1x(self):
        engine = EconomicsEngine()
        # After growth subsidy duration
        mult = engine.growth_subsidy_multiplier(4320 + 8760)
        assert mult == 1.0

    def test_midpoint(self):
        engine = EconomicsEngine()
        mid_epoch = 4320 + 8760 // 2
        mult = engine.growth_subsidy_multiplier(mid_epoch)
        assert 1.0 < mult < 1.5

    def test_no_subsidy_in_bootstrap(self):
        engine = EconomicsEngine()
        assert engine.growth_subsidy_multiplier(0) == 1.0

    def test_no_subsidy_in_maturity(self):
        engine = EconomicsEngine()
        assert engine.growth_subsidy_multiplier(20000) == 1.0

    def test_growth_subsidy_in_rewards(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=50)
        reward = engine.compute_node_reward(node, epoch=5000, fee_pool_share=0)
        assert reward.growth_subsidy > 0
        assert reward.phase == NetworkPhase.GROWTH


# ---------------------------------------------------------------------------
# Dynamic fee pricing
# ---------------------------------------------------------------------------


class TestDynamicFee:
    def test_zero_utilization_gives_min_fee(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(0.0)
        expected = int(engine.config.base_commit_fee * engine.config.min_fee_multiplier)
        assert fee == expected

    def test_target_utilization_gives_base_fee(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(0.5)
        assert fee == engine.config.base_commit_fee

    def test_high_utilization_increases_fee(self):
        engine = EconomicsEngine()
        base = engine.compute_commit_fee(0.5)
        high = engine.compute_commit_fee(0.9)
        assert high > base

    def test_low_utilization_decreases_fee(self):
        engine = EconomicsEngine()
        base = engine.compute_commit_fee(0.5)
        low = engine.compute_commit_fee(0.1)
        assert low < base

    def test_fee_clamped_to_max(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(10.0)
        max_fee = int(engine.config.base_commit_fee * engine.config.max_fee_multiplier)
        assert fee == max_fee

    def test_fee_never_negative(self):
        engine = EconomicsEngine()
        fee = engine.compute_commit_fee(-1.0)
        assert fee > 0


# ---------------------------------------------------------------------------
# Fee split (4-way: operator / burn / endowment / insurance)
# ---------------------------------------------------------------------------


class TestFeeSplit:
    def test_split_sums_to_total(self):
        engine = EconomicsEngine()
        fee = 1_000_000
        operator, burn, endowment, insurance = engine.split_fee(fee)
        assert operator + burn + endowment + insurance == fee

    def test_split_ratios(self):
        engine = EconomicsEngine()
        fee = 10_000
        operator, burn, endowment, insurance = engine.split_fee(fee)
        assert operator == 6000  # 60%
        assert burn == 1500  # 15%
        assert endowment == 1000  # 10%
        assert insurance == 1500  # 15%

    def test_invalid_split_raises(self):
        with pytest.raises(ValueError, match="10000 bps"):
            EconomicsConfig(
                fee_operator_share_bps=5000,
                fee_burn_share_bps=5000,
                fee_endowment_share_bps=1000,
                fee_insurance_share_bps=5000,
            )

    def test_zero_fee_split(self):
        engine = EconomicsEngine()
        operator, burn, endowment, insurance = engine.split_fee(0)
        assert operator == 0
        assert burn == 0
        assert endowment == 0
        assert insurance == 0

    def test_endowment_accumulates(self):
        engine = EconomicsEngine()
        nodes = [NodeEconomics(node_id="n", stake=1000 * WEI_PER_LTP, shards_stored=10)]
        engine.process_epoch(epoch=5000, nodes=nodes, total_commitments_this_epoch=100)
        assert engine.total_endowment > 0

        endow1 = engine.total_endowment
        engine.process_epoch(epoch=5001, nodes=nodes, total_commitments_this_epoch=100)
        assert engine.total_endowment > endow1


# ---------------------------------------------------------------------------
# Minimum stake scaling
# ---------------------------------------------------------------------------


class TestMinStake:
    def test_bootstrap_min_stake(self):
        engine = EconomicsEngine()
        assert engine.min_stake_for_epoch(0) == 100 * WEI_PER_LTP

    def test_growth_ramps_up(self):
        engine = EconomicsEngine()
        start = engine.min_stake_for_epoch(4320)
        end = engine.min_stake_for_epoch(17519)
        assert start < end
        assert start >= 100 * WEI_PER_LTP
        assert end <= 1000 * WEI_PER_LTP

    def test_maturity_min_stake(self):
        engine = EconomicsEngine()
        assert engine.min_stake_for_epoch(17520) == 10_000 * WEI_PER_LTP


# ---------------------------------------------------------------------------
# Progressive slashing
# ---------------------------------------------------------------------------


class TestSlashing:
    def test_tier_progression(self):
        assert tier_for_offense_count(0) == SlashingTier.WARNING
        assert tier_for_offense_count(1) == SlashingTier.WARNING
        assert tier_for_offense_count(2) == SlashingTier.MINOR
        assert tier_for_offense_count(3) == SlashingTier.MINOR
        assert tier_for_offense_count(4) == SlashingTier.MAJOR
        assert tier_for_offense_count(5) == SlashingTier.MAJOR
        assert tier_for_offense_count(6) == SlashingTier.CRITICAL
        assert tier_for_offense_count(100) == SlashingTier.CRITICAL

    def test_tier_boundaries_exact(self):
        """Verify exact offense count → tier mapping at boundaries."""
        assert tier_for_offense_count(1) == SlashingTier.WARNING  # 1st offense
        assert tier_for_offense_count(2) == SlashingTier.MINOR  # 2nd offense
        assert tier_for_offense_count(4) == SlashingTier.MAJOR  # 4th offense
        assert tier_for_offense_count(6) == SlashingTier.CRITICAL  # 6th offense

    def test_slash_amounts_escalate(self):
        engine = EconomicsEngine()
        stake = 10_000 * WEI_PER_LTP

        node = NodeEconomics(node_id="n", stake=stake, offense_count=1)
        amt1, _ = engine.compute_slash(node)

        node.offense_count = 3
        amt3, _ = engine.compute_slash(node)

        node.offense_count = 6
        amt6, _ = engine.compute_slash(node)

        assert amt1 < amt3 < amt6

    def test_warning_is_1_percent(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        amt, tier = engine.compute_slash(node)
        assert tier == SlashingTier.WARNING
        assert amt == 100  # 1% of 10000

    def test_critical_is_30_percent(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=6)
        amt, tier = engine.compute_slash(node)
        assert tier == SlashingTier.CRITICAL
        assert amt == 3000  # 30% of 10000

    def test_should_evict_at_threshold(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=5)
        assert not engine.should_evict(node)
        node.offense_count = 6
        assert engine.should_evict(node)


# ---------------------------------------------------------------------------
# Correlation penalty (Ethereum-inspired)
# ---------------------------------------------------------------------------


class TestCorrelationPenalty:
    def test_no_correlation_gives_base_rate(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        amt_solo, _ = engine.compute_slash(node)
        amt_no_ctx, _ = engine.compute_slash(
            node, concurrent_slashed_stake=0, total_network_stake=0
        )
        assert amt_solo == amt_no_ctx  # same as base

    def test_correlated_attack_costs_more(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        amt_solo, _ = engine.compute_slash(node)
        # 30% of network slashed simultaneously
        amt_corr, _ = engine.compute_slash(
            node,
            concurrent_slashed_stake=30_000,
            total_network_stake=100_000,
        )
        assert amt_corr > amt_solo

    def test_correlation_multiplier_capped_at_3x(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        base, _ = engine.compute_slash(node)
        # 100% of network slashed
        corr, _ = engine.compute_slash(
            node,
            concurrent_slashed_stake=100_000,
            total_network_stake=100_000,
        )
        assert corr == base * 3  # capped at 3x

    def test_small_correlation_has_small_effect(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=100_000, offense_count=1)
        base, _ = engine.compute_slash(node)
        # Only 1% of network slashed
        corr, _ = engine.compute_slash(
            node,
            concurrent_slashed_stake=1000,
            total_network_stake=100_000,
        )
        # Should be ~1.02x the base, very small increase
        assert corr >= base
        assert corr < base * 1.1

    def test_33pct_correlated_gives_about_1_66x(self):
        """At 33% correlated failure: multiplier = 1 + 2*0.33 = 1.66x"""
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        base, _ = engine.compute_slash(node)
        corr, _ = engine.compute_slash(
            node,
            concurrent_slashed_stake=33_000,
            total_network_stake=100_000,
        )
        ratio = corr / base
        assert 1.5 < ratio < 1.8

    def test_never_slashes_more_than_total_stake(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=100, offense_count=6)
        # 30% base rate * 3x correlation = 90%, but CRITICAL at 30% → 90 max
        corr, _ = engine.compute_slash(
            node,
            concurrent_slashed_stake=100_000,
            total_network_stake=100_000,
        )
        assert corr <= node.stake


# ---------------------------------------------------------------------------
# Offense decay
# ---------------------------------------------------------------------------


class TestOffenseDecay:
    def test_decay_after_clean_window(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=3, clean_epochs_since_offense=720)
        decayed = engine.apply_offense_decay(node, current_epoch=1000)
        assert decayed == 1
        assert node.offense_count == 2

    def test_no_decay_before_window(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=3, clean_epochs_since_offense=500)
        decayed = engine.apply_offense_decay(node, current_epoch=1000)
        assert decayed == 0
        assert node.offense_count == 3

    def test_multiple_decays(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=3, clean_epochs_since_offense=2160)
        decayed = engine.apply_offense_decay(node, current_epoch=5000)
        assert decayed == 3  # 2160 // 720 = 3, but capped at offense_count
        assert node.offense_count == 0

    def test_no_decay_at_zero(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=0, clean_epochs_since_offense=2000)
        decayed = engine.apply_offense_decay(node, current_epoch=5000)
        assert decayed == 0

    def test_decay_resets_clean_counter(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", offense_count=2, clean_epochs_since_offense=720)
        engine.apply_offense_decay(node, current_epoch=1000)
        assert node.clean_epochs_since_offense == 0

    def test_epoch_processing_increments_clean_epochs(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n",
            stake=1000 * WEI_PER_LTP,
            offense_count=1,
            clean_epochs_since_offense=0,
        )
        engine.process_epoch(epoch=0, nodes=[node])
        assert node.clean_epochs_since_offense == 1


# ---------------------------------------------------------------------------
# Reward vesting
# ---------------------------------------------------------------------------


class TestRewardVesting:
    def test_vesting_entry_claimable(self):
        entry = VestingEntry(amount=1000, start_epoch=0, duration_epochs=100)
        assert entry.claimable_at(0) == 0  # nothing vested at start
        assert entry.claimable_at(50) == 500  # 50% at midpoint
        assert entry.claimable_at(100) == 1000  # 100% at end
        assert entry.claimable_at(200) == 1000  # capped

    def test_vesting_entry_partial_claim(self):
        entry = VestingEntry(amount=1000, start_epoch=0, duration_epochs=100)
        claim1 = entry.claimable_at(50)
        entry.claimed = claim1
        claim2 = entry.claimable_at(75)
        assert claim2 == 250  # 75% total - 50% already claimed

    def test_reward_breakdown_has_vesting_split(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=100)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.total > 0
        assert reward.immediate_payout == reward.total * 50 // 100
        assert reward.vested_amount == reward.total - reward.immediate_payout
        assert reward.immediate_payout + reward.vested_amount == reward.total

    def test_node_claim_vested(self):
        node = NodeEconomics(
            node_id="n",
            vesting_entries=[
                VestingEntry(amount=1000, start_epoch=0, duration_epochs=100),
            ],
        )
        released = node.claim_vested(current_epoch=50)
        assert released == 500

    def test_node_total_vesting(self):
        node = NodeEconomics(
            node_id="n",
            vesting_entries=[
                VestingEntry(amount=1000, start_epoch=0, duration_epochs=100),
                VestingEntry(amount=2000, start_epoch=50, duration_epochs=100),
            ],
        )
        assert node.total_vesting == 3000

    def test_fully_vested_entries_cleaned_up(self):
        node = NodeEconomics(
            node_id="n",
            vesting_entries=[
                VestingEntry(amount=1000, start_epoch=0, duration_epochs=10),
            ],
        )
        node.claim_vested(current_epoch=100)
        assert len(node.vesting_entries) == 0


# ---------------------------------------------------------------------------
# Slashing grace period
# ---------------------------------------------------------------------------


class TestSlashingGracePeriod:
    def test_pending_slash_creation(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        ps = engine.create_pending_slash(node, 100, SlashingTier.WARNING, current_epoch=0)
        assert ps.amount == 100
        assert ps.finalization_epoch == 168  # 7 days
        assert not ps.is_finalized(0)
        assert not ps.is_finalized(167)
        assert ps.is_finalized(168)

    def test_pending_slash_reversal(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        ps = engine.create_pending_slash(node, 100, SlashingTier.WARNING, current_epoch=0)
        assert engine.reverse_pending_slash(ps)
        assert ps.reversed
        assert not ps.is_finalized(200)  # reversed, never finalizes

    def test_double_reversal_fails(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        ps = engine.create_pending_slash(node, 100, SlashingTier.WARNING, current_epoch=0)
        engine.reverse_pending_slash(ps)
        assert not engine.reverse_pending_slash(ps)  # already reversed

    def test_finalize_pending_slashes(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        ps1 = engine.create_pending_slash(node, 100, SlashingTier.WARNING, current_epoch=0)
        ps2 = engine.create_pending_slash(node, 200, SlashingTier.MINOR, current_epoch=100)

        finalized = engine.finalize_pending_slashes(node, current_epoch=170)
        assert len(finalized) == 1  # only ps1
        assert finalized[0].amount == 100
        assert len(node.pending_slashes) == 1  # ps2 still pending

    def test_reversed_slashes_cleaned_on_finalize(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", stake=10_000, offense_count=1)
        ps = engine.create_pending_slash(node, 100, SlashingTier.WARNING, current_epoch=0)
        engine.reverse_pending_slash(ps)
        finalized = engine.finalize_pending_slashes(node, current_epoch=200)
        assert len(finalized) == 0
        assert len(node.pending_slashes) == 0


# ---------------------------------------------------------------------------
# Reward computation
# ---------------------------------------------------------------------------


class TestRewardComputation:
    def test_basic_storage_reward(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=100)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.storage_reward == 100 * engine.config.base_storage_reward_per_shard
        assert reward.storage_reward > 0

    def test_availability_reward(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=0)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.availability_reward == engine.config.base_availability_reward

    def test_audit_bonus_for_perfect_score(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1",
            stake=1000 * WEI_PER_LTP,
            shards_stored=100,
            audit_score=100,
        )
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.audit_bonus > 0

    def test_no_audit_bonus_for_imperfect_score(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1",
            stake=1000 * WEI_PER_LTP,
            shards_stored=100,
            audit_score=90,
        )
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.audit_bonus == 0

    def test_bootstrap_subsidy_at_epoch_0(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=50)
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=0)
        assert reward.bootstrap_subsidy > 0
        assert reward.phase == NetworkPhase.BOOTSTRAP

    def test_no_subsidy_after_growth(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=50)
        reward = engine.compute_node_reward(node, epoch=20000, fee_pool_share=0)
        assert reward.bootstrap_subsidy == 0
        assert reward.growth_subsidy == 0

    def test_fee_share_included(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n1", stake=1000 * WEI_PER_LTP, shards_stored=10)
        reward = engine.compute_node_reward(node, epoch=5000, fee_pool_share=50000)
        assert reward.fee_share == 50000
        assert reward.total >= 50000

    def test_cooldown_blocks_rewards(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1",
            stake=1000 * WEI_PER_LTP,
            shards_stored=100,
            cooldown_until_epoch=10,
        )
        reward = engine.compute_node_reward(node, epoch=5, fee_pool_share=10000)
        assert reward.total == 0

    def test_evicted_node_earns_nothing(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1",
            stake=1000 * WEI_PER_LTP,
            shards_stored=100,
            evicted=True,
        )
        reward = engine.compute_node_reward(node, epoch=0, fee_pool_share=10000)
        assert reward.total == 0

    def test_total_equals_sum_of_components(self):
        engine = EconomicsEngine()
        node = NodeEconomics(
            node_id="n1",
            stake=1000 * WEI_PER_LTP,
            shards_stored=100,
            audit_score=100,
        )
        r = engine.compute_node_reward(node, epoch=0, fee_pool_share=5000)
        expected = (
            r.storage_reward
            + r.availability_reward
            + r.audit_bonus
            + r.bootstrap_subsidy
            + r.growth_subsidy
            + r.fee_share
        )
        assert r.total == expected


# ---------------------------------------------------------------------------
# Epoch processing
# ---------------------------------------------------------------------------


class TestEpochProcessing:
    def _make_nodes(self, count: int, shards: int = 100) -> list[NodeEconomics]:
        return [
            NodeEconomics(
                node_id=f"node-{i}",
                stake=1000 * WEI_PER_LTP,
                shards_stored=shards,
                audit_score=100,
            )
            for i in range(count)
        ]

    def test_epoch_snapshot_fields(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(4)
        snap = engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=100)
        assert isinstance(snap, EpochSnapshot)
        assert snap.epoch == 0
        assert snap.phase == NetworkPhase.BOOTSTRAP
        assert snap.active_nodes == 4
        assert snap.total_staked > 0
        assert hasattr(snap, "total_fees_to_endowment")

    def test_rewards_distributed_to_all_active_nodes(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(5)
        snap = engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=50)
        assert len(snap.rewards) == 5
        assert all(r.total > 0 for r in snap.rewards)

    def test_evicted_nodes_excluded(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        nodes[2].evicted = True
        snap = engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=10)
        assert snap.active_nodes == 2
        assert len(snap.rewards) == 2

    def test_fees_burned_and_insured(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        snap = engine.process_epoch(
            epoch=5000,
            nodes=nodes,
            total_commitments_this_epoch=500,
            network_capacity=10000,
        )
        assert snap.total_fees_collected > 0
        assert snap.total_fees_burned > 0
        assert snap.total_fees_to_insurance > 0
        assert snap.total_fees_to_endowment > 0

    def test_cumulative_burn_tracking(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        engine.process_epoch(epoch=0, nodes=nodes, total_commitments_this_epoch=100)
        burn1 = engine.total_burned
        engine.process_epoch(epoch=1, nodes=nodes, total_commitments_this_epoch=100)
        burn2 = engine.total_burned
        assert burn2 > burn1

    def test_empty_network_returns_snapshot(self):
        engine = EconomicsEngine()
        snap = engine.process_epoch(epoch=0, nodes=[], total_commitments_this_epoch=0)
        assert snap.active_nodes == 0
        assert snap.total_rewards_distributed == 0

    def test_high_utilization_increases_fees(self):
        engine = EconomicsEngine()
        nodes = self._make_nodes(3)
        snap_low = engine.process_epoch(
            epoch=0,
            nodes=nodes,
            total_commitments_this_epoch=10,
            network_capacity=10000,
        )
        snap_high = engine.process_epoch(
            epoch=1,
            nodes=nodes,
            total_commitments_this_epoch=9000,
            network_capacity=10000,
        )
        assert snap_high.fee_multiplier > snap_low.fee_multiplier

    def test_fee_share_proportional_to_effective_stake(self):
        engine = EconomicsEngine()
        nodes = [
            NodeEconomics(node_id="big", stake=9000 * WEI_PER_LTP, shards_stored=100),
            NodeEconomics(node_id="small", stake=1000 * WEI_PER_LTP, shards_stored=100),
        ]
        snap = engine.process_epoch(
            epoch=5000,
            nodes=nodes,
            total_commitments_this_epoch=1000,
            network_capacity=10000,
        )
        big_reward = next(r for r in snap.rewards if r.node_id == "big")
        small_reward = next(r for r in snap.rewards if r.node_id == "small")
        assert big_reward.fee_share > small_reward.fee_share


# ---------------------------------------------------------------------------
# Capacity scaling
# ---------------------------------------------------------------------------


class TestCapacityScaling:
    def test_overloaded_node(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", shards_stored=20000)
        assert engine.is_node_overloaded(node)

    def test_not_overloaded_node(self):
        engine = EconomicsEngine()
        node = NodeEconomics(node_id="n", shards_stored=5000)
        assert not engine.is_node_overloaded(node)

    def test_recommended_node_count(self):
        engine = EconomicsEngine()
        assert engine.recommended_node_count(0) == 1
        assert engine.recommended_node_count(10000) == 1
        assert engine.recommended_node_count(10001) == 2
        assert engine.recommended_node_count(100000) == 10


# ---------------------------------------------------------------------------
# NodeEconomics properties
# ---------------------------------------------------------------------------


class TestNodeEconomics:
    def test_effective_stake_with_perfect_score(self):
        node = NodeEconomics(node_id="n", stake=10000, audit_score=100)
        assert node.effective_stake == 10000

    def test_effective_stake_degraded(self):
        node = NodeEconomics(node_id="n", stake=10000, audit_score=50)
        assert node.effective_stake == 5000

    def test_slashing_tier_property(self):
        node = NodeEconomics(node_id="n", offense_count=0)
        assert node.slashing_tier == SlashingTier.WARNING
        node.offense_count = 6
        assert node.slashing_tier == SlashingTier.CRITICAL


# ---------------------------------------------------------------------------
# Base L1 backend integration
# ---------------------------------------------------------------------------


class TestBaseL1EconomicsIntegration:
    def _create_backend(self):
        return create_backend(
            BackendConfig(
                backend_type="base-l1",
                enable_economics_engine=True,
                min_stake_wei=100 * WEI_PER_LTP,
            )
        )

    def test_economics_engine_initialized(self):
        backend = self._create_backend()
        assert backend.economics_engine is not None

    def test_register_node_creates_economics_entry(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=200 * WEI_PER_LTP)
        assert "node-0" in backend.node_economics
        assert backend.node_economics["node-0"].stake == 200 * WEI_PER_LTP

    def test_register_node_respects_dynamic_min_stake(self):
        backend = self._create_backend()
        result = backend.register_node("node-0", "US-East", stake_wei=50 * WEI_PER_LTP)
        assert result is False

    def test_pricing_includes_dynamic_fields(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=200 * WEI_PER_LTP)
        pricing = backend.get_pricing()
        assert "dynamic_commit_fee" in pricing
        assert "network_phase" in pricing
        assert pricing["network_phase"] == "bootstrap"
        assert "min_stake_required" in pricing
        assert "bootstrap_multiplier" in pricing
        assert "total_endowment" in pricing
        assert "total_burned" in pricing

    def test_process_epoch_distributes_rewards(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)
        backend.register_node("node-1", "US-West", stake_wei=500 * WEI_PER_LTP)
        backend.update_node_shards("node-0", 50)
        backend.update_node_shards("node-1", 50)

        initial_stake_0 = backend.node_economics["node-0"].stake

        snap = backend.process_epoch(epoch=0, commitments_this_epoch=100)
        assert snap is not None
        assert snap["phase"] == "bootstrap"
        assert snap["active_nodes"] == 2
        assert snap["total_rewards_distributed"] > 0

        # Immediate portion auto-compounded into stake
        assert backend.node_economics["node-0"].stake > initial_stake_0

    def test_process_epoch_creates_vesting_entries(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)
        backend.update_node_shards("node-0", 50)

        backend.process_epoch(epoch=0, commitments_this_epoch=100)
        node_econ = backend.node_economics["node-0"]
        # Should have vesting entries from the 50% deferred portion
        assert len(node_econ.vesting_entries) > 0
        assert node_econ.total_vesting > 0

    def test_slash_uses_progressive_tiers(self):
        backend = self._create_backend()
        initial_stake = 1000 * WEI_PER_LTP
        backend.register_node("node-0", "US-East", stake_wei=initial_stake)

        amt1 = backend.slash_node("node-0", b"evidence-1")
        assert amt1 == initial_stake * 100 // 10_000  # 1%

        node_econ = backend.node_economics["node-0"]
        assert node_econ.offense_count == 1

        remaining_stake = node_econ.stake
        amt2 = backend.slash_node("node-0", b"evidence-2")
        expected_amt2 = remaining_stake * 500 // 10_000  # 5%
        assert amt2 == expected_amt2
        assert node_econ.offense_count == 2

    def test_slash_with_correlation_penalty(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=1000 * WEI_PER_LTP)
        backend.register_node("node-1", "US-West", stake_wei=1000 * WEI_PER_LTP)

        # Slash node-0 without correlation context
        amt_solo = backend.slash_node("node-0", b"evidence")

        # Re-register for clean comparison
        backend2 = self._create_backend()
        backend2.register_node("node-0", "US-East", stake_wei=1000 * WEI_PER_LTP)
        backend2.register_node("node-1", "US-West", stake_wei=1000 * WEI_PER_LTP)

        # Slash with 50% of network stake concurrent
        amt_corr = backend2.slash_node(
            "node-0",
            b"evidence",
            concurrent_slashed_stake=1000 * WEI_PER_LTP,
        )
        assert amt_corr > amt_solo

    def test_slash_auto_evicts_at_critical(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=10000 * WEI_PER_LTP)

        for i in range(6):
            backend.slash_node("node-0", f"evidence-{i}".encode())

        assert backend.node_economics["node-0"].evicted is True

    def test_slash_creates_pending_slash(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=1000 * WEI_PER_LTP)

        backend.slash_node("node-0", b"evidence")
        node_econ = backend.node_economics["node-0"]
        assert len(node_econ.pending_slashes) > 0

    def test_process_epoch_returns_none_without_engine(self):
        backend = create_backend(
            BackendConfig(
                backend_type="base-l1",
                enable_economics_engine=False,
            )
        )
        assert backend.process_epoch(epoch=0) is None

    def test_epoch_commitment_counter_resets(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)

        from src.ltp.primitives import canonical_hash

        eid = canonical_hash(b"test-entity-1")
        backend.append_commitment(eid, b'{"test":true}', b"\x00" * 64, b"\x01" * 32)
        assert backend._epoch_commitment_count == 1

        backend.process_epoch(epoch=0)
        assert backend._epoch_commitment_count == 0

    def test_multiple_epochs_accumulate_snapshots(self):
        backend = self._create_backend()
        backend.register_node("node-0", "US-East", stake_wei=500 * WEI_PER_LTP)
        backend.update_node_shards("node-0", 10)

        for i in range(5):
            backend.process_epoch(epoch=i, commitments_this_epoch=50)

        assert len(backend.epoch_snapshots) == 5
        assert all(s["total_rewards_distributed"] > 0 for s in backend.epoch_snapshots)
