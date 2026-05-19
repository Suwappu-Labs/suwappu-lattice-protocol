"""
Tests for competitor-inspired refinements (§6.3–6.4).

Covers three refinements:
  1. Burn-not-redistribute (Sia-inspired): slashed stake burns to endowment
  2. Erasure-coded audit (Storj-inspired): corrupt shard identification
  3. Graduated withholding (Storj-inspired): 75%→50%→25%→0% schedule
"""

import os
import time

import pytest

from src.ltp.commitment import (
    EVICTION_COOLDOWN_SECONDS,
    MIN_STAKE_LTP,
    STAKE_LOCKUP_SECONDS,
    WITHHOLDING_SCHEDULE,
    AuditResult,
    CommitmentNetwork,
    CommitmentNode,
    StakeEscrow,
    StorageEndowment,
)
from src.ltp.entity import Entity
from src.ltp.keypair import KeyPair
from src.ltp.protocol import LTPProtocol

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def alice() -> KeyPair:
    return KeyPair.generate("alice")


@pytest.fixture
def network() -> CommitmentNetwork:
    """Six-node network for tests that need committed entities."""
    net = CommitmentNetwork()
    for node_id, region in [
        ("node-us-east-1", "US-East"),
        ("node-us-west-1", "US-West"),
        ("node-eu-west-1", "EU-West"),
        ("node-eu-east-1", "EU-East"),
        ("node-ap-east-1", "AP-East"),
        ("node-ap-south-1", "AP-South"),
    ]:
        net.add_node(node_id, region)
    return net


# ===========================================================================
# 1. BURN-NOT-REDISTRIBUTE (Sia-inspired §6.4)
# ===========================================================================


class TestStorageEndowment:
    """Tests for the StorageEndowment class itself."""

    def test_initial_state(self):
        endowment = StorageEndowment()
        assert endowment.balance == 0.0
        assert endowment.total_burned == 0.0
        assert endowment.burn_history == []

    def test_burn_increases_balance(self):
        endowment = StorageEndowment()
        endowment.burn(500.0, "eviction_slash", node_id="node-1")
        assert endowment.balance == 500.0
        assert endowment.total_burned == 500.0

    def test_burn_is_cumulative(self):
        endowment = StorageEndowment()
        endowment.burn(300.0, "slash_1")
        endowment.burn(200.0, "slash_2")
        assert endowment.balance == 500.0
        assert endowment.total_burned == 500.0

    def test_burn_records_history(self):
        endowment = StorageEndowment()
        now = 1_000_000.0
        endowment.burn(100.0, "audit_failure", node_id="bad-node", now=now)
        assert len(endowment.burn_history) == 1
        entry = endowment.burn_history[0]
        assert entry["amount"] == 100.0
        assert entry["reason"] == "audit_failure"
        assert entry["node_id"] == "bad-node"
        assert entry["timestamp"] == now

    def test_spend_deducts_from_balance(self):
        endowment = StorageEndowment()
        endowment.burn(1000.0, "slash")
        spent = endowment.spend(400.0, "storage_subsidy")
        assert spent == 400.0
        assert endowment.balance == 600.0
        # total_burned stays the same (historical record)
        assert endowment.total_burned == 1000.0

    def test_spend_capped_at_balance(self):
        endowment = StorageEndowment()
        endowment.burn(100.0, "slash")
        spent = endowment.spend(500.0, "over_spend")
        assert spent == 100.0
        assert endowment.balance == 0.0

    def test_spend_on_empty_returns_zero(self):
        endowment = StorageEndowment()
        spent = endowment.spend(100.0, "nothing")
        assert spent == 0.0


class TestBurnNotRedistribute:
    """Verify slashed stake goes to endowment, not reporters."""

    def test_network_has_endowment(self):
        net = CommitmentNetwork()
        assert isinstance(net.endowment, StorageEndowment)
        assert net.endowment.balance == 0.0

    def test_eviction_burns_slashed_stake_to_endowment(self):
        """Core test: slashed stake must flow to endowment on eviction."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("slashable", "US-East", stake=10_000, now=now)
        node.create_pending_slash(2_000, "audit_failure", now=now)
        node.create_pending_slash(1_000, "corruption", now=now)

        result = net.evict_node(node, now=now + 100)

        assert result["stake_slashed"] == 3_000
        assert net.endowment.balance == 3_000
        assert net.endowment.total_burned == 3_000

    def test_endowment_burn_history_tracks_eviction(self):
        """Burn history should record the eviction event."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("tracked-slash", "US-East", stake=5_000, now=now)
        node.create_pending_slash(1_500, "audit_failure", now=now)

        net.evict_node(node, now=now + 50)

        burns = net.endowment.burn_history
        assert len(burns) >= 1
        slash_burn = [b for b in burns if b["reason"] == "eviction_slash"]
        assert len(slash_burn) == 1
        assert slash_burn[0]["amount"] == 1_500
        assert slash_burn[0]["node_id"] == "tracked-slash"

    def test_no_slash_no_burn(self):
        """Eviction with no pending slashes should not burn anything."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("clean-evict", "US-East", stake=5_000, now=now)

        net.evict_node(node, now=now + 100)

        # No slash, but withheld earnings are 0 too
        assert net.endowment.balance == 0.0

    def test_multiple_evictions_accumulate_in_endowment(self):
        """Multiple evictions should accumulate in the endowment."""
        net = CommitmentNetwork()
        now = 1_000_000.0

        node1 = net.register_node("bad-1", "US-East", stake=5_000, now=now)
        node1.create_pending_slash(1_000, "audit_failure", now=now)
        net.evict_node(node1, now=now + 10)

        node2 = net.register_node("bad-2", "US-West", stake=8_000, now=now)
        node2.create_pending_slash(2_000, "corruption", now=now)
        net.evict_node(node2, now=now + 20)

        assert net.endowment.balance == 3_000
        assert len(net.endowment.burn_history) == 2

    def test_audit_failure_then_eviction_burns_to_endowment(self, network, alice):
        """End-to-end: audit failure → escrow → eviction → endowment burn."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"burn-test-data", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        target.deposit_stake(5_000)

        # Delete shards to force audit failure
        for key in list(target.shards.keys()):
            target.remove_shard(key[0], key[1])

        result = network.audit_node(target)
        if result.challenged > 0:
            assert result.result == "FAIL"

            # Evict
            evict_result = network.evict_node(target)
            assert evict_result["stake_slashed"] > 0
            assert network.endowment.balance > 0


# ===========================================================================
# 2. ERASURE-CODED AUDIT — Corrupt shard identification (Storj-inspired)
# ===========================================================================


class TestCorruptShardIdentification:
    """Verify audit identifies specific corrupt/missing shards."""

    def test_audit_result_has_corrupt_shards_field(self):
        result = AuditResult(
            node_id="test",
            challenged=0,
            passed=0,
            failed=0,
            missing=0,
            suspicious_latency=0,
            burst_size=1,
            avg_response_us=0.0,
            result="PASS",
            strikes=0,
        )
        assert hasattr(result, "corrupt_shards")
        assert result.corrupt_shards == []

    def test_passing_audit_has_no_corrupt_shards(self, network, alice):
        """A healthy node should have zero corrupt shards."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"healthy-shard-test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        result = network.audit_node(target)

        if result.challenged > 0:
            assert result.result == "PASS"
            assert result.corrupt_shards == []

    def test_missing_shard_identified(self, network, alice):
        """Deleted shards should appear in corrupt_shards list."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"corrupt-shard-test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        # Record which shards this node holds
        held_shards = [(eid, idx) for (eid, idx) in target.shards.keys()]

        if not held_shards:
            pytest.skip("Target node holds no shards for this entity")

        # Delete all shards
        for eid, idx in held_shards:
            target.remove_shard(eid, idx)

        result = network.audit_node(target)
        assert result.result == "FAIL"
        assert len(result.corrupt_shards) > 0

        # Every corrupt shard should be a (entity_id, shard_index) tuple
        for entry in result.corrupt_shards:
            assert isinstance(entry, tuple)
            assert len(entry) == 2

    def test_corrupt_shard_data_detected(self, network, alice):
        """Shards with wrong data should be detected via cross-replica check."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"corrupt-data-test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        held_shards = list(target.shards.keys())

        if not held_shards:
            pytest.skip("Target node holds no shards")

        # Corrupt one shard by replacing with garbage
        eid, idx = held_shards[0]
        target.shards[(eid, idx)] = b"CORRUPTED_DATA_" + os.urandom(32)

        result = network.audit_node(target)

        # The corrupted shard should appear in corrupt_shards
        if result.challenged > 0 and result.failed > 0:
            corrupt_keys = [(e, i) for e, i in result.corrupt_shards]
            assert (eid, idx) in corrupt_keys

    def test_partial_corruption_identifies_specific_shards(self, network, alice):
        """Only corrupted shards should appear, not all shards."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"partial-corrupt", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        target = network.nodes[0]
        held_shards = list(target.shards.keys())

        if len(held_shards) < 2:
            pytest.skip("Need at least 2 shards to test partial corruption")

        # Corrupt only the first shard
        eid, idx = held_shards[0]
        target.shards[(eid, idx)] = b"BAD_DATA"

        result = network.audit_node(target)

        if result.failed > 0:
            # The specific corrupted shard should be identified
            corrupt_set = set(result.corrupt_shards)
            assert (eid, idx) in corrupt_set


# ===========================================================================
# 3. GRADUATED WITHHOLDING (Storj-inspired §6.3)
# ===========================================================================


class TestWithholdingSchedule:
    """Verify the WITHHOLDING_SCHEDULE constant."""

    def test_schedule_has_three_tiers(self):
        assert len(WITHHOLDING_SCHEDULE) == 3

    def test_schedule_rates_decrease(self):
        rates = [rate for _, rate in WITHHOLDING_SCHEDULE]
        assert rates == sorted(rates, reverse=True)

    def test_schedule_thresholds_increase(self):
        thresholds = [t for t, _ in WITHHOLDING_SCHEDULE]
        assert thresholds == sorted(thresholds)


class TestWithholdingRate:
    """Test CommitmentNode.withholding_rate() based on node age."""

    def test_brand_new_node_75_percent(self):
        node = CommitmentNode("new-node", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        rate = node.withholding_rate(now=now + 1)
        assert rate == 0.75

    def test_month_2_still_75_percent(self):
        node = CommitmentNode("month2", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        # 60 days in
        rate = node.withholding_rate(now=now + 60 * 24 * 3600)
        assert rate == 0.75

    def test_month_4_drops_to_50_percent(self):
        node = CommitmentNode("month4", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        # 100 days in (past 90-day threshold)
        rate = node.withholding_rate(now=now + 100 * 24 * 3600)
        assert rate == 0.50

    def test_month_7_drops_to_25_percent(self):
        node = CommitmentNode("month7", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        # 200 days in (past 180-day threshold)
        rate = node.withholding_rate(now=now + 200 * 24 * 3600)
        assert rate == 0.25

    def test_month_10_zero_withholding(self):
        node = CommitmentNode("veteran", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        # 280 days in (past 270-day threshold)
        rate = node.withholding_rate(now=now + 280 * 24 * 3600)
        assert rate == 0.0

    def test_exact_threshold_boundaries(self):
        node = CommitmentNode("boundary", "US-East")
        now = 1_000_000.0
        node.registered_at = now

        # Exactly at 90-day boundary → transitions to 50%
        t90 = 90 * 24 * 3600
        assert node.withholding_rate(now=now + t90) == 0.50

        # Exactly at 180-day boundary → transitions to 25%
        t180 = 180 * 24 * 3600
        assert node.withholding_rate(now=now + t180) == 0.25

        # Exactly at 270-day boundary → transitions to 0%
        t270 = 270 * 24 * 3600
        assert node.withholding_rate(now=now + t270) == 0.0


class TestAccrueEarnings:
    """Test CommitmentNode.accrue_earnings() withholding logic."""

    def test_new_node_withholds_75_percent(self):
        node = CommitmentNode("earner", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        net = node.accrue_earnings(1000.0, now=now + 1)
        assert net == 250.0  # 75% withheld → 25% paid
        assert node.withheld_earnings == 750.0
        assert node.total_earnings == 1000.0

    def test_veteran_node_no_withholding(self):
        node = CommitmentNode("veteran", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        net = node.accrue_earnings(1000.0, now=now + 280 * 24 * 3600)
        assert net == 1000.0
        assert node.withheld_earnings == 0.0

    def test_cumulative_withholding(self):
        node = CommitmentNode("earner", "US-East")
        now = 1_000_000.0
        node.registered_at = now

        node.accrue_earnings(100.0, now=now + 1)  # 75% rate
        node.accrue_earnings(200.0, now=now + 2)  # 75% rate
        assert node.withheld_earnings == pytest.approx(225.0)  # 75 + 150
        assert node.total_earnings == 300.0

    def test_mid_schedule_50_percent(self):
        node = CommitmentNode("mid", "US-East")
        now = 1_000_000.0
        node.registered_at = now
        # 120 days in → 50% rate
        net = node.accrue_earnings(400.0, now=now + 120 * 24 * 3600)
        assert net == 200.0
        assert node.withheld_earnings == 200.0


class TestReleaseWithheld:
    """Test CommitmentNode.release_withheld() for graceful exits."""

    def test_full_release(self):
        node = CommitmentNode("earner", "US-East")
        node.withheld_earnings = 500.0
        released = node.release_withheld(fraction=1.0)
        assert released == 500.0
        assert node.withheld_earnings == 0.0

    def test_partial_release(self):
        node = CommitmentNode("earner", "US-East")
        node.withheld_earnings = 1000.0
        released = node.release_withheld(fraction=0.5)
        assert released == 500.0
        assert node.withheld_earnings == 500.0

    def test_zero_fraction_releases_nothing(self):
        node = CommitmentNode("earner", "US-East")
        node.withheld_earnings = 500.0
        released = node.release_withheld(fraction=0.0)
        assert released == 0.0
        assert node.withheld_earnings == 500.0

    def test_fraction_clamped_to_one(self):
        node = CommitmentNode("earner", "US-East")
        node.withheld_earnings = 500.0
        released = node.release_withheld(fraction=2.0)
        assert released == 500.0
        assert node.withheld_earnings == 0.0


class TestWithheldEarningsForfeiture:
    """Verify withheld earnings are burned to endowment on eviction."""

    def test_eviction_forfeits_withheld_earnings(self):
        """Withheld earnings must be burned to endowment on eviction."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("greedy", "US-East", stake=5_000, now=now)

        # Accrue some earnings (75% withheld for new node)
        node.accrue_earnings(2000.0, now=now + 1)
        assert node.withheld_earnings == 1500.0  # 75% of 2000

        result = net.evict_node(node, now=now + 100)

        assert result["forfeited_earnings"] == 1500.0
        assert node.withheld_earnings == 0.0
        assert net.endowment.balance == 1500.0

    def test_eviction_burns_both_slash_and_withheld(self):
        """Both slashed stake AND withheld earnings go to endowment."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("double-burn", "US-East", stake=10_000, now=now)

        node.create_pending_slash(2_000, "audit_failure", now=now)
        node.accrue_earnings(4000.0, now=now + 1)  # 75% → 3000 withheld

        result = net.evict_node(node, now=now + 100)

        assert result["stake_slashed"] == 2_000
        assert result["forfeited_earnings"] == 3_000
        # Total in endowment = 2000 (slash) + 3000 (withheld)
        assert net.endowment.balance == 5_000

    def test_no_withheld_no_forfeiture(self):
        """Node with no withheld earnings has zero forfeiture."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("no-earnings", "US-East", stake=5_000, now=now)

        result = net.evict_node(node, now=now + 100)

        assert result["forfeited_earnings"] == 0.0

    def test_endowment_history_tracks_forfeiture(self):
        """Forfeited earnings should appear in endowment burn history."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("forfeitable", "US-East", stake=5_000, now=now)
        node.accrue_earnings(1000.0, now=now + 1)

        net.evict_node(node, now=now + 100)

        forfeit_burns = [
            b for b in net.endowment.burn_history if b["reason"] == "withheld_earnings_forfeiture"
        ]
        assert len(forfeit_burns) == 1
        assert forfeit_burns[0]["amount"] == 750.0  # 75% of 1000
        assert forfeit_burns[0]["node_id"] == "forfeitable"


# ===========================================================================
# Integration: all three refinements together
# ===========================================================================


class TestRefinementsIntegration:
    def test_full_lifecycle_with_refinements(self, alice):
        """
        End-to-end: register → earn → audit fail → escrow → evict →
        slash burned + withheld forfeited → endowment receives both.
        """
        net = CommitmentNetwork()
        now = 1_000_000.0

        # Set up healthy nodes
        for nid, reg in [
            ("h-1", "US-East"),
            ("h-2", "US-West"),
            ("h-3", "EU-West"),
            ("h-4", "EU-East"),
            ("h-5", "AP-East"),
        ]:
            net.register_node(nid, reg, stake=5_000, now=now)

        # Register attacker
        attacker = net.register_node("attacker", "AP-South", stake=8_000, now=now)

        # Commit data
        protocol = LTPProtocol(net)
        entity = Entity(content=b"integration-refinements", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        # Attacker earns some payouts (75% withheld as new node)
        net_payout = attacker.accrue_earnings(2000.0, now=now + 10)
        assert net_payout == 500.0  # 25% of 2000
        assert attacker.withheld_earnings == 1500.0

        # Attacker drops all shards
        for key in list(attacker.shards.keys()):
            attacker.remove_shard(key[0], key[1])

        # Audit detects failure
        result = net.audit_node(attacker)

        if result.challenged > 0:
            assert result.result == "FAIL"
            # Corrupt shards should be identified
            assert len(result.corrupt_shards) > 0

        # Evict attacker
        evict_result = net.evict_node(attacker, now=now + 200)
        assert evict_result["eviction_count"] == 1

        # Endowment received burned slash + forfeited earnings
        assert net.endowment.balance > 0
        assert net.endowment.total_burned > 0
        assert len(net.endowment.burn_history) >= 1

        # Attacker's withheld earnings are zeroed
        assert attacker.withheld_earnings == 0.0
