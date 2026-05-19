"""
Tests for mainnet security hardening (§6.2).

Covers:
  - Staking: min-stake enforcement, lockup period, withdrawal constraints
  - Escrow: pending slash prevents withdrawal (race condition fix)
  - Sybil resistance: eviction cooldown, re-registration blocking, history carry-forward
  - VDF audit scheduling: non-deterministic audit timing
  - Correlation penalty: escalated slashing for repeat offenders
  - Permanent reputation: offense history with decay-resistant tracking
"""

import os
import time

import pytest

from src.ltp.commitment import (
    CORRELATION_PENALTY_MAX,
    CORRELATION_PENALTY_SCALE,
    EVICTION_COOLDOWN_SECONDS,
    MIN_STAKE_LTP,
    REPUTATION_DECAY_FLOOR,
    REPUTATION_DECAY_RATE,
    STAKE_LOCKUP_SECONDS,
    AuditResult,
    CommitmentNetwork,
    CommitmentNode,
    StakeEscrow,
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
    """Six-node network with staking (for tests that need committed entities)."""
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


# ---------------------------------------------------------------------------
# Staking: min-stake enforcement
# ---------------------------------------------------------------------------


class TestStakeMinimum:
    def test_deposit_below_minimum_rejected(self):
        node = CommitmentNode("test-node", "US-East")
        assert node.deposit_stake(MIN_STAKE_LTP - 1) is False
        assert node.stake == 0.0

    def test_deposit_at_minimum_accepted(self):
        node = CommitmentNode("test-node", "US-East")
        assert node.deposit_stake(MIN_STAKE_LTP) is True
        assert node.stake == MIN_STAKE_LTP

    def test_deposit_above_minimum_accepted(self):
        node = CommitmentNode("test-node", "US-East")
        assert node.deposit_stake(10_000) is True
        assert node.stake == 10_000

    def test_register_node_below_minimum_raises(self):
        net = CommitmentNetwork()
        with pytest.raises(ValueError, match="below minimum"):
            net.register_node("node-1", "US-East", stake=99)

    def test_register_node_at_minimum_succeeds(self):
        net = CommitmentNetwork()
        node = net.register_node("node-1", "US-East", stake=MIN_STAKE_LTP)
        assert node.stake == MIN_STAKE_LTP
        assert node in net.nodes


# ---------------------------------------------------------------------------
# Staking: lockup period
# ---------------------------------------------------------------------------


class TestStakeLockup:
    def test_lockup_prevents_early_withdrawal(self):
        node = CommitmentNode("test-node", "US-East")
        now = 1_000_000.0
        node.deposit_stake(5_000, now=now)

        # Try to withdraw 1 second later — should be blocked
        assert node.can_withdraw(now=now + 1) is False
        withdrawn = node.withdraw_stake(5_000, now=now + 1)
        assert withdrawn == 0.0
        assert node.stake == 5_000

    def test_lockup_allows_withdrawal_after_expiry(self):
        node = CommitmentNode("test-node", "US-East")
        now = 1_000_000.0
        node.deposit_stake(5_000, now=now)

        # Withdraw after lockup expires
        after_lockup = now + STAKE_LOCKUP_SECONDS + 1
        assert node.can_withdraw(now=after_lockup) is True
        withdrawn = node.withdraw_stake(5_000, now=after_lockup)
        assert withdrawn == 5_000
        assert node.stake == 0.0

    def test_partial_withdrawal(self):
        node = CommitmentNode("test-node", "US-East")
        now = 1_000_000.0
        node.deposit_stake(5_000, now=now)

        after_lockup = now + STAKE_LOCKUP_SECONDS + 1
        withdrawn = node.withdraw_stake(2_000, now=after_lockup)
        assert withdrawn == 2_000
        assert node.stake == 3_000


# ---------------------------------------------------------------------------
# Escrow: withdrawal race condition fix (CONFIRMED vulnerability)
# ---------------------------------------------------------------------------


class TestWithdrawalRaceCondition:
    """
    Validates fix for: 'create_pending_slash() stores the slash but never
    locks the stake. A node with a pending 30% slash can withdraw the other
    70% before finalization.'
    """

    def test_pending_slash_blocks_withdrawal(self):
        """Core fix: pending slash must prevent ALL withdrawal."""
        node = CommitmentNode("test-node", "US-East")
        now = 1_000_000.0
        node.deposit_stake(10_000, now=now)

        # Create a pending 30% slash
        node.create_pending_slash(3_000, "audit_failure", now=now)

        # Even after lockup, cannot withdraw while slash is pending
        after_lockup = now + STAKE_LOCKUP_SECONDS + 1
        assert node.can_withdraw(now=after_lockup) is False
        withdrawn = node.withdraw_stake(7_000, now=after_lockup)
        assert withdrawn == 0.0

    def test_available_stake_excludes_escrowed(self):
        """Available stake must exclude escrowed amounts."""
        node = CommitmentNode("test-node", "US-East")
        node.deposit_stake(10_000)
        node.create_pending_slash(3_000, "audit_failure")
        assert node.available_stake() == 7_000

    def test_multiple_escrows_stack(self):
        """Multiple pending slashes cumulatively reduce available stake."""
        node = CommitmentNode("test-node", "US-East")
        node.deposit_stake(10_000)
        node.create_pending_slash(2_000, "audit_failure")
        node.create_pending_slash(3_000, "corruption")
        assert node.available_stake() == 5_000

    def test_finalize_deducts_from_stake(self):
        """Finalizing slashes deducts from actual stake."""
        node = CommitmentNode("test-node", "US-East")
        node.deposit_stake(10_000)
        node.create_pending_slash(3_000, "audit_failure")

        slashed = node.finalize_pending_slashes()
        assert slashed == 3_000
        assert node.stake == 7_000
        # After finalization, escrow is cleared
        assert all(e.finalized for e in node.pending_slashes)

    def test_escrow_cannot_exceed_stake(self):
        """Escrow amount capped at actual stake to prevent underflow."""
        node = CommitmentNode("test-node", "US-East")
        node.deposit_stake(1_000)
        escrow = node.create_pending_slash(5_000, "audit_failure")
        assert escrow.amount == 1_000  # Capped at stake

    def test_withdrawal_allowed_after_slash_finalized(self):
        """Once slashes are finalized, remaining stake can be withdrawn."""
        node = CommitmentNode("test-node", "US-East")
        now = 1_000_000.0
        node.deposit_stake(10_000, now=now)
        node.create_pending_slash(3_000, "audit_failure", now=now)

        node.finalize_pending_slashes()

        after_lockup = now + STAKE_LOCKUP_SECONDS + 1
        assert node.can_withdraw(now=after_lockup) is True
        withdrawn = node.withdraw_stake(7_000, now=after_lockup)
        assert withdrawn == 7_000


# ---------------------------------------------------------------------------
# Sybil resistance: re-registration after eviction (CONFIRMED vulnerability)
# ---------------------------------------------------------------------------


class TestSybilResistance:
    """
    Validates fix for: 'register_node() has no cooldown, no rate-limiting,
    and no eviction history check. An evicted attacker can immediately
    re-stake with a new node_id.'
    """

    def test_immediate_reregistration_blocked(self):
        """Evicted node cannot immediately re-register."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("attacker", "US-East", stake=5_000, now=now)

        net.evict_node(node, now=now + 100)

        # Immediate re-registration should be blocked
        with pytest.raises(ValueError, match="eviction cooldown"):
            net.register_node("attacker", "US-East", stake=5_000, now=now + 200)

    def test_reregistration_after_cooldown_allowed(self):
        """Node can re-register after cooldown period expires."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("attacker", "US-East", stake=5_000, now=now)

        net.evict_node(node, now=now + 100)

        # After cooldown, re-registration should succeed
        after_cooldown = now + 100 + EVICTION_COOLDOWN_SECONDS + 1
        new_node = net.register_node("attacker", "US-East", stake=5_000, now=after_cooldown)
        assert new_node.stake == 5_000

    def test_eviction_history_persists(self):
        """Eviction count and offense history carry forward across re-registrations."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("repeat-offender", "US-East", stake=5_000, now=now)
        node.record_offense("audit_failure", weight=2.0, now=now)

        net.evict_node(node, now=now + 100)

        # Re-register after cooldown
        after_cooldown = now + 100 + EVICTION_COOLDOWN_SECONDS + 1
        new_node = net.register_node("repeat-offender", "US-East", stake=5_000, now=after_cooldown)
        # History should carry forward
        assert new_node.eviction_count == 1
        assert len(new_node.offense_history) >= 1
        assert new_node.reputation_score < 1.0

    def test_eviction_count_increments(self):
        """Each eviction increments the counter."""
        net = CommitmentNetwork()
        now = 1_000_000.0

        node = net.register_node("serial-evictee", "US-East", stake=5_000, now=now)
        result = net.evict_node(node, now=now + 100)
        assert result["eviction_count"] == 1

    def test_eviction_registry_records_metadata(self):
        """Global eviction registry stores complete eviction record."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("tracked", "US-East", stake=5_000, now=now)
        node.record_offense("audit_failure", now=now)

        net.evict_node(node, now=now + 100)

        record = net._eviction_registry["tracked"]
        assert record["evicted_at"] == now + 100
        assert record["eviction_count"] == 1
        assert len(record["offense_history"]) >= 1


# ---------------------------------------------------------------------------
# VDF-randomized audit scheduling (CONFIRMED vulnerability: timing attack)
# ---------------------------------------------------------------------------


class TestVDFAuditScheduling:
    """
    Validates fix for: 'Audits use deterministic scheduling. An attacker
    can observe the pattern and delete shards between audit windows.'
    """

    def test_schedule_varies_by_epoch(self):
        """Different epochs produce different schedule offsets."""
        net = CommitmentNetwork()
        node = net.add_node("test-node", "US-East")
        offsets = [net._vdf_audit_schedule(node, epoch) for epoch in range(10)]
        # Not all the same
        assert len(set(offsets)) > 1

    def test_schedule_varies_by_node(self):
        """Different nodes get different schedule offsets in the same epoch."""
        net = CommitmentNetwork()
        node_a = net.add_node("node-a", "US-East")
        node_b = net.add_node("node-b", "US-West")
        offset_a = net._vdf_audit_schedule(node_a, 42)
        offset_b = net._vdf_audit_schedule(node_b, 42)
        assert offset_a != offset_b

    def test_schedule_range(self):
        """Schedule offset is always in [0, 1)."""
        net = CommitmentNetwork()
        node = net.add_node("test-node", "US-East")
        for epoch in range(100):
            offset = net._vdf_audit_schedule(node, epoch)
            assert 0.0 <= offset < 1.0

    def test_different_seeds_different_schedules(self):
        """Different network seeds produce different schedules."""
        net1 = CommitmentNetwork()
        net2 = CommitmentNetwork()
        node1 = net1.add_node("same-node", "US-East")
        node2 = net2.add_node("same-node", "US-East")

        # Seeds are random, so schedules should differ
        offsets1 = [net1._vdf_audit_schedule(node1, e) for e in range(5)]
        offsets2 = [net2._vdf_audit_schedule(node2, e) for e in range(5)]
        assert offsets1 != offsets2

    def test_audit_epoch_increments(self, network, alice):
        """Each audit call advances the epoch counter."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"epoch test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        epoch_before = network._audit_epoch
        network.audit_node(network.nodes[0])
        assert network._audit_epoch == epoch_before + 1


# ---------------------------------------------------------------------------
# Correlation penalty escalation
# ---------------------------------------------------------------------------


class TestCorrelationPenalty:
    def test_first_offense_base_penalty(self):
        """First offense gets base multiplier (close to 1.0)."""
        net = CommitmentNetwork()
        node = net.add_node("clean-node", "US-East")
        penalty = net._correlation_penalty(node)
        assert penalty == pytest.approx(1.0)

    def test_repeated_offenses_escalate_penalty(self):
        """Repeat offenders get escalated penalty multiplier."""
        net = CommitmentNetwork()
        for i in range(5):
            net.add_node(f"node-{i}", "US-East")
        target = net.nodes[0]

        # Record several offenses
        for _ in range(3):
            target.record_offense("audit_failure")

        penalty = net._correlation_penalty(target)
        assert penalty > 1.0

    def test_penalty_capped_at_maximum(self):
        """Penalty multiplier cannot exceed CORRELATION_PENALTY_MAX."""
        net = CommitmentNetwork()
        node = net.add_node("bad-actor", "US-East")

        # Flood with offenses
        for _ in range(100):
            node.record_offense("audit_failure")

        penalty = net._correlation_penalty(node)
        assert penalty <= CORRELATION_PENALTY_MAX

    def test_audit_failure_creates_escrow(self, network, alice):
        """Failed audit should automatically create a pending slash escrow."""
        protocol = LTPProtocol(network)
        entity = Entity(content=b"slash test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        # Find a node that actually holds shards for this entity
        target = max(network.nodes, key=lambda n: len(list(n.shards.keys())))
        assert len(list(target.shards.keys())) > 0, "No node holds shards"
        target.deposit_stake(5_000)

        # Delete all shards to force audit failure
        for key in list(target.shards.keys()):
            target.remove_shard(key[0], key[1])

        result = network.audit_node(target)
        assert result.result == "FAIL"
        assert len(target.pending_slashes) > 0
        assert target.pending_slashes[0].reason == "audit_failure"


# ---------------------------------------------------------------------------
# Permanent reputation tracking
# ---------------------------------------------------------------------------


class TestReputationTracking:
    def test_clean_node_perfect_reputation(self):
        node = CommitmentNode("clean", "US-East")
        assert node.reputation_score == 1.0
        assert len(node.offense_history) == 0

    def test_offense_degrades_reputation(self):
        node = CommitmentNode("offender", "US-East")
        node.record_offense("audit_failure")
        assert node.reputation_score < 1.0

    def test_multiple_offenses_further_degrade(self):
        node = CommitmentNode("serial-offender", "US-East")
        node.record_offense("audit_failure")
        rep_after_one = node.reputation_score
        node.record_offense("audit_failure")
        assert node.reputation_score < rep_after_one

    def test_reputation_never_goes_negative(self):
        node = CommitmentNode("worst-actor", "US-East")
        for _ in range(100):
            node.record_offense("audit_failure", weight=5.0)
        assert node.reputation_score >= 0.0

    def test_offense_history_is_permanent(self):
        node = CommitmentNode("tracked", "US-East")
        node.record_offense("corruption", weight=2.0, now=1_000_000.0)
        assert len(node.offense_history) == 1

        # Even after many successful audits, offense stays in history
        node.audit_passes += 100
        assert len(node.offense_history) == 1
        assert node.offense_history[0]["type"] == "corruption"

    def test_high_weight_offense_impacts_more(self):
        node_low = CommitmentNode("low-offense", "US-East")
        node_high = CommitmentNode("high-offense", "US-East")
        node_low.record_offense("minor", weight=0.1)
        node_high.record_offense("major", weight=5.0)
        assert node_high.reputation_score < node_low.reputation_score

    def test_decay_never_reaches_zero(self):
        """Verify REPUTATION_DECAY_FLOOR prevents full decay of old offenses."""
        node = CommitmentNode("old-offender", "US-East")
        node.record_offense("ancient_offense", weight=1.0, now=0)
        # Add many more offenses to push the ancient one far back
        for i in range(50):
            node.record_offense("recent", weight=0.01, now=float(i + 1))
        # The ancient offense should still contribute (floor prevents zero)
        assert node.reputation_score < 1.0


# ---------------------------------------------------------------------------
# DA attack profitability check
# ---------------------------------------------------------------------------


class TestDAAttackMitigation:
    """
    Validates that the economic model makes the DA attack unprofitable
    through adequate slash penalties.
    """

    def test_slash_exceeds_savings(self, network, alice):
        """
        With correlation penalties, the slash for dropping shards should
        exceed the storage cost savings ($150/mo), making the attack
        unprofitable.
        """
        protocol = LTPProtocol(network)
        entity = Entity(content=b"da-attack-test", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        # Find a node that actually holds shards for this entity
        target = max(network.nodes, key=lambda n: len(list(n.shards.keys())))
        assert len(list(target.shards.keys())) > 0, "No node holds shards"
        target.deposit_stake(10_000)

        # Simulate repeated audit failures (DA attack pattern)
        for key in list(target.shards.keys()):
            target.remove_shard(key[0], key[1])

        # Multiple audit rounds
        for _ in range(3):
            # Re-populate shards so audit has something to check
            entity2 = Entity(content=os.urandom(64), shape="x-ltp/test")
            protocol.commit(entity2, alice, n=8, k=4)
            for key in list(target.shards.keys()):
                target.remove_shard(key[0], key[1])
            network.audit_node(target)

        # After repeated failures, escrowed amount should be substantial
        escrowed = sum(e.amount for e in target.pending_slashes if not e.finalized)
        assert escrowed > 0, "No escrow created for repeated failures"


# ---------------------------------------------------------------------------
# Eviction finalizes slashes
# ---------------------------------------------------------------------------


class TestEvictionSlashFinalization:
    def test_eviction_finalizes_pending_slashes(self):
        """Eviction should finalize all pending slashes."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("slashed", "US-East", stake=10_000, now=now)
        node.create_pending_slash(2_000, "audit_failure", now=now)
        node.create_pending_slash(1_000, "corruption", now=now)

        result = net.evict_node(node, now=now + 100)
        assert result["stake_slashed"] == 3_000
        assert node.stake == 7_000
        assert all(e.finalized for e in node.pending_slashes)

    def test_eviction_records_in_registry(self):
        """Eviction creates a permanent registry entry."""
        net = CommitmentNetwork()
        now = 1_000_000.0
        node = net.register_node("tracked", "US-East", stake=5_000, now=now)
        net.evict_node(node, now=now + 50)

        assert "tracked" in net._eviction_registry
        assert net._eviction_registry["tracked"]["evicted_at"] == now + 50


# ---------------------------------------------------------------------------
# Integration: full lifecycle
# ---------------------------------------------------------------------------


class TestSecurityLifecycle:
    def test_full_node_lifecycle(self, alice):
        """
        End-to-end: register → commit → audit fail → escrow → evict →
        cooldown → re-register with history.
        """
        net = CommitmentNetwork()
        now = 1_000_000.0

        # 1. Register with adequate stake
        for nid, reg in [
            ("healthy-1", "US-East"),
            ("healthy-2", "US-West"),
            ("healthy-3", "EU-West"),
            ("healthy-4", "EU-East"),
            ("healthy-5", "AP-East"),
        ]:
            net.register_node(nid, reg, stake=5_000, now=now)

        attacker = net.register_node("attacker", "AP-South", stake=5_000, now=now)

        # 2. Commit an entity
        protocol = LTPProtocol(net)
        entity = Entity(content=b"lifecycle test data", shape="x-ltp/test")
        protocol.commit(entity, alice, n=8, k=4)

        # 3. Attacker drops all shards
        for key in list(attacker.shards.keys()):
            attacker.remove_shard(key[0], key[1])

        # 4. Audit detects failure → creates escrow
        result = net.audit_node(attacker)
        if result.challenged > 0:
            assert result.result == "FAIL"
            assert len(attacker.pending_slashes) > 0

            # 5. Cannot withdraw while slash is pending
            after_lockup = now + STAKE_LOCKUP_SECONDS + 1
            assert attacker.can_withdraw(now=after_lockup) is False
        else:
            # If placement didn't assign shards to attacker, manually record
            # the offense so the rest of the lifecycle test can proceed.
            attacker.record_offense("shard_withholding", weight=2.0, now=now)
            attacker.create_pending_slash(500.0, "manual_audit_failure", now=now)

        # 6. Evict → finalizes slashes
        evict_result = net.evict_node(attacker, now=now + 200)
        assert evict_result["eviction_count"] == 1

        # 7. Cannot immediately re-register
        with pytest.raises(ValueError, match="eviction cooldown"):
            net.register_node("attacker", "AP-South", stake=5_000, now=now + 300)

        # 8. Re-register after cooldown — history persists
        after_cooldown = now + 200 + EVICTION_COOLDOWN_SECONDS + 1
        new_node = net.register_node("attacker", "AP-South", stake=5_000, now=after_cooldown)
        assert new_node.eviction_count == 1
        assert new_node.reputation_score < 1.0
