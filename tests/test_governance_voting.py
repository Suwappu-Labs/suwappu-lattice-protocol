"""
Operator supermajority voting for phase transitions.

Tests vote creation/verification, TransitionVoteManager with
supermajority threshold, and integration with GovernanceTransition.
"""

from __future__ import annotations

import pytest

from src.ltp import KeyPair
from src.ltp.enforcement import (
    DecentralizationMetrics,
    GovernanceTransition,
)
from src.ltp.governance import (
    TransitionVote,
    TransitionVoteManager,
    create_transition_vote,
    verify_transition_vote,
)
from src.ltp.primitives import canonical_hash

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def op_a() -> KeyPair:
    return KeyPair.generate("op-a")


@pytest.fixture(scope="session")
def op_b() -> KeyPair:
    return KeyPair.generate("op-b")


@pytest.fixture(scope="session")
def op_c() -> KeyPair:
    return KeyPair.generate("op-c")


@pytest.fixture(scope="session")
def op_d() -> KeyPair:
    return KeyPair.generate("op-d")


@pytest.fixture(scope="session")
def op_e() -> KeyPair:
    return KeyPair.generate("op-e")


# ---------------------------------------------------------------------------
# TransitionVote
# ---------------------------------------------------------------------------


class TestTransitionVote:
    def test_create_vote(self, op_a):
        vote = create_transition_vote(op_a, "bootstrap", "growth")
        assert vote.from_phase == "bootstrap"
        assert vote.to_phase == "growth"
        assert vote.voter_vk_hash == canonical_hash(op_a.vk)
        assert len(vote.signature) > 0

    def test_verify_vote(self, op_a):
        vote = create_transition_vote(op_a, "bootstrap", "growth")
        assert verify_transition_vote(vote, op_a.vk) is True

    def test_verify_wrong_vk_rejected(self, op_a, op_b):
        vote = create_transition_vote(op_a, "bootstrap", "growth")
        assert verify_transition_vote(vote, op_b.vk) is False

    def test_tampered_vote_rejected(self, op_a):
        vote = create_transition_vote(op_a, "bootstrap", "growth")
        tampered = TransitionVote(
            voter_vk_hash=vote.voter_vk_hash,
            from_phase="growth",  # Changed!
            to_phase="maturity",  # Changed!
            signature=vote.signature,
            timestamp=vote.timestamp,
        )
        assert verify_transition_vote(tampered, op_a.vk) is False


# ---------------------------------------------------------------------------
# TransitionVoteManager
# ---------------------------------------------------------------------------


class TestTransitionVoteManager:
    def test_register_and_cast(self, op_a):
        mgr = TransitionVoteManager()
        mgr.register_operator("op-a", canonical_hash(op_a.vk))

        vote = create_transition_vote(op_a, "bootstrap", "growth")
        tally = mgr.cast_vote("bootstrap->growth", vote)
        assert tally["votes"] == 1
        assert tally["total_operators"] == 1

    def test_tally_tracking(self, op_a, op_b):
        mgr = TransitionVoteManager()
        mgr.register_operator("op-a", canonical_hash(op_a.vk))
        mgr.register_operator("op-b", canonical_hash(op_b.vk))

        mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))
        tally = mgr.cast_vote(
            "bootstrap->growth", create_transition_vote(op_b, "bootstrap", "growth")
        )

        assert tally["votes"] == 2
        assert tally["total_operators"] == 2

    def test_duplicate_vote_rejected(self, op_a):
        mgr = TransitionVoteManager()
        mgr.register_operator("op-a", canonical_hash(op_a.vk))

        mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))
        with pytest.raises(ValueError, match="already voted"):
            mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))

    def test_unregistered_voter_rejected(self, op_a):
        mgr = TransitionVoteManager()
        # op_a not registered
        with pytest.raises(ValueError, match="not a registered operator"):
            mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))

    def test_vote_signature_verified(self, op_a, op_b):
        mgr = TransitionVoteManager()
        mgr.register_operator("op-a", canonical_hash(op_a.vk))

        vote = create_transition_vote(op_a, "bootstrap", "growth")
        # Correct VK passes
        mgr.cast_vote("bootstrap->growth", vote, voter_vk=op_a.vk)

    def test_bad_vote_signature_rejected(self, op_a, op_b):
        mgr = TransitionVoteManager()
        mgr.register_operator("op-a", canonical_hash(op_a.vk))

        vote = create_transition_vote(op_a, "bootstrap", "growth")
        with pytest.raises(ValueError, match="signature verification failed"):
            mgr.cast_vote("bootstrap->growth", vote, voter_vk=op_b.vk)


# ---------------------------------------------------------------------------
# Supermajority Threshold
# ---------------------------------------------------------------------------


class TestSupermajority:
    def test_2_of_3_passes(self, op_a, op_b, op_c):
        """2/3 = 66.7% — meets >=2/3 threshold."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))

        mgr.cast_vote("b->g", create_transition_vote(op_a, "bootstrap", "growth"))
        assert not mgr.has_supermajority("b->g")

        mgr.cast_vote("b->g", create_transition_vote(op_b, "bootstrap", "growth"))
        assert mgr.has_supermajority("b->g")  # 2/3 = 66.7% >= 66.7%

    def test_1_of_3_fails(self, op_a, op_b, op_c):
        """1/3 = 33% — below threshold."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))

        mgr.cast_vote("b->g", create_transition_vote(op_a, "bootstrap", "growth"))
        assert not mgr.has_supermajority("b->g")

    def test_3_of_5_fails(self, op_a, op_b, op_c, op_d, op_e):
        """3/5 = 60% — below 66.7% threshold. Need 4."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        for kp, label in [(op_a, "a"), (op_b, "b"), (op_c, "c"), (op_d, "d"), (op_e, "e")]:
            mgr.register_operator(label, canonical_hash(kp.vk))

        for kp in [op_a, op_b, op_c]:
            mgr.cast_vote("b->g", create_transition_vote(kp, "bootstrap", "growth"))

        assert not mgr.has_supermajority("b->g")  # 3/5 = 60% < 66.7%

    def test_4_of_5_passes(self, op_a, op_b, op_c, op_d, op_e):
        """4/5 = 80% — above threshold."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        for kp, label in [(op_a, "a"), (op_b, "b"), (op_c, "c"), (op_d, "d"), (op_e, "e")]:
            mgr.register_operator(label, canonical_hash(kp.vk))

        for kp in [op_a, op_b, op_c, op_d]:
            mgr.cast_vote("b->g", create_transition_vote(kp, "bootstrap", "growth"))

        assert mgr.has_supermajority("b->g")  # 4/5 = 80% >= 66.7%


# ---------------------------------------------------------------------------
# Execute If Ready
# ---------------------------------------------------------------------------


class TestExecuteIfReady:
    def _make_metrics(self, operators: int = 10, hhi: float = 1000.0, gini: float = 0.3):
        return DecentralizationMetrics(
            active_operators=operators,
            hhi=hhi,
            gini_coefficient=gini,
            governance_participation=0.20,
            foundation_veto_active=True,
        )

    def test_supermajority_and_metrics_pass(self, op_a, op_b, op_c):
        """Supermajority + metrics pass → transition executes."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))

        for kp in [op_a, op_b]:
            mgr.cast_vote("bootstrap->growth", create_transition_vote(kp, "bootstrap", "growth"))

        gt = GovernanceTransition()
        metrics = self._make_metrics(operators=10)  # Passes BOOTSTRAP→GROWTH (needs ≥5)

        result = mgr.execute_if_ready("bootstrap->growth", gt, metrics)
        assert result is True

    def test_supermajority_but_metrics_fail(self, op_a, op_b, op_c):
        """Supermajority but metrics fail → no transition."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))

        for kp in [op_a, op_b]:
            mgr.cast_vote("growth->maturity", create_transition_vote(kp, "growth", "maturity"))

        gt = GovernanceTransition()
        # Execute bootstrap→growth first so we can test growth→maturity
        gt.execute_transition("bootstrap", "growth", self._make_metrics(operators=10))

        # Metrics for GROWTH→MATURITY fail (need 100 operators, HHI<2500, Gini<0.65)
        bad_metrics = self._make_metrics(operators=5)  # Only 5, need 100

        result = mgr.execute_if_ready("growth->maturity", gt, bad_metrics)
        assert result is False  # Supermajority reached, but metrics fail

    def test_no_supermajority(self, op_a, op_b, op_c):
        """No supermajority → no transition regardless of metrics."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))

        # Only 1 vote
        mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))

        gt = GovernanceTransition()
        metrics = self._make_metrics(operators=10)

        result = mgr.execute_if_ready("bootstrap->growth", gt, metrics)
        assert result is None


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    def test_execute_distinguishes_no_supermajority_from_metrics_fail(self, op_a, op_b, op_c):
        """None = no supermajority, False = metrics fail, True = executed."""
        mgr = TransitionVoteManager(required_ratio=2 / 3)
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.register_operator("b", canonical_hash(op_b.vk))
        mgr.register_operator("c", canonical_hash(op_c.vk))

        gt = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=1000.0,
            gini_coefficient=0.3,
            governance_participation=0.2,
            foundation_veto_active=True,
        )

        # No votes yet → None
        result = mgr.execute_if_ready("bootstrap->growth", gt, metrics)
        assert result is None

        # Add supermajority votes
        mgr.cast_vote("bootstrap->growth", create_transition_vote(op_a, "bootstrap", "growth"))
        mgr.cast_vote("bootstrap->growth", create_transition_vote(op_b, "bootstrap", "growth"))

        # Supermajority + good metrics → True
        result = mgr.execute_if_ready("bootstrap->growth", gt, metrics)
        assert result is True

    def test_zero_operators_no_supermajority(self):
        """With zero registered operators, supermajority is never reached."""
        mgr = TransitionVoteManager()
        assert not mgr.has_supermajority("any_key")
        tally = mgr.get_tally("any_key")
        assert tally["total_operators"] == 0
        assert tally["has_supermajority"] is False

    def test_invalid_transition_key_format(self, op_a, op_b):
        """execute_if_ready raises on malformed transition_key."""
        mgr = TransitionVoteManager()
        mgr.register_operator("a", canonical_hash(op_a.vk))
        mgr.cast_vote("bad_key", create_transition_vote(op_a, "bootstrap", "growth"))

        gt = GovernanceTransition()
        metrics = DecentralizationMetrics(
            active_operators=10,
            hhi=1000.0,
            gini_coefficient=0.3,
            governance_participation=0.2,
            foundation_veto_active=True,
        )
        with pytest.raises(ValueError, match="Invalid transition_key format"):
            mgr.execute_if_ready("bad_key", gt, metrics)
