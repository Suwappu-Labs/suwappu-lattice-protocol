"""
Node admission protocol tests.

Tests m-of-n endorsement voting, admission state machine, endorsement
signature creation/verification, and CommitmentNetwork integration.

All tests are deterministic — no threads, no sleeps.
"""

from __future__ import annotations

import pytest

from src.ltp import CommitmentNetwork, KeyPair
from src.ltp.node.admission import (
    AdmissionRecord,
    AdmissionState,
    EndorsementVote,
    InvalidAdmissionTransition,
    NodeAdmissionManager,
    create_endorsement,
    verify_endorsement,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def operator_a() -> KeyPair:
    return KeyPair.generate("operator-a")


@pytest.fixture(scope="session")
def operator_b() -> KeyPair:
    return KeyPair.generate("operator-b")


@pytest.fixture(scope="session")
def operator_c() -> KeyPair:
    return KeyPair.generate("operator-c")


@pytest.fixture(scope="session")
def applicant() -> KeyPair:
    return KeyPair.generate("applicant-node")


# ---------------------------------------------------------------------------
# AdmissionState
# ---------------------------------------------------------------------------


class TestAdmissionState:
    def test_all_states_exist(self):
        assert AdmissionState.APPLYING.value == "applying"
        assert AdmissionState.ENDORSED.value == "endorsed"
        assert AdmissionState.ADMITTED.value == "admitted"
        assert AdmissionState.ACTIVE.value == "active"
        assert AdmissionState.SUSPENDED.value == "suspended"
        assert AdmissionState.EVICTED.value == "evicted"

    def test_six_states_total(self):
        assert len(AdmissionState) == 6


# ---------------------------------------------------------------------------
# Endorsement Signatures
# ---------------------------------------------------------------------------


class TestEndorsementVote:
    def test_create_endorsement(self, operator_a):
        vote = create_endorsement(operator_a, "node-1")
        assert vote.applicant_node_id == "node-1"
        assert len(vote.signature) > 0
        assert vote.endorser_label == "operator-a"

    def test_verify_endorsement(self, operator_a):
        vote = create_endorsement(operator_a, "node-2")
        assert verify_endorsement(vote, operator_a.vk) is True

    def test_verify_wrong_vk_rejected(self, operator_a, operator_b):
        vote = create_endorsement(operator_a, "node-3")
        assert verify_endorsement(vote, operator_b.vk) is False

    def test_tampered_signature_rejected(self, operator_a):
        vote = create_endorsement(operator_a, "node-4")
        tampered = EndorsementVote(
            endorser_vk_hash=vote.endorser_vk_hash,
            applicant_node_id=vote.applicant_node_id,
            signature=b"\x00" * 64,
            timestamp=vote.timestamp,
        )
        assert verify_endorsement(tampered, operator_a.vk) is False


# ---------------------------------------------------------------------------
# NodeAdmissionManager — Core Flow
# ---------------------------------------------------------------------------


class TestNodeAdmissionManager:
    def test_apply(self, applicant):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        rec = mgr.apply("node-1", canonical_hash(applicant.vk))
        assert rec.state == AdmissionState.APPLYING
        assert rec.required_endorsements == 2

    def test_endorse_below_threshold(self, applicant, operator_a):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("node-1", canonical_hash(applicant.vk))

        vote = create_endorsement(operator_a, "node-1")
        rec = mgr.endorse("node-1", vote)
        assert rec.state == AdmissionState.APPLYING  # 1/2, not enough
        assert len(rec.endorsements) == 1

    def test_endorse_reaches_threshold(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("node-1", canonical_hash(applicant.vk))

        mgr.endorse("node-1", create_endorsement(operator_a, "node-1"))
        rec = mgr.endorse("node-1", create_endorsement(operator_b, "node-1"))
        assert rec.state == AdmissionState.ENDORSED  # 2/2

    def test_full_lifecycle(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("node-lc", canonical_hash(applicant.vk))
        mgr.endorse("node-lc", create_endorsement(operator_a, "node-lc"))
        mgr.endorse("node-lc", create_endorsement(operator_b, "node-lc"))

        rec = mgr.admit("node-lc")
        assert rec.state == AdmissionState.ADMITTED
        assert rec.admitted_at > 0

        rec = mgr.activate("node-lc")
        assert rec.state == AdmissionState.ACTIVE
        assert rec.activated_at > 0


# ---------------------------------------------------------------------------
# Endorsement Threshold Variants
# ---------------------------------------------------------------------------


class TestEndorsementThreshold:
    def test_2_of_3(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("t23", canonical_hash(applicant.vk))
        mgr.endorse("t23", create_endorsement(operator_a, "t23"))
        rec = mgr.endorse("t23", create_endorsement(operator_b, "t23"))
        assert rec.state == AdmissionState.ENDORSED

    def test_3_of_5(self, applicant, operator_a, operator_b, operator_c):
        mgr = NodeAdmissionManager(m=3, n=5)
        from src.ltp.primitives import canonical_hash

        mgr.apply("t35", canonical_hash(applicant.vk))
        mgr.endorse("t35", create_endorsement(operator_a, "t35"))
        mgr.endorse("t35", create_endorsement(operator_b, "t35"))
        rec = mgr.endorse("t35", create_endorsement(operator_c, "t35"))
        assert rec.state == AdmissionState.ENDORSED

    def test_insufficient_endorsements(self, applicant, operator_a):
        mgr = NodeAdmissionManager(m=3, n=5)
        from src.ltp.primitives import canonical_hash

        mgr.apply("insuf", canonical_hash(applicant.vk))
        rec = mgr.endorse("insuf", create_endorsement(operator_a, "insuf"))
        assert rec.state == AdmissionState.APPLYING  # 1/3, not enough

    def test_duplicate_endorser_rejected(self, applicant, operator_a):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("dup", canonical_hash(applicant.vk))
        mgr.endorse("dup", create_endorsement(operator_a, "dup"))

        with pytest.raises(ValueError, match="already endorsed"):
            mgr.endorse("dup", create_endorsement(operator_a, "dup"))


# ---------------------------------------------------------------------------
# State Transitions
# ---------------------------------------------------------------------------


class TestAdmissionStateTransitions:
    def test_applying_to_admitted_rejected(self, applicant):
        """Cannot skip endorsement step."""
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("skip", canonical_hash(applicant.vk))
        with pytest.raises(InvalidAdmissionTransition):
            mgr.admit("skip")

    def test_applying_to_active_rejected(self, applicant):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("skip2", canonical_hash(applicant.vk))
        with pytest.raises(InvalidAdmissionTransition):
            mgr.activate("skip2")

    def test_evicted_cannot_reactivate(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("evict", canonical_hash(applicant.vk))
        mgr.endorse("evict", create_endorsement(operator_a, "evict"))
        mgr.endorse("evict", create_endorsement(operator_b, "evict"))
        mgr.admit("evict")
        mgr.activate("evict")
        mgr.evict("evict", "misbehavior")

        with pytest.raises(InvalidAdmissionTransition):
            mgr.reactivate("evict")

    def test_duplicate_application_rejected(self, applicant):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("dup-app", canonical_hash(applicant.vk))
        with pytest.raises(ValueError, match="already has active"):
            mgr.apply("dup-app", canonical_hash(applicant.vk))


# ---------------------------------------------------------------------------
# Integration with CommitmentNetwork
# ---------------------------------------------------------------------------


class TestAdmissionWithNetwork:
    def test_register_with_admission_gate(self, applicant, operator_a, operator_b):
        """register_node requires ADMITTED status when admission_manager is set."""
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("gated", canonical_hash(applicant.vk))
        mgr.endorse("gated", create_endorsement(operator_a, "gated"))
        mgr.endorse("gated", create_endorsement(operator_b, "gated"))
        mgr.admit("gated")

        network = CommitmentNetwork()
        node = network.register_node("gated", "US-East", 1500.0, admission_manager=mgr)
        assert node.node_id == "gated"

    def test_register_rejected_without_admission(self, applicant):
        """register_node rejects unadmitted nodes when gate is active."""
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("ungated", canonical_hash(applicant.vk))

        network = CommitmentNetwork()
        with pytest.raises(ValueError, match="admission status"):
            network.register_node("ungated", "US-East", 1500.0, admission_manager=mgr)

    def test_register_without_gate_backward_compat(self):
        """Without admission_manager, register_node works as before."""
        network = CommitmentNetwork()
        node = network.register_node("nogate", "US-East", 1500.0)
        assert node.node_id == "nogate"

    def test_register_no_admission_record_rejected(self):
        """Node with no admission record is rejected when gate is active."""
        mgr = NodeAdmissionManager(m=2, n=3)
        network = CommitmentNetwork()
        with pytest.raises(ValueError, match="no admission record"):
            network.register_node("unknown", "US-East", 1500.0, admission_manager=mgr)


# ---------------------------------------------------------------------------
# Suspension and Eviction
# ---------------------------------------------------------------------------


class TestSuspensionAndEviction:
    def test_suspend_active_node(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("susp", canonical_hash(applicant.vk))
        mgr.endorse("susp", create_endorsement(operator_a, "susp"))
        mgr.endorse("susp", create_endorsement(operator_b, "susp"))
        mgr.admit("susp")
        mgr.activate("susp")

        rec = mgr.suspend("susp", "audit failure")
        assert rec.state == AdmissionState.SUSPENDED
        assert rec.rejection_reason == "audit failure"

    def test_reactivate_suspended_node(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("react", canonical_hash(applicant.vk))
        mgr.endorse("react", create_endorsement(operator_a, "react"))
        mgr.endorse("react", create_endorsement(operator_b, "react"))
        mgr.admit("react")
        mgr.activate("react")
        mgr.suspend("react", "temp issue")

        rec = mgr.reactivate("react")
        assert rec.state == AdmissionState.ACTIVE

    def test_evict_active_node(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("ev", canonical_hash(applicant.vk))
        mgr.endorse("ev", create_endorsement(operator_a, "ev"))
        mgr.endorse("ev", create_endorsement(operator_b, "ev"))
        mgr.admit("ev")
        mgr.activate("ev")

        rec = mgr.evict("ev", "permanent ban")
        assert rec.state == AdmissionState.EVICTED
        assert rec.rejection_reason == "permanent ban"

    def test_evict_suspended_node(self, applicant, operator_a, operator_b):
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("evs", canonical_hash(applicant.vk))
        mgr.endorse("evs", create_endorsement(operator_a, "evs"))
        mgr.endorse("evs", create_endorsement(operator_b, "evs"))
        mgr.admit("evs")
        mgr.activate("evs")
        mgr.suspend("evs", "issue")

        rec = mgr.evict("evs", "final")
        assert rec.state == AdmissionState.EVICTED


# ---------------------------------------------------------------------------
# Audit Fixes
# ---------------------------------------------------------------------------


class TestAuditFixes:
    """Tests for issues found during 5A/5B audit."""

    def test_endorsement_signature_verified_by_manager(self, applicant, operator_a):
        """endorse() with endorser_vk verifies signature."""
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("sigcheck", canonical_hash(applicant.vk))

        vote = create_endorsement(operator_a, "sigcheck")
        # Should succeed with correct VK
        rec = mgr.endorse("sigcheck", vote, endorser_vk=operator_a.vk)
        assert len(rec.endorsements) == 1

    def test_bad_endorsement_signature_rejected_by_manager(self, applicant, operator_a, operator_b):
        """endorse() with wrong endorser_vk rejects the vote."""
        mgr = NodeAdmissionManager(m=2, n=3)
        from src.ltp.primitives import canonical_hash

        mgr.apply("badsig", canonical_hash(applicant.vk))

        vote = create_endorsement(operator_a, "badsig")
        # Wrong VK should fail
        with pytest.raises(ValueError, match="signature verification failed"):
            mgr.endorse("badsig", vote, endorser_vk=operator_b.vk)

    def test_snapshot_isolation(self, applicant, operator_a):
        """Snapshot copies don't share endorsement list with internal state."""
        mgr = NodeAdmissionManager(m=3, n=5)
        from src.ltp.primitives import canonical_hash

        mgr.apply("iso", canonical_hash(applicant.vk))

        snap1 = mgr.get("iso")
        assert len(snap1.endorsements) == 0

        mgr.endorse("iso", create_endorsement(operator_a, "iso"))

        # Original snapshot should NOT have the new endorsement
        assert len(snap1.endorsements) == 0

        snap2 = mgr.get("iso")
        assert len(snap2.endorsements) == 1
