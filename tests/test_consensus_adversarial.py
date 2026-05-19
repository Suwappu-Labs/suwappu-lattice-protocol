"""Adversarial and edge-case tests for consensus adapter (Spec D1b §8)."""

import pytest

from src.ltp.consensus.adapter import MysticetiAdapter
from src.ltp.consensus.events import ConsensusEventType
from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    combine_partial_signatures,
    partial_sign,
    threshold_verify,
)
from src.ltp.execution.committee.dkg.types import DKGSessionConfig
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.writer import IdentityTier

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_roster(n: int, epoch: int = 1) -> CommitteeRoster:
    members = [
        CommitteeMember(
            writer_fp=f"validator-{i}".encode(),
            bls_pk=bytes([i]) * 48,
            tier=IdentityTier.COMPOSITE,
            joined_epoch=0,
            role=CommitteeRole.ACTIVE,
        )
        for i in range(n)
    ]
    return CommitteeRoster(
        vm_tag=1,
        epoch=epoch,
        active_members=members,
        standby_members=[],
        formed_at=0,
        formation_round=0,
    )


def _run_dkg(n: int, threshold: int, epoch: int = 1):
    participants = [f"validator-{i}".encode() for i in range(n)]
    cfg = DKGSessionConfig(
        vm_tag=1,
        epoch=epoch,
        threshold=threshold,
        participants=participants,
        timeout_rounds=10,
        start_round=0,
    )
    sessions = [DKGSession(cfg, fp, idx + 1) for idx, fp in enumerate(participants)]

    commitments, all_shares = [], []
    for s in sessions:
        c, shares = s.begin()
        commitments.append(c)
        all_shares.append(shares)

    for s in sessions:
        for c in commitments:
            if c.dealer_fp != s.my_fp:
                s.receive_commitment(c)
        s.end_commitment_phase()

    for i, s in enumerate(sessions):
        fp = participants[i]
        for shares in all_shares:
            if fp in shares:
                s.receive_share(shares[fp])
        s.end_sharing_phase()

    signing_keys, group_pk = [], None
    for s in sessions:
        result, key = s.finalize()
        signing_keys.append(key)
        if group_pk is None:
            group_pk = result.group_pk

    return signing_keys, group_pk


class FakeCommitteeManager:
    def __init__(self, roster=None, epoch=1, signing_keys=None):
        self._roster = roster
        self._epoch = epoch
        self._signing_keys = signing_keys or {}

    @property
    def roster(self):
        return self._roster

    @property
    def epoch(self):
        return self._epoch

    def has_dkg_result(self, epoch):
        return epoch in self._signing_keys

    def tick(self, current_round, timestamp_ms):
        return False

    def advance_epoch(self, new_epoch, new_roster):
        self._epoch = new_epoch
        self._roster = new_roster

    def evict_member(self, writer_fp):
        if self._roster is None:
            return
        self._roster.active_members = [
            m for m in self._roster.active_members if m.writer_fp != writer_fp
        ]


# ---------------------------------------------------------------------------
# Module-scoped fixtures for BLS tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dkg_4():
    return _run_dkg(4, 3, epoch=1)


@pytest.fixture(scope="module")
def dkg_4_epoch2():
    return _run_dkg(4, 3, epoch=2)


# ---------------------------------------------------------------------------
# Eviction scenarios
# ---------------------------------------------------------------------------


class TestEvictionScenarios:
    def test_evicted_validator_blocks_excluded(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"pre-evict")
        adapter.drive_rounds(2)

        cm.evict_member(b"validator-0")
        adapter.tick(2, 10000)

        adapter.submit_transaction(b"post-evict")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        adapter.stop()

    def test_double_eviction_is_idempotent(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.evict_member(b"validator-1")
        events1 = adapter.tick(10, 5000)
        events2 = adapter.tick(11, 6000)

        evictions = [
            e for e in events1 + events2 if e.event_type == ConsensusEventType.VALIDATOR_EVICTED
        ]
        assert len(evictions) == 1
        adapter.stop()

    def test_eviction_of_leader_round(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.drive_rounds(1)

        cm.evict_member(b"validator-1")
        adapter.tick(1, 5000)

        adapter.submit_transaction(b"after-leader-evict")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        adapter.stop()

    def test_submit_after_stop_raises(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.stop()
        with pytest.raises(RuntimeError):
            adapter.submit_transaction(b"too-late")

    def test_all_validators_evicted_halts_liveness(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()

        for i in range(4):
            cm.evict_member(f"validator-{i}".encode())
        adapter.tick(0, 0)

        assert adapter._validator_set is not None
        assert adapter._validator_set.active_count() == 0
        adapter.stop()


# ---------------------------------------------------------------------------
# Epoch transition scenarios
# ---------------------------------------------------------------------------


class TestEpochTransitions:
    def test_validator_set_grow_4_to_7(self):
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"epoch1-tx")
        adapter.drive_rounds(3)

        cm.advance_epoch(2, _make_roster(7, epoch=2))
        events = adapter.tick(100, 50000)
        epoch_events = [e for e in events if e.event_type == ConsensusEventType.EPOCH_TRANSITION]
        assert len(epoch_events) == 1
        assert epoch_events[0].payload["validator_count"] == 7

        rebuilt = [e for e in adapter.events() if e.event_type == ConsensusEventType.ENGINE_REBUILT]
        assert len(rebuilt) == 1
        assert rebuilt[0].payload["validator_count"] == 7
        adapter.stop()

    def test_validator_set_shrink_7_to_4(self):
        cm = FakeCommitteeManager(roster=_make_roster(7, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(100, 50000)

        rebuilt = [e for e in adapter.events() if e.event_type == ConsensusEventType.ENGINE_REBUILT]
        assert len(rebuilt) == 1
        assert rebuilt[0].payload["validator_count"] == 4
        adapter.stop()

    def test_epoch_advance_during_active_rounds(self):
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"inflight-tx")
        adapter.drive_rounds(3)

        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(50, 25000)

        adapter.submit_transaction(b"post-epoch-tx")
        post_batches = adapter.drive_rounds(5)
        assert len(post_batches) > 0
        adapter.stop()

    def test_concurrent_epoch_and_eviction(self):
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        new_roster = _make_roster(4, epoch=2)
        cm.advance_epoch(2, new_roster)
        cm.evict_member(b"validator-3")

        events = adapter.tick(100, 50000)
        types = {e.event_type for e in events}
        assert ConsensusEventType.EPOCH_TRANSITION in types
        adapter.stop()

    def test_multiple_rapid_epoch_advances(self):
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(10, 5000)

        cm.advance_epoch(3, _make_roster(4, epoch=3))
        adapter.tick(20, 10000)

        epoch_events = [
            e for e in adapter.events() if e.event_type == ConsensusEventType.EPOCH_TRANSITION
        ]
        assert len(epoch_events) == 2
        assert epoch_events[0].payload["new_epoch"] == 2
        assert epoch_events[1].payload["new_epoch"] == 3
        adapter.stop()


# ---------------------------------------------------------------------------
# BLS edge cases
# ---------------------------------------------------------------------------


class TestBLSEdgeCases:
    def test_bls_sig_from_previous_epoch_fails(self, dkg_4, dkg_4_epoch2):
        keys_e1, _ = dkg_4
        _, gpk_e2 = dkg_4_epoch2
        msg = b"cross-epoch-test"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_e1[:3]]
        sig = combine_partial_signatures(partials, 3)
        assert threshold_verify(gpk_e2, msg, sig, DOMAIN_ATTESTATION) is False

    def test_epoch_without_dkg_keys_graceful_degradation(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"no-dkg")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        attested = [
            e for e in adapter.events() if e.event_type == ConsensusEventType.COMMIT_ATTESTED
        ]
        assert len(attested) == 0
        adapter.stop()

    def test_zero_transaction_rounds_with_bls(self, dkg_4):
        keys, group_pk = dkg_4
        cm = FakeCommitteeManager(
            roster=_make_roster(4),
            signing_keys={1: keys},
        )
        adapter = MysticetiAdapter(cm)
        adapter.start()
        batches = adapter.drive_rounds(3)
        adapter.stop()

    def test_engine_rebuilt_stream_continues(self):
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"pre-rebuild")
        adapter.drive_rounds(3)

        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(50, 25000)

        adapter.submit_transaction(b"post-rebuild")
        post = adapter.drive_rounds(5)
        assert len(post) > 0
        adapter.stop()

    def test_eviction_at_commit_round_still_valid(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"evict-round-tx")
        batches = adapter.drive_rounds(3)

        cm.evict_member(b"validator-2")
        adapter.tick(3, 15000)

        assert len(batches) > 0
        adapter.stop()

    def test_sig_verification_across_epoch_boundary(self, dkg_4):
        keys, group_pk = dkg_4
        msg = b"cross-epoch-attestation"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys[:3]]
        sig = combine_partial_signatures(partials, 3)
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION) is True

    def test_stale_validator_after_removal(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.evict_member(b"validator-3")
        adapter.tick(0, 0)

        assert adapter._validator_set.is_evicted(b"validator-3") is True
        tx_hash = adapter.submit_transaction(b"from-stale")
        assert len(tx_hash) == 32
        adapter.stop()

    def test_roster_mismatch_detected(self):
        """Roster has fewer members than validator set — evictions detected."""
        roster = _make_roster(4)
        cm = FakeCommitteeManager(roster=roster, epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        # Remove 2 members from roster (simulating external evictions)
        cm.evict_member(b"validator-0")
        cm.evict_member(b"validator-2")
        events = adapter.tick(5, 2500)

        evicted = [e for e in events if e.event_type == ConsensusEventType.VALIDATOR_EVICTED]
        assert len(evicted) == 2
        fps = {e.payload["writer_fp"] for e in evicted}
        assert fps == {b"validator-0", b"validator-2"}
        adapter.stop()
