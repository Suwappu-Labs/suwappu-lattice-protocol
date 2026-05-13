"""Tests for MysticetiAdapter lifecycle and CommitteeSync integration (Spec D1b §5-6)."""

import hashlib

import pytest

from src.ltp.consensus.adapter import MysticetiAdapter
from src.ltp.consensus.events import ConsensusEvent, ConsensusEventType
from src.ltp.consensus.validator_set import ValidatorSet
from src.ltp.execution.consensus import ConsensusAdapter
from src.ltp.execution.types import OrderedBatch
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.writer import IdentityTier

from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.types import DKGSessionConfig


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
        vm_tag=1, epoch=epoch, active_members=members,
        standby_members=[], formed_at=0, formation_round=0,
    )


def _run_dkg(n: int, threshold: int, epoch: int = 1):
    participants = [f"validator-{i}".encode() for i in range(n)]
    cfg = DKGSessionConfig(
        vm_tag=1, epoch=epoch, threshold=threshold,
        participants=participants, timeout_rounds=10, start_round=0,
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
    """Minimal CommitteeManager stub for adapter tests."""

    def __init__(
        self,
        roster: CommitteeRoster | None = None,
        epoch: int = 1,
        signing_keys: dict | None = None,
    ) -> None:
        self._roster = roster
        self._epoch = epoch
        self._signing_keys: dict = signing_keys or {}

    @property
    def roster(self):
        return self._roster

    @property
    def epoch(self):
        return self._epoch

    def has_dkg_result(self, epoch: int) -> bool:
        return epoch in self._signing_keys

    def tick(self, current_round: int, timestamp_ms: int) -> bool:
        return False

    def advance_epoch(self, new_epoch: int, new_roster: CommitteeRoster):
        """Test helper: simulate epoch advance."""
        self._epoch = new_epoch
        self._roster = new_roster

    def evict_member(self, writer_fp: bytes):
        """Test helper: remove a member from active roster."""
        if self._roster is None:
            return
        self._roster.active_members = [
            m for m in self._roster.active_members
            if m.writer_fp != writer_fp
        ]


# ---------------------------------------------------------------------------
# Module-scoped DKG fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dkg_4():
    return _run_dkg(4, 3, epoch=1)


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------

class TestProtocolCompliance:

    def test_satisfies_consensus_adapter_protocol(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        assert isinstance(adapter, ConsensusAdapter)
        adapter.stop()

    def test_consensus_type_returns_mysticeti_dag(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        assert adapter.consensus_type() == "mysticeti-dag"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:

    def test_start_stop(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        assert adapter._running is True
        adapter.stop()
        assert adapter._running is False

    def test_start_without_roster_raises(self):
        cm = FakeCommitteeManager(roster=None)
        adapter = MysticetiAdapter(cm)
        with pytest.raises(RuntimeError, match="No roster"):
            adapter.start()

    def test_submit_transaction_returns_hash(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        tx = b"hello-transaction"
        tx_hash = adapter.submit_transaction(tx)
        assert tx_hash == hashlib.sha3_256(tx).digest()
        adapter.stop()

    def test_current_round_increments(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        assert adapter.current_round() == -1
        adapter.drive_rounds(1)
        assert adapter.current_round() == 0
        adapter.stop()


# ---------------------------------------------------------------------------
# Batch production
# ---------------------------------------------------------------------------

class TestBatchProduction:

    def test_drive_rounds_yields_ordered_batches(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"tx-for-batch")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        for b in batches:
            assert isinstance(b, OrderedBatch)
        adapter.stop()

    def test_ordered_batch_has_correct_consensus_type(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"tx1")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        assert batches[0].consensus_type == "dag"
        adapter.stop()

    def test_four_validators_produce_commits(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"tx4v")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        adapter.stop()

    def test_seven_validators_produce_commits(self):
        cm = FakeCommitteeManager(roster=_make_roster(7))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"tx7v")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        adapter.stop()

    def test_transactions_appear_in_batches(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"payload-A")
        adapter.submit_transaction(b"payload-B")
        batches = adapter.drive_rounds(5)
        all_txs = []
        for b in batches:
            all_txs.extend(b.transactions)
        assert b"payload-A" in all_txs
        assert b"payload-B" in all_txs
        adapter.stop()


# ---------------------------------------------------------------------------
# BLS integration
# ---------------------------------------------------------------------------

class TestBLSIntegration:

    def test_batches_with_bls_signing(self, dkg_4):
        keys, group_pk = dkg_4
        cm = FakeCommitteeManager(
            roster=_make_roster(4),
            signing_keys={1: keys},
        )
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"bls-tx")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        attested = [
            e for e in adapter.events()
            if e.event_type == ConsensusEventType.COMMIT_ATTESTED
        ]
        assert len(attested) > 0
        adapter.stop()

    def test_adapter_works_without_dkg_keys(self):
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"no-bls-tx")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        adapter.stop()


# ---------------------------------------------------------------------------
# Epoch and eviction via tick
# ---------------------------------------------------------------------------

class TestEpochAndEviction:

    def test_tick_detects_epoch_advance(self):
        roster_e1 = _make_roster(4, epoch=1)
        cm = FakeCommitteeManager(roster=roster_e1, epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        roster_e2 = _make_roster(4, epoch=2)
        cm.advance_epoch(2, roster_e2)

        events = adapter.tick(100, 50000)
        epoch_events = [
            e for e in events
            if e.event_type == ConsensusEventType.EPOCH_TRANSITION
        ]
        assert len(epoch_events) == 1
        assert epoch_events[0].payload["old_epoch"] == 1
        assert epoch_events[0].payload["new_epoch"] == 2
        adapter.stop()

    def test_tick_detects_eviction(self):
        roster = _make_roster(4, epoch=1)
        cm = FakeCommitteeManager(roster=roster, epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.evict_member(b"validator-1")

        events = adapter.tick(50, 25000)
        evicted = [
            e for e in events
            if e.event_type == ConsensusEventType.VALIDATOR_EVICTED
        ]
        assert len(evicted) == 1
        assert evicted[0].payload["writer_fp"] == b"validator-1"
        assert evicted[0].payload["validator_index"] == 1
        adapter.stop()

    def test_events_recorded_in_history(self):
        roster = _make_roster(4, epoch=1)
        cm = FakeCommitteeManager(roster=roster, epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()
        assert len(adapter.events()) == 0

        cm.evict_member(b"validator-0")
        adapter.tick(10, 5000)
        assert len(adapter.events()) >= 1
        adapter.stop()
