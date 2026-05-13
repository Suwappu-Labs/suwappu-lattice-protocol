# Consensus Adapter and Validator Management (D1b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the D1a Mysticeti DAG engine to the ETP execution pipeline via `MysticetiAdapter` (implementing `ConsensusAdapter`), with BLS-signed certificates, validator identity mapping, epoch transitions, and mid-epoch eviction.

**Architecture:** Layered + event-driven hybrid. Six source modules with strict dependencies: `events.py` and `validator_set.py` are leaf nodes; `bls_certificates.py` and `backend.py` depend on D1a/C3c only; `committee_sync.py` bridges CommitteeManager to consensus events; `adapter.py` orchestrates everything and implements the `ConsensusAdapter` protocol.

**Tech Stack:** Python 3.12+, pytest + Hypothesis, BLS12-381 via py_ecc, threshold signing from C3c, Mysticeti engine from D1a

---

## File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/ltp/consensus/events.py` | `ConsensusEventType` enum, `ConsensusEvent` frozen dataclass |
| Create | `src/ltp/consensus/validator_set.py` | `ValidatorInfo`, `ValidatorSet` — identity mapping + eviction tracking |
| Create | `src/ltp/consensus/bls_certificates.py` | `SignedCertificate`, `BLSCertificateManager` — BLS partial signing, aggregation, verification |
| Create | `src/ltp/consensus/backend.py` | `ConsensusBackend` ABC, `LocalConsensusBackend` wrapping `LocalMysticetiEngine` |
| Create | `src/ltp/consensus/committee_sync.py` | `CommitteeSync` — bridges CommitteeManager epochs/evictions to consensus events |
| Create | `src/ltp/consensus/adapter.py` | `MysticetiAdapter` — implements `ConsensusAdapter`, orchestrates all D1b components |
| Modify | `src/ltp/consensus/__init__.py` | Add D1b exports |
| Create | `tests/test_consensus_events.py` | Event type and payload tests (~8) |
| Create | `tests/test_consensus_validator_set.py` | ValidatorSet identity mapping and eviction tests (~14) |
| Create | `tests/test_consensus_bls_certs.py` | BLS signing, aggregation, verification tests (~16) |
| Create | `tests/test_consensus_backend.py` | Backend abstraction and delegation tests (~12) |
| Create | `tests/test_consensus_adapter.py` | MysticetiAdapter lifecycle and integration tests (~15) |
| Create | `tests/test_consensus_adversarial.py` | Adversarial edge-case scenarios (~18) |

---

### Task 1: Event System

**Files:**
- Create: `src/ltp/consensus/events.py`
- Test: `tests/test_consensus_events.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_consensus_events.py
"""Tests for consensus event types (Spec D1b §1)."""

import pytest

from src.ltp.consensus.events import ConsensusEvent, ConsensusEventType


class TestConsensusEventType:
    """ConsensusEventType enum tests."""

    def test_enum_has_four_values(self):
        assert len(ConsensusEventType) == 4

    def test_epoch_transition_exists(self):
        assert ConsensusEventType.EPOCH_TRANSITION.value == "epoch_transition"

    def test_validator_evicted_exists(self):
        assert ConsensusEventType.VALIDATOR_EVICTED.value == "validator_evicted"

    def test_commit_attested_exists(self):
        assert ConsensusEventType.COMMIT_ATTESTED.value == "commit_attested"

    def test_engine_rebuilt_exists(self):
        assert ConsensusEventType.ENGINE_REBUILT.value == "engine_rebuilt"


class TestConsensusEvent:
    """ConsensusEvent dataclass tests."""

    def test_event_creation_with_all_fields(self):
        event = ConsensusEvent(
            event_type=ConsensusEventType.EPOCH_TRANSITION,
            epoch=5,
            round=1000,
            timestamp_ms=1234567890,
            payload={"old_epoch": 4, "new_epoch": 5},
        )
        assert event.event_type == ConsensusEventType.EPOCH_TRANSITION
        assert event.epoch == 5
        assert event.round == 1000
        assert event.timestamp_ms == 1234567890
        assert event.payload == {"old_epoch": 4, "new_epoch": 5}

    def test_event_is_frozen(self):
        event = ConsensusEvent(
            event_type=ConsensusEventType.COMMIT_ATTESTED,
            epoch=1,
            round=10,
            timestamp_ms=0,
            payload={},
        )
        with pytest.raises(AttributeError):
            event.epoch = 2  # type: ignore[misc]

    def test_each_event_type_has_distinct_payload_keys(self):
        """Verify expected payload shapes per event type."""
        epoch_payload = {
            "old_epoch": 0, "new_epoch": 1,
            "validator_count": 4, "dkg_completed": True,
        }
        evicted_payload = {
            "writer_fp": b"\x01" * 32, "validator_index": 2,
            "reason": "crash", "remaining_active": 3,
        }
        attested_payload = {
            "round": 5, "batch_digest": b"\xab" * 32,
            "signature": b"\xcd" * 96,
        }
        rebuilt_payload = {
            "epoch": 2, "validator_count": 7,
            "quorum_threshold": 5,
        }

        for event_type, payload in [
            (ConsensusEventType.EPOCH_TRANSITION, epoch_payload),
            (ConsensusEventType.VALIDATOR_EVICTED, evicted_payload),
            (ConsensusEventType.COMMIT_ATTESTED, attested_payload),
            (ConsensusEventType.ENGINE_REBUILT, rebuilt_payload),
        ]:
            event = ConsensusEvent(
                event_type=event_type,
                epoch=1, round=0, timestamp_ms=0,
                payload=payload,
            )
            assert event.payload == payload
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_events.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.consensus.events'`

- [ ] **Step 3: Write the implementation**

```python
# src/ltp/consensus/events.py
"""Consensus event system (Spec D1b §1)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ConsensusEventType(Enum):
    """Types of consensus-layer events."""

    EPOCH_TRANSITION = "epoch_transition"
    VALIDATOR_EVICTED = "validator_evicted"
    COMMIT_ATTESTED = "commit_attested"
    ENGINE_REBUILT = "engine_rebuilt"


@dataclass(frozen=True)
class ConsensusEvent:
    """A single consensus-layer event with typed payload."""

    event_type: ConsensusEventType
    epoch: int
    round: int
    timestamp_ms: int
    payload: dict
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_events.py -v`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/events.py tests/test_consensus_events.py
git commit -m "feat(d1b): add consensus event system — ConsensusEventType enum and ConsensusEvent frozen dataclass"
```

---

### Task 2: ValidatorSet

**Files:**
- Create: `src/ltp/consensus/validator_set.py`
- Test: `tests/test_consensus_validator_set.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_consensus_validator_set.py
"""Tests for validator set identity mapping (Spec D1b §2)."""

import pytest

from src.ltp.consensus.validator_set import ValidatorInfo, ValidatorSet
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.writer import IdentityTier


def _make_roster(n: int, epoch: int = 1) -> CommitteeRoster:
    """Build a CommitteeRoster with n active members."""
    members = [
        CommitteeMember(
            writer_fp=f"validator-{i}".encode(),
            bls_pk=bytes([i]) * 48,
            tier=IdentityTier.FULL,
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


class TestValidatorInfo:
    """ValidatorInfo frozen dataclass tests."""

    def test_creation(self):
        info = ValidatorInfo(
            writer_fp=b"fp1",
            bls_pk=b"\x01" * 48,
            validator_index=0,
        )
        assert info.writer_fp == b"fp1"
        assert info.validator_index == 0

    def test_frozen(self):
        info = ValidatorInfo(writer_fp=b"fp", bls_pk=b"\x00" * 48, validator_index=0)
        with pytest.raises(AttributeError):
            info.validator_index = 1  # type: ignore[misc]


class TestValidatorSet:
    """ValidatorSet identity mapping and eviction tests."""

    def test_from_roster_builds_correct_set(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.epoch == 1
        assert vs.size == 4

    def test_index_for_fp_round_trip(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        fp = b"validator-2"
        idx = vs.index_for(fp)
        assert idx == 2
        assert vs.fp_for(idx) == fp

    def test_bls_pk_for_index(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.bls_pk_for(0) == bytes([0]) * 48
        assert vs.bls_pk_for(3) == bytes([3]) * 48

    def test_evict_marks_validator(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        fp = b"validator-1"
        assert vs.is_active(fp) is True
        vs.evict(fp)
        assert vs.is_active(fp) is False
        assert vs.is_evicted(fp) is True

    def test_evict_does_not_change_indices(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        vs.evict(b"validator-1")
        # Other validators keep their indices
        assert vs.index_for(b"validator-0") == 0
        assert vs.index_for(b"validator-2") == 2
        assert vs.index_for(b"validator-3") == 3

    def test_evict_does_not_change_quorum(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        q_before = vs.quorum_threshold
        vs.evict(b"validator-1")
        assert vs.quorum_threshold == q_before

    def test_active_count_decrements_on_eviction(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.active_count() == 4
        vs.evict(b"validator-0")
        assert vs.active_count() == 3
        vs.evict(b"validator-2")
        assert vs.active_count() == 2

    def test_evicted_indices_tracking(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        vs.evict(b"validator-1")
        vs.evict(b"validator-3")
        assert vs.evicted_indices() == {1, 3}

    def test_double_eviction_is_idempotent(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        vs.evict(b"validator-1")
        vs.evict(b"validator-1")  # second eviction — no error
        assert vs.active_count() == 3
        assert vs.evicted_indices() == {1}

    def test_unknown_writer_fp_raises_key_error(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        with pytest.raises(KeyError):
            vs.index_for(b"unknown-validator")

    def test_from_roster_empty_roster(self):
        roster = CommitteeRoster(
            vm_tag=1, epoch=1, active_members=[], standby_members=[],
            formed_at=0, formation_round=0,
        )
        vs = ValidatorSet.from_roster(roster)
        assert vs.size == 0
        assert vs.active_count() == 0
        assert vs.quorum_threshold == 1  # 2*(0-1)//3 +1 = 1 with floor

    def test_quorum_n4_gives_q3(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.quorum_threshold == 3  # f=1, 2*1+1=3

    def test_quorum_n7_gives_q5(self):
        roster = _make_roster(7)
        vs = ValidatorSet.from_roster(roster)
        assert vs.quorum_threshold == 5  # f=2, 2*2+1=5

    def test_members_property_returns_copy(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        members = vs.members
        members.clear()
        assert vs.size == 4  # internal list unaffected
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_validator_set.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.consensus.validator_set'`

- [ ] **Step 3: Write the implementation**

```python
# src/ltp/consensus/validator_set.py
"""Validator identity mapping and eviction tracking (Spec D1b §2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..execution.committee.types import CommitteeRoster


@dataclass(frozen=True)
class ValidatorInfo:
    """Identity record for a single validator."""

    writer_fp: bytes
    bls_pk: bytes
    validator_index: int


class ValidatorSet:
    """Maps committee roster identities to engine indices.

    Fixed at epoch creation. Evictions mark validators inactive but never
    change index assignments or quorum threshold.
    """

    def __init__(self, epoch: int, members: list[ValidatorInfo]) -> None:
        self._epoch = epoch
        self._members = list(members)
        n = len(members)
        f = (n - 1) // 3 if n > 0 else 0
        self._quorum_threshold = 2 * f + 1
        self._evicted: set[bytes] = set()
        self._fp_to_index: dict[bytes, int] = {
            m.writer_fp: m.validator_index for m in members
        }
        self._index_to_fp: dict[int, bytes] = {
            m.validator_index: m.writer_fp for m in members
        }
        self._index_to_bls: dict[int, bytes] = {
            m.validator_index: m.bls_pk for m in members
        }

    @classmethod
    def from_roster(cls, roster: CommitteeRoster) -> ValidatorSet:
        """Build a ValidatorSet from a CommitteeRoster."""
        members = [
            ValidatorInfo(
                writer_fp=m.writer_fp,
                bls_pk=m.bls_pk,
                validator_index=i,
            )
            for i, m in enumerate(roster.active_members)
        ]
        return cls(epoch=roster.epoch, members=members)

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def members(self) -> list[ValidatorInfo]:
        return list(self._members)

    @property
    def quorum_threshold(self) -> int:
        return self._quorum_threshold

    @property
    def size(self) -> int:
        return len(self._members)

    def index_for(self, writer_fp: bytes) -> int:
        if writer_fp not in self._fp_to_index:
            raise KeyError(f"Unknown writer_fp: {writer_fp!r}")
        return self._fp_to_index[writer_fp]

    def fp_for(self, index: int) -> bytes:
        if index not in self._index_to_fp:
            raise KeyError(f"Unknown index: {index}")
        return self._index_to_fp[index]

    def bls_pk_for(self, index: int) -> bytes:
        if index not in self._index_to_bls:
            raise KeyError(f"Unknown index: {index}")
        return self._index_to_bls[index]

    def evict(self, writer_fp: bytes) -> None:
        if writer_fp not in self._fp_to_index:
            raise KeyError(f"Unknown writer_fp: {writer_fp!r}")
        self._evicted.add(writer_fp)

    def is_active(self, writer_fp: bytes) -> bool:
        return writer_fp in self._fp_to_index and writer_fp not in self._evicted

    def is_evicted(self, writer_fp: bytes) -> bool:
        return writer_fp in self._evicted

    def active_count(self) -> int:
        return len(self._members) - len(self._evicted)

    def evicted_indices(self) -> set[int]:
        return {self._fp_to_index[fp] for fp in self._evicted}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_validator_set.py -v`
Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/validator_set.py tests/test_consensus_validator_set.py
git commit -m "feat(d1b): add ValidatorSet — identity mapping with eviction tracking"
```

---

### Task 3: BLS Certificate Manager

**Files:**
- Create: `src/ltp/consensus/bls_certificates.py`
- Test: `tests/test_consensus_bls_certs.py`

**Note:** Tests use real BLS12-381 operations via py_ecc. A module-scoped DKG fixture runs once to generate threshold signing keys.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_consensus_bls_certs.py
"""Tests for BLS certificate signing and verification (Spec D1b §3)."""

import pytest

from src.ltp.consensus.bls_certificates import (
    DOMAIN_CONSENSUS_ACK,
    BLSCertificateManager,
    SignedCertificate,
)
from src.ltp.consensus.types import Block, Certificate
from src.ltp.consensus.validator_set import ValidatorInfo, ValidatorSet
from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.types import DKGSessionConfig
from src.ltp.execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    ThresholdSigningKey,
    partial_sign,
)


def _run_dkg(n: int, threshold: int, epoch: int = 1):
    """Run a mini DKG ceremony. Returns (signing_keys, group_pk)."""
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


@pytest.fixture(scope="module")
def dkg_keys_4():
    """4-validator DKG with threshold 3 (module-scoped for speed)."""
    return _run_dkg(4, 3, epoch=1)


@pytest.fixture(scope="module")
def validator_set_4(dkg_keys_4):
    """ValidatorSet with 4 members matching DKG keys."""
    keys, _ = dkg_keys_4
    members = [
        ValidatorInfo(
            writer_fp=k.participant_fp,
            bls_pk=k.group_pk,  # group_pk as stand-in for individual pk
            validator_index=i,
        )
        for i, k in enumerate(keys)
    ]
    return ValidatorSet(epoch=1, members=members)


@pytest.fixture(scope="module")
def sample_block():
    """A sample Block for signing tests."""
    return Block(
        author=0, round=5,
        payload=(b"tx1", b"tx2"),
        parents=frozenset(),
        timestamp_ms=1000,
    )


class TestSignAck:
    """BLSCertificateManager.sign_ack tests."""

    def test_sign_ack_produces_partial_signature(self, dkg_keys_4, sample_block):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        partial = mgr.sign_ack(keys[0], sample_block.digest)
        assert partial.signature is not None
        assert len(partial.signature) == 96  # compressed G2 point
        assert partial.signer_index == keys[0].participant_index

    def test_sign_ack_is_deterministic(self, dkg_keys_4, sample_block):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        p1 = mgr.sign_ack(keys[0], sample_block.digest)
        p2 = mgr.sign_ack(keys[0], sample_block.digest)
        assert p1.signature == p2.signature

    def test_different_keys_produce_different_signatures(self, dkg_keys_4, sample_block):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        p0 = mgr.sign_ack(keys[0], sample_block.digest)
        p1 = mgr.sign_ack(keys[1], sample_block.digest)
        assert p0.signature != p1.signature


class TestAggregateAndVerify:
    """BLS aggregation and certificate verification tests."""

    def test_aggregate_ack_signatures_combines_partials(
        self, dkg_keys_4, validator_set_4, sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)
        assert len(agg) == 96

    def test_aggregated_signature_verifies(
        self, dkg_keys_4, validator_set_4, sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

        cert = Certificate(
            block=sample_block,
            signers=frozenset(k.participant_index for k in keys[:3]),
        )
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=agg,
            signer_keys=frozenset(),
        )
        assert mgr.verify_certificate_signature(signed) is True

    def test_verify_fails_with_wrong_group_key(
        self, dkg_keys_4, validator_set_4, sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

        cert = Certificate(
            block=sample_block,
            signers=frozenset(k.participant_index for k in keys[:3]),
        )
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=agg,
            signer_keys=frozenset(),
        )
        # Swap to a wrong group_pk
        mgr_bad = BLSCertificateManager(group_pk=b"\xff" * 96)
        assert mgr_bad.verify_certificate_signature(signed) is False

    def test_verify_fails_with_tampered_digest(
        self, dkg_keys_4, validator_set_4, sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(k, sample_block.digest) for k in keys[:3]]
        agg = mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

        # Create a different block with different digest
        tampered_block = Block(
            author=0, round=5, payload=(b"TAMPERED",),
            parents=frozenset(), timestamp_ms=1000,
        )
        cert = Certificate(
            block=tampered_block,
            signers=frozenset(k.participant_index for k in keys[:3]),
        )
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=agg,
            signer_keys=frozenset(),
        )
        assert mgr.verify_certificate_signature(signed) is False

    def test_insufficient_partials_raises(
        self, dkg_keys_4, validator_set_4, sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        partials = [mgr.sign_ack(keys[0], sample_block.digest)]  # only 1, need 3
        with pytest.raises(ValueError, match="Need at least"):
            mgr.aggregate_ack_signatures(partials, sample_block.digest, validator_set_4)

    def test_empty_partials_raises(
        self, dkg_keys_4, validator_set_4, sample_block,
    ):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        with pytest.raises(ValueError, match="Need at least"):
            mgr.aggregate_ack_signatures([], sample_block.digest, validator_set_4)


class TestSignedCertificate:
    """SignedCertificate dataclass tests."""

    def test_wraps_certificate_correctly(self, sample_block):
        cert = Certificate(block=sample_block, signers=frozenset({0, 1, 2}))
        signed = SignedCertificate(
            certificate=cert,
            aggregated_signature=b"\xaa" * 96,
            signer_keys=frozenset({b"k0", b"k1", b"k2"}),
        )
        assert signed.certificate is cert
        assert len(signed.aggregated_signature) == 96
        assert len(signed.signer_keys) == 3

    def test_frozen(self, sample_block):
        cert = Certificate(block=sample_block, signers=frozenset({0}))
        signed = SignedCertificate(
            certificate=cert, aggregated_signature=b"\x00" * 96,
            signer_keys=frozenset(),
        )
        with pytest.raises(AttributeError):
            signed.aggregated_signature = b"\xff" * 96  # type: ignore[misc]


class TestBatchAttestation:
    """Batch signing and attestation verification tests."""

    def test_sign_committed_batch_round_trip(self, dkg_keys_4):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        batch_bytes = b"batch-round-5-epoch-1"
        partials = [
            mgr.sign_committed_batch(k, batch_bytes) for k in keys[:3]
        ]
        from src.ltp.execution.committee.dkg.threshold_signing import (
            combine_partial_signatures,
        )
        combined = combine_partial_signatures(partials, 3)
        assert mgr.verify_batch_attestation(combined, batch_bytes, group_pk) is True

    def test_verify_batch_attestation_rejects_wrong_message(self, dkg_keys_4):
        keys, group_pk = dkg_keys_4
        mgr = BLSCertificateManager(group_pk=group_pk)
        batch_bytes = b"correct-batch"
        partials = [
            mgr.sign_committed_batch(k, batch_bytes) for k in keys[:3]
        ]
        from src.ltp.execution.committee.dkg.threshold_signing import (
            combine_partial_signatures,
        )
        combined = combine_partial_signatures(partials, 3)
        assert mgr.verify_batch_attestation(combined, b"wrong-batch", group_pk) is False

    def test_different_domain_produces_different_signature(self, dkg_keys_4):
        keys, _ = dkg_keys_4
        mgr = BLSCertificateManager()
        msg = b"same-message"
        p_att = mgr.sign_committed_batch(keys[0], msg, domain=DOMAIN_ATTESTATION)
        p_ack = mgr.sign_ack(keys[0], msg)
        assert p_att.signature != p_ack.signature

    def test_verify_with_no_group_pk_returns_false(self, sample_block):
        mgr = BLSCertificateManager()  # no group_pk
        cert = Certificate(block=sample_block, signers=frozenset({0}))
        signed = SignedCertificate(
            certificate=cert, aggregated_signature=b"\x00" * 96,
            signer_keys=frozenset(),
        )
        assert mgr.verify_certificate_signature(signed) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_bls_certs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.consensus.bls_certificates'`

- [ ] **Step 3: Write the implementation**

```python
# src/ltp/consensus/bls_certificates.py
"""BLS certificate signing and verification (Spec D1b §3)."""

from __future__ import annotations

from dataclasses import dataclass

from .types import Certificate
from .validator_set import ValidatorSet

from ..execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    PartialSignature,
    ThresholdSigningKey,
    combine_partial_signatures,
    partial_sign,
    threshold_verify,
)

__all__ = [
    "DOMAIN_CONSENSUS_ACK",
    "BLSCertificateManager",
    "SignedCertificate",
]

DOMAIN_CONSENSUS_ACK = b"ETP-CONSENSUS-ACK:v1"


@dataclass(frozen=True)
class SignedCertificate:
    """A D1a Certificate wrapped with an aggregated BLS signature."""

    certificate: Certificate
    aggregated_signature: bytes  # 96-byte aggregated G2
    signer_keys: frozenset[bytes]  # BLS public keys of signers


class BLSCertificateManager:
    """Manages BLS partial signing, aggregation, and verification for certificates."""

    def __init__(self, group_pk: bytes | None = None) -> None:
        self._group_pk = group_pk

    def update_keys(self, group_pk: bytes) -> None:
        self._group_pk = group_pk

    @property
    def group_pk(self) -> bytes | None:
        return self._group_pk

    def sign_ack(
        self,
        signing_key: ThresholdSigningKey,
        block_digest: bytes,
    ) -> PartialSignature:
        """Produce a BLS partial signature over a block digest."""
        return partial_sign(signing_key, block_digest, DOMAIN_CONSENSUS_ACK)

    def aggregate_ack_signatures(
        self,
        partials: list[PartialSignature],
        block_digest: bytes,
        validator_set: ValidatorSet,
    ) -> bytes:
        """Combine partial ack signatures into an aggregated BLS signature."""
        return combine_partial_signatures(partials, validator_set.quorum_threshold)

    def verify_certificate_signature(
        self,
        signed_cert: SignedCertificate,
    ) -> bool:
        """Verify an aggregated certificate signature against the group key."""
        if self._group_pk is None:
            return False
        try:
            return threshold_verify(
                self._group_pk,
                signed_cert.certificate.digest,
                signed_cert.aggregated_signature,
                DOMAIN_CONSENSUS_ACK,
            )
        except Exception:
            return False

    def sign_committed_batch(
        self,
        signing_key: ThresholdSigningKey,
        batch_bytes: bytes,
        domain: bytes = DOMAIN_ATTESTATION,
    ) -> PartialSignature:
        """Produce a BLS partial signature over committed batch bytes."""
        return partial_sign(signing_key, batch_bytes, domain)

    def verify_batch_attestation(
        self,
        signature: bytes,
        batch_bytes: bytes,
        group_pk: bytes,
        domain: bytes = DOMAIN_ATTESTATION,
    ) -> bool:
        """Verify a threshold BLS attestation signature."""
        try:
            return threshold_verify(group_pk, batch_bytes, signature, domain)
        except Exception:
            return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_bls_certs.py -v`
Expected: 16 passed (may take 30-60s due to real BLS operations)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/bls_certificates.py tests/test_consensus_bls_certs.py
git commit -m "feat(d1b): add BLSCertificateManager — partial signing, aggregation, certificate and batch verification"
```

---

### Task 4: ConsensusBackend

**Files:**
- Create: `src/ltp/consensus/backend.py`
- Test: `tests/test_consensus_backend.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_consensus_backend.py
"""Tests for ConsensusBackend ABC and LocalConsensusBackend (Spec D1b §4)."""

import pytest
from abc import ABC

from src.ltp.consensus.backend import ConsensusBackend, LocalConsensusBackend
from src.ltp.consensus.types import CommitDecision
from src.ltp.consensus.faults import FaultConfig, FaultType


class TestConsensusBackendABC:
    """ConsensusBackend abstract base class tests."""

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            ConsensusBackend()  # type: ignore[abstract]

    def test_is_abstract(self):
        assert issubclass(ConsensusBackend, ABC)


class TestLocalConsensusBackend:
    """LocalConsensusBackend delegation tests."""

    def test_creation_with_validator_count(self):
        backend = LocalConsensusBackend(4)
        assert backend.get_validator_count() == 4

    def test_advance_round_returns_round_number(self):
        backend = LocalConsensusBackend(4)
        r = backend.advance_round()
        assert r == 0
        r = backend.advance_round()
        assert r == 1

    def test_current_round_tracks(self):
        backend = LocalConsensusBackend(4)
        assert backend.current_round() == -1
        backend.advance_round()
        assert backend.current_round() == 0

    def test_run_rounds_produces_commit_decisions(self):
        backend = LocalConsensusBackend(4)
        decisions = backend.run_rounds(5)
        assert isinstance(decisions, list)
        for d in decisions:
            assert isinstance(d, CommitDecision)

    def test_submit_transactions_forwarded(self):
        backend = LocalConsensusBackend(4)
        backend.submit_transactions([b"tx1", b"tx2"])
        # Transactions should appear in committed blocks after running rounds
        decisions = backend.run_rounds(5)
        all_payloads = []
        for d in decisions:
            for block in d.committed_blocks:
                all_payloads.extend(block.payload)
        assert b"tx1" in all_payloads
        assert b"tx2" in all_payloads

    def test_inject_fault_crash(self):
        backend = LocalConsensusBackend(4)
        fault = FaultConfig(validator=0, fault_type=FaultType.CRASH, start_round=0)
        backend.inject_fault(fault)
        # Should still run without error (crashed validator is skipped)
        backend.run_rounds(3)

    def test_rebuild_creates_new_engine(self):
        backend = LocalConsensusBackend(4)
        backend.advance_round()
        assert backend.current_round() == 0
        backend.rebuild(7)
        assert backend.get_validator_count() == 7
        assert backend.current_round() == -1  # reset after rebuild

    def test_rebuild_preserves_round_timeout(self):
        backend = LocalConsensusBackend(4, round_timeout_ms=500)
        backend.rebuild(7)
        assert backend._round_timeout_ms == 500

    def test_start_stop_lifecycle(self):
        backend = LocalConsensusBackend(4, round_timeout_ms=50)
        backend.start()
        assert backend._engine._running is True
        backend.stop()
        assert backend._engine._running is False

    def test_stream_commits_yields_decisions(self):
        backend = LocalConsensusBackend(4, round_timeout_ms=10)
        backend.submit_transactions([b"tx-stream"])
        backend.start()
        commits = []
        for decision in backend.stream_commits():
            commits.append(decision)
            if len(commits) >= 1:
                backend.stop()
                break
        assert len(commits) >= 1
        assert isinstance(commits[0], CommitDecision)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_backend.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.consensus.backend'`

- [ ] **Step 3: Write the implementation**

```python
# src/ltp/consensus/backend.py
"""Consensus backend abstraction (Spec D1b §4)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from .types import CommitDecision
from .faults import FaultConfig
from .engine import LocalMysticetiEngine

__all__ = ["ConsensusBackend", "LocalConsensusBackend"]


class ConsensusBackend(ABC):
    """Abstract interface for a consensus engine.

    LocalConsensusBackend wraps the in-process Mysticeti engine.
    Future GrpcConsensusBackend (D2+) will implement the same contract.
    """

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def submit_transactions(self, txs: list[bytes]) -> None: ...

    @abstractmethod
    def advance_round(self) -> int: ...

    @abstractmethod
    def run_rounds(self, n: int) -> list[CommitDecision]: ...

    @abstractmethod
    def stream_commits(self) -> Iterator[CommitDecision]: ...

    @abstractmethod
    def current_round(self) -> int: ...

    @abstractmethod
    def inject_fault(self, fault: FaultConfig) -> None: ...

    @abstractmethod
    def get_validator_count(self) -> int: ...

    @abstractmethod
    def rebuild(self, num_validators: int, fault_tolerance: int | None = None) -> None: ...


class LocalConsensusBackend(ConsensusBackend):
    """Wraps LocalMysticetiEngine. All methods delegate directly."""

    def __init__(
        self,
        num_validators: int,
        fault_tolerance: int | None = None,
        round_timeout_ms: int = 1000,
    ) -> None:
        self._round_timeout_ms = round_timeout_ms
        self._engine = LocalMysticetiEngine(
            num_validators,
            fault_tolerance=fault_tolerance,
            round_timeout_ms=round_timeout_ms,
        )

    def start(self) -> None:
        self._engine.start()

    def stop(self) -> None:
        self._engine.stop()

    def submit_transactions(self, txs: list[bytes]) -> None:
        self._engine.submit_transactions(txs)

    def advance_round(self) -> int:
        return self._engine.advance_round()

    def run_rounds(self, n: int) -> list[CommitDecision]:
        return self._engine.run_rounds(n)

    def stream_commits(self) -> Iterator[CommitDecision]:
        return self._engine.stream_commits()

    def current_round(self) -> int:
        return self._engine._current_round

    def inject_fault(self, fault: FaultConfig) -> None:
        self._engine.inject_fault(fault)

    def get_validator_count(self) -> int:
        return self._engine._n

    def rebuild(self, num_validators: int, fault_tolerance: int | None = None) -> None:
        self._engine = LocalMysticetiEngine(
            num_validators,
            fault_tolerance=fault_tolerance,
            round_timeout_ms=self._round_timeout_ms,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_backend.py -v`
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/backend.py tests/test_consensus_backend.py
git commit -m "feat(d1b): add ConsensusBackend ABC and LocalConsensusBackend wrapping Mysticeti engine"
```

---

### Task 5: CommitteeSync

**Files:**
- Create: `src/ltp/consensus/committee_sync.py`

No separate test file — CommitteeSync is tested via adapter integration tests in Task 6.

- [ ] **Step 1: Write the implementation**

```python
# src/ltp/consensus/committee_sync.py
"""CommitteeSync — bridges CommitteeManager to consensus events (Spec D1b §5)."""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

from .events import ConsensusEvent, ConsensusEventType
from .validator_set import ValidatorSet

if TYPE_CHECKING:
    from ..execution.committee.manager import CommitteeManager
    from ..execution.committee.dkg.threshold_signing import ThresholdSigningKey

__all__ = ["CommitteeSync"]


class CommitteeSync:
    """Detects epoch transitions and evictions, emits ConsensusEvents."""

    def __init__(self, committee_manager: CommitteeManager) -> None:
        self._cm = committee_manager
        self._current_epoch: int = committee_manager.epoch
        self._validator_set: ValidatorSet | None = None
        self._listeners: list[Callable[[ConsensusEvent], None]] = []
        self._known_evicted: set[bytes] = set()

    @property
    def current_validator_set(self) -> ValidatorSet | None:
        return self._validator_set

    def set_validator_set(self, vs: ValidatorSet) -> None:
        self._validator_set = vs
        self._known_evicted = set()

    def register_listener(self, callback: Callable[[ConsensusEvent], None]) -> None:
        self._listeners.append(callback)

    def has_signing_keys(self, epoch: int) -> bool:
        return self._cm.has_dkg_result(epoch)

    def get_signing_keys(self, epoch: int) -> list[ThresholdSigningKey]:
        return self._cm._signing_keys.get(epoch, [])

    def sync_epoch(self, round: int, timestamp_ms: int) -> ConsensusEvent | None:
        """Check if epoch advanced. If yes, build new ValidatorSet and emit event."""
        new_epoch = self._cm.epoch
        if new_epoch <= self._current_epoch:
            return None

        old_epoch = self._current_epoch
        self._current_epoch = new_epoch

        roster = self._cm.roster
        if roster is not None:
            self._validator_set = ValidatorSet.from_roster(roster)
            self._known_evicted = set()

        validator_count = self._validator_set.size if self._validator_set else 0
        dkg_completed = self._cm.has_dkg_result(new_epoch)

        event = ConsensusEvent(
            event_type=ConsensusEventType.EPOCH_TRANSITION,
            epoch=new_epoch,
            round=round,
            timestamp_ms=timestamp_ms,
            payload={
                "old_epoch": old_epoch,
                "new_epoch": new_epoch,
                "validator_count": validator_count,
                "dkg_completed": dkg_completed,
            },
        )
        self._notify(event)
        return event

    def sync_evictions(
        self,
        validator_set: ValidatorSet,
        round: int,
        timestamp_ms: int,
    ) -> list[ConsensusEvent]:
        """Compare roster against ValidatorSet, emit events for new evictions."""
        events: list[ConsensusEvent] = []
        roster = self._cm.roster
        if roster is None:
            return events

        active_fps = {m.writer_fp for m in roster.active_members}

        for member in validator_set.members:
            fp = member.writer_fp
            if fp in self._known_evicted:
                continue
            if fp not in active_fps and not validator_set.is_evicted(fp):
                validator_set.evict(fp)
                self._known_evicted.add(fp)
                event = ConsensusEvent(
                    event_type=ConsensusEventType.VALIDATOR_EVICTED,
                    epoch=self._current_epoch,
                    round=round,
                    timestamp_ms=timestamp_ms,
                    payload={
                        "writer_fp": fp,
                        "validator_index": member.validator_index,
                        "reason": "evicted_from_roster",
                        "remaining_active": validator_set.active_count(),
                    },
                )
                self._notify(event)
                events.append(event)

        return events

    def on_tick(
        self,
        round: int,
        timestamp_ms: int,
    ) -> list[ConsensusEvent]:
        """Run sync_epoch + sync_evictions, return all events."""
        events: list[ConsensusEvent] = []

        epoch_event = self.sync_epoch(round, timestamp_ms)
        if epoch_event is not None:
            events.append(epoch_event)

        if self._validator_set is not None:
            eviction_events = self.sync_evictions(
                self._validator_set, round, timestamp_ms,
            )
            events.extend(eviction_events)

        return events

    def _notify(self, event: ConsensusEvent) -> None:
        for listener in self._listeners:
            listener(event)
```

- [ ] **Step 2: Run existing tests to verify no regressions**

Run: `pytest tests/test_consensus_*.py -v`
Expected: All previously passing tests still pass

- [ ] **Step 3: Commit**

```bash
git add src/ltp/consensus/committee_sync.py
git commit -m "feat(d1b): add CommitteeSync — epoch transition and eviction detection bridge"
```

---

### Task 6: MysticetiAdapter

**Files:**
- Create: `src/ltp/consensus/adapter.py`
- Test: `tests/test_consensus_adapter.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_consensus_adapter.py
"""Tests for MysticetiAdapter lifecycle and CommitteeSync integration (Spec D1b §5-6)."""

import hashlib
import time

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
            tier=IdentityTier.FULL,
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
        assert batches[0].consensus_type == "mysticeti-dag"
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
        # Check that COMMIT_ATTESTED events were emitted
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
        assert len(batches) > 0  # works without BLS
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

        # Simulate epoch advance
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

        # Simulate eviction: remove validator-1 from roster
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_adapter.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.ltp.consensus.adapter'`

- [ ] **Step 3: Write the implementation**

```python
# src/ltp/consensus/adapter.py
"""MysticetiAdapter — real ConsensusAdapter implementation (Spec D1b §6)."""

from __future__ import annotations

import hashlib
from typing import Iterator, TYPE_CHECKING

from .events import ConsensusEvent, ConsensusEventType
from .validator_set import ValidatorSet
from .bls_certificates import BLSCertificateManager, SignedCertificate, DOMAIN_CONSENSUS_ACK
from .backend import LocalConsensusBackend
from .committee_sync import CommitteeSync
from .types import CommitDecision
from .engine import to_ordered_batch
from .faults import FaultConfig, FaultType

if TYPE_CHECKING:
    from ..execution.committee.manager import CommitteeManager
    from ..execution.committee.dkg.threshold_signing import ThresholdSigningKey

from ..execution.types import OrderedBatch
from ..execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    combine_partial_signatures,
)

__all__ = ["MysticetiAdapter"]


class MysticetiAdapter:
    """Implements ConsensusAdapter — connects Mysticeti engine to execution pipeline.

    Orchestrates ValidatorSet, BLSCertificateManager, LocalConsensusBackend,
    and CommitteeSync.
    """

    def __init__(
        self,
        committee_manager: CommitteeManager,
        round_timeout_ms: int = 1000,
    ) -> None:
        self._committee_manager = committee_manager
        self._round_timeout_ms = round_timeout_ms
        self._committee_sync = CommitteeSync(committee_manager)
        self._bls_manager = BLSCertificateManager()
        self._backend: LocalConsensusBackend | None = None
        self._validator_set: ValidatorSet | None = None
        self._signing_keys: list[ThresholdSigningKey] | None = None
        self._events: list[ConsensusEvent] = []
        self._running = False
        self._current_epoch = committee_manager.epoch

    def start(self) -> None:
        """Build validator set from roster, create backend, init BLS manager."""
        roster = self._committee_manager.roster
        if roster is None:
            raise RuntimeError("No roster available — cannot start adapter")

        self._validator_set = ValidatorSet.from_roster(roster)
        self._committee_sync.set_validator_set(self._validator_set)
        n = self._validator_set.size

        self._backend = LocalConsensusBackend(
            n, round_timeout_ms=self._round_timeout_ms,
        )

        epoch = self._committee_manager.epoch
        self._current_epoch = epoch
        if self._committee_manager.has_dkg_result(epoch):
            keys = self._committee_sync.get_signing_keys(epoch)
            if keys:
                self._signing_keys = keys
                self._bls_manager.update_keys(keys[0].group_pk)

        self._running = True

    def stop(self) -> None:
        """Stop the backend and clear running state."""
        if self._backend is not None:
            self._backend.stop()
        self._running = False

    def stream_batches(self) -> Iterator[OrderedBatch]:
        """Pull commits from backend, add BLS signatures, yield OrderedBatch."""
        if self._backend is None:
            return
        for decision in self._backend.stream_commits():
            yield self._process_decision(decision)

    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        """Forward transaction to backend, return SHA3-256 hash."""
        if self._backend is None:
            raise RuntimeError("Adapter not started")
        self._backend.submit_transactions([tx_bytes])
        return hashlib.sha3_256(tx_bytes).digest()

    def current_round(self) -> int:
        """Return the current consensus round."""
        if self._backend is None:
            return -1
        return self._backend.current_round()

    def consensus_type(self) -> str:
        return "mysticeti-dag"

    def drive_rounds(self, n: int) -> list[OrderedBatch]:
        """Run n rounds synchronously. Returns ordered batches."""
        if self._backend is None:
            raise RuntimeError("Adapter not started")
        decisions = self._backend.run_rounds(n)
        return [self._process_decision(d) for d in decisions]

    def tick(
        self,
        round: int,
        timestamp_ms: int,
    ) -> list[ConsensusEvent]:
        """Drive CommitteeSync, handle epoch/eviction events."""
        events = self._committee_sync.on_tick(round, timestamp_ms)

        for event in events:
            self._events.append(event)

            if event.event_type == ConsensusEventType.EPOCH_TRANSITION:
                self._handle_epoch_transition(event)

            elif event.event_type == ConsensusEventType.VALIDATOR_EVICTED:
                self._handle_eviction(event)

        return events

    def events(self) -> list[ConsensusEvent]:
        """Return event history."""
        return list(self._events)

    def _handle_epoch_transition(self, event: ConsensusEvent) -> None:
        """Rebuild backend for new epoch."""
        new_epoch = event.payload["new_epoch"]
        self._current_epoch = new_epoch

        self._validator_set = self._committee_sync.current_validator_set
        if self._validator_set is None:
            return

        n = self._validator_set.size
        if self._backend is not None:
            self._backend.rebuild(n)

        # Update BLS keys
        if self._committee_sync.has_signing_keys(new_epoch):
            keys = self._committee_sync.get_signing_keys(new_epoch)
            if keys:
                self._signing_keys = keys
                self._bls_manager.update_keys(keys[0].group_pk)
        else:
            self._signing_keys = None

        # Emit ENGINE_REBUILT event
        rebuilt_event = ConsensusEvent(
            event_type=ConsensusEventType.ENGINE_REBUILT,
            epoch=new_epoch,
            round=event.round,
            timestamp_ms=event.timestamp_ms,
            payload={
                "epoch": new_epoch,
                "validator_count": n,
                "quorum_threshold": self._validator_set.quorum_threshold,
            },
        )
        self._events.append(rebuilt_event)

    def _handle_eviction(self, event: ConsensusEvent) -> None:
        """Inject CRASH fault for evicted validator."""
        if self._backend is None:
            return
        idx = event.payload["validator_index"]
        fault = FaultConfig(
            validator=idx,
            fault_type=FaultType.CRASH,
            start_round=0,
        )
        self._backend.inject_fault(fault)

    def _process_decision(self, decision: CommitDecision) -> OrderedBatch:
        """Convert CommitDecision to OrderedBatch with optional BLS signing."""
        batch = to_ordered_batch(decision, self._current_epoch)

        # BLS signing: sign the leader certificate if keys available
        if self._signing_keys and self._validator_set:
            self._sign_decision(decision, batch)

        return batch

    def _sign_decision(
        self,
        decision: CommitDecision,
        batch: OrderedBatch,
    ) -> None:
        """Add BLS signatures to the decision's certificate and attest the batch."""
        cert = decision.leader_certificate
        keys = self._signing_keys
        vs = self._validator_set
        if not keys or not vs:
            return

        # Produce partial ack sigs from each signer in the certificate
        partials = []
        for signer_idx in sorted(cert.signers):
            if signer_idx < len(keys):
                partial = self._bls_manager.sign_ack(keys[signer_idx], cert.digest)
                partials.append(partial)

        # Aggregate into signed certificate (if enough partials)
        if len(partials) >= vs.quorum_threshold:
            agg_sig = self._bls_manager.aggregate_ack_signatures(
                partials, cert.digest, vs,
            )
            SignedCertificate(
                certificate=cert,
                aggregated_signature=agg_sig,
                signer_keys=frozenset(
                    vs.bls_pk_for(i) for i in cert.signers if i < vs.size
                ),
            )

        # Attest the batch
        batch_bytes = self._serialize_batch(batch)
        threshold = vs.quorum_threshold
        batch_partials = []
        for k in keys[:threshold]:
            bp = self._bls_manager.sign_committed_batch(k, batch_bytes)
            batch_partials.append(bp)

        if len(batch_partials) >= threshold:
            combined_sig = combine_partial_signatures(batch_partials, threshold)
            batch_digest = hashlib.sha3_256(batch_bytes).digest()

            attest_event = ConsensusEvent(
                event_type=ConsensusEventType.COMMIT_ATTESTED,
                epoch=self._current_epoch,
                round=batch.round,
                timestamp_ms=batch.timestamp_ms,
                payload={
                    "round": batch.round,
                    "batch_digest": batch_digest,
                    "signature": combined_sig,
                },
            )
            self._events.append(attest_event)

    @staticmethod
    def _serialize_batch(batch: OrderedBatch) -> bytes:
        """Deterministic serialization of OrderedBatch for signing."""
        h = hashlib.sha3_256()
        h.update(batch.round.to_bytes(8, "big"))
        h.update(batch.epoch.to_bytes(8, "big"))
        h.update(len(batch.transactions).to_bytes(4, "big"))
        for tx in batch.transactions:
            h.update(len(tx).to_bytes(4, "big"))
            h.update(tx)
        return h.digest()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_adapter.py -v`
Expected: 15 passed

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/adapter.py tests/test_consensus_adapter.py
git commit -m "feat(d1b): add MysticetiAdapter implementing ConsensusAdapter protocol with BLS signing"
```

---

### Task 7: Adversarial Tests

**Files:**
- Create: `tests/test_consensus_adversarial.py`

All source files already exist. This task adds edge-case and adversarial scenario tests.

- [ ] **Step 1: Write the adversarial tests**

```python
# tests/test_consensus_adversarial.py
"""Adversarial and edge-case tests for consensus adapter (Spec D1b §8)."""

import hashlib
import pytest

from src.ltp.consensus.adapter import MysticetiAdapter
from src.ltp.consensus.events import ConsensusEventType
from src.ltp.consensus.validator_set import ValidatorSet
from src.ltp.consensus.bls_certificates import BLSCertificateManager
from src.ltp.consensus.faults import FaultConfig, FaultType
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.writer import IdentityTier
from src.ltp.execution.committee.dkg.session import DKGSession
from src.ltp.execution.committee.dkg.types import DKGSessionConfig
from src.ltp.execution.committee.dkg.threshold_signing import (
    DOMAIN_ATTESTATION,
    partial_sign,
    combine_partial_signatures,
    threshold_verify,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_roster(n: int, epoch: int = 1) -> CommitteeRoster:
    members = [
        CommitteeMember(
            writer_fp=f"validator-{i}".encode(),
            bls_pk=bytes([i]) * 48,
            tier=IdentityTier.FULL,
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
            m for m in self._roster.active_members
            if m.writer_fp != writer_fp
        ]


# ---------------------------------------------------------------------------
# Module-scoped fixtures for BLS tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dkg_4():
    return _run_dkg(4, 3, epoch=1)


@pytest.fixture(scope="module")
def dkg_7():
    return _run_dkg(7, 5, epoch=2)


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
        # Should still produce batches with remaining 3 validators
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
            e for e in events1 + events2
            if e.event_type == ConsensusEventType.VALIDATOR_EVICTED
        ]
        assert len(evictions) == 1  # only one eviction event
        adapter.stop()

    def test_eviction_of_leader_round(self):
        """Evicting the leader for a round — protocol continues."""
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.drive_rounds(1)  # round 0

        # Evict validator 1 (leader for round 1)
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
        epoch_events = [
            e for e in events
            if e.event_type == ConsensusEventType.EPOCH_TRANSITION
        ]
        assert len(epoch_events) == 1
        assert epoch_events[0].payload["validator_count"] == 7

        # Engine should be rebuilt
        rebuilt = [
            e for e in adapter.events()
            if e.event_type == ConsensusEventType.ENGINE_REBUILT
        ]
        assert len(rebuilt) == 1
        assert rebuilt[0].payload["validator_count"] == 7
        adapter.stop()

    def test_validator_set_shrink_7_to_4(self):
        cm = FakeCommitteeManager(roster=_make_roster(7, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(100, 50000)

        rebuilt = [
            e for e in adapter.events()
            if e.event_type == ConsensusEventType.ENGINE_REBUILT
        ]
        assert len(rebuilt) == 1
        assert rebuilt[0].payload["validator_count"] == 4
        adapter.stop()

    def test_epoch_advance_during_active_rounds(self):
        """Epoch advance during active consensus — in-flight commits drain."""
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"inflight-tx")
        pre_batches = adapter.drive_rounds(3)

        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(50, 25000)

        # Post-epoch rounds should work with rebuilt engine
        adapter.submit_transaction(b"post-epoch-tx")
        post_batches = adapter.drive_rounds(5)
        assert len(post_batches) > 0
        adapter.stop()

    def test_concurrent_epoch_and_eviction(self):
        """Epoch advance + eviction in the same tick."""
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()

        # Advance epoch (new roster has 4 members but we evict one immediately)
        new_roster = _make_roster(4, epoch=2)
        cm.advance_epoch(2, new_roster)
        cm.evict_member(b"validator-3")

        events = adapter.tick(100, 50000)
        # Should have both epoch transition and eviction
        types = {e.event_type for e in events}
        assert ConsensusEventType.EPOCH_TRANSITION in types
        # Eviction might be detected in the same tick
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
            e for e in adapter.events()
            if e.event_type == ConsensusEventType.EPOCH_TRANSITION
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
        """Signature from epoch 1 keys should not verify under epoch 2 group key."""
        keys_e1, gpk_e1 = dkg_4
        keys_e2, gpk_e2 = dkg_4_epoch2
        msg = b"cross-epoch-test"
        # Sign with epoch 1 keys
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys_e1[:3]]
        sig = combine_partial_signatures(partials, 3)
        # Verify under epoch 2 group key — should fail
        assert threshold_verify(gpk_e2, msg, sig, DOMAIN_ATTESTATION) is False

    def test_epoch_without_dkg_keys_graceful_degradation(self):
        """Adapter works without DKG keys — no BLS signing, no COMMIT_ATTESTED."""
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"no-dkg")
        batches = adapter.drive_rounds(5)
        assert len(batches) > 0
        attested = [
            e for e in adapter.events()
            if e.event_type == ConsensusEventType.COMMIT_ATTESTED
        ]
        assert len(attested) == 0  # no attestation without keys
        adapter.stop()

    def test_zero_transaction_rounds_with_bls(self, dkg_4):
        """Empty rounds with BLS signing — no crash."""
        keys, group_pk = dkg_4
        cm = FakeCommitteeManager(
            roster=_make_roster(4),
            signing_keys={1: keys},
        )
        adapter = MysticetiAdapter(cm)
        adapter.start()
        # No transactions submitted
        batches = adapter.drive_rounds(3)
        # Should produce batches (possibly empty) without error
        adapter.stop()

    def test_engine_rebuilt_stream_continues(self):
        """After rebuild, new rounds produce valid batches."""
        cm = FakeCommitteeManager(roster=_make_roster(4, epoch=1), epoch=1)
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"pre-rebuild")
        pre = adapter.drive_rounds(3)

        # Rebuild via epoch transition
        cm.advance_epoch(2, _make_roster(4, epoch=2))
        adapter.tick(50, 25000)

        adapter.submit_transaction(b"post-rebuild")
        post = adapter.drive_rounds(5)
        assert len(post) > 0
        adapter.stop()

    def test_eviction_at_commit_round_still_valid(self):
        """Validator evicted at the same round as a commit — commit still counts."""
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()
        adapter.submit_transaction(b"evict-round-tx")
        batches = adapter.drive_rounds(3)

        # Evict after commits produced — commits already in are still valid
        cm.evict_member(b"validator-2")
        adapter.tick(3, 15000)

        assert len(batches) > 0
        adapter.stop()

    def test_sig_verification_across_epoch_boundary(self, dkg_4):
        """Signature produced in epoch N, verified in epoch N+1."""
        keys, group_pk = dkg_4
        msg = b"cross-epoch-attestation"
        partials = [partial_sign(k, msg, DOMAIN_ATTESTATION) for k in keys[:3]]
        sig = combine_partial_signatures(partials, 3)

        # Verify with same group_pk — should pass regardless of epoch
        assert threshold_verify(group_pk, msg, sig, DOMAIN_ATTESTATION) is True

    def test_stale_validator_after_removal(self):
        """Validator removed from roster submits — still works, just evicted."""
        cm = FakeCommitteeManager(roster=_make_roster(4))
        adapter = MysticetiAdapter(cm)
        adapter.start()

        cm.evict_member(b"validator-3")
        adapter.tick(0, 0)

        # Adapter should have evicted validator-3
        assert adapter._validator_set.is_evicted(b"validator-3") is True
        # But submit_transaction still works (goes through backend mempool)
        tx_hash = adapter.submit_transaction(b"from-stale")
        assert len(tx_hash) == 32
        adapter.stop()
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `pytest tests/test_consensus_adversarial.py -v`
Expected: 18 passed

- [ ] **Step 3: Commit**

```bash
git add tests/test_consensus_adversarial.py
git commit -m "test(d1b): add adversarial tests — evictions, epoch transitions, BLS edge cases"
```

---

### Task 8: Package Exports and Regression

**Files:**
- Modify: `src/ltp/consensus/__init__.py`

- [ ] **Step 1: Update __init__.py with D1b exports**

Add after existing D1a imports in `src/ltp/consensus/__init__.py`:

```python
# D1b: Consensus Adapter and Validator Management
from .events import ConsensusEvent, ConsensusEventType
from .validator_set import ValidatorInfo, ValidatorSet
from .bls_certificates import (
    DOMAIN_CONSENSUS_ACK,
    BLSCertificateManager,
    SignedCertificate,
)
from .backend import ConsensusBackend, LocalConsensusBackend
from .committee_sync import CommitteeSync
from .adapter import MysticetiAdapter
```

Add to `__all__`:

```python
    # D1b: Events
    "ConsensusEvent",
    "ConsensusEventType",
    # D1b: Validator Set
    "ValidatorInfo",
    "ValidatorSet",
    # D1b: BLS Certificates
    "DOMAIN_CONSENSUS_ACK",
    "BLSCertificateManager",
    "SignedCertificate",
    # D1b: Backend
    "ConsensusBackend",
    "LocalConsensusBackend",
    # D1b: Committee Sync
    "CommitteeSync",
    # D1b: Adapter
    "MysticetiAdapter",
```

- [ ] **Step 2: Run all D1b tests**

Run: `pytest tests/test_consensus_events.py tests/test_consensus_validator_set.py tests/test_consensus_bls_certs.py tests/test_consensus_backend.py tests/test_consensus_adapter.py tests/test_consensus_adversarial.py -v`
Expected: ~83 passed

- [ ] **Step 3: Run full regression**

Run: `pytest tests/ -v`
Expected: 3,660+ passed (3,580 existing + ~83 new), 0 failed

- [ ] **Step 4: Commit**

```bash
git add src/ltp/consensus/__init__.py
git commit -m "feat(d1b): export all D1b types from consensus package — events, validator_set, bls_certificates, backend, committee_sync, adapter"
```

---

## Gate Checklist

After all tasks complete, verify:

- [ ] `MysticetiAdapter` implements `ConsensusAdapter` protocol (`isinstance` check passes)
- [ ] `stream_batches()` yields `OrderedBatch` with `consensus_type="mysticeti-dag"`
- [ ] BLS partial signatures on acks, aggregated signatures on certificates
- [ ] `SignedCertificate` carries verifiable aggregated BLS signature
- [ ] `ValidatorSet` maps `writer_fp` to engine index, tracks evictions
- [ ] Epoch transitions rebuild engine with new validator count from roster
- [ ] Mid-epoch evictions inject CRASH faults, exclude validator immediately
- [ ] Quorum threshold fixed per epoch — does not change on eviction
- [ ] `ConsensusBackend` ABC allows future gRPC swap without adapter changes
- [ ] `CommitteeSync` bridges CommitteeManager events to consensus layer
- [ ] Graceful degradation when DKG keys unavailable (no BLS signing, protocol still works)
- [ ] All D1a tests still pass (3,580+)
- [ ] ~83 new tests across 6 test files
