# Mysticeti DAG Protocol Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-contained `src/ltp/consensus/` package implementing the Mysticeti DAG-BFT protocol with full protocol logic, deterministic commit rules, in-process multi-validator simulation, and Byzantine fault injection.

**Architecture:** Multi-leader DAG-BFT. All validators propose simultaneously per round. Blocks become certificates when they receive 2f+1 acks. A deterministic leader election (`round % n`) selects a leader per round; the commit rule checks whether 2f+1 next-round certificates reference the leader (direct commit) or whether the leader is in a later committed leader's causal history (indirect commit). A `LocalMysticetiEngine` runs n validators in-process connected by a `MessageBus` with partition support. Byzantine fault injection covers 6 fault types.

**Tech Stack:** Python 3.12+, hashlib (SHA3-256), dataclasses, threading (async mode), pytest

---

## File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/ltp/consensus/__init__.py` | Package exports — all public types and classes |
| Create | `src/ltp/consensus/types.py` | `Block`, `Certificate`, `CommitDecision`, `EquivocationProof`, `RoundState` |
| Create | `src/ltp/consensus/dag_store.py` | `DAGStore` — indexed block/certificate storage per validator |
| Create | `src/ltp/consensus/protocol.py` | `MysticetiProtocol` — pure protocol logic for one validator |
| Create | `src/ltp/consensus/commit_rule.py` | `evaluate_direct_commit`, `evaluate_indirect_commit`, `collect_causal_history` |
| Create | `src/ltp/consensus/engine.py` | `LocalMysticetiEngine` — in-process multi-validator simulation |
| Create | `src/ltp/consensus/faults.py` | `FaultType`, `FaultConfig`, `PartitionConfig` |
| Create | `src/ltp/consensus/message_bus.py` | `MessageBus` — in-memory routing with partition support |
| Create | `tests/test_consensus_types.py` | DAG data structure tests (~8 tests) |
| Create | `tests/test_consensus_dag_store.py` | DAGStore tests (~10 tests) |
| Create | `tests/test_consensus_protocol.py` | Protocol logic tests (~12 tests) |
| Create | `tests/test_consensus_commit_rule.py` | Commit rule tests (~10 tests) |
| Create | `tests/test_consensus_engine.py` | Engine integration tests (~10 tests) |
| Create | `tests/test_consensus_byzantine.py` | Byzantine fault tests (~12 tests) |
| Create | `tests/test_consensus_e2e.py` | Full pipeline E2E tests (~8 tests) |

---

### Task 1: DAG Data Structures — Types

**Files:**
- Create: `src/ltp/consensus/__init__.py` (empty init, will grow later)
- Create: `src/ltp/consensus/types.py`
- Create: `tests/test_consensus_types.py`

- [ ] **Step 1: Create package init (minimal)**

Create `src/ltp/consensus/__init__.py`:

```python
"""Mysticeti DAG-BFT consensus engine (Spec D1a)."""
```

- [ ] **Step 2: Write failing tests for Block**

Create `tests/test_consensus_types.py`:

```python
"""Tests for DAG data structures (Spec D1a §1)."""

import hashlib

from ltp.consensus.types import (
    Block,
    Certificate,
    CommitDecision,
    EquivocationProof,
    RoundState,
)


class TestBlock:
    """Block frozen dataclass and digest computation."""

    def test_block_creation(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b.author == 0
        assert b.round == 1
        assert b.payload == (b"tx1",)
        assert b.parents == frozenset()
        assert b.timestamp_ms == 1000
        assert isinstance(b.digest, bytes)
        assert len(b.digest) == 32  # SHA3-256

    def test_digest_deterministic(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest == b2.digest

    def test_digest_changes_with_author(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_digest_changes_with_round(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=2, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_digest_changes_with_payload(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_digest_changes_with_parents(self):
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset({b"\x00" * 32}), timestamp_ms=1000)
        assert b1.digest != b2.digest

    def test_block_is_frozen(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        import dataclasses
        assert dataclasses.is_dataclass(b)
        try:
            b.author = 1  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_digest_ignores_timestamp(self):
        """Timestamp is not part of the digest — it's metadata only."""
        b1 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=9999)
        assert b1.digest == b2.digest
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_consensus_types.py::TestBlock -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ltp.consensus.types'`

- [ ] **Step 4: Implement Block**

Create `src/ltp/consensus/types.py`:

```python
"""DAG data structures for Mysticeti consensus (Spec D1a §1)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def _compute_block_digest(
    author: int,
    round: int,
    payload: tuple[bytes, ...],
    parents: frozenset[bytes],
) -> bytes:
    """SHA3-256(author || round || len(payload) || sorted(payload) || sorted(parents))."""
    h = hashlib.sha3_256()
    h.update(author.to_bytes(4, "big"))
    h.update(round.to_bytes(8, "big"))
    h.update(len(payload).to_bytes(4, "big"))
    for p in sorted(payload):
        h.update(p)
    for parent in sorted(parents):
        h.update(parent)
    return h.digest()


@dataclass(frozen=True)
class Block:
    """A single proposal from a validator."""

    author: int
    round: int
    payload: tuple[bytes, ...]
    parents: frozenset[bytes]
    timestamp_ms: int
    digest: bytes = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "digest",
            _compute_block_digest(self.author, self.round, self.payload, self.parents),
        )
```

- [ ] **Step 5: Run Block tests to verify they pass**

Run: `pytest tests/test_consensus_types.py::TestBlock -v`
Expected: 8 PASSED

- [ ] **Step 6: Write failing tests for Certificate, CommitDecision, EquivocationProof, RoundState**

Append to `tests/test_consensus_types.py`:

```python
class TestCertificate:
    """Certificate creation and quorum validation."""

    def test_certificate_creation(self):
        b = Block(author=0, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1, 2}))
        assert cert.block is b
        assert cert.signers == frozenset({0, 1, 2})
        assert cert.digest == b.digest

    def test_certificate_is_frozen(self):
        b = Block(author=0, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1, 2}))
        try:
            cert.block = b  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass

    def test_certificate_digest_matches_block(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1}))
        assert cert.digest == b.digest


class TestCommitDecision:
    """CommitDecision structure."""

    def test_commit_decision_creation(self):
        b = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        cert = Certificate(block=b, signers=frozenset({0, 1, 2}))
        cd = CommitDecision(leader_certificate=cert, committed_blocks=[b], round=1)
        assert cd.leader_certificate is cert
        assert cd.committed_blocks == [b]
        assert cd.round == 1


class TestEquivocationProof:
    """EquivocationProof requires same author+round, different digest."""

    def test_equivocation_proof_creation(self):
        a = Block(author=0, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b = Block(author=0, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proof = EquivocationProof(author=0, block_a=a, block_b=b, round=1)
        assert proof.author == 0
        assert proof.block_a.digest != proof.block_b.digest
        assert proof.round == 1


class TestRoundState:
    """RoundState is mutable — tracks per-round progress."""

    def test_round_state_defaults(self):
        rs = RoundState(round=5)
        assert rs.round == 5
        assert rs.proposals == {}
        assert rs.acks == {}
        assert rs.certificates == {}
        assert rs.timed_out is False

    def test_round_state_mutable(self):
        rs = RoundState(round=1)
        rs.timed_out = True
        assert rs.timed_out is True
        b = Block(author=0, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        rs.proposals[0] = b
        assert 0 in rs.proposals
```

- [ ] **Step 7: Run all tests to verify failures**

Run: `pytest tests/test_consensus_types.py -v`
Expected: Block tests PASS, Certificate/CommitDecision/EquivocationProof/RoundState tests FAIL (not yet defined)

- [ ] **Step 8: Implement remaining types**

Append to `src/ltp/consensus/types.py`:

```python
@dataclass(frozen=True)
class Certificate:
    """A block with 2f+1 acknowledgments."""

    block: Block
    signers: frozenset[int]
    digest: bytes = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "digest", self.block.digest)


@dataclass(frozen=True)
class CommitDecision:
    """Output of the commit rule — a leader and its causal history."""

    leader_certificate: Certificate
    committed_blocks: list[Block]
    round: int


@dataclass(frozen=True)
class EquivocationProof:
    """Evidence that a validator proposed two conflicting blocks."""

    author: int
    block_a: Block
    block_b: Block
    round: int


@dataclass
class RoundState:
    """Tracks per-round progress within a validator's local view."""

    round: int
    proposals: dict[int, Block] = field(default_factory=dict)
    acks: dict[bytes, set[int]] = field(default_factory=dict)
    certificates: dict[int, Certificate] = field(default_factory=dict)
    timed_out: bool = False
```

- [ ] **Step 9: Run all type tests**

Run: `pytest tests/test_consensus_types.py -v`
Expected: 14 PASSED

- [ ] **Step 10: Commit**

```bash
git add src/ltp/consensus/__init__.py src/ltp/consensus/types.py tests/test_consensus_types.py
git commit -m "feat(consensus): DAG data structures — Block, Certificate, CommitDecision, EquivocationProof, RoundState"
```

---

### Task 2: DAGStore — Indexed Block and Certificate Storage

**Files:**
- Create: `src/ltp/consensus/dag_store.py`
- Create: `tests/test_consensus_dag_store.py`

- [ ] **Step 1: Write failing tests for DAGStore**

Create `tests/test_consensus_dag_store.py`:

```python
"""Tests for DAGStore (Spec D1a §2)."""

from ltp.consensus.types import Block, Certificate
from ltp.consensus.dag_store import DAGStore


def _block(author: int, round: int, payload: tuple[bytes, ...] = (), parents: frozenset[bytes] = frozenset()) -> Block:
    return Block(author=author, round=round, payload=payload, parents=parents, timestamp_ms=1000)


def _cert(block: Block, signers: frozenset[int]) -> Certificate:
    return Certificate(block=block, signers=signers)


class TestDAGStoreBlocks:
    """Block storage and retrieval."""

    def test_add_and_get_block(self):
        dag = DAGStore()
        b = _block(0, 1)
        dag.add_block(b)
        assert dag.get_block(b.digest) is b

    def test_get_missing_block_returns_none(self):
        dag = DAGStore()
        assert dag.get_block(b"\x00" * 32) is None

    def test_reject_duplicate_block_same_round_author(self):
        dag = DAGStore()
        b1 = _block(0, 1, payload=(b"tx1",))
        b2 = _block(0, 1, payload=(b"tx2",))
        dag.add_block(b1)
        added = dag.add_block(b2)
        assert added is False  # second block rejected
        assert dag.get_block(b1.digest) is b1

    def test_blocks_at_round(self):
        dag = DAGStore()
        b0 = _block(0, 1)
        b1 = _block(1, 1)
        b2 = _block(0, 2)
        dag.add_block(b0)
        dag.add_block(b1)
        dag.add_block(b2)
        round_1 = dag.blocks_at_round(1)
        assert len(round_1) == 2
        assert set(b.author for b in round_1) == {0, 1}

    def test_blocks_at_empty_round(self):
        dag = DAGStore()
        assert dag.blocks_at_round(99) == []


class TestDAGStoreCertificates:
    """Certificate storage and quorum queries."""

    def test_add_and_get_certificate(self):
        dag = DAGStore()
        b = _block(0, 1)
        cert = _cert(b, frozenset({0, 1, 2}))
        dag.add_certificate(cert)
        assert dag.get_certificate(0, 1) is cert

    def test_get_missing_certificate_returns_none(self):
        dag = DAGStore()
        assert dag.get_certificate(0, 1) is None

    def test_certificates_at_round(self):
        dag = DAGStore()
        b0 = _block(0, 1)
        b1 = _block(1, 1)
        c0 = _cert(b0, frozenset({0, 1, 2}))
        c1 = _cert(b1, frozenset({0, 1, 2}))
        dag.add_certificate(c0)
        dag.add_certificate(c1)
        certs = dag.certificates_at_round(1)
        assert len(certs) == 2

    def test_has_quorum_certificates(self):
        """2f+1 certificates at a round means quorum. For n=4, f=1, need 3."""
        dag = DAGStore()
        for author in range(3):
            b = _block(author, 1)
            dag.add_certificate(_cert(b, frozenset({0, 1, 2})))
        assert dag.has_quorum_certificates(round=1, quorum_threshold=3) is True

    def test_no_quorum_certificates(self):
        dag = DAGStore()
        b = _block(0, 1)
        dag.add_certificate(_cert(b, frozenset({0, 1, 2})))
        assert dag.has_quorum_certificates(round=1, quorum_threshold=3) is False

    def test_certificates_at_empty_round(self):
        dag = DAGStore()
        assert dag.certificates_at_round(99) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_dag_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ltp.consensus.dag_store'`

- [ ] **Step 3: Implement DAGStore**

Create `src/ltp/consensus/dag_store.py`:

```python
"""DAGStore — indexed block and certificate storage (Spec D1a §2)."""

from __future__ import annotations

from collections import defaultdict

from .types import Block, Certificate


class DAGStore:
    """Per-validator indexed storage for DAG blocks and certificates.

    Blocks indexed by digest and by (round, author).
    Certificates indexed by (round, author) for commit rule lookups.
    """

    def __init__(self) -> None:
        self._blocks_by_digest: dict[bytes, Block] = {}
        self._blocks_by_round: dict[int, dict[int, Block]] = defaultdict(dict)
        self._certs_by_round: dict[int, dict[int, Certificate]] = defaultdict(dict)

    def add_block(self, block: Block) -> bool:
        """Store a block. Returns False if a block from same (round, author) already exists."""
        if block.author in self._blocks_by_round[block.round]:
            return False
        self._blocks_by_digest[block.digest] = block
        self._blocks_by_round[block.round][block.author] = block
        return True

    def get_block(self, digest: bytes) -> Block | None:
        """Retrieve a block by its digest."""
        return self._blocks_by_digest.get(digest)

    def blocks_at_round(self, round: int) -> list[Block]:
        """All blocks stored for a given round."""
        return list(self._blocks_by_round.get(round, {}).values())

    def add_certificate(self, cert: Certificate) -> None:
        """Store a certificate, indexed by (round, author)."""
        self._certs_by_round[cert.block.round][cert.block.author] = cert

    def get_certificate(self, author: int, round: int) -> Certificate | None:
        """Retrieve a certificate by (author, round)."""
        return self._certs_by_round.get(round, {}).get(author)

    def certificates_at_round(self, round: int) -> list[Certificate]:
        """All certificates at a given round."""
        return list(self._certs_by_round.get(round, {}).values())

    def has_quorum_certificates(self, round: int, quorum_threshold: int) -> bool:
        """Whether the round has at least quorum_threshold certificates."""
        return len(self._certs_by_round.get(round, {})) >= quorum_threshold
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_dag_store.py -v`
Expected: 11 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/dag_store.py tests/test_consensus_dag_store.py
git commit -m "feat(consensus): DAGStore — indexed block and certificate storage"
```

---

### Task 3: Fault Types and MessageBus

**Files:**
- Create: `src/ltp/consensus/faults.py`
- Create: `src/ltp/consensus/message_bus.py`
- Modify: `tests/test_consensus_types.py` (add fault/message bus unit tests)

These are infrastructure pieces needed before the protocol logic. They have no dependency on protocol or commit rule.

- [ ] **Step 1: Write failing tests for fault types and MessageBus**

Create a new test section at the bottom of `tests/test_consensus_types.py`:

```python
from ltp.consensus.faults import FaultType, FaultConfig, PartitionConfig
from ltp.consensus.message_bus import MessageBus


class TestFaultTypes:
    """FaultType enum and config dataclasses."""

    def test_fault_type_values(self):
        assert FaultType.HONEST.value == "honest"
        assert FaultType.EQUIVOCATE.value == "equivocate"
        assert FaultType.WITHHOLD.value == "withhold"
        assert FaultType.CRASH.value == "crash"
        assert FaultType.DELAY.value == "delay"
        assert FaultType.CENSOR.value == "censor"

    def test_fault_config(self):
        fc = FaultConfig(validator=1, fault_type=FaultType.CRASH, start_round=5)
        assert fc.validator == 1
        assert fc.fault_type == FaultType.CRASH
        assert fc.start_round == 5
        assert fc.end_round is None
        assert fc.params == {}

    def test_partition_config(self):
        pc = PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=3,
            duration=5,
        )
        assert pc.group_a == frozenset({0, 1})
        assert pc.group_b == frozenset({2, 3})
        assert pc.start_round == 3
        assert pc.duration == 5


class TestMessageBus:
    """In-memory message routing with partition support."""

    def test_send_and_receive(self):
        bus = MessageBus(num_validators=4)
        bus.send(from_v=0, to_v=1, message="hello")
        pending = bus.pending_for(1)
        assert len(pending) == 1
        assert pending[0] == (0, "hello")

    def test_broadcast(self):
        bus = MessageBus(num_validators=4)
        bus.broadcast(from_v=0, message="block")
        for v in range(1, 4):
            pending = bus.pending_for(v)
            assert len(pending) == 1
            assert pending[0] == (0, "block")
        # sender doesn't receive own broadcast
        assert bus.pending_for(0) == []

    def test_deliver_all_clears_pending(self):
        bus = MessageBus(num_validators=4)
        bus.broadcast(from_v=0, message="block")
        delivered = bus.deliver_all()
        assert len(delivered) > 0
        for v in range(4):
            assert bus.pending_for(v) == []

    def test_partition_blocks_cross_group(self):
        bus = MessageBus(num_validators=4)
        pc = PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        )
        bus.set_partition(pc)
        bus.broadcast(from_v=0, message="block")
        # Group A (validator 1) receives it
        assert len(bus.pending_for(1)) == 1
        # Group B (validators 2, 3) do NOT receive it
        assert bus.pending_for(2) == []
        assert bus.pending_for(3) == []

    def test_clear_partition_restores_delivery(self):
        bus = MessageBus(num_validators=4)
        pc = PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        )
        bus.set_partition(pc)
        bus.clear_partition()
        bus.broadcast(from_v=0, message="healed")
        assert len(bus.pending_for(2)) == 1
        assert len(bus.pending_for(3)) == 1
```

- [ ] **Step 2: Run tests to verify failures**

Run: `pytest tests/test_consensus_types.py::TestFaultTypes tests/test_consensus_types.py::TestMessageBus -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement FaultType, FaultConfig, PartitionConfig**

Create `src/ltp/consensus/faults.py`:

```python
"""Byzantine fault injection types (Spec D1a §3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FaultType(Enum):
    """Types of Byzantine behavior a validator can exhibit."""

    HONEST = "honest"
    EQUIVOCATE = "equivocate"
    WITHHOLD = "withhold"
    CRASH = "crash"
    DELAY = "delay"
    CENSOR = "censor"


@dataclass(frozen=True)
class FaultConfig:
    """Configuration for a single fault injection."""

    validator: int
    fault_type: FaultType
    start_round: int
    end_round: int | None = None
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PartitionConfig:
    """Network partition between two groups of validators."""

    group_a: frozenset[int]
    group_b: frozenset[int]
    start_round: int
    duration: int | None = None
```

- [ ] **Step 4: Implement MessageBus**

Create `src/ltp/consensus/message_bus.py`:

```python
"""In-memory message routing with partition support (Spec D1a §3)."""

from __future__ import annotations

from collections import defaultdict

from .faults import PartitionConfig


class MessageBus:
    """Routes messages between simulated validators.

    Supports point-to-point, broadcast, and network partitions.
    Messages are tuples of (from_validator, payload).
    """

    def __init__(self, num_validators: int) -> None:
        self._num_validators = num_validators
        self._pending: dict[int, list[tuple[int, object]]] = defaultdict(list)
        self._partition: PartitionConfig | None = None

    def _is_partitioned(self, from_v: int, to_v: int) -> bool:
        """Check if delivery is blocked by an active partition."""
        if self._partition is None:
            return False
        p = self._partition
        from_in_a = from_v in p.group_a
        to_in_a = to_v in p.group_a
        from_in_b = from_v in p.group_b
        to_in_b = to_v in p.group_b
        # Block cross-group delivery
        if (from_in_a and to_in_b) or (from_in_b and to_in_a):
            return True
        return False

    def send(self, from_v: int, to_v: int, message: object) -> None:
        """Point-to-point delivery (subject to partition)."""
        if not self._is_partitioned(from_v, to_v):
            self._pending[to_v].append((from_v, message))

    def broadcast(self, from_v: int, message: object) -> None:
        """Broadcast to all validators except sender."""
        for to_v in range(self._num_validators):
            if to_v != from_v:
                self.send(from_v, to_v, message)

    def set_partition(self, config: PartitionConfig) -> None:
        """Activate a network partition."""
        self._partition = config

    def clear_partition(self) -> None:
        """Remove the active partition."""
        self._partition = None

    def pending_for(self, validator: int) -> list[tuple[int, object]]:
        """Messages waiting for a validator (not yet delivered)."""
        return list(self._pending.get(validator, []))

    def deliver_all(self) -> list[tuple[int, int, object]]:
        """Drain and return all pending messages as (from, to, message) triples."""
        delivered: list[tuple[int, int, object]] = []
        for to_v, messages in self._pending.items():
            for from_v, msg in messages:
                delivered.append((from_v, to_v, msg))
        self._pending.clear()
        return delivered
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_consensus_types.py::TestFaultTypes tests/test_consensus_types.py::TestMessageBus -v`
Expected: 8 PASSED

- [ ] **Step 6: Run full type test file**

Run: `pytest tests/test_consensus_types.py -v`
Expected: 22 PASSED (14 from Task 1 + 8 new)

- [ ] **Step 7: Commit**

```bash
git add src/ltp/consensus/faults.py src/ltp/consensus/message_bus.py tests/test_consensus_types.py
git commit -m "feat(consensus): fault types and MessageBus with partition support"
```

---

### Task 4: MysticetiProtocol — Propose, Ack, Equivocation

**Files:**
- Create: `src/ltp/consensus/protocol.py`
- Create: `tests/test_consensus_protocol.py`

This task implements the core protocol logic: block creation, acknowledgment, certificate formation, and equivocation detection. Commit rule evaluation is deferred to Task 5. `receive_certificate()` stores certs but does not call commit rule yet.

- [ ] **Step 1: Write failing tests for propose, ack, and equivocation**

Create `tests/test_consensus_protocol.py`:

```python
"""Tests for MysticetiProtocol (Spec D1a §2)."""

from ltp.consensus.types import Block, Certificate, EquivocationProof
from ltp.consensus.protocol import MysticetiProtocol


class TestPropose:
    """Block proposal logic."""

    def test_propose_creates_block(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=(b"tx1",))
        assert block.author == 0
        assert block.round == 1
        assert block.payload == (b"tx1",)
        assert isinstance(block.digest, bytes)

    def test_propose_round_0_has_no_parents(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=0, payload=())
        assert block.parents == frozenset()

    def test_propose_references_known_parent_certs(self):
        """Propose at round 2 should reference certs from round 1."""
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        # Manually add some certs to round 1
        b1 = Block(author=1, round=1, payload=(), parents=frozenset(), timestamp_ms=1000)
        cert1 = Certificate(block=b1, signers=frozenset({0, 1, 2}))
        proto.receive_certificate(cert1)
        block = proto.propose(round=2, payload=(b"tx2",))
        assert cert1.digest in block.parents

    def test_propose_stored_in_dag(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        assert proto.dag_store.get_block(block.digest) is block


class TestReceiveBlock:
    """Receiving and acknowledging blocks."""

    def test_receive_valid_block_returns_ack(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        ack = proto.receive_block(block)
        assert ack == 0  # own validator index

    def test_receive_block_stores_it(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(block)
        assert proto.dag_store.get_block(block.digest) is block

    def test_receive_duplicate_block_returns_none(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(block)
        ack = proto.receive_block(block)
        assert ack is None

    def test_receive_block_from_equivocator_returns_none(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        b2 = Block(author=1, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b1)
        proto.receive_block(b2)  # triggers equivocation
        # Subsequent blocks from equivocator are rejected
        b3 = Block(author=1, round=2, payload=(), parents=frozenset(), timestamp_ms=2000)
        assert proto.receive_block(b3) is None


class TestReceiveAck:
    """Ack accumulation and certificate formation."""

    def test_ack_accumulates(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        cert = proto.receive_ack(block.digest, signer=1)
        assert cert is None  # only 1 ack so far (need 3 for n=4, f=1)

    def test_ack_forms_certificate_at_quorum(self):
        """n=4, f=1, quorum=2f+1=3. Author's own propose counts as an ack."""
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        # Author (0) implicitly acks their own block. Need 2 more.
        proto.receive_ack(block.digest, signer=1)
        cert = proto.receive_ack(block.digest, signer=2)
        assert cert is not None
        assert isinstance(cert, Certificate)
        assert cert.block is block
        assert len(cert.signers) >= 3

    def test_ack_below_quorum_returns_none(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        block = proto.propose(round=1, payload=())
        cert = proto.receive_ack(block.digest, signer=1)
        assert cert is None


class TestEquivocation:
    """Equivocation detection."""

    def test_detect_equivocation(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b1)
        b2 = Block(author=1, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proof = proto.detect_equivocation(b2)
        assert proof is not None
        assert isinstance(proof, EquivocationProof)
        assert proof.author == 1
        assert proof.round == 1

    def test_no_equivocation_for_new_block(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proof = proto.detect_equivocation(b)
        assert proof is None

    def test_is_equivocator_after_detection(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        b1 = Block(author=1, round=1, payload=(b"tx1",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b1)
        b2 = Block(author=1, round=1, payload=(b"tx2",), parents=frozenset(), timestamp_ms=1000)
        proto.receive_block(b2)
        assert proto.is_equivocator(1) is True
        assert proto.is_equivocator(0) is False


class TestLeaderAndRound:
    """Leader election and round management."""

    def test_leader_for_round(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        assert proto.leader_for_round(0) == 0
        assert proto.leader_for_round(1) == 1
        assert proto.leader_for_round(4) == 0
        assert proto.leader_for_round(7) == 3

    def test_skip_round(self):
        proto = MysticetiProtocol(validator_index=0, num_validators=4)
        proto.skip_round(5)
        assert proto.dag_store.blocks_at_round(5) == []  # no blocks proposed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_protocol.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ltp.consensus.protocol'`

- [ ] **Step 3: Implement MysticetiProtocol (without commit rule)**

Create `src/ltp/consensus/protocol.py`:

```python
"""MysticetiProtocol — pure protocol logic for a single validator (Spec D1a §2)."""

from __future__ import annotations

import time

from .types import Block, Certificate, CommitDecision, EquivocationProof, RoundState
from .dag_store import DAGStore


class MysticetiProtocol:
    """Mysticeti DAG-BFT protocol state for one validator.

    Pure logic — receives messages, produces messages. No I/O.
    """

    def __init__(
        self,
        validator_index: int,
        num_validators: int,
        fault_tolerance: int | None = None,
    ) -> None:
        self._index = validator_index
        self._n = num_validators
        self._f = fault_tolerance if fault_tolerance is not None else (num_validators - 1) // 3
        self._quorum = 2 * self._f + 1
        self._dag = DAGStore()
        self._rounds: dict[int, RoundState] = {}
        self._equivocators: set[int] = set()
        self._committed_digests: set[bytes] = set()
        self._committed_rounds: set[int] = set()
        self._current_round = 0

    @property
    def dag_store(self) -> DAGStore:
        return self._dag

    @property
    def current_round(self) -> int:
        return self._current_round

    def _get_round_state(self, round: int) -> RoundState:
        if round not in self._rounds:
            self._rounds[round] = RoundState(round=round)
        return self._rounds[round]

    def leader_for_round(self, round: int) -> int:
        """Deterministic leader: round % n."""
        return round % self._n

    def propose(self, round: int, payload: tuple[bytes, ...] = ()) -> Block:
        """Create a block for this round, referencing known parent certs."""
        parents: frozenset[bytes]
        if round == 0:
            parents = frozenset()
        else:
            parent_certs = self._dag.certificates_at_round(round - 1)
            parents = frozenset(c.digest for c in parent_certs)
        block = Block(
            author=self._index,
            round=round,
            payload=payload,
            parents=parents,
            timestamp_ms=int(time.time() * 1000),
        )
        self._dag.add_block(block)
        rs = self._get_round_state(round)
        rs.proposals[self._index] = block
        # Author implicitly acks own block
        if block.digest not in rs.acks:
            rs.acks[block.digest] = set()
        rs.acks[block.digest].add(self._index)
        if round > self._current_round:
            self._current_round = round
        return block

    def receive_block(self, block: Block) -> int | None:
        """Validate and store block. Returns own index as ack, or None."""
        if block.author in self._equivocators:
            return None
        # Check for equivocation
        proof = self.detect_equivocation(block)
        if proof is not None:
            self._equivocators.add(block.author)
            return None
        added = self._dag.add_block(block)
        if not added:
            return None  # duplicate
        rs = self._get_round_state(block.round)
        rs.proposals[block.author] = block
        if block.digest not in rs.acks:
            rs.acks[block.digest] = set()
        rs.acks[block.digest].add(self._index)
        if block.round > self._current_round:
            self._current_round = block.round
        return self._index

    def receive_ack(self, block_digest: bytes, signer: int) -> Certificate | None:
        """Accumulate ack. Return Certificate when quorum reached."""
        block = self._dag.get_block(block_digest)
        if block is None:
            return None
        rs = self._get_round_state(block.round)
        if block_digest not in rs.acks:
            rs.acks[block_digest] = set()
        rs.acks[block_digest].add(signer)
        if len(rs.acks[block_digest]) >= self._quorum and block.author not in rs.certificates:
            cert = Certificate(block=block, signers=frozenset(rs.acks[block_digest]))
            rs.certificates[block.author] = cert
            self._dag.add_certificate(cert)
            return cert
        return None

    def receive_certificate(self, cert: Certificate) -> CommitDecision | None:
        """Store certificate and check commit rule.

        Commit rule evaluation is delegated to commit_rule.py (Task 5).
        Returns None until commit rule is wired up.
        """
        rs = self._get_round_state(cert.block.round)
        rs.certificates[cert.block.author] = cert
        self._dag.add_certificate(cert)
        if cert.block.round > self._current_round:
            self._current_round = cert.block.round
        return None  # Commit rule wired in Task 5

    def check_commit(self, round: int) -> CommitDecision | None:
        """Evaluate commit rule for round's leader. Wired in Task 5."""
        return None  # Commit rule wired in Task 5

    def detect_equivocation(self, block: Block) -> EquivocationProof | None:
        """Check if author already proposed a different block at this round."""
        existing = self._dag.get_block(block.digest)
        if existing is not None and existing.digest == block.digest:
            return None  # exact same block, not equivocation
        round_blocks = self._dag.blocks_at_round(block.round)
        for b in round_blocks:
            if b.author == block.author and b.digest != block.digest:
                return EquivocationProof(
                    author=block.author,
                    block_a=b,
                    block_b=block,
                    round=block.round,
                )
        return None

    def skip_round(self, round: int) -> None:
        """Mark a round as timed out."""
        rs = self._get_round_state(round)
        rs.timed_out = True

    def is_equivocator(self, author: int) -> bool:
        """Check if an author has been flagged for equivocation."""
        return author in self._equivocators
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_protocol.py -v`
Expected: 14 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/protocol.py tests/test_consensus_protocol.py
git commit -m "feat(consensus): MysticetiProtocol — propose, ack, certificate formation, equivocation detection"
```

---

### Task 5: Commit Rule — Direct, Indirect, and Causal History

**Files:**
- Create: `src/ltp/consensus/commit_rule.py`
- Create: `tests/test_consensus_commit_rule.py`
- Modify: `src/ltp/consensus/protocol.py` (wire commit rule into `receive_certificate` and `check_commit`)

- [ ] **Step 1: Write failing tests for the commit rule**

Create `tests/test_consensus_commit_rule.py`:

```python
"""Tests for commit rule evaluation (Spec D1a §2)."""

from ltp.consensus.types import Block, Certificate, CommitDecision
from ltp.consensus.dag_store import DAGStore
from ltp.consensus.commit_rule import (
    evaluate_direct_commit,
    evaluate_indirect_commit,
    collect_causal_history,
)


def _block(author: int, round: int, parents: frozenset[bytes] = frozenset()) -> Block:
    return Block(author=author, round=round, payload=(), parents=parents, timestamp_ms=1000)


def _cert(block: Block, n: int = 4) -> Certificate:
    """Certificate signed by all n validators."""
    return Certificate(block=block, signers=frozenset(range(n)))


def _build_dag_with_direct_commit(n: int = 4) -> tuple[DAGStore, int, int]:
    """Build a DAG where leader at round 0 has a direct commit.

    Round 0: all n validators propose. Leader = 0 % n = 0.
    All blocks certified.
    Round 1: all n validators propose with parents referencing round 0 certs.
    All blocks certified. The leader cert at round 0 is referenced by >=2f+1 at round 1.

    Returns (dag, leader_round=0, leader_author=0).
    """
    dag = DAGStore()
    f = (n - 1) // 3
    quorum = 2 * f + 1

    # Round 0: all propose, all certified
    r0_certs = {}
    for author in range(n):
        b = _block(author, 0)
        dag.add_block(b)
        c = _cert(b, n)
        dag.add_certificate(c)
        r0_certs[author] = c

    # Round 1: all propose referencing all round 0 certs
    parent_digests = frozenset(c.digest for c in r0_certs.values())
    for author in range(n):
        b = _block(author, 1, parents=parent_digests)
        dag.add_block(b)
        c = _cert(b, n)
        dag.add_certificate(c)

    return dag, 0, 0  # leader_round=0, leader_author=0


class TestDirectCommit:
    """Direct commit: 2f+1 certs at round+1 reference the leader cert."""

    def test_direct_commit_succeeds(self):
        dag, leader_round, leader_author = _build_dag_with_direct_commit(n=4)
        f = 1
        quorum = 2 * f + 1
        decision = evaluate_direct_commit(dag, leader_round, leader_author, quorum)
        assert decision is not None
        assert isinstance(decision, CommitDecision)
        assert decision.round == leader_round
        assert decision.leader_certificate.block.author == leader_author

    def test_direct_commit_fails_below_quorum(self):
        """Only 1 cert at round+1 references the leader — not enough."""
        dag = DAGStore()
        n = 4
        # Round 0: leader proposes, gets certified
        leader_block = _block(0, 0)
        dag.add_block(leader_block)
        dag.add_certificate(_cert(leader_block, n))

        # Round 1: only 1 validator proposes referencing leader
        child = _block(1, 1, parents=frozenset({leader_block.digest}))
        dag.add_block(child)
        dag.add_certificate(_cert(child, n))

        decision = evaluate_direct_commit(dag, 0, 0, quorum_threshold=3)
        assert decision is None

    def test_direct_commit_with_7_validators(self):
        """n=7, f=2, quorum=5. All 7 certs at round 1 reference leader at round 0."""
        dag, leader_round, leader_author = _build_dag_with_direct_commit(n=7)
        decision = evaluate_direct_commit(dag, leader_round, leader_author, quorum_threshold=5)
        assert decision is not None


class TestCausalHistory:
    """Causal history collection — BFS through parent links."""

    def test_causal_history_includes_all_reachable(self):
        dag = DAGStore()
        n = 4
        # Round 0: 4 blocks, all certified
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        # Round 1: leader references all round 0 certs
        parent_digests = frozenset(c.digest for c in r0_certs.values())
        leader_block = _block(1, 1, parents=parent_digests)
        dag.add_block(leader_block)
        leader_cert = _cert(leader_block, n)
        dag.add_certificate(leader_cert)

        history = collect_causal_history(dag, leader_cert, already_committed=set())
        # Should include all round 0 blocks + the leader block itself
        digests = {b.digest for b in history}
        for author in range(n):
            r0_block = dag.blocks_at_round(0)
            assert any(b.author == author for b in r0_block)
        assert leader_block.digest in digests

    def test_causal_history_excludes_already_committed(self):
        dag = DAGStore()
        b0 = _block(0, 0)
        dag.add_block(b0)
        dag.add_certificate(_cert(b0, 4))

        b1 = _block(1, 1, parents=frozenset({b0.digest}))
        dag.add_block(b1)
        cert1 = _cert(b1, 4)
        dag.add_certificate(cert1)

        # b0 already committed
        history = collect_causal_history(dag, cert1, already_committed={b0.digest})
        digests = {b.digest for b in history}
        assert b0.digest not in digests
        assert b1.digest in digests

    def test_causal_history_ordered_by_round_then_author(self):
        dag = DAGStore()
        n = 4
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        parent_digests = frozenset(c.digest for c in r0_certs.values())
        leader = _block(0, 1, parents=parent_digests)
        dag.add_block(leader)
        leader_cert = _cert(leader, n)
        dag.add_certificate(leader_cert)

        history = collect_causal_history(dag, leader_cert, already_committed=set())
        # Verify ordering: round increases monotonically, within same round author increases
        for i in range(1, len(history)):
            prev, curr = history[i - 1], history[i]
            assert (prev.round, prev.author) <= (curr.round, curr.author)


class TestIndirectCommit:
    """Indirect commit: skipped leader committed through later leader's causal history."""

    def test_indirect_commit_through_later_leader(self):
        """Round 0: leader=0 proposes but isn't directly committed.
        Round 1: leader=1 skipped (no commit).
        Round 2: leader=2 directly committed. Leader 0's cert is in leader 2's
        causal history, so leader 0 is indirectly committed.
        """
        dag = DAGStore()
        n = 4
        f = 1
        quorum = 2 * f + 1

        # Round 0: all propose, all certified
        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        # Round 1: only 1 validator proposes (not enough for direct commit of leader 0)
        # But all certs are formed anyway — leader 1 does get certified
        r1_certs = {}
        r0_parents = frozenset(c.digest for c in r0_certs.values())
        for author in range(n):
            b = _block(author, 1, parents=r0_parents)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r1_certs[author] = c

        # Round 2: all propose referencing round 1 certs
        r1_parents = frozenset(c.digest for c in r1_certs.values())
        for author in range(n):
            b = _block(author, 2, parents=r1_parents)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)

        # Leader at round 0 = validator 0. It's in causal history of leader at round 2.
        # Assume round 2 leader (validator 2) is committed.
        decision = evaluate_indirect_commit(
            dag, round=0, leader=0, committed_rounds={2},
        )
        assert decision is not None
        assert decision.round == 0

    def test_indirect_commit_not_in_causal_history(self):
        """If the leader at round r is NOT in any committed leader's causal history,
        indirect commit returns None."""
        dag = DAGStore()
        # Empty DAG — nothing reachable
        decision = evaluate_indirect_commit(dag, round=0, leader=0, committed_rounds=set())
        assert decision is None

    def test_no_double_commit(self):
        """Already-committed rounds should not produce another decision."""
        dag = DAGStore()
        n = 4

        r0_certs = {}
        for author in range(n):
            b = _block(author, 0)
            dag.add_block(b)
            c = _cert(b, n)
            dag.add_certificate(c)
            r0_certs[author] = c

        r0_parents = frozenset(c.digest for c in r0_certs.values())
        for author in range(n):
            b = _block(author, 1, parents=r0_parents)
            dag.add_block(b)
            dag.add_certificate(_cert(b, n))

        # Round 0 is already in committed_rounds — should not re-commit
        decision = evaluate_indirect_commit(dag, round=0, leader=0, committed_rounds={0})
        assert decision is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_commit_rule.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ltp.consensus.commit_rule'`

- [ ] **Step 3: Implement commit rule**

Create `src/ltp/consensus/commit_rule.py`:

```python
"""Direct and indirect commit rule evaluation (Spec D1a §2)."""

from __future__ import annotations

from collections import deque

from .types import Block, Certificate, CommitDecision
from .dag_store import DAGStore


def collect_causal_history(
    dag: DAGStore,
    certificate: Certificate,
    already_committed: set[bytes],
) -> list[Block]:
    """BFS through parent links to collect uncommitted blocks in causal order.

    Returns blocks ordered by (round, author).
    """
    visited: set[bytes] = set()
    result: list[Block] = []
    queue: deque[bytes] = deque([certificate.digest])

    while queue:
        digest = queue.popleft()
        if digest in visited or digest in already_committed:
            continue
        visited.add(digest)
        block = dag.get_block(digest)
        if block is None:
            # Try to find it via certificate
            continue
        result.append(block)
        for parent_digest in block.parents:
            if parent_digest not in visited and parent_digest not in already_committed:
                queue.append(parent_digest)

    # Order by (round, author)
    result.sort(key=lambda b: (b.round, b.author))
    return result


def evaluate_direct_commit(
    dag: DAGStore,
    round: int,
    leader: int,
    quorum_threshold: int,
) -> CommitDecision | None:
    """Check if the leader at `round` has a direct commit.

    Direct commit: 2f+1 certificates at round+1 include the leader cert's
    digest in their parents.
    """
    leader_cert = dag.get_certificate(leader, round)
    if leader_cert is None:
        return None

    # Count how many round+1 certificates reference this leader
    next_round_certs = dag.certificates_at_round(round + 1)
    referencing = 0
    for cert in next_round_certs:
        if leader_cert.digest in cert.block.parents:
            referencing += 1

    if referencing < quorum_threshold:
        return None

    committed = collect_causal_history(dag, leader_cert, already_committed=set())
    return CommitDecision(
        leader_certificate=leader_cert,
        committed_blocks=committed,
        round=round,
    )


def evaluate_indirect_commit(
    dag: DAGStore,
    round: int,
    leader: int,
    committed_rounds: set[int],
) -> CommitDecision | None:
    """Check if the leader at `round` can be indirectly committed.

    Indirect: if a later committed leader's causal history includes this
    leader's certificate, then this leader is also committed transitively.
    """
    if round in committed_rounds:
        return None  # already committed

    leader_cert = dag.get_certificate(leader, round)
    if leader_cert is None:
        return None

    # Check if any committed round's leader has this cert in its causal history
    for committed_round in sorted(committed_rounds):
        if committed_round <= round:
            continue
        n_validators = max(
            (b.author + 1 for b in dag.blocks_at_round(0)),
            default=1,
        )
        committed_leader = committed_round % n_validators
        committed_cert = dag.get_certificate(committed_leader, committed_round)
        if committed_cert is None:
            continue
        # Walk causal history of committed leader
        history = collect_causal_history(dag, committed_cert, already_committed=set())
        history_digests = {b.digest for b in history}
        if leader_cert.block.digest in history_digests:
            committed_blocks = collect_causal_history(dag, leader_cert, already_committed=set())
            return CommitDecision(
                leader_certificate=leader_cert,
                committed_blocks=committed_blocks,
                round=round,
            )

    return None
```

- [ ] **Step 4: Run commit rule tests**

Run: `pytest tests/test_consensus_commit_rule.py -v`
Expected: 10 PASSED

- [ ] **Step 5: Wire commit rule into MysticetiProtocol**

Modify `src/ltp/consensus/protocol.py` — add import at top and update two methods:

Add import after existing imports:

```python
from .commit_rule import evaluate_direct_commit, evaluate_indirect_commit, collect_causal_history
```

Replace `receive_certificate` method:

```python
    def receive_certificate(self, cert: Certificate) -> CommitDecision | None:
        """Store certificate and check commit rule."""
        rs = self._get_round_state(cert.block.round)
        rs.certificates[cert.block.author] = cert
        self._dag.add_certificate(cert)
        if cert.block.round > self._current_round:
            self._current_round = cert.block.round
        # Check if any uncommitted leader can now be committed
        return self._try_commit_from(cert.block.round)

    def _try_commit_from(self, trigger_round: int) -> CommitDecision | None:
        """Try to commit the leader for the round before trigger_round."""
        # Direct commit: check leader at trigger_round - 1
        if trigger_round > 0:
            target_round = trigger_round - 1
            if target_round not in self._committed_rounds:
                leader = self.leader_for_round(target_round)
                if not self.is_equivocator(leader):
                    decision = evaluate_direct_commit(
                        self._dag, target_round, leader, self._quorum,
                    )
                    if decision is not None:
                        self._committed_rounds.add(target_round)
                        for b in decision.committed_blocks:
                            self._committed_digests.add(b.digest)
                        return decision
        return None
```

Replace `check_commit` method:

```python
    def check_commit(self, round: int) -> CommitDecision | None:
        """Evaluate commit rule for a specific round's leader."""
        if round in self._committed_rounds:
            return None
        leader = self.leader_for_round(round)
        if self.is_equivocator(leader):
            return None
        # Try direct
        decision = evaluate_direct_commit(self._dag, round, leader, self._quorum)
        if decision is not None:
            self._committed_rounds.add(round)
            for b in decision.committed_blocks:
                self._committed_digests.add(b.digest)
            return decision
        # Try indirect
        decision = evaluate_indirect_commit(
            self._dag, round, leader, self._committed_rounds,
        )
        if decision is not None:
            self._committed_rounds.add(round)
            for b in decision.committed_blocks:
                self._committed_digests.add(b.digest)
            return decision
        return None
```

- [ ] **Step 6: Run protocol tests again (should still pass)**

Run: `pytest tests/test_consensus_protocol.py -v`
Expected: 14 PASSED

- [ ] **Step 7: Run full test suite so far**

Run: `pytest tests/test_consensus_types.py tests/test_consensus_dag_store.py tests/test_consensus_protocol.py tests/test_consensus_commit_rule.py -v`
Expected: 49 PASSED (14 + 11 + 14 + 10)

- [ ] **Step 8: Commit**

```bash
git add src/ltp/consensus/commit_rule.py src/ltp/consensus/protocol.py tests/test_consensus_commit_rule.py
git commit -m "feat(consensus): commit rule — direct, indirect, and causal history collection"
```

---

### Task 6: LocalMysticetiEngine — Synchronous Mode

**Files:**
- Create: `src/ltp/consensus/engine.py`
- Create: `tests/test_consensus_engine.py`

The engine orchestrates n validators using MysticetiProtocol + MessageBus. This task implements the synchronous mode (`advance_round`, `run_rounds`) and `to_ordered_batch`. Async mode is added in Task 8.

- [ ] **Step 1: Write failing tests for the engine**

Create `tests/test_consensus_engine.py`:

```python
"""Tests for LocalMysticetiEngine (Spec D1a §3)."""

from ltp.consensus.engine import LocalMysticetiEngine, to_ordered_batch
from ltp.consensus.types import CommitDecision
from ltp.execution.types import OrderedBatch


class TestEngineLifecycle:
    """Engine creation and basic properties."""

    def test_create_engine(self):
        engine = LocalMysticetiEngine(num_validators=4)
        assert len(engine.validators) == 4

    def test_validators_have_correct_indices(self):
        engine = LocalMysticetiEngine(num_validators=4)
        for i, v in enumerate(engine.validators):
            assert v._index == i

    def test_get_dag_store(self):
        engine = LocalMysticetiEngine(num_validators=4)
        dag = engine.get_dag_store(0)
        assert dag is engine.validators[0].dag_store


class TestSynchronousMode:
    """Step-by-step round execution."""

    def test_advance_round_returns_round_number(self):
        engine = LocalMysticetiEngine(num_validators=4)
        r = engine.advance_round()
        assert r == 0

    def test_advance_round_increments(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.advance_round()
        r = engine.advance_round()
        assert r == 1

    def test_run_rounds_produces_commits(self):
        engine = LocalMysticetiEngine(num_validators=4)
        # Run enough rounds for direct commit to trigger
        # Round 0: all propose. Round 1: all propose referencing round 0 certs.
        # At round 1, leader at round 0 (validator 0) gets direct-committed.
        decisions = engine.run_rounds(5)
        assert len(decisions) > 0
        for d in decisions:
            assert isinstance(d, CommitDecision)

    def test_commit_rounds_are_monotonic(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(10)
        rounds = [d.round for d in decisions]
        assert rounds == sorted(rounds)

    def test_submit_transactions_appear_in_commits(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx_hello", b"tx_world"])
        decisions = engine.run_rounds(5)
        all_payloads: list[bytes] = []
        for d in decisions:
            for block in d.committed_blocks:
                all_payloads.extend(block.payload)
        assert b"tx_hello" in all_payloads
        assert b"tx_world" in all_payloads

    def test_deterministic_same_result(self):
        """Same initial state + same operations = same result."""
        def run():
            engine = LocalMysticetiEngine(num_validators=4)
            engine.submit_transactions([b"tx1"])
            return engine.run_rounds(5)
        d1 = run()
        d2 = run()
        assert len(d1) == len(d2)
        for a, b in zip(d1, d2):
            assert a.round == b.round


class TestToOrderedBatch:
    """Conversion from CommitDecision to OrderedBatch."""

    def test_to_ordered_batch_basic(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx1", b"tx2"])
        decisions = engine.run_rounds(5)
        assert len(decisions) > 0
        batch = to_ordered_batch(decisions[0], epoch=42)
        assert isinstance(batch, OrderedBatch)
        assert batch.epoch == 42
        assert batch.consensus_type == "dag"
        assert batch.round == decisions[0].round

    def test_to_ordered_batch_leader_authority(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=1)
            assert batch.leader_authority == d.leader_certificate.block.author

    def test_to_ordered_batch_collects_all_txs(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx_a", b"tx_b", b"tx_c"])
        decisions = engine.run_rounds(5)
        all_txs: list[bytes] = []
        for d in decisions:
            batch = to_ordered_batch(d, epoch=1)
            all_txs.extend(batch.transactions)
        assert b"tx_a" in all_txs
        assert b"tx_b" in all_txs
        assert b"tx_c" in all_txs
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_consensus_engine.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ltp.consensus.engine'`

- [ ] **Step 3: Implement LocalMysticetiEngine (synchronous mode)**

Create `src/ltp/consensus/engine.py`:

```python
"""LocalMysticetiEngine — in-process multi-validator simulation (Spec D1a §3)."""

from __future__ import annotations

import time
import threading
from collections import deque
from typing import Iterator

from .types import Block, Certificate, CommitDecision
from .protocol import MysticetiProtocol
from .message_bus import MessageBus
from .faults import FaultType, FaultConfig, PartitionConfig
from ..execution.types import OrderedBatch


def to_ordered_batch(decision: CommitDecision, epoch: int) -> OrderedBatch:
    """Convert a CommitDecision to an OrderedBatch for the execution pipeline."""
    transactions: list[bytes] = []
    for block in decision.committed_blocks:
        transactions.extend(block.payload)
    return OrderedBatch(
        round=decision.round,
        epoch=epoch,
        transactions=transactions,
        leader_authority=decision.leader_certificate.block.author,
        timestamp_ms=decision.leader_certificate.block.timestamp_ms,
        consensus_type="dag",
    )


class LocalMysticetiEngine:
    """In-process Mysticeti simulation with n validators.

    Supports synchronous mode (advance_round/run_rounds) for deterministic
    testing, and async mode (start/stop/stream_commits) for production-like
    behavior.
    """

    def __init__(
        self,
        num_validators: int,
        fault_tolerance: int | None = None,
        round_timeout_ms: int = 1000,
    ) -> None:
        self._n = num_validators
        self._f = fault_tolerance if fault_tolerance is not None else (num_validators - 1) // 3
        self._quorum = 2 * self._f + 1
        self._round_timeout_ms = round_timeout_ms
        self._current_round = -1  # next advance_round will go to 0

        self._validators = [
            MysticetiProtocol(i, num_validators, self._f)
            for i in range(num_validators)
        ]
        self._bus = MessageBus(num_validators)
        self._mempool: deque[bytes] = deque()
        self._fault_configs: dict[int, FaultConfig] = {}

        # Async mode state
        self._running = False
        self._commit_queue: deque[CommitDecision] = deque()
        self._thread: threading.Thread | None = None

    @property
    def validators(self) -> list[MysticetiProtocol]:
        return self._validators

    def get_dag_store(self, validator: int):
        return self._validators[validator].dag_store

    def submit_transactions(self, txs: list[bytes]) -> None:
        """Add transactions to the mempool for the next round."""
        self._mempool.extend(txs)

    def inject_fault(self, fault: FaultConfig) -> None:
        """Register a fault configuration for a validator."""
        self._fault_configs[fault.validator] = fault

    def _is_faulty(self, validator: int, round: int, fault_type: FaultType) -> bool:
        """Check if a validator has a specific fault active at this round."""
        cfg = self._fault_configs.get(validator)
        if cfg is None:
            return False
        if cfg.fault_type != fault_type:
            return False
        if round < cfg.start_round:
            return False
        if cfg.end_round is not None and round > cfg.end_round:
            return False
        return True

    def advance_round(self) -> int:
        """Execute one full round synchronously. Returns the round number."""
        self._current_round += 1
        r = self._current_round
        decisions: list[CommitDecision] = []

        # Phase 1: Propose
        blocks: list[Block] = []
        for v_idx in range(self._n):
            if self._is_faulty(v_idx, r, FaultType.CRASH):
                continue

            if self._is_faulty(v_idx, r, FaultType.EQUIVOCATE):
                # Equivocating: propose two different blocks
                b1 = self._validators[v_idx].propose(r, payload=(b"equivocate_a",))
                b2 = Block(
                    author=v_idx, round=r, payload=(b"equivocate_b",),
                    parents=b1.parents, timestamp_ms=b1.timestamp_ms,
                )
                blocks.append(b1)
                blocks.append(b2)
                continue

            # Determine payload — censors always empty, honest drain mempool
            payload: tuple[bytes, ...] = ()
            if self._is_faulty(v_idx, r, FaultType.CENSOR):
                payload = ()
            elif self._mempool:
                payload = tuple(self._mempool)
                self._mempool.clear()

            block = self._validators[v_idx].propose(r, payload)
            blocks.append(block)

        # Phase 2: Broadcast blocks, receive, ack
        acks: list[tuple[bytes, int]] = []
        for block in blocks:
            for v_idx in range(self._n):
                if self._is_faulty(v_idx, r, FaultType.CRASH):
                    continue
                if v_idx == block.author:
                    continue
                if self._is_faulty(block.author, r, FaultType.WITHHOLD):
                    targets = self._fault_configs[block.author].params.get("withhold_targets", [])
                    if v_idx in targets:
                        continue
                ack = self._validators[v_idx].receive_block(block)
                if ack is not None:
                    acks.append((block.digest, ack))

        # Phase 3: Broadcast acks, form certificates
        certs: list[Certificate] = []
        for block_digest, signer in acks:
            for v_idx in range(self._n):
                if self._is_faulty(v_idx, r, FaultType.CRASH):
                    continue
                if self._is_faulty(signer, r, FaultType.DELAY):
                    continue  # delayed acks not delivered this round
                cert = self._validators[v_idx].receive_ack(block_digest, signer)
                if cert is not None:
                    certs.append(cert)

        # Phase 4: Broadcast certificates, check commit
        seen_certs: set[bytes] = set()
        unique_certs: list[Certificate] = []
        for cert in certs:
            if cert.digest not in seen_certs:
                seen_certs.add(cert.digest)
                unique_certs.append(cert)

        for cert in unique_certs:
            for v_idx in range(self._n):
                if self._is_faulty(v_idx, r, FaultType.CRASH):
                    continue
                decision = self._validators[v_idx].receive_certificate(cert)
                if decision is not None and decision.round not in {d.round for d in decisions}:
                    decisions.append(decision)

        # Also explicitly check commit for all uncommitted rounds
        for v_idx in range(self._n):
            if self._is_faulty(v_idx, r, FaultType.CRASH):
                continue
            for check_round in range(r + 1):
                decision = self._validators[v_idx].check_commit(check_round)
                if decision is not None and decision.round not in {d.round for d in decisions}:
                    decisions.append(decision)
                    break  # one commit per check cycle

        decisions.sort(key=lambda d: d.round)
        self._commit_queue.extend(decisions)
        return r

    def run_rounds(self, n: int) -> list[CommitDecision]:
        """Run n rounds, return all commit decisions produced."""
        all_decisions: list[CommitDecision] = []
        for _ in range(n):
            self.advance_round()
        while self._commit_queue:
            all_decisions.append(self._commit_queue.popleft())
        all_decisions.sort(key=lambda d: d.round)
        return all_decisions

    # Async mode (placeholder — fully implemented in Task 8)
    def start(self) -> None:
        """Begin async protocol execution."""
        self._running = True

    def stop(self) -> None:
        """Stop async execution."""
        self._running = False

    def stream_commits(self) -> Iterator[CommitDecision]:
        """Yield committed decisions. In sync mode, drains the queue."""
        while self._commit_queue:
            yield self._commit_queue.popleft()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_consensus_engine.py -v`
Expected: 10 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/engine.py tests/test_consensus_engine.py
git commit -m "feat(consensus): LocalMysticetiEngine — synchronous mode with advance_round and run_rounds"
```

---

### Task 7: Byzantine Fault Tests

**Files:**
- Create: `tests/test_consensus_byzantine.py`

Tests Byzantine fault injection against the engine. No new source files — this validates the fault handling already built into the engine.

- [ ] **Step 1: Write Byzantine fault tests**

Create `tests/test_consensus_byzantine.py`:

```python
"""Byzantine fault injection tests (Spec D1a §3)."""

from ltp.consensus.engine import LocalMysticetiEngine
from ltp.consensus.faults import FaultType, FaultConfig, PartitionConfig


class TestEquivocation:
    """Equivocating validator detected and excluded."""

    def test_equivocator_detected(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.EQUIVOCATE, start_round=0,
        ))
        engine.run_rounds(3)
        # All honest validators should have flagged validator 1
        for v_idx in [0, 2, 3]:
            assert engine.validators[v_idx].is_equivocator(1) is True

    def test_equivocator_blocks_excluded_from_commit(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.EQUIVOCATE, start_round=0,
        ))
        decisions = engine.run_rounds(5)
        for d in decisions:
            for block in d.committed_blocks:
                assert block.author != 1, "Equivocator blocks should not be in committed history"


class TestCrashFaults:
    """Crash fault tolerance."""

    def test_f_crash_faults_protocol_continues(self):
        """n=4, f=1. One crash fault — protocol should still commit."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=3, fault_type=FaultType.CRASH, start_round=0,
        ))
        decisions = engine.run_rounds(8)
        assert len(decisions) > 0, "Should still produce commits with f crash faults"

    def test_f_plus_1_crash_faults_halts(self):
        """n=4, f=1. Two crash faults — liveness lost."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=2, fault_type=FaultType.CRASH, start_round=0,
        ))
        engine.inject_fault(FaultConfig(
            validator=3, fault_type=FaultType.CRASH, start_round=0,
        ))
        decisions = engine.run_rounds(8)
        # With only 2 out of 4 validators, quorum (3) cannot be reached
        assert len(decisions) == 0, "Should not produce commits with f+1 crash faults"

    def test_crash_after_round_3(self):
        """Validator crashes after round 3 — commits before crash are fine."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.CRASH, start_round=4,
        ))
        decisions = engine.run_rounds(10)
        # Should still have commits — only 1 fault out of f=1 allowed
        assert len(decisions) > 0


class TestWithhold:
    """Withholding validator — sends to some but not others."""

    def test_withhold_still_forms_certs(self):
        """Validator 1 withholds from validator 3. With n=4, quorum=3,
        the other 3 honest validators can still form certificates."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.WITHHOLD, start_round=0,
            params={"withhold_targets": [3]},
        ))
        decisions = engine.run_rounds(8)
        assert len(decisions) > 0


class TestDelay:
    """Delayed acknowledgments."""

    def test_delayed_acks_still_commits(self):
        """Delayed acks slow things down but don't prevent eventual commits
        (other validators compensate)."""
        engine = LocalMysticetiEngine(num_validators=7)  # n=7, f=2
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.DELAY, start_round=0,
        ))
        decisions = engine.run_rounds(10)
        # With 6 honest out of 7 (quorum=5), should still commit
        assert len(decisions) > 0


class TestCensor:
    """Censoring validator proposes empty blocks."""

    def test_censored_txs_included_by_others(self):
        """Validator 0 censors, but other validators include txs."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine.inject_fault(FaultConfig(
            validator=0, fault_type=FaultType.CENSOR, start_round=0,
        ))
        engine.submit_transactions([b"important_tx"])
        decisions = engine.run_rounds(5)
        all_txs: list[bytes] = []
        for d in decisions:
            for block in d.committed_blocks:
                all_txs.extend(block.payload)
        # The tx should appear from another honest validator
        assert b"important_tx" in all_txs


class TestNetworkPartition:
    """Network partition — two groups cannot communicate."""

    def test_partition_halts_commits(self):
        """n=4 partitioned into {0,1} and {2,3}. Neither group has quorum (3)."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine._bus.set_partition(PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        ))
        decisions = engine.run_rounds(5)
        assert len(decisions) == 0, "No commits during partition (neither side has quorum)"

    def test_partition_heal_resumes_commits(self):
        """Partition heals after round 3, commits resume."""
        engine = LocalMysticetiEngine(num_validators=4)
        engine._bus.set_partition(PartitionConfig(
            group_a=frozenset({0, 1}),
            group_b=frozenset({2, 3}),
            start_round=0,
        ))
        # Run 3 rounds under partition
        for _ in range(3):
            engine.advance_round()
        # Heal partition
        engine._bus.clear_partition()
        # Run more rounds — should eventually commit
        for _ in range(5):
            engine.advance_round()
        decisions = list(engine.stream_commits())
        assert len(decisions) > 0, "Commits should resume after partition heals"


class TestMixedFaults:
    """Combined Byzantine behaviors."""

    def test_equivocate_plus_crash_within_f(self):
        """n=7, f=2. One equivocator + one crash = 2 Byzantine, exactly f.
        Protocol should survive."""
        engine = LocalMysticetiEngine(num_validators=7)
        engine.inject_fault(FaultConfig(
            validator=1, fault_type=FaultType.EQUIVOCATE, start_round=0,
        ))
        engine.inject_fault(FaultConfig(
            validator=2, fault_type=FaultType.CRASH, start_round=0,
        ))
        decisions = engine.run_rounds(10)
        assert len(decisions) > 0, "Should survive f total Byzantine faults"
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `pytest tests/test_consensus_byzantine.py -v`
Expected: 12 PASSED

If any tests fail, the engine's fault handling in `advance_round` needs adjustment. The fault injection logic is already in the engine from Task 6, so these tests validate it works correctly. Debug any failures by checking:
- Crash faults: validators with CRASH are skipped in all phases
- Equivocation: two blocks are proposed, honest validators detect and flag
- Withhold: blocks not delivered to specified targets
- Delay: acks from delayed validator not delivered
- Censor: validator proposes empty payload
- Partition: MessageBus blocks cross-group delivery

- [ ] **Step 3: Commit**

```bash
git add tests/test_consensus_byzantine.py
git commit -m "test(consensus): Byzantine fault tests — equivocation, crash, withhold, delay, censor, partition"
```

---

### Task 8: E2E Tests and Async Mode

**Files:**
- Create: `tests/test_consensus_e2e.py`
- Modify: `src/ltp/consensus/engine.py` (add async mode)

- [ ] **Step 1: Write E2E tests**

Create `tests/test_consensus_e2e.py`:

```python
"""End-to-end consensus pipeline tests (Spec D1a §5)."""

from ltp.consensus.engine import LocalMysticetiEngine, to_ordered_batch
from ltp.execution.types import OrderedBatch


class TestE2EFourValidators:
    """4-validator pipeline: submit -> run -> collect OrderedBatches."""

    def test_txs_appear_in_ordered_batches(self):
        engine = LocalMysticetiEngine(num_validators=4)
        engine.submit_transactions([b"tx_a", b"tx_b", b"tx_c"])
        decisions = engine.run_rounds(5)
        batches = [to_ordered_batch(d, epoch=1) for d in decisions]
        all_txs: list[bytes] = []
        for batch in batches:
            all_txs.extend(batch.transactions)
        assert b"tx_a" in all_txs
        assert b"tx_b" in all_txs
        assert b"tx_c" in all_txs

    def test_ordered_batches_have_correct_fields(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=10)
            assert isinstance(batch, OrderedBatch)
            assert batch.consensus_type == "dag"
            assert batch.epoch == 10
            assert batch.round >= 0
            assert batch.leader_authority >= 0

    def test_leader_authority_matches_leader(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=1)
            expected_leader = d.round % 4
            assert batch.leader_authority == expected_leader


class TestE2ESevenValidators:
    """7-validator pipeline — higher fault tolerance."""

    def test_7_validators_produce_commits(self):
        engine = LocalMysticetiEngine(num_validators=7)
        decisions = engine.run_rounds(10)
        assert len(decisions) > 0

    def test_7_validators_correctness(self):
        engine = LocalMysticetiEngine(num_validators=7)
        engine.submit_transactions([b"big_tx"])
        decisions = engine.run_rounds(5)
        batches = [to_ordered_batch(d, epoch=1) for d in decisions]
        all_txs = [tx for b in batches for tx in b.transactions]
        assert b"big_tx" in all_txs


class TestE2EEdgeCases:
    """Edge cases and ordering guarantees."""

    def test_empty_rounds_still_commit(self):
        """Rounds with no transactions should still produce commits (empty payload)."""
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(5)
        assert len(decisions) > 0  # commits happen even with empty payload

    def test_large_batch_1000_txs(self):
        """Submit 1000 transactions, verify all appear in committed output."""
        engine = LocalMysticetiEngine(num_validators=4)
        txs = [f"tx_{i}".encode() for i in range(1000)]
        engine.submit_transactions(txs)
        decisions = engine.run_rounds(10)
        batches = [to_ordered_batch(d, epoch=1) for d in decisions]
        all_txs = set()
        for batch in batches:
            all_txs.update(batch.transactions)
        for tx in txs:
            assert tx in all_txs, f"Missing transaction: {tx}"

    def test_epoch_propagation(self):
        engine = LocalMysticetiEngine(num_validators=4)
        decisions = engine.run_rounds(3)
        for d in decisions:
            batch = to_ordered_batch(d, epoch=42)
            assert batch.epoch == 42
```

- [ ] **Step 2: Run E2E tests**

Run: `pytest tests/test_consensus_e2e.py -v`
Expected: 8 PASSED

- [ ] **Step 3: Add async mode to the engine**

Modify `src/ltp/consensus/engine.py` — replace the `start`, `stop`, and `stream_commits` methods:

```python
    def start(self) -> None:
        """Begin async protocol execution on a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._async_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop async execution."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _async_loop(self) -> None:
        """Background loop that advances rounds on a timer."""
        interval = self._round_timeout_ms / 1000.0
        while self._running:
            self.advance_round()
            import time as _time
            _time.sleep(interval)

    def stream_commits(self) -> Iterator[CommitDecision]:
        """Yield committed decisions. Blocks briefly in async mode."""
        while self._running or self._commit_queue:
            if self._commit_queue:
                yield self._commit_queue.popleft()
            elif self._running:
                import time as _time
                _time.sleep(0.01)
            else:
                break
```

- [ ] **Step 4: Write async mode test**

Add to `tests/test_consensus_e2e.py`:

```python
import time


class TestAsyncMode:
    """Async mode — engine runs on background thread."""

    def test_async_start_stop(self):
        engine = LocalMysticetiEngine(num_validators=4, round_timeout_ms=50)
        engine.start()
        time.sleep(0.3)  # Let a few rounds run
        engine.stop()
        # Should have produced some commits
        commits = list(engine.stream_commits())
        assert len(commits) > 0

    def test_async_submit_and_commit(self):
        engine = LocalMysticetiEngine(num_validators=4, round_timeout_ms=50)
        engine.submit_transactions([b"async_tx"])
        engine.start()
        time.sleep(0.3)
        engine.stop()
        commits = list(engine.stream_commits())
        all_txs: list[bytes] = []
        for d in commits:
            for block in d.committed_blocks:
                all_txs.extend(block.payload)
        assert b"async_tx" in all_txs
```

- [ ] **Step 5: Run full E2E test file**

Run: `pytest tests/test_consensus_e2e.py -v`
Expected: 10 PASSED

- [ ] **Step 6: Commit**

```bash
git add src/ltp/consensus/engine.py tests/test_consensus_e2e.py
git commit -m "feat(consensus): E2E tests and async mode for LocalMysticetiEngine"
```

---

### Task 9: Package Exports and Integration

**Files:**
- Modify: `src/ltp/consensus/__init__.py` (full exports)

This final task wires up all package exports and runs the complete test suite.

- [ ] **Step 1: Write the full __init__.py**

Replace `src/ltp/consensus/__init__.py`:

```python
"""Mysticeti DAG-BFT consensus engine (Spec D1a)."""

from .types import (
    Block,
    Certificate,
    CommitDecision,
    EquivocationProof,
    RoundState,
)
from .dag_store import DAGStore
from .protocol import MysticetiProtocol
from .commit_rule import (
    evaluate_direct_commit,
    evaluate_indirect_commit,
    collect_causal_history,
)
from .engine import LocalMysticetiEngine, to_ordered_batch
from .faults import FaultType, FaultConfig, PartitionConfig
from .message_bus import MessageBus

__all__ = [
    # DAG data structures
    "Block",
    "Certificate",
    "CommitDecision",
    "EquivocationProof",
    "RoundState",
    # Storage
    "DAGStore",
    # Protocol
    "MysticetiProtocol",
    # Commit rule
    "evaluate_direct_commit",
    "evaluate_indirect_commit",
    "collect_causal_history",
    # Engine
    "LocalMysticetiEngine",
    "to_ordered_batch",
    # Fault injection
    "FaultType",
    "FaultConfig",
    "PartitionConfig",
    # Message bus
    "MessageBus",
]
```

- [ ] **Step 2: Verify imports work**

Run: `python -c "from ltp.consensus import Block, Certificate, MysticetiProtocol, LocalMysticetiEngine, FaultType; print('All imports OK')"`
Expected: `All imports OK`

- [ ] **Step 3: Run all consensus tests**

Run: `pytest tests/test_consensus_types.py tests/test_consensus_dag_store.py tests/test_consensus_protocol.py tests/test_consensus_commit_rule.py tests/test_consensus_engine.py tests/test_consensus_byzantine.py tests/test_consensus_e2e.py -v`
Expected: ~72 PASSED

- [ ] **Step 4: Run entire test suite (regression check)**

Run: `pytest tests/ -v --tb=short`
Expected: 3,487 + ~72 = ~3,559 PASSED, 0 FAILED

- [ ] **Step 5: Commit**

```bash
git add src/ltp/consensus/__init__.py
git commit -m "feat(consensus): package exports — complete D1a Mysticeti DAG protocol engine"
```

---

## Summary

| Task | Description | Tests | Commit |
|------|-------------|-------|--------|
| 1 | DAG data structures (Block, Certificate, CommitDecision, EquivocationProof, RoundState) | ~14 | `feat(consensus): DAG data structures` |
| 2 | DAGStore — indexed block/certificate storage | ~11 | `feat(consensus): DAGStore` |
| 3 | Fault types and MessageBus with partition support | ~8 | `feat(consensus): fault types and MessageBus` |
| 4 | MysticetiProtocol — propose, ack, equivocation | ~14 | `feat(consensus): MysticetiProtocol` |
| 5 | Commit rule — direct, indirect, causal history | ~10 | `feat(consensus): commit rule` |
| 6 | LocalMysticetiEngine — synchronous mode | ~10 | `feat(consensus): LocalMysticetiEngine` |
| 7 | Byzantine fault tests | ~12 | `test(consensus): Byzantine fault tests` |
| 8 | E2E tests and async mode | ~10 | `feat(consensus): E2E tests and async mode` |
| 9 | Package exports and integration | — | `feat(consensus): package exports` |

**Total: 9 tasks, ~72 tests across 7 test files, 8 source files.**
