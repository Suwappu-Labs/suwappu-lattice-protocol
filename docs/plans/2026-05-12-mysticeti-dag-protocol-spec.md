# Mysticeti DAG Protocol Engine (Spec D1a)

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Date:** May 12, 2026
**Depends on:** C3c (Threshold BLS Signing) — completed
**Delivers:** In-process Mysticeti DAG-BFT consensus engine with full protocol logic, Byzantine fault handling, and deterministic simulation
**Part of:** D1 (Consensus Protocol Integration), split as D1a/D1b/D1c

---

## Overview

Spec D1a implements the core Mysticeti DAG-BFT protocol as a self-contained Python package. Mysticeti is a multi-leader DAG-based BFT protocol (proven in Sui) that achieves sub-second latency by eliminating explicit voting rounds — certificates form implicitly through acknowledgments, and a deterministic commit rule extracts a total order from the DAG.

This spec builds a `LocalMysticetiEngine` that runs the full protocol in-process with multiple simulated validators. It serves as both the development/test engine and the reference implementation for the production Rust sidecar (D1b). The engine supports high-fidelity Byzantine fault injection including equivocation, crash faults, message withholding, and network partitions.

### D1 Decomposition

| Sub-spec | Scope | Status |
|----------|-------|--------|
| **D1a (this)** | DAG protocol engine — types, protocol logic, commit rule, local engine, Byzantine faults | This spec |
| **D1b** | Consensus adapter — MysticetiAdapter, gRPC client, dual-mode validator sets, committee integration | After D1a |
| **D1c** | NodeExecutor — pull/push execution loops, production pipeline wiring, threshold attestations | After D1b |

### Architecture Decisions (confirmed)

- **Consensus family:** Mysticeti DAG-BFT
- **Integration model:** Sidecar interface + local Python simulation. Production swaps the local engine for a Rust `etp-mysticeti-sidecar` via gRPC.
- **Protocol fidelity:** High — full DAG, certificate formation, direct/indirect commit, view change, equivocation detection, Byzantine fault injection
- **AWS:** Available for additional capacity when needed

---

## 1. DAG Data Structures

### Block (frozen dataclass)

A single proposal from a validator.

| Field | Type | Description |
|-------|------|-------------|
| `author` | `int` | Validator index (0-based) |
| `round` | `int` | DAG round number |
| `payload` | `tuple[bytes, ...]` | Transactions included (immutable for frozen dataclass) |
| `parents` | `frozenset[bytes]` | Digests of parent blocks from round-1 |
| `timestamp_ms` | `int` | Wall clock when proposed |
| `digest` | `bytes` | SHA3-256 of (author, round, payload, parents) — computed once, cached |

The digest is computed deterministically: `SHA3-256(author.to_bytes(4) || round.to_bytes(8) || len(payload).to_bytes(4) || concat(sorted(payload)) || concat(sorted(parents)))`. This ensures the same logical block always produces the same digest regardless of field ordering.

### Certificate (frozen dataclass)

A block with 2f+1 acknowledgments.

| Field | Type | Description |
|-------|------|-------------|
| `block` | `Block` | The certified block |
| `signers` | `frozenset[int]` | Set of validator indices that acknowledged |
| `digest` | `bytes` | Same as block.digest — certificates reference blocks 1:1 |

A certificate is valid when `len(signers) >= 2f + 1` where `f = (n - 1) // 3`. Certificates are the building blocks of the DAG — each round's blocks reference the previous round's certificates through their `parents` field.

### CommitDecision (frozen dataclass)

Output of the commit rule.

| Field | Type | Description |
|-------|------|-------------|
| `leader_certificate` | `Certificate` | The leader block that was committed |
| `committed_blocks` | `list[Block]` | All blocks reachable from this leader (causal history), in causal order |
| `round` | `int` | The round this commit covers |

Causal ordering: blocks are ordered by `(round, author)`. All blocks at round `r` come before all blocks at round `r+1`. Within a round, blocks are ordered by author index.

### EquivocationProof (frozen dataclass)

Evidence that a validator proposed two conflicting blocks.

| Field | Type | Description |
|-------|------|-------------|
| `author` | `int` | The equivocating validator |
| `block_a` | `Block` | First block |
| `block_b` | `Block` | Conflicting block (same round+author, different digest) |
| `round` | `int` | The round where equivocation occurred |

### RoundState (dataclass, mutable)

Tracks per-round progress within a validator's local view.

| Field | Type | Description |
|-------|------|-------------|
| `round` | `int` | Which round |
| `proposals` | `dict[int, Block]` | author -> block |
| `acks` | `dict[bytes, set[int]]` | block_digest -> set of ack signers |
| `certificates` | `dict[int, Certificate]` | author -> certificate |
| `timed_out` | `bool` | Whether this round was skipped |

---

## 2. Mysticeti Protocol Logic

### Protocol Phases

**1. Propose** — Every validator proposes one block per round. The block's `parents` field references all certificates from the previous round that the validator has seen. Multi-leader: all validators propose simultaneously.

**2. Acknowledge** — When a validator receives a valid block, it sends an acknowledgment (the validator's index). When a block accumulates 2f+1 acknowledgments, it becomes a `Certificate`. No separate voting phase — this is Mysticeti's key optimization.

**3. Commit Rule** — Deterministic leader election: `leader = round % n`. A leader certificate at round `r` is committed when:

- **Direct commit:** 2f+1 certificates at round `r+1` include the leader cert's digest in their parents. The supermajority saw the leader.
- **Indirect commit:** If a leader at round `r` wasn't directly committed but a later leader at round `r+k` IS committed, and the round `r` leader is in the causal history of the round `r+k` leader, then round `r`'s leader is committed transitively.

When a leader is committed, all blocks in its causal history that haven't been committed yet are also committed, in causal order. This produces a `CommitDecision`.

**4. View Change (Timeout)** — If a round doesn't produce enough certificates within a timeout, validators skip the leader for that round and advance. The skipped leader's blocks can still be committed later via indirect commit if they're in a future leader's causal history.

**5. Equivocation Detection** — If a validator proposes two different blocks for the same `(round, author)`, any validator that sees both produces an `EquivocationProof`. The equivocating validator is flagged, and its blocks are excluded from commit consideration.

### MysticetiProtocol

Pure protocol logic for a single validator. No I/O — receives messages, produces messages.

```python
class MysticetiProtocol:
    def __init__(
        self,
        validator_index: int,
        num_validators: int,
        fault_tolerance: int | None = None,  # defaults to (n-1)//3
    ) -> None
```

| Method | Returns | Description |
|--------|---------|-------------|
| `propose(round, payload)` | `Block` | Create a block referencing known parent certs |
| `receive_block(block)` | `int?` | Validate, store, return ack (own index) if valid, None if invalid/duplicate |
| `receive_ack(block_digest, signer)` | `Certificate?` | Accumulate acks; return cert when 2f+1 reached |
| `receive_certificate(cert)` | `CommitDecision?` | Store cert; check commit rule, return decision if triggered |
| `check_commit(round)` | `CommitDecision?` | Evaluate commit rule for a specific round's leader |
| `detect_equivocation(block)` | `EquivocationProof?` | Check if author already proposed at this round |
| `skip_round(round)` | `None` | Mark a round as timed out, advance |
| `leader_for_round(round)` | `int` | `round % num_validators` |
| `is_equivocator(author)` | `bool` | Check if author has been flagged |
| `current_round` | `int` | Property: highest round with activity |
| `dag_store` | `DAGStore` | Property: access the local DAG |

### Commit Rule (separate module)

The commit rule is the most complex logic. Separated into `commit_rule.py` for clarity:

```python
def evaluate_direct_commit(
    dag: DAGStore,
    round: int,
    leader: int,
    quorum_threshold: int,
) -> CommitDecision | None:
    """Check if the leader at `round` has a direct commit."""

def evaluate_indirect_commit(
    dag: DAGStore,
    round: int,
    leader: int,
    committed_rounds: set[int],
) -> CommitDecision | None:
    """Check if the leader at `round` can be indirectly committed."""

def collect_causal_history(
    dag: DAGStore,
    certificate: Certificate,
    already_committed: set[bytes],
) -> list[Block]:
    """BFS/DFS through parent links to collect uncommitted blocks in causal order."""
```

---

## 3. LocalMysticetiEngine

In-process simulation running the full DAG protocol with `n` validators.

### Constructor

```python
class LocalMysticetiEngine:
    def __init__(
        self,
        num_validators: int,
        fault_tolerance: int | None = None,  # defaults to (n-1)//3
        round_timeout_ms: int = 1000,
    ) -> None
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `start()` | `None` | Begin protocol — validators start proposing (async mode) |
| `stop()` | `None` | Graceful shutdown |
| `submit_transactions(txs)` | `None` | Add transactions to the mempool; next proposer includes them |
| `stream_commits()` | `Iterator[CommitDecision]` | Blocking iterator yielding committed decisions in order |
| `advance_round()` | `int` | Manually tick to next round (synchronous mode for tests) |
| `run_rounds(n)` | `list[CommitDecision]` | Run n rounds, return all commit decisions produced |
| `inject_fault(fault)` | `None` | Inject a Byzantine fault |
| `get_dag_store(validator)` | `DAGStore` | Inspect a specific validator's DAG |
| `validators` | `list[MysticetiProtocol]` | Access individual validator protocol instances |

### Execution Modes

**Synchronous (testing):** `advance_round()` and `run_rounds(n)` drive the protocol step-by-step. Each round executes deterministically:

1. All honest validators propose (creating blocks with parent certs)
2. All blocks broadcast via MessageBus
3. Each validator processes received blocks, produces acks
4. All acks broadcast
5. Each validator processes acks, forms certificates when threshold met
6. All certificates broadcast
7. Each validator checks commit rule, yields CommitDecisions

**Async (production-like):** `start()` spawns an internal loop that advances rounds on a timer (`round_timeout_ms`). `stream_commits()` yields as commits happen.

### Byzantine Fault Injection

**FaultType** (enum):

| Value | Description |
|-------|-------------|
| `HONEST` | Default — follows protocol |
| `EQUIVOCATE` | Proposes two different blocks per round |
| `WITHHOLD` | Proposes but doesn't send to some validators |
| `CRASH` | Stops participating after a specified round |
| `DELAY` | Delays acknowledgments by k rounds |
| `CENSOR` | Proposes blocks that exclude specific transactions |

**FaultConfig** (dataclass):

| Field | Type | Description |
|-------|------|-------------|
| `validator` | `int` | Which validator to fault |
| `fault_type` | `FaultType` | Type of Byzantine behavior |
| `start_round` | `int` | When the fault begins |
| `end_round` | `int?` | When it ends (None = permanent) |
| `params` | `dict` | Fault-specific parameters (e.g., `withhold_targets`, `delay_rounds`) |

### Message Bus

**MessageBus** — In-memory message routing between simulated validators:

| Method | Returns | Description |
|--------|---------|-------------|
| `send(from_v, to_v, message)` | `None` | Point-to-point delivery |
| `broadcast(from_v, message)` | `None` | Send to all validators |
| `set_partition(config)` | `None` | Configure network partition |
| `clear_partition()` | `None` | Heal partition |
| `pending_for(validator)` | `list` | Messages waiting for delivery |
| `deliver_all()` | `None` | Deliver all pending messages (synchronous mode) |

**PartitionConfig** (dataclass):

| Field | Type | Description |
|-------|------|-------------|
| `group_a` | `frozenset[int]` | First partition group |
| `group_b` | `frozenset[int]` | Second partition group |
| `start_round` | `int` | When partition begins |
| `duration` | `int?` | Rounds until heal (None = permanent) |

### Conversion to OrderedBatch

The engine converts `CommitDecision` to `OrderedBatch` for the execution pipeline:

```python
def to_ordered_batch(decision: CommitDecision, epoch: int) -> OrderedBatch:
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
```

---

## 4. File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/ltp/consensus/__init__.py` | Package exports |
| Create | `src/ltp/consensus/types.py` | `Block`, `Certificate`, `CommitDecision`, `EquivocationProof`, `RoundState` |
| Create | `src/ltp/consensus/dag_store.py` | `DAGStore` — indexed block/certificate storage |
| Create | `src/ltp/consensus/protocol.py` | `MysticetiProtocol` — pure protocol logic |
| Create | `src/ltp/consensus/commit_rule.py` | Direct/indirect commit rule evaluation |
| Create | `src/ltp/consensus/engine.py` | `LocalMysticetiEngine` — in-process multi-validator simulation |
| Create | `src/ltp/consensus/faults.py` | `FaultType`, `FaultConfig`, `PartitionConfig` — Byzantine fault injection |
| Create | `src/ltp/consensus/message_bus.py` | `MessageBus` — in-memory message routing with partition support |
| Create | `tests/test_consensus_types.py` | DAG data structure tests |
| Create | `tests/test_consensus_dag_store.py` | DAGStore tests |
| Create | `tests/test_consensus_protocol.py` | Protocol logic tests |
| Create | `tests/test_consensus_commit_rule.py` | Commit rule tests |
| Create | `tests/test_consensus_engine.py` | LocalMysticetiEngine tests |
| Create | `tests/test_consensus_byzantine.py` | Byzantine fault tests |
| Create | `tests/test_consensus_e2e.py` | Full engine E2E tests |

New package: `src/ltp/consensus/` — a peer of `src/ltp/execution/`, not a child. Consensus feeds into the execution layer but does not depend on it. The only cross-dependency is `OrderedBatch` from `src/ltp/execution/types.py` for the conversion bridge in `engine.py`.

---

## 5. Testing Strategy

### Unit: types (test_consensus_types.py) ~8 tests
- Block digest is deterministic (same inputs = same hash)
- Block digest changes with any field change
- Certificate requires block reference
- CommitDecision orders committed_blocks causally
- EquivocationProof requires same (round, author), different digest
- Frozen dataclass enforcement

### Unit: DAGStore (test_consensus_dag_store.py) ~10 tests
- Add/get block round-trip
- Reject duplicate blocks (same round+author)
- Add/get certificate round-trip
- `blocks_at_round` returns all blocks for a round
- `certificates_at_round` returns all certs for a round
- `has_quorum_certificates` returns True when 2f+1 certs exist
- Empty round returns empty list
- Cross-round queries don't leak

### Unit: protocol (test_consensus_protocol.py) ~12 tests
- `propose()` creates block with correct parent references
- `receive_block()` stores block, returns ack
- `receive_block()` rejects block with invalid parents
- `receive_ack()` accumulates; returns cert at 2f+1
- `receive_ack()` below threshold returns None
- `leader_for_round()` is deterministic
- `detect_equivocation()` catches double proposal
- `is_equivocator()` true after detection
- `skip_round()` marks round as timed out
- Equivocator's blocks excluded from commit consideration

### Unit: commit rule (test_consensus_commit_rule.py) ~10 tests
- Direct commit: leader cert at r with 2f+1 child certs at r+1
- No commit: leader cert at r with only f child certs at r+1
- Indirect commit: skipped leader at r committed through leader at r+2
- Causal ordering: committed_blocks ordered by round then author
- Non-leader blocks in causal history included in commit
- Skipped round leader not directly committed
- Multiple consecutive commits produce correct ordering
- No double-commit (already committed blocks excluded)

### Integration: engine (test_consensus_engine.py) ~10 tests
- 4 validators, honest: rounds advance, commits produced
- Submit transactions -> transactions appear in committed blocks
- `run_rounds(10)` produces monotonically increasing commit rounds
- Synchronous mode is deterministic (same seed = same results)
- `stream_commits()` yields in order
- `get_dag_store(v)` reflects validator's local view
- Engine start/stop lifecycle
- `to_ordered_batch()` produces valid OrderedBatch with `consensus_type="dag"`

### Byzantine: faults (test_consensus_byzantine.py) ~12 tests
- Equivocating validator detected by all honest validators
- Equivocating validator's blocks excluded from commit
- f crash faults: protocol continues, commits still produced
- f+1 crash faults: protocol halts (liveness lost)
- Withholding validator: other validators still form certificates
- Network partition (2 groups): no commits during partition, recovery after heal
- Delayed acks: commits still produced, just slower
- Censoring validator: censored txs included by other validators
- Mixed faults (equivocate + crash): protocol survives up to f total Byzantine

### E2E: full pipeline (test_consensus_e2e.py) ~8 tests
- 4 validators: submit txs -> run rounds -> collect OrderedBatches -> verify all txs present
- 7 validators: higher throughput, same correctness
- Transaction ordering preserved within a block
- Multiple rounds produce consecutive round numbers in OrderedBatch
- Leader authority in OrderedBatch matches committed leader
- Epoch field propagation
- Empty rounds (no txs submitted) still produce commits (empty payload)
- Large batch: 1000 transactions distributed across rounds

**Estimated: ~70 tests across 7 test files.**

---

## 6. Gate D1a Criteria

- [ ] `Block`, `Certificate`, `CommitDecision` types with deterministic digests
- [ ] `DAGStore` indexes blocks and certificates by (round, author), tracks quorum
- [ ] `MysticetiProtocol` implements propose/ack/certify/commit cycle
- [ ] Direct commit rule: leader certified by 2f+1 at next round
- [ ] Indirect commit rule: skipped leader committed through later leader's causal history
- [ ] Causal history collection orders committed blocks correctly
- [ ] Equivocation detection and exclusion
- [ ] `LocalMysticetiEngine` runs n validators in-process, produces `CommitDecision`s
- [ ] Byzantine fault injection: equivocate, crash, withhold, partition
- [ ] f Byzantine faults tolerated; f+1 halts liveness (verified)
- [ ] `to_ordered_batch()` produces valid `OrderedBatch` compatible with existing execution pipeline
- [ ] All existing tests still pass (3,487+)
- [ ] ~70 new consensus tests added

---

## 7. Non-Goals (Deferred to D1b/D1c)

- **MysticetiAdapter / gRPC client** — D1b scope. The local engine uses direct in-process calls, not gRPC.
- **Validator set management** — D1b scope. D1a uses a fixed `num_validators` integer.
- **Committee roster integration** — D1b scope. D1a has no dependency on `CommitteeManager`.
- **NodeExecutor / execution loop** — D1c scope. D1a produces `CommitDecision`s; wiring them to the router is D1c.
- **Rust sidecar** — Production deployment. The local engine is the Python reference; the Rust sidecar is a build-chain addition that implements the same gRPC contract.
- **Real networking** — D2 scope. All message delivery is in-process via `MessageBus`.
- **Threshold signing of consensus messages** — The protocol uses validator indices for acks, not BLS signatures. Real signature-based certificates are a D1b enhancement when the adapter integrates with the committee's signing keys.
