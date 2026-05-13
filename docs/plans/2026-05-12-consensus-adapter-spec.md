# Consensus Adapter and Validator Management (Spec D1b)

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Date:** May 12, 2026
**Depends on:** D1a (Mysticeti DAG Protocol Engine) — completed, C3a (Committee Formation) — completed, C3c (Threshold BLS Signing) — completed
**Delivers:** `MysticetiAdapter` implementing `ConsensusAdapter`, BLS-signed certificates, validator set management with mid-epoch eviction, `ConsensusBackend` abstraction for future sidecar swap
**Part of:** D1 (Consensus Protocol Integration), split as D1a/D1b/D1c

---

## Overview

Spec D1b connects the D1a Mysticeti DAG engine to the ETP execution pipeline. It implements `MysticetiAdapter` (the real `ConsensusAdapter` that replaces `FakeConsensusAdapter`), adds BLS cryptographic signing at every protocol layer, manages validator identity mapping between committee rosters and engine indices, and handles epoch transitions and mid-epoch evictions.

The architecture is layered with event-driven state propagation:
- **Layered** for component structure: each module has one responsibility with a well-defined interface
- **Event-driven** for reactive flows: evictions, epoch transitions, and commit attestations propagate via an event system

### Design Decisions (confirmed)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| BLS integration depth | Full — signed acks, aggregated certs, threshold-signed output, verifiable proofs | Mysticeti is new; cover all frames |
| Validator set changes | Hybrid — additions at epoch boundary, evictions immediate | Responsive to misbehavior without mid-epoch quorum recalculation |
| gRPC scope | Abstract interface only — `ConsensusBackend` ABC, local implementation | No premature gRPC dependency; sidecar doesn't exist yet |
| Validator identity | Hybrid — index-based engine, lookup table adapter, identity-native for BLS ops | Engine stays efficient; adapter bridges to cryptographic identities |
| Testing | Full adversarial coverage — ~80+ tests | Cover all edge cases for a new protocol |

---

## 1. Event System

### ConsensusEventType (enum)

| Value | Description |
|-------|-------------|
| `EPOCH_TRANSITION` | Epoch advanced, new validator set active |
| `VALIDATOR_EVICTED` | Validator removed mid-epoch |
| `COMMIT_ATTESTED` | Committed batch signed by committee |
| `ENGINE_REBUILT` | Consensus engine rebuilt for new epoch |

### ConsensusEvent (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | `ConsensusEventType` | Which event |
| `epoch` | `int` | Epoch when event occurred |
| `round` | `int` | Round when event occurred |
| `timestamp_ms` | `int` | Wall clock |
| `payload` | `dict` | Event-specific data |

Event payloads by type:
- `EPOCH_TRANSITION`: `{old_epoch: int, new_epoch: int, validator_count: int, dkg_completed: bool}`
- `VALIDATOR_EVICTED`: `{writer_fp: bytes, validator_index: int, reason: str, remaining_active: int}`
- `COMMIT_ATTESTED`: `{round: int, batch_digest: bytes, signature: bytes}`
- `ENGINE_REBUILT`: `{epoch: int, validator_count: int, quorum_threshold: int}`

---

## 2. ValidatorSet

Maps between committee roster identities (`writer_fp`, `bls_pk`) and engine indices. Fixed at epoch creation, supports mid-epoch eviction without changing index assignments.

### ValidatorInfo (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `writer_fp` | `bytes` | Writer fingerprint from committee roster |
| `bls_pk` | `bytes` | BLS12-381 public key |
| `validator_index` | `int` | 0-based engine index |

### ValidatorSet

| Field/Method | Type/Returns | Description |
|-------------|-------------|-------------|
| `epoch` | `int` | Epoch this set was created for |
| `members` | `list[ValidatorInfo]` | Ordered list — position = index |
| `quorum_threshold` | `int` | `2f+1` where `f = (n-1)//3`, fixed at creation |
| `from_roster(roster)` | `ValidatorSet` | Class method: build from `CommitteeRoster` |
| `index_for(writer_fp)` | `int` | Lookup index by fingerprint |
| `fp_for(index)` | `bytes` | Lookup fingerprint by index |
| `bls_pk_for(index)` | `bytes` | Lookup BLS key by index |
| `evict(writer_fp)` | `None` | Mark validator as evicted (does not change indices or quorum) |
| `is_active(writer_fp)` | `bool` | False if evicted |
| `is_evicted(writer_fp)` | `bool` | True if evicted |
| `active_count()` | `int` | Number of non-evicted validators |
| `evicted_indices()` | `set[int]` | Indices of all evicted validators |
| `size` | `int` | Total members (including evicted) |

**Eviction semantics:** Quorum threshold is fixed at epoch creation. Evicting a validator reduces the effective honest count but the threshold stays the same. If `active_count() < quorum_threshold`, the protocol halts (correct behavior — signals epoch advance needed). This matches BFT safety guarantees.

---

## 3. BLS Certificate Manager

Handles BLS partial signing of consensus messages, aggregation into certificate signatures, and verification.

### SignedCertificate (frozen dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `certificate` | `Certificate` | D1a certificate (block + signer indices) |
| `aggregated_signature` | `bytes` | 96-byte BLS aggregated signature over block.digest |
| `signer_keys` | `frozenset[bytes]` | BLS public keys of signers |

### BLSCertificateManager

| Method | Returns | Description |
|--------|---------|-------------|
| `sign_ack(signing_key, block_digest)` | `bytes` | Produce BLS partial signature over block digest using validator's threshold signing key |
| `aggregate_ack_signatures(partials, block_digest, validator_set)` | `bytes` | Combine 2f+1 partial sigs via Lagrange interpolation into aggregated signature |
| `verify_certificate_signature(signed_cert, validator_set)` | `bool` | Verify aggregated sig against committee group key |
| `sign_committed_batch(signing_key, batch_bytes, domain)` | `bytes` | Sign committed output for attestation (uses `DOMAIN_ATTESTATION`) |
| `verify_batch_attestation(signature, batch_bytes, group_pk, domain)` | `bool` | Verify attestation signature |

BLS operations delegate to the existing `threshold_signing` module from C3c (`partial_sign`, `combine_partial_signatures`, `threshold_verify`). The manager adds certificate-specific domain separation and validator set awareness.

Domain constants (reuses C3c):
- `DOMAIN_ATTESTATION` — for committed batch attestation
- `DOMAIN_STATE_ROOT` — reserved for D1c state root signing
- `DOMAIN_CROSS_VM` — reserved for cross-VM attestation

---

## 4. ConsensusBackend

Abstract interface for the consensus engine. `LocalConsensusBackend` wraps `LocalMysticetiEngine`. Future `GrpcConsensusBackend` (D2+) will implement the same interface.

### ConsensusBackend (ABC)

```python
class ConsensusBackend(ABC):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def submit_transactions(self, txs: list[bytes]) -> None: ...
    def advance_round(self) -> int: ...
    def run_rounds(self, n: int) -> list[CommitDecision]: ...
    def stream_commits(self) -> Iterator[CommitDecision]: ...
    def current_round(self) -> int: ...
    def inject_fault(self, fault: FaultConfig) -> None: ...
    def get_validator_count(self) -> int: ...
    def rebuild(self, num_validators: int, fault_tolerance: int | None = None) -> None: ...
```

### LocalConsensusBackend

Wraps `LocalMysticetiEngine`. Key behaviors:
- `rebuild(num_validators)` creates a new `LocalMysticetiEngine` with the given validator count. Called on epoch transitions when the roster size changes.
- `inject_fault(FaultConfig(validator=idx, fault_type=CRASH))` is used for mid-epoch evictions — the engine treats the evicted validator as crashed.
- All other methods delegate directly to the engine.
- Holds a reference to the engine's `round_timeout_ms` setting for async mode.

---

## 5. CommitteeSync

Bridges `CommitteeManager` (C3a) events to the consensus adapter layer. Detects epoch transitions and evictions, builds `ValidatorSet` from roster, emits `ConsensusEvent`s.

### CommitteeSync

| Method | Returns | Description |
|--------|---------|-------------|
| `__init__(committee_manager)` | — | Takes reference to `CommitteeManager` |
| `sync_epoch()` | `ConsensusEvent?` | Check if epoch advanced. If yes: build new `ValidatorSet` from roster, emit `EPOCH_TRANSITION` |
| `sync_evictions(validator_set)` | `list[ConsensusEvent]` | Compare roster against `ValidatorSet`, emit `VALIDATOR_EVICTED` for any new evictions |
| `on_tick(round, timestamp_ms)` | `list[ConsensusEvent]` | Run `sync_epoch` + `sync_evictions`, return all events |
| `register_listener(callback)` | `None` | Register event callback |
| `current_validator_set` | `ValidatorSet?` | The active validator set |
| `has_signing_keys(epoch)` | `bool` | Whether DKG keys exist for the epoch |
| `get_signing_keys(epoch)` | `list[ThresholdSigningKey]` | Retrieve signing keys from `CommitteeManager._signing_keys[epoch]` (accessed via adapter's committee_manager reference) |

### Epoch Transition Flow

1. `CommitteeManager.tick(round, timestamp)` returns `True`
2. `CommitteeSync.sync_epoch()` detects `committee_manager.epoch > current_epoch`
3. New `ValidatorSet` built from `committee_manager.roster`
4. `CommitteeSync` checks `committee_manager.has_dkg_result(new_epoch)` for signing keys
5. `EPOCH_TRANSITION` event emitted with `{old_epoch, new_epoch, validator_count, dkg_completed}`
6. Adapter receives event, calls `backend.rebuild(new_validator_count)`
7. `BLSCertificateManager` updates signing keys if DKG completed
8. `ENGINE_REBUILT` event emitted

### Mid-Epoch Eviction Flow

1. `CommitteeManager.on_writer_state_change()` triggers eviction in roster
2. `CommitteeSync.sync_evictions(validator_set)` detects evicted member
3. `validator_set.evict(writer_fp)` marks the validator
4. `backend.inject_fault(FaultConfig(validator=evicted_index, fault_type=CRASH))` — engine skips this validator
5. `VALIDATOR_EVICTED` event emitted with `{writer_fp, validator_index, reason, remaining_active}`
6. Protocol continues with remaining validators, same quorum threshold

---

## 6. MysticetiAdapter

Implements `ConsensusAdapter` — the real replacement for `FakeConsensusAdapter`. Orchestrates all D1b components.

### Constructor

```python
class MysticetiAdapter:
    def __init__(
        self,
        committee_manager: CommitteeManager,
        round_timeout_ms: int = 1000,
    ) -> None
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `start()` | `None` | Build `ValidatorSet` from roster, create backend, init BLS manager, start consensus |
| `stop()` | `None` | Stop backend, clear state |
| `stream_batches()` | `Iterator[OrderedBatch]` | Pull commits from backend, sign certs, convert to OrderedBatch, yield |
| `submit_transaction(tx_bytes)` | `bytes` | Forward to backend, return SHA3-256 hash of tx |
| `current_round()` | `int` | Delegate to backend |
| `consensus_type()` | `str` | Return `"mysticeti-dag"` |
| `tick(round, timestamp_ms)` | `list[ConsensusEvent]` | Drive CommitteeSync, handle epoch/eviction events |
| `events()` | `list[ConsensusEvent]` | Return event history |

### stream_batches() Pipeline

1. Backend yields `CommitDecision`
2. For each certificate in the decision, `BLSCertificateManager.aggregate_ack_signatures()` produces aggregated BLS signature
3. Wrap as `SignedCertificate`
4. Convert to `OrderedBatch` via `to_ordered_batch(decision, epoch)`
5. If signing keys available, `BLSCertificateManager.sign_committed_batch()` for attestation
6. Emit `COMMIT_ATTESTED` event
7. Yield `OrderedBatch`

### ConsensusAdapter Protocol Compliance

`MysticetiAdapter` implements all 6 methods of the `ConsensusAdapter` protocol:

| ConsensusAdapter Method | MysticetiAdapter Implementation |
|------------------------|---------------------------------|
| `start()` | Build validator set, create backend, start |
| `stop()` | Stop backend, clear state |
| `stream_batches()` | Pipeline above |
| `submit_transaction(tx_bytes)` | Forward to backend |
| `current_round()` | Delegate to backend |
| `consensus_type()` | `"mysticeti-dag"` |

---

## 7. File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/ltp/consensus/events.py` | `ConsensusEventType`, `ConsensusEvent` |
| Create | `src/ltp/consensus/validator_set.py` | `ValidatorInfo`, `ValidatorSet` |
| Create | `src/ltp/consensus/bls_certificates.py` | `BLSCertificateManager`, `SignedCertificate` |
| Create | `src/ltp/consensus/backend.py` | `ConsensusBackend` (ABC), `LocalConsensusBackend` |
| Create | `src/ltp/consensus/committee_sync.py` | `CommitteeSync` |
| Create | `src/ltp/consensus/adapter.py` | `MysticetiAdapter` |
| Modify | `src/ltp/consensus/__init__.py` | Add D1b exports |
| Create | `tests/test_consensus_events.py` | Event type tests (~8) |
| Create | `tests/test_consensus_validator_set.py` | ValidatorSet tests (~14) |
| Create | `tests/test_consensus_bls_certs.py` | BLS signing/verification tests (~16) |
| Create | `tests/test_consensus_backend.py` | Backend abstraction tests (~12) |
| Create | `tests/test_consensus_adapter.py` | MysticetiAdapter lifecycle tests (~15) |
| Create | `tests/test_consensus_adversarial.py` | Adversarial scenario tests (~18) |

---

## 8. Testing Strategy

### Unit: Events (~8 tests)
- Event creation with all required fields
- Each event type's payload structure
- Frozen dataclass enforcement
- Event type enum completeness

### Unit: ValidatorSet (~14 tests)
- Build from CommitteeRoster
- Index ↔ writer_fp lookup round-trip
- BLS key lookup by index
- Evict marks validator, does not change indices
- Evict does not change quorum threshold
- is_active / is_evicted state transitions
- active_count decrements on eviction
- evicted_indices tracking
- Double eviction is idempotent
- Unknown writer_fp raises KeyError
- from_roster with empty roster
- Quorum calculation: n=4 → q=3, n=7 → q=5

### Unit: BLS Certificates (~16 tests)
- sign_ack produces 96-byte partial signature
- Partial signature is deterministic (same key + digest = same sig)
- aggregate_ack_signatures combines partials
- Aggregated signature verifies against group key
- Verification fails with wrong group key
- Verification fails with tampered block digest
- SignedCertificate wraps Certificate correctly
- sign_committed_batch with DOMAIN_ATTESTATION
- verify_batch_attestation round-trip
- Partial sig from wrong epoch key fails aggregation
- Signature from insufficient partials (below threshold) fails
- Empty partials list handled gracefully
- Different domain separation produces different signatures

### Unit: Backend (~12 tests)
- LocalConsensusBackend delegates to engine
- advance_round returns round number
- run_rounds produces CommitDecisions
- submit_transactions forwarded to engine
- rebuild creates new engine with new validator count
- inject_fault for eviction (CRASH type)
- current_round tracks correctly
- get_validator_count matches construction
- rebuild preserves round_timeout_ms setting
- Backend ABC cannot be instantiated directly

### Integration: Adapter (~15 tests)
- MysticetiAdapter satisfies ConsensusAdapter protocol (isinstance check)
- start/stop lifecycle
- stream_batches yields OrderedBatch instances
- stream_batches includes BLS-signed certificates
- submit_transaction returns tx hash
- current_round increments
- consensus_type returns "mysticeti-dag"
- tick triggers epoch advance when due
- tick triggers eviction when writer state changes
- Events recorded in event history
- Adapter with 4 validators produces commits
- Adapter with 7 validators produces commits
- Transactions submitted before start are included after start

### Adversarial: Edge Cases (~18 tests)
- Evicted validator's blocks excluded after eviction round
- BLS signature from previous epoch fails verification
- Validator set grow across epochs (4→7)
- Validator set shrink across epochs (7→4)
- Epoch advance during active rounds — in-flight commits drain
- Double eviction of same validator — idempotent
- Eviction of current round's leader — protocol continues
- Submit transaction after stop — graceful rejection
- All validators evicted — liveness halts
- Roster mismatch (committee has member not in validator set)
- Concurrent epoch advance + eviction in same tick
- Stale validator submitting after removal
- Engine rebuilt mid-stream — stream_batches continues
- Zero-transaction rounds with BLS signing
- Epoch with no DKG keys — adapter works without BLS signing (graceful degradation)
- Multiple rapid epoch advances
- Eviction at exact round of commit — commit still valid
- Signature verification across epoch boundary (committed in epoch N, verified in epoch N+1)

**Estimated: ~83 tests across 6 test files.**

---

## 9. Gate D1b Criteria

- [ ] `MysticetiAdapter` implements `ConsensusAdapter` protocol (isinstance check passes)
- [ ] `stream_batches()` yields `OrderedBatch` with `consensus_type="mysticeti-dag"`
- [ ] BLS partial signatures on acks, aggregated signatures on certificates
- [ ] `SignedCertificate` carries verifiable aggregated BLS signature
- [ ] `ValidatorSet` maps writer_fp ↔ engine index, tracks evictions
- [ ] Epoch transitions rebuild engine with new validator count from roster
- [ ] Mid-epoch evictions inject CRASH faults, exclude validator immediately
- [ ] Quorum threshold fixed per epoch — does not change on eviction
- [ ] `ConsensusBackend` ABC allows future gRPC swap without adapter changes
- [ ] `CommitteeSync` bridges CommitteeManager events to consensus layer
- [ ] Graceful degradation when DKG keys unavailable (no BLS signing, protocol still works)
- [ ] All D1a tests still pass (3,580+)
- [ ] ~83 new tests across 6 test files

---

## 10. Non-Goals (Deferred to D1c/D2)

- **NodeExecutor / execution loop** — D1c scope. D1b produces `OrderedBatch`; wiring to `TransactionRouter` is D1c.
- **gRPC client implementation** — D2+ scope. D1b provides the `ConsensusBackend` ABC; the gRPC backend is built when the Rust sidecar exists.
- **Real networking** — D2 scope. All consensus runs in-process.
- **State root signing** — D1c scope. Uses `DOMAIN_STATE_ROOT` after execution.
- **Rust sidecar** — Production infrastructure. Python engine is the reference; Rust sidecar implements the same `ConsensusBackend` contract via gRPC.
