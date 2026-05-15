> **Superseded** — archived 2026-05-15. Some gateway VM work landed in `deploy/preflight_gateway.py` and `deploy/run_gateway.sh`; see [`docs/plans/2026-05-11-production-roadmap.md`](../2026-05-11-production-roadmap.md) for the current scope.
> Retained for the original gateway architecture rationale and POA attestation design.

---

# LTP Gateway VM Plan — POA Attestation Gateway for GSX Devnet

**Author:** Javier Calderon Jr, CTO - Global Settlement (GSX)

**Date:** April 30, 2026

**Status:** Planning

**Scope:** VM-based LTP gateway for cross-chain event qualification and attestation, POA/POS trust model, single-VM gateway through dual-VM introduction, phased build toward devnet integration.

**Precedes:** Proposed MoveVM+DID Architecture - the dual VM phase (Phase 4) establishes the execution environment that MoveVM identity operations will later run within. DID Expansion Plan begins after MoveVM+DID work starts and is built in tandem.

---

## Summary

This plan defines a phased approach to deploying the LTP/ETP protocol as a live participant in the GSX network, progressing from a single-VM attestation gateway to a dual-VM execution environment:

| Phase | Scope | VM Model | Goal |
|---|---|---|---|
| **1-3** | LTP Gateway VM | Single VM (EVM) | Prove POA attestation on a live testnet/devnet |
| **4** | Dual VM Introduction | EVM + MoveVM | Establish dual execution environment for future identity layer |
| **Strategic** | greth + Mysticeti spike | Parallel | Ensure design does not conflict with mainnet chain direction |

Phases 1-3 build a hardened single-VM gateway that qualifies external chain events for acceptance into GSX devnet. This is what the implementation can honestly support today — proven infrastructure, no new execution environments.

Phase 4 introduces MoveVM as a second execution environment alongside EVM, establishing the writer permissioning model, BLS state root attestation(putting theory to the test), and Move state propagation. Phase 4 is infrastructure plumbing — it builds the dual-VM runtime but does not yet implement the identity system. Identity comes from the subsequent Proposed MoveVM+DID Architecture and DID Expansion Plan, which build on the dual-VM foundation.

### Document Sequencing

```
This Document (LTP Gateway VM Plan)
├── Phase 1-3: Single VM (EVM) — POA attestation gateway
└── Phase 4: Dual VM (EVM + MoveVM) — execution environment introduction
         ↓
Proposed MoveVM+DID Architecture
    Full identity system design on the dual-VM foundation
    (Move DID registry, resource model, Ethereum account binding)
         ↓
DID Expansion Plan
    did:etp method, VCs, cross-chain resolution, phased rollout
    (starts after MoveVM+DID begins, built in tandem)
```

### What the Gateway Is

- An external event qualifier
- An LTP attestation signer
- A permissioned bridge into GSX devnet
- Proven as a commitment, relay, bridge, and attestation system
- The stepping stone to the dual-VM architecture

### What the Gateway Is Not

- Not a consensus participant
- Not a validator replacement
- Not the final chain history arbiter
- Not yet proven as a native consensus participant
- Not the identity layer (that comes from the MoveVM+DID and DID Expansion plans)

---

## Rationale — Why the Gateway VM Comes First

The LTP/ETP implementation has the right infrastructure for the single-VM gateway:

| Existing Component | Location | Role in Gateway |
|---|---|---|
| Deployed bridge contracts | GSX Testnet + Base Sepolia | Event source / anchor target |
| Live bidirectional bridge | `src/ltp/bridge/live.py` | Cross-chain transfer mechanics |
| BridgeOperatorService | `src/ltp/bridge/operator.py` | Daemon pattern: poll, commit, retry |
| Commitment Log | `src/ltp/commitment.py` | Append-only attestation record |
| ML-DSA-65 signing | `src/ltp/primitives.py` | PQ-safe attestation signatures |
| API Gateway | `src/ltp/gateway/app.py` | REST interface with JWT auth |
| Gossip discovery | `src/ltp/node/gossip.py` | Peer-to-peer node awareness |
| Three-phase lifecycle | `src/ltp/protocol.py` | Commit -> Lattice -> Materialize |
| Anchor subsystem | `src/ltp/node/anchor_scheduler.py` | Batch on-chain submission with retry |
| Signer authorization | `contracts/src/LTPAnchorRegistry.sol` | On-chain signer verification |
| 5-layer validation | `contracts/src/LTPAnchorRegistry.sol` | Replay, signer, sequence, expiry, state |
| Prometheus metrics | `src/ltp/observability/metrics.py` | Operational monitoring |
| Structured logging | `src/ltp/observability/logging.py` | Audit trail |

What does not exist yet: a single hardened VM process that wires these components into a unified gateway runtime with external chain event watching and devnet commitment writing. That is what Phases 1-3 build.

What also does not exist: a second execution environment (MoveVM) running alongside EVM with proper writer permissioning and state attestation. That is what Phase 4 introduces — after the single-VM gateway is proven.

### Why Single VM First, Then Dual VM

The dual-VM architecture (EVM + MoveVM) described in the Proposed MoveVM Architecture is the target state for identity operations. But introducing two VMs, writer permissioning, BLS attestation, and state propagation simultaneously with a new gateway runtime is too much surface area to validate at once.

The single-VM gateway isolates the attestation model: does POA-signed event qualification work end-to-end on live testnets? Once proven, Phase 4 adds the dual-VM layer with confidence that the underlying attestation, anchoring, and operational patterns are sound.

### Why Not Jump to greth + Mysticeti

greth + Mysticeti is strategically better for mainnet alignment, but it requires:

- Execution engine ownership
- Consensus engineers assigned
- Devnet block production working
- Clear RPC compatibility goals
- Chain spec defined
- State root format defined
- Validator registration defined
- POA/POS handoff defined
- Bridge acceptance rules defined

The implementation status shows what is real today: the LTP/ETP bridge, commitments, deployed contracts, and operator daemon. The gateway VM builds on proven infrastructure. greth + Mysticeti runs as a parallel architecture spike.

---

## Trust Model

### POA Gateway Role (Phases 1-3, Single VM)

The VM is the first POA-style authority surface:

| Responsibility | Description |
|---|---|
| Observe | Monitor external testnet bridge contract for triggering events |
| Verify | Check source chain finality, event validity, replay status |
| Attest | Create ML-DSA-65 signed LTP commitment record |
| Anchor | Submit commitment to GSX devnet via authorized signer |
| Reject | Refuse malformed, replayed, or unauthorized events |

The gateway does **not**:
- Own consensus
- Replace validators
- Decide final chain history
- Execute privileged chain operations beyond attestation

### POA/POS Split (Phases 1-3)

```
POA Gateway (LTP attestation layer)
        |
        |  Signs LTP commitment
        v
Devnet Contract (LTPAnchorRegistry)
        |
        |  Verifies authorized POA signer
        |  5-layer validation (replay, signer, sequence, expiry, state)
        v
Commitment becomes devnet-readable state
        |
        v
POS Validators (future)
        |
        |  Enforce ordering, finality, state execution rules
        |  Verify commitment well-formedness
        |  Verify source event proof validity
        |  Verify challenge window / ZK proof satisfaction
        v
Final chain state
```

**POA side attestations:**
- "I observed this source-chain bridge event."
- "I verified the source-chain finality threshold."
- "I created this LTP commitment record."
- "This payload hash maps to this source transaction."
- "This commitment is authorized for devnet acceptance."

**POS side verification (does not trust POA blindly):**
- POA signer is authorized
- Commitment is well-formed
- Source event proof is valid
- Commitment has not already been consumed
- State transition is deterministic
- Challenge window or ZK proof requirement satisfied

### Expanded POA/POS Split (Phase 4, Dual VM)

Phase 4 introduces the asymmetric topology from the MoveVM architecture:

```
POA Nodes (MoveVM writers + EVM executors)
        |
        |  Execute Move transactions from ordered DAG stream
        |  Produce signed attestation over Move state root
        |  Continue executing EVM transactions identically to POS nodes
        v
BLS Aggregate Signature on Move State Root
        |
        |  Gossiped to POS nodes (out-of-band, decoupled from DAG blocks)
        v
POS Nodes (EVM executors + Move state readers)
        |
        |  Execute EVM transactions identically to POA nodes
        |  Receive Move state deltas from POA nodes
        |  Recompute Move state root locally
        |  Verify recomputed root against BLS-signed attestation
        |  Serve as the read surface for Move state
        v
Any Client / Contract / External Verifier
        |
        |  Requests Move state with Merkle proof
        |  Verifies BLS signature on state root
        |  Walks Merkle inclusion proof
        |  No trust in any specific node required
```

**Key property**: Both node roles run the same DAG consensus protocol and execute EVM transactions identically. The asymmetry exists only at MoveVM — POA nodes execute Move, POS nodes consume the results. Consensus remains a single source of truth for transaction ordering across both VMs.

### Relationship to DID Plan

The DID Expansion Plan (Phase 2: Node Operator Identity) will give each gateway VM a DID. Authorization to act as a POA gateway will be expressed as a Verifiable Credential issued by the network operator. This plan establishes the runtime; the MoveVM+DID architecture establishes the identity execution environment; the DID plan establishes the identity layer on top of both.

---

## Gateway Architecture (Phases 1-3, Single VM)

### Transaction Flow

```
External Testnet Bridge Contract (Base Sepolia)
        |
Event Listener / Finality Watcher
        |
LTP Gateway Validator
        |
Commitment Log Entry
        |
ML-DSA-65 Signed Attestation
        |
Anchor to GSX Devnet
        |
Devnet Contract (LTPAnchorRegistry)
        |
Accept or Reject Commitment
```

### Gateway Validation Checklist

The gateway commits to devnet only after verifying all of the following:

| # | Check | Source |
|---|---|---|
| 1 | Source chain ID matches expected | Event metadata |
| 2 | Bridge contract address is authorized | Gateway config |
| 3 | Event signature matches expected ABI | Event log |
| 4 | Transaction hash is valid and confirmed | RPC receipt query |
| 5 | Block number is at or above confirmation depth | RPC block query |
| 6 | Finality depth threshold met | Configurable per source chain |
| 7 | Replay status -- event not already processed | Local replay protection DB |
| 8 | Authorized signer status -- gateway key is registered on devnet | On-chain `authorizedSigners[vkHash]` |
| 9 | Commitment hash is well-formed | SHA3-256 domain-separated hash |
| 10 | Payload hash matches event data | Recompute and compare |
| 11 | Source/destination routing is correct | Event fields match gateway config |
| 12 | Challenge/fraud window status (if optimistic mode) | ChallengeManager state |

### VM Components

The gateway VM runs a single hardened process composed of:

| Component | Based On | Purpose |
|---|---|---|
| **RPC Listener** | New (web3.py event subscription) | Watch external testnet bridge contract for events |
| **Finality Watcher** | Extends `AnchorVerifier` pattern | Wait for confirmation/finality depth before processing |
| **Event Validator** | New (validation checklist above) | Verify event fields, replay status, routing |
| **LTP Commitment Writer** | Extends `BridgeOperatorService` | Create commitment record, sign with ML-DSA-65 |
| **Devnet Anchor Client** | Extends `AnchorClient` | Submit commitment to GSX devnet registry |
| **Replay Protection DB** | Extends `SequenceTracker` | Per-source-chain, per-event deduplication |
| **Challenge Manager** | Existing `ChallengeManager` | Optimistic mode: track challenge windows |
| **Retry Queue** | Existing `BridgeOperatorService` retry pattern | Failed submissions retried on subsequent ticks |
| **Structured Logger** | Existing `StructuredLogger` | Full audit trail with correlation IDs |
| **Prometheus Metrics** | Existing `MetricsRegistry` | Operational monitoring |
| **Admin Config** | Extends `NodeConfig` | Source chain RPC, devnet RPC, signer key, finality depth |

### Configuration

Extends the existing `NodeConfig` with gateway-specific fields:

```toml
[gateway_vm]
enabled = true
mode = "poa-attestation"     # not "consensus" -- wording matters

[gateway_vm.source]
chain_id = 84532             # Base Sepolia
rpc_url = "https://..."
bridge_contract = "0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0"
finality_depth = 12          # blocks before event is considered final
poll_interval_seconds = 5

[gateway_vm.destination]
chain_id = 103115120         # GSX Devnet
rpc_url = "https://..."
registry_address = "0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4"
operator_key = "env:GSX_GATEWAY_KEY"  # resolved from environment

[gateway_vm.validation]
replay_db_path = "/data/replay.db"
max_retries = 5
retry_interval_seconds = 30
challenge_mode = "optimistic"  # "optimistic" | "zk" | "disabled"
challenge_period_seconds = 3600  # 1 hour for testnet

[gateway_vm.observability]
metrics_port = 9090
log_format = "json"
log_level = "info"
```

---

## Phased Implementation

### Phase 1: LTP Gateway VM (Single VM, EVM)

**Goal:** One hardened VM that bridges external testnet events into GSX devnet via LTP attestation.

**Deliverables:**

1. `src/ltp/gateway_vm/` -- Gateway VM module:
   - `listener.py` -- RPC event subscription for bridge contract events
   - `finality.py` -- Finality watcher (extends AnchorVerifier confirmation depth pattern)
   - `validator.py` -- 12-point validation checklist (Section 4.2)
   - `writer.py` -- LTP commitment creation and ML-DSA-65 signing
   - `replay.py` -- SQLite-backed replay protection (per source chain, per event hash)
   - `config.py` -- Gateway VM configuration (extends NodeConfig)
   - `main.py` -- Unified gateway process (startup, shutdown, signal handling)
2. Extension of `BridgeOperatorService` daemon pattern for the gateway tick loop
3. Extension of `AnchorClient` for devnet-specific submission
4. Gateway-specific Prometheus metrics:
   - `gateway_events_observed` -- Counter of bridge events seen
   - `gateway_events_accepted` -- Counter of events passing validation
   - `gateway_events_rejected` -- Counter of events failing validation (labeled by rejection reason)
   - `gateway_anchor_latency` -- Histogram of time from event observation to devnet anchor
   - `gateway_finality_wait` -- Histogram of time spent waiting for finality
   - `gateway_replay_rejections` -- Counter of replay attempts detected
5. Deployment: single VM instance on GSX infrastructure
6. Tests: unit tests for each component + integration test for full event-to-anchor flow

**Builds on:**
- `BridgeOperatorService` (poll, commit, retry pattern)
- `AnchorClient` (web3.py submission, rate limiter, circuit breaker)
- `AnchorVerifier` (confirmation depth, finality tracking)
- `SequenceTracker` (monotonic sequencing, replay protection)
- `StructuredLogger` + `MetricsRegistry` (observability)
- `ChallengeManager` (optimistic mode challenge tracking)
- Deployed contracts on GSX Testnet and Base Sepolia

### Phase 2: Triggering Transaction Flow

**Goal:** End-to-end verified flow from bridge contract event to devnet commitment.

**Sequence:**

```
1. Bridge contract on external testnet emits event
2. Gateway event listener detects event
3. Gateway waits finality threshold (configurable depth)
4. Gateway validates event fields (12-point checklist)
5. Gateway creates LTP commitment record
6. Gateway signs commitment with authorized ML-DSA-65 key
7. Gateway anchors commitment to GSX devnet (LTPAnchorRegistry.anchor())
8. Devnet contract accepts only if signer + payload + replay checks pass
9. Gateway logs full trace for audit (structured JSON, correlation ID)
```

**Deliverables:**

1. End-to-end integration test: trigger bridge contract -> gateway processes -> devnet anchor verified
2. Multi-event batch test: multiple events in rapid succession
3. Bidirectional test: Base Sepolia -> GSX and GSX -> Base Sepolia
4. Operational dashboard: Grafana dashboard template for gateway metrics
5. Gateway REST endpoints:
   - `GET /gateway/status` -- Current gateway state (listening, syncing, active, degraded)
   - `GET /gateway/events?status=X` -- Processed events by status (accepted, rejected, pending, retrying)
   - `GET /gateway/events/{tx_hash}` -- Single event lookup with full validation trace
   - `GET /gateway/health` -- Liveness + readiness (K8s probe compatible)

### Phase 3: Stress Testing

**Goal:** Determine whether LTP works with POA attestation under adversarial and degraded conditions.

**Test scenarios:**

| # | Scenario | Tests |
|---|---|---|
| 1 | Duplicate events | Same event emitted twice -- gateway rejects replay |
| 2 | Chain reorgs | Source chain reorg after event seen but before finality -- gateway discards |
| 3 | RPC downtime | Source or destination RPC goes down -- gateway queues and retries |
| 4 | Signer revocation | Gateway signer revoked on devnet mid-operation -- anchor rejected |
| 5 | Bad payloads | Malformed event data -- gateway rejects at validation |
| 6 | Malformed commitments | Invalid commitment structure -- devnet contract rejects |
| 7 | Delayed finality | Source chain slow to produce blocks -- gateway waits, does not skip |
| 8 | Bridge contract pause | Source bridge contract paused -- gateway detects and halts processing |
| 9 | Devnet write failure | Devnet RPC returns error -- gateway retries with backoff |
| 10 | Replayed transaction hash | Same TX hash submitted with different payload -- gateway detects mismatch |
| 11 | Out-of-order events | Events arrive non-sequentially -- gateway orders by source block number |
| 12 | Challenge period expiration | Optimistic mode: challenge window expires -- gateway auto-finalizes |
| 13 | ZK proof fallback | ZK mode: gateway generates STARK proof for instant finality |
| 14 | Multiple gateways | Two gateway VMs processing same event stream -- only one anchor succeeds (sequence monotonicity) |
| 15 | Gateway crash recovery | Gateway process killed mid-operation -- restarts and reconciles from replay DB + on-chain state |

**Success criteria:**
- All 15 scenarios pass without manual intervention
- Gateway processes 100 events/minute sustained under load
- No duplicate anchors on devnet under any scenario
- Full audit trail recoverable from structured logs
- Metrics accurately reflect all acceptance/rejection/retry counts

### Phase 4: Dual VM Introduction (EVM + MoveVM)

**Goal:** Introduce MoveVM as a second execution environment alongside EVM, establishing the runtime infrastructure that the [Proposed MoveVM+DID Architecture](Proposed-MoveVM-DID.docx) will build upon. Phase 4 is infrastructure -- it does not implement the identity system.

**Prerequisite:** Phases 1-3 complete. Single-VM POA attestation proven on live testnets.

#### What Phase 4 Builds

| Component | Purpose | Feeds Into |
|---|---|---|
| MoveVM execution on POA nodes | Second execution environment alongside EVM | MoveVM+DID: Move `did::registry` module |
| Writer permissioning at transaction validity | POA-only Move writes enforced deterministically | MoveVM+DID: DID document write authority |
| BLS aggregate attestation on Move state roots | Committee-signed Move state becomes verifiable | MoveVM+DID: DID state becomes portable and provable |
| Move state delta propagation to POS nodes | POS nodes verify and serve Move state reads | MoveVM+DID: Universal DID resolution |
| Decoupled attestation cadence | Move attestation on 1-5s cycle, independent from DAG blocks | MoveVM+DID: DID freshness tiers |
| EVM precompile for Move state reads | EVM contracts can read Move state natively | MoveVM+DID: On-chain DID verification from EVM |

#### What Phase 4 Does NOT Build

- No DID registry module (MoveVM+DID document scope)
- No DID document schema or operations (DID Expansion Plan scope)
- No Verifiable Credentials (DID Expansion Plan scope)
- No Ethereum account binding (MoveVM+DID document scope)
- No identity governance (MoveVM+DID document scope)

Phase 4 answers: "Can we run two VMs on the same chain with proper permissioning and attestation?" The MoveVM+DID document answers: "What do we build on that dual-VM foundation?"

#### Split Topology

Both node roles run the full DAG consensus protocol and execute EVM transactions identically. The asymmetry exists only at MoveVM:

**POA nodes (~30 at initial scale):**
- Run MoveVM alongside EVM
- Execute Move transactions from the ordered DAG stream
- Maintain the full Move authenticated state tree
- Produce BLS-signed attestations over Move state root after each execution epoch
- Derive authority from committee admission, not from staking

**POS nodes (larger population):**
- Do not run MoveVM
- Receive Move state deltas from POA nodes
- Apply deltas to local Move state tree copy
- Verify recomputed root against BLS-signed attestation
- Serve as the read surface for Move state (Merkle proofs against signed roots)
- Detect committee equivocation if recomputed root disagrees with attestation

#### Transaction-Level Writer Enforcement

Writer permissioning is enforced at the transaction validity layer, not at consensus:

```python
ordered_txs = dag.output()
for tx in ordered_txs:
    if tx.kind == EVM:
        evm.execute(tx)
    elif tx.kind == MOVE:
        if not writers.contains(tx.sender):
            continue  # deterministic no-op
        move_vm.execute(tx)
```

- **Mempool layer (soft check):** DAG workers reject Move transactions from non-writers at ingestion. Performance optimization only.
- **Post-ordering layer (security boundary):** Every node verifies Move transaction sender is in writer registry before MoveVM execution. Unauthorized transactions become no-ops deterministically.
- **Writer registry:** Lives on the EVM side as a governance contract. Same governance surface as all other protocol parameters. Move trusts whatever writer list EVM publishes at the current block height.

Each block commits two state roots into its header -- one for EVM, one for Move.

#### BLS State Root Attestation

After each Move execution epoch, the POA committee collectively signs the new Move state root:

| Property | Detail |
|---|---|
| Signature scheme | BLS aggregate (constant-size regardless of committee size) |
| Attestation content | Move state root + epoch identifier |
| Propagation | Gossiped to all nodes, out-of-band from DAG blocks |
| Cadence | 1-5 seconds (independent from DAG block production) |
| POS verification | Apply deltas, recompute root, check against signed attestation |
| Mismatch handling | POS node refuses to serve reads until inconsistency is resolved |

**Why decoupled from DAG blocks:** Move transactions are a small minority of overall traffic. Coupling attestation to block headers ties DAG throughput to Move execution latency. Decoupling preserves EVM throughput while Move attestations arrive on their own cadence.

**Signing scheme progression (Phase 4 starts with the simplest, migrates as needed):**

| Scheme | Signing Latency | On-Chain Verify Gas | Committee Change | When |
|---|---|---|---|---|
| Aggregator-rotated BLS | ~100ms | 80-130K | Cheap; update list | Phase 4 start |
| Threshold BLS (DKG) | ~100ms | 50-80K | Expensive; rerun DKG | When committee stabilizes |
| FROST / Schnorr | ~100ms | 3-10K | Expensive; rerun DKG | When cross-chain verification volume grows |

Start with aggregator-rotated BLS (no ceremony, well-understood). Migrate to threshold BLS or FROST when committee membership stabilizes and cross-chain verification economics justify the DKG overhead. The migration is feasible because signature verification is versioned at the verifier contract, not baked into consensus.

#### Move State Propagation

**State delta distribution:**
1. POA nodes execute Move transactions and produce state deltas
2. Deltas are gossiped to all POS nodes (piggybacks on existing DAG gossip infrastructure)
3. POS nodes apply deltas to local state tree copy
4. POS nodes recompute Move state root
5. POS nodes verify root against BLS-signed attestation
6. On match: POS node serves Move state reads with Merkle proofs
7. On mismatch: POS node halts Move reads, flags committee equivocation

**Portable verification artifact (produced by any POS node on request):**
- Serialized Move state entry (BCS encoding)
- Merkle inclusion proof locating it in the Move state tree
- Move state root the proof is rooted in
- Epoch identifier
- POA committee BLS aggregate signature over root + epoch

Any verifier (off-chain, on-chain, cross-chain) checks the same sequence: verify BLS signature against committee public keys, walk Merkle proof, parse BCS bytes. No trust in any specific node.

#### EVM Precompile for Move State Reads

For same-chain verification, EVM contracts do not need the attestation mechanism. Move state is physically present on the node executing the EVM transaction. A precompile reads it directly:

| Precompile Address | Function | Gas Cost |
|---|---|---|
| `0x0F` (tentative) | Move state read (generic) | Negligible (memory access) |

This precompile is reserved in Phase 4 but becomes critical in the MoveVM+DID phase when EVM contracts need to read DID state. Designing the precompile interface now ensures the MoveVM+DID document does not require retroactive chain changes.

#### Operational Cost Estimates (Phase 4, Dual VM)

At steady-state with the Move subsystem running (pre-identity, infrastructure only):

| Node Role | Additional Storage | CPU | Bandwidth Overhead |
|---|---|---|---|
| POS node | ~2 GB beyond EVM baseline | 1 core (delta verification) | ~25 KB/s |
| POA node | ~3 GB beyond EVM baseline | 1 dedicated core + BLS signing | ~25 KB/s + signing rounds |

These estimates are for the Move infrastructure with minimal state. Identity workload (millions of DIDs) adds storage growth described in the MoveVM+DID architecture document.

#### Phase 4 Deliverables

1. MoveVM integration into POA node binary (Move execution alongside EVM)
2. Writer registry governance contract on EVM side
3. Transaction-level writer enforcement in post-ordering validation
4. BLS aggregate signing implementation for POA committee
5. Move state delta propagation protocol (extends existing gossip)
6. POS delta application and root verification
7. Dual state root block header (EVM root + Move root)
8. Precompile address reservation and interface definition
9. Integration tests:
   - Authorized Move transaction executes on POA, propagates to POS
   - Unauthorized Move transaction becomes deterministic no-op
   - BLS attestation produced, verified by POS nodes
   - Precompile reads Move state from EVM contract
   - Committee equivocation detected on root mismatch
10. Stress tests:
    - Move execution under concurrent EVM load (throughput isolation)
    - BLS signing round latency at 30 committee members
    - State delta propagation latency across geographically distributed nodes
    - Writer registry update mid-epoch (committee membership change)

#### Phase 4 Forward Compatibility

Design choices in Phase 4 that enable the MoveVM+DID and DID Expansion plans:

| Phase 4 Decision | Enables |
|---|---|
| Move resource model available | MoveVM+DID: DID documents as non-copyable, non-droppable resources |
| BLS-signed state roots | MoveVM+DID: Portable DID proofs verifiable by anyone |
| Writer permissioning | MoveVM+DID: Only POA committee can create/update DID documents |
| Precompile interface | MoveVM+DID: EVM contracts read DID state at memory-access cost |
| Decoupled attestation | DID Expansion: Freshness tiers (Tier 0-3) map to attestation cadence |
| Portable verification artifact | DID Expansion: Cross-chain DID resolution without trust in relay |
| Dual state roots | DID Expansion: Move state root independently verifiable on external chains |

---

## Strategic Track -- greth + Mysticeti Architecture Spike

This is **not** the critical path. It runs in parallel to ensure the gateway interface does not conflict with the mainnet chain direction.

### Spike Scope

| Question | Goal |
|---|---|
| How does the gateway VM's attestation output map to greth's block/state model? | Ensure commitment format is compatible |
| Where does LTP attestation fit in Mysticeti's DAG ordering? | Define the integration point |
| What is the RPC compatibility surface between gateway VM and greth? | Identify shared interfaces |
| How does the POA gateway signer model map to greth's validator registration? | Ensure signer migration path |
| What state root format does greth use, and can LTP commitment hashes participate? | Verify hash compatibility |
| How does the dual state root (EVM + Move) map to greth's block header format? | Phase 4 compatibility |
| Can greth support a precompile at `0x0F` for Move state reads? | Phase 4 precompile alignment |

### Spike Deliverables

1. Architecture document: greth + Mysticeti integration points for LTP attestation
2. Interface compatibility assessment: gateway VM -> greth migration path
3. Shared type definitions: if any data structures need to be compatible now, define them early
4. Risk register: what gateway VM decisions could conflict with greth + Mysticeti
5. Dual-VM feasibility assessment: MoveVM alongside greth EVM execution model

### Non-Goals for the Spike

- No greth implementation
- No Mysticeti consensus implementation
- No devnet running greth
- No chain spec finalization
- No validator registration system

The spike produces a document, not code. Code comes after the gateway VM is proven.

---

## Relationship to Other Plans

```
LTP Gateway VM Plan (this document)
    |
    |  Phase 1-3: Single VM (EVM)
    |    Establishes: runtime environment, POA attestation model,
    |                 cross-chain event qualification, devnet integration
    |
    |  Phase 4: Dual VM (EVM + MoveVM)
    |    Establishes: dual execution environment, writer permissioning,
    |                 BLS state root attestation, Move state propagation,
    |                 precompile interface
    |
    +---> Proposed MoveVM+DID Architecture
    |       |
    |       |  Builds on Phase 4 dual-VM foundation
    |       |  Adds: Move DID registry module, resource-model DID documents,
    |       |         Ethereum account binding, committee signing governance,
    |       |         storage tiering, external verification patterns
    |       |
    |       +---> DID Expansion Plan
    |               |
    |               |  Built in tandem with MoveVM+DID
    |               |  Adds: did:etp method, VCs, freshness tiers,
    |               |         cross-chain ZK resolution, phased rollout
    |               |
    |               +--- Phase 1: Federation VCs
    |               +--- Phase 2: Node DIDs -> gateway VM gets a DID
    |               +--- Phase 3: Institutional DIDs + ZK resolution
    |               +--- Phase 4: Retail DIDs + protocol fee abstraction
    |
    +---> greth + Mysticeti Spike (strategic track)
            |
            |  Validates: gateway + dual-VM interface compatibility
            |             with future chain architecture
            |
            +--- Feeds into: mainnet architecture decisions
```

Each layer is independently useful and incrementally buildable. The single-VM gateway proves attestation. The dual-VM phase proves the execution environment. MoveVM+DID builds identity on the proven foundation. The DID Expansion Plan operationalizes identity at scale.

---

## Existing Infrastructure Reuse

### Phases 1-3 (Single VM)

| Gateway VM Need | Existing Code | Modification |
|---|---|---|
| Daemon process with tick loop | `BridgeOperatorService` | Extend with event listener |
| On-chain submission with retry | `AnchorClient` (token bucket, circuit breaker) | Configure for devnet |
| Confirmation depth tracking | `AnchorVerifier` (two-phase verification) | Reuse for source chain finality |
| Replay protection | `SequenceTracker` (per-signer monotonic) | Extend with per-event-hash dedup |
| Challenge window management | `ChallengeManager` (state machine, auto-finalize) | Reuse directly |
| ML-DSA-65 attestation signing | `MLDSA.sign()` + domain separation | New domain tag: `GSX-LTP:GATEWAY-ATTEST:v1` |
| Structured logging | `StructuredLogger` + `CorrelationContext` | Reuse directly |
| Prometheus metrics | `MetricsRegistry` | Add gateway-specific counters |
| TOML + env config | `NodeConfig.from_toml_with_env_overlay()` | Extend with gateway fields |
| gRPC health + REST diagnostics | `HealthServer` + `NodeDiagnosticsServer` | Extend with gateway endpoints |
| Signal handling + shutdown ordering | `ETPNode.stop()` (reverse-startup) | Same pattern for gateway |

Estimated new code (Phases 1-3): ~1,500-2,000 lines for the gateway VM module.

### Phase 4 (Dual VM)

| Dual VM Need | Existing Code | New Work |
|---|---|---|
| Move execution engine | None | MoveVM binary integration |
| Writer registry contract | `LTPAnchorRegistry` governance pattern | New EVM contract, same UUPS + Timelock pattern |
| Transaction-level enforcement | Gateway validator pattern | Post-ordering Move tx filter |
| BLS aggregate signing | None (ML-DSA-65 exists for LTP) | BLS library integration + signing round protocol |
| State delta propagation | Gossip protocol (`src/ltp/node/gossip.py`) | New message type for Move deltas |
| POS delta verification | `AnchorVerifier` pattern | Root recomputation + BLS signature check |
| Dual state root | Block header format | New header field for Move root |
| Precompile | None | Interface definition + address reservation |

Estimated new code (Phase 4): ~4,000-6,000 lines + MoveVM binary integration.

---

## Open Questions

### Phases 1-3

| # | Question | Resolution Target |
|---|---|---|
| 1 | GSX devnet RPC endpoint and chain ID for the gateway VM target | Blockchain team |
| 2 | How many gateway VMs should run in parallel for the initial testnet? | Architecture decision -- start with 1, scale to 3 for redundancy testing |
| 3 | Should the gateway VM run in Docker or as a bare process on the VM? | Dockerfile exists in `deploy/Dockerfile` -- Docker preferred for reproducibility |
| 4 | What is the finality depth for Base Sepolia events before gateway processing? | Suggest 12 blocks (~2 min), configurable |
| 5 | Should the gateway accept events from multiple source chains simultaneously? | Phase 1: single source. Phase 2: multi-source with per-chain config |
| 6 | Gateway signer key: fresh keypair or reuse existing bridge operator key? | Fresh keypair recommended -- separate authorization scope |
| 7 | Timelock delay for gateway signer registration on devnet | 60s for testnet (matches current deployment), 24-48h for production |

### Phase 4

| # | Question | Resolution Target |
|---|---|---|
| 8 | MoveVM binary: which Move implementation (Aptos Move, Sui Move, or independent)? | Architecture decision -- impacts resource model semantics |
| 9 | BLS library: which implementation (blst, py_ecc, or other)? | Engineering decision -- blst recommended for production performance |
| 10 | Precompile address `0x0F`: coordinate with greth docs for reservation | greth + Mysticeti spike |
| 11 | Writer registry contract: separate from or extension of `LTPAnchorRegistry`? | Architecture decision -- separate recommended (clean separation of concerns) |
| 12 | Committee size at Phase 4 launch: initial POA node count? | Operational decision -- suggest ~30 per MoveVM+DID architecture |
| 13 | BLS key management: how do POA nodes manage BLS keys alongside ML-DSA-65 keys? | Key ceremony design |
| 14 | Move state delta format: raw state changes or structured deltas? | Engineering decision (impacts bandwidth and verification) |
| 15 | greth + Mysticeti spike: who leads this, and what is the timeline? | Team coordination |

---

*This document defines the phased path from a single-VM POA attestation gateway to a dual-VM execution environment. Phases 1-3 prove the attestation model on live testnets with proven infrastructure. Phase 4 introduces MoveVM alongside EVM, establishing the runtime that the MoveVM+DID identity architecture and DID Expansion Plan will build upon. Each phase is independently deployable and validates the assumptions of the next.*
