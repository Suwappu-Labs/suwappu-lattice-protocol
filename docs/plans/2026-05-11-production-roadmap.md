# ETP Production Roadmap

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Date:** May 11, 2026
**Purpose:** Map all remaining work from current state to production-ready multi-node deployment. Living reference document — update as specs are completed.

---

## Current State (as of May 11, 2026)

| Metric | Value |
|--------|-------|
| Python modules | 202 |
| Test files | 194 |
| Tests passing | 3,461 |
| Solidity contracts | 8 |
| Deploy scripts | 15 |
| Live deployments | 2 (GSX Testnet v5, Base Sepolia v6) |
| Subpackages | 20 |

---

## Completed Milestones

| Spec | Name | Status | Tests |
|------|------|--------|-------|
| A | Core Protocol (state machine, envelopes, erasure, Merkle, lattice) | Done | ~800 |
| B | Multi-VM Execution Layer (registry, router, state root, precompile, attestation) | Done | ~350 |
| C1 | BLS12-381 Primitives & Key Management | Done | ~90 |
| C2 | Writer Registry & Per-VM Policies (RBAC, emergency recovery, epoch) | Done | ~250 |
| C3a | Committee Formation & Epoch Management | Done | ~180 |
| C3b | Threshold DKG (Pedersen VSS, session state machine, key registry) | Done | ~91 |
| — | Gateway VM Phases 1-4 (core, tx flow, stress, dual VM) | Done | ~166 |
| — | On-chain: LTPAnchorRegistry (UUPS), MultiSig, Timelock, Bridge contracts | Deployed | 84 (Solidity) |
| — | Bridge module (L1Anchor, Relayer, L2Materializer, ChallengeManager, fraud proofs) | Done | ~200 |
| — | ZK STARK/FRI prover (Goldilocks field, Merkle, FRI, stark_proof) | Done | ~150 |
| — | Cloud infrastructure interfaces (KMS, queue, backup, scheduler, orchestrator) | Interfaces done | ~100 |
| — | Compliance framework (9 subsystems, FIPS dual-mode) | Done | ~80 |

---

## What Remains — Spec Inventory

### Phase 5: Committee Signing

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **C3c** | Threshold BLS Signing | Small (5-7 tasks) | C3b (done) |

**Scope:** `partial_sign()`, `combine_signatures()`, `threshold_verify()` using the DKG-produced keys. The key infrastructure exists — this adds the signing protocol on top.

**Delivers:** Committees can produce threshold BLS signatures over attestations, state roots, and cross-VM messages. This is the payoff for all of C3a/C3b.

---

### Phase 6: Transport & Networking

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **D1** | Consensus Protocol Integration | Large (10-14 tasks) | C3c |
| **D2** | P2P Encrypted Transport | Large (10-14 tasks) | D1 |
| **D3** | Node Discovery & Service Mesh | Medium (7-10 tasks) | D2 |

**Scope:** Replace `FakeConsensusAdapter`, `FakeDKGTransport`, `InMemoryFederationTransport` with real networked implementations. This is the **critical architectural decision** — protocol selection (HotStuff? Tendermint? Mysticeti?), P2P library (libp2p? gRPC?), ML-KEM encrypted channels for DKG share transport, node discovery and peer management.

**Delivers:** Multi-node operation. Without this, everything runs single-process.

**Open decisions:**
- Consensus protocol family (BFT variant selection)
- P2P transport library
- Message serialization format (protobuf? CBOR? SSZ?)
- Relationship to GSX mainnet chain direction (greth + Mysticeti spike referenced in Gateway VM Plan)

---

### Phase 7: Execution Backends

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **E1** | EVM Executor Backend | Medium (7-10 tasks) | D1 (needs consensus for ordering) |
| **E2** | Move Executor Backend | Medium (7-10 tasks) | E1 (patterns established) |

**Scope:** Replace `EVMExecutor` and `MoveExecutor` stubs with real VM integration. EVM via JSON-RPC to execution clients (geth, reth). Move via Aptos/Sui Move runtime or independent binary. Wire through the existing `TransactionRouter` and `VMRegistry`.

**Delivers:** Real transaction execution against actual VM runtimes instead of stub responses.

**Open decisions:**
- MoveVM variant (Aptos Move, Sui Move, or independent) — referenced as Q8 in Gateway VM execution roadmap
- Execution client selection for EVM
- State storage backend (LevelDB? RocksDB? Custom?)

---

### Phase 8: Cryptographic Hardening

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **F1** | Certified PQC Bindings | Medium (7-10 tasks) | None (independent) |
| **F2** | HSM Integration | Medium (5-8 tasks) | F1 |

**Scope:** The compliance module currently reports ML-KEM-768 and ML-DSA-65 as "simulated" in default mode. The FIPS mode path exists (`FIPSCryptoProvider`) but routes through OpenSSL 3.x which may or may not have certified PQC support depending on the build. `SoftwareHSM` is explicitly labeled "NOT suitable for production."

**What's NOT stubbed (correction from earlier audit):**
- The ZK STARK/FRI stack is **fully real** — `field.py`, `merkle.py`, `fri.py`, `stark_proof.py` are complete implementations, not PoC stubs
- `SimulatedZKBridgeProver` now delegates to the real `STARKBridgeProver` — the "simulated" label is legacy naming
- SP1 and RISC Zero provers exist with local/network modes (`sp1_prover.py`, `risc0_prover.py`)

**What IS stubbed:**
- Default-mode PQC is the project's own Python implementations, not FIPS-validated
- `SoftwareHSM` is in-memory, not hardware-backed
- No PKCS#11 or cloud KMS binding for key material protection

**Delivers:** FIPS 140-3 compliant crypto path with hardware key protection.

---

### Phase 9: Production Infrastructure

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **G1** | Cloud Infrastructure Bindings | Medium (8-12 tasks) | None (independent) |
| **G2** | Observability & TLS Production | Small (4-6 tasks) | G1 |

**Scope:** Replace all `InMemory*` implementations with production backends:

| Current (In-Memory) | Production Target |
|---------------------|-------------------|
| `InMemoryKMSBackend` | AWS KMS / GCP Cloud KMS / Azure Key Vault |
| `InMemoryQueue` | SQS / Pub/Sub / NATS |
| `InMemoryBackupManager` | S3 / GCS with encryption |
| `InMemoryScheduler` | CloudWatch Events / Cloud Scheduler |
| `InMemoryOrchestrator` | Step Functions / Cloud Workflows |
| `InMemoryCertManager` | Let's Encrypt / Vault PKI |
| `InMemoryFederationTransport` | See D2 (P2P transport) |

**Delivers:** Cloud-native deployment capability. The interfaces are proven — these are backend swaps.

**Note:** `InMemoryFederationTransport` replacement is covered by Spec D2, not here. Federation transport is a protocol concern, not an infrastructure concern.

---

### Phase 10: Cross-Chain Bridge E2E

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **H1** | Bridge Relay & End-to-End Wiring | Medium (8-12 tasks) | D2 (transport), E1 (EVM backend) |

**Scope:** The bridge module is **more complete than initially assessed**:
- `L1Anchor`, `Relayer`, `L2Materializer` — fully implemented
- `BridgeOperatorService` — persistent daemon with retry
- `WatcherService` — off-chain fraud detection
- `ChallengeManager` — optimistic challenge state machine
- Three fraud proof types implemented
- `ZKBridgeVerifier` handles v1/v2/v3 proofs
- SP1 + RISC Zero provers with local/network modes

**What's missing:** End-to-end wiring against live chains with real finality, real gas, real reorgs. The individual components are built and tested in isolation — they need to be orchestrated together against real EVM endpoints with the deployed BridgeEmitter and OptimisticBridgeChallenge contracts.

**Delivers:** Live cross-chain transfers with fraud proof protection.

---

### Phase 11: Identity

| Spec | Name | Size | Depends On |
|------|------|------|------------|
| **I1** | MoveVM + DID Architecture | Large (12-16 tasks) | E2 (Move backend), H1 (bridge) |
| **I2** | DID Expansion (did:etp, VCs, cross-chain ZK resolution) | Large (15-20 tasks) | I1 |

**Scope:** Defined in two existing documents:
- `docs/Proposed-MoveVM-DID.docx` — Move DID registry module, resource model, writer permissioning
- `docs/DID_EXPANSION_PLAN.md` — Full 892-line plan: `did:etp` W3C DID Core 1.0 method, VC architecture, 4-phase rollout (federation VCs → node DIDs → institutional → retail), cross-chain ZK resolution via STARK prover

**Phased internally:**

| DID Phase | Target | Anchoring |
|-----------|--------|-----------|
| Phase 1 | Federation VCs (machine-to-machine) | Commitment Log (X-mode) |
| Phase 2 | Node/operator DIDs | Commitment Log (X-mode) |
| Phase 3 | Institutional user DIDs + ZK cross-chain | On-chain primary (Y-mode) |
| Phase 4 | Retail user DIDs | On-chain primary (Y-mode) |

**Delivers:** W3C-compliant decentralized identity on post-quantum infrastructure with cross-chain resolution.

---

## Dependency Graph

```
COMPLETED (C3b)
    │
    ▼
C3c: Threshold Signing ─────────────────────────────────────────┐
    │                                                            │
    ▼                                                            │
D1: Consensus Protocol                                           │
    │                                                            │
    ▼                                                            │
D2: P2P Encrypted Transport ──────────────────┐                 │
    │                                          │                 │
    ▼                                          │                 │
D3: Node Discovery                             │                 │
                                               │                 │
    ┌──────────────────────────────────────────┘                 │
    │                                                            │
    ▼                                                            │
E1: EVM Executor Backend                                         │
    │                                                            │
    ▼                                                            │
E2: Move Executor Backend                                        │
    │                                                            │
    ├──────────────────┐                                         │
    ▼                  ▼                                         │
H1: Bridge E2E    I1: MoveVM+DID                                 │
                       │                                         │
                       ▼                                         │
                  I2: DID Expansion                              │
                                                                 │
                                                                 │
INDEPENDENT (can run in parallel after C3c): ◄───────────────────┘
    F1: Certified PQC Bindings
        │
        ▼
    F2: HSM Integration
    G1: Cloud Infrastructure Bindings
        │
        ▼
    G2: Observability & TLS
```

---

## Critical Path

The longest dependency chain determines minimum calendar time:

```
C3c → D1 → D2 → D3 → E1 → E2 → I1 → I2
 5      14    14    10    10    10   16    20  ≈ 99 tasks on critical path
```

**Parallel tracks** (can run concurrently with the critical path once C3c is done):
- F1 → F2 (crypto hardening): ~15 tasks
- G1 → G2 (cloud/infra): ~16 tasks
- H1 (bridge E2E): ~12 tasks (starts after D2 + E1)

---

## Phase Gates

### Gate 5 — C3c Complete
| Check | Criteria |
|-------|----------|
| Threshold signing works | `partial_sign()` + `combine_signatures()` produces valid BLS signature |
| Verification works | `threshold_verify()` accepts t-of-n partial sigs, rejects t-1 |
| CommitteeManager integration | `tick()` produces threshold-signed attestations when DKG result exists |
| No regressions | All 3,461+ existing tests pass |

**Decision:** Proceed to D1 (Transport). Consider publishing threshold signing benchmarks.

### Gate 6 — Transport Complete (D1 + D2 + D3)
| Check | Criteria |
|-------|----------|
| Multi-node consensus | N nodes reach agreement on ordered blocks |
| Encrypted DKG | Full DKG ceremony completes over real P2P with ML-KEM encrypted shares |
| Node discovery | Nodes find peers and establish connections |
| Federation | Cross-node federation messages delivered reliably |
| No regressions | All tests pass |

**Decision:** This is the **first multi-node gate**. Deploy 3+ node testnet on GSX devnet. This is the proving ground — if consensus + DKG + federation work across real nodes, the protocol is viable.

### Gate 7 — Execution Backends Complete (E1 + E2)
| Check | Criteria |
|-------|----------|
| EVM transactions execute | Real EVM state changes via JSON-RPC |
| Move transactions execute | Real Move resource operations |
| Cross-VM routing | TransactionRouter dispatches to correct backend |
| Multi-VM state root | State root aggregates across live VMs |
| No regressions | All tests pass |

**Decision:** Proceed to identity layer. Consider mainnet deployment timeline.

### Gate 8 — Production Hardening Complete (F1 + F2 + G1 + G2)
| Check | Criteria |
|-------|----------|
| FIPS compliance | `FIPSCryptoProvider` mode uses certified bindings, no "simulated" labels |
| HSM integration | Key material protected by hardware (PKCS#11 or cloud KMS) |
| Cloud services | All `InMemory*` replaced with production backends |
| TLS | Real certificate management, auto-renewal |
| No regressions | All tests pass |

**Decision:** Production-ready infrastructure. Can deploy to regulated environments.

### Gate 9 — Bridge E2E Complete (H1)
| Check | Criteria |
|-------|----------|
| Live cross-chain transfer | L1→L2 and L2→L1 with real finality |
| Fraud detection | Watcher detects and submits fraud proofs |
| Challenge resolution | OptimisticBridgeChallenge resolves on-chain |
| ZK verification | STARK proofs verified on-chain via ZKBridgeVerifier |
| No regressions | All tests pass |

**Decision:** Cross-chain bridge operational. Proceed to identity.

### Gate 10 — Identity Complete (I1 + I2)
| Check | Criteria |
|-------|----------|
| did:etp method | W3C DID Core 1.0 compliant |
| Verifiable Credentials | Issue, present, verify VCs |
| Cross-chain resolution | ZK STARK proof of DID state across chains |
| All 4 DID phases | Federation → Node → Institutional → Retail |
| No regressions | All tests pass |

**Decision:** Feature-complete protocol. Mainnet launch candidate.

---

## Scope Summary

| Phase | Specs | Est. Tasks | Est. New Tests |
|-------|-------|-----------|----------------|
| 5: Committee Signing | C3c | 5-7 | ~40 |
| 6: Transport & Networking | D1, D2, D3 | 30-38 | ~250 |
| 7: Execution Backends | E1, E2 | 14-20 | ~150 |
| 8: Crypto Hardening | F1, F2 | 12-18 | ~80 |
| 9: Production Infrastructure | G1, G2 | 12-18 | ~60 |
| 10: Bridge E2E | H1 | 8-12 | ~80 |
| 11: Identity | I1, I2 | 27-36 | ~200 |
| **Total** | **13 specs** | **108-149 tasks** | **~860 new tests** |

**Projected final state:** ~4,300+ tests, ~250+ modules, production-ready multi-node protocol with W3C DID identity layer.

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Consensus protocol selection delays | High | Blocks all of Phase 6 | Align with GSX mainnet direction (greth + Mysticeti) early |
| MoveVM variant decision deferred | High | Blocks E2 and I1 | Aptos Move recommended; make decision before E1 completes |
| FIPS-certified PQC libraries immature | Medium | F1 scope unclear | liboqs is available; assess OpenSSL 3.x PQC module status |
| SP1/RISC Zero prover performance | Medium | H1 latency concerns | Real provers exist; benchmark before committing to production path |
| Transport library selection | High | Architectural lock-in | Prototype with libp2p; keep transport protocol abstract |
| DID plan scope creep | Medium | I2 becomes unbounded | 4-phase internal gating already defined in DID Expansion Plan |
| Cross-chain finality assumptions | Medium | Bridge E2E fragile | Test against real reorgs on testnets before mainnet |
| HSM vendor lock-in | Low | F2 portability | PKCS#11 standard interface; cloud KMS as fallback |

---

## Open Architectural Decisions

These must be resolved during brainstorming, before their respective specs are written:

| # | Decision | Affects | Resolution Deadline |
|---|----------|---------|---------------------|
| 1 | Consensus protocol family (HotStuff / Tendermint / Mysticeti) | D1 | Before D1 spec |
| 2 | P2P library (libp2p / gRPC / custom) | D2 | Before D2 spec |
| 3 | Message serialization (protobuf / CBOR / SSZ) | D1, D2 | Before D1 spec |
| 4 | MoveVM variant (Aptos / Sui / independent) | E2, I1 | Before E2 spec |
| 5 | EVM execution client (geth / reth / erigon) | E1 | Before E1 spec |
| 6 | State storage backend (LevelDB / RocksDB / custom) | E1, E2 | Before E1 spec |
| 7 | PQC library (liboqs / OpenSSL 3.x PQC / vendor) | F1 | Before F1 spec |
| 8 | HSM standard (PKCS#11 / cloud KMS / both) | F2 | Before F2 spec |
| 9 | Cloud provider primary target (AWS / GCP / multi) | G1 | Before G1 spec |
| 10 | ZK prover for production bridge (SP1 / RISC Zero / native STARK) | H1 | Before H1 spec |

---

## Document Sequencing

```
This Roadmap (reference)
│
├── Spec C3c: Threshold BLS Signing
│       ↓
├── Spec D1: Consensus Protocol
├── Spec D2: P2P Encrypted Transport
├── Spec D3: Node Discovery
│       ↓
├── Spec E1: EVM Executor Backend
├── Spec E2: Move Executor Backend
│       ↓
├── Spec H1: Bridge Relay E2E
│       ↓
├── Spec I1: MoveVM + DID Architecture
│       (references: docs/Proposed-MoveVM-DID.docx)
├── Spec I2: DID Expansion
│       (references: docs/DID_EXPANSION_PLAN.md)
│
├── [Parallel] Spec F1: Certified PQC Bindings
├── [Parallel] Spec F2: HSM Integration
├── [Parallel] Spec G1: Cloud Infrastructure Bindings
└── [Parallel] Spec G2: Observability & TLS
```

Each spec follows the established cycle: **Brainstorm → Design Spec → Implementation Plan → Subagent-Driven Execution → Gate Check**.

---

## Corrections to Earlier Audit

During roadmap preparation, the following items were found to be more complete than initially assessed:

1. **ZK STARK/FRI stack is fully real** — `field.py`, `merkle.py`, `fri.py`, `stark_proof.py` are complete implementations with 128-bit security, not PoC stubs.
2. **`SimulatedZKBridgeProver` delegates to real `STARKBridgeProver`** — the "simulated" label is legacy naming; it produces real STARK proofs.
3. **SP1 and RISC Zero provers exist** with local and network modes — not just stubs.
4. **Bridge module is substantially complete** — L1Anchor, Relayer, L2Materializer, BridgeOperatorService, WatcherService, ChallengeManager, three fraud proof types all implemented. Missing: E2E wiring against live chains.
5. **Compliance framework has real logic** — 9 subsystems (RBAC, GeoFence, AuditLogger, KeyRotation, GDPRDeletion, SIEM, HSM) are implemented, not stubs. Only `SoftwareHSM` is a simulation; the rest are production logic with in-memory backends.
