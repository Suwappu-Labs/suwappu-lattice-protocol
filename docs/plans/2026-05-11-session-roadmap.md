# ETP Session Roadmap — Current State to Feature-Complete

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Date:** May 11, 2026
**Purpose:** Session-aware execution roadmap mapping every remaining spec to concrete work sessions, with dependency chains, complexity ratings, and honest caveats. Living document — update as gates are cleared.

---

## Project Snapshot (May 11, 2026)

| Metric | Value |
|--------|-------|
| Python modules | 202 |
| Python tests | 3,349 |
| Solidity tests | 181 |
| **Total tests** | **3,530** |
| Source subpackages | 20 |
| Live deployments | 2 (GSX Testnet v5, Base Sepolia v6) |
| Completed specs | 13 (A through C3b) |
| Development days (git history) | 10 |
| Total commits | 95 |

---

## What's Proven — No Longer Theory

### Real Cryptography (zero simulations in the critical path)

| Component | Implementation | Backend | Status |
|-----------|---------------|---------|--------|
| ML-KEM-768 (FIPS 203) | `primitives.py` | `pqcrypto.kem.ml_kem_768` | **REAL** — enforced at import via `assert_real_crypto()` |
| ML-DSA-65 (FIPS 204) | `primitives.py` | `pqcrypto.sign.ml_dsa_65` | **REAL** — enforced at import |
| XChaCha20-Poly1305 | `primitives.py` | `pynacl` bindings | **REAL** |
| BLS12-381 | `bls.py`, `ec_backend.py` | `blst` (C) or `py_ecc` (pure Python) | **REAL** — dual backend, real pairings |
| Pedersen VSS | `dkg/vss.py` | BLS12-381 G1 curve ops | **REAL** — dual commitments, share verification |
| DKG Ceremony | `dkg/session.py` | 4-phase state machine | **REAL** — full QUAL set, complaint handling |
| ZK STARK/FRI | `zk/fri.py`, `zk/stark_proof.py` | Goldilocks field, NTT, Fiat-Shamir | **REAL** — full prover + verifier |
| Reed-Solomon Erasure | `erasure.py` | GF(256) Vandermonde + `zfec` fast path | **REAL** |
| Merkle Log | `merkle_log/tree.py` | RFC 6962 compliant | **REAL** — audit paths + consistency proofs |
| Fraud Proofs (3 types) | `bridge/fraud_proof.py` | ML-DSA verify calls | **REAL** |
| SHA3-256 / BLAKE3-256 | `domain.py`, throughout | Dual-lane hashing | **REAL** — lanes never mixed |

### Real Protocol Core

| Component | Location | Tests | Status |
|-----------|----------|-------|--------|
| State machine (10 transitions) | `anchor/state.py` + Solidity | Cross-parity verified | **PROVEN** |
| Envelope commit/seal/unseal | `envelope.py`, `lattice.py` | ~800 | **PROVEN** |
| Multi-VM routing + state root | `execution/` (VMRegistry, Router, WriterGate) | ~350 | **PROVEN** |
| Committee formation + epoch | `execution/committee/` | ~180 | **PROVEN** |
| DKG key generation | `execution/committee/dkg/` | ~91 | **PROVEN** |
| Gateway VM daemon | `gateway_vm/` | ~166 | **PROVEN** |
| Bridge components (5 modules) | `bridge/` | ~200 | **PROVEN** — individually, not E2E |
| Compliance framework (9 systems) | `compliance.py` | ~80 | **PROVEN** — software-only |
| Writer registry + RBAC | `execution/writer*.py` | ~250 | **PROVEN** |

### Deployed On-Chain

| Contract | GSX Testnet (v5) | Base Sepolia (v6) |
|----------|------------------|-------------------|
| LTPAnchorRegistry (UUPS) | `0xB29d...` | `0x79eF...` |
| LTPMultiSig (2-of-2) | `0x0106...` | `0x4c32...` |
| TimelockController | `0x7C26...` | `0xc915...` |
| BridgeEmitter | — | Deployed |
| OptimisticBridgeChallenge | — | Deployed |
| ZKBridgeVerifier | — | Deployed |

Governance path proven: MultiSig (2-of-2) -> Timelock (60s) -> Registry. Version bumps verified on-chain through 6 iterations.

---

## What's Still Theoretical

| Component | Current State | What's Missing |
|-----------|--------------|----------------|
| Threshold BLS signing | DKG keys exist, no signing protocol | `partial_sign()`, `combine_signatures()`, `threshold_verify()` |
| Consensus | `FakeConsensusAdapter` only | No real BFT (HotStuff/Tendermint/Mysticeti) |
| P2P networking | `FakeDKGTransport`, `InMemoryFederationTransport` | No real encrypted channels, no peer discovery |
| EVM executor | Stub — in-memory hash-rolling | No geth/reth JSON-RPC connection |
| Move executor | `FakeMoveBackend` only | No real MoveVM runtime |
| Ed25519 composite | SHA-512 hash placeholder | Real Ed25519 in `MLDSA65_ED25519` path |
| HSM | `SoftwareHSM` (in-memory) | No PKCS#11 or cloud KMS hardware binding |
| Cloud backends | `InMemory*` for queue/scheduler/orchestrator | Real cloud service bindings (exception: `AWSKMSBackend` is real) |
| Federation HTTP | httpx transport exists | NIR signature is `b""` placeholder |
| Bridge E2E | Components work in isolation | Never tested against live finality/reorgs/gas |
| DID / Identity | 892-line plan + .docx spec | Zero implementation |
| Mainnet deployment | Scripts exist | No broadcast artifacts |

---

## Spec-by-Spec Execution Plan

### Spec Sizing Matrix

| Spec | Tasks | Sessions (design + build) | Complexity | Blocking Decision |
|------|-------|--------------------------|------------|-------------------|
| C3c | 5-7 | 1-2 | Low — well-defined, no open decisions | None |
| D1 | 10-14 | 3-4 | High — consensus protocol selection required | Consensus family (HotStuff / Tendermint / Mysticeti) |
| D2 | 10-14 | 3-4 | High — P2P architecture, encryption | P2P library (libp2p / gRPC / custom), serialization format |
| D3 | 7-10 | 2-3 | Medium | None (builds on D2 patterns) |
| E1 | 7-10 | 2-3 | Medium — but needs real EVM node | EVM client (geth / reth / erigon) |
| E2 | 7-10 | 2-3 | Medium — MoveVM variant decision blocks | MoveVM variant (Aptos / Sui / independent) |
| F1 | 7-10 | 2-3 | Medium — library evaluation | PQC library (liboqs / OpenSSL 3.x PQC / vendor) |
| F2 | 5-8 | 2 | Medium | HSM standard (PKCS#11 / cloud KMS / both) |
| G1 | 8-12 | 2-3 | Low — mechanical swaps | Cloud provider primary target (AWS / GCP / multi) |
| G2 | 4-6 | 1-2 | Low | None |
| H1 | 8-12 | 2-3 | Medium — needs D2 + E1 working | ZK prover for production (SP1 / RISC Zero / native STARK) |
| I1 | 12-16 | 3-5 | High — architecture decisions, existing .docx spec | Move DID registry design |
| I2 | 15-20 | 4-6 | High — 892-line plan exists but needs conversion | 4-phase DID rollout scoping |
| **Total** | **108-149** | **~28-41 sessions** | | **10 open architectural decisions** |

---

### Horizon 1: Near-Term — Committees Can Sign Things

**Specs:** C3c (Threshold BLS Signing)
**Sessions:** 1-2
**Unlocks:** Committees produce threshold BLS signatures over attestations, state roots, and cross-VM messages. This is the payoff for all of C3a/C3b.

```
C3b (DONE) ──► C3c: Threshold BLS Signing
                 ├── partial_sign(message, secret_share) -> PartialSig
                 ├── combine_signatures(partial_sigs, group_pk) -> BLSSignature
                 ├── threshold_verify(message, signature, group_pk) -> bool
                 └── CommitteeManager integration: tick() produces signed attestations
```

**Gate 5 Criteria:**
- [ ] `partial_sign()` + `combine_signatures()` produces valid BLS signature
- [ ] `threshold_verify()` accepts t-of-n partial sigs, rejects t-1
- [ ] `CommitteeManager.tick()` produces threshold-signed attestations when DKG result exists
- [ ] All 3,530+ existing tests still pass

**Risk:** Low. Math is well-known. DKG infrastructure is proven. No open decisions.

---

### Horizon 2: Mid-Term — Multi-Node with Real VMs

**Specs:** D1, D2, D3, E1, E2
**Sessions:** 12-17
**Unlocks:** Multiple ETP nodes discover each other, reach consensus, execute real transactions. This is the transition from "works on one machine" to "works as a distributed system."

```
C3c (Gate 5) ──► D1: Consensus Protocol ──► D2: P2P Transport ──► D3: Node Discovery
                  │                           │
                  │ Replaces:                 │ Replaces:
                  │ FakeConsensusAdapter      │ FakeDKGTransport
                  │                           │ InMemoryFederationTransport
                  │                           │
                  └───────────────────────────┴──► E1: EVM Backend ──► E2: Move Backend
                                                   │                    │
                                                   │ Replaces:         │ Replaces:
                                                   │ EVMExecutor stub  │ FakeMoveBackend
                                                   │ (hash-rolling)    │
```

#### D1: Consensus Protocol Integration (10-14 tasks, 3-4 sessions)

**Open decision (MUST resolve before spec):** Consensus family.

| Option | Pros | Cons | GSX Alignment |
|--------|------|------|---------------|
| Mysticeti (Sui DAG-BFT) | Sub-second latency, DAG parallelism | Newer, less battle-tested | greth + Mysticeti spike referenced in Gateway VM Plan |
| HotStuff / HotStuff-2 | Well-studied, linear communication | Higher latency than DAG | Standard choice |
| Tendermint/CometBFT | Mature ecosystem, Cosmos tooling | 2-round latency, older design | Less aligned with GSX direction |

**Recommendation:** Mysticeti, aligned with GSX mainnet direction. Prototype in D1 with fallback abstraction.

**Delivers:**
- `ConsensusAdapter` real implementation (replaces `FakeConsensusAdapter`)
- Block ordering, proposal, voting, finality
- Integration with existing `TransactionRouter`

#### D2: P2P Encrypted Transport (10-14 tasks, 3-4 sessions)

**Open decisions:** P2P library, message serialization.

| Decision | Options | Leaning |
|----------|---------|---------|
| P2P library | libp2p / gRPC / custom | libp2p (peer discovery built-in, Noise/QUIC encryption) |
| Serialization | protobuf / CBOR / SSZ | protobuf (ecosystem maturity) or SSZ (Ethereum alignment) |

**Delivers:**
- ML-KEM encrypted channels for DKG share transport
- Real `DKGTransport` replacing `FakeDKGTransport`
- Real `FederationTransport` replacing `InMemoryFederationTransport`
- Peer connection management

#### D3: Node Discovery & Service Mesh (7-10 tasks, 2-3 sessions)

**Delivers:**
- Peer discovery (mDNS for local, DHT/bootstrap for wide-area)
- Connection management, peer scoring
- Service mesh for internal node communication

#### E1: EVM Executor Backend (7-10 tasks, 2-3 sessions)

**Open decision:** EVM client (geth / reth / erigon).
**External dependency:** Requires a running EVM node for integration tests.

**Delivers:**
- Real `EVMExecutor` via JSON-RPC (replaces hash-rolling stub)
- State storage backend integration
- `TransactionRouter` wired to live EVM

#### E2: Move Executor Backend (7-10 tasks, 2-3 sessions)

**Open decision:** MoveVM variant (Aptos Move / Sui Move / independent).
**External dependency:** Requires MoveVM binary.

**Delivers:**
- Real `MoveExecutor` via gRPC or embedded runtime
- Move resource operations through `TransactionRouter`

**Gate 6 Criteria (after D1-D3):**
- [ ] N nodes reach agreement on ordered blocks
- [ ] Full DKG ceremony completes over real P2P with ML-KEM encrypted shares
- [ ] Nodes find peers and establish connections
- [ ] Cross-node federation messages delivered reliably
- [ ] **Deploy 3+ node testnet on GSX devnet** (the proving ground)

**Gate 7 Criteria (after E1-E2):**
- [ ] Real EVM state changes via JSON-RPC
- [ ] Real Move resource operations
- [ ] TransactionRouter dispatches to correct backend
- [ ] State root aggregates across live VMs

**Risk:** High. This is where theory meets distributed reality. Consensus protocol selection is the single highest-stakes decision remaining. Wrong choice means rework. External dependencies (EVM node, MoveVM binary) add setup time outside our session loop.

---

### Horizon 3: Parallel Track — Production-Grade Infrastructure

**Specs:** F1, F2, G1, G2
**Sessions:** 7-11 (can run concurrently with Horizon 2 after C3c)
**Unlocks:** FIPS 140-3 compliance, hardware key protection, cloud-native deployment. Required for regulated environments.

```
C3c (Gate 5) ──► F1: Certified PQC Bindings ──► F2: HSM Integration
                  │
                  │ Independent (no dependency on D1-D3):
                  │
                  └──► G1: Cloud Infrastructure ──► G2: Observability & TLS
```

#### F1: Certified PQC Bindings (7-10 tasks, 2-3 sessions)

**Open decision:** PQC library (liboqs / OpenSSL 3.x PQC module / vendor).

**Current state:** ML-KEM-768 and ML-DSA-65 are real via `pqcrypto` Python package. `FIPSCryptoProvider` exists but routes through potentially uncertified builds. Need FIPS-validated bindings.

**Delivers:**
- FIPS 140-3 validated PQC path
- No more "simulated" labels in any mode
- Benchmark suite for PQC operations

#### F2: HSM Integration (5-8 tasks, 2 sessions)

**Open decision:** PKCS#11 / cloud KMS / both.

**Delivers:**
- Hardware-backed key material protection (replaces `SoftwareHSM`)
- PKCS#11 or cloud KMS binding
- Key ceremony procedures

#### G1: Cloud Infrastructure Bindings (8-12 tasks, 2-3 sessions)

**Open decision:** Primary cloud target (AWS / GCP / multi-cloud).

| Current In-Memory | Production Target |
|-------------------|-------------------|
| `InMemoryQueue` | SQS / Pub/Sub / NATS |
| `InMemoryBackupManager` | S3 / GCS with encryption |
| `InMemoryScheduler` | CloudWatch Events / Cloud Scheduler |
| `InMemoryOrchestrator` | Step Functions / Cloud Workflows |
| `InMemoryCertManager` | Let's Encrypt / Vault PKI |

Note: `AWSKMSBackend` already exists as real boto3 — that pattern extends to the rest.
Note: `InMemoryFederationTransport` is covered by D2, not G1.

**Delivers:** Cloud-native deployment. The interfaces are proven — these are backend swaps.

#### G2: Observability & TLS Production (4-6 tasks, 1-2 sessions)

**Delivers:**
- Real certificate management with auto-renewal
- Production Prometheus/Grafana dashboards
- Structured logging for production ops

**Gate 8 Criteria:**
- [ ] `FIPSCryptoProvider` uses certified bindings, zero "simulated" labels
- [ ] Key material protected by hardware (PKCS#11 or cloud KMS)
- [ ] All `InMemory*` replaced with production backends
- [ ] Real TLS certificate management with auto-renewal

**Risk:** Medium. Library evaluation for F1 is the main uncertainty. G1/G2 are mechanical swaps — low risk, just effort.

---

### Horizon 4: Late-Stage — Bridge E2E + Identity

**Specs:** H1, I1, I2
**Sessions:** 9-14
**Unlocks:** Live cross-chain transfers with fraud proof protection. W3C-compliant decentralized identity on post-quantum infrastructure.

```
D2 (transport) + E1 (EVM) ──► H1: Bridge Relay E2E
                                │
E2 (Move) ─────────────────────┼──► I1: MoveVM + DID Architecture
                                │    │
                                │    └──► I2: DID Expansion (4 internal phases)
                                │          ├── Phase 1: Federation VCs (machine-to-machine)
                                │          ├── Phase 2: Node/operator DIDs
                                │          ├── Phase 3: Institutional user DIDs + ZK cross-chain
                                │          └── Phase 4: Retail user DIDs
```

#### H1: Bridge Relay & End-to-End Wiring (8-12 tasks, 2-3 sessions)

**Open decision:** ZK prover for production (SP1 / RISC Zero / native STARK).

**Current state more complete than expected:**
- L1Anchor, Relayer, L2Materializer — fully implemented
- BridgeOperatorService — persistent daemon with retry
- WatcherService — off-chain fraud detection
- ChallengeManager — complete optimistic FSM
- Three fraud proof types — real ML-DSA verification
- SP1 + RISC Zero provers — exist with local/network modes

**What's missing:** End-to-end wiring against live chains with real finality, real gas, real reorgs. The individual components are built and tested in isolation — they need to be orchestrated together against the deployed BridgeEmitter and OptimisticBridgeChallenge contracts on Base Sepolia.

**Delivers:**
- Live L1 -> L2 and L2 -> L1 transfers
- Fraud detection and on-chain challenge resolution
- ZK STARK proof verification on-chain

**Gate 9 Criteria:**
- [ ] Live cross-chain transfer with real finality
- [ ] Watcher detects and submits fraud proofs
- [ ] OptimisticBridgeChallenge resolves on-chain
- [ ] STARK proofs verified on-chain via ZKBridgeVerifier

#### I1: MoveVM + DID Architecture (12-16 tasks, 3-5 sessions)

**Source specs:** `docs/Proposed-MoveVM-DID.docx`, early sections of `docs/DID_EXPANSION_PLAN.md`

**Delivers:**
- Move DID registry module
- Resource model for DID documents
- Writer permissioning for DID operations
- `did:etp` method skeleton (W3C DID Core 1.0)

#### I2: DID Expansion (15-20 tasks, 4-6 sessions)

**Source spec:** `docs/DID_EXPANSION_PLAN.md` (892 lines, 4 phases)

| DID Phase | Target | Anchoring Mode | Complexity |
|-----------|--------|----------------|------------|
| Phase 1 | Federation VCs (machine-to-machine) | Commitment Log (X-mode) | Medium |
| Phase 2 | Node/operator DIDs | Commitment Log (X-mode) | Medium |
| Phase 3 | Institutional user DIDs + ZK cross-chain | On-chain primary (Y-mode) | High |
| Phase 4 | Retail user DIDs | On-chain primary (Y-mode) | High |

**Delivers:**
- W3C DID Core 1.0 compliant `did:etp` method
- Verifiable Credential issuance, presentation, verification
- Cross-chain ZK STARK proof of DID state
- Full 4-phase identity rollout

**Gate 10 Criteria (feature-complete):**
- [ ] `did:etp` method passes W3C DID Core 1.0 compliance
- [ ] VCs: issue, present, verify
- [ ] Cross-chain DID resolution via ZK STARK
- [ ] All 4 DID phases operational
- [ ] All tests pass (~4,300+ projected)

**Risk:** High. I2 is practically a project within a project. The 892-line plan needs conversion into executable specs. Four internal phases mean four sub-gates. Scope creep is the primary threat — the existing 4-phase internal gating helps contain it.

---

## Dependency Graph

```
COMPLETED (C3b — Threshold DKG)
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

Longest dependency chain determines minimum session count:

```
C3c ──► D1 ──► D2 ──► D3 ──► E1 ──► E2 ──► I1 ──► I2
 1-2    3-4    3-4    2-3    2-3    2-3    3-5    4-6   = 21-30 sessions on critical path
```

Parallel tracks (concurrent with critical path after C3c):
- F1 -> F2: 4-6 sessions
- G1 -> G2: 3-5 sessions
- H1: 2-3 sessions (starts after D2 + E1)

**With interleaving, wall-clock drops from ~35 to ~25 sessions.**

---

## Horizon Summary

| Horizon | Specs | Sessions | What It Unlocks |
|---------|-------|----------|-----------------|
| Near-term | C3c | 1-2 | Committees can sign things |
| Mid-term | D1-D3, E1-E2 | 12-17 | Multi-node with real VMs |
| Parallel | F1-F2, G1-G2 | 7-11 | Production-grade infra |
| Late-stage | H1, I1-I2 | 9-14 | Bridge E2E + Identity |
| **Total** | **13 specs** | **~25-35 (interleaved)** | **Feature-complete protocol** |

---

## Open Architectural Decisions

These must be resolved during brainstorming, before their respective specs:

| # | Decision | Affects | Candidates | Leaning |
|---|----------|---------|------------|---------|
| 1 | Consensus protocol family | D1 | HotStuff / Tendermint / Mysticeti | Mysticeti (GSX alignment) |
| 2 | P2P library | D2 | libp2p / gRPC / custom | libp2p |
| 3 | Message serialization | D1, D2 | protobuf / CBOR / SSZ | protobuf or SSZ |
| 4 | MoveVM variant | E2, I1 | Aptos / Sui / independent | Aptos Move (recommended) |
| 5 | EVM execution client | E1 | geth / reth / erigon | reth (Rust, performance) |
| 6 | State storage backend | E1, E2 | LevelDB / RocksDB / custom | RocksDB |
| 7 | PQC library | F1 | liboqs / OpenSSL 3.x PQC / vendor | liboqs |
| 8 | HSM standard | F2 | PKCS#11 / cloud KMS / both | Both (PKCS#11 + cloud KMS) |
| 9 | Cloud provider primary | G1 | AWS / GCP / multi-cloud | AWS (KMS backend exists) |
| 10 | ZK prover for production | H1 | SP1 / RISC Zero / native STARK | Native STARK (already built) |

---

## Honest Caveats

1. **Not all sessions are equal.** C3b was fast because the decisions were already made — Pedersen DKG, BLS12-381, the math is well-known. Transport (D1-D3) involves decisions that can't be speed-run. Picking the wrong consensus protocol means rework.

2. **External dependencies slow things down.** E1 needs a running EVM node. E2 needs a MoveVM binary. F1 needs evaluating real FIPS libraries. These involve setup and testing outside our session loop.

3. **The parallel tracks help.** F1, F2, G1, G2 can run concurrently with D1-D3. If we interleave, the wall-clock count drops from ~35 sessions to maybe ~25.

4. **Identity (I1 + I2) is the wildcard.** The DID Expansion Plan is 892 lines and four internal phases. That's practically a project within a project.

5. **Gate 6 is the existential test.** When consensus + DKG + federation work across real nodes on the GSX devnet, the protocol is proven viable as a distributed system. Everything before Gate 6 runs single-process. Everything after it is multi-node. If Gate 6 fails, the architecture needs fundamental rethinking.

6. **Mainnet is not in this roadmap.** This roadmap ends at feature-complete. Mainnet deployment is a separate gate with its own security audit, load testing, and regulatory review requirements.

---

## Projected Final State

| Metric | Current | Projected |
|--------|---------|-----------|
| Python modules | 202 | ~250+ |
| Total tests | 3,530 | ~4,400+ |
| Specs completed | 13 | 26 |
| Live deployments | 2 (testnet) | Testnet + mainnet candidate |
| Node mode | Single-process | Multi-node distributed |
| Identity | None | W3C DID Core 1.0 compliant |
| FIPS compliance | Software-only | Hardware-backed, FIPS 140-3 |
| Cross-chain | Components only | Live bridge with fraud proofs |

---

## Document Sequencing

Each spec follows the established cycle: **Brainstorm -> Design Spec -> Implementation Plan -> Subagent-Driven Execution -> Gate Check**.

```
This Roadmap (reference)
│
├── Spec C3c: Threshold BLS Signing         ← START HERE
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

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Consensus protocol selection delays | High | Blocks all of Phase 6 | Align with GSX mainnet direction (greth + Mysticeti) early |
| MoveVM variant decision deferred | High | Blocks E2 and I1 | Aptos Move recommended; decide before E1 completes |
| FIPS-certified PQC libraries immature | Medium | F1 scope unclear | liboqs is available; assess OpenSSL 3.x PQC module status |
| SP1/RISC Zero prover performance | Medium | H1 latency concerns | Native STARK prover already built; benchmark before committing |
| Transport library selection | High | Architectural lock-in | Prototype with libp2p; keep transport protocol abstract |
| DID plan scope creep | Medium | I2 becomes unbounded | 4-phase internal gating already defined |
| Cross-chain finality assumptions | Medium | Bridge E2E fragile | Test against real reorgs on testnets before mainnet |
| Gate 6 failure | Low | Fundamental rethink | Strong local test coverage de-risks; 3-node devnet is the proving ground |
| HSM vendor lock-in | Low | F2 portability | PKCS#11 standard interface; cloud KMS as fallback |
| Session estimate drift | Medium | Timeline slips | Track actual vs. estimated per spec; adjust future estimates |
