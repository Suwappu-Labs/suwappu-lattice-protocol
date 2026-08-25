# LTP Session Roadmap — Current State to Feature-Complete

**Author:** Suwappu (SUWAPPU)
**Date:** May 11, 2026
**Last verified against the tree:** August 25, 2026 (at `28ce733`)
**Purpose:** Session-aware execution roadmap mapping every remaining spec to concrete work sessions, with dependency chains, complexity ratings, and honest caveats. Living document — update as gates are cleared.

> **Revision note (2026-08-25).** Between 2026-05-12 and 2026-08-25 this file
> was edited twice, both times by mechanical rebrands (`ETP` → `LTP`,
> `GSX` → `Suwappu`); its content had not been revised since it was written.
> This pass re-checks every claim against the tree and marks what has since
> shipped. Where a spec has landed, the original estimate is kept alongside the
> outcome rather than deleted — the estimate-vs-actual record is the point.
>
> Two newer plans now carry the detail this document only sketches, and should
> be read with it:
> [`2026-08-04-external-validator-onboarding.md`](2026-08-04-external-validator-onboarding.md)
> (D2/D3 restated as concrete blockers B1–B7) and
> [`2026-08-16-research-round.md`](2026-08-16-research-round.md)
> (cryptographic backlog). Sprint-level tracking lives in Linear
> (team `GLO`, project **LTP Dev Net**), not in this repo.
>
> **Gate numbering caveat.** This document numbers gates
> 5=C3c, 6=D1–D3, 7=E1–E2, 8=F/G, 9=H1, 10=feature-complete.
> [`2026-05-15-gate-5-6-closure.md`](2026-05-15-gate-5-6-closure.md), written
> four days later, numbers them 7=Transport, 8=Execution, 9=Production
> hardening — an off-by-one against this file from Gate 7 onward. The two
> schemes have never been reconciled; cite the document alongside the gate
> number.

---

## Project Snapshot

| Metric | May 11, 2026 | August 25, 2026 |
|--------|-------------:|----------------:|
| Python modules (`src/`) | 202 | 255 |
| Python test functions | 3,349 | 3,940 |
| Solidity test / invariant functions | 181 | 356 |
| **Total** | **3,530** | **4,296** |
| Source subpackages (`src/ltp/*/`) | 20 | 18 |
| Lean 4 theorems (machine-checked) | — | 53 |
| Live deployments | 2 (SUWAPPU Testnet v5, Base Sepolia v6) | 2 (unchanged; v7 pending) |
| Completed specs | 13 (A through C3b) | 17 (A through C3c, D1a–D1c) |
| Total commits | 95 | 350 |

**How the August figures were produced.** Static counts — `def test_` for
Python, `function test/invariant/echidna` for Solidity — not a `pytest`
collection or a `forge` run; neither toolchain was available in the
environment where this pass was made. For comparison, `README.md` reports
4,033 *collected* Python tests and 339 Solidity functions; parametrized cases
explain most of that gap.

**Do not subtract the two columns.** The May figures were reported as
collected counts, so the columns are not measured the same way — the movement
is indicative, not an exact delta. The subpackage count fell from 20 to 18
through consolidation, not through loss of capability.

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
| Threshold BLS signing (C3c) | `execution/committee/dkg/threshold_signing.py` | — | **SHIPPED** since May — `partial_sign`, `combine_partial_signatures`, `threshold_verify` |
| DAG-BFT consensus (D1a–D1c) | `consensus/` (14 modules), `consensus/adapter.py::DagBftAdapter` | — | **SHIPPED** since May — real `ConsensusAdapter` over `LocalConsensusBackend` |
| EVM execution over JSON-RPC (E1) | `execution/executors/evm.py::JsonRpcEVMBackend` | — | **SHIPPED** since May — replaced the hash-rolling stub |
| Corridor attestation (7-of-9) | `corridor/` (13 modules) | — | **PROVEN** — digest parity locked against the Rust reference |
| Machine-checked proofs | `formal/lean/` (12 files) | 53 theorems | **PROVEN** — `sorry`-free, CI-gated |

### Deployed On-Chain

| Contract | SUWAPPU Testnet (v5) | Base Sepolia (v6) |
|----------|------------------|-------------------|
| LTPAnchorRegistry (UUPS) | `0xB29d...` | `0x79eF...` |
| LTPMultiSig (2-of-2) | `0x0106...` | `0x4c32...` |
| TimelockController | `0x7C26...` | `0xc915...` |
| BridgeEmitter | — | Deployed |
| OptimisticBridgeChallenge | — | Deployed |
| ZKBridgeVerifier | — | Deployed |

Governance path proven: MultiSig (2-of-2) -> Timelock (60s) -> Registry. Version bumps verified on-chain through 6 iterations.

**Unchanged as of 2026-08-25, and this is the single most consequential open
item in the repo.** The v7 governance-hardening changes (audit findings
LTP-A-002, -005, -006, -007, -009, -017, -018, -030) are `FIXED-IN-SOURCE`
and **not deployed**. Until v7 ships, the live Base Sepolia deployment keeps
a 2-of-2 MultiSig, a 60-second Timelock, and — per
[`../BRIDGE_TRUST_MODEL.md`](../BRIDGE_TRUST_MODEL.md) §2 — a
`ZKBridgeVerifier` in `MODE_SIMULATED`, whose "proof" is a keccak256 tag over
caller-chosen inputs. `lockProduction()` does not exist on the deployed
contract, so that fast path cannot be locked out before the upgrade. See
[`../DEPLOYED_CONTRACTS.md`](../DEPLOYED_CONTRACTS.md) §"v7 Governance
Hardening". Per `CLAUDE.md`, the upgrade needs a plan under `docs/plans/` and
`make contracts-secaudit` green before any contract change is proposed.

---

## What's Still Theoretical

Re-verified against the tree on 2026-08-25. Four rows have closed; the rest
stand, several with sharper detail than the original entry.

| Component | State (2026-08-25) | What's Missing |
|-----------|--------------------|----------------|
| ~~Threshold BLS signing~~ | **CLOSED** — `threshold_signing.py` | — |
| ~~Consensus~~ | **CLOSED** — `DagBftAdapter` over `LocalConsensusBackend`. `FakeConsensusAdapter` still ships as a test double | Distributed operation, which is D2's problem, not D1's |
| **P2P networking** | **OPEN, and the hardest item on this list.** `dkg/transport.py` holds a `DKGTransport` Protocol and `FakeDKGTransport`, which passes messages through Python lists | No network implementation at all — **threshold DKG cannot run between two machines**. `HTTPFederationTransport` exists for federation, so that half is partly closed; the DKG half is not |
| ~~EVM executor~~ | **CLOSED** — `JsonRpcEVMBackend` | Integration testing against a live client |
| **Move executor** | **OPEN** — `MoveBackend` is a `Protocol` with zero implementations; `FakeMoveBackend` now lives only in `tests/` | The named production target `MysticetiGrpcBackend` does not exist |
| ~~Ed25519 composite~~ | **CLOSED** — real `pynacl` signing (commit `b4897cf`) | — |
| **HSM** | **OPEN, unchanged** — `SoftwareHSM` only; `hsm.py:42` still marks `PKCS11HSM` "not yet implemented" | PKCS#11 or cloud-KMS hardware binding |
| **Cloud backends** | **OPEN, unchanged** — `InMemoryQueue`, `InMemoryScheduler`, `InMemoryOrchestrator`, `InMemoryBackupManager`; `AWSKMSBackend` remains the lone real one | Real service bindings for the other four |
| **Federation HTTP** | **OPEN, unchanged** — `federation.py:538` still `signature=b""  # placeholder`, and `:1099` the same for `responder_signature` | Real NIR signing |
| **Bridge E2E** | **OPEN, advanced** — `bridge/live.py` and `scripts/bridge_live.py` now exist | Still never exercised against live finality, reorgs, or gas |
| **DID / Identity** | **OPEN, partly started** — `corridor/did_doc.py` and `corridor/did_stark.py` implement a DID document model and rotation-proof surface. The original "zero implementation" is no longer true | The W3C `did:ltp` method, VC issue/present/verify, and the 4-phase rollout (I1/I2) are untouched |
| **Mainnet deployment** | **OPEN, unchanged** — scripts exist, no `broadcast/` artifacts anywhere in `contracts/` | An actual deploy |
| **On-chain node registry** | **OPEN — newly surfaced.** `backends/ethereum.py:17,:513` documents and simulates `LTPNodeRegistry.sol`; no such contract exists in `contracts/src/` | The contract, plus real staking (`min_stake_wei` defaults to 0) |
| **Admission / committees as services** | **OPEN — newly surfaced.** `NodeAdmissionManager` and `WriterRegistry` are instantiated nowhere in `src/`, only in tests; `node/main.py` references neither | Persistence, an applicant-facing endpoint, and a shared view across nodes |

---

## Spec-by-Spec Execution Plan

### Spec Sizing Matrix

| Spec | Status (2026-08-25) | Tasks | Sessions (est.) | Complexity | Blocking Decision |
|------|---------------------|-------|-----------------|------------|-------------------|
| C3c | ✅ **DONE** | 5-7 | 1-2 | Low — well-defined, no open decisions | None |
| D1 | ✅ **DONE** — shipped as D1a/D1b/D1c | 10-14 | 3-4 | High — consensus protocol selection required | ✅ Resolved: DAG-BFT, Mysticeti-inspired |
| D2 | ⬜ **OPEN — critical path** | 10-14 | 3-4 | High — P2P architecture, encryption | ⬜ Open: P2P library, serialization format |
| D3 | ⬜ **OPEN** | 7-10 | 2-3 | Medium | None (builds on D2 patterns) |
| E1 | ✅ **DONE** | 7-10 | 2-3 | Medium — but needs real EVM node | ✅ Resolved by construction: client-agnostic JSON-RPC |
| E2 | ⬜ **OPEN** | 7-10 | 2-3 | Medium — MoveVM variant decision blocks | 🟡 Leaning Sui — code names `MysticetiGrpcBackend`, not built |
| F1 | ⬜ **OPEN** | 7-10 | 2-3 | Medium — library evaluation | ⬜ Open: PQC library (liboqs / OpenSSL 3.x PQC / vendor) |
| F2 | ⬜ **OPEN** | 5-8 | 2 | Medium | ⬜ Open: HSM standard (PKCS#11 / cloud KMS / both) |
| G1 | ⬜ **OPEN** | 8-12 | 2-3 | Low — mechanical swaps | 🟡 Leaning AWS — `AWSKMSBackend` is the only real binding |
| G2 | ⬜ **OPEN** | 4-6 | 1-2 | Low | None |
| H1 | ⬜ **OPEN, advanced** | 8-12 | 2-3 | Medium — needs D2 + E1 working | ⬜ Open: ZK prover for production |
| I1 | ⬜ **OPEN, partly started** | 12-16 | 3-5 | High — architecture decisions, existing .docx spec | ⬜ Open: Move DID registry design |
| I2 | ⬜ **OPEN** | 15-20 | 4-6 | High — 892-line plan exists but needs conversion | ⬜ Open: 4-phase DID rollout scoping |
| **Remaining** | **9 of 13 specs open** | **~72-100** | **~19-27 sessions** | | **7 open decisions (3 resolved)** |

**Estimate-vs-actual.** The four closed specs (C3c, D1, E1, plus the C3a/C3b
work that preceded them) were estimated at 9–13 sessions and are done. No
per-session actuals were recorded, so the remaining estimates have not been
recalibrated — treat them as the original author's figures, not as validated
throughput.

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

**Gate 5 Criteria:** — ✅ **CLOSED.** Declared closed by
[`2026-05-15-gate-5-6-closure.md`](2026-05-15-gate-5-6-closure.md)
("closed at the in-process integration surface").

- [x] `partial_sign()` + `combine_partial_signatures()` produces valid BLS signature
- [x] `threshold_verify()` accepts t-of-n partial sigs, rejects t-1
- [x] `CommitteeManager.tick()` produces threshold-signed attestations when DKG result exists
- [x] Existing tests still pass — per the closure doc and CI; **not** re-run for this revision pass

**Risk:** Low — borne out. The estimate held.

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

| Option | Pros | Cons | SUWAPPU Alignment |
|--------|------|------|---------------|
| Mysticeti (Sui DAG-BFT) | Sub-second latency, DAG parallelism | Newer, less battle-tested | greth + Mysticeti spike referenced in Gateway VM Plan |
| HotStuff / HotStuff-2 | Well-studied, linear communication | Higher latency than DAG | Standard choice |
| Tendermint/CometBFT | Mature ecosystem, Cosmos tooling | 2-round latency, older design | Less aligned with SUWAPPU direction |

**Recommendation:** Mysticeti, aligned with SUWAPPU mainnet direction. Prototype in D1 with fallback abstraction.

**✅ DELIVERED** — shipped as three sub-specs (D1a, D1b, D1c). The decision
went to a **Mysticeti-inspired DAG-BFT**, implemented in-repo as
`consensus/engine.py::LocalDagBftEngine` with `consensus/adapter.py::DagBftAdapter`
as the real `ConsensusAdapter`. Class names were deliberately renamed away from
"Mysticeti" (commit `86e21c0`) to avoid implying shared lineage or endorsement;
`consensus/__init__.py` documents the attribution to arXiv:2310.14821.
`FakeConsensusAdapter` is retained as a test double, not as the default.

Note the boundary: the backend is `LocalConsensusBackend` — consensus is real
but **single-process**. Making it distributed is D2's job, not a D1 gap.

#### D2: P2P Encrypted Transport (10-14 tasks, 3-4 sessions)

**Open decisions:** P2P library, message serialization.

| Decision | Options | Leaning |
|----------|---------|---------|
| P2P library | libp2p / gRPC / custom | libp2p (peer discovery built-in, Noise/QUIC encryption) |
| Serialization | protobuf / CBOR / SSZ | protobuf (ecosystem maturity) or SSZ (Ethereum alignment) |

**⬜ OPEN — this is now the single highest-leverage unstarted spec.** With D1
and E1 closed, D2 is the head of the remaining critical path, and
[`2026-08-04-external-validator-onboarding.md`](2026-08-04-external-validator-onboarding.md)
independently reaches the same conclusion from the operator side, calling its
transport blocker (B4) "the hardest blocker and the one most likely to be
underestimated."

Verified 2026-08-25: `dkg/transport.py` contains a `DKGTransport` Protocol and
`FakeDKGTransport` passing messages through Python lists — no network
implementation exists. The federation half has moved: `HTTPFederationTransport`
(`federation_http.py`) is real, though `InMemoryFederationTransport` remains
the test default and the NIR signature is still a `b""` placeholder.

What the transport actually has to provide, per the onboarding plan:
authenticated, ordered, **per-recipient private** delivery of shares, plus
broadcast for commitments and complaints. That is more than a socket.

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

**✅ DELIVERED** (commit `038f314`). `execution/executors/evm.py` now carries a
`JsonRpcEVMBackend` alongside the `InMemoryEVMBackend` default, so
`EVMExecutor` reaches a real chain when constructed with one. The client
decision (geth / reth / erigon) was resolved by construction rather than by
choosing: the backend speaks plain JSON-RPC and is client-agnostic.

**Still owed:** integration testing against a live client. The
`InMemoryEVMBackend` remains the zero-argument default for backward
compatibility, so a caller that constructs `EVMExecutor()` still gets a
simulation — a trap worth closing before this is called finished.

#### E2: Move Executor Backend (7-10 tasks, 2-3 sessions)

**Open decision:** MoveVM variant (Aptos Move / Sui Move / independent).
**External dependency:** Requires MoveVM binary.

**⬜ OPEN.** Verified 2026-08-25: `execution/executors/move.py` defines a
`MoveBackend` `Protocol` and nothing that implements it. `FakeMoveBackend` has
moved out of `src/` and now exists only in `tests/test_execution_move.py`.

The variant decision has drifted rather than been made: the module docstring
names Sui Move and a production `MysticetiGrpcBackend`, while the roadmap's
decision table (#4 below) still recommends Aptos. **These contradict each
other and neither is implemented.** Resolve the contradiction before scoping.

**Delivers:**
- Real `MoveExecutor` via gRPC or embedded runtime
- Move resource operations through `TransactionRouter`

**Gate 6 Criteria (after D1-D3):** — 🟡 **PARTIALLY CLOSED.**
[`2026-05-15-gate-5-6-closure.md`](2026-05-15-gate-5-6-closure.md) declares
Gate 6 closed *"at the in-process integration surface"* and explicitly defers
live multi-machine deployment. Against the criteria as written here:

- [x] N nodes reach agreement on ordered blocks — **in one Python process**
- [ ] Full DKG ceremony completes over real P2P with ML-KEM encrypted shares — blocked on D2
- [ ] Nodes find peers and establish connections — blocked on D3
- [x] Cross-node federation messages delivered reliably — `HTTPFederationTransport` exists; NIR signature still a placeholder
- [ ] **Deploy 3+ node testnet on SUWAPPU devnet** — not done. `suwappu.network` did not resolve when checked on 2026-08-04, and every seed endpoint in the repo is a placeholder (onboarding plan B1)

The honest reading: consensus is proven as an algorithm and unproven as a
distributed system. The existential question this gate was designed to answer
(caveat 5 below) is still open.

**Gate 7 Criteria (after E1-E2):** — 🟡 **HALF MET.**
- [x] Real EVM state changes via JSON-RPC — E1 shipped
- [ ] Real Move resource operations — blocked on E2; no `MoveBackend` implementation exists
- [x] TransactionRouter dispatches to correct backend
- [ ] State root aggregates across live VMs — needs both VMs live

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

The graph below is the original May 11 plan, left as drawn. Status as of
2026-08-25 follows it.

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

**Status against that graph (2026-08-25):**

| Node | Status |
|---|---|
| C3c Threshold Signing | ✅ shipped |
| D1 Consensus Protocol | ✅ shipped as D1a / D1b / D1c |
| **D2 P2P Encrypted Transport** | ⬜ **open — critical-path head** |
| D3 Node Discovery | ⬜ open (blocked by D2) |
| E1 EVM Executor Backend | ✅ shipped — came off the critical path early |
| E2 Move Executor Backend | ⬜ open (variant decision contradictory) |
| H1 Bridge E2E | ⬜ open, advanced — now gated on D2 alone |
| I1 / I2 DID | ⬜ open; corridor DID surface exists, `did:` method does not |
| F1 / F2 / G1 / G2 | ⬜ all open, all still parallelizable |

---

## Critical Path

Longest dependency chain determines minimum session count:

Original (May 11) — the first three links are now closed:

```
C3c ──► D1 ──► D2 ──► D3 ──► E1 ──► E2 ──► I1 ──► I2
 1-2    3-4    3-4    2-3    2-3    2-3    3-5    4-6   = 21-30 sessions on critical path
 DONE   DONE                 DONE
```

Remaining as of 2026-08-25 — E1 came off the chain early, so **D2 is now the
head**:

```
D2 ──► D3 ──► E2 ──► I1 ──► I2
3-4    2-3    2-3    3-5    4-6   = 15-21 sessions on critical path
```

Parallel tracks (all still open, none blocked by D2):
- F1 -> F2: 4-6 sessions
- G1 -> G2: 3-5 sessions
- H1: 2-3 sessions (D2 + E1 — E1 is done, so H1 is gated on D2 alone)

**With interleaving, ~15-20 sessions remain.** This assumes the original
estimates hold; see the estimate-vs-actual note in the sizing matrix.

**Not on this chain, and more urgent than any of it:** the v7 contract deploy.
It is not a spec in this roadmap, carries a live CRITICAL finding
(LTP-A-007), and blocks nothing here — which is exactly why it is easy to
leave sitting.

---

## Horizon Summary

| Horizon | Specs | Status | Sessions left | What It Unlocks |
|---------|-------|--------|---------------|-----------------|
| Near-term | C3c | ✅ done | 0 | Committees can sign things |
| Mid-term | D1-D3, E1-E2 | 🟡 D1, E1 done; D2, D3, E2 open | 7-10 | Multi-node with real VMs |
| Parallel | F1-F2, G1-G2 | ⬜ all open | 7-11 | Production-grade infra |
| Late-stage | H1, I1-I2 | ⬜ open (H1 advanced, I1 partly started) | 9-14 | Bridge E2E + Identity |
| **Total** | **4 of 13 specs done** | | **~15-20 (interleaved)** | **Feature-complete protocol** |

---

## Open Architectural Decisions

These must be resolved during brainstorming, before their respective specs:

Three of the ten have been settled by shipped code. Status re-checked 2026-08-25.

| # | Decision | Affects | Status | Outcome / Leaning |
|---|----------|---------|--------|-------------------|
| 1 | Consensus protocol family | D1 | ✅ **RESOLVED** | DAG-BFT, Mysticeti-inspired (arXiv:2310.14821), names distanced per `86e21c0` |
| 2 | P2P library | D2 | ⬜ **OPEN — blocks the critical path** | libp2p |
| 3 | Message serialization | D1, D2 | ⬜ **OPEN** | protobuf or SSZ. Note `proto/etp_execution.proto` and the gRPC surface in `network/` already commit to protobuf in practice |
| 4 | MoveVM variant | E2, I1 | ⚠️ **CONTRADICTORY** | This table says Aptos; `executors/move.py` says Sui + `MysticetiGrpcBackend`. Neither is built. Must be reconciled before E2 |
| 5 | EVM execution client | E1 | ✅ **RESOLVED by construction** | Client-agnostic JSON-RPC — no single client chosen, and none needs to be |
| 6 | State storage backend | E1, E2 | ⬜ **OPEN** | RocksDB. `storage/` currently offers SQLite (WAL), filesystem, and memory stores |
| 7 | PQC library | F1 | ⬜ **OPEN** | liboqs. Today: `pqcrypto` + `pynacl`, real but not FIPS-validated builds |
| 8 | HSM standard | F2 | ⬜ **OPEN** | Both (PKCS#11 + cloud KMS) |
| 9 | Cloud provider primary | G1 | 🟡 **DE FACTO AWS** | `AWSKMSBackend` is the only real binding; never ratified as a decision |
| 10 | ZK prover for production | H1 | ⚠️ **DRIFTING** | Leaning was native STARK; `zkvm/` carries both SP1 and RISC Zero hosts and SP1 was upgraded 4.0 → 6.3.1 in `c50d2eb`. Meanwhile the *deployed* verifier is in `MODE_SIMULATED` — no prover at all |

---

## Honest Caveats

1. **Not all sessions are equal.** C3b was fast because the decisions were already made — Pedersen DKG, BLS12-381, the math is well-known. Transport (D1-D3) involves decisions that can't be speed-run. Picking the wrong consensus protocol means rework.

2. **External dependencies slow things down.** E1 needs a running EVM node. E2 needs a MoveVM binary. F1 needs evaluating real FIPS libraries. These involve setup and testing outside our session loop.

3. **The parallel tracks help.** F1, F2, G1, G2 can run concurrently with D1-D3. If we interleave, the wall-clock count drops from ~35 sessions to maybe ~25.

4. **Identity (I1 + I2) is the wildcard.** The DID Expansion Plan is 892 lines and four internal phases. That's practically a project within a project.

5. **Gate 6 is the existential test — and it is still unanswered.** When
   consensus + DKG + federation work across real nodes on the SUWAPPU devnet,
   the protocol is proven viable as a distributed system. Everything before
   Gate 6 runs single-process. Everything after it is multi-node. If Gate 6
   fails, the architecture needs fundamental rethinking.

   **Status 2026-08-25:** Gate 6 was declared closed *at the in-process
   surface* on 2026-05-15, which is real progress but is not what this caveat
   was asking. Threshold DKG still cannot run between two machines, and
   `suwappu.network` did not resolve when checked on 2026-08-04. Three months
   on, the question this gate exists to answer has not been put to the test.
   Nothing downstream should be read as de-risked by the partial closure.

6. **Mainnet is not in this roadmap.** This roadmap ends at feature-complete. Mainnet deployment is a separate gate with its own security audit, load testing, and regulatory review requirements.

---

## Projected Final State

| Metric | May 11 | **Now (Aug 25)** | Projected |
|--------|--------|------------------|-----------|
| Python modules | 202 | **255** | ~250+ — *reached* |
| Total tests | 3,530 | **4,296** | ~4,400+ — nearly reached |
| Specs completed | 13 | **17** | 26 |
| Live deployments | 2 (testnet) | **2 (testnet), v7 pending** | Testnet + mainnet candidate |
| Node mode | Single-process | **Single-process** | Multi-node distributed |
| Identity | None | **Corridor DID doc + rotation proofs; no `did:` method** | W3C DID Core 1.0 compliant |
| FIPS compliance | Software-only | **Software-only** | Hardware-backed, FIPS 140-3 |
| Cross-chain | Components only | **Components + live runner; deployed verifier is `MODE_SIMULATED`** | Live bridge with fraud proofs |

The two projections already met are both *volume* measures — modules and
tests. Every structural one — node mode, FIPS posture, identity, cross-chain —
is where it was in May. Worth noticing which kind of progress the last three
months produced.

---

## Document Sequencing

Each spec follows the established cycle: **Brainstorm -> Design Spec -> Implementation Plan -> Subagent-Driven Execution -> Gate Check**.

```
This Roadmap (reference)
│
├── Spec C3c: Threshold BLS Signing         ✅ DONE
│       ↓
├── Spec D1: Consensus Protocol             ✅ DONE (D1a/D1b/D1c)
├── Spec D2: P2P Encrypted Transport        ← START HERE
├── Spec D3: Node Discovery
│       ↓
├── Spec E1: EVM Executor Backend           ✅ DONE
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

Re-scored 2026-08-25.

| Risk | Likelihood | Impact | Mitigation / status |
|------|-----------|--------|---------------------|
| ~~Consensus protocol selection delays~~ | ✅ **Retired** | — | Resolved: DAG-BFT shipped as D1a–D1c |
| MoveVM variant decision deferred | **High — materialized** | Blocks E2 and I1 | Not made, and the docs now contradict each other (Aptos vs Sui). Deferred past E1 exactly as feared |
| FIPS-certified PQC libraries immature | Medium | F1 scope unclear | Unchanged. liboqs available; OpenSSL 3.x PQC status unassessed |
| SP1/RISC Zero prover performance | Medium | H1 latency concerns | Unchanged — but the deployed-verifier risk below dominates it |
| Transport library selection | **High — now the top risk** | Architectural lock-in | Unchanged and unstarted. D2 is the critical-path head; it cannot be interleaved around forever |
| DID plan scope creep | Medium | I2 becomes unbounded | Unchanged; 4-phase gating still the mitigation |
| Cross-chain finality assumptions | Medium | Bridge E2E fragile | Unchanged. `bridge/live.py` exists but has never met a real reorg |
| Gate 6 failure | **Low → Unknown** | Fundamental rethink | Cannot be scored: the multi-node test that would produce evidence has not been run. Scoring it "Low" on in-process coverage is the mistake to avoid |
| HSM vendor lock-in | Low | F2 portability | Unchanged |
| Session estimate drift | Medium | Timeline slips | **Materialized silently** — no per-session actuals were recorded, so drift is unmeasurable |
| **Deployed verifier accepts forged proofs** | **Certain — live now** | Bridge trust collapses to "anyone" | *New.* LTP-A-007: Base Sepolia `ZKBridgeVerifier` in `MODE_SIMULATED`, fixed in source, undeployed. Ship v7 |
| **Roadmap drifts from reality again** | Medium | Planning on stale facts | *New.* This file went 105 days without a content revision while labelled a living document. Re-verify at each gate close |
