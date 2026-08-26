> **Superseded** — archived 2026-05-15. Original "Planning" status from April 2026; no implementation work has landed. See [`docs/plans/2026-05-11-production-roadmap.md`](../2026-05-11-production-roadmap.md) for current scope.
> Retained for the DID design rationale; the referenced "Proposed MoveVM+DID Architecture" .docx is not in git.

---

# ETP DID Expansion Plan — Decentralized Identity via Lattice Transfer Protocol

**Author:** Suwappu (SUWAPPU)
**Date:** April 24, 2026
**Status:** Planning
**Scope:** `did:etp` method specification, DID/VC integration architecture, phased implementation roadmap, PQ-safe ZK cross-chain resolution path.
**Depends on:** [LTP Gateway VM Plan](LTP_GATEWAY_VM_PLAN.md) Phase 4 (dual VM introduction) and [Proposed MoveVM+DID Architecture](Proposed-MoveVM-DID.docx). This plan starts after MoveVM+DID work begins and is built in tandem.

---

## 1. Executive Summary

This document defines the plan for adding a Decentralized Identity (DID) layer to the Entanglement Transfer Protocol. The design extends ETP's existing post-quantum cryptographic primitives (ML-DSA-65, ML-KEM-768), commitment log, on-chain anchor registry, and federation protocol to support W3C DID Core 1.0 compliant identifiers and Verifiable Credentials.

The approach is phased:

| Phase | Target | Anchoring Model | DID Type |
|---|---|---|---|
| **Phase 1** | Cross-network federation credentials | Commitment Log primary (X-mode) | Federation network DIDs |
| **Phase 2** | Node/operator identity | Commitment Log primary (X-mode) | Node operator DIDs |
| **Phase 3** | Institutional user credentials + ZK cross-chain resolution | On-chain primary (Y-mode) | Institutional user DIDs |
| **Phase 4** | Retail user credentials | On-chain primary (Y-mode) | Individual user DIDs |

Each phase builds on the previous. Federation VCs prove the DID method works with machine-to-machine trust. Node DIDs extend it to individual participants. User DIDs extend it to the broadest audience. PQ-safe ZK proofs (built on ETP's existing STARK infrastructure) upgrade cross-chain resolution from relay-dependent to trustless.

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| DID Method | `did:etp:<network_id>:<identifier>` | Native to ETP primitives, W3C DID Core 1.0 compliant |
| Anchoring | Commitment Log first → On-chain primary later | Ships fast on existing infra, upgrades without breaking changes |
| DID Priority | Federation VCs → Node DIDs → User DIDs | Proves method at low scale, builds up |
| VM transition | EVM-only (Phase 1-2) → Dual VM EVM+MoveVM (Phase 3-4) | Solidity first on proven infra; Move resource model when dual VM is ready |
| Consensus integration | Contract now, precompile later (3C) | EVM contract first, chain-level enforcement when Gravm/Mysticy ready |
| Contract architecture | Three-layer merge (2A + 2B + 2C) evolving to Move resources + EVM index | Defense-in-depth; Move resources enforce DID invariants at language level |
| Stale read mitigation | STH gating + gossip broadcast + on-chain events, tiered | Verifier chooses freshness policy per use case |
| DID update model | Full LTP COMMIT per update (Phase 1-2), two-tier evaluated Phase 3 | Preserves LTP immutability, no core protocol modifications |
| Fee model | Operator pays → subject pays → meta-tx → protocol fee | Matches phase progression from low-scale to high-scale |
| ZK cross-chain resolution | PQ-safe STARK proofs for trustless cross-chain DID state verification | Uses existing ETP STARK prover; vendor-agnostic architecture |

---

## 2. Background and Context

### 2.1 Current ETP Implementation State

As of April 2026, ETP comprises 250+ files, 2,726+ tests (all passing), and live bidirectional bridge operations on SUWAPPU Testnet (chain ID 103115120) and Base Sepolia (chain ID 84532). The system implements:

- **Real PQ cryptography**: ML-KEM-768/1024, ML-DSA-65/87, XChaCha20-Poly1305 (zero simulations)
- **Three-phase transfer lifecycle**: Commit → Lattice → Materialize with constant-size sealed keys (~1,300-1,442 bytes)
- **RFC 6962 commitment log**: Append-only Merkle tree with ML-DSA-65 signed tree heads
- **On-chain contracts**: LTPAnchorRegistry (UUPS proxy), LTPMultiSig, OptimisticBridgeChallenge, ZKBridgeVerifier — deployed on both chains
- **Live bridge**: 53 on-chain transactions, 8 verified anchor TXs, all 7 bridge phases exercised
- **Federation**: NIR discovery, mutual agreement protocol, cross-network shard fetching, rate limiting
- **Three bridge tiers**: Optimistic (7-day challenge), ZK (SP1/RISC Zero), STARK (FRI-based, PQ-safe)
- **API Gateway**: FastAPI with ML-DSA-65 JWT authentication, rate limiting, operational endpoints
- **Gossip peer discovery**: ML-DSA-65 signed peer exchange, anti-amplification, liveness timeout

**No DID layer exists yet.** This plan defines how to build one on these foundations.

### 2.2 Existing Primitives That Map to DID Concepts

| DID Concept | Existing ETP Primitive | Location |
|---|---|---|
| DID Identifier | `EntityID` = `H(content \|\| shape \|\| ts \|\| vk)` | `src/ltp/protocol.py` |
| Verification Method | ML-DSA-65 VK | `src/ltp/primitives.py`, `KeyPair` |
| Key Agreement | ML-KEM-768 EK | `src/ltp/primitives.py`, `SealedBox` |
| DID Document storage | CommitmentLog (append-only, Merkle-proven) | `src/ltp/commitment.py` |
| DID Resolution | CT REST API + Federation fetch | `src/ltp/rest_server.py`, `src/ltp/federation.py` |
| Key Rotation | `KeyRotationManager` with predecessor chain | `src/ltp/keypair.py` |
| Revocation | On-chain state machine (`ANCHORED → DELETED`) | `contracts/src/LTPAnchorRegistry.sol` |
| Cross-chain resolution | LiveBridge + Federation NIR | `src/ltp/bridge/live.py`, `src/ltp/federation.py` |
| Network Identity | `NetworkIdentityRecord` (NIR) | `src/ltp/federation.py` |
| Bilateral trust | `FederationAgreement` (ML-DSA-65 signed) | `src/ltp/federation.py` |
| Trust tiers | `FederationRegistry` (UNTRUSTED → VERIFIED → FEDERATED) | `src/ltp/federation.py` |

### 2.3 Cross-Chain ZK Resolution — ETP STARK Approach

The Y-mode cross-chain DID resolution requires trustless proof of source chain state on a destination chain. ETP already has the infrastructure for this.

**ETP's STARK prover is PQ-safe end-to-end.** The `STARKBridgeProver` uses FRI + Goldilocks field (p = 2^64 - 2^32 + 1) + SHA3-256 Merkle tree commitment — no pairings, no elliptic curves, fully hash-based at both the proving and verification layers. This prover is already tested, integrated with `ZKBridgeVerifier`, and deployed on both chains. It is the foundation for cross-chain DID resolution.

**Cross-chain DID resolution architecture:**

| Pattern | Application to DID |
|---|---|
| Mirror contracts | Mirror `ETPDIDRegistry` state across chains with STARK proof of source validity |
| Untrusted relayer | Relayer transports DID state + proofs; cannot forge or redirect (extends existing `LiveBridge` model) |
| State conservation | Every DID pointer update on destination chain backed by valid source chain state |
| Proof-verified sync | Destination chain verifies STARK proof on-chain before accepting DID state |

**PQ security chain (end-to-end, no external dependencies):**
- DID Document signed with ML-DSA-65 (FIPS 204, PQ-safe)
- Cross-chain state proven via ETP STARK (FRI + Goldilocks + SHA3-256, PQ-safe)
- On-chain verification via hash comparison (SHA3-256, PQ-safe)
- No pairings, no elliptic curves, no SNARK compression in the critical path

**Related work:** The entangled rollup pattern (see References) describes a similar cross-chain state mirroring approach for asset transfers using SNARK-compressed proofs for on-chain verification. ETP's approach differs by keeping STARK verification on-chain directly, preserving PQ safety end-to-end. External zkVM backends remain future options if they add PQ-safe on-chain verification paths.

### 2.4 Team Call Notes — Key Constraints (April 2026)

The following constraints were established during a team architecture call:

**Consensus Architecture:**
- Two-ring consensus model: POS validators order transactions, POA nodes seal blocks
- Mysticy uses DAG for execution parallelism (not consensus). Gravm runs single-node execution
- Parallel execution groups transactions by storage access dependencies for concurrent processing (batch time: ~60ms vs ~500ms sequential)
- Separate communication channels for block gossiping and consensus sealing

**DID-Specific Constraints:**
- DIDs are formatted strings containing prefixes and hashes representing identity sources
- DIDs can map to identifiers like Ethereum addresses with associated cryptographic proofs
- DID data stored in account fields on-chain, either initialized or left empty
- Must handle nil pointers for empty DID fields to conform with RLP encoding standards
- LTP messages are immutable and timestamped uniquely — mutable DID pointers are problematic
- Team proposed a persistent writable key in LTP pointing to latest DID packets (addressed via version chain pattern in this plan)
- Synchronization delays can cause nodes to read stale DID data before updates propagate
- Supernodes (e.g., central banks) create and commit DID data
- Validators must sign off on and validate DID assurances
- Must align with W3C DID 1.0 and relevant regulatory standards

**LTP Limitations Acknowledged:**
- LTP does not natively support mutable state or writable keys
- Cross-chain DID updates require complex synchronization and propagation strategies
- Practical prototype (Javier's implementation) diverges from theoretical whitepaper assumptions — prioritize prototype-based insights over speculative theory
- Modifying LTP for writable fields may introduce consensus and propagation issues
- Current LTP design favors immutable, append-only data flows (this plan preserves that)

**VM Decision:**
- Single VM (EVM) for Phases 1-2, transitioning to dual VM (EVM + MoveVM) for Phases 3-4
- The [LTP Gateway VM Plan](LTP_GATEWAY_VM_PLAN.md) Phase 4 introduces MoveVM as the identity execution environment
- The [Proposed MoveVM+DID Architecture](Proposed-MoveVM-DID.docx) defines the Move DID registry module, resource model, and writer permissioning
- Phases 1-2 DID contracts use Solidity 0.8.24, UUPS proxy pattern, existing deployment conventions
- Phases 3-4 DID operations migrate to Move resources with EVM contracts serving as index/cache via precompile reads

---

## 3. DID Method Specification: `did:etp`

### 3.1 Syntax

```
did:etp:<network_id>:<identifier>
```

- **`network_id`**: Derived from the NIR genesis STH hash. Distinguishes SUWAPPU Testnet, Base Sepolia, future mainnets. Human-readable aliases permitted (`suwappu-testnet`, `base-sepolia`) with canonical resolution to the full hash.
- **`identifier`**: SHA3-256 hash of the initial DID Document entity committed to the Commitment Log. Deterministic, collision-resistant, post-quantum safe. Prefixed with `sha3-256:` per the ETP dual-lane convention.

**Examples:**
```
did:etp:suwappu-testnet:sha3-256:a1b2c3d4e5f6...    (federation network DID)
did:etp:suwappu-testnet:sha3-256:f7e8d9c0b1a2...    (node operator DID)
did:etp:base-sepolia:sha3-256:1a2b3c4d5e6f...   (institutional user DID)
```

### 3.2 DID Document Schema

W3C DID Core 1.0 compliant with ETP-specific extensions:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://etp.suwappu.io/ns/did/v1"
  ],
  "id": "did:etp:suwappu-testnet:sha3-256:a1b2c3d4...",
  "controller": "did:etp:suwappu-testnet:sha3-256:f4e5d6a7...",
  "verificationMethod": [
    {
      "id": "#ml-dsa-65-key-1",
      "type": "MLDSA65VerificationKey2026",
      "controller": "did:etp:suwappu-testnet:sha3-256:a1b2c3d4...",
      "publicKeyMultibase": "z..."
    }
  ],
  "keyAgreement": [
    {
      "id": "#ml-kem-768-key-1",
      "type": "MLKEM768KeyAgreementKey2026",
      "controller": "did:etp:suwappu-testnet:sha3-256:a1b2c3d4...",
      "publicKeyMultibase": "z..."
    }
  ],
  "authentication": ["#ml-dsa-65-key-1"],
  "assertionMethod": ["#ml-dsa-65-key-1"],
  "service": [
    {
      "id": "#commitment-log",
      "type": "ETPCommitmentLog",
      "serviceEndpoint": "https://log.suwappu.io/ct/v1/"
    },
    {
      "id": "#federation-api",
      "type": "ETPFederationEndpoint",
      "serviceEndpoint": "https://fed.suwappu.io/federation/v1/"
    }
  ],
  "chainAnchors": [
    {
      "chainId": 103115120,
      "registry": "LTPAnchorRegistry",
      "contract": "0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4",
      "entityIdHash": "0x..."
    },
    {
      "chainId": 103115120,
      "registry": "ETPDIDRegistry",
      "contract": "0x...",
      "didPointer": "0x..."
    }
  ],
  "versionChain": {
    "sequence": 1,
    "predecessor": null,
    "commitmentRef": "sha3-256:...",
    "sthSequence": 42
  }
}
```

**Verification Method types**: `MLDSA65VerificationKey2026` and `MLKEM768KeyAgreementKey2026` are new W3C verification method types for FIPS 204 (ML-DSA-65) and FIPS 203 (ML-KEM-768). No registered type exists for these algorithms — ETP defines them in its DID context (`https://etp.suwappu.io/ns/did/v1`).

**`chainAnchors[]`**: Forward-compatible array listing on-chain anchor points. Both `LTPAnchorRegistry` and `ETPDIDRegistry` are listed. When STARK-based cross-chain resolution arrives (Y-mode), anchors gain a `zkProof` field — same schema, richer trust model. This field enables centralized exchanges to verify DID state against on-chain records.

**`versionChain`**: Solves the LTP immutability vs DID mutability tension. Each DID Document version is an immutable LTP entity. Updates produce a new entity with `sequence: N+1` and `predecessor: previous_entity_id`. The on-chain contract pointer tracks the HEAD. The `sthSequence` field enables stale read detection — a resolver verifies its local STH is at least this sequence number.

### 3.3 DID Operations

**Create:**
1. Generate ML-DSA-65 + ML-KEM-768 keypair (`KeyPair`)
2. Construct DID Document (JSON, schema above)
3. LTP COMMIT: serialize → erasure code → encrypt → distribute → sign → append to Commitment Log
4. On-chain: `LTPAnchorRegistry.anchor()` + `ETPDIDRegistry.createDID()`
5. DID identifier = SHA3-256 hash of the initial committed entity

**Update (key rotation, service endpoint change):**
1. Construct new DID Document with `versionChain.sequence += 1`, `predecessor = current_entity_id`
2. Sign with current (pre-rotation) ML-DSA-65 key
3. LTP COMMIT: full pipeline (new entity in Commitment Log)
4. On-chain: `ETPDIDRegistry.updatePointer()` (validates anchor exists via 2C pattern)
5. Broadcast revocation signal to federated networks (4B)
6. Emit `DIDKeyRotated` event on-chain (4C)

**Resolve:**
1. Check on-chain `ETPDIDRegistry.didPointers[didHash]` for latest `entityIdHash`
2. Fetch DID Document from Commitment Log via `GET /ct/v1/get-entry-and-proof?entity_id=X`
3. Verify Merkle inclusion proof against STH
4. Verify ML-DSA-65 signature on the CommitmentRecord
5. Return DID Document with resolution metadata (freshness tier, STH age)

**Deactivate:**
1. On-chain: `ETPDIDRegistry.revokeDID()` → emits `DIDRevoked` event
2. State transition: `ANCHORED → DELETED` in LTPAnchorRegistry
3. Broadcast revocation to federated networks (immediate, all tiers)
4. Commitment Log entry preserved (audit trail) but resolver returns `deactivated: true`

**Cross-chain resolve (Phase 1-2, X-mode):**
1. Source chain resolver follows standard resolve path
2. LiveBridge propagates anchor + DID pointer to destination chain
3. Destination chain resolver queries local contracts

**Cross-chain resolve (Phase 3+, Y-mode with PQ-safe STARK proofs):**
1. Verifier on destination chain requests ZK proof of source chain DID state
2. ETP STARK prover generates FRI-based proof of: DID pointer value + anchor record existence + STH signature validity on source chain
3. Destination chain verifier validates STARK proof on-chain via `ZKBridgeVerifier` (v3 format, hash-only, PQ-safe)
4. No relay trust required — proof is self-verifying

### 3.4 Version Chain Model

```
did:etp:...:abc123 → resolves to → HEAD entity in chain

Entity v1 (create)    Entity v2 (rotate key)    Entity v3 (add service)
     │                       │                          │
     └── immutable LTP ─────└── immutable LTP ─────────└── immutable LTP
                                                         ↑
                                         on-chain pointer: latestEntityIdHash
```

- Each version is a complete DID Document (not a delta)
- The on-chain pointer is the canonical HEAD
- Predecessor links enable audit trail traversal
- The Commitment Log holds the full version history
- Fork detection: only one HEAD per `didHash` per chain; bridge-synced pointers make cross-chain forks detectable

---

## 4. Contract Architecture

### 4.1 Three-Layer Merge (2A + 2B + 2C)

```
┌──────────────────────────────────────────────────────────────┐
│  DIDOperations (Wrapper Contract)                    [2B]    │
│  ─────────────────────────────────────────────                │
│  - commitDID(): atomic anchor + pointer creation              │
│  - updateDID(): atomic anchor + pointer update                │
│  - bridgeDID(): atomic cross-chain DID sync                   │
│  - Calls both contracts in single TX                          │
│  - Convenience entry point for bridge operator / supernodes   │
│  - Holds no state — pure orchestration                        │
├──────────────────────────────────────────────────────────────┤
│  ETPDIDRegistry (Standalone Contract)                [2C]    │
│  ─────────────────────────────────────────────                │
│  - didPointers: bytes32 didHash → bytes32 latestEntityIdHash  │
│  - createDID(): validates anchor exists in AnchorRegistry     │
│  - updatePointer(): validates anchor + signer authorization   │
│  - revokeDID(): emits DIDRevoked event                        │
│  - getDID(): read pointer                                     │
│  - Anchor-first enforcement built in (cross-contract read)    │
│  - UUPS upgradeable, admin = Timelock                         │
│  - Independent from AnchorRegistry upgrade cycle              │
├──────────────────────────────────────────────────────────────┤
│  LTPAnchorRegistry (Existing Contract)               [2A]    │
│  ─────────────────────────────────────────────                │
│  - anchor() remains independently callable                    │
│  - No DID awareness — stays general-purpose                   │
│  - Existing deployments (SUWAPPU Testnet, Base Sepolia) unaffected│
│  - 5-layer validation unchanged                               │
└──────────────────────────────────────────────────────────────┘
```

**Three entry points, one consistency guarantee:**
- Supernode calls `DIDOperations.commitDID()` → atomic anchor + pointer (2B wraps 2C wraps 2A)
- Direct caller hits `ETPDIDRegistry.updatePointer()` → validates anchor exists (2C enforces 2A happened first)
- Auditor/exchange queries each contract independently → always consistent because 2C prevents pointer without anchor
- Existing `LTPAnchorRegistry` callers are unaffected — zero contract modifications for non-DID operations

**Centralized exchange verification paths:**
1. Query `ETPDIDRegistry` only — purpose-built DID API, sufficient for most integrations
2. Query both contracts and require consistency — defense-in-depth
3. Query `LTPAnchorRegistry` for raw anchor data + independently verify Commitment Log — maximum assurance, no trust in DID contract logic

### 4.2 ETPDIDRegistry Contract Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IETPDIDRegistry {
    // --- Events ---
    event DIDCreated(bytes32 indexed didHash, bytes32 entityIdHash, bytes32 signerVkHash);
    event DIDUpdated(bytes32 indexed didHash, bytes32 newEntityIdHash, uint256 newSequence);
    event DIDKeyRotated(bytes32 indexed didHash, uint256 newSequence, bytes32 newEntityIdHash);
    event DIDRevoked(bytes32 indexed didHash);

    // --- Structs ---
    struct DIDRecord {
        bytes32 latestEntityIdHash;   // Points to HEAD of version chain
        bytes32 signerVkHash;         // Authorized controller's VK hash
        uint256 sequence;             // Version chain sequence number
        uint64  createdAt;            // Block timestamp of creation
        uint64  updatedAt;            // Block timestamp of last update
        bool    revoked;              // Deactivation flag
    }

    // --- Write Operations ---
    function createDID(bytes32 didHash, bytes32 entityIdHash, bytes32 signerVkHash) external;
    function updatePointer(bytes32 didHash, bytes32 newEntityIdHash, uint256 newSequence) external;
    function revokeDID(bytes32 didHash) external;

    // --- Read Operations ---
    function getDID(bytes32 didHash) external view returns (DIDRecord memory);
    function isActive(bytes32 didHash) external view returns (bool);
    function getSequence(bytes32 didHash) external view returns (uint256);
}
```

**Validation rules (inside `createDID` and `updatePointer`):**
1. Signer authorization — `authorizedDIDSigners[msg.sender]` or governance path
2. Anchor verification — cross-contract read to `LTPAnchorRegistry.anchors(entityIdHash).anchoredAt != 0`
3. Sequence monotonicity — `newSequence > current.sequence` (prevents replay)
4. Revocation check — `!current.revoked` (revoked DIDs cannot be updated)
5. Controller authorization — `current.signerVkHash` matches caller (only controller can update)

### 4.3 DIDOperations Wrapper Interface

```solidity
interface IDIDOperations {
    function commitDID(
        ILTPAnchorRegistry.AnchorParams calldata anchorParams,
        bytes32 didHash,
        bytes32 signerVkHash
    ) external;

    function updateDID(
        ILTPAnchorRegistry.AnchorParams calldata anchorParams,
        bytes32 didHash,
        uint256 newSequence
    ) external;

    function bridgeDID(
        ILTPAnchorRegistry.AnchorParams calldata anchorParams,
        bytes32 didHash,
        bytes32 signerVkHash,
        uint256 sequence,
        uint64 sourceChainId
    ) external;
}
```

### 4.4 Precompile Migration Path (3C)

Phase 1-2: All DID validation logic lives in Solidity (`ETPDIDRegistry` contract).

Phase 3+: When Gravm/Mysticy chain development is ready, critical operations move to a precompile:

```
Phase 1-2:
  ETPDIDRegistry.createDID() → Solidity validation logic

Phase 3+:
  ETPDIDRegistry.createDID() → calls precompile at address 0x0F
                                → DID validation at consensus level
                                → POS validators enforce DID rules during ordering
                                → POA nodes reject blocks with invalid DID transitions
```

The contract API remains unchanged. Callers see the same interface. The precompile enables validators to enforce DID invariants at the consensus level — a block containing an invalid DID operation is rejected before sealing, rather than just reverting at execution time.

**Precompile boundary design**: The `ETPDIDRegistry` contract separates validation logic from storage logic. Validation functions (`_validateCreate`, `_validateUpdate`, `_validateRevoke`) are isolated and stateless — they take inputs and return bool. These are the functions that migrate to the precompile. Storage mutations remain in Solidity.

---

## 5. Stale Read Mitigation — Freshness Architecture

### 5.1 Three Layered Mechanisms

**5.1.1 — Mechanism 4A: STH Sequence Gating**

Every Verifiable Credential includes the `sthSequence` from the DID Document's version chain. A verifier checks whether its local view of the source network's STH is at least this sequence number before trusting the credential.

Uses the existing `GET /ct/v1/get-sth` endpoint and federation STH verification (already implemented with real ML-DSA-65 signatures in `src/ltp/federation.py`).

**5.1.2 — Mechanism 4B: Gossip Revocation Broadcast**

Key rotation and revocation events are broadcast to federated networks via the existing gossip protocol. A new message type in `PeerExchangeMessage`:

```json
{
  "type": "did_revocation",
  "did": "did:etp:suwappu-testnet:sha3-256:...",
  "action": "rotate | revoke",
  "newSequence": 3,
  "sthSequence": 87,
  "signature": "ml-dsa-65:..."
}
```

Federated networks that receive this signal invalidate their cached DID state and force a fresh fetch on next resolution.

**5.1.3 — Mechanism 4C: On-Chain Revocation Events**

The `ETPDIDRegistry` emits events on key rotation and revocation:

```solidity
event DIDKeyRotated(bytes32 indexed didHash, uint256 newSequence, bytes32 newEntityIdHash);
event DIDRevoked(bytes32 indexed didHash);
```

Exchanges monitor these events on their local chain. If the DID was bridge-synced, the event fires locally. Otherwise, the exchange monitors the source chain.

### 5.2 Freshness Tiers

| Tier | Verifier Type | Max Staleness | Mechanisms | Failure Mode |
|---|---|---|---|---|
| **Tier 0 (Real-time)** | Centralized exchange, high-value settlement | 1 block (~12s) | 4C on-chain events on local chain | Reject if local chain DID event is behind source chain |
| **Tier 1 (Near-real-time)** | Node operator verification, bridge operations | 60 seconds | 4B gossip broadcast + 4A STH gate | Reject if STH sequence delta > 1 from credential's claim |
| **Tier 2 (Periodic)** | Federation network trust verification | 5 minutes | 4A STH gating + scheduled federation STH fetch | Warn if STH age > 5 min, reject if > 15 min |
| **Tier 3 (Lazy)** | Low-value verification, informational queries | 1 hour | 4A STH gating only, no push | Accept with `stale: true` flag in resolution metadata |

**Verifier policy enforcement**: Each verifier declares its tier at initialization. The DID resolver returns resolution metadata including `sthAge`, `sourceSthSequence`, `localSthSequence`, and `freshnessStatus` (`FRESH` / `ACCEPTABLE` / `STALE` / `UNKNOWN`). The verifier applies its tier policy to decide accept/warn/reject. This is configuration, not code — same resolver, different thresholds.

**Revocation override**: Regardless of tier, a `DIDRevoked` event (4C) or revocation broadcast (4B) is treated as immediate. A revoked DID is rejected at all tiers with zero grace period.

---

## 6. Immutability Model — Version Chain Architecture

### 6.1 Core Principle

LTP's append-only, immutable data model is preserved. No writable pointers are added to LTP. The mutability required by DID operations lives entirely in the on-chain contract layer (`ETPDIDRegistry.didPointers` mapping).

Each DID update is a full LTP COMMIT cycle:

```
DID key rotation:
  → Create new DID Document (v2) with updated verificationMethod
  → Erasure code into n shards
  → Encrypt shards with fresh CEK (forward secrecy)
  → Distribute to commitment nodes
  → Sign CommitmentRecord with ML-DSA-65
  → Append to Commitment Log (Merkle tree grows)
  → Anchor on-chain via LTPAnchorRegistry.anchor()
  → Update pointer via ETPDIDRegistry.updatePointer()
  → Bridge to other chains if needed
```

### 6.2 Scaling Projections

| Scale | DIDs | Avg Updates/Year/DID | New Log Entries/Year | Phase |
|---|---|---|---|---|
| Federation only | ~100 networks | 4 (quarterly rotation) | 400 | Phase 1 |
| + Node operators | ~10,000 nodes | 2 (annual + incident) | 20,400 | Phase 2 |
| + Institutional users | ~1,000,000 | 3 (rotation + updates) | 3,020,400 | Phase 3 |
| + Retail users | ~100,000,000 | 2 | 200,020,400 | Phase 4 |

### 6.3 Update Model by Phase

**Phase 1-2: Full commit per update (1B-i)**

Every DID update goes through the complete LTP COMMIT pipeline. Federation and node DIDs have low update frequency (< 20,400 entries/year). The overhead is negligible. This approach is consistent, auditable, and every version is independently verifiable.

**Phase 3 evaluation: Two-tier commit model (1B-iii)**

If institutional user DID update volume warrants it, evaluate a two-tier model:
- **Core updates** (key rotation, revocation): Full LTP COMMIT pipeline — erasure coded, encrypted, distributed, PQ-secured
- **Metadata updates** (service endpoints, display names): Lightweight path — ML-DSA-65 signed update appended to Commitment Log without erasure coding or shard distribution

The DID Document schema distinguishes between core fields (full pipeline) and metadata fields (lightweight). This evaluation happens before Phase 3 implementation begins, based on observed Phase 2 performance data.

### 6.4 Fork Detection

The version chain's predecessor links combined with on-chain pointer canonicality provide fork detection:

- **Same log**: The Commitment Log rejects duplicate `entity_id` values. Two competing updates produce two different entities — only one can be the HEAD pointer on-chain.
- **Cross-chain**: Bridge-synced DID pointers are compared. If chain A's pointer disagrees with chain B's pointer for the same `didHash`, the bridge detects the inconsistency during sync.
- **Cross-federation**: Independent Commitment Logs could theoretically contain forked version chains. The on-chain pointer (bridge-synced) is the canonical tiebreaker. Federation STH cross-verification (already implemented) detects log-level forks.

---

## 7. Economic Model — Fee Architecture

### 7.1 Phase-Appropriate Fee Models

| Phase | DID Type | Fee Model | Rationale |
|---|---|---|---|
| **Phase 1** | Federation network DIDs | **5A: Operator pays** | Network operator already funds anchor operations via `BridgeOperatorService`. DID operations piggyback on same wallet. |
| **Phase 2** | Node operator DIDs | **5A + 5B: Operator bootstraps, node maintains** | Operator funds initial DID creation during admission. Node funds subsequent updates from staking rewards. |
| **Phase 3** | Institutional user DIDs | **5B: Subject pays** | Institution holds native gas tokens, submits and funds own transactions directly. |
| **Phase 4** | Retail user DIDs | **5C: Meta-transaction relayer** | Relayer submits TX on behalf of user. User signs DID operation off-chain; relayer wraps in funded TX. Aligns with ERC-4337 account abstraction patterns. |
| **Long-term** | All DID types | **5D: Protocol fee abstraction** | Wire `EconomicsEngine` to on-chain token flows. DID operations funded from protocol revenue (storage rewards, staking yield). |

### 7.2 Gas Cost Estimates (Preliminary)

| Operation | Estimated Gas | Notes |
|---|---|---|
| `createDID()` | ~100,000 | New storage slot + cross-contract read |
| `updatePointer()` | ~60,000 | Storage update + cross-contract read + event |
| `revokeDID()` | ~40,000 | Storage update + event |
| `commitDID()` (wrapper) | ~200,000 | anchor() + createDID() in single TX |
| `updateDID()` (wrapper) | ~160,000 | anchor() + updatePointer() in single TX |

These are estimates. Actual costs depend on EVM implementation details and will be benchmarked during Phase 1 development.

---

## 8. Cross-Chain ZK Resolution Path (PQ-Safe)

### 8.1 Current State (X-Mode — Relay-Dependent)

Cross-chain DID resolution in Phases 1-2 uses the existing LiveBridge:

```
Resolver on Base Sepolia wants did:etp:suwappu-testnet:...
  → LiveBridge has already synced the DID pointer to Base Sepolia
  → Resolver queries local ETPDIDRegistry
  → Fetches full DID Document from Commitment Log (federation fetch or local cache)
  → Trust assumption: Bridge operator honestly synced the pointer
```

This works and ships immediately. The trust assumption is acceptable for federation and node DIDs (Phases 1-2) because bridge operators are known, registered, and slashable entities.

### 8.2 Target State (Y-Mode — PQ-Safe Trustless Resolution)

Phase 3+ upgrades cross-chain resolution to trustless via ETP's STARK prover:

```
Resolver on Base Sepolia wants did:etp:suwappu-testnet:...
  → Requests ZK proof of SUWAPPU Testnet DID state
  → ETP STARK prover generates FRI-based proof of:
      1. ETPDIDRegistry.didPointers[didHash] == entityIdHash (on SUWAPPU Testnet)
      2. LTPAnchorRegistry.anchors[entityIdHash].anchoredAt != 0 (anchor exists)
      3. STH signature is valid for the claimed tree size (log integrity)
  → Proof submitted to ZKBridgeVerifier on Base Sepolia (STARK v3 format)
  → Verifier validates proof on-chain (hash-only verification, PQ-safe)
  → Resolver fetches DID Document from Commitment Log
  → Trust assumption: STARK proof soundness (mathematical, not operational)
```

**PQ security chain (end-to-end):**
- DID Document signed with ML-DSA-65 (FIPS 204, PQ-safe)
- Cross-chain state proven via STARK (FRI + Goldilocks + SHA3-256, PQ-safe)
- On-chain verification via hash comparison (SHA3-256, PQ-safe)
- No pairings, no elliptic curves, no Groth16 in the critical path

### 8.3 Mirror Contract Pattern for DID

Cross-chain DID state mirroring using ETP's STARK prover:

- **Source chain**: `ETPDIDRegistry` holds authoritative DID state
- **Destination chain**: Mirror `ETPDIDRegistry` holds STARK-proven copy of source state
- **Proof**: ETP STARK proof (FRI-based) that source chain state transition was valid
- **Update propagation**: Relayer nodes pass DID state changes + STARK proofs between chains. Relayer is untrusted — it cannot forge proofs or modify DID state. Same trust model as the existing `LiveBridge` relay, but with mathematical proof replacing operational trust.
- **State conservation invariant**: Every DID pointer update on the destination chain is backed by a valid source chain state proof

**Mirror registry modes:**
- `AUTHORITATIVE` — This chain is the source of truth for this DID. Writes accepted directly.
- `MIRROR` — This chain holds a ZK-proven copy. Writes accepted only with valid STARK proof of source chain state.
- `BRIDGE_RELAY` — This chain holds a relay-synced copy (X-mode fallback). Writes accepted from authorized bridge operators.

The `ETPDIDRegistry` contract supports all three modes per DID, enabling gradual migration from relay to ZK-proven state.

### 8.4 `chainAnchors[]` Schema Evolution

The DID Document `chainAnchors` array is designed for this upgrade:

**Phase 1-2 (X-mode):**
```json
{
  "chainId": 84532,
  "registry": "ETPDIDRegistry",
  "contract": "0x...",
  "didPointer": "0x...",
  "syncMethod": "bridge-relay"
}
```

**Phase 3+ (Y-mode):**
```json
{
  "chainId": 84532,
  "registry": "ETPDIDRegistry",
  "contract": "0x...",
  "didPointer": "0x...",
  "syncMethod": "stark-proof",
  "zkProof": {
    "prover": "etp-stark-fri",
    "sourceChainId": 103115120,
    "proofHash": "0x...",
    "verifiedAt": 1745000000,
    "pqSafe": true
  }
}
```

Same schema structure. The `syncMethod` field distinguishes trust models. Verifiers that require ZK-backed resolution reject `bridge-relay` entries. Verifiers that accept relay-backed resolution work with both. The `pqSafe` flag enables verifiers to enforce post-quantum requirements on the proof itself.

### 8.5 Prerequisites for Y-Mode

| Prerequisite | Status | Dependency |
|---|---|---|
| ETP STARK prover (FRI + Goldilocks) | **Implemented** | `src/ltp/bridge/_stark_fallback.py`, tested |
| `ZKBridgeVerifier` STARK v3 support | **Implemented** | Real FRI-based verification on both chains |
| STARK proof for DID-specific public inputs | Not implemented | Extend `ZKBridgePublicInputs` with DID fields |
| Mirror contract pattern | Not implemented | New mode in `ETPDIDRegistry` |
| Cross-chain relayer for DID state | Partially exists | `BridgeOperatorService` needs DID awareness |
| STARK proof of EVM storage reads | Not implemented | Prove `didPointers[hash]` storage slot via FRI |
| Proof size optimization | Pending evaluation | Current STARK proofs ~232B (bridge); DID proofs may be larger due to additional public inputs |

**Key advantage over external zkVM approaches**: The ETP STARK prover has zero external dependencies. No Rust toolchain, no external SDK, no vendor relationship. The prover is Python-native, tested in the existing CI pipeline, and already integrated with the on-chain verifier. Y-mode is an extension of existing infrastructure, not a new integration.

---

## 9. Verifiable Credentials Architecture

### 9.1 VC Issuance Flow (Federation — Phase 1)

Federation agreements (already implemented as bilateral ML-DSA-65 signed agreements) become W3C Verifiable Credentials:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://etp.suwappu.io/ns/credentials/v1"
  ],
  "type": ["VerifiableCredential", "ETPFederationCredential"],
  "issuer": "did:etp:suwappu-testnet:sha3-256:...",
  "issuanceDate": "2026-04-23T12:00:00Z",
  "credentialSubject": {
    "id": "did:etp:base-sepolia:sha3-256:...",
    "federationTrust": "FEDERATED",
    "networkId": "sha3-256:...",
    "capabilities": ["shard-fetch", "sth-verify", "entity-resolve"],
    "agreementRef": "sha3-256:..."
  },
  "proof": {
    "type": "MLDSA65Signature2026",
    "created": "2026-04-23T12:00:00Z",
    "verificationMethod": "did:etp:suwappu-testnet:sha3-256:...#ml-dsa-65-key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

### 9.2 VC Types by Phase

| Phase | VC Type | Issuer | Subject | Claims |
|---|---|---|---|---|
| **1** | `ETPFederationCredential` | Network operator DID | Federated network DID | Trust tier, capabilities, agreement ref |
| **1** | `ETPNetworkOperatorCredential` | Network operator DID | Self (self-issued) | NIR fields, genesis STH, protocol version |
| **2** | `ETPNodeAuthorizationCredential` | Network operator DID | Node operator DID | Authorization scope (shard storage, auditing, bridge operation) |
| **2** | `ETPNodeAdmissionCredential` | Endorsing nodes (m-of-n) | Admitted node DID | Admission state, endorsement signatures, stake amount |
| **3** | `ETPInstitutionalIdentityCredential` | Supernode (e.g., central bank) DID | Institutional user DID | KYC/AML status, jurisdiction, accreditation level |
| **4** | `ETPUserCredential` | Institutional issuer DID | Individual user DID | Identity claims, authorization scope |

### 9.3 VC Storage and Transport

Verifiable Credentials are LTP entities. They go through the standard three-phase lifecycle:

1. **COMMIT**: VC serialized as entity, committed to Commitment Log, anchored on-chain
2. **LATTICE**: VC sealed to intended verifier via ML-KEM-768 (privacy-preserving — only the intended verifier can unseal)
3. **MATERIALIZE**: Verifier unseals, reconstructs VC, verifies issuer's DID and ML-DSA-65 proof signature

This gives VCs the same security properties as all ETP entities: PQ-secure transport, forward secrecy per credential, append-only audit trail, data availability via erasure coding.

### 9.4 VC Revocation

VCs are revoked by updating the issuer's DID Document to include a revocation list, or by revoking the subject's DID entirely. The on-chain `DIDRevoked` event (4C) serves as the revocation signal for all credentials associated with that DID.

For granular per-VC revocation (revoking a specific credential without revoking the DID), a `RevocationList2026` service endpoint in the issuer's DID Document points to a Commitment Log entry containing the revocation list — following the W3C `StatusList2021` pattern but stored in ETP's Commitment Log.

---

## 10. Phased Implementation Roadmap

### Phase 1: Federation Verifiable Credentials

**Goal**: Prove the `did:etp` method works with machine-to-machine trust between federated ETP networks.

**Builds on**: `NetworkIdentityRecord`, `FederationAgreement`, `FederationRegistry`, CT REST API, gossip protocol.

**Deliverables:**
1. `did:etp` W3C DID Method specification document
2. `src/ltp/did/` — Python DID module:
   - `method.py` — DID creation, update, deactivation, resolution
   - `document.py` — DID Document schema, serialization, validation
   - `resolver.py` — Multi-tier resolver with freshness policy enforcement
   - `credentials.py` — VC issuance, verification, revocation list
3. `contracts/src/ETPDIDRegistry.sol` — On-chain DID pointer registry
4. `contracts/src/DIDOperations.sol` — Wrapper contract for atomic operations
5. Integration with existing `FederationAgreement` → VC issuance pipeline
6. Gossip revocation broadcast (new message type in `PeerExchangeMessage`)
7. Deployment to SUWAPPU Testnet and Base Sepolia
8. End-to-end tests: create federation DID → issue VC → resolve cross-network → verify → revoke

**Fee model**: Operator pays (5A).
**Anchoring**: Commitment Log primary (X-mode).
**Freshness**: Tier 2 (5-minute periodic STH fetch).

### Phase 2: Node Operator Identity

**Goal**: Every ETP node operator gets a DID. Authorization expressed as Verifiable Credentials.

**Builds on**: Phase 1 DID module, `AdmissionProtocol` (m-of-n endorsement), `KeyPair`, node bootstrap sequence.

**Deliverables:**
1. Node bootstrap integration — DID creation as part of `ETPNode` 18-step bootstrap (new step between keypair generation and network registration)
2. `ETPNodeAuthorizationCredential` issuance by network operator
3. `ETPNodeAdmissionCredential` issuance by endorsing nodes (maps to existing `AdmissionState` machine)
4. Signer registration via DID — `registerSigner(vkHash)` backed by DID resolution instead of raw VK hash
5. API Gateway JWT auth backed by DID — `verify_jwt()` resolves caller DID for authorization
6. Node diagnostics DID endpoint — `GET /node/did` returns node's DID Document
7. End-to-end tests: node bootstraps with DID → admission via VC → signer registration via DID → authorized operations

**Fee model**: Operator bootstraps (5A), node maintains (5B).
**Anchoring**: Commitment Log primary (X-mode).
**Freshness**: Tier 1 (60-second gossip broadcast).

### Phase 3: Institutional Users + PQ-Safe Cross-Chain Resolution

**Goal**: Institutional users (exchanges, banks, regulated entities) get DIDs. Cross-chain resolution upgrades from relay to PQ-safe STARK proofs.

**Builds on**: Phase 2 DID infrastructure, `LiveBridge`, `ZKBridgeVerifier`, ETP STARK prover.

**Deliverables:**
1. `ETPInstitutionalIdentityCredential` schema and issuance flow
2. Supernode DID creation quorum — contract-level M-of-N supernode signature requirement
3. Evaluate two-tier commit model (1B-iii) based on Phase 2 performance data
4. RocksDB migration for Commitment Log Merkle tree (scaling prerequisite)
5. Extend ETP STARK prover for DID-specific public inputs (didHash, entityIdHash, sequence)
6. Mirror `ETPDIDRegistry` pattern for cross-chain DID state mirroring (AUTHORITATIVE / MIRROR / BRIDGE_RELAY modes)
7. `ZKBridgeVerifier` extension for DID-specific STARK proof verification
8. `chainAnchors[]` upgrade from `bridge-relay` to `stark-proof`
9. Centralized exchange integration guide — verification paths, freshness tier selection, API reference
10. End-to-end tests: institutional DID creation → cross-chain STARK resolution → exchange verification

**Fee model**: Subject pays (5B).
**Anchoring**: Transition to on-chain primary (Y-mode).
**Freshness**: Tier 0 (real-time on-chain events) for exchanges.

### Phase 4: Retail Users + Protocol Fee Abstraction

**Goal**: Individual users get DIDs with meta-transaction support. Protocol-level fee abstraction.

**Builds on**: Phase 3 infrastructure, ERC-4337 account abstraction patterns.

**Deliverables:**
1. `ETPUserCredential` schema and issuance flow
2. Meta-transaction relayer for gasless DID operations (5C)
3. ERC-4337 integration or equivalent account abstraction
4. Protocol fee abstraction (5D) — wire `EconomicsEngine` to on-chain token flows
5. Precompile migration (3C) — move DID validation to consensus-level when Gravm/Mysticy ready
6. Scale testing at 1M+ DIDs
7. End-to-end tests: user DID creation via meta-tx → VC issuance → cross-chain resolution → revocation

**Fee model**: Meta-transaction (5C) → Protocol fee (5D).
**Anchoring**: On-chain primary (Y-mode).
**Freshness**: All tiers available, verifier-selected.

---

## 11. Dependencies and Prerequisites

### 11.1 Existing Infrastructure Required (No Changes)

| Component | Used By | Location |
|---|---|---|
| ML-DSA-65 / ML-KEM-768 keypairs | DID verification methods | `src/ltp/primitives.py` |
| CommitmentLog (append-only, Merkle) | DID Document storage | `src/ltp/commitment.py` |
| CT REST API | DID resolution | `src/ltp/rest_server.py` |
| Federation protocol | Cross-network DID resolution | `src/ltp/federation.py` |
| LTPAnchorRegistry | On-chain anchoring | `contracts/src/LTPAnchorRegistry.sol` |
| LiveBridge | Cross-chain DID sync (X-mode) | `src/ltp/bridge/live.py` |
| Gossip protocol | Revocation broadcast | `src/ltp/node/gossip.py` |
| API Gateway + JWT auth | DID-authenticated API access | `src/ltp/gateway/` |
| KeyRotationManager | DID key rotation | `src/ltp/keypair.py` |
| AdmissionProtocol | Node DID admission quorum | `src/ltp/node/admission.py` |

### 11.2 New Infrastructure Required

| Component | Phase | Dependency |
|---|---|---|
| `src/ltp/did/` Python module | Phase 1 | None — builds on existing primitives |
| `ETPDIDRegistry.sol` contract | Phase 1 | Solidity 0.8.24, UUPS pattern |
| `DIDOperations.sol` wrapper | Phase 1 | `ETPDIDRegistry` + `LTPAnchorRegistry` |
| Gossip revocation message type | Phase 1 | `src/ltp/node/gossip.py` extension |
| Node bootstrap DID integration | Phase 2 | Phase 1 DID module |
| RocksDB Merkle tree migration | Phase 3 | `lsm-db` or `rocksdb` Python binding |
| STARK prover DID extension | Phase 3 | Extend existing `STARKBridgeProver` with DID public inputs |
| Mirror contract pattern | Phase 3 | `ETPDIDRegistry` mirror mode (AUTHORITATIVE / MIRROR / BRIDGE_RELAY) |
| Meta-transaction relayer | Phase 4 | ERC-4337 or custom relayer |
| Precompile (Gravm/Mysticy) | Phase 4 | Chain development readiness |

### 11.3 External Dependencies

| Dependency | Phase | Risk | Mitigation |
|---|---|---|---|
| W3C DID Core 1.0 spec stability | Phase 1 | Low — spec is a W3C Recommendation | Track via W3C DID WG |
| Gravm/Mysticy precompile support | Phase 4 | Medium — chain development timeline | Contract-level (3C) works indefinitely without precompile |
| ERC-4337 or equivalent on SUWAPPU chain | Phase 4 | Low-medium — standard pattern | Custom relayer as fallback |

---

## 12. Open Questions

| # | Question | Affects | Resolution Target |
|---|---|---|---|
| 1 | W3C registration process for `MLDSA65VerificationKey2026` and `MLKEM768KeyAgreementKey2026` verification method types | Phase 1 | Before Phase 1 spec finalization |
| 2 | Optimal M-of-N threshold for supernode DID creation quorum | Phase 3 | Governance team decision |
| 3 | STARK proof size for DID-specific public inputs — current bridge proofs are 232B; DID proofs may need additional fields | Phase 3 | Benchmark during STARK prover extension |
| 4 | Two-tier commit model (1B-iii) threshold — at what update volume does the lightweight path become necessary? | Phase 3 | Benchmark during Phase 2 |
| 5 | Precompile address allocation in Gravm/Mysticy | Phase 4 | Chain development coordination |
| 6 | Token model for protocol fee abstraction (5D) | Phase 4 | Economic model team |
| 7 | RLP encoding conventions for nil DID pointer fields in account state | Phase 3+ (Y-mode) | Chain development coordination |
| 8 | Cross-chain DID governance — if a DID is revoked on chain A, what is the enforcement mechanism on chain B before STARK proofs are available? | Phase 1-2 | Bridge operator policy + gossip broadcast (4B) |
| 9 | Should external zkVM backends (Ziren, SP1, RISC Zero) be supported as optional non-PQ proof paths for ecosystems that don't require quantum resistance? | Phase 3+ | Architecture team decision — PQ-safe STARK is default; classical backends opt-in with explicit warning. Revisit if any external zkVM adds STARK-only on-chain verification (no SNARK wrapping). |

---

## 13. References

- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) — DID specification
- [W3C Verifiable Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model/) — VC specification
- [Entangled Rollups Whitepaper](https://www.zkm.io/whitepaper/entangled-rollups-lp) — Related work: cross-chain state mirroring patterns
- [Ziren zkVM](https://github.com/ProjectZKM/Ziren) — Related work: entangled rollup reference implementation
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/publications/detail/fips/203/final) — Post-quantum key encapsulation
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/publications/detail/fips/204/final) — Post-quantum digital signatures
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) — Account abstraction
- [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) — Certificate Transparency (commitment log model)
- LTP Gateway VM Plan (internal) — `docs/LTP_GATEWAY_VM_PLAN.md` (Phase 4: dual VM introduction)
- Proposed MoveVM+DID Architecture (internal) — `docs/Proposed-MoveVM-DID.docx` (dual VM identity architecture, built in tandem with this plan)
- ETP Implementation Status (internal) — `docs/ETP_IMPLEMENTATION_STATUS.md`
- ETP Bridge MVP Scope (internal) — `docs/bridge-mvp-scope.md`
- ETP Cross-Deployment Federation (internal) — `docs/design-decisions/CROSS_DEPLOYMENT_FEDERATION.md`
- ETP ZK Transfer Mode (internal) — `docs/design-decisions/ZK_TRANSFER_MODE.md`

---

*This document captures planning decisions from the April 2026 architecture discussions. It is a living plan subject to revision as implementation proceeds and dependencies (STARK prover DID extension, Gravm/Mysticy precompile support) mature.*
