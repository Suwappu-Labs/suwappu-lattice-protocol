# LTP Architecture (v2 — Option C Security)

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
  - [Entity Engine](#1-entity-engine)
  - [Lattice Key Generator](#2-lattice-key-generator-v2--minimal-sealed-key)
  - [Materialization Engine](#3-materialization-engine-v2--unseal-derive-decrypt)
- [Commitment Network Topology](#4-commitment-network-topology)
  - [Node Lifecycle](#41-node-lifecycle)
  - [Audit Protocol](#42-audit-protocol)
- [Transfer Flow](#5-transfer-flow-sequence)
- [Security Layers](#6-security-layers)
- [Data Flow Summary](#7-data-flow-summary)
- [Technology Choices](#8-technology-choices)
- [Economics Engine](#9-economics-engine)
- [Enforcement Pipeline](#10-enforcement-pipeline)
- [Progressive Decentralization](#11-progressive-decentralization)
- [Compliance Framework](#12-compliance-framework)
- [Federation Protocol](#13-federation-protocol)
- [Streaming Protocol](#14-streaming-protocol)
- [ZK Transfer Mode](#15-zk-transfer-mode)
- [Bridge Protocol](#16-bridge-protocol)
- [Backend Architecture](#17-backend-architecture)

## System Overview

```mermaid
flowchart TD
    subgraph LTP["LATTICE TRANSFER PROTOCOL v2"]
        direction TB
        SENDER["Sender"] -->|"COMMIT\n(encrypted shards)"| CL
        SENDER -->|"~1,300 bytes\nML-KEM sealed"| RECEIVER["Receiver"]
        RECEIVER -->|"MATERIALIZE\n(unseal → derive → fetch → decrypt)"| CL

        subgraph CL["COMMITMENT LAYER"]
            direction TB
            LOG["Commitment Log (Append-Only)\nRecord 1 ← Record 2 ← ... ← Record N\nMerkle root of ciphertext hashes only"]
            NODES["Commitment Nodes (Encrypted Shard Storage)\nAEAD-encrypted ciphertext — nodes cannot read\nKeyed by entity_id, index — derivable by receiver"]
        end
    end
```

### Implementation Mapping

| Architecture Component | Source Files |
|---|---|
| Entity Engine | `entity.py`, `erasure.py`, `shards.py` |
| Lattice Key Generator | `lattice.py`, `keypair.py` |
| Materialization Engine | `protocol.py` |
| Commitment Network | `commitment.py`, `merkle_log/` |
| Enforcement | `enforcement.py`, `enforcement_pipeline.py` |
| Economics | `economics.py` |
| Bridge | `bridge/` (`anchor.py`, `relayer.py`, `materializer.py`) |
| Verification | `verify/` (`core.py`, `results.py`) |

### GSX Stack Boundary

LTP is the transfer and attestation layer in the GSX stack. `gsx-dag` owns
certificate-DAG ordering and validator-ring consensus. `gsx-db` owns the
canonical EVM/Move state substrate, including capability-gated mutation,
state-root calculation, anchor dispatch, recovery replay, and L2 sync. LTP
anchors and attests those state roots through `LTPAnchorRegistry`; it does not
directly mutate GSX-DB state.

See [GSX DAG and GSX-DB Integration](GSX_DAG_DB_INTEGRATION.md) for the
cross-repo source paths and verification trail.

---

## Component Architecture

### 1. Entity Engine

The Entity Engine is the sender-side component that prepares entities for commitment.

```mermaid
flowchart TD
    subgraph EE["ENTITY ENGINE (v2)"]
        CI[Content Ingester] --> SA[Shape Analyzer\nschema detect]
        SA --> IC["Identity Computer\nH(content ‖ shape ‖ time ‖ pubkey)"]
        IC --> EC[Erasure Encoder\nn shards, k min]
        EC -->|"plaintext shards"| SE["Shard Encryptor\nCEK = random(256)\nAEAD(CEK, shard, nonce=index)"]
        SE -->|"encrypted shards"| SD[Shard Distributor\nconsistent hash]
        SD --> CW[Commitment Writer\nMerkle root only]
    end
```

### 2. Lattice Key Generator (v2 — Minimal Sealed Key)

```mermaid
flowchart TD
    subgraph LKG["LATTICE KEY GENERATOR (Option C)"]
        direction TB
        INPUTS["Inputs:\nentity_id — from commitment\nCEK — from shard encryption\ncommitment_ref — hash of record\nreceiver_pubkey — destination\naccess_policy — rules"]
        INPUTS --> PAYLOAD["Inner Payload (~160 bytes):\nentity_id: 32 bytes\nCEK: 32 bytes\ncommitment_ref: 32 bytes\naccess_policy: ~20-50 bytes"]
        PAYLOAD --> SEAL["Sealing (envelope encryption):\n1. Ephemeral ML-KEM encapsulation\n2. Derive AEAD key from shared secret\n3. AEAD encrypt entire payload\n4. Package: kem_ct(1088) + nonce + aead_ct + tag"]
        SEAL --> OUTPUT["Output: Sealed LatticeKey ~1,300B\nPoC: 1088+16+32 = 1136B overhead\nProd: 1088+24+16 = 1128B overhead"]
    end
```

### 3. Materialization Engine (v2 — Unseal, Derive, Decrypt)

```mermaid
flowchart TD
    subgraph ME["MATERIALIZATION ENGINE (Option C)"]
        KU["Key Unsealer\nunseal with private key\nextract CEK"] --> CV["Commitment Verifier\nfetch record, verify\nH(record) == commitment_ref"]
        CV --> LD["Location Deriver\nConsistentHash(entity_id ‖ index)\nno shard_ids needed"]
        LD --> PF["Parallel Fetcher\nfetch k-of-n ENCRYPTED\nshards from nearest nodes"]
        PF --> SD["Shard Decryptor\nAEAD_Decrypt(CEK, enc_shard, index)\ntag verified first"]
        SD --> ED["Erasure Decoder\nreconstruct from k decrypted shards"]
        ED --> EV["Entity Verifier\nH(entity) == entity_id?"]
        EV --> DONE["ENTITY MATERIALIZED"]
    end
```

---

## 4. Commitment Network Topology

```mermaid
flowchart TD
    LOG["COMMITMENT LOG\nGlobal, Shared, Append-Only"]
    LOG --> RA & RB & RC

    subgraph RA["Region A (US-East)"]
        N1a[N1] & N2a[N2] & N3a[N3]
    end

    subgraph RB["Region B (EU-West)"]
        N4b[N4] & N5b[N5] & N6b[N6]
    end

    subgraph RC["Region C (AP-East)"]
        N7c[N7] & N8c[N8] & N9c[N9]
    end
```

Commitment nodes store ENCRYPTED shards and replicate within and across regions.
Receivers fetch from nearest nodes. Nodes cannot read shard content (ciphertext only).

### 4.1 Node Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Apply
    Apply --> Admitted: Identity attestation\n+ storage bond
    Admitted --> Active: Verified
    Active --> Audit: Audit challenge
    Audit --> Active: Pass
    Audit --> Warning: Fail (strike)
    Warning --> Active: Pass subsequent audit
    Warning --> Evicted: 3rd strike
    Evicted --> [*]: Bond slashed\n+ shard repair
```

### 4.2 Audit Protocol

```mermaid
sequenceDiagram
    participant A as Auditor
    participant N as Node
    participant R as Other Replica

    A->>N: Challenge(eid, idx, nonce)
    N->>N: Compute H(ct || nonce)
    N->>A: H(ct || nonce)
    A->>R: Verify against known-good hash
    R->>A: H(ct || nonce)
    A->>A: Match → PASS / Mismatch or Timeout → FAIL
```

---

## 5. Transfer Flow (Sequence)

```mermaid
sequenceDiagram
    participant S as Sender
    participant CL as Commitment Layer
    participant R as Receiver

    Note over S: 1. Compute EntityID
    Note over S: 2. Erasure encode → shards
    Note over S: 3. Generate CEK (random)
    Note over S: 4. AEAD encrypt each shard
    S->>CL: 5. Distribute encrypted shards
    Note over CL: Ciphertext stored by (eid, index)
    S->>CL: 6. Write commitment record (Merkle root only)
    Note over S: 7. Generate lattice key
    S->>R: 8. Seal key (~1,300 bytes, ML-KEM)
    Note over S: Sender done. Can go offline.
    Note over R: 9. Unseal key (private key)
    Note over R: 10. Extract CEK
    R->>CL: 11. Fetch record
    Note over R: 12. Verify record
    Note over R: 13. Derive shard locations
    R->>CL: 14. Fetch k encrypted shards
    CL->>R: Return shards
    Note over R: 15. AEAD decrypt with CEK
    Note over R: 16. Erasure decode
    Note over R: 17. Verify entity
    Note over R: ENTITY MATERIALIZED
```

---

## 6. Security Layers

```mermaid
flowchart BT
    L1["Layer 1: INFORMATION-THEORETIC SECURITY\nErasure coding k-of-n threshold\n< k shards reveal nothing\nDistributed across independent nodes"]
    L2["Layer 2: CRYPTOGRAPHIC INTEGRITY\nContent-addressed entities (BLAKE3)\nMerkle root over encrypted shard hashes\nML-DSA-65 signatures (FIPS 204)"]
    L3["Layer 3: ZERO-KNOWLEDGE (Optional)\nZK-proofs on commitment records\nVerifiable computation on hidden data"]
    L4["Layer 4: SHARD ENCRYPTION\nAEAD with random 256-bit CEK\nPer-shard nonce derivation\nNodes store ciphertext only"]
    L5["Layer 5: SEALED ENVELOPE (ML-KEM-768)\nFresh encapsulation per seal\nZero metadata leakage\nReceiver identity verified during unseal"]
    L6["Layer 6: ACCESS POLICY\nOne-time materialization\nTime-bounded access\nDelegatable permissions\nRevocable lattice link"]

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    L5 --> L6
```

### Attack Surface Closure (v1 → v2)

```
  LEAK 1: Lattice Key (in transit)
  v1: ✗ Plaintext JSON with shard_ids, encoding params, sender_id
  v2: ✓ Sealed envelope — opaque ciphertext, zero metadata

  LEAK 2: Commitment Log (at rest)
  v1: ✗ Listed all shard_ids in plaintext
  v2: ✓ Merkle root only — hashes of ciphertext, no individual IDs

  LEAK 3: Commitment Nodes (at rest)
  v1: ✗ Stored plaintext shards, served to anyone
  v2: ✓ AEAD-encrypted ciphertext — useless without CEK
```

---

## 7. Data Flow Summary

| Stage | Data Size | Who Performs | Network Cost |
|-------|-----------|-------------|-------------|
| Entity → Shards | O(entity) | Sender (local) | None |
| Shards → Encrypted Shards | O(entity) + O(n×32) tags | Sender (local) | None |
| Encrypted Shards → Nodes | O(entity × replication) | Sender → Network | Amortized, async |
| Commitment Record | O(1) ~512B | Sender → Log | Minimal |
| **Lattice Key** | **O(1) ~1,300B sealed** | **Sender → Receiver** | **Near zero** |
| Encrypted Shards → Receiver | O(entity) | Network → Receiver | Local fetches |
| Decrypt + Decode | O(entity) | Receiver (local) | None |

**Critical insight**: The sender-to-receiver direct path carries O(1) data. The O(entity)
work happens between sender↔network (commit phase) and network↔receiver (materialize phase),
where "network" means **nearby commitment nodes**.

**Honest cost accounting**: Total system bandwidth is O(entity × replication_factor) + O(entity),
which is strictly greater than direct transfer's O(entity). The advantage is *not* bandwidth
reduction — it is bottleneck relocation: replacing one long-haul O(entity) transfer with
parallel local O(entity/k) fetches, plus amortized fan-out to multiple receivers.

---

## 8. Technology Choices

| Component | Recommended | Rationale |
|-----------|------------|-----------|
| Hash function | BLAKE3 | Fast, secure, parallelizable, ZK-friendly |
| Signatures | ML-DSA-65 (FIPS 204) | Post-quantum (Dilithium); NIST Level 3 |
| Key encapsulation | ML-KEM-768 (FIPS 203) | Post-quantum (Kyber); replaces X25519 |
| Erasure coding | Vandermonde RS over GF(256) | Any k-of-n reconstruction (polynomial 0x11D) |
| Commitment log | Merkle DAG / append-only ledger | Immutable, verifiable, decentralizable |
| Shard placement | Consistent hashing (jump hash) | Deterministic, balanced, minimal disruption |
| Shard encryption | XChaCha20-Poly1305 | AEAD, fast, nonce-misuse resistant |
| Storage proofs | Challenge-response (H(ct ‖ nonce)) | Lightweight, no SNARKs/VDFs needed |
| Node identity | ML-DSA-65 attestation / SPIFFE SVID | Sybil resistance via verifiable identity |

---

## 9. Economics Engine

The economics module manages the incentive layer: node staking, reward distribution, progressive slashing, and correlation penalties.

```mermaid
flowchart TD
    subgraph Economics["ECONOMICS ENGINE"]
        STAKE[Node Stakes\nMinimum bond required] --> REWARDS[Reward Distribution\nPer-epoch fee split]
        REWARDS --> VEST[Vesting Schedule\n90-day linear vest]
        STAKE --> SLASH[Progressive Slashing\n1% → 5% → 15% → 30%]
        SLASH --> CORR[Correlation Penalty\nUp to 3x multiplier\nfor concurrent failures]
        CORR --> EVICT[Eviction\n3+ strikes → bond slash\n+ shard repair]
        SLASH --> GRACE[7-Day Grace Period\nReversible before finalization]
        GRACE -->|Finalized| EVICT
        GRACE -->|Reversed| STAKE
    end
```

**Key design decisions:**
- Progressive slashing tiers prevent accidental total loss
- Correlation penalty (Ethereum-inspired) deters coordinated attacks
- 7-day grace period allows reversal of incorrect slashes
- 30-day offense decay enables rehabilitation

---

## 10. Enforcement Pipeline

Seven enforcement mechanisms spanning the protocol lifecycle.

```mermaid
flowchart TD
    subgraph Enforcement["ENFORCEMENT PIPELINE"]
        PDP["1. PDP Storage Proofs\n160-byte cryptographic proof\nof data possession"]
        PS["2. Programmable Slashing\nCustom SlashingConditions\nper-condition stake allocation"]
        ISD["3. Intersubjective Disputes\nStake-weighted voting\nfor subjective violations"]
        VDF["4. VDF-Enhanced Audits\nPhysics-based timing\nguarantees"]
        MEV["5. MEV Protection\nEncrypted submissions\nEpoch-based batching"]
        FV["6. Formal Verification\nSafety/liveness invariants\nProperty-based testing"]
        PD["7. Progressive Decentralization\nIrreversible phase transitions\nMetrics-based triggers"]
    end

    PDP -->|Growth Phase| PS
    PS -->|Growth Phase| MEV
    MEV -->|Maturity Phase| ISD
    ISD -->|Maturity Phase| VDF
    FV -->|All Phases| PDP
    PD -->|All Phases| FV
```

---

## 11. Progressive Decentralization

Enforcement governance evolves through three irreversible phases.

```mermaid
stateDiagram-v2
    [*] --> Bootstrap
    Bootstrap --> Growth: epoch >= 4320\nAND nodes >= min_genesis

    state Bootstrap {
        [*] --> B_Active
        B_Active: Foundation veto power\nMin 3 operators\nPermissioned eviction
    }

    Growth --> Maturity: epoch >= 17520\nAND HHI < 2500\nAND Gini < 0.65

    state Growth {
        [*] --> G_Active
        G_Active: Programmable slashing\nPDP storage proofs\nMEV protection
    }

    state Maturity {
        [*] --> M_Active
        M_Active: Foundation veto REVOKED\nIntersubjective disputes\nGovernance minimization
    }
```

| Metric | Bootstrap | Growth | Maturity |
|--------|-----------|--------|----------|
| Operator count | >= 5 | >= 20 | >= 100 |
| HHI (concentration) | Any | < 5000 | < 2500 |
| Gini (distribution) | Any | < 0.80 | < 0.65 |
| Foundation veto | Yes | Yes | **No** |

---

## 12. Compliance Framework

Nine control families for regulatory compliance.

```mermaid
flowchart TD
    subgraph Compliance["COMPLIANCE FRAMEWORK"]
        direction TB
        AC[Access Control] --> DG[Data Governance]
        DG --> KM[Key Management]
        KM --> AL[Audit Logging]
        AL --> IR[Incident Response]
        IR --> DP[Data Protection]
        DP --> NW[Network Security]
        NW --> CM[Change Management]
        CM --> BC[Business Continuity]
    end

    Evidence["Automated Evidence\nCollection"] --> Compliance
    Compliance --> Report["Compliance Report\nPer-framework mapping"]
```

---

## 13. Federation Protocol

Cross-deployment discovery, trust escalation, and interoperability.

```mermaid
stateDiagram-v2
    [*] --> UNTRUSTED: Network discovered
    UNTRUSTED --> VERIFIED: NIR signature valid\nSTH chain verified
    VERIFIED --> FEDERATED: Mutual agreement\nOperator approval
    FEDERATED --> VERIFIED: Revocation\n168-epoch grace
    FEDERATED --> UNTRUSTED: Fork detected
    VERIFIED --> UNTRUSTED: STH inconsistency
```

```mermaid
sequenceDiagram
    participant A as Network A (Receiver)
    participant B as Network B (Source)

    Note over A: Entity committed on Network B
    A->>B: EntityResolutionRequest(entity_id)
    B->>A: EntityResolutionResponse(found, inclusion_proof, STH)
    A->>A: Verify inclusion proof against STH
    A->>B: ShardFetchRequest(entity_id, indices, auth)
    B->>A: Encrypted shards
    A->>A: Decrypt with CEK, decode, verify
    Note over A: Entity materialized cross-network
```

---

## 14. Streaming Protocol

Chunked streaming for large entities and live data.

```mermaid
sequenceDiagram
    participant S as Sender
    participant N as Network
    participant R as Receiver

    S->>N: COMMIT(chunk_0)
    N->>R: distribute shards
    S->>R: LATTICE(chunk_0)
    Note over R: MATERIALIZE(chunk_0)

    S->>N: COMMIT(chunk_1)
    N->>R: distribute shards
    S->>R: LATTICE(chunk_1)
    Note over R: MATERIALIZE(chunk_1)

    S->>N: COMMIT(manifest)
    S->>R: LATTICE(manifest)
    Note over R: Verify aggregate integrity
```

| Property | Batch Mode | Streaming Mode |
|----------|-----------|---------------|
| First-byte latency | O(entity_size) | O(chunk_size) |
| Memory footprint | O(entity_size) | O(chunk_size x pipeline_depth) |
| Failure granularity | All-or-nothing | Per-chunk recovery |

---

## 15. ZK Transfer Mode

Optional hiding commitments for low-entropy entities.

```mermaid
flowchart LR
    subgraph Standard["Standard Mode"]
        S_EID["entity_id = H(content)"] --> S_LOG["Public in log"]
        S_LOG --> S_MAT["Materialize:\nverify H(entity) == entity_id"]
    end

    subgraph ZK["ZK Mode"]
        Z_EID["entity_id = H(content)"] --> Z_BLIND["blind_id = Poseidon(entity_id || r)"]
        Z_BLIND --> Z_PROOF["+ Groth16 proof"]
        Z_PROOF --> Z_LOG["blind_id in log\n(entity_id hidden)"]
        Z_LOG --> Z_MAT["Materialize:\nverify Poseidon(eid || r) == blind_id"]
    end
```

> **Warning:** ZK mode uses Groth16/BLS12-381, which is **not post-quantum safe**.

---

## 16. Bridge Protocol

Cross-chain transfer via the three-phase protocol.

```mermaid
flowchart LR
    subgraph L1["L1 (Source Chain)"]
        LOCK["Lock tokens"] --> COMMIT["COMMIT\nErasure + encrypt\n+ log commit"]
    end

    subgraph Relay["Relay Layer"]
        LATTICE["LATTICE\nSealed key ~1.3KB\nML-KEM to L2 verifier"]
    end

    subgraph L2["L2 (Dest Chain)"]
        MAT["MATERIALIZE\nVerify + reconstruct"] --> MINT["Mint tokens"]
    end

    COMMIT --> LATTICE
    LATTICE --> MAT
```

---

## 17. Backend Architecture

Pluggable commitment backends behind a common interface.

```mermaid
flowchart TD
    IF["CommitmentBackend\n(Abstract Interface)\nappend_commitment()\nis_finalized()\nfetch_commitment()"]
    IF --> LOCAL["LocalBackend\nIn-memory\nPoC / tests"]
    IF --> MONAD["MonadL1Backend\n~500ms finality\n~10K TPS\nNative opcodes"]
    IF --> ETH["EthereumBackend\nL1: ~12.8 min finality\nL2: ~2s soft finality\nSmart contracts"]
```

Usage:
```python
from ltp.backends import BackendConfig, create_backend

backend = create_backend(BackendConfig(backend_type="ethereum", eth_use_l2=True))
ref = backend.append_commitment(entity_id, record_bytes, signature, sender_vk)
```
