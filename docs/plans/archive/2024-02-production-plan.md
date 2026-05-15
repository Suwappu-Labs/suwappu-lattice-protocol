> **Superseded** — archived 2026-05-15. See [`docs/plans/2026-05-11-production-roadmap.md`](../2026-05-11-production-roadmap.md) for current milestones.
> Retained for historical context; test counts ("821 tests") and timelines below are stale.

---

# ETP Production Implementation Plan

From PoC (current: 821 tests, in-memory, simulated crypto) to production-grade post-quantum bridge.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Operator["ETP Operator"]
        API["API Gateway\nFastAPI"] --- PROTO["Protocol Service\nLTPProtocol\nCommit / Lattice / Materialize"]
        LOG["Commitment Log Service\ngRPC\nAppend / STH Sign / Proofs"] --- SHARD["Shard Storage Nodes\ngRPC, n instances\nStore/Fetch / Audit / RocksDB"]
        PROTO --- LOG
        PROTO --- SHARD

        subgraph Bridge["Bridge Services"]
            ANCHOR["L1 Anchor\nWatch L1 events"] --- RELAY["Relayer\nSeal + transport"]
            RELAY --- MATL["L2 Materializer\nVerify + reconstruct"]
        end

        subgraph Storage["Storage Layer"]
            ROCKS["RocksDB\nMerkle tree + commitment records"]
            HSM["HSM/Vault\nOperator ML-DSA signing key"]
        end

        PROTO --- Bridge
        LOG --- Storage
    end
```

---

## Phase 1: Production Crypto Swap

**Goal:** Replace PoC BLAKE2b-HMAC simulations with real FIPS 203/204 implementations. Zero protocol logic changes — same API, real math.

### 1.1 Dependencies

```toml
# pyproject.toml additions
[project]
dependencies = [
    "liboqs-python>=0.15.0",   # ML-KEM-768 + ML-DSA-65 (FIPS 203/204)
    "PyNaCl>=1.5.0",           # XChaCha20-Poly1305 (libsodium)
    "zfec>=1.5.0",             # Reed-Solomon erasure coding
    "blake3>=1.0.0",           # BLAKE3-256 content addressing
]
```

| Component | PoC (current) | Production | Library |
|-----------|--------------|------------|---------|
| KEM | BLAKE2b lookup tables | ML-KEM-768 (FIPS 203) | liboqs-python |
| Signatures | BLAKE2b-HMAC lookup tables | ML-DSA-65 (FIPS 204) | liboqs-python |
| AEAD | BLAKE2b keystream + XOR | XChaCha20-Poly1305 | PyNaCl (libsodium) |
| Erasure | Pure Python GF(256) loops | C-optimized RS | zfec |
| Hashing | BLAKE2b-256 (stdlib) | BLAKE3-256 | blake3 |

**Why liboqs-python:** Most mature PQ library, Trail of Bits audited (2024), FIPS 203/204 final compliant, correct key sizes verified. The C compilation step is the main friction — mitigate with Docker base images that pre-install liboqs.

> **Current status (March 2026):** The implementation uses `pqcrypto` as the PQ backend. Migration to liboqs or pyca/cryptography (Issue #12824, targeting H1 2026 via BoringSSL/AWS-LC) is planned when stable APIs are available.

**Alternative path:** `pqcrypto` (`pip install pqcrypto`) has simpler install (pre-built wheels) but no security audit and no constant-time guarantees. Use for CI/dev; liboqs for production.

**Future:** pyca/cryptography ML-KEM support is tracked in Issue #12824, targeting H1 2026 via BoringSSL/AWS-LC backends (not OpenSSL). As of March 2026, no PQC APIs have been released.

### 1.2 Migration Steps

#### primitives.py — MLKEM class

```python
import oqs

class MLKEM:
    EK_SIZE = 1184
    DK_SIZE = 2400
    CT_SIZE = 1088
    SS_SIZE = 32

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        ek = kem.generate_keypair()  # returns ek, stores dk internally
        dk = kem.export_secret_key()
        return ek, dk

    @classmethod
    def encaps(cls, ek: bytes) -> tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        ct, ss = kem.encap_secret(ek)
        return ss, ct

    @classmethod
    def decaps(cls, dk: bytes, ciphertext: bytes) -> bytes:
        kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=dk)
        return kem.decap_secret(ciphertext)
```

- Remove `_PoC_dk_to_ek`, `_PoC_encaps_table`, `_POC_TABLE_MAX`
- Remove `reset_poc_state()` from MLKEM
- Remove the PoC `warnings.warn()`
- All existing tests should pass with identical key/ct sizes

#### primitives.py — MLDSA class

```python
class MLDSA:
    VK_SIZE = 1952
    SK_SIZE = 4032
    SIG_SIZE = 3309

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        sig = oqs.Signature("ML-DSA-65")
        vk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return vk, sk

    @classmethod
    def sign(cls, sk: bytes, message: bytes) -> bytes:
        sig = oqs.Signature("ML-DSA-65", secret_key=sk)
        return sig.sign(message)

    @classmethod
    def verify(cls, vk: bytes, message: bytes, signature: bytes) -> bool:
        sig = oqs.Signature("ML-DSA-65")
        return sig.verify(message, signature, vk)
```

- Remove `_PoC_sk_to_vk`, `_PoC_sig_table`
- Real ML-DSA verify is stateless — no lookup tables needed

#### primitives.py — AEAD class

```python
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,  # 24
    crypto_aead_xchacha20poly1305_ietf_ABYTES,      # 16
)

class AEAD:
    TAG_SIZE = 16  # Poly1305 (was 32 with BLAKE2b)
    NONCE_SIZE = 24  # XChaCha20 (was 16)

    @classmethod
    def encrypt(cls, key, plaintext, nonce, aad=b""):
        return crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key
        )

    @classmethod
    def decrypt(cls, key, ciphertext_with_tag, nonce, aad=b""):
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext_with_tag, aad, nonce, key
        )
```

**Breaking change:** TAG_SIZE 32→16, NONCE_SIZE 16→24. Update:
- `shards.py` nonce derivation: `H_bytes(...)[:24]` instead of `[:16]`
- `keypair.py` SealedBox format: nonce field grows from 16→24 bytes
- Total SealedBox overhead: 1088 + 24 + 16 = 1128 bytes (was 1088 + 16 + 32 = 1136)

#### primitives.py — Hashing

```python
import blake3

def H(data: bytes) -> str:
    return "blake3:" + blake3.blake3(data).hexdigest()

def H_bytes(data: bytes) -> bytes:
    return blake3.blake3(data).digest()
```

- Algorithm prefix changes from `blake2b:` to `blake3:`
- All existing hashes become invalid (expected — new deployment)
- 3-5x faster content addressing

#### erasure.py — ErasureCoder

```python
import zfec

class ErasureCoder:
    @classmethod
    def encode(cls, data: bytes, n: int, k: int) -> list[bytes]:
        length_prefix = struct.pack('>Q', len(data))
        padded = cls._pad(length_prefix + data, k)
        chunk_size = len(padded) // k
        chunks = [padded[i*chunk_size:(i+1)*chunk_size] for i in range(k)]
        encoder = zfec.Encoder(k, n)
        return encoder.encode(chunks)

    @classmethod
    def decode(cls, shards: dict[int, bytes], n: int, k: int) -> bytes:
        indices = sorted(shards.keys())[:k]
        share_data = [shards[i] for i in indices]
        decoder = zfec.Decoder(k, n)
        chunks = decoder.decode(share_data, indices)
        result = b"".join(chunks)
        length = struct.unpack('>Q', result[:8])[0]
        return result[8:8 + length]
```

- ~1000x faster (C vs pure Python)
- Same GF(256) math, same k-of-n semantics
- Remove `_GF_EXP`, `_GF_LOG`, `_init_gf`, `_gf_mul`, `_gf_inv`, `_invert_vandermonde`

### 1.3 Test Strategy

- All 821 existing tests must pass after swap
- Key sizes are identical → no structural changes to tests
- Add integration test: round-trip with real ML-KEM encaps/decaps
- Add test: verify ML-DSA signature created by one process, verified by another (no shared state)
- Remove tests that depend on PoC behavior (`reset_poc_state`, `_PoC_sig_table`)

### 1.4 Estimated Effort

| Task | Effort |
|------|--------|
| Replace MLKEM/MLDSA bodies | 1 day |
| Replace AEAD (nonce/tag size changes) | 1 day |
| Replace ErasureCoder with zfec | 0.5 day |
| Replace H/H_bytes with BLAKE3 | 0.5 day |
| Update SealedBox format for new nonce/tag | 0.5 day |
| Fix all tests | 1 day |
| Docker image with liboqs | 0.5 day |
| **Total** | **~5 days** |

---

## Phase 2: Persistent Storage

**Goal:** Replace in-memory data structures with durable storage. Survives process restart.

### 2.1 Merkle Tree → RocksDB

Current: `MerkleTree` stores nodes in a Python list (`self._nodes`).

Production:
- **RocksDB** via `python-rocksdb` for the Merkle tree and commitment records
- Key schema: `tree:L:{level}:I:{index}` → 32-byte hash
- Leaf schema: `leaf:{index}` → serialized `CommitmentRecord.to_bytes()`
- Entity index: `entity:{entity_id}` → leaf index (for O(1) lookup)

Why RocksDB:
- LSM-tree optimized for write-heavy append workloads
- Used by Ethereum (geth), RocksDB-backed Merkle trees are battle-tested
- Write-ahead log provides crash recovery
- Sub-millisecond lookups for proof generation

Alternative considered: **Merkle Mountain Range (MMR)** — better for very large trees (10M+ entries) since it's truly append-only at the storage level. Evaluate when tree exceeds 1M entries.

### 2.2 Shard Storage → gRPC Nodes + Local Disk

Current: `CommitmentNode.shards` is a Python dict.

Production:
- Each shard node runs a gRPC daemon
- Shards stored in local RocksDB keyed by `H(entity_id || shard_index)`
- Shard repair: surviving replicas push to replacement nodes on failure detection
- Heartbeat monitoring: miss 3 consecutive → suspected failed → initiate repair after 5min

### 2.3 Commitment Log Replication

Single-operator model (Phase 2):
- One operator runs the append-only log
- Publishes ML-DSA-signed STH after each append
- External auditors poll STH endpoint and verify monotonicity

Multi-operator model (Phase 4+):
- Independent operators, each with their own log
- STH gossip via libp2p gossipsub or HTTP polling
- Fork detection via STH comparison (no consensus needed — CT model)

### 2.4 Estimated Effort

| Task | Effort |
|------|--------|
| RocksDB MerkleTree backend | 3 days |
| RocksDB CommitmentRecord store | 2 days |
| gRPC shard node daemon | 3 days |
| Shard repair protocol | 2 days |
| STH publishing endpoint | 1 day |
| Integration tests with persistent storage | 2 days |
| **Total** | **~13 days** |

---

## Phase 3: API Layer + Serialization

**Goal:** Expose the protocol over the network. Replace Python dataclasses with wire-format serialization.

### 3.1 Protocol Buffers

```protobuf
syntax = "proto3";
package etp.v1;

message BridgeMessage {
  string msg_type = 1;
  string source_chain = 2;
  string dest_chain = 3;
  string sender = 4;
  string recipient = 5;
  bytes payload = 6;
  uint64 nonce = 7;
  double timestamp = 8;
}

message RelayPacket {
  bytes sealed_key = 1;     // ~1.1KB ML-KEM sealed blob
  string source_chain = 2;
  string dest_chain = 3;
  uint64 nonce = 4;
  uint64 source_block = 5;
  string entity_id = 6;
}

message CommitmentProof {
  string entity_id = 1;
  uint64 leaf_index = 2;
  repeated bytes proof_hashes = 3;
  bytes root_hash = 4;
  bytes sth_signature = 5;
}

service ETPBridge {
  rpc CommitMessage(BridgeMessage) returns (BridgeCommitment);
  rpc RelayPacket(BridgeCommitment) returns (RelayPacket);
  rpc Materialize(RelayPacket) returns (MaterializeResult);
  rpc GetInclusionProof(ProofRequest) returns (CommitmentProof);
}
```

### 3.2 API Split

| Interface | Protocol | Use Case |
|-----------|----------|----------|
| Internal (node↔node) | gRPC + Protobuf | Shard storage/fetch, relay transport |
| External (client-facing) | REST (FastAPI) + JSON | Bridge message submission, proof queries |
| Monitoring | Prometheus metrics | Operational visibility |

### 3.3 Estimated Effort

| Task | Effort |
|------|--------|
| Protobuf schema + codegen | 1 day |
| gRPC service implementations | 3 days |
| FastAPI REST gateway | 2 days |
| Prometheus metrics | 1 day |
| End-to-end integration tests | 2 days |
| **Total** | **~9 days** |

---

## Phase 4: On-Chain Bridge Verification

**Goal:** Deploy L1 smart contracts that verify ETP commitments on-chain, enabling trustless L1↔L2 bridging.

### 4.1 The ML-DSA On-Chain Problem

Direct ML-DSA-65 verification in Solidity costs **50-200M gas** (exceeds block gas limit). Not feasible.

**Solution: zkVM-wrapped verification.** Prove ML-DSA signature validity + Merkle inclusion inside a zkVM, verify the succinct proof on-chain.

### 4.2 Three-Phase Bridge Rollout

#### Phase 4a: Optimistic Bridge (fastest to market)

```
Operator posts STH root → L1 contract
  └── 7-day challenge period
  └── Watchers verify ML-DSA off-chain
  └── Fraud proof = show inconsistent STH
Users submit Merkle proof → execute withdrawal (~60-100K gas)
```

- Gas cost: ~60,000-100,000 per withdrawal
- Latency: 7-day challenge period
- Trust: 1-of-n honest watcher

#### Phase 4b: ZK-Verified Bridge (production target)

```
Operator posts STH root + zkVM proof → L1 contract
  └── Proof attests: "ML-DSA signature on this STH is valid"
  └── No challenge period (validity proof = instant finality)
Users submit Merkle proof → execute withdrawal
```

- **zkVM options:** SP1 (Succinct) or RISC Zero
  - Write ML-DSA verifier in Rust (reuse existing crate)
  - zkVM proves execution → SNARK for on-chain verification
- Gas cost: ~300-500K per root update (amortized across batch); ~60-100K per withdrawal
- Latency: Minutes (proving time)
- Trust: Cryptographic soundness only

#### Phase 4c: STARK Bridge (full PQ security)

- Replace SNARK wrapper with STARK for end-to-end post-quantum security
- SNARK proofs use pairing-based crypto (not PQ-safe) — STARKs use only hashes
- Options: Cairo/Starknet, or STARK-native zkVM
- Gas cost: ~500K-1M per root update (or amortized via shared provers)

### 4.3 L1 Contract Structure

```solidity
contract ETPBridge {
    bytes32 public latestRoot;
    uint256 public latestSequence;
    mapping(bytes32 => bool) public executed;

    // Phase 4a: optimistic
    function proposeRoot(bytes32 root, uint256 seq) external onlyOperator;
    function challengeRoot(uint256 seq, bytes calldata proof) external;

    // Phase 4b: validity
    function updateRoot(bytes32 root, uint256 seq, bytes calldata zkProof) external;

    // Withdrawal execution (both phases)
    function executeWithdrawal(
        bytes calldata message,
        bytes32[] calldata merkleProof,
        uint256 leafIndex
    ) external;
}
```

**Hash choice for on-chain proofs:**
- Option A: keccak256 (native EVM, cheapest: ~5K gas for 20-level proof)
- Option B: BLAKE2b via EIP-152 precompile (~8-15K gas, hash-consistent with off-chain)
- Recommendation: keccak256 on-chain, BLAKE3 off-chain. The bridge contract maintains its own keccak256 Merkle commitment derived from the operator's posted root.

### 4.4 Estimated Effort

| Task | Effort |
|------|--------|
| Phase 4a: Optimistic L1 contract | 5 days |
| Phase 4a: Watcher service | 3 days |
| Phase 4b: ML-DSA verifier in Rust (for zkVM) | 3 days |
| Phase 4b: SP1/RISC Zero integration | 5 days |
| Phase 4b: L1 SNARK verifier contract | 3 days |
| Phase 4c: STARK migration (Cairo or STARK zkVM) | 10 days |
| Solidity tests + audit prep | 5 days |
| **Total** | **~34 days** |

---

## Phase 5: Production Hardening

### 5.1 Key Management

| Key | Protection | Storage |
|-----|-----------|---------|
| Operator ML-DSA sk (STH signing) | HSM (AWS CloudHSM / YubiHSM 2) | Never on disk |
| Bridge relayer ML-KEM dk | HashiCorp Vault (encrypted at rest) | Loaded to memory at startup |
| CEKs | Ephemeral | Generated per entity, transmitted in sealed key, never stored |
| Node mTLS certs | Standard PKI | Auto-rotated via cert-manager |

### 5.2 Monitoring & Alerting

| Metric | Alert Threshold |
|--------|----------------|
| Node audit failure rate | > 5% → data loss risk |
| STH publishing gap | > 60s → log service may be down |
| Nonce monotonicity violation | Any → replay attack attempt |
| Materialize failure spike | > 10% → network partition or shard loss |
| Bridge message age | > finality threshold → oracle stale |
| Shard fetch latency p99 | > 500ms → node degradation |

Stack: Prometheus + Grafana for metrics, structured JSON logs via Loki, distributed tracing with correlation IDs per transfer.

### 5.3 Container Architecture

```yaml
# docker-compose.yml (development)
services:
  api-gateway:        # FastAPI REST
  protocol-service:   # Core LTP (commit/lattice/materialize)
  log-service:        # Merkle tree + STH signing
  shard-node-1:       # Encrypted shard storage (US-East)
  shard-node-2:       # (US-West)
  shard-node-3:       # (EU-West)
  bridge-anchor:      # L1 event watcher → commit
  bridge-relayer:     # Seal + transport
  bridge-materializer: # L2 verify + reconstruct
  finality-oracle:    # L1 block confirmation tracker
  prometheus:         # Metrics collection
  grafana:            # Dashboards
```

Production: Kubernetes with Helm charts. Each shard node as a StatefulSet with persistent volumes.

---

## Execution Timeline

| Phase | Duration | Cumulative | Deliverable |
|-------|----------|-----------|-------------|
| **1: Crypto Swap** | 5 days | Week 1 | Real FIPS 203/204 + XChaCha20 + zfec + BLAKE3 |
| **2: Persistent Storage** | 13 days | Week 3-4 | RocksDB Merkle tree + gRPC shard nodes |
| **3: API Layer** | 9 days | Week 5-6 | Protobuf + gRPC + REST + monitoring |
| **4a: Optimistic Bridge** | 8 days | Week 7-8 | L1 contract + watcher (7-day finality) |
| **4b: ZK Bridge** | 11 days | Week 9-11 | zkVM proof + instant finality |
| **5: Hardening** | 5 days | Week 12 | HSM, monitoring, container orchestration |
| **4c: STARK Bridge** | 10 days | Week 13-14 | Full PQ on-chain verification |

**Total: ~14 weeks** from PoC to production-ready PQ bridge with full on-chain verification.

```mermaid
gantt
    title Execution Timeline
    dateFormat  YYYY-MM-DD
    axisFormat  Week %W

    section Phase 1
    Crypto Swap           :p1, 2026-04-01, 5d

    section Phase 2
    Persistent Storage    :p2, after p1, 13d

    section Phase 3
    API Layer             :p3, after p2, 9d

    section Phase 4a
    Optimistic Bridge     :p4a, after p3, 8d

    section Phase 4b
    ZK Bridge             :p4b, after p4a, 11d

    section Phase 5
    Hardening             :p5, after p4b, 5d

    section Phase 4c
    STARK Bridge          :p4c, after p5, 10d
```

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|-----------|
| liboqs-python compilation fails on target platform | Blocks Phase 1 | Docker base image with pre-built liboqs; fallback to pqcrypto |
| zfec GPL license incompatible with project license | Blocks Phase 1 | Use pyeclib (BSD) with liberasurecode backend |
| ML-DSA on-chain verification gas too high even via zkVM | Blocks Phase 4b | Stay on optimistic bridge (Phase 4a); batch more proofs |
| BLAKE3 introduces dependency on Rust toolchain | Complicates CI | Keep BLAKE2b (stdlib) as fallback; BLAKE3 is optional optimization |
| pyca/cryptography adds ML-KEM before we ship | Opportunity | Migrate from liboqs to pyca/cryptography for better ecosystem integration |
| Tag size change (32→16) breaks existing sealed keys | Data migration | Version the SealedBox format; old keys use v1 (32B tag), new use v2 (16B) |

---

## Decision Log

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| PQ crypto library | liboqs-python | pqcrypto, fips203/fips204 | Most mature, audited, FIPS compliant |
| AEAD | XChaCha20-Poly1305 (PyNaCl) | AES-256-GCM, ChaCha20-Poly1305 | 24B nonce (safe with derived nonces), constant-time, most audited |
| Erasure coding | zfec | pyeclib, Intel ISA-L | Simplest API, native k-of-n semantics, fast C impl |
| Content hashing | BLAKE3 | Keep BLAKE2b | 3-5x faster, tree hashing built-in, algorithm-prefixed format allows migration |
| Merkle storage | RocksDB | LMDB, PostgreSQL, SQLite | Write-optimized LSM tree, crash recovery, proven in blockchain systems |
| On-chain verification | zkVM (SP1) → SNARK | Direct Solidity, STARK-only, optimistic-only | Best balance of gas cost (~300K), proving time, and PQ migration path |
| Wire format | Protobuf | CBOR, MessagePack, JSON | Code generation, streaming, gRPC native, schema evolution |
| Log replication | CT-style STH gossip | Raft consensus, PBFT | No consensus needed for append-only + fork detection model |
