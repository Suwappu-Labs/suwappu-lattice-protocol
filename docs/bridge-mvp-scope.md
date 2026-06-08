# ETP Bridge MVP — L1↔L2 Cross-Chain Transfer via Lattice Protocol

## Problem Statement

Blockchain bridges are the #1 attack surface in crypto ($2.8B+ stolen 2021–2024).
The root causes are consistent:

- **Compromised relay keys** (Ronin: 5-of-9 multisig stolen → $624M)
- **Missing message validation** (Wormhole: forged guardian signatures → $326M)
- **Broken commitment verification** (Nomad: bad Merkle root init → $190M)
- **No quantum resistance** (all current bridges use ECDSA/EdDSA — broken by CRQC)

ETP's primitives directly address each of these:

| Bridge Weakness | ETP Primitive |
|---|---|
| Key compromise → full drain | ML-KEM forward secrecy (fresh encapsulation per message) |
| Forged attestations | ML-DSA-65 signatures on CT-style Merkle log |
| Missing DA proofs | Erasure-coded shards with O(log n) inclusion proofs |
| Single-point relay | Sealed lattice key is self-authenticating (no trusted relay) |
| No quantum resistance | ML-KEM-768 + ML-DSA-65 (NIST Level 3) |

## Architecture

```mermaid
flowchart LR
    subgraph L1["L1 (Source Chain)"]
        COMMIT["1. COMMIT\nLock tokens\nErasure code\nEncrypt\nLog commit"]
    end

    subgraph Relay["Relay Layer"]
        LATTICE["2. LATTICE\nSealed key ~1.3KB\nML-KEM sealed\nto L2 verifier"]
    end

    subgraph L2["L2 (Dest Chain)"]
        MAT["3. MATERIALIZE\nVerify + mint\nReconstruct\nExecute"]
    end

    COMMIT --> LATTICE --> MAT
```

### Phase Mapping: ETP → Bridge

| ETP Phase | Bridge Operation | What Happens |
|---|---|---|
| **COMMIT** | Lock & Attest on L1 | User locks tokens in L1 contract. Bridge operator erasure-encodes the lock event (amount, recipient, nonce), encrypts shards with a fresh CEK, distributes to DA nodes, and appends a signed commitment record to the Merkle log. |
| **LATTICE** | Relay Sealed Key | The bridge operator seals a LatticeKey (containing entity_id + CEK + commitment_ref) to the L2 verifier's ML-KEM public key. Only this ~1.3KB sealed blob crosses the chain gap. The relay is untrusted — it cannot read or forge the sealed key. |
| **MATERIALIZE** | Verify & Mint on L2 | L2 verifier unseals the key, fetches the commitment record from the log, verifies the ML-DSA signature chain, fetches and decrypts shards, reconstructs the lock event, verifies the EntityID integrity hash, and mints equivalent tokens. |

## MVP Scope

### Core Types

```python
@dataclass
class BridgeMessage:
    """A cross-chain message (lock event, state transition, etc.)."""
    msg_type: str           # "token_lock", "state_update", "governance"
    source_chain: str       # "ethereum", "optimism", etc.
    dest_chain: str
    sender: str             # L1 address (hex)
    recipient: str          # L2 address (hex)
    payload: dict           # {token, amount, nonce, ...}
    nonce: int              # Replay protection (monotonic per sender)
    timestamp: float

@dataclass
class BridgeCommitment:
    """The L1-side commitment: wraps ETP CommitmentRecord with bridge metadata."""
    message: BridgeMessage
    entity_id: str
    commitment_ref: str
    merkle_proof: dict      # Inclusion proof from the commitment log
    source_block: int       # L1 block number (for finality tracking)
```

### Components

#### 1. `L1Anchor` — Source Chain Commitment

Wraps `LTPProtocol.commit()` with bridge-specific logic:

- Serializes `BridgeMessage` → `Entity` (canonical JSON → bytes)
- Validates nonce monotonicity (replay protection)
- Calls `protocol.commit()` → gets entity_id, record, CEK
- Generates Merkle inclusion proof for the commitment
- Returns `BridgeCommitment` + CEK (CEK stays off-chain)

#### 2. `Relayer` — Cross-Chain Key Transport

Wraps `LTPProtocol.lattice()`:

- Takes `BridgeCommitment` + CEK + L2 verifier's public key
- Calls `protocol.lattice()` → sealed key (~1.3KB)
- Packages sealed key + bridge metadata (source chain, dest chain, nonce)
- Returns `RelayPacket` — the only data that crosses chains
- **Trust model**: Relayer is untrusted. It transports an opaque sealed blob.
  It cannot read the CEK, cannot forge the commitment, and cannot redirect
  to a different recipient (sealed to specific L2 verifier key).

#### 3. `L2Materializer` — Destination Chain Verification

Wraps `LTPProtocol.materialize()` with bridge verification:

- Unseals the lattice key (ML-KEM decapsulation)
- Fetches commitment record from the shared log
- Verifies ML-DSA signature chain (operator → commitment)
- Verifies Merkle inclusion proof (commitment in log)
- Reconstructs the `BridgeMessage` from shards
- Validates bridge-specific invariants:
  - Nonce hasn't been processed before (replay protection)
  - dest_chain matches this chain
  - source_block has sufficient finality confirmations
- Returns the verified `BridgeMessage` for execution (mint, unlock, etc.)

### Security Properties

1. **PQ-secure relay**: ML-KEM-768 seals the CEK. A quantum computer that breaks
   ECDSA (every existing bridge) cannot break the relay layer.

2. **Forward secrecy per message**: Each `lattice()` call generates a fresh
   ML-KEM encapsulation. Compromising one relay packet doesn't compromise others.

3. **Append-only audit trail**: The Merkle log with ML-DSA STHs provides
   cryptographic proof that commitments are immutable and ordered. Any fork
   (equivocation) is detectable.

4. **Data availability**: Erasure coding means the bridge message survives
   partial DA node failures (k-of-n reconstruction).

5. **Self-authenticating messages**: The EntityID = H(content || shape || ts || vk)
   binds the message content to the commitment. Substitution attacks are detected
   at materialize time.

6. **Untrusted relay**: The relayer transports an opaque sealed blob. It cannot:
   - Read the message (encrypted CEK)
   - Forge the commitment (ML-DSA signed)
   - Redirect to wrong recipient (ML-KEM sealed to specific key)
   - Replay old messages (nonce + commitment_ref binding)

### What the MVP Does NOT Include

- **Smart contract integration** — Smart contract integration is underway — LTPAnchorRegistry (UUPS proxy) and LTPMultiSig are deployed on SUWAPPU Testnet (Chain ID 103115120)
- **Multi-relayer consensus** — single relayer (trust assumptions documented)
- **Fee mechanism** — no economic incentives/slashing
- **Finality oracle** — L1 block finality is simulated (configurable parameter)
- **Cross-log synchronization** — single shared CommitmentLog
- **Token standards** — no ERC-20/721 wrapping logic
- **Dual-lane hashing** — The protocol uses a dual-lane hashing architecture: SHA3-256 for canonical/on-chain paths and BLAKE3-256 for internal/performance paths

### File Layout

```
src/ltp/bridge/
├── __init__.py          # Public API exports
├── message.py           # BridgeMessage, BridgeCommitment, RelayPacket
├── anchor.py            # L1Anchor — source chain commitment
├── relayer.py           # Relayer — cross-chain sealed key transport
└── materializer.py      # L2Materializer — dest chain verify + reconstruct

# Monotonic sequencing lives in src/ltp/sequencing.py::SequenceTracker
# (VK-fingerprint keyed, chain-bound, temporal expiry — supersedes the
# old bridge/nonce.py which has been removed)

tests/
└── test_bridge.py       # End-to-end: lock → relay → verify → mint
```

### End-to-End Test Scenario

```
1. Alice locks 100 USDC on L1 (Ethereum)
2. L1Anchor commits the lock event → entity_id, Merkle proof, CEK
3. Relayer seals the key to L2 verifier → RelayPacket (~1.3KB)
4. L2Materializer on Optimism:
   a. Unseals the key
   b. Verifies commitment + ML-DSA signature
   c. Verifies Merkle inclusion proof
   d. Reconstructs the lock event from shards
   e. Validates: nonce fresh, dest_chain correct, EntityID matches
5. Bridge mints 100 USDC to Alice on L2
6. Replay attempt with same nonce → REJECTED
7. Tampered relay packet → ML-KEM unseal FAILS
8. Tampered commitment record → ML-DSA verification FAILS
```

## Next Steps (Post-MVP)

1. **Multi-relayer with threshold attestation** — require t-of-n relayers to
   independently produce sealed keys, adding Byzantine fault tolerance
2. **On-chain light client** — verify STH signatures and Merkle proofs in
   a Solidity/Cairo/Noir verifier contract
3. **Bidirectional bridge** — L2→L1 materialization (withdrawal path)
4. **Finality oracle integration** — watch L1 for confirmed blocks before
   L2 execution
5. **Production crypto hardening** — integrate liboqs ML-KEM/ML-DSA for remaining PoC paths
