# Threat Model — Entanglement Transfer Protocol

**Version:** 1.0
**Date:** 2026-03-29
**Framework:** STRIDE + PQC-specific threat categories

This document identifies assets, threat sources, and categorized threats for the
Entanglement Transfer Protocol (ETP/LTP). For the full protocol specification,
see the [Whitepaper](WHITEPAPER.md). For implementation details, see the
[Architecture](design-decisions/ARCHITECTURE.md).

---

## 1. Protocol Overview

ETP transfers data via three phases:

1. **COMMIT** — Sender erasure-codes content into n shards, encrypts each with a
   random CEK via AEAD, distributes encrypted shards to commitment nodes, and
   signs a Merkle root commitment record with ML-DSA-65.

2. **LATTICE** — Sender seals a ~1.3KB lattice key (entity_id + CEK + commitment_ref)
   to the receiver using ML-KEM-768 envelope encryption.

3. **MATERIALIZE** — Receiver unseals the lattice key, verifies the commitment
   signature, fetches k-of-n shards, decrypts, and reconstructs the original content.

**On-chain settlement:** Commitment digests are anchored on-chain via LTPAnchorRegistry
(UUPS proxy) governed by MultiSig → Timelock → Registry.

---

## 2. Assets

| Asset | Description | Confidentiality | Integrity | Availability |
|-------|-------------|:-:|:-:|:-:|
| **Content Encryption Key (CEK)** | Random 256-bit key encrypting all shards of an entity | Critical | High | Medium |
| **Sealed Lattice Key** | ML-KEM-768 encrypted blob containing CEK + entity_id | Critical | High | Medium |
| **Plaintext Content** | Original entity data before commitment | Critical | High | Low |
| **Encrypted Shards** | AEAD-encrypted fragments stored on commitment nodes | Low (encrypted) | High | High |
| **Merkle Root** | Hash of encrypted shard set — commitment integrity anchor | N/A | Critical | High |
| **ML-DSA-65 Signing Keys** | Private keys for commitment signatures | Critical | Critical | High |
| **ML-KEM-768 Decapsulation Keys** | Private keys for unsealing lattice keys | Critical | Critical | High |
| **Commitment Records** | Signed, append-only log entries | Low | Critical | High |
| **Bridge Nonces** | Replay protection counters for cross-chain transfers | Low | High | High |
| **Governance Keys** | MultiSig owner keys controlling contract upgrades | Critical | Critical | Critical |

---

## 3. Threat Sources

| Source | Capability | Motivation |
|--------|-----------|------------|
| **Network Attacker** | Intercept, modify, replay network traffic. Active MitM. | Steal content, impersonate parties |
| **Malicious Commitment Node** | Store/serve encrypted shards, observe access patterns | Collude to reconstruct content, withhold shards |
| **Compromised Bridge Relayer** | Relay or withhold sealed keys between L1/L2 | Intercept cross-chain transfers, replay attacks |
| **Quantum Adversary** | Future quantum computer capable of breaking classical crypto | Harvest Now, Decrypt Later (HNDL) |
| **Governance Attacker** | Compromise MultiSig owner key(s) | Upgrade contract maliciously, pause operations |
| **Insider Threat** | Access to signing keys, deployment infrastructure | Exfiltrate keys, forge commitments |

---

## 4. Threats by Category

### 4.1 Spoofing (S)

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| S1 | Attacker impersonates Sender by forging commitment signatures | Low | Critical | ML-DSA-65 signatures on all commitment records; verification in MATERIALIZE phase | Key compromise (addressed by key rotation) |
| S2 | Attacker impersonates Receiver to unseal lattice keys | Low | Critical | ML-KEM-768 sealed to receiver's specific encapsulation key | Key compromise of receiver's DK |
| S3 | Bridge relayer forges relay packets | Low | High | Sealed keys are ML-KEM encrypted; relayer cannot read/modify content | Relayer can delay or drop packets (availability) |

### 4.2 Tampering (T)

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| T1 | Modify encrypted shards in storage | Low | High | Merkle root verification at MATERIALIZE; AEAD authentication tag | Node must collude with >n-k nodes to make reconstruction fail |
| T2 | Tamper with commitment record | Low | Critical | ML-DSA-65 signature + append-only Merkle log; fork detection via signed tree heads | Log operator compromise |
| T3 | Tamper with on-chain anchor digest | Low | Critical | UUPS proxy admin is Timelock (60s testnet / 24h+ production); MultiSig threshold | Governance key compromise |
| T4 | Modify sealed lattice key in transit | Low | High | AEAD authentication in ML-KEM envelope | Decryption fails; detected at MATERIALIZE |

### 4.3 Repudiation (R)

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| R1 | Sender denies having committed an entity | Low | Medium | ML-DSA-65 non-repudiation; commitment record signed with sender's key | Key compromise allows plausible deniability |
| R2 | Node denies having stored a shard | Medium | Medium | PDP (Proof of Data Possession) challenges; slashing for audit failures | Colluding nodes with >k shards |

### 4.4 Information Disclosure (I)

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| I1 | **HNDL: Harvest encrypted traffic now, decrypt with future quantum computer** | Medium | Critical | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) — post-quantum safe. Forward secrecy via fresh encapsulation per transfer | Algorithm break (no known attack on MLWE) |
| I2 | Shard collusion: <k nodes collude to reconstruct content | Low | Critical | Information-theoretic security: <k shards reveal zero information about content (erasure coding property) | ≥k nodes colluding defeats threshold |
| I3 | CEK leakage via side-channel | Low | Critical | CEK generated via os.urandom(); nonce derived from CEK+entity_id (defense-in-depth) | Timing/power side-channels on KEM operations |
| I4 | Metadata leakage: access patterns reveal who transfers to whom | Medium | Medium | Encrypted shards are content-addressed; lattice key size is constant (O(1)) regardless of content | Network-level traffic analysis |
| I5 | ZK mode weakness: Groth16/BLS12-381 is NOT post-quantum safe | High (if used) | Critical | ZK mode explicitly documented as non-PQ-safe; standard mode recommended for quantum threat models | Users must opt out of ZK mode |

### 4.5 Denial of Service (D)

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| D1 | Nodes withhold shards, preventing materialization | Medium | High | Erasure coding: only k-of-n shards needed; multiple replicas across regions | Coordinated node attack exceeding n-k threshold |
| D2 | Flood commitment log with junk entries | Medium | Medium | Staking requirement; rate limiting on anchor client; circuit breaker | Sufficiently funded attacker |
| D3 | Bridge relayer drops relay packets | Medium | Medium | Receiver can detect missing relay; multiple relayers for redundancy | Single-relayer deployments |
| D4 | Governance attack: pause contract | Low | High | MultiSig threshold prevents single-key pause; Timelock delay for upgrades | Compromised MultiSig quorum |

### 4.6 Elevation of Privilege (E)

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| E1 | Bypass MultiSig to upgrade contract | Low | Critical | UUPS `_authorizeUpgrade()` gated to Timelock admin; 2-of-2 MultiSig threshold | Compromised MultiSig + Timelock in window |
| E2 | Unauthorized signer registration | Low | High | `registerSigner()` requires admin (Timelock) authorization; per-signer sequence tracking | Governance key compromise |
| E3 | Cross-parity exploit: trigger Solidity-only state transition from Python | Low | Medium | Documented intentional divergence (UNKNOWN→ANCHORED Solidity-only); formally verified in CrossParityTest | Undiscovered divergences |

### 4.7 PQC-Specific Threats

| ID | Threat | Likelihood | Impact | Mitigation | Residual Risk |
|----|--------|:----------:|:------:|------------|---------------|
| PQ1 | **Harvest Now, Decrypt Later (HNDL)** — adversary stores sealed keys for future quantum decryption | Medium | Critical | ML-KEM-768 is NIST-standardized PQC (FIPS 203); resistant to known quantum attacks on MLWE | Unforeseen breakthrough in lattice cryptanalysis |
| PQ2 | Side-channel attack on ML-KEM encapsulation/decapsulation | Low | High | Constant-time implementation goal; real backend (pqcrypto) uses reference C code | Python GC/allocation timing leaks; PoC simulation not constant-time |
| PQ3 | Implementation divergence between PoC simulation and real backend | Medium | High | ACVP test vector validation; backend detection with automatic fallback | PoC tables are LRU-bounded and non-deterministic |
| PQ4 | Algorithm migration risk during hybrid period | Low | Medium | Hybrid signatures (ML-DSA-65 + Ed25519) via composite signing; algorithm registry for agility | Transition-period vulnerabilities |

---

## 5. Out of Scope

These threats are explicitly NOT addressed by this threat model:

- **Operating system compromise** — if the host OS is compromised, all bets are off
- **Hardware attacks** — physical access to machines running ETP nodes
- **Social engineering** — phishing for governance keys, etc.
- **Denial of service at the network layer** — DDoS on node infrastructure
- **Bugs in Python stdlib** — report to Python Security Response Team
- **Bugs in OpenZeppelin contracts** — report to OpenZeppelin
- **Economic attacks on the incentive model** — separate analysis needed

---

## 6. Security Verification Status

| Mechanism | Verification | Status |
|-----------|-------------|--------|
| ML-KEM-768 key sizes | FIPS 203 Table 3 | Verified in test suite |
| ML-DSA-65 key sizes | FIPS 204 Table 1 | Verified in test suite |
| State machine transitions | 36 transition pairs exhaustive | Verified (Python + Solidity) |
| Python↔Solidity parity | CrossParityTest | Verified (10 Python / 11 Solidity transitions) |
| Erasure coding | k-of-n reconstruction | 1,167 Python tests |
| Smart contract | Fuzz (256 iter) + Invariant (3,840 calls) | 84 Solidity tests |
| ACVP test vectors | NIST ML-KEM-768 + ML-DSA-65 | Added (requires pqcrypto backend) |

---

## 7. Recommendations for Audit

Priority items for an independent security audit:

1. **Cryptographic implementation review** — PoC simulation correctness, real backend integration, nonce derivation
2. **Smart contract audit** — UUPS upgrade safety, access control, reentrancy, storage layout
3. **Protocol design review** — 3-phase security properties, sealed key confidentiality, forward secrecy
4. **Cross-parity validation** — Python↔Solidity state machine completeness
5. **Side-channel assessment** — timing behavior of KEM/DSA operations in Python
