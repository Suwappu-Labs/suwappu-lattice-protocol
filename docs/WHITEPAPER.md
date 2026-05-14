<div align="center">

# LTP: Lattice Transfer Protocol

### Whitepaper

<br>

*A data transfer protocol in which no data payload is transmitted between sender and receiver.*
*The sender commits. The receiver materializes. No payload crosses the sender–receiver link.*

<br>

| **Author** | **Version** | **Date** | **Status** | **Classification** |
|:----------:|:-----------:|:--------:|:----------:|:------------------:|
| Jas Strokus | 0.1.0-draft | 2026-03-29 | Protocol Draft | Public |

</div>

<br>

---

**Overview**

LTP inverts the data transfer paradigm. Rather than transmitting a payload from sender to
receiver, the sender **commits** an immutable, content-addressed, erasure-coded entity to a
distributed commitment layer and delivers a constant-size cryptographic **lattice key**
(~1,300 bytes) to the receiver. The receiver **materializes** the entity from geographically
nearby commitment nodes — achieving O(1) sender→receiver bandwidth independent of entity
size, with full post-quantum security as a default.

**Core guarantees:**

| Property | Guarantee | Primitive |
|:---------|:----------|:----------|
| Sender→receiver path | O(1) constant-size sealed key, independent of entity size | ML-KEM-768 (FIPS 203) |
| Immutability | Content-addressed EntityID — any modification produces a different identity | BLAKE3-256 |
| Threshold secrecy | Fewer than *k* shards reveal zero information about entity content | Information-theoretic |
| Non-repudiation | Append-only signed commitment record on a Merkle log | ML-DSA-65 (FIPS 204) |
| Post-quantum security | Standard mode fully PQ-safe — no X25519 or Ed25519 in the protocol | ML-KEM + ML-DSA + BLAKE3 |
| ZK privacy mode | Hiding commitment for EntityID fingerprinting prevention | Groth16 / BLS12-381 ⚠ |

> ⚠ **ZK mode is not post-quantum safe.** Groth16 over BLS12-381 is broken by Shor's
> algorithm. Standard mode is fully post-quantum. See §3.2.4 for the planned upgrade path.

**Keywords:** distributed systems · post-quantum cryptography · content-addressed storage ·
erasure coding · capability-based access control · append-only audit logs · ML-KEM-768 ·
ML-DSA-65 · BLAKE3 · Certificate Transparency · Reed-Solomon coding

---

## Table of Contents

---

**Preliminary Sections**

- [Abstract](#abstract)
- [Note on Terminology](#note-on-terminology)

---

**Clauses**

- [1. The Ontology of Data Transfer](#1-the-ontology-of-data-transfer)
    - [1.1 What Is an "Entity"?](#11-what-is-an-entity)
        - [1.1.1 Shape Specification](#111-shape-specification)
    - [1.2 The Entity Identity Function](#12-the-entity-identity-function)
- [2. The Three Phases of Transfer](#2-the-three-phases-of-transfer)
    - [2.1 Phase 1: COMMIT](#phase-1-commit)
        - [2.1.1 Deterministic Sharding](#211-deterministic-sharding)
        - [2.1.2 Distributed Shard Placement](#212-distributed-shard-placement)
        - [2.1.3 The Commitment Record](#213-the-commitment-record)
    - [2.2 Phase 2: LATTICE](#phase-2-lattice)
        - [2.2.1 The Lattice Key](#221-the-lattice-key)
        - [2.2.2 Key Properties of the Lattice Key](#222-key-properties-of-the-lattice-key)
    - [2.3 Phase 3: MATERIALIZE](#phase-3-materialize)
        - [2.3.1 Reconstruction Process](#231-reconstruction-process)
        - [2.3.2 Why This Is Fast](#232-why-this-is-fast)
- [3. Security Model](#3-security-model)
    - [3.1 Threat Analysis](#31-threat-analysis)
    - [3.2 Zero-Knowledge Transfer Mode](#32-zero-knowledge-transfer-mode)
        - [3.2.1 Modified Commitment Record](#321-modified-commitment-record)
        - [3.2.2 ZK Proof Specification](#322-zk-proof-specification)
        - [3.2.3 Security Properties](#323-security-properties)
        - [3.2.4 Limitations and Honest Assessment](#324-limitations-and-honest-assessment)
    - [3.3 Formal Security Definitions](#33-formal-security-definitions)
        - [3.3.1 Entity Immutability (Collision Resistance)](#331-entity-immutability-collision-resistance)
        - [3.3.2 Shard Integrity (Second-Preimage Resistance)](#332-shard-integrity-second-preimage-resistance)
        - [3.3.3 Transfer Confidentiality (IND-CPA)](#333-transfer-confidentiality-ind-cpa)
        - [3.3.4 Commitment Non-Repudiation (EUF-CMA)](#334-commitment-non-repudiation-euf-cma)
        - [3.3.5 Threshold Secrecy (Information-Theoretic)](#335-threshold-secrecy-information-theoretic)
        - [3.3.6 Transfer Immutability (Composite Game)](#336-transfer-immutability-composite-game)
        - [3.3.7 What Cannot Be Formally Proven](#337-what-cannot-be-formally-proven)
- [4. Immutability Guarantees](#4-immutability-guarantees)
    - [4.1 Why Immutability Is Inherent](#41-why-immutability-is-inherent)
    - [4.2 Versioning vs. Mutation](#42-versioning-vs-mutation)
    - [4.3 Immutability ≠ Availability](#43-immutability--availability)
- [5. Commitment Network](#5-commitment-network)
    - [5.1 Bootstrap: How the Network Starts](#51-bootstrap-how-the-network-starts)
        - [5.1.1 Genesis Configuration](#511-genesis-configuration)
        - [5.1.2 Why Permissioned Genesis?](#512-why-permissioned-genesis)
        - [5.1.3 Progressive Decentralization](#513-progressive-decentralization)
        - [5.1.4 Commitment Log Trust Model](#514-commitment-log-trust-model)
            - [5.1.4.1 Minimum Conformance Requirements (CT-Style Merkle Log)](#5141-minimum-conformance-requirements-ct-style-merkle-log)
            - [5.1.4.2 Fork Detection and Consistency Verification](#5142-fork-detection-and-consistency-verification)
    - [5.2 Sybil Resistance](#52-sybil-resistance)
        - [5.2.1 Layer 1: Identity Verification](#521-layer-1-identity-verification)
        - [5.2.2 Layer 2: Storage Proofs](#522-layer-2-storage-proofs)
        - [5.2.3 Audit Protocol](#523-audit-protocol)
    - [5.3 Collusion Resistance](#53-collusion-resistance)
        - [5.3.1 Pre-Option-C (Broken)](#531-pre-option-c-broken)
        - [5.3.2 Post-Option-C (Mitigated)](#532-post-option-c-mitigated)
    - [5.4 Data Availability](#54-data-availability)
        - [5.4.1 Availability Model](#541-availability-model)
            - [5.4.1.1 Correlated Failure Model](#5411-correlated-failure-model)
        - [5.4.2 Failure Modes and Repair](#542-failure-modes-and-repair)
        - [5.4.3 The CAP Theorem and LTP](#543-the-cap-theorem-and-ltp)
        - [5.4.4 Availability vs. Permanence](#544-availability-vs-permanence)
    - [5.5 Network Economics (Interface, Not Implementation)](#55-network-economics-interface-not-implementation)
- [6. Breaking the Constraints](#6-breaking-the-constraints)
    - [6.1 Latency](#61-latency)
    - [6.2 Geographic Distance](#62-geographic-distance)
    - [6.3 Computing Power](#63-computing-power)
    - [6.4 Formal Cost Model](#64-formal-cost-model)
- [7. Comparison with Existing Approaches](#7-comparison-with-existing-approaches)
- [8. Related Work and Prior Art](#8-related-work-and-prior-art)
    - [8.1 Content-Addressed Storage](#81-content-addressed-storage)
    - [8.2 Erasure-Coded Distributed Storage](#82-erasure-coded-distributed-storage)
    - [8.3 Append-Only Commitment Logs](#83-append-only-commitment-logs)
    - [8.4 Capability-Based Security](#84-capability-based-security)
    - [8.5 Peer-to-Peer Content Distribution](#85-peer-to-peer-content-distribution)
    - [8.6 Hybrid and Convergent Systems](#86-hybrid-and-convergent-systems)
    - [8.7 What LTP Contributes](#87-what-ltp-contributes)
    - [References](#references)
- [9. Use Cases](#9-use-cases)
    - [9.1 Large File Fan-Out](#91-large-file-fan-out)
    - [9.2 Immutable Audit Trail](#92-immutable-audit-trail)
    - [9.3 Secure Messaging](#93-secure-messaging)
    - [9.4 State Synchronization](#94-state-synchronization)
    - [9.5 High-Latency Link Optimization](#95-high-latency-link-optimization)
- [10. Open Questions](#10-open-questions)
- [11. Conclusion](#11-conclusion)

---

**Appendices**

- [Appendix A: High-Latency Link Optimization (Thought Experiment)](#appendix-a-high-latency-link-optimization-thought-experiment)

---

### Note on Terminology

The name **"Lattice"** is deliberately chosen for its triple resonance with the protocol's design:

1. **Network lattice** — the distributed commitment nodes form a lattice topology through which
   shards are placed, replicated, and fetched from the nearest points
2. **Lattice-based cryptography** — the protocol's post-quantum primitives (ML-KEM-768 and
   ML-DSA-65) are founded on the hardness of the Module Learning With Errors problem, a
   lattice problem in algebraic number theory
3. **Mathematical lattice** — the erasure-coded shard space forms a partially ordered structure
   where any k-of-n subset is sufficient for reconstruction

The name does **not** imply any connection to quantum entanglement, quantum mechanics, or
quantum information theory. The protocol operates entirely within classical computing and
post-quantum cryptography.

---

## Abstract

We propose a data transfer protocol in which no data payload is transmitted between sender and
receiver. Instead, the sender **commits** an immutable, content-addressed representation of the
entity to a distributed commitment layer, transmits a minimal cryptographic **lattice key**
to the receiver, and the receiver **materializes** the entity through deterministic reconstruction
from distributed shards. The protocol achieves:

- **Decoupled transfer** — the sender→receiver path carries only a ~1,300-byte sealed key (ML-KEM-768), independent of entity size. Total system bandwidth is O(entity × replication), but the direct-path bottleneck is eliminated.
- **Immutability by design** — every transfer is a permanent, auditable commitment
- **Security without trust** — verification is mathematical, not institutional
- **Geography-optimized materialization** — the receiver fetches shards from the nearest available nodes, converting a long-haul transfer into parallel local fetches

> **⚠ ZK mode post-quantum warning:** Standard LTP is fully post-quantum — ML-KEM-768
> (FIPS 203), ML-DSA-65 (FIPS 204), BLAKE3-256, and information-theoretic erasure coding;
> no classical-only primitives. ZK transfer mode (§3.2) uses Groth16 over BLS12-381, which
> is vulnerable to Shor's algorithm and does **not** provide quantum-resistant hiding. **ZK
> mode MUST NOT be used in deployments with a quantum-adversary threat model.** The planned
> upgrade path is a STARK or lattice-based proof system (§3.2.4, §10 Open Question 8).

---

## 1. The Ontology of Data Transfer

### 1.1 What Is an "Entity"?

In LTP, we do not transfer "files," "packets," or "messages." We transfer **entities**. An entity
is any discrete, self-contained unit of state:

- A document
- A database row
- A video frame sequence
- A machine learning model
- An application state snapshot
- A human identity credential

An entity has three properties:
1. **Content** — the raw information (arbitrary bytes)
2. **Shape** — a canonical type descriptor that gives content meaning
3. **Identity** — a unique, deterministic fingerprint derived from content + shape

#### 1.1.1 Shape Specification

The **shape** field is a canonical, case-insensitive string that describes the semantic type
of the entity's content. It serves two purposes: (a) it allows the receiver to interpret the
reconstructed bytes, and (b) it participates in the EntityID hash, so the same content
committed with different declared shapes produces different entities.

**Format.** Shape MUST be one of:

| Category | Format | Examples |
|----------|--------|----------|
| IANA media type | `type/subtype` per [RFC 6838](https://datatracker.ietf.org/doc/html/rfc6838) | `text/plain`, `application/json`, `image/png` |
| Parameterized media type | `type/subtype; param=value` per [RFC 2045 §5](https://datatracker.ietf.org/doc/html/rfc2045#section-5) | `text/plain; charset=utf-8`, `application/json; schema=urn:ltp:medical-record:v1` |
| LTP extension type | `x-ltp/subtype` (reserved namespace for protocol-internal types) | `x-ltp/state-snapshot`, `x-ltp/credential-bundle` |

**Extension Type Registry.** The `x-ltp/` namespace is reserved for LTP-defined extension
types. To prevent independently developed implementations from assigning conflicting meanings
to the same subtype, new `x-ltp/` values MUST be registered before use. Registration is
lightweight: submit the subtype name, a one-paragraph semantic description, and a contact
to the LTP Extension Registry document maintained alongside this specification (see
`docs/extension-registry.md` in the reference repository). Unregistered subtypes SHOULD
be prefixed with a reverse-domain identifier (e.g., `x-ltp/com.example.my-type`) to avoid
collisions during local experimentation. IANA media types (`type/subtype`) do not require
LTP registration — they are governed by RFC 6838.

**Canonicalization rules:**
1. The `type` and `subtype` components are lowercased before hashing (per RFC 6838 §4.2)
2. Parameters are sorted lexicographically by parameter name
3. Whitespace around `;` and `=` delimiters is stripped
4. The canonical form is encoded as UTF-8 bytes for inclusion in the EntityID hash

**Interoperability invariant:** Two conforming LTP implementations that commit the same
content with the same declared shape MUST produce identical EntityIDs. The canonicalization
rules above guarantee this. An implementation that uses `TEXT/PLAIN` and one that uses
`text/plain` canonicalize to the same bytes and produce the same hash.

**Opaque content rule:** The shape is a *declared* type, not a *verified* type. LTP does
not parse or validate content against its shape. A sender may commit a PNG image with shape
`text/plain` — the EntityID will be valid, but the receiver will find the content
uninterpretable as text. Shape is metadata, not a constraint.

### 1.2 The Entity Identity Function

Every entity has a deterministic identity:

```
EntityID = H(content || shape || timestamp || sender_pubkey)
```

Where:
- `H` is a collision-resistant hash function. The **default is BLAKE3-256**; BLAKE2b-256 is
  an interoperable alternative with identical output length. ZK transfer mode (§3.2) requires
  Poseidon in place of BLAKE3 for circuit-friendliness. Hash outputs are encoded as lowercase
  hexadecimal strings prefixed with the algorithm name: `blake3:<hex>` or `blake2b:<hex>`.
- `||` denotes concatenation
- `timestamp` is the commitment time (logical clock, not wall clock)
- `sender_pubkey` is the sender's public key, binding identity to origin

This identity is **permanent**. The same content committed by the same sender at the same
logical moment always produces the same identity. Different moment = different entity. This
is not a bug — it is the immutability guarantee.

**Deduplication consequence.** Because EntityID includes `timestamp` and `sender_pubkey`,
identical content committed by the same sender at different logical times produces different
EntityIDs. The commitment network stores a distinct set of encrypted shards for each commit
with no mechanism to detect or coalesce redundant payloads. For fan-out workflows (one commit,
many receivers) this is irrelevant. For workflows that repeatedly commit identical content,
storage costs accumulate linearly with commit count. See §6.4 for a workload-specific storage
cost analysis.

**This is a deliberate design tradeoff, not an incidental consequence.** LTP's EntityID binds
content to origin (`sender_pubkey`) and moment (`timestamp`), providing *provenance guarantees*
that content-only hashing cannot offer: two entities that happen to share the same bytes remain
distinguishable by who committed them and when. Systems like IPFS and Git use content-only
hashing (`H(content)`) *precisely because* deduplication is a primary goal — a file committed
by two different parties to a Git repository produces the same blob hash regardless of origin.
LTP occupies the opposite point in this tradeoff space: provenance and immutability are
first-class guarantees, and deduplication is opt-in (via ContentHash, below) with an explicit
privacy cost. Deployments where storage efficiency outweighs provenance requirements should
evaluate whether content-only hashing (IPFS, Git) or a hybrid approach better fits their
workload.

**Optional ContentHash.** Deployments that require storage-layer deduplication without
breaking immutability semantics may compute:

```
ContentHash = H(content || shape)
```

as an optional out-of-band field in the commitment record. ContentHash is NOT the entity's
identity and does not participate in the EntityID computation or any security proof.
It allows storage nodes to identify shards that encrypt identical plaintext.

**Privacy tradeoff:** ContentHash enables any log observer to detect that two different
senders committed the same content (by comparing ContentHash values). For sensitive
deployments — where the fact that two parties hold the same data is itself confidential —
ContentHash MUST NOT be included in the public commitment record.

---

## 2. The Three Phases of Transfer

The three phases provide cumulative security guarantees, formalized in §3.3:

| Phase | Source Authentication | Destination Confidentiality | Forward Secrecy | Formal Basis |
|-------|:-------------------:|:--------------------------:|:--------------:|-------------|
| **COMMIT** | ML-DSA-65 signed commitment | Encrypted shards (CEK-protected) | N/A | Theorems 3, 4 (§3.3.1, §3.3.2) |
| **LATTICE** | Signed commitment binds sender | ML-KEM-768 sealed to receiver (IND-CCA2) | Fresh encapsulation per transfer | Theorems 5, 8 (§3.3.3, §3.3.6) |
| **MATERIALIZE** | Signature + Merkle root verified | Plaintext reconstructed by receiver only | Preserved (ephemeral shared secret discarded) | Theorems 6, 7 (§3.3.4, §3.3.5) |

This follows the pattern established by the Noise Protocol Framework [Perrin, 2018], where security properties are tracked per-message through the handshake. ETP's three phases correspond to a three-message protocol with strictly increasing security guarantees.

### Phase 1: COMMIT

The sender does not prepare the entity for transmission. Instead, the sender **commits** the
entity to a distributed commitment layer.

#### 2.1.1 Deterministic Sharding

The entity is decomposed into `n` shards using deterministic erasure coding,
then each shard is encrypted with a random Content Encryption Key (CEK):

```
plaintext_shards = ErasureEncode(entity, n, k)
CEK = CSPRNG(256 bits)     # MUST be fresh per entity — see invariant below
nonces        = [H(CEK || entity_id || index)[:nonce_len] for index in range(n)]
encrypted_shards = [AEAD_Encrypt(CEK, shard, nonce=nonces[index]) for index, shard in enumerate(plaintext_shards)]
```

Where:
- `n` = total number of shards produced
- `k` = minimum number of shards needed to reconstruct (k < n)
- The encoding is deterministic: same input always produces same shards
- `CEK` = a random 256-bit Content Encryption Key, unique per entity
- Each shard is encrypted with AEAD (authenticated encryption) before distribution
- Commitment nodes store **only ciphertext** — they cannot read shard content
- Each encrypted shard is integrity-checked: `ShardHash = H(encrypted_shard || entity_id || shard_index)`

**Reed-Solomon Canonical Parameters.** To guarantee interoperability — two conforming
implementations MUST produce identical shards and identical Merkle roots for the same
entity — the RS encoding is fully specified as follows:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Field | GF(2⁸) | 8-bit finite field |
| Primitive polynomial | $x^8 + x^4 + x^3 + x^2 + 1$ (0x11d) | Standard GF(2⁸) construction; same as used in AES, ISA-L, BackBlaze |
| Generator element | $\alpha = \texttt{0x02}$ | Primitive root of GF(2⁸) under 0x11d |
| Evaluation points | $\{1,\, \alpha,\, \alpha^2,\, \ldots,\, \alpha^{n-1}\}$ | Powers of generator; row $i$ of encoding matrix has entries $[\alpha^{0 \cdot i}, \alpha^{1 \cdot i}, \ldots, \alpha^{(k-1) \cdot i}]$ |
| Encoding matrix | Vandermonde: $V[i][j] = \alpha^{i \cdot j}$ for $i \in [0,n)$, $j \in [0,k)$ | Non-systematic; any $k$ rows are invertible (MDS property) |
| Decoding | Gauss-Jordan elimination over GF(2⁸) | Select any $k$ available rows, invert $k \times k$ submatrix |
| Shard size | $\lceil |$entity$| / k \rceil$ bytes, zero-padded to equal length | Entity is split into $k$ equal data chunks before encoding |

The `algorithm` field in the commitment record (see §2.1.3) MUST be `"reed-solomon-gf256"`
with the parameters above. Implementations MUST NOT use a different primitive polynomial,
generator, or matrix construction and claim conformance with this identifier.

**Interoperability test vector.** Encoding a 4-byte entity `[0x01, 0x02, 0x03, 0x04]`
with $n=4$, $k=2$ under these parameters produces the following shards (in hex). The entity
is split into $k=2$ coefficient chunks: $c_0 = [\texttt{0x01}, \texttt{0x02}]$,
$c_1 = [\texttt{0x03}, \texttt{0x04}]$. For each byte position $b$, the encoding evaluates
$p_b(x) = c_0[b] \oplus (c_1[b] \otimes_{\text{GF}} x)$ at evaluation points
$\alpha^i$. All arithmetic is in GF(2⁸) under 0x11d (addition = XOR, multiplication = finite
field multiply).

- Shard 0 ($\alpha^0 = 1$): `0x02 0x06`  *($p_0(1) = \texttt{0x01} \oplus \texttt{0x03} = \texttt{0x02}$, $p_1(1) = \texttt{0x02} \oplus \texttt{0x04} = \texttt{0x06}$)*
- Shard 1 ($\alpha^1 = 2$): `0x07 0x0A`  *($p_0(2) = \texttt{0x01} \oplus (2 \otimes_{\text{GF}} \texttt{0x03}) = \texttt{0x01} \oplus \texttt{0x06} = \texttt{0x07}$, $p_1(2) = \texttt{0x02} \oplus (2 \otimes_{\text{GF}} \texttt{0x04}) = \texttt{0x02} \oplus \texttt{0x08} = \texttt{0x0A}$)*
- Shard 2 ($\alpha^2 = 4$): `0x0D 0x12`  *($p_0(4) = \texttt{0x01} \oplus (4 \otimes_{\text{GF}} \texttt{0x03}) = \texttt{0x01} \oplus \texttt{0x0C} = \texttt{0x0D}$, $p_1(4) = \texttt{0x02} \oplus (4 \otimes_{\text{GF}} \texttt{0x04}) = \texttt{0x02} \oplus \texttt{0x10} = \texttt{0x12}$)*
- Shard 3 ($\alpha^3 = 8$): `0x19 0x22`  *($p_0(8) = \texttt{0x01} \oplus (8 \otimes_{\text{GF}} \texttt{0x03}) = \texttt{0x01} \oplus \texttt{0x18} = \texttt{0x19}$, $p_1(8) = \texttt{0x02} \oplus (8 \otimes_{\text{GF}} \texttt{0x04}) = \texttt{0x02} \oplus \texttt{0x20} = \texttt{0x22}$)*
- Any 2 of 4 shards reconstruct the original 4 bytes.

Note: Because the encoding is **non-systematic**, even shard 0 (at evaluation point
$\alpha^0 = 1$) computes $c_0[b] \oplus c_1[b]$, which does not equal the raw data chunk
unless $c_1[b] = 0$. Implementations that produce raw data chunks as the first $k$ shards
are implementing a *systematic* code, which is not conformant.

*Implementations MUST validate against this test vector before deployment. Verification
against an independent GF(2⁸) library (e.g., `galois` in Python, `leopard-rs` in Rust)
is strongly recommended.*

**Complete Test Vector (Reed-Solomon GF(2⁸), irreducible polynomial 0x11D):**

```
Input:    [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21] ("Hello!")
k = 3, n = 6
Evaluation points: α ∈ {1, 2, 3, 4, 5, 6}

Step 1: Prepend 8-byte big-endian length prefix
  Padded: [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06, 0x48,0x65,0x6C,0x6C,0x6F,0x21]
  (14 bytes, padded to 15 bytes = 3 chunks × 5 bytes)

Step 2: Split into k=3 chunks
  Chunk d₀: [0x00, 0x00, 0x00, 0x00, 0x00]
  Chunk d₁: [0x00, 0x00, 0x06, 0x48, 0x65]
  Chunk d₂: [0x6C, 0x6C, 0x6F, 0x21, 0x00]

Step 3: Evaluate polynomial p(α) = d₀ + d₁·α + d₂·α² at each α
  Shard 0 (α=1): p(1)  = d₀ ⊕ d₁ ⊕ d₂
  Shard 1 (α=2): p(2)  = d₀ ⊕ GF_mul(2,d₁) ⊕ GF_mul(4,d₂)
  ... (all arithmetic in GF(2⁸) with polynomial 0x11D)

Step 4: Any 3 of 6 shards reconstruct via Vandermonde inversion
  Reconstruction verified: decode({0,2,4}) = decode({1,3,5}) = original
```

Implementers SHOULD verify their erasure coding implementation against this vector and the ACVP test suite in `tests/test_formal_math.py`.

**Security Invariant — Nonce Derivation:**

Each shard's AEAD nonce is derived as:

```
nonce_i = H(CEK || entity_id || shard_index)[:nonce_len]
```

where `nonce_len` is the AEAD algorithm's required nonce length (e.g., 12 bytes for
AES-256-GCM or ChaCha20-Poly1305) and `H` is the protocol's hash function. This construction
provides defense-in-depth: nonce uniqueness depends on both CEK freshness *and* the
entity's identity, meaning a (CEK, entity_id) pair is sufficient to guarantee distinct
nonces across all shards of a single entity.

The scheme remains safe even under partial CSPRNG failures: a nonce collision between two
different entities requires both an identical CEK *and* an identical entity_id, which is
computationally infeasible. This also eliminates catastrophic failure modes from
seed-state cloning (e.g., VM snapshot/restore) or cached CEK reuse across retry paths.

**CEK reuse across entities is mitigated** by the nonce derivation scheme: two different
entities with the same CEK but different entity_ids produce different nonces, so their
(CEK, nonce) pairs collide with negligible probability, bounded by $q^2 / 2^{97}$ under the
random oracle model, where $q$ is the number of (entity\_id, shard\_index) pairs encrypted
under the same CEK. CEKs MUST still be generated fresh per entity from a
CSPRNG (e.g., `os.urandom`, `/dev/urandom`, `CryptGenRandom`) as a defense-in-depth
measure. Each commit operation MUST generate a fresh CEK regardless of content or entity_id.
Implementations SHOULD validate that the CEK is not degenerate (all-zero, all-one).

#### 2.1.2 Distributed Shard Placement

Shards are placed across a distributed network of **commitment nodes**. Placement follows a
deterministic algorithm based on the EntityID:

```
placement(shard_i) = ConsistentHash(EntityID || shard_index) → node_set
```

This means:
- Both sender and receiver can independently compute where shards live
- No central registry or lookup service is needed
- Shards are replicated across geographically diverse nodes
- The receiver will materialize from the **nearest** available shards

#### 2.1.3 The Commitment Record

Once shards are distributed, the sender publishes a **commitment record** to an append-only
commitment log (this can be a blockchain, a Merkle DAG, or any immutable append-only structure):

```json
{
  "entity_id": "blake3:7f3a8b...",
  "sender": "ml-dsa-65:verification_key...",
  "shard_map_root": "blake3:merkle_root_of_encrypted_shard_hashes",
  "encoding_params": { "n": 64, "k": 32, "algorithm": "reed-solomon-gf256", "gf_poly": "0x11d", "eval": "vandermonde-powers-of-0x02" },
  "shape_hash": "blake3:schema_hash...",
  "timestamp": 1740422400,
  "signature": "ml-dsa-65:sig...  (3,309 bytes, quantum-resistant)"
}
```

Critical security property: the commitment record contains **no individual shard IDs**.
Only a Merkle root of hashes of **encrypted** shards is stored. This reveals nothing
about the plaintext content — they are hashes of ciphertext.

The record is the **proof that the entity exists and was committed**. It is small (< 1 KB),
immutable, and independently verifiable.

### Phase 2: LATTICE

The sender transmits a minimal **lattice key** to the receiver. This is the only data
that traverses the sender → receiver path directly.

#### 2.2.1 The Lattice Key

The lattice key contains exactly **three secrets** and a policy:

```
LatticeKey = {
  entity_id,              // 32 bytes — which entity to materialize
  content_encryption_key, // 32 bytes — CEK to decrypt shards
  commitment_ref,         // 32 bytes — hash of commitment record
  access_policy           // ~20-50 bytes — materialization rules
}
```

Critically, the key does **NOT** contain:
- `shard_ids` — receiver derives shard locations from `entity_id` via consistent hashing
- `encoding_params` — receiver reads these from the commitment record
- `sender_id` — receiver reads this from the commitment record

The entire key is **sealed** via ML-KEM-768 (FIPS 203) key encapsulation. Each seal
operation generates a fresh encapsulation, providing forward secrecy per transfer.

The lattice key is:
- **Minimal** — ~160 bytes inner payload, ~1,300 bytes sealed, regardless of entity size
- **Sealed** — ML-KEM encapsulated to the receiver's encapsulation key (quantum-resistant)
- **Self-authenticating** — contains the commitment reference for verification
- **Policy-bound** — includes access rules (one-time, time-limited, delegatable, etc.)

**Access Policy Schema.** The `access_policy` field follows this JSON schema, per the IETF CFRG specification guidelines [draft-irtf-cfrg-cryptography-specification-01]:

```json
{
  "type": "unrestricted" | "one-time" | "time-limited" | "delegatable",
  "not_before": <Unix timestamp, optional>,
  "not_after": <Unix timestamp, optional>,
  "max_materializations": <integer, optional — for "one-time">,
  "delegate_to": [<receiver_vk_fingerprint>, ...] <optional — for "delegatable">
}
```

The default policy is `{"type": "unrestricted"}`. Policy enforcement occurs during the MATERIALIZE phase (§2.3.1, step 2): the receiver MUST verify that the current time falls within `[not_before, not_after]` and that the materialization count does not exceed `max_materializations`. Implementations that do not support policy enforcement MUST reject any policy with `type` other than `"unrestricted"`.

- **Opaque** — an interceptor sees only random bytes (no metadata leaks)
- **Post-quantum** — ML-KEM-768 resists both classical and quantum adversaries

#### 2.2.2 Key Properties of the Lattice Key

The lattice key is **not the data**. It is the **proof of right to reconstruct**. This
creates several remarkable properties:

1. **Sender→receiver decoupling**: Transferring 1 KB and transferring 1 TB produce the same
   size sealed lattice key (~1,300 bytes). The sender→receiver direct transmission is O(1).
   Note: total system bandwidth is O(entity × replication) across the commit and materialize
   phases. The advantage is not bandwidth elimination — it is *bottleneck relocation*: the
   sender-receiver path (often the slowest link) is reduced to a constant, and the O(entity)
   work shifts to the receiver↔network path, which can be geographically optimized.

2. **Three-layer interception resistance**: An attacker faces three independent barriers:
   - **Layer 1 (Sealed envelope)**: The key is encrypted to the receiver's public key;
     intercepting it yields opaque ciphertext with no metadata
   - **Layer 2 (Encrypted shards)**: Even if an attacker queries the commitment network
     directly, all shards are AEAD-encrypted; without the CEK, they are useless
   - **Layer 3 (Minimal log)**: The commitment log contains only a Merkle root of
     ciphertext hashes — no individual shard IDs, no content, no CEK

3. **Non-repudiation**: The commitment record on the append-only log proves the sender committed
   the entity. The lattice key proves the sender authorized the receiver. Both are
   cryptographically signed.

4. **Forward secrecy**: Each lattice key uses a fresh ML-KEM-768 encapsulation, producing
   a unique (shared_secret, ciphertext) pair per seal. The shared_secret is used once for AEAD
   encryption and then immediately zeroized. Compromising the receiver's decapsulation key
   after the shared_secret has been destroyed does not expose historical transfers.

   **Forward secrecy lifecycle:**
   1. `seal()` calls ML-KEM.Encaps(receiver_ek) → fresh (ss, kem_ct)
   2. ss is used as the AEAD key for the payload, then zeroized in memory
   3. kem_ct is embedded in the sealed output
   4. Only the holder of dk can recover ss from kem_ct (Module-LWE hardness)
   5. After the receiver processes the sealed key and zeroizes ss, the shared
      secret is unrecoverable — even if dk is later compromised
   6. For defense-in-depth, receivers SHOULD rotate ek/dk periodically;
      old dk values MUST be securely destroyed after rotation

### Phase 3: MATERIALIZE

The receiver uses the lattice key to **reconstruct** the entity from the commitment layer.

#### 2.3.1 Reconstruction Process

```
1. Unseal lattice key with receiver's private key → extract entity_id, CEK, commitment_ref
2. Fetch commitment record from append-only log using entity_id
3. Verify commitment record: H(record) == commitment_ref (integrity check)
4. Verify commitment record signature (sender authenticity)
5. Read encoding params (n, k) from commitment record
6. Derive shard locations: ConsistentHash(entity_id || shard_index) for index in 0..n-1
7. Fetch k-of-n ENCRYPTED shards from nearest available commitment nodes (parallel)
8. Decrypt each shard: AEAD_Decrypt(CEK, encrypted_shard, nonce=H(CEK || entity_id || shard_index)[:nonce_len])
   — AEAD authentication tag is verified BEFORE decryption (tamper detection)
9. ErasureDecode(decrypted_shards, k) → entity content
10. Verify: H(entity_content || shape || timestamp || sender_pubkey) == entity_id
    — *End-to-end content integrity check.* This is distinct from the Merkle root verification
    in steps 3–4, which confirms commitment record integrity. This step independently verifies
    that the reconstructed content matches the EntityID, providing a second line of defense:
    an adversary who substitutes a valid-but-different commitment record (one whose signature
    and Merkle root internally check out, but which references a different entity) cannot
    pass this check, because the reconstructed content will hash to a different EntityID.
11. Entity materialized. Transfer complete.
```

#### 2.3.2 Why This Is Fast

Traditional transfer: **move all the data across one path (sender → receiver)**

LTP materialization: **pull k shards in parallel from the nearest nodes in the commitment network**

```
Traditional:    S ════════════════(entire payload)════════════════> R
                  Bottleneck: sender upload × distance to receiver

LTP:            S ──(~1,300B sealed key)──> R
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          ...k shards, parallel, nearest-first
```

**Important nuance:** The total bytes moved across the system is *greater* than direct
transfer — the commit phase uploads O(entity × replication_factor) to the network, and the
materialize phase downloads O(entity) from it. LTP does not eliminate bandwidth; it
**relocates the bottleneck**:

- The sender→receiver path (often the slowest, highest-latency link) shrinks to O(1)
- The O(entity) work shifts to receiver↔nearby-nodes, which can be geographically local
- The commit-phase bandwidth is amortized: committed once, materialized by many receivers

The win is not "less bandwidth" — it is **faster perceived transfer** via parallelism,
geographic locality, and sender-independence. For the formal bandwidth model, fan-out
break-even analysis, and latency equations, see §6.4.

#### 2.3.3 Protocol Timing Constraints

Implementations MUST enforce timeout bounds on each protocol phase to prevent
indefinite hangs and enable timeout-based failure detection (cf. WireGuard §5
rekey timers, RFC 6962 Maximum Merge Delay).

| Phase | Default Timeout | Max Retries | Description |
|-------|:--------------:|:-----------:|-------------|
| **COMMIT** | 30 seconds | 3 | Time to distribute all $n$ shards, sign commitment record, and append to Merkle log |
| **LATTICE** | 10 seconds | 1 | Time to seal lattice key via ML-KEM-768 and transmit to receiver |
| **MATERIALIZE** | 60 seconds | 3 | Time to fetch $k$-of-$n$ shards, decrypt, erasure-decode, and verify EntityID |

A phase that exceeds its timeout transitions to `TIMED_OUT` state. The sender or
receiver MAY retry up to `max_retries` times with exponential backoff:

$$t_{\text{retry}} = t_{\text{base}} \cdot 2^{i-1} \cdot (1 + \text{jitter})$$

where $i$ is the retry number (1-indexed) and $\text{jitter} \in [0, 0.5]$ is uniform
random. Jitter prevents synchronized retries across concurrent transfers
(cf. FoundationDB thundering herd mitigation).

If all retries are exhausted, the transfer transitions to `FAILED` state. Committed
entities remain in the Merkle log regardless of failure — they are immutable once
appended. The sender may re-initiate a new transfer with a fresh CEK.

#### 2.3.4 Key Rotation Protocol

Participants SHOULD rotate ML-KEM encapsulation keys every 90 days to limit the
impact of key compromise (cf. NIST SP 800-57 §5.3, WireGuard rekey every 2 minutes).

**Rotation protocol:**

1. **Generate successor:** New KeyPair with `version = old.version + 1`, linked via
   `predecessor_vk_hash = H(old.vk)`.
2. **Publish new $ek$:** Distribute the new encapsulation key via the commitment network.
3. **Grace period (default: 1 hour):** Both old and new $dk$ are accepted for
   ML-KEM decapsulation. Senders may seal to either key during this window.
4. **Retirement:** After the grace period, old $dk$ and $sk$ are securely zeroized.
   Implementations SHOULD use `sodium_memzero()` or equivalent constant-time
   memory clearing.
5. **Chain verification:** Any party can verify the key chain by checking that each
   key's `predecessor_vk_hash` matches $H(vk)$ of the previous key.

**Key chain structure:**

```
KeyPair v1 (created: T₀, expires: T₁ + grace)
  └── KeyPair v2 (created: T₁, predecessor: H(v1.vk), expires: T₂ + grace)
       └── KeyPair v3 (created: T₂, predecessor: H(v2.vk))
```

The key chain provides **non-repudiation continuity**: if a sender rotates keys,
the chain proves that all historical commitment signatures are attributable to
the same identity (verifiable via the `predecessor_vk_hash` chain).

---

## 3. Security Model

### 3.1 Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| Man-in-the-middle intercepts lattice key | Entire key is sealed (envelope-encrypted) to receiver's public key; interceptor sees opaque ciphertext with zero metadata |
| Attacker scrapes commitment log | Log contains only Merkle root of encrypted shard hashes — no shard IDs, no content, no CEK |
| Attacker fetches shards from nodes | Shards are AEAD-encrypted with CEK; without CEK, ciphertext is computationally useless |
| Attacker compromises < k nodes | Information-theoretic security: < k shards (even decrypted) reveal zero information about the entity |
| Sender denies transfer occurred | Commitment record is on immutable append-only log with sender's signature |
| Receiver claims different data was sent | Entity ID is deterministic hash of content; both parties can verify |
| Replay attack (re-use lattice key) | Access policy can enforce one-time materialization; commitment nodes track access |
| Quantum computing threat | **Standard mode: fully post-quantum** — ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), BLAKE3-256 (quantum-resistant; BLAKE2b-256 is equivalent), information-theoretic erasure coding; no X25519 or Ed25519. **ZK mode: NOT quantum-resistant** — Groth16 over BLS12-381 is broken by Shor's algorithm. ZK mode MUST NOT be used under a quantum-adversary threat model (see §3.2.4 and Abstract warning). |

### 3.2 Zero-Knowledge Transfer Mode

**Purpose.** ZK mode addresses the EntityID fingerprinting limitation identified in §3.3.3:
in standard LTP, `entity_id = H(entity_content || ...)` is published to the public commitment
log, allowing observers to fingerprint low-entropy entities by computing and matching candidate
hashes. ZK mode replaces the public entity_id with a hiding commitment, eliminating
fingerprinting while preserving immutability and non-repudiation.

**Scope.** This section specifies the core ZK mode instantiation sufficient to close the
confidentiality gap in §3.3.3. Content-property proofs (e.g., proving "this entity is a valid
JSON document" without revealing content) require additional circuit composition and are
deferred to a future protocol version (see §10, Open Question 8).

#### 3.2.1 Modified Commitment Record

In ZK mode, the commitment record replaces `entity_id` with a blinded identifier:

```json
{
  "mode": "zk",
  "blind_id":       "Poseidon(entity_id || r)   // r ← CSPRNG(256 bits), NOT published",
  "shard_map_root": "poseidon:merkle_root_of_encrypted_shard_hashes",
  "encoding_params": { "n": 64, "k": 32, "algorithm": "reed-solomon-gf256", "gf_poly": "0x11d", "eval": "vandermonde-powers-of-0x02" },
  "shape":           "application/json",
  "timestamp":       1740422400,
  "zk_proof":        "...",   // Groth16 proof over R_ZK — see §3.2.2
  "signature":       "ml-dsa-65:sig..."
}
```

`blind_id = Poseidon(entity_id || r)` is a hiding commitment: it binds the sender to
entity_id without revealing it. Since `r` is 256 bits of CSPRNG output, `blind_id` is
computationally indistinguishable from a random value to any public log observer.

The entity_id and blinding factor are carried privately in the sealed lattice key:

```
LatticeKey (ZK mode) = {
  entity_id,      // 32 bytes — private, NOT on the public log
  r,              // 32 bytes — blinding factor for blind_id verification
  cek,            // 32 bytes — CEK to decrypt shards
  commitment_ref, // 32 bytes — hash of the ZK commitment record
  access_policy
}
```

The receiver opens the commitment by verifying `Poseidon(entity_id || r) == blind_id`, then
proceeds with shard placement, AEAD decryption, erasure decoding, and entity verification
identically to standard LTP.

#### 3.2.2 ZK Proof Specification

The ZK proof demonstrates that the sender knows an entity consistent with blind_id, without
revealing entity_id or entity_content.

**Proof system:** Groth16 [16] over BLS12-381. Chosen for its minimal proof size (~192 bytes)
and sub-millisecond verification. The per-circuit trusted setup is a deployment consideration
discussed in §3.2.4.

**Hash function:** ZK mode uses Poseidon [17] in place of BLAKE3 for all circuit-internal
hash operations. Poseidon is ZK-friendly (designed for low R1CS gate count). When §1.2
specifies "BLAKE3 or Poseidon," ZK mode MUST use Poseidon.

**The relation R_ZK:**

```
Public inputs:   blind_id, shape_hash, timestamp, sender_vk
Private witnesses: entity_id, r, entity_content

R_ZK is satisfied iff:
  (1) blind_id  = Poseidon(entity_id || r)
  (2) entity_id = Poseidon(entity_content || shape || timestamp || sender_vk)
```

Condition (1) is commitment consistency: the public log entry is bound to a specific
entity_id. Condition (2) is entity well-formedness: the entity_id was correctly derived from
entity_content. Together they tie the public blind_id to a specific committed entity without
revealing it.

**Performance estimates (Groth16 over BLS12-381, R_ZK as above):**

| Metric | Estimate | Notes |
|--------|----------|-------|
| Proof size | ~192 bytes | Fixed for Groth16 |
| Proof generation | 500ms–2s (CPU) | ~10–100ms with GPU/FPGA |
| Proof verification | <1ms | Single pairing check |
| Circuit size | ~10,000–25,000 R1CS constraints | Dominated by two Poseidon-128 permutations |

Estimates are based on published Groth16 benchmarks for comparable Poseidon circuits.

#### 3.2.3 Security Properties

**EntityID privacy (hiding).** Under the zero-knowledge property of Groth16 and the
hiding property of the Poseidon commitment scheme $C(x; r) = \text{Poseidon}(x \| r)$,
the public log entry `(blind_id, zk_proof)` is
computationally indistinguishable from `(random, simulated_proof)` to any PPT observer.
An adversary who knows candidate entities $(e_0, e_1)$ cannot match either against the
log entry — entity_id is not present, and the hiding property of $C(x; r)$ ensures that
$C(x; r)$ is computationally indistinguishable from uniform when $r$ is drawn uniformly
from $\{0,1\}^{256}$. The EntityID fingerprinting attack from §3.3.3 is neutralized.

**Binding (immutability preserved).** By the binding property of the Poseidon commitment
scheme and the soundness of Groth16, a sender cannot open blind_id to two distinct entity_ids
without breaking Poseidon collision resistance. Theorem 8 (Transfer Immutability) holds in
ZK mode with the additional binding assumption.

**Non-repudiation preserved.** The ML-DSA-65 signature covers the full ZK commitment record
(including blind_id and zk_proof). Theorem 6 is preserved: the sender cannot deny generating
a commitment record they signed.

**TCONF in ZK mode.** The fingerprinting component of the TCONF limitation (§3.3.3) does not
apply when ZK mode is active: entity_id is absent from the public log. The encrypted-components
bound of Theorem 5 holds unconditionally under ZK mode.

#### 3.2.4 Limitations and Honest Assessment

1. **Trusted setup.** Groth16 requires a per-circuit trusted setup ceremony (MPC over the
   circuit structure). A compromised setup allows fabricating valid proofs for false statements.
   Production deployments MUST use a multi-party ceremony with independent participants.
   PLONK (universal setup) or STARKs (no setup) are alternatives with larger proofs (~500 bytes
   and ~20–200 KB respectively).

2. **Post-quantum status.** Groth16 relies on bilinear pairings over BLS12-381, which are
   broken by Shor's algorithm in polynomial time on a sufficiently large quantum computer.
   ZK mode as specified does **NOT** provide quantum-resistant hiding. **ZK mode MUST NOT
   be used in deployments with a quantum-adversary threat model.** Standard LTP (without ZK
   mode) is fully post-quantum; the PQ gap is isolated to the privacy-enhanced mode only.

   Planned post-quantum upgrade path:
   - **Near-term (STARK):** Replace Groth16 with a hash-based STARK (e.g., over BLAKE3 or
     Poseidon). No trusted setup required; security reduces to collision resistance of the
     hash function. Proof sizes grow to ~20–200 KB.
   - **Medium-term (lattice ZK):** Lattice-based proof systems (e.g., Ligero++, Spartan
     over a PQ-safe hash) may yield smaller proofs. No NIST-standardized lattice-based ZK
     system exists as of this writing.

   Until a post-quantum ZK instantiation is standardized and integrated, deployments
   requiring both content-privacy (hiding) and quantum resistance SHOULD forgo ZK mode and
   accept the EntityID fingerprinting limitation of §3.3.3, mitigated by ensuring entity
   content has sufficient min-entropy (§3.3.3 guidance). See §10, Open Question 8.

3. **Content-property proofs.** R_ZK proves commitment consistency only, not content
   constraints. Application-layer predicates ("entity_content is valid JSON with `amount ∈
   [0, 1000]`") require extending condition (2) with predicate-specific circuit gates. These
   are outside the scope of this version and deferred to application-layer circuit libraries.

4. **Shard placement opacity.** Commitment nodes store shards keyed by entity_id (privately
   known to sender and receiver). Nodes cannot verify the entity_id → blind_id binding
   without r. This is intentional — nodes must not learn entity_id — but places placement
   validation responsibility on the sender and receiver rather than the network.

### 3.3 Formal Security Definitions

This section defines the security properties of LTP as cryptographic games and formally
reduces each to standard assumptions. We adopt the notation of Bellare and Rogaway:
$\mathcal{A}$ denotes a PPT (probabilistic polynomial time) adversary, $\mathsf{negl}(\lambda)$
denotes a negligible function in security parameter $\lambda$, and $\mathsf{Adv}^{X}_{\mathcal{A}}$
denotes $\mathcal{A}$'s advantage in game $X$.

**Note on theorem numbering.** The theorems in this section are numbered 3–8. Theorems 1
and 2 are reserved for the informal Corollary (Immutability) and Remark (Availability
Boundary) in §4.3, which are prose restatements of results proved here rather than
independent formal results. The numbering is kept consistent so that cross-references
in §4 align with the formal proofs in §3.3.

**Trust Model Assumption (applies to all theorems in this section).** All theorems below
assume an honest append-only commitment log: once a commitment record is accepted at position
$i$, no party can modify it or insert a different record at position $i$, and all honest
participants observe a consistent log state. This is an idealization. In practice, the
commitment log is implemented by one of the trust tiers described in §5.1.4 — ranging from
a single trusted operator (full trust) to a CT-style multi-operator Merkle log (trust in at
least one honest mirror) to a BFT replicated log ($> 2/3$ honest operators). The security
guarantees of Theorems 3, 6, and 8 hold only to the extent that the chosen log implementation
satisfies this assumption. See §5.1.4 for the conditions under which each implementation
tier meets it, and for the consequences if it is violated.

**Conditional restatement.** Where theorems reference the commitment log, they should be
read as: *"Under the assumption that the commitment log satisfies append-only integrity and
consistency (§5.1.4), the following holds..."* This conditionality is not restated in each
theorem for brevity, but it is always present.

#### 3.3.1 Entity Immutability (Collision Resistance)

**Definition (IMM game).** The immutability game $\mathsf{Game}_{\mathcal{A}}^{\text{IMM}}$
proceeds as follows:

```
Game IMM:
  1. Adversary A receives the hash function H and the protocol parameters.
  2. A outputs two entities (e, e') with e ≠ e'.
  3. A wins if EntityID(e) = EntityID(e').
```

**Theorem 3 (Entity Immutability).** For any PPT adversary $\mathcal{A}$ and any
collision-resistant hash function $H$ with $n$-bit output:

$$\mathsf{Adv}^{\text{IMM}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{CR}}_{H}(\lambda)$$

where $\mathsf{Adv}^{\text{CR}}_{H}$ is the collision-resistance advantage against $H$.

*Proof.* Reduction: Given $\mathcal{A}$ that wins IMM, construct $\mathcal{B}$ that breaks
collision resistance of $H$. $\mathcal{B}$ runs $\mathcal{A}$ and receives $(e, e')$ with
$e \neq e'$ and $H(\text{encode}(e)) = H(\text{encode}(e'))$. Since $e \neq e'$ implies
$\text{encode}(e) \neq \text{encode}(e')$ (encoding is injective), $\mathcal{B}$ outputs
$(\text{encode}(e), \text{encode}(e'))$ as a collision for $H$. ∎

**Concrete security.** The theorem holds for any $n$-bit collision-resistant $H$. The
canonical choice is **BLAKE3-256** ($n = 256$); BLAKE2b-256 is an equally valid alternative
with identical output length and equivalent security parameters. The classical birthday
bound gives $\mathsf{Adv}^{\text{CR}}_{H} \leq q^2 / 2^{257}$ where $q$ is the number of
hash evaluations. At $q = 2^{128}$ (computational limit): $\mathsf{Adv} \approx 2^{-1}$
(infeasible in practice).

**Post-quantum collision resistance.** Grover's algorithm reduces preimage search to
$O(2^{128})$ quantum queries but targets preimages, not collisions. The
Brassard–Høyer–Tapp (BHT) quantum collision-finding algorithm [BHT98] achieves query
complexity $O(N^{1/3})$ for finding collisions in an $N$-element domain; Aaronson and
Shi [AS04] proved the matching lower bound $\Omega(N^{1/3})$, establishing BHT as
asymptotically optimal. For a 256-bit hash:

$$O((2^{256})^{1/3}) = O(2^{85.3})$$

The correct post-quantum security characterization:

| Property | Classical Security | Post-Quantum Security |
|:---------|:-----------------:|:--------------------:|
| Preimage resistance (BLAKE3-256) | 256 bits | 128 bits (Grover) |
| Collision resistance (BLAKE3-256) | 128 bits (birthday) | **~85 bits (BHT)** |

The ~85-bit quantum collision resistance remains well above any practical attack threshold
and does not threaten the protocol's security margins. However, preimage resistance and
collision resistance have different post-quantum security levels.

> [BHT98] Brassard, G., Høyer, P., Tapp, A. "Quantum Cryptanalysis of Hash and
> Claw-Free Functions." LATIN 1998.
>
> [AS04] Aaronson, S., Shi, Y. "Quantum Lower Bounds for the Collision and the
> Element Distinctness Problems." J. ACM, 2004.

#### 3.3.2 Shard Integrity (Second-Preimage Resistance)

**Definition (SINT game).** The shard integrity game $\mathsf{Game}_{\mathcal{A}}^{\text{SINT}}$
proceeds as follows:

```
Game SINT:
  1. Challenger commits entity e with shards {s_0, ..., s_{n-1}}.
  2. Adversary A receives entity_id, all shard hashes H(s_i ‖ entity_id ‖ i),
     and the AEAD ciphertexts (as stored on commitment nodes).
  3. A outputs (i, s_i') with s_i' ≠ s_i.
  4. A wins if H(s_i' ‖ entity_id ‖ i) = H(s_i ‖ entity_id ‖ i)
     AND the AEAD tag verifies.
```

**Theorem 4 (Shard Integrity).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{SINT}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{SPR}}_{H}(\lambda) + \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}(\lambda)$$

where $\mathsf{Adv}^{\text{SPR}}_{H}$ is the second-preimage resistance advantage and
$\mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}$ is the AEAD authentication advantage.

*Proof.* Winning the SINT game requires the adversary to pass **both** checks simultaneously: the submitted $s_i'$ must produce a hash collision ($H(s_i' \| \text{entity\_id} \| i) = H(s_i \| \text{entity\_id} \| i)$, targeting SPR of $H$) **and** the corresponding AEAD ciphertext must carry a valid authentication tag (targeting AEAD authenticity). Let $E_1$ be the event that the adversary breaks SPR and $E_2$ be the event that it forges a valid AEAD tag. Since both conditions are required simultaneously, $\Pr[\text{win}] = \Pr[E_1 \cap E_2] \leq \min(\Pr[E_1], \Pr[E_2]) \leq \mathsf{Adv}^{\text{SPR}}_{H} + \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}$. The sum bound is conservative but valid ($\min(a,b) \leq a + b$ for non-negative $a, b$); the actual advantage is more tightly bounded by $\min(\mathsf{Adv}^{\text{SPR}}_{H},\, \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}})$. ∎

**Note (double protection).** Content-addressing and AEAD authentication form two independent barriers. An adversary who breaks only one check does not win the SINT game — both must be defeated simultaneously. This makes the protocol resilient against adversaries who can break either primitive in isolation.

#### 3.3.3 Transfer Confidentiality (IND-CPA)

**ML-KEM-768 Security Parameters.** The sealed lattice key's confidentiality reduces to the Module-LWE problem with parameters (k=3, q=3329, η₁=2, η₂=2), achieving NIST Security Level 3 — equivalent to AES-192 against quantum adversaries. The IND-CCA2 property is obtained via the Fujisaki-Okamoto transform applied to an IND-CPA-secure K-PKE scheme [Bos et al., 2017; FIPS 203 §4]. The recent formal verification of Signal's PQXDH protocol [Bhargavan et al., USENIX Security 2024] — the first machine-checked post-quantum security proof of a real-world protocol using CryptoVerif — identified a KEM binding property requirement: the KEM ciphertext must be bound to the encapsulation key. ETP satisfies this property because the sealed lattice key includes the entity_id (which is derived from the sender's verification key) alongside the KEM ciphertext.

**Definition (TCONF game).** Transfer confidentiality is defined via an IND-CPA-style
indistinguishability game adapted for LTP's commit-lattice-materialize structure:

```
Game TCONF:
  1. Challenger generates keypairs for sender S and receiver R.
  2. Adversary A chooses two equal-length entities (e_0, e_1) and submits them.
  3. Challenger flips coin b ∈ {0, 1} and runs the full LTP protocol on e_b:
     - COMMIT: erasure encode, AEAD encrypt shards, distribute to nodes
     - LATTICE: seal key to R's public key
  4. Adversary A receives:
     - The sealed lattice key (ML-KEM ciphertext)
     - All encrypted shards stored on commitment nodes
     - The full public commitment log entry for e_b:
         entity_id = H(e_b), shard_map_root, encoding params, ML-DSA signature
     Note: A may also independently evaluate H(e_0) and H(e_1), since H is public
     and A submitted e_0 and e_1 in step 2. The entity_id is therefore computable
     by A without observing the log.
  5. A outputs guess b'.
  6. A wins if b' = b.
```

**EntityID fingerprinting.** Because `entity_id = H(e_b)` is published to the public
commitment log, and because $\mathcal{A}$ chose $e_0$ and $e_1$ in step 2, $\mathcal{A}$
can evaluate $H(e_0)$ and $H(e_1)$ and compare against the logged entity_id, identifying
$b$ directly. This attack succeeds with advantage 1 and cannot be mitigated by any choice
of AEAD or KEM algorithm — it follows from the public visibility of the content hash.
This property is inherent to content-addressed systems and is shared by IPFS, Git,
Tahoe-LAFS, and any protocol that records content hashes in a public log.

**Theorem 5 (Transfer Confidentiality — Conditional).** The TCONF advantage decomposes
into two independent attack surfaces:

1. **EntityID fingerprinting:** $\mathsf{Adv}^{\text{ID}}_{\mathcal{A}} = 1$ for any
   adversary who chose $(e_0, e_1)$ and can evaluate $H$ — which is always the case.
   This component is not bounded by any cryptographic assumption.

2. **Encrypted-components advantage:** For attacks limited to the sealed key and
   AEAD-encrypted shards (i.e., excluding the entity_id fingerprinting path), for any
   PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{TCONF,enc}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}(\lambda) + \mathsf{Adv}^{\text{IND-CPA}}_{\text{AEAD}}(\lambda)$$

*Proof sketch (encrypted components only).* We proceed via a sequence of games, treating
entity_id as a fixed public value and bounding only attacks on the cryptographic components:

- **Game 0** = TCONF restricted to attacks on the sealed key and AEAD shards.
- **Game 1**: Replace ML-KEM shared secret with random. By ML-KEM IND-CCA security,
  $|\Pr[G_0] - \Pr[G_1]| \leq \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}$.
  Now the sealed key is a random encryption — independent of $b$.
- **Game 2**: Replace AEAD encryptions of shards with encryptions of zeros. By AEAD
  IND-CPA security, $|\Pr[G_1] - \Pr[G_2]| \leq \mathsf{Adv}^{\text{IND-CPA}}_{\text{AEAD}}$.
  Now the shard ciphertexts are independent of $b$.

In Game 2, restricted to the encrypted components, the adversary's view is independent of
$b$, so $\Pr[G_2] = 1/2$. By the triangle inequality:

$$|\Pr[G_0] - 1/2| \leq \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}} + \mathsf{Adv}^{\text{IND-CPA}}_{\text{AEAD}}$$

which yields the stated bound. ∎

**Practical security.** For most real-world entities (large files, cryptographic keys,
rich documents), the entity space has sufficient min-entropy that EntityID fingerprinting
is infeasible in practice: an adversary observing entity_id cannot enumerate candidate
entities to find a hash match. In this high-entropy regime, TCONF effectively reduces to
the encrypted-components bound.

**Security limitation: low-entropy entities.** When entities are drawn from a small or
enumerable set (e.g., "approved"/"rejected," a small integer, a name from a known list),
entity_id is an effective distinguisher and the adversary wins TCONF with advantage 1 by
evaluating $H(e_0)$ and $H(e_1)$ directly. Standard LTP provides no confidentiality
guarantee for low-entropy entities committed to the public log.

**Mitigation.** For low-entropy entities, use the ZK Transfer Mode (§3.2), which conceals
entity_id from the public commitment log. When committed entities may be guessable or
enumerable, the ZK mode MUST be used; relying on Theorem 5 in such settings provides
no confidentiality guarantee.

#### 3.3.4 Commitment Non-Repudiation (EUF-CMA)

**Definition (NREP game).** The non-repudiation game $\mathsf{Game}_{\mathcal{A}}^{\text{NREP}}$
proceeds as follows:

```
Game NREP:
  1. Challenger generates ML-DSA-65 keypair (vk, sk) for sender S.
  2. Adversary A is given vk and oracle access to Sign(sk, ·).
  3. A outputs a commitment record c* and signature σ* such that:
     - Verify(vk, c*, σ*) = ACCEPT
     - S never signed c* (c* was not queried to the signing oracle)
  4. A wins if the above conditions hold.
```

**Theorem 6 (Non-Repudiation).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{NREP}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA-65}}(\lambda)$$

*Proof.* Direct reduction: $\mathcal{B}$ embeds the EUF-CMA challenge key as $S$'s
verification key. Any forgery $(c^*, \sigma^*)$ from $\mathcal{A}$ is a valid EUF-CMA
forgery. ML-DSA-65 (FIPS 204) achieves NIST Level 3 security (128 bits against quantum
adversaries via the Module-LWE hardness assumption). ∎

**Consequence.** Once a sender commits an entity and the ML-DSA-65 signature is recorded in
the append-only log, the sender cannot deny the commitment. The receiver can present the
signed record as unforgeable evidence of the transfer's existence.

#### 3.3.5 Threshold Secrecy (Information-Theoretic)

**Definition (TSEC game).** The threshold secrecy game
$\mathsf{Game}_{\mathcal{A}}^{\text{TSEC}}$ proceeds as follows:

```
Game TSEC:
  1. Challenger picks a uniformly random entity e from the entity space.
  2. Challenger erasure-encodes e into n shards {s_0, ..., s_{n-1}}.
  3. Adversary A (computationally unbounded) receives any t < k shards of
     her choice (adaptive or non-adaptive). A has no prior knowledge of e.
  4. A outputs any function of the observed shards.
  5. A wins if her output reveals any information about e beyond the prior
     distribution (i.e., if the posterior distribution of e differs from
     the prior).
```

**Theorem 7 (Threshold Secrecy — MDS Secrecy).** For any adversary $\mathcal{A}$ (computationally unbounded, including quantum), observing any $t < k$ shards of a uniformly random entity $e$:

$$\Pr[M = e \mid \text{any } t < k \text{ shards}] = \Pr[M = e]$$

The conditional distribution of $e$ given any $t < k$ observed shards is identical to its prior distribution. Equivalently, $\mathsf{Adv}^{\text{TSEC}}_{\mathcal{A}} = 0$.

*Proof.* The Vandermonde encoding evaluates a degree-$(k-1)$ polynomial $p(x) = \sum_{j=0}^{k-1} c_j x^j$
over GF(256) at $n$ distinct points. Any $t < k$ evaluations leave $k - t \geq 1$ degrees
of freedom. Formally: for any set $T$ of $t < k$ evaluation points and any observed values
at those points, exactly $256^{k-t}$ polynomials of degree at most $k - 1$ are consistent
with those evaluations. Since the entity $e$ is the coefficient vector $(c_0, \ldots, c_{k-1})$
drawn uniformly at random, and the number of consistent polynomials is the same regardless of
the true $e$, every candidate entity is equally consistent with the observed shards. The
posterior distribution of $e$ is therefore identical to the prior, giving $\mathsf{Adv}^{\text{TSEC}}_{\mathcal{A}} = 0$.
This is the **MDS (Maximum Distance Separable) secrecy property** of Reed-Solomon codes —
it holds against adversaries with unlimited computational power, including quantum computers. ∎

**Note on chosen-message distinguishing.** The TSEC game is stated for an adversary without
prior knowledge of $e$ — the case that arises in practice when an attacker compromises fewer
than $k$ commitment nodes but does not know what was committed. An adversary who already knows
the set of candidate entities can distinguish trivially: since the Vandermonde encoding is
deterministic, computing the expected shard for each candidate and comparing against the
observed shard identifies the encoding with certainty. This is not a weakness of the
construction — it is intentional. The protocol relies on **AEAD encryption (Layer 4)** as the
primary confidentiality guarantee against adversaries who may know or guess candidate entities.
The MDS threshold secrecy property provides a second line of defense for the specific case
where an adversary has obtained the CEK but controls fewer than $k$ commitment nodes.

**Formal basis.** The threshold secrecy of ETP's erasure coding follows from the MDS (Maximum Distance Separable) property of Reed-Solomon codes over GF(2⁸), first connected to secret sharing by McEliece and Sarwate [1981]. Any k−1 shards leave exactly one degree of freedom in the polynomial coefficient space, revealing zero information about the entity content in the Shannon sense. This is information-theoretic security — it holds regardless of the adversary's computational power, including against quantum adversaries.

**In LTP's context:** Even if an adversary compromises $k - 1$ commitment nodes and decrypts
the AEAD ciphertexts (by also obtaining the CEK) without prior knowledge of the entity,
the $k - 1$ plaintext shards reveal zero information about the entity. This information-theoretic
guarantee is unconditional — it holds against quantum computers — and provides defense in
depth behind AEAD encryption.

#### 3.3.6 Transfer Immutability (Composite Game)

**Definition (TIMM game).** Transfer immutability captures the end-to-end property: no
adversary can cause a receiver to accept an entity different from what the sender committed.
This is the defining security goal of LTP.

```
Game TIMM:
  1. Challenger runs honest setup: generates keypairs, commitment network.
  2. Sender S commits entity e via COMMIT, producing record R and CEK.
  3. S creates lattice key K via LATTICE, sealed to receiver R's pk.
  4. Adversary A controls the network: A can modify, drop, or inject
     shards on commitment nodes; A can modify the sealed key in transit;
     A can forge commitment records (if able); A controls all nodes
     except the append-only log.
  5. Receiver R runs MATERIALIZE with whatever A delivers.
  6. A wins if R outputs e' with e' ≠ e (receiver accepts wrong data).
```

**Theorem 8 (Transfer Immutability).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{TIMM}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{CR}}_{H}(\lambda) + \mathsf{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA}}(\lambda) + \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}(\lambda) + \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}(\lambda)$$

*Proof.* Viable attack paths against the TIMM game require breaking *multiple* barriers
simultaneously. The principal attack paths are:

- **Path A (shard substitution):** Substitute AEAD ciphertexts (breaking AEAD AUTH) **and**
  find $e'$ with $H(e') = H(e)$ that passes the final integrity check (breaking CR).

- **Path B (commitment forgery):** Forge a commitment record pointing to an attacker-controlled
  Merkle root (breaking EUF-CMA) **and** modify the sealed key to reference the forged
  record (breaking ML-KEM IND-CCA).

- **Path C (key extraction + content substitution):** Extract the CEK from the sealed key
  (breaking ML-KEM IND-CCA) **and** substitute entity content that passes the hash check
  (breaking CR).

Each path's success probability is a *product* of two or more barrier advantages, which is
dominated by the largest single-barrier advantage in the product. Since each path requires
at least one of the four barrier advantages, the union bound over the individual barrier
advantages remains valid:

$$\mathsf{Adv}^{\text{TIMM}} \leq \mathsf{Adv}^{\text{CR}}_{H} + \mathsf{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA}} + \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}} + \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}$$

This sum bound is conservative — the multi-barrier composition means the protocol's actual
security is stronger than any single component. ∎

**This is LTP's strongest security theorem.** It is a composite reduction that chains four
standard cryptographic assumptions. Under NIST Level 3 security (ML-KEM-768 + ML-DSA-65
+ BLAKE3-256), ML-KEM and ML-DSA each provide $\geq 128$ bits of post-quantum security,
while BLAKE3-256 provides ~85-bit post-quantum collision resistance (BHT bound) and
128-bit post-quantum preimage resistance (Grover bound).

#### 3.3.7 What Cannot Be Formally Proven

| Claim | Why It Cannot Be Proven | Status |
|-------|------------------------|--------|
| "Faster than direct transfer" | Performance is empirical. Depends on topology, entity size, node placement. | Acknowledged in §6.4 (cost model) |
| "Geography-independent" | Requires commitment nodes near receivers. No protocol guarantees this. | Deployment-dependent |
| "Sub-latency transfer" | O(1) key size is proven; O(1) total latency is not. MATERIALIZE fetches O(entity) data. | Reframed as "bottleneck relocation" |
| "Secure without trust" | Requires honest append-only log and ≥ k honest shard replicas. These ARE trust assumptions. | Acknowledged in §5.1 |
| "Permanent storage" | Requires economic incentives to sustain nodes. Without incentives, rational nodes evict data. | Acknowledged in §5.4.4, §5.5 |

---

## 4. Immutability Guarantees

> **Informal Summary.** This section provides an accessible explanation of LTP's immutability
> properties for readers who want intuition before the formalism. The authoritative security
> definitions and game-based proofs are in §3.3 (Theorems 3–8). Formal statements, reduction
> bounds, and concrete security parameters are in §3.3; this section provides cross-references
> and prose context only.

### 4.1 Why Immutability Is Inherent

LTP's immutability is a **consequence of the design**, not an added feature. Four structural
properties enforce it; each is formally analyzed in §3.3:

| Design property | Ensures | Formal result |
|-----------------|---------|---------------|
| EntityIDs are content-addressed — `H(content ‖ shape ‖ …)` | One-bit content change produces a different EntityID | Theorem 3 (IMM, §3.3.1) |
| Commitment records are append-only and hash-chained | No party can modify or retract a published commitment | Theorem 6 (NREP, §3.3.4) + log trust model (§5.1.4) |
| Shards carry AEAD authentication tags | Tampering is detected and rejected at decryption | Theorem 4 (SINT, §3.3.2) |
| Lattice keys are sealed and bound to a specific commitment reference | Receiver materializes exactly what the sender committed, verified end-to-end | Theorem 8 (TIMM, §3.3.6) |

See §3.3 for the complete game-based definitions, reduction proofs, and concrete security bounds.

### 4.2 Versioning vs. Mutation

If a sender wants to "update" an entity, they commit a **new entity** with a reference to the
previous one:

```json
{
  "entity_id": "blake3:new_hash...",
  "predecessor": "blake3:old_hash...",
  "version": 2,
  ...
}
```

This creates an immutable **version chain**. Every version exists permanently. "Updating" is
actually "appending a new version." The full history is always auditable.

### 4.3 Immutability ≠ Availability

A critical distinction that protocols often conflate:

| Property | Guarantee | Condition |
|----------|----------|-----------|
| **Immutability** | If data is reconstructed, it is *exactly* what was committed | UNCONDITIONAL — content-addressing ensures any valid reconstruction is authentic. No mechanism exists to produce corrupted data with a valid EntityID. |
| **Availability** | Committed data *can* be reconstructed | CONDITIONAL — requires ≥ $k$ shard indices with ≥ 1 live replica each (see §5.4) |

**Corollary (Immutability — informal restatement of Theorems 3 and 8, §3.3).** Let $E$ be an
entity committed with EntityID $= H(E)$. Any content $E'$ produced by the MATERIALIZE phase
satisfies $E' = E$, or the integrity check fails and the receiver obtains nothing. There is
no intermediate state where the receiver accepts incorrect data. *(Full formal proof:
Theorem 3 via collision resistance of $H$; Theorem 8 via the four-barrier composite reduction.
Both in §3.3.)*

**Remark (Availability Boundary).** Let $A_i$ denote the event that shard index $i$ has
at least one available replica. The entity is reconstructable if and only if
$|\{i : A_i\}| \geq k$. Below this threshold, the entity is **permanently lost** — the
commitment record proves it existed, but the content cannot be recovered.

The failure mode is **graceful, not corrupted**: MATERIALIZE returns nothing rather than
partial or incorrect data. Immutability is never violated — the entity either materializes
exactly or doesn't materialize at all. *(Availability probability model with worked examples:
§5.4.1. Correlated failure model: §5.4.1.1.)*

**Why this tension is fundamental.** Any distributed storage system must accept that
availability is probabilistic: disks fail, operators leave, regions go offline. LTP's
contribution is making the two guarantees *orthogonal*:

- Immutability is enforced by *cryptography* (hashes, signatures, AEAD tags) — it holds
  regardless of network state.
- Availability is enforced by *redundancy* ($k$-of-$n$ erasure coding × $r$-way
  replication) — it degrades with failures but can be restored via repair.

The `ErasureCoder` implements true any-$k$-of-$n$ reconstruction over GF(256), using a
Vandermonde encoding matrix with Gauss-Jordan decoding. This means:

- The first $k$ data shards are NOT privileged — any $k$ shards suffice
- Losing ALL data shards (indices 0 through $k-1$) is survivable if $k$ parity shards remain
- The failure boundary is sharp: at $k$ shards the entity reconstructs exactly; at $k-1$
  it is irrecoverable

See §5.4 for the full availability model, failure modes, and repair protocol.

---

## 5. Commitment Network

The protocol assumes a distributed network of commitment nodes that store encrypted shards
and serve them to authorized receivers. This section addresses how that network comes into
existence, how it resists attacks, and what availability guarantees it can offer.

### 5.1 Bootstrap: How the Network Starts

LTP defines a **permissioned genesis** with a path to progressive decentralization.

#### 5.1.1 Genesis Configuration

A deployment begins with a genesis configuration:

```json
{
  "genesis_version": 1,
  "minimum_nodes": 6,
  "minimum_regions": 3,
  "minimum_admin_domains": 2,
  "genesis_operators": [
    {"id": "operator_a", "attestation": "ml-dsa-65:vk_a...", "region": "US-East"},
    {"id": "operator_b", "attestation": "ml-dsa-65:vk_b...", "region": "EU-West"},
    {"id": "operator_c", "attestation": "ml-dsa-65:vk_c...", "region": "AP-East"}
  ],
  "admission_policy": "permissioned",
  "audit_interval_seconds": 3600
}
```

The genesis set must satisfy:
- At least $2k$ nodes (where $k$ = minimum reconstruction threshold), ensuring no single
  entity of $k$ nodes can reconstruct all shards even before considering encryption
- Nodes span $\geq 3$ geographic regions and $\geq 2$ administrative domains
- Each genesis operator provides an ML-DSA-65 verification key as identity attestation

#### 5.1.2 Why Permissioned Genesis?

A fully permissionless bootstrap (like Bitcoin's) requires a consensus mechanism from block 0
and is vulnerable to early Sybil attacks when the network is small. LTP's commitment network
is a **storage network**, not a ledger — it does not need proof-of-work or proof-of-stake for
its primary function (storing and serving encrypted shards). The trust requirement is lighter:
nodes must be **available** and **honest about storage** (they need not agree on global
transaction ordering).

Starting permissioned and progressively opening admission is the approach taken by
Certificate Transparency [7] and Hyperledger Fabric [8], both of which share LTP's
requirement for append-only integrity without full decentralized consensus.

#### 5.1.3 Progressive Decentralization

The network evolves through three stages:

| Stage | Admission | Sybil Resistance | Trust Model |
|-------|-----------|-------------------|-------------|
| **Genesis** | Curated operators only | Identity verification | Known operators |
| **Permissioned** | Application + endorsement by $m$-of-$n$ existing operators | Identity + storage proofs | Reputation + audit |
| **Open** | Self-registration + storage bond + storage proofs | Economic + cryptographic | Proof-based (minimal trust) |

Transition between stages is governed by the genesis configuration and requires a
supermajority ($\geq 2/3$) of existing operators to approve via signed votes.

#### 5.1.4 Commitment Log Trust Model

The append-only commitment log is foundational to LTP's immutability and non-repudiation
guarantees (Theorems 3, 6, 8 in §3.3). The security proofs assume an idealized log that
cannot be tampered with. In practice, this assumption requires an explicit implementation
choice.

---

> **RECOMMENDED IMPLEMENTATION: CT-style multi-operator Merkle log**
>
> Implementers who need a default SHOULD use the CT-style Merkle log specified
> in §5.1.4.2 below. It satisfies all three formal log assumptions with the weakest
> trust requirement (at least 1 honest operator), uses only LTP's existing primitives
> (BLAKE2b-256 + ML-DSA-65), and requires no consensus protocol.
>
> **Reference implementation:** `src/merkle_log/` in the LTP repository.
> **Reference tests:** `tests/test_merkle_log.py` (42 tests demonstrating
> tamper-evidence, O(log N) inclusion proofs, and equivocation detection).
>
> Other tiers are available for deployments with stronger adversarial requirements:
> BFT for environments where operators may be Byzantine, public blockchain for
> fully decentralized deployments. These escalate complexity and trust cost without
> improving the append-only guarantee for the CT use case.

---

**Formal trust assumptions.** LTP's commitment log requires all three:

| Assumption | Formal Statement | Consequence if Violated |
|-----------|-----------------|------------------------|
| **Append-only integrity** | Once a record $R$ is accepted at position $i$, no operation can modify $R$ or insert a different record at position $i$. | Corollary (§4.3) and Theorem 3 fail — adversary can retroactively alter committed content. |
| **Consistency** | All honest participants observe the same log state (up to bounded propagation delay $\delta$). | Non-repudiation (Theorem 6) fails — sender could present different log states to different verifiers. |
| **Liveness** | A valid commitment record submitted by an honest sender is accepted within bounded time $\Delta$. | Availability degrades — entities cannot be committed. Does NOT affect already-committed entities. |

**Trust tiers.** All four satisfy the formal assumptions; they differ in the strength of
the trust requirement:

| Implementation | Append-Only | Consistency | Trust Requirement | Use when |
|---------------|-------------|-------------|-------------------|----------|
| Single trusted operator | Operator honesty | Trivial (single source) | Full trust in operator | Internal/private deployments only |
| **CT-style multi-operator Merkle log [7]** | **≥ 1 honest operator publishes the tree head** | **Gossip detects forks** | **≥ 1 honest mirror** | **Default — most deployments** |
| BFT replicated log (PBFT/Raft) | $f < n/3$ Byzantine operators | BFT consensus | $> 2/3$ honest operators | Adversarial multi-party environments |
| Public blockchain | Computational hardness (PoW) or economic security (PoS) | Longest-chain / finality gadget | Honest majority of stake/work | Fully decentralized / permissionless |

##### 5.1.4.1 Minimum Conformance Requirements (CT-Style Merkle Log)

An implementation claiming to satisfy the CT-style Merkle log requirement MUST:

| Requirement | Specification |
|-------------|---------------|
| **Tree hash** | Append-only binary Merkle tree; leaf nodes: `H(0x00 \|\| record)`, internal nodes: `H(0x01 \|\| left \|\| right)` — RFC 6962 §2.1 domain separation |
| **Hash primitive** | BLAKE2b-256 — consistent with LTP's content-addressing primitive (§1.2) |
| **Signed Tree Heads** | Each STH MUST be ML-DSA-65 signed over `sequence \|\| tree_size \|\| timestamp \|\| root_hash`; sequence MUST be monotonically increasing per operator |
| **Inclusion proofs** | MUST produce O(log N) sibling-path proofs for any record; any verifier MUST be able to reconstruct the root from (record, proof, tree_size) without holding other records |
| **Equivocation detection** | MUST treat two valid STHs from the same operator at the same sequence number with different root hashes as a self-contained equivocation proof requiring no further data |
| **Operator count** | SHOULD operate with ≥ 2 independent operators exchanging STHs via gossip; 1 operator is permitted for private deployments |

An implementation MUST NOT:
- Modify or delete any record after appending.
- Issue an STH with a lower tree_size than the operator's previous STH.
- Omit the ML-DSA-65 signature from any published STH.

##### 5.1.4.2 Fork Detection and Consistency Verification

**Fork detection.** A *log fork* occurs when an operator presents different log states to
different participants (equivocation). LTP detects this via:

1. **Signed tree heads (STH).** Each log operator periodically signs and publishes:
   $\text{STH}_i = \text{Sign}(sk_{\text{op}}, \text{seq} \| \text{size} \| t \| \text{root})$.
   Receivers SHOULD fetch STHs from multiple operators and check consistency.

2. **Gossip protocol.** Participants exchange STHs. Any pair of valid STHs at the same
   sequence number with different roots is cryptographic proof of equivocation — the
   pair is a self-contained evidence bundle any third party can verify. This follows the
   Certificate Transparency gossip model [7].

3. **Inclusion proofs.** The log provides an O(log N) Merkle audit path proving a
   commitment record exists in the tree committed by a given STH. Receivers verify this
   proof independently before accepting materialization.

**What happens if the log is compromised?**

| Attack | Impact | Detection | Recovery |
|--------|--------|-----------|----------|
| Operator withholds records | New commits blocked; existing entities unaffected | Liveness timeout; failover to alternate operator | Switch to healthy operator; re-submit pending commits |
| Operator equivocates (fork) | Different receivers see different logs | Gossip detects inconsistent STHs; equivocation proven by two conflicting STHs alone | Equivocation proof published; operator evicted; logs merged |
| Operator deletes a record | Non-repudiation violated for that record | Any participant with a cached STH + inclusion proof detects deletion | Cached proofs serve as evidence; operator evicted |
| All operators compromised | Full log integrity lost | No automated detection | Catastrophic — requires manual recovery and network re-bootstrap |

**Minimum viable trust for non-repudiation:** Theorem 6 (non-repudiation) holds if at
least one honest participant (operator, receiver, or auditor) retains a copy of the STH
at the time the commitment was made. The commitment record's ML-DSA signature is
self-authenticating — it can be verified against the sender's public key without trusting
the log. The log's role is to prevent the sender from denying the *existence* of the
commitment, not its *authenticity*.

### 5.2 Sybil Resistance

A Sybil attack occurs when an adversary creates many fake identities to gain disproportionate
influence. In LTP's context, a Sybil attacker controlling many nodes could:
- Dominate shard placement (receive most shards via consistent hashing)
- Coordinate to withhold shards (availability attack)
- In pre-Option-C designs, coordinate to reconstruct data (confidentiality attack — **now mitigated**)

LTP employs a dual-layer Sybil defense:

#### 5.2.1 Layer 1: Identity Verification

Every commitment node must prove its identity through one of:

| Method | Stage | Mechanism |
|--------|-------|-----------|
| Operator attestation | Genesis / Permissioned | Organizational identity verified by existing operators |
| SPIFFE/SPIRE SVID [11] | Permissioned / Open | Short-lived X.509 workload identity, automatically rotated |
| Economic bond | Open | Deposit stake to a smart contract; stake slashed on misbehavior |

Each identity method binds a node to a **verifiable identity** that is expensive to replicate
at scale. An attacker cannot cheaply create thousands of identities.

#### 5.2.2 Layer 2: Storage Proofs

Identity alone is insufficient — a node could register legitimately but not actually store
data. LTP requires ongoing **proof-of-storage** via a challenge-response protocol with
anti-outsourcing measures:

```
Auditor → Node:  Challenge(entity_id, shard_index, nonce, deadline=now+T)
Node → Auditor:  Proof(H(encrypted_shard || nonce), response_time)    [within T]
```

- The auditor sends a random nonce and a specific (entity_id, shard_index) pair
- The node must return `H(ciphertext || nonce)` within a **strict time bound** $T$
- Since shards are AEAD-encrypted, the node computes over **ciphertext** — no plaintext
  access is needed and no confidentiality is compromised
- The auditor can verify the response because it knows the expected `H(ciphertext || nonce)`
  (it can compute this from the data it observed during the commit phase, or by fetching
  the shard from a different replica)

**Anti-outsourcing measures.** The primary weakness of challenge-response storage proofs is
that a node can outsource storage and re-fetch data when challenged. LTP employs three
layered mitigations:

1. **Tight time bound** $T$**.** The challenge window $T$ MUST be set below the network
   round-trip time to the nearest other replica. Specifically:
   $$T < \min_{j \neq i} \text{RTT}(\text{node}_i, \text{replica}_j) - \epsilon$$
   where $\epsilon$ accounts for hash computation time. If $T = 50\text{ms}$ and the
   nearest replica is 100ms away, the node cannot re-fetch in time. The auditor records
   response latency; consistently near-deadline responses trigger escalated auditing.

   **Calibrating T in practice.** The ideal T is deployment-specific and requires active
   measurement:

   - **Historical latency profiling.** During network bootstrap, and re-evaluated whenever
     the node set changes significantly, auditors SHOULD measure pairwise RTT distributions
     between known replica locations. A conservative target: set $T \leq P_{10}(\text{RTT}_{\text{nearest replica}}) - \epsilon$,
     so that at least 90% of measured RTTs to any nearby replica exceed $T$. This ensures a
     co-located but legitimately storing node passes comfortably, while a node that must
     network-fetch is caught most of the time.

   - **Adaptive bounds.** Auditors SHOULD track per-node response latency over time. A node
     whose latency distribution shifts toward the $T$ boundary (e.g., P75 latency exceeds
     $0.8T$) is flagged for escalated auditing even if it has not yet missed a deadline.

   - **Variable network conditions.** RTTs vary with congestion, routing changes, and
     hardware load. $T$ should be re-evaluated periodically (e.g., on a weekly basis) and
     should be set conservatively: a false positive (honest node fails due to transient
     latency spike) is recoverable; a false negative (outsourcing node passes due to a
     tight $T$) is undetected.

2. **Burst challenges.** Instead of one challenge per audit, the auditor issues $b$
   challenges for **random** (entity_id, shard_index) pairs simultaneously. The node must
   respond to all $b$ within the same window $T$. A node that stores legitimately performs
   $b$ local disk reads (~1ms each for SSD). A node that outsources must perform $b$
   network fetches — the bandwidth and latency quickly exceed $T$.
   $$\text{Outsourcing cost} = b \times \text{RTT}_{\text{fetch}} + b \times \text{shard\_size} / \text{bandwidth}$$

3. **Economic deterrent.** Audit failure triggers bond slashing. The bond MUST be set such
   that the expected penalty from random audits exceeds the cost savings from outsourcing:
   $$\text{bond\_slash} \times P(\text{caught}) > \text{storage\_cost\_saved} \times \text{period}$$
   This makes outsourcing economically irrational even if individual challenges can
   sometimes be passed dishonestly.

**Honest limitation.** The time-bound $T$ is a **statistical deterrent**, not a cryptographic
guarantee. Its effectiveness depends entirely on the gap between an outsourcing node's
re-fetch latency and $T$:

$$P(\text{catch outsourcing node}) \approx P\!\left(\text{RTT}_{\text{fetch}} + \frac{\text{shard\_size}}{\text{bandwidth}_{\text{fetch}}} > T\right)$$

A node with a co-located proxy 5ms away trivially passes a $T = 50\text{ms}$ bound; a node
re-fetching from a datacenter 200ms away is reliably caught. The expected detection rate is
a function of the adversary's infrastructure, not a fixed security parameter. These measures
raise the cost of outsourcing significantly but do NOT provide cryptographic proof-of-storage.
For deployments requiring a cryptographic guarantee, LTP recommends augmenting with
proof-of-replication (PoRep) at the cost of SNARK overhead (as in Filecoin's PoSt). For
most deployments, time-bounded burst challenges with economic bonds provide a practical and
operationally tractable deterrent.

**Why this is simpler than Filecoin's Proof-of-Replication:**

Filecoin requires Proofs of Replication (PoRep) and Proofs of Spacetime (PoSt) to prevent
nodes from generating data on-the-fly or outsourcing storage. These require SNARKs, VDFs
(verifiable delay functions), and a sealing ceremony. LTP's storage proofs are lighter because:

1. **No deduplication defense needed.** Filecoin must prove *unique* physical copies exist
   (to prevent a node from storing one copy and claiming storage for many). LTP doesn't care
   about physical uniqueness — if a node can serve the correct ciphertext, that's sufficient.

2. **No proof-of-spacetime needed.** Filecoin must prove *continuous* storage over time via
   periodic SNARK proofs. LTP uses periodic random challenges with burst probing — simpler
   but weaker. The time-bounded burst challenge ($b$ challenges within $T$) limits how far
   away re-fetch storage can be, and economic bonds make the penalty for audit failure
   outweigh the savings from shirking.

3. **Ciphertext is randomly verifiable.** Since encrypted shards are deterministic (same CEK +
   entity_id + shard_index → same derived nonce → same ciphertext), any party with a copy
   can verify any other party's claim.

#### 5.2.3 Audit Protocol

Audits are performed by a rotating set of auditors selected from the existing operator pool:

```
┌─────────────────────────────────────────────────────────────┐
│                    AUDIT PROTOCOL                            │
│                                                              │
│  1. Auditor selection: round-robin from operators            │
│  2. Target selection: random (entity_id, shard_index) pair   │
│     from the commitment log                                  │
│  3. Challenge: Auditor sends (entity_id, index, nonce)       │
│  4. Response: Node returns H(ciphertext || nonce) within T   │
│  5. Verification: Auditor compares against known-good hash   │
│  6. Result:                                                  │
│     ✓ Pass → node reputation +1                              │
│     ✗ Fail → strike recorded                                 │
│     ✗✗ 3 strikes → eviction + bond slash (if applicable)     │
│  7. Repair: evicted node's shards re-replicated to healthy   │
│     nodes (ciphertext only — no plaintext exposed)           │
└─────────────────────────────────────────────────────────────┘
```

The audit interval is configurable (default: every 3600 seconds per node). A node that fails
3 consecutive audits is evicted. Its shards are re-replicated from surviving replicas to
maintain the replication factor $r$.

### 5.3 Collusion Resistance

The collusion question is: **what if $k$ or more nodes conspire to pool their shards and
reconstruct an entity?**

#### 5.3.1 Pre-Option-C (Broken)

In the original design (plaintext shards), $k$ colluding nodes holding distinct shard indices
could reconstruct the full entity via erasure decoding. This was a real vulnerability.

#### 5.3.2 Post-Option-C (Mitigated)

With Option C (implemented in LTP v2), all shards are AEAD-encrypted with a random CEK before
distribution. Colluding nodes face the following:

```
k colluding nodes pool encrypted shards
  → Erasure decode ciphertext → encrypted entity (useless without CEK)
  → CEK exists ONLY inside the sealed lattice key
  → Sealed lattice key is ML-KEM-encapsulated to the receiver's ek
  → Collusion without CEK is computationally equivalent to breaking AEAD
```

**Formal argument:** Let $\mathcal{A}$ be an adversary controlling $k$ or more nodes. $\mathcal{A}$
possesses $k$ encrypted shards $\{E_i = \text{AEAD}(CEK, S_i, i)\}_{i \in K}$ where $|K| \geq k$.
To recover any plaintext shard $S_i$, $\mathcal{A}$ must break the IND-CPA security of the AEAD
scheme without knowledge of CEK. The CEK is:

- Never transmitted to any commitment node
- Only present inside the sealed lattice key (ML-KEM-768 encapsulated to receiver)
- Generated fresh per entity (no key reuse across entities)

Therefore, node collusion reduces to AEAD key recovery, which is computationally infeasible
under standard assumptions.

**What collusion CAN still achieve:**

| Attack | Can colluding nodes do it? | Mitigation |
|--------|---------------------------|------------|
| Read plaintext content | **No** — shards are AEAD-encrypted | Option C |
| Reconstruct encrypted entity | **Yes** — but useless without CEK | Option C |
| Withhold shards (availability attack) | **Yes** — denial of service | Replication + audit |
| Delete shards | **Yes** — but detected by audit | Audit + repair protocol |
| Serve corrupted shards | **No** — AEAD tag verification catches corruption | AEAD integrity |

The residual risk from collusion is **availability**, not **confidentiality**. This is addressed
in Section 5.4.

### 5.4 Data Availability

Immutability guarantees that committed data **cannot be changed**. Availability guarantees
that committed data **can be accessed**. LTP provides probabilistic availability guarantees,
not absolute ones.

#### 5.4.1 Availability Model

Given:
- $n$ = total shards per entity
- $k$ = reconstruction threshold ($k < n$)
- $r$ = replication factor (copies of each shard across independent nodes)
- $p$ = probability a single node is unavailable (crash, eviction, network partition)

A shard index $i$ is available if **at least 1** of its $r$ replicas is online:

$$P(\text{shard}_i \text{ available}) = 1 - p^r$$

The entity is available if **at least $k$** of $n$ shard indices have at least one live replica:

$$P(\text{entity available}) = \sum_{j=k}^{n} \binom{n}{j} (1 - p^r)^j \cdot (p^r)^{n-j}$$

**Worked example** ($n = 8, k = 4, r = 3, p = 0.1$):

$$P(\text{shard}_i \text{ available}) = 1 - 0.1^3 = 0.999$$

$$P(\text{entity available}) = \sum_{j=4}^{8} \binom{8}{j} (0.999)^j (0.001)^{8-j} \approx 0.999\,999\,999\,97$$

Even with 10% individual node failure rate, the combination of erasure coding ($k$-of-$n$)
and replication ($r$ copies) produces >99.9999999% availability. This is the power of
compounding two orthogonal redundancy mechanisms.

**Important caveat: independence assumption.** The formula above assumes node failures are
independent events. In real-world deployments, failures are highly correlated: cloud provider
outages, network partitions, and regional disasters affect multiple nodes simultaneously.
The worked example above is technically correct under independence but potentially misleading.
See §5.4.1.1 for a correlated failure model that provides realistic availability estimates.

##### 5.4.1.1 Correlated Failure Model

To model realistic failures, we partition nodes into $R$ **failure domains** (typically
geographic regions or administrative domains). Nodes within the same domain experience
correlated failures: when a domain-level event occurs (cloud outage, network partition),
all nodes in that domain fail simultaneously.

Let:
- $R$ = number of failure domains
- $p_d$ = probability of a domain-level failure (e.g., regional cloud outage)
- $p_n$ = probability of an independent node failure (within a healthy domain)
- Each shard index has $r$ replicas, distributed across at least $\min(r, R)$ domains

A shard index $i$ with replicas in domains $D_1, D_2, \ldots, D_r$ is unavailable when
all replicas are down. Under the correlated model, replica $j$ in domain $D_j$ fails if:
- The domain fails (probability $p_d$), OR
- The individual node fails (probability $p_n$), independently

The combined per-replica failure probability is:
$$p_{\text{replica}} = p_d + (1 - p_d) \cdot p_n = p_d + p_n - p_d \cdot p_n$$

If replicas are in **independent** domains:
$$P(\text{shard}_i \text{ unavailable}) = \prod_{j=1}^{r} p_{\text{replica},j}$$

If replicas are in the **same** domain (worst case):
$$P(\text{shard}_i \text{ unavailable}) = p_d + (1 - p_d) \cdot p_n^r$$

**Worked example** ($n = 8, k = 4, r = 3$ replicas across $R = 3$ independent regions,
$p_d = 0.01$ regional outage, $p_n = 0.05$ individual node failure):

With cross-region distribution:
$$p_{\text{replica}} = 0.01 + 0.05 - 0.01 \times 0.05 = 0.0595$$
$$P(\text{shard}_i \text{ unavailable}) = 0.0595^3 \approx 2.1 \times 10^{-4}$$
$$P(\text{shard}_i \text{ available}) \approx 0.99979$$

With same-region colocation (anti-pattern):
$$P(\text{shard}_i \text{ unavailable}) = 0.01 + 0.99 \times 0.05^3 \approx 0.01012$$
$$P(\text{shard}_i \text{ available}) \approx 0.98988$$

| Placement | Per-shard availability | Entity availability ($k$=4 of $n$=8) |
|-----------|----------------------|--------------------------------------|
| Independent assumption ($p=0.1$) | 99.9% | 99.9999999% |
| Cross-region (realistic) | 99.98% | 99.999997% |
| Same-region (anti-pattern) | 98.99% | 99.58% |

The difference is stark: same-region colocation drops entity availability from "nine nines"
to barely two nines. This is why the genesis configuration requires `minimum_regions ≥ 3`
and the placement algorithm MUST distribute replicas across independent failure domains.

**Deployment requirement:** The shard placement algorithm (§2.1.2) MUST satisfy the
following constraint:
$$\forall i : |\{\text{domain}(\text{replica}_j) : j \in \text{replicas}(i)\}| \geq \min(r, R)$$

That is, replicas of the same shard index MUST be placed in as many distinct failure
domains as possible. The PoC demonstrates this via region-aware consistent hashing.

**Caveat: cross-domain independence.** The correlated failure model above addresses
*intra-domain* correlation (all nodes in a failed domain go down together) but still
assumes *cross-domain* independence: the failure of domain $D_i$ is independent of domain
$D_j$. This assumption does not model global cloud provider outages, shared DNS failures,
coordinated adversarial attacks, or common-mode software failures that affect multiple
domains simultaneously. Deployments facing such correlated cross-domain risks should
account for them separately.

**Erasure coding guarantee.** The availability model assumes ANY $k$ shards are sufficient
for reconstruction — not just the first $k$ "data" shards. The reference implementation
achieves this via a Vandermonde encoding matrix over GF(256) with Gauss-Jordan decoding.
Shard indices are not privileged: losing all "data" shards is recoverable if $k$ "parity"
shards survive. The proof-of-concept demonstrates this explicitly (see demo: "Degraded
Materialization").

#### 5.4.2 Failure Modes and Repair

| Failure | Detection | Response |
|---------|-----------|----------|
| Single node crash | Audit challenge timeout | Re-replicate affected shards from surviving replicas |
| Region outage | Multiple audit failures in same region | Trigger cross-region re-replication |
| Node eviction (misbehavior) | 3 consecutive audit failures | Slash bond, redistribute shards |
| Correlated failure ($> n - k$ shard indices lost) | MATERIALIZE returns < k shards | Entity becomes **permanently unavailable** (committed but inaccessible) |

**Repair protocol:** When a node is evicted or detected as failed, the network executes:

```
1. Identify all (entity_id, shard_index) pairs stored on the failed node
2. For each pair, check if other replicas exist on healthy nodes
3. If replica exists: copy encrypted shard to a new node (assignment via consistent hash)
4. If no replica exists: shard index is marked DEGRADED (reduced redundancy)
5. Update replication metadata
```

Critically, repair operates on **ciphertext**. The repair process never requires the CEK or
any access to plaintext. Any authorized node can store a replica without learning content.

#### 5.4.3 The CAP Theorem and LTP

LTP's commitment network must navigate the CAP theorem:

| CAP Property | LTP's Choice |
|-------------|-------------|
| **Consistency** | Commitment log is strongly consistent (append-only, hash-chained). Shard storage is eventually consistent (replicas may lag). |
| **Availability** | Probabilistic (see §5.4.1). Not guaranteed under correlated failure of $> n - k$ shard indices. |
| **Partition Tolerance** | Supported. Partitioned regions serve locally-cached shards; commitment log reconciles post-partition. |

**Honest assessment:** LTP prioritizes **consistency** (immutability is non-negotiable) and
**partition tolerance** (geographically distributed by design). Availability is probabilistic
and degrades under correlated failures. This is the same tradeoff made by Tahoe-LAFS [3]
and Storj [4].

#### 5.4.4 Availability vs. Permanence

The commitment record is **permanent** (on the append-only log). The shards are **available
with high probability** but not guaranteed permanent:

- Shards may have a **TTL (time-to-live)** after which nodes MAY evict them
- Without economic incentives, rational nodes have no reason to store data indefinitely
- For permanent storage, senders must **renew TTL** (potentially with payment)
- The commitment record survives even if all shards are evicted — the entity is proven to
  have existed, but can no longer be materialized

This mirrors Filecoin's deal model: storage is a service, not a right. The protocol
guarantees immutability and integrity; availability requires ongoing economic commitment.

### 5.5 Network Economics (Interface, Not Implementation)

LTP intentionally does **not** specify a token, a consensus mechanism, or a fee schedule.
Instead, it defines **interfaces** that any economic layer must satisfy:

```
Interface: NodeIncentive
  - compensate(node_id, bytes_stored, seconds_stored, bytes_served) → reward
  - slash(node_id, audit_failure_count) → penalty

Interface: CommitmentPricing
  - price(entity_size, replication_factor, ttl_seconds) → cost
  - renew(entity_id, additional_ttl) → cost

Interface: AdmissionControl
  - apply(node_identity, storage_proof, bond) → accepted | rejected
  - evict(node_id, reason, audit_evidence) → confirmation
```

**Why not specify economics?** The optimal incentive mechanism depends on deployment context:

| Deployment | Economic Model | Example |
|-----------|---------------|---------|
| Enterprise (private) | Organizational obligation | Internal SLA — nodes run by IT departments |
| Consortium | Mutual obligation + SLA | CT log operators [7] — run by CAs for collective benefit |
| Public (open) | Token/payment + staking | Filecoin [5], Storj [4] — economic incentives |

Specifying a token would limit LTP to public deployments. Specifying organizational obligation
would limit it to enterprises. The interface layer allows any of these.

---

## 6. Breaking the Constraints

### 6.1 Latency

**Traditional**: Latency = f(distance, hops, payload_size)  
**LTP**: Latency = f(key_transmission) + f(nearest_shard_fetch)

The sealed lattice key is ~1,300 bytes (increased from ~240 bytes pre-quantum due to
ML-KEM-768 ciphertext overhead — the honest cost of quantum resistance). Its transmission
is near-instantaneous on any network. Shard fetching is parallelized from the nearest nodes.

The bottleneck relocation principle is explained in §2.3.2; the formal latency equations
and sensitivity analysis are in §6.4.

### 6.2 Geographic Distance

**Traditional**: New York → Tokyo = ~200ms RTT minimum (speed of light through fiber).  
For a 1 GB file at 100 Mbps effective throughput: ~80 seconds, bottlenecked by the single path.

**LTP**: The sender in New York transmits a ~1,300-byte sealed key to the receiver in Tokyo
(one round trip, ~200ms). The receiver then fetches k encrypted shards in parallel from
Tokyo-local commitment nodes (~5-10ms RTT each). Materialization time is dominated by
*local bandwidth*, not transoceanic latency.

The geographic cost is paid **once** when shards are distributed to the commitment network
during the commit phase (this happens asynchronously, before any receiver is involved).
Subsequent materializations by any receiver anywhere draw from *nearby nodes*.

**Honest tradeoff:** The commit phase requires distributing O(entity × replication) bytes
across the global network. For a single sender → single receiver transfer, total system
bandwidth is higher than direct transfer. For the full cost model, break-even analysis, and
"where LTP wins / loses honestly," see §6.4.

### 6.3 Computing Power

**Traditional**: Sender must serialize, compress, encrypt, and transmit. Receiver must receive,
decrypt, decompress, and deserialize. Both need sufficient compute.  
**LTP**: The heavy work (erasure encoding, shard distribution) is done once at commit time and
can be offloaded to the commitment network. Materialization (erasure decoding from k shards) is
computationally lightweight and highly parallelizable.

### 6.4 Formal Cost Model

Let:
- $D$ = entity size in bytes
- $n$ = total shards, $k$ = reconstruction threshold
- $r$ = replication factor per shard (copies of each shard across independent nodes)
- $\rho = nr/k$ = combined expansion factor (erasure coding expansion $n/k$ times replication $r$)
- $N$ = number of receivers
- $L_{SR}$ = latency between sender and receiver
- $L_{RN}$ = latency between receiver and nearest commitment node
- $L_{\log}$ = latency for commitment record lookup from the append-only log (step 2 of MATERIALIZE)

**Bandwidth costs:**

Reed-Solomon $(n, k)$ encoding produces $n$ shards, each of size $\lceil D/k \rceil$ bytes.
Each shard is replicated $r$ times across the commitment network. The total sender upload
during the commit phase is therefore $n \cdot (D/k) \cdot r = D \cdot nr/k = D\rho$, not $D \cdot r$.
The factor of $n/k$ represents the erasure coding expansion that occurs *before* replication.

| Metric | Direct Transfer | LTP |
|--------|----------------|-----|
| Sender upload (per transfer) | $D$ | — (already committed) |
| Sender upload (commit, once) | — | $D \cdot nr/k = D\rho$ |
| Sender→receiver direct | $D$ | $O(1)$ (~1,300 bytes) |
| Receiver download | $D$ | $D$ (k shards × $D/k$) |
| **Total system, 1 receiver** | $D$ | $D\rho + D = D(\rho+1)$ |
| **Total system, N receivers** | $D \cdot N$ | $D\rho + D \cdot N$ |
| **Amortized per receiver (N large)** | $D$ | $\approx D$ |

**Key formula — total system bandwidth:**

$$B_{LTP}(N) = D\rho + D \cdot N = D \cdot \frac{nr}{k} + D \cdot N$$
$$B_{direct}(N) = D \cdot N$$

For $N = 1$: $B_{LTP} = D(\rho+1) > D = B_{direct}$. **LTP is strictly worse for single-transfer bandwidth.**

For $N > \rho$: $B_{LTP} \approx D \cdot N \approx B_{direct}$. **LTP amortizes to parity.**

At the default parameters ($n = 64$, $k = 32$, $r = 3$): $\rho = 64 \cdot 3 / 32 = 6$.
Break-even occurs at $N > 6$ receivers (not $N > 3$).

For large $N$: The commit cost $D\rho$ becomes negligible. Each additional receiver costs only
$D$ (local shard fetches) + ~1,300 bytes (sealed key). Sender bandwidth is constant after commit.

**Latency costs:**

$$T_{direct} = L_{SR} + \frac{D}{\text{bandwidth}_{SR}}$$

$$T_{LTP} = \underbrace{L_{RN} + \frac{1300}{\text{bandwidth}_{SR}} + L_{\log}}_{\text{key + record lookup (negligible)}} + \underbrace{\frac{D/k}{\alpha \cdot \text{bandwidth}_{RN}}}_{\text{k parallel shard fetches}}$$

where $\alpha \in (0, 1]$ is a **parallelism efficiency factor** representing the fraction of
theoretical parallel bandwidth actually achieved. The ideal case $\alpha = 1$ (full parallelism)
requires dedicated per-shard connections with no receiver-side or node-side contention.
In practice $\alpha < 1$ due to:

- **TCP connection overhead**: Each shard fetch requires a connection (or stream), adding
  per-connection handshake latency, especially pronounced when $k$ is large.
- **Node-side I/O scheduling**: If multiple receivers are fetching from the same commitment
  node simultaneously, node disk I/O contention degrades throughput.
- **Receiver bandwidth cap**: If $k \cdot \text{bandwidth}_{RN} > \text{bandwidth}_{receiver}$,
  the receiver's uplink becomes the bottleneck and the parallel advantage is bounded by
  $\text{bandwidth}_{receiver} / (D/k)$, not by node bandwidth.
- **Straggler effect**: $T_{LTP}$ is determined by the *slowest* of the $k$ shard fetches.
  Under load, tail latency can dominate.

**Sensitivity to $\alpha$:**

| Scenario | $\alpha$ | $T_{LTP}$ relative to ideal |
|----------|----------|---------------------------|
| Dedicated bandwidth, no contention | $\approx 1.0$ | Ideal |
| Shared nodes, moderate load | $\approx 0.5$–$0.8$ | $1.25$–$2\times$ slower |
| Receiver bandwidth-limited | $\approx \text{bandwidth}_{receiver} / (k \cdot \text{bandwidth}_{RN})$ | Bottlenecked by receiver |
| High-contention shared nodes | $\approx 0.2$–$0.4$ | $2.5$–$5\times$ slower |

The latency advantage claimed by LTP holds when $\alpha \cdot \text{bandwidth}_{RN} \gg \text{bandwidth}_{SR}$.
For small $\alpha$ (high contention deployments), the advantage narrows. Actual $\alpha$ should
be measured empirically for each deployment topology before relying on the latency model.

When $\text{bandwidth}_{RN} \gg \text{bandwidth}_{SR}$ and $\alpha$ is close to 1 (receiver near
low-contention commitment nodes, far from sender), $T_{LTP} \ll T_{direct}$. This is the
latency advantage.

When $\alpha \cdot \text{bandwidth}_{RN} \approx \text{bandwidth}_{SR}$ (equidistant or high
contention), $T_{LTP} \approx T_{direct}$ but with the sender free to go offline.

**Where LTP wins honestly:**
1. Fan-out: $N$ receivers for near-constant sender cost
2. Latency: receiver-local fetches vs. sender-distance fetches
3. Sender-independence: sender contributes zero bandwidth after commit
4. Availability: shards survive sender going offline

**Where LTP loses honestly:**
1. Single-transfer bandwidth: $\rho + 1 = nr/k + 1$ times worse than direct (e.g., $7\times$ at $n=64, k=32, r=3$)
2. Storage: the commitment network stores $D \cdot nr/k$ bytes persistently
3. Complexity: three-phase protocol vs. one-phase direct send
4. **Deduplication:** no coalescing across commits — every commit pays the full $D \cdot nr/k$
   storage cost regardless of overlap with prior versions. Storage cost implications for
   high-churn workloads:

   | Workload | Storage cost (no dedup) | Mitigation |
   |----------|------------------------|------------|
   | **Version control** (M commits, ~D bytes each) | $M \cdot D \cdot nr/k$ — full snapshot per commit | Delta-encode *before* committing; commit the delta as the entity, not the full snapshot |
   | **Incremental backup** (M daily snapshots of D bytes) | $M \cdot D \cdot nr/k$ — even if only fraction $\delta$ of content changes per run | Same: commit the changed blocks as distinct entities; reconstruct by layering at the application layer |
   | **Collaborative editing** (P editors commit near-identical versions) | $P \cdot D \cdot nr/k$ per round | Merge at the application layer before committing; commit the canonical merged entity only |
   | **Fan-out** (N receivers, 1 commit) | $D \cdot nr/k$ (once) | Favorable case — this is LTP's primary use case |

   ContentHash (§1.2) provides storage-layer deduplication for *byte-identical* commits at the
   cost of revealing content equality to log observers. For version control and backup workloads
   the practical recommendation is to apply delta encoding or content deduplication *before*
   the COMMIT phase — each LTP entity should represent a distinct logical unit, not an
   intermediate edit state.

---

## 7. Comparison with Existing Approaches

| Property | TCP/IP | IPFS | BitTorrent | Tahoe-LAFS | Storj | **LTP** |
|----------|--------|------|-----------|------------|-------|---------|
| Payload travels sender→receiver | Yes | Partial | Partial | No | No | **No** |
| Content-addressed | No | Yes | Partial | Yes | Yes | **Yes** |
| Immutable | No | Yes | No | Yes | Yes | **Yes** |
| Client-side encryption | TLS layer | No | No | **Yes** | **Yes** | **Yes** |
| Shards encrypted at rest | N/A | No | No | **Yes** | **Yes** | **Yes** |
| Erasure-coded redundancy | No | No | No | **Yes** | **Yes** | **Yes** |
| Sender→receiver path O(1) | No | No | No | No | No | **Yes** |
| Capability-based access control | No | No | No | **Yes** | **Yes** | **Yes** |
| Capability bound to receiver identity | No | No | No | No | No | **Yes (ML-KEM)** |
| Forward secrecy (PQ) | TLS layer | No | No | No | No | **Yes (ML-KEM)** |
| PQ signatures on commitments | No | No | No | No | No | **Yes (ML-DSA)** |
| ZK privacy mode | No | No | No | No | No | **Yes†** |
| Survives sender going offline | No | If pinned | If seeded | **Yes** | **Yes** | **Yes** |
| Receiver proximity optimization | No | Partial | Partial | No | Partial | **Yes** |
| Deterministic shard placement | No | DHT | DHT peers | Server-assigned | Server-assigned | **Consistent hash** |
| Append-only audit log | No | No | No | No | No | **Yes** |
| **Protocol complexity** | Low | Medium | Low | High | High | **Very High** |
| **Production deployment maturity** | Ubiquitous | Production | Ubiquitous | Limited | Production | **Research prototype** |
| **Single-transfer overhead** | Minimal | Low | Low | Moderate | Moderate | **High (commit + lattice + materialize round-trips)** |

† ZK privacy mode uses Groth16 over BLS12-381, which is **not post-quantum safe** (broken by
Shor's algorithm). Standard mode provides full post-quantum security. ZK mode MUST NOT be
used under a quantum-adversary threat model. See §3.2.4 and the Abstract warning.

**Reading guide:** LTP's unique cells (only LTP has "Yes") are: O(1) sender→receiver path,
receiver-bound capabilities, per-message PQ forward secrecy, PQ-signed append-only audit log,
and ZK privacy mode (standard mode only is fully PQ-safe). The encrypted storage, erasure coding, and capability-based access that
LTP shares with Tahoe-LAFS and Storj are acknowledged as prior art — see Section 8. The final
three rows reflect dimensions where LTP is weakest: LTP's three-phase design introduces
significant protocol complexity compared to point-to-point alternatives; it is currently a
research prototype with no production deployment; and for single-receiver, small-payload
transfers, the commit+lattice+materialize overhead dominates (see §6.4).

### Erasure Coding Durability Comparison

Concrete durability measurements from production systems, measured in "nines" (e.g., 99.99% = four nines):

| System | Parameters | Expansion Factor | Durability (10% churn) | Repair Bandwidth |
|--------|-----------|:----------------:|:---------------------:|:----------------:|
| **LTP** | k=4, n=8, r=3 | 2x (×3 replication) | 99.9999999% (theory, independent) | O(k) per shard |
| **Storj** | k=29, n=80 | 2.76x | 11 nines | ~55% of replication |
| **Storj** | k=16, n=32 | 2x | Higher than 10x replication | — |
| **Filecoin** | RS + PoRep | 3–10x | Cryptographic proof (PoSt) | Full sector re-seal |
| **Tahoe-LAFS** | k=3, n=10 | 3.33x | Provider-independent | Full re-encode |

Data sourced from Storj file redundancy documentation [storj.dev/learn/concepts/file-redundancy] and Filecoin specification. LTP's theoretical availability assumes independent node failures (§5.4.1); correlated failure model in §5.4.1.1 provides more conservative estimates.

---

## 8. Related Work and Prior Art

LTP is not built in a vacuum. Its design draws from, recombines, and extends ideas pioneered by
decades of work in distributed systems, cryptography, and peer-to-peer networking. This section
honestly acknowledges the lineage and articulates what — if anything — LTP contributes beyond
its predecessors.

### 8.1 Content-Addressed Storage

**IPFS (InterPlanetary File System, 2015)** [1] introduced content-addressed, Merkle-DAG-based
storage to mainstream distributed systems. In IPFS, files are split into blocks, each identified
by a cryptographic hash (CID), and retrieved by requesting the CID from the network. Peers who
have fetched a block can re-serve it, creating BitTorrent-like swarming.

**Git (2005)** [2] pioneered the idea that a repository's entire history could be addressed by
content hashes (SHA-1, now SHA-256). Every commit, tree, and blob is content-addressed, making
the history immutable and independently verifiable.

**What LTP borrows:** Content-addressing as the identity function (`EntityID = H(content || ...)`).
This is not novel — it is a direct application of the same principle.

**Where LTP diverges:** In IPFS, any peer with the CID can fetch the content; there is no built-in
access control. In LTP, knowing the `entity_id` is insufficient — the receiver also needs the
Content Encryption Key (CEK), which is sealed inside the lattice key. IPFS retrieval is
*permissionless*; LTP materialization is *capability-gated*. Additionally, LTP encrypts all shards
at rest (AEAD with CEK), whereas IPFS blocks are stored and served in plaintext by default.

### 8.2 Erasure-Coded Distributed Storage

**Tahoe-LAFS (Least-Authority File Store, 2007)** [3] was among the first systems to combine
erasure coding with capability-based access control for untrusted storage. Files are encrypted
client-side, erasure-coded into shares, and distributed to storage servers. Capabilities (read-caps,
write-caps) are unforgeable tokens that grant specific access rights. Tahoe-LAFS coined the
principle: *"the server doesn't learn anything about the data."*

**Storj (2018)** [4] applies Reed-Solomon erasure coding over a decentralized network of storage
nodes. Files are encrypted client-side, split into 80 pieces (of which any 29 can reconstruct),
and distributed to independent operators. Access grants (serialized macaroons) authorize retrieval.

**Filecoin (2020)** [5] extends IPFS with cryptoeconomic guarantees: storage providers submit
Proofs of Replication and Proofs of Spacetime to demonstrate that data is physically stored.
This addresses the data availability problem that LTP's Section 10 (Open Questions) leaves open.

**What LTP borrows:** Erasure coding for redundancy and threshold reconstruction (k-of-n); client-side
encryption before distribution; the property that storage nodes cannot read content.

**Where LTP diverges:** Tahoe-LAFS, Storj, and Filecoin are *storage systems* — they address "how
do I store data durably on untrusted nodes?" LTP frames the same infrastructure as a *transfer
protocol* — the question is "how does entity X get from sender A to receiver B," with the storage
layer as an intermediate step rather than the end goal. The distinction is one of framing and
protocol-level abstraction: LTP's three-phase model (commit → lattice → materialize) treats
the distributed storage as a side-effect of the commit phase, not as the primary interface.

Whether this framing is a meaningful contribution or merely a relabeling is a fair question.
We argue the value lies in the protocol-level UX: the sender thinks in terms of "commit and
lattice," not "upload to storage provider and share access grant." The operational semantics
differ even if the underlying mechanisms are similar.

### 8.3 Append-Only Commitment Logs

**Bitcoin (2008)** [6] introduced the hash-chained, proof-of-work append-only ledger. Each block
references the hash of the previous block, making history tamper-evident.

**Certificate Transparency (2013)** [7] applies Merkle-tree append-only logs to TLS certificate
issuance. CAs must publish certificates to public logs, and anyone can verify that a certificate
was (or was not) logged. CT logs are simpler than blockchain — they require only a trusted log
operator (or multiple operators for cross-verification) rather than decentralized consensus.

**Hyperledger Fabric (2018)** [8] demonstrates that append-only commitment logs need not be
permissionless blockchains — permissioned channels with endorsement policies can achieve
immutability with lower latency and without proof-of-work.

**What LTP borrows:** The commitment log is a direct application of these ideas. The whitepaper
deliberately does not specify a consensus mechanism (Section 10, Open Question 3) — it could be
a blockchain, a CT-style Merkle log, or a permissioned ledger. The immutability guarantee
(Section 4) relies only on the append-only property and hash chaining, not on a specific
consensus protocol.

**Where LTP diverges:** LTP's commitment log is minimal by design: it stores only a Merkle root
of encrypted shard hashes, the entity_id, encoding params, and an ML-DSA signature. No shard
IDs, no content, no CEK. This is a tighter interface than most blockchain-based systems, which
tend to store more metadata. The log's purpose is *attestation* ("this entity was committed by
this sender at this time"), not general-purpose state management.

### 8.4 Capability-Based Security

**Dennis & Van Horn (1966)** [9] introduced the capability model: an unforgeable token that
simultaneously designates a resource and authorizes access to it. The holder of a capability
can access the resource; without it, the resource is unreachable. Capabilities are the
*minimum viable authorization* — no identity checks, no ACLs, just possession of proof.

**Macaroons (2014)** [10] extended capabilities with *caveats* — conditions that can be added
by any party in the delegation chain (e.g., "valid until 2026-03-24," "only from IP range X").
Storj uses serialized macaroons as its access grant format.

**SPIFFE/SPIRE (2017+)** [11] provides workload identity in distributed systems via short-lived
X.509 certificates (SVIDs), enabling zero-trust service-to-service authentication.

**What LTP borrows:** The lattice key is a capability. It designates a resource (the
committed entity) and authorizes a specific receiver to materialize it. The `access_policy`
field (one-time, time-bounded, delegatable) is directly inspired by macaroon caveats.

**Where LTP diverges:** The lattice key combines capability semantics with envelope
encryption (ML-KEM). A Storj access grant can be used by anyone who possesses it; an LTP
lattice key is sealed to a specific receiver's encapsulation key and is useless to anyone
else. This binds the capability to a cryptographic identity, not just to possession.

### 8.5 Peer-to-Peer Content Distribution

**BitTorrent (2001)** [12] demonstrated that large-file distribution could be decentralized:
the original seeder uploads once, and peers exchange pieces among themselves. The more popular
a file becomes, the faster it distributes (unlike client-server, where popularity causes
congestion). BitTorrent's piece model (splitting content into fixed-size chunks distributed
across peers) is an ancestor of LTP's shard model.

**NDN (Named Data Networking, 2009+)** [13] proposes replacing IP's host-centric architecture
with data-centric networking: consumers request data by name, and any node that has a cached
copy can serve it. The network layer itself becomes content-addressed. NDN's "fetch from
wherever is closest" philosophy directly parallels LTP's receiver-side materialization from
nearest commitment nodes.

**What LTP borrows:** Parallel multi-source fetching (from BitTorrent/NDN), the principle that
the first upload is the expensive operation and subsequent retrievals amortize the cost, and
the idea that content should flow from where it is cached rather than from a fixed origin.

**Where LTP diverges:** BitTorrent has no built-in encryption or access control — torrents are
public by default. NDN's data-centric model operates at the network layer, while LTP is an
application-layer protocol. LTP's commitment phase is a one-time sender operation (not a
continuous seeding obligation), and the commitment network serves encrypted shards without
needing to understand or index the content.

### 8.6 Hybrid and Convergent Systems

Several systems have independently converged on similar combinations:

**Tahoe-LAFS + Capability Model** arguably comes closest to LTP's design: encrypted erasure-coded
storage with capability-based access. LTP's main departure is the protocol framing (transfer vs.
storage), the ML-KEM sealed envelope (binding capabilities to a specific receiver), and the
explicit three-phase model with an append-only commitment log.

**Keybase (2014-2020)** [14] combined KBFS (an encrypted, content-addressed filesystem) with
public-key identity and Merkle-tree-based audit logs. Users could share files by name, with
client-side encryption and server-side ignorance — similar to LTP's "nodes store ciphertext."

**Secure Scuttlebutt (SSB, 2014+)** [15] uses append-only logs per identity, with content-
addressed messages and capability-based private groups. SSB's offline-first design (gossip
replication, no central server) parallels LTP's sender-independence property.

**GSX DAG L1 + GSX-DB (2026)** [18][19] is the companion deployment surface for
LTP in the GSX stack. GSX DAG provides certificate-DAG ordering, validator-ring
consensus, and corridor super-node attestation. GSX-DB provides the canonical
state substrate below that chain: capability-gated mutation, dual EVM/Move
projections, OCC block execution, state-tree roots, anchor dispatch, recovery
replay, and L2 state sync. LTP remains the transfer and attestation layer; it
does not mutate the GSX-DB state substrate directly.

### 8.7 What LTP Contributes

Given the depth of prior art, the honest answer is: **LTP's individual components are not novel.
Its contribution is the protocol-level synthesis.**

Specifically:

1. **The three-phase model (commit → lattice → materialize) as a transfer primitive.** Prior
   systems treat content-addressed storage + capabilities as *storage with sharing*. LTP treats
   the combination as *a data transfer protocol* — an alternative to sending payloads. This is
   primarily a conceptual contribution. Whether it proves practically valuable depends on
   whether the abstraction enables workflows that existing tools make awkward.

2. **The sealed lattice key as a constant-size, receiver-bound, post-quantum transfer
   token.** Unlike Storj access grants (bearer tokens, anyone who holds them can use them),
   the lattice key is cryptographically bound to a specific receiver via ML-KEM-768.
   Unlike Tahoe-LAFS read-caps (static, no expiry built-in), the lattice key includes
   inline access policy (one-time, time-bounded, delegatable) and uses per-seal forward
   secrecy. The combination of capability + receiver binding + per-message forward secrecy +
   inline policy in a constant-size token is, to our knowledge, not present in prior systems.

3. **Deterministic receiver-side location derivation.** In IPFS and Storj, the provider/sharer
   must communicate block CIDs or shard locations to the receiver explicitly. In LTP, the
   receiver computes shard locations from the entity_id via consistent hashing — no lookup
   service, no external metadata. This eliminates one round-trip and one point of failure.

4. **Post-quantum security as a default, not an upgrade path.** ML-KEM-768 for key encapsulation
   and ML-DSA-65 for signatures are the *default* primitives, not optional add-ons. Most
   existing distributed storage systems use X25519/Ed25519 and mention post-quantum as future
   work.

We make no claim that these contributions are individually groundbreaking. The question for the
reader is whether the synthesis, and the mental model it enables ("don't move the data — transfer
the proof"), justifies a dedicated protocol specification. We believe it does, but acknowledge
that reasonable reviewers may disagree.

### 8.8 International Post-Quantum Standardization Landscape

LTP's post-quantum cryptography is aligned with NIST FIPS 203/204, but PQC standardization
is a global effort. The following national programs are developing or evaluating post-quantum
cryptographic standards, each of which may influence regional adoption requirements:

| Country | Body | Program | Status (2025) | Relevance to LTP |
|---------|------|---------|---------------|-----------------|
| **USA** | NIST | FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) | Standards final (Aug 2024); HQC selected as 2nd KEM | Primary alignment target |
| **China** | CACR (中国密码学会) | Chinese PQC Algorithm Competition | Algorithm collection phase; openHiTLS provides ML-KEM/ML-DSA | Critical for GSX L1 deployment |
| **Japan** | CRYPTREC | CRYPTREC Report 2024 | Published Jul 2025; Symposium 2025 held | Government crypto evaluation |
| **Korea** | KpqC | Korean PQC Competition | Evaluation phase; ETRI leads research | Independent algorithm track |
| **France** | ANSSI | PQ Migration Recommendations | Published; supports hybrid schemes | EU regulatory influence |
| **Germany** | BSI | TR-02102 PQ Technical Guidelines | Published; referenced across EU | EU member state adoption |
| **Russia** | TC 26 | GOST PQC Standard | Development; separate from NIST | Independent standard track |
| **EU** | ENISA | PQ Crypto Recommendations | Published (2024) | Supranational guidance |
| **Australia** | ASD | CNSA 2.0 alignment | Pure PQ by 2030 target | Early adopter timeline |

**Convergence vs. divergence:** While NIST's ML-KEM and ML-DSA are the most widely adopted
standards, China's CACR competition and Korea's KpqC may produce algorithms not in the NIST
portfolio. LTP's cryptographic agility (configurable SecurityProfile, pluggable backends)
is designed to accommodate regional algorithm requirements without protocol-level changes.

### References

[1] J. Benet, "IPFS — Content Addressed, Versioned, P2P File System," arXiv:1407.3561, 2014.

[2] L. Torvalds, "Git: A distributed version control system," 2005. https://git-scm.com/

[3] Z. Wilcox-O'Hearn, "Tahoe — The Least-Authority Filesystem," ACM CCS StorageSS Workshop, 2008.

[4] Storj Labs, "Storj: A Decentralized Cloud Storage Network Framework," Storj Whitepaper v3, 2018.

[5] Protocol Labs, "Filecoin: A Decentralized Storage Network," Filecoin Whitepaper, 2017 (mainnet 2020).

[6] S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.

[7] B. Laurie, A. Langley, E. Kasper, "Certificate Transparency," RFC 6962, 2013.

[8] E. Androulaki et al., "Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains," EuroSys, 2018.

[9] J. B. Dennis and E. C. Van Horn, "Programming Semantics for Multiprogrammed Computations," Communications of the ACM, 9(3), 1966.

[10] A. Birgisson, J. G. Politz, U. Erlingsson, A. Taly, M. Vrable, M. Lentczner, "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud," NDSS, 2014.

[11] CNCF, "SPIFFE: Secure Production Identity Framework for Everyone," https://spiffe.io/, 2017.

[12] B. Cohen, "Incentives Build Robustness in BitTorrent," Workshop on Economics of P2P Systems, 2003.

[13] L. Zhang et al., "Named Data Networking," ACM SIGCOMM CCR, 2014. (NDN project started 2009.)

[14] Keybase, Inc., "Keybase filesystem (KBFS)," https://book.keybase.io/docs/files, 2014-2020.

[15] D. Tarr et al., "Secure Scuttlebutt: An Identity-Centric Protocol for Subjective and Decentralized Applications," IFIP, 2019.

[16] J. Groth, "On the Size of Pairing-Based Non-Interactive Arguments," EUROCRYPT, 2016.

[17] L. Grassi, D. Khovratovich, C. Rechberger, A. Roy, M. Schofnegger, "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems," USENIX Security Symposium, 2021.

[18] Global Settlement Network, "GSX DAG Layer 1," companion implementation and academic paper, 2026. https://github.com/GlobalSettlementNetwork/gsx-dag

[19] Global Settlement Network, "GSX-DB: A Polymorphic Dual-VM State Substrate with Capability-Gated Mutation," companion implementation, 2026. https://github.com/GlobalSettlementNetwork/gsx-db

- [Bos et al., 2017] CRYSTALS-Kyber: A CCA-secure module-lattice-based KEM. IACR ePrint 2017/634. https://eprint.iacr.org/2017/634
- [Bhargavan et al., 2024] Formal verification of the PQXDH post-quantum key agreement protocol. USENIX Security 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan
- [McEliece & Sarwate, 1981] On sharing secrets and Reed-Solomon codes. Communications of the ACM, 24(9). https://dl.acm.org/doi/10.1145/358746.358762
- [Perrin, 2018] The Noise Protocol Framework. https://noiseprotocol.org/noise.html
- [IETF CFRG] Guidelines for Writing Cryptography Specifications. draft-irtf-cfrg-cryptography-specification-01. https://www.ietf.org/archive/id/draft-irtf-cfrg-cryptography-specification-01.html
- [Lipp et al., 2019] A Mechanised Cryptographic Proof of the WireGuard Virtual Private Network Protocol. EuroS&P 2019. https://inria.hal.science/hal-02100345v3/document
- [openHiTLS] Open-source TLS library with ML-KEM/ML-DSA support. https://github.com/openHiTLS/openHiTLS
- [CACR] Chinese Association for Cryptologic Research — Post-Quantum Algorithm Competition. http://www.cacrnet.org.cn/

---

## 9. Use Cases

### 9.1 Large File Fan-Out
A 50 GB dataset is committed once. Any number of receivers can materialize it by each receiving
a ~1,300-byte sealed lattice key (ML-KEM-768). Each receiver's materialization time is
dominated by local shard fetching from nearby nodes — not by the sender's bandwidth or
availability. For N receivers, direct transfer costs O(50GB × N). LTP costs O(50GB ×
replication) for the commit plus O(~1,300B × N) for the keys — amortized cost per receiver
approaches zero as N grows.

### 9.2 Immutable Audit Trail
Every data transfer is permanently recorded. A compliance system can verify: "Entity X was
committed by Sender A at time T and lattice-linked with Receiver B." No party can deny or alter this.

### 9.3 Secure Messaging
A message is committed and lattice-linked. The lattice key is the message notification. The
content never traverses the public internet as a readable payload. Even if intercepted, the
lattice key alone is useless.

### 9.4 State Synchronization
Two distributed systems synchronize state by exchanging lattice keys. Each system materializes
the other's state from the commitment network. This is faster than traditional replication because
shards are fetched locally, and only the delta (new entity) needs materialization.

In the GSX stack, the state being synchronized is the GSX-DB state root produced
after GSX DAG ordering. The flow is one-directional: DAG-ordered blocks update
GSX-DB through its `gsxdb-bridge` capability gate; GSX-DB emits state roots and
anchors; LTP corridor super-nodes attest those anchors; receivers materialize
committed snapshots or deltas with lattice keys. A lattice key can authorize
materialization, but it cannot directly mutate GSX-DB state.

### 9.5 High-Latency Link Optimization

*Moved to [Appendix A](#appendix-a-high-latency-link-optimization-thought-experiment) to
maintain the technical focus of the main document. The two properties it demonstrates —
sender-independence and geographic optimization — are the same properties illustrated by
the grounded scenarios in §§9.1–9.4.*

---

## 10. Open Questions

1. ~~**Commitment network economics**: How are commitment nodes incentivized to store and serve shards?~~
   **Addressed in §5.5.** LTP defines economic interfaces (compensate, slash, pricing) without
   mandating a specific mechanism. Deployment-dependent: organizational SLA, mutual obligation,
   or token/staking (see §5.5 table).

2. **Shard eviction**: When can shards be garbage collected? (Never? After TTL? After all authorized
   receivers materialize?) **Partially addressed in §5.4.4** — TTL-based eviction with renewal.
   Open: optimal TTL default, interaction between TTL expiry and in-flight lattice keys.

3. ~~**Commitment log consensus**: What consensus mechanism secures the append-only log?~~
   **Addressed in §5.1.2.** LTP does not require full BFT consensus. The commitment network is
   a storage network; the log requires only append-only integrity and hash chaining. A Certificate
   Transparency–style Merkle log with trusted operators is sufficient.

4. **Bandwidth for initial shard distribution**: The commit phase still requires distributing n
   shards. Can this be amortized or pipelined?

5. **Real-time streaming**: Can LTP support continuous entity streams (video, telemetry), or is it
   inherently batch-oriented?

6. **Audit protocol formalization**: The storage proof challenge-response (§5.2.2) is lightweight
   but weaker than Filecoin's PoSt. A node that re-fetches data just before an audit passes
   dishonestly. Can time-bounded challenges be tightened without requiring SNARKs?

7. **Cross-deployment federation**: How do independently bootstrapped LTP networks discover and
   trust each other's commitment nodes?

8. **ZK Transfer Mode extensions**: §3.2 specifies a Groth16-based hiding commitment for
   entity_id privacy, but defers two significant capabilities: (a) content-property proofs —
   circuit composition for application-layer predicates (JSON schema, range proofs, etc.); and
   (b) post-quantum ZK — replacing the BLS12-381 pairing with a STARK or lattice-based proof
   system that resists Shor's algorithm. What is the appropriate circuit composition model for
   (a), and which post-quantum proof system best balances proof size, generation time, and
   absence of trusted setup for (b)?

---

## 11. Conclusion

LTP inverts the data transfer paradigm. Rather than asking "how do I send this data to you," it
asks "how do I prove this data exists, and give you the right to reconstruct it near you."

The result is a protocol where:
- **The sender→receiver path is O(1)** — a constant-size sealed key (~1,300B), regardless of entity size
- **Total system bandwidth is higher than direct transfer** — but the bottleneck shifts from
  the sender-receiver link to receiver-local fetches, with amortized fan-out
- **Transfer is immutable** by mathematical construction, not policy
- **Security is cryptographic** not perimeter-based
- **Geography is optimized** because materialization pulls from nearby nodes
- **The sender can go offline** after commitment without affecting the transfer

Data doesn't move. Proof moves. Truth materializes.
Bandwidth doesn't disappear. It redistributes to where it's cheapest.

---

## Appendix A: High-Latency Link Optimization (Thought Experiment) {#appendix-a-high-latency-link-optimization-thought-experiment}

*This appendix is an illustrative thought experiment demonstrating two specific LTP properties —
sender-independence and geographic optimization — in an extreme high-latency scenario. It is
not a practical deployment proposal; the infrastructure assumptions (Mars-local commitment
nodes, inter-planetary shard pre-replication) are deployment choices, not protocol features.
The same properties are demonstrated by the grounded use cases in §§9.1–9.4.*

**Scenario.** An Earth sender commits a 1 GB entity destined for multiple Mars-side receivers.
Earth-Mars light delay is 20 minutes one-way; effective Earth-Mars bandwidth is 1 Mbps
(a realistic deep-space link capacity). Mars-local bandwidth between receivers and Mars-local
commitment nodes is 1 Gbps.

**Direct transfer (without LTP) for $N$ receivers:**
$$T_{\text{direct}} = 20\text{ min} + \frac{1\text{ GB}}{1\text{ Mbps}} \approx 20\text{ min} + 2.2\text{ hr per receiver}$$
Each receiver independently pulls the full payload from Earth. Total Earth upload: $N \times 1\text{ GB}$.

**LTP (with Mars-local commitment nodes):**
- *Commit phase (once, asynchronous):* Sender distributes shards to Mars nodes. With
  $n = 64$, $k = 32$, $r = 3$: total upload $= D \cdot nr/k = 1\text{ GB} \times 6 = 6\text{ GB}$.
  At 1 Mbps: $6\text{ GB} / 1\text{ Mbps} \approx 13.4\text{ hours}$ of Earth upload,
  paid once regardless of $N$.
  paid once regardless of $N$.
- *Lattice phase (per receiver):* ~1,300-byte sealed key transmitted in $< 1\text{ s}$ +
  20-minute light delay.
- *Materialize phase (per receiver):* $1\text{ GB} / 1\text{ Gbps} = 8\text{ seconds}$
  from Mars-local nodes.
$$T_{\text{LTP per receiver}} \approx 20\text{ min (light delay)} + 8\text{ sec (local fetch)}$$

**What this illustrates:**

1. **Sender-independence:** After the commit phase completes, the Earth sender goes offline.
   Materialization is driven entirely by receiver ↔ Mars-local-node bandwidth. The sender's
   availability is decoupled from any specific transfer.

2. **Geographic optimization:** Each receiver's materialization time is dominated by
   Mars-local latency (8 seconds), not Earth-Mars latency (2.2 hours per receiver for
   direct transfer). LTP relocates the bandwidth-intensive step from a high-latency
   intercontinental link to a low-latency local one.

**Break-even on bandwidth:** LTP uses $D(\rho + N) = D(nr/k + N)$ total system bytes versus direct's $DN$.
LTP's extra commit cost is $D \cdot nr/k$. At $n = 64$, $k = 32$, $r = 3$ ($\rho = 6$): break-even is
$N > \rho = 6$ receivers — beyond 6 Mars-side receivers, LTP's total Earth upload ($6\text{ GB}$ once)
is less than direct's ($N \times 1\text{ GB}$). At $N = 10$: LTP saves $4\text{ GB}$ of Earth upload.

**What this does NOT claim.** LTP does not solve the physics of light delay — initial shard
replication to Mars still traverses the 20-minute link. The advantage requires pre-populated
Mars-local commitment nodes, which is an infrastructure deployment decision, not a protocol
guarantee. The scenario is meaningful only when the commit cost is amortized across a
sufficiently large receiver population (break-even: $N > r$).

---

*LTP v0.1.0-draft — Lattice Transfer Protocol*
