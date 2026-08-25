<div align="center">

# LTP: Lattice Transfer Protocol

## Whitepaper

<br>

*A data transfer protocol in which no data payload is transmitted between sender and receiver.*
*The sender commits. The receiver materializes. No payload crosses the sender–receiver link.*

<br>

| **Author** | **Version** | **Date** | **Status** | **Classification** |
|:----------:|:-----------:|:--------:|:----------:|:------------------:|
| Tsolmondorj Natsagdorj | 0.4.1 | 2026-08-21 | Public Draft — Request for Comments | Public |

</div>

<br>

---

**Overview**

LTP inverts the data transfer paradigm. Rather than transmitting a payload from sender to
receiver, the sender **commits** an immutable, content-addressed, erasure-coded entity to a
distributed commitment layer and delivers a constant-size cryptographic **lattice key**
(1,423 bytes measured, §7.4) to the receiver. The receiver **materializes** the entity from
geographically nearby commitment nodes — achieving O(1) sender→receiver bandwidth independent
of entity size, with post-quantum security as the default on the core transfer path.

**Core guarantees:**

| Property | Guarantee | Primitive |
|:---------|:----------|:----------|
| Sender→receiver path | O(1) constant-size sealed key, independent of entity size (measured invariant, §7.4) | ML-KEM-768 (FIPS 203) |
| Immutability | Content-addressed EntityID — any modification produces a different identity | SHA3-256 (FIPS 202), canonical lane (§1.3) |
| Threshold secrecy | Fewer than *k* shards reveal zero information about content that is not guessable/enumerable (see §3.3.5); guessable content requires ZK mode | Information-theoretic |
| Non-repudiation | Append-only signed commitment record on a Merkle log | ML-DSA-65 (FIPS 204) |
| Post-quantum security | Core transfer path (COMMIT/LATTICE/MATERIALIZE) is PQ-safe by default; two optional surfaces are not — see below | ML-KEM + ML-DSA + SHA3-256 |
| ZK privacy mode | Hiding commitment for EntityID fingerprinting prevention | Groth16 / BLS12-381 ⚠ |

> ⚠ **Two surfaces outside the core transfer path are not post-quantum safe.** (1) ZK
> transfer mode uses Groth16 over BLS12-381, broken by Shor's algorithm (§3.2.4).
> (2) The corridor attestation quorum signs with BLS12-381, which is likewise
> pairing-based and Shor-breakable (§8.3). A third, opt-in composite signature mode
> pairs ML-DSA-65 with Ed25519 for transition-period assurance (§8.2). The
> COMMIT/LATTICE/MATERIALIZE path itself uses no classical-only primitive. See §3.4
> for the consolidated post-quantum posture.

**Keywords:** distributed systems · post-quantum cryptography · content-addressed storage ·
erasure coding · capability-based access control · append-only audit logs · ML-KEM-768 ·
ML-DSA-65 · SHA3-256 · BLAKE3 · Certificate Transparency · Reed-Solomon coding

---

## Table of Contents

---

**Preliminary Sections**

- [Abstract](#abstract)
- [Note on Terminology](#note-on-terminology)
- [Notation](#notation)

---

**Clauses**

- [1. The Ontology of Data Transfer](#1-the-ontology-of-data-transfer)
    - [1.1 What Is an "Entity"?](#11-what-is-an-entity)
        - [1.1.1 Shape Specification](#111-shape-specification)
    - [1.2 The Entity Identity Function](#12-the-entity-identity-function)
    - [1.3 Dual-Lane Hashing](#13-dual-lane-hashing)
- [2. The Three Phases of Transfer](#2-the-three-phases-of-transfer)
    - [2.1 Phase 1: COMMIT](#21-phase-1-commit)
        - [2.1.1 Deterministic Sharding](#211-deterministic-sharding)
        - [2.1.2 Distributed Shard Placement](#212-distributed-shard-placement)
        - [2.1.3 The Commitment Record](#213-the-commitment-record)
    - [2.2 Phase 2: LATTICE](#22-phase-2-lattice)
        - [2.2.1 The Lattice Key](#221-the-lattice-key)
        - [2.2.2 Key Properties of the Lattice Key](#222-key-properties-of-the-lattice-key)
    - [2.3 Phase 3: MATERIALIZE](#23-phase-3-materialize)
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
        - [3.3.8 Machine-Checked Verification Status](#338-machine-checked-verification-status)
    - [3.4 Post-Quantum Posture, by Surface](#34-post-quantum-posture-by-surface)
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
            - [5.4.1.2 Common-Cause Failure and Software Monoculture](#5412-common-cause-failure-and-software-monoculture)
        - [5.4.2 Failure Modes and Repair](#542-failure-modes-and-repair)
        - [5.4.3 The CAP Theorem and LTP](#543-the-cap-theorem-and-ltp)
        - [5.4.4 Availability vs. Permanence](#544-availability-vs-permanence)
    - [5.5 Network Economics (Interface, Not Implementation)](#55-network-economics-interface-not-implementation)
- [6. Breaking the Constraints](#6-breaking-the-constraints)
    - [6.1 Latency](#61-latency)
    - [6.2 Geographic Distance](#62-geographic-distance)
    - [6.3 Computing Power](#63-computing-power)
    - [6.4 Formal Cost Model](#64-formal-cost-model)
    - [6.5 Exact Cost of the Coding Layer](#65-exact-cost-of-the-coding-layer)
- [7. Empirical Evaluation](#7-empirical-evaluation)
    - [7.1 Cryptographic Primitives](#71-cryptographic-primitives)
    - [7.2 Erasure Coding](#72-erasure-coding)
    - [7.3 End-to-End Transfer](#73-end-to-end-transfer)
    - [7.4 Artifact Sizes](#74-artifact-sizes)
    - [7.5 Threats to Validity](#75-threats-to-validity)
- [8. Reference Implementation and Deployment Status](#8-reference-implementation-and-deployment-status)
    - [8.1 What Is Implemented](#81-what-is-implemented)
    - [8.2 Cryptographic Agility and the Composite Signature Mode](#82-cryptographic-agility-and-the-composite-signature-mode)
    - [8.3 The Corridor: Cross-Chain Attestation](#83-the-corridor-cross-chain-attestation)
    - [8.4 On-Chain Anchoring and Its Trust Assumptions](#84-on-chain-anchoring-and-its-trust-assumptions)
    - [8.5 Deployment Status](#85-deployment-status)
    - [8.6 Where the Implementation Diverges From This Paper](#86-where-the-implementation-diverges-from-this-paper)
- [9. Comparison with Existing Approaches](#9-comparison-with-existing-approaches)
- [10. Related Work and Prior Art](#10-related-work-and-prior-art)
    - [10.1 Content-Addressed Storage](#101-content-addressed-storage)
    - [10.2 Erasure-Coded Distributed Storage](#102-erasure-coded-distributed-storage)
    - [10.3 Append-Only Commitment Logs](#103-append-only-commitment-logs)
    - [10.4 Capability-Based Security](#104-capability-based-security)
    - [10.5 Peer-to-Peer Content Distribution](#105-peer-to-peer-content-distribution)
    - [10.6 Hybrid and Convergent Systems](#106-hybrid-and-convergent-systems)
    - [10.7 What LTP Contributes](#107-what-ltp-contributes)
    - [10.8 International Post-Quantum Standardization Landscape](#108-international-post-quantum-standardization-landscape)
    - [10.9 Data Availability Sampling and Verifiable Erasure-Coded Commitments](#109-data-availability-sampling-and-verifiable-erasure-coded-commitments)
    - [References](#references)
- [11. Use Cases](#11-use-cases)
    - [11.1 Large File Fan-Out](#111-large-file-fan-out)
    - [11.2 Immutable Audit Trail](#112-immutable-audit-trail)
    - [11.3 Secure Messaging](#113-secure-messaging)
    - [11.4 State Synchronization](#114-state-synchronization)
    - [11.5 High-Latency Link Optimization](#115-high-latency-link-optimization)
    - [11.6 Where LTP Is the Wrong Tool](#116-where-ltp-is-the-wrong-tool)
- [12. Open Questions](#12-open-questions)
- [13. Conclusion](#13-conclusion)

---

**Appendices**

- [Appendix A: High-Latency Link Optimization (Thought Experiment)](#appendix-a-high-latency-link-optimization-thought-experiment)
- [Appendix B: Conformance Requirements](#appendix-b-conformance-requirements)
- [Appendix C: Companion Documents](#appendix-c-companion-documents)
- [Revision History](#revision-history)

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

The protocol was formerly named **ETP (Entanglement Transfer Protocol)**; some repository
artifacts (e.g., `docs/formal/etp-protocol.vp`) retain the old name.

---

### Notation

Symbols used throughout, collected for reference. Section numbers point to the definition.

| Symbol | Meaning | Defined |
|:------:|---------|:-------:|
| $D$ | Entity size in bytes | §6.4 |
| $n$ | Total shards produced by erasure coding | §2.1.1 |
| $k$ | Reconstruction threshold; any $k$ of $n$ shards suffice ($k < n$) | §2.1.1 |
| $r$ | Replication factor — independent copies of each shard | §5.4.1 |
| $\rho$ | Combined storage expansion, $\rho = nr/k$ | §6.4 |
| $N$ | Number of receivers materializing one committed entity | §6.4 |
| $H$ | Canonical-lane hash function (default SHA3-256) | §1.3 |
| $\alpha_i$ | Reed-Solomon evaluation point for shard $i$; $\alpha_i = i+1$ | §2.1.1 |
| $\alpha$ | Parallelism efficiency factor, $\alpha \in (0,1]$ — fraction of ideal parallel fetch bandwidth achieved | §6.4 |
| $L_{SR}$ | One-way sender→receiver latency (sealed-key delivery) | §6.4 |
| $L_{RN}$ | Receiver→nearest-commitment-node latency | §6.4 |
| $L_{\log}$ | Commitment-record lookup latency from the append-only log | §6.4 |
| $T$ | Storage-audit challenge deadline | §5.2.2 |
| $b$ | Burst size — simultaneous challenges per audit | §5.2.2 |
| $p$ | Probability a single node is unavailable (independent model) | §5.4.1 |
| $p_d$ | Probability of a domain-level (regional) failure | §5.4.1.1 |
| $p_n$ | Probability of an independent node failure within a healthy domain | §5.4.1.1 |
| $p_{sw}$ | Probability of a common-mode software failure across the deployment | §5.4.1.2 |
| $R$ | Number of independent failure domains | §5.4.1.1 |
| $\lambda$ | Security parameter | §3.3 |
| $\mathcal{A}$ | PPT adversary | §3.3 |
| $\mathsf{Adv}^{X}_{\mathcal{A}}$ | Advantage of $\mathcal{A}$ in game $X$ | §3.3 |
| $\mathsf{negl}(\lambda)$ | Negligible function in $\lambda$ | §3.3 |
| $f$ | Byzantine fault tolerance bound | §3.3.8, §8.1 |
| $\|$ or $\|$ | Concatenation | §1.2 |

Two distinct uses of $\alpha$ appear above. $\alpha_i$ with a subscript is always a
finite-field evaluation point in the erasure coding of §2.1.1; bare $\alpha$ is always the
parallelism efficiency factor of §6.4. They are unrelated, and the collision is retained
because both notations are standard in their respective literatures.

---

## Abstract

We propose a data transfer protocol in which no data payload is transmitted between sender and
receiver. Instead, the sender **commits** an immutable, content-addressed representation of the
entity to a distributed commitment layer, transmits a minimal cryptographic **lattice key**
to the receiver, and the receiver **materializes** the entity through deterministic reconstruction
from distributed shards. The protocol achieves:

- **Decoupled transfer** — the sender→receiver path carries only a 1,423-byte sealed key (ML-KEM-768), independent of entity size; we measure this invariant directly in §7.4. Total system bandwidth is O(entity × replication), but the direct-path bottleneck is eliminated.
- **Immutability by design** — every transfer is a permanent, auditable commitment
- **Verification without institutional trust on the transfer path** — materialization is verified cryptographically end-to-end; the on-chain settlement surface carries separate and weaker trust assumptions, stated in §8.4
- **Geography-optimized materialization** — the receiver fetches shards from the nearest available nodes, converting a long-haul transfer into parallel local fetches

> **⚠ Post-quantum scope.** The core transfer path is fully post-quantum — ML-KEM-768
> (FIPS 203), ML-DSA-65 (FIPS 204), SHA3-256 (FIPS 202), and information-theoretic erasure
> coding, with no classical-only primitive. Two optional surfaces are **not**: ZK transfer
> mode (§3.2), which uses Groth16 over BLS12-381, and the corridor attestation quorum
> (§8.3), which uses BLS12-381 aggregate signatures. Both are broken by Shor's algorithm.
> **Neither MUST be relied upon in deployments with a quantum-adversary threat model.** The
> planned upgrade path is a STARK or lattice-based proof system (§3.2.4, §12 Open
> Question 6). §3.4 gives the consolidated per-surface posture.

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
- `H` is the **canonical-lane** hash function (§1.3). The default is **SHA3-256** (FIPS 202);
  SHA-384 and SHA-512 are the other permitted canonical-lane choices. ZK transfer mode (§3.2)
  requires Poseidon in place of SHA3-256 for circuit-friendliness. Hash outputs are encoded as
  lowercase hexadecimal strings prefixed with the algorithm name: `sha3-256:<hex>`. A
  conforming EntityID is therefore a 73-character string — a 9-character prefix and 64 hex
  digits under the SHA3-256 default; a deployment on a SHA-384 profile (§8.2) produces
  `sha384:` + 96 hex digits instead, and implementations MUST NOT assume a fixed length.
- `||` denotes concatenation
- `timestamp` is the commitment time (logical clock, not wall clock), encoded as an 8-byte
  big-endian IEEE 754 double
- `sender_pubkey` is the sender's ML-DSA-65 verification key (1,952 bytes), binding identity
  to a cryptographic key rather than a mutable label

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

### 1.3 Dual-Lane Hashing

LTP does not use a single hash function. It uses two, separated by trust boundary rather
than by preference, and the separation is normative.

| Lane | Default | Permitted set | Governs |
|------|---------|---------------|---------|
| **Canonical** | SHA3-256 (FIPS 202) | SHA3-256, SHA-384, SHA-512 — FIPS-approved only | EntityIDs, commitment records, Merkle roots and tree heads, corridor digests, anything a regulator or external auditor evaluates |
| **Internal** | BLAKE3-256 | Unconstrained | Shard placement and indexing, chunk integrity, caching, AEAD keystream — never part of the compliance trust boundary |

**Why two lanes.** The two lanes answer different questions. The canonical lane answers
"will an auditor accept this artifact as evidence?", which in regulated deployments means
the algorithm must appear in a FIPS standard — BLAKE3 does not, and no amount of
engineering merit changes that. The internal lane answers "how fast can we hash a large
number of shards?", where FIPS approval is irrelevant because the output never leaves the
implementation. Collapsing the two would force a choice between failing a compliance
review and accepting a large throughput penalty on the hot path.

The penalty is not hypothetical. We measure SHA3-256 at 350 MiB/s and BLAKE3 at
5,965 MiB/s on the same host — a **17× difference** (§7.1). Shard placement hashes every
(entity, index, replica) triple in the network, so the internal lane runs orders of
magnitude more often than the canonical lane; putting SHA3-256 there would make hashing,
rather than erasure coding, the dominant cost at large *n*.

**Normative rules.**

1. The canonical lane MUST reject any algorithm outside the FIPS-approved set above. This
   rejection is unconditional — it is not gated on a compliance-mode flag, because an
   artifact's audience is not knowable at hash time.
2. Implementations MUST NOT substitute an internal-lane hash for a canonical-lane one. An
   EntityID computed with BLAKE3-256 is not a conforming EntityID, and will not match one
   computed by a conforming implementation.
3. A third function, the **specification-frozen** hash, is pinned to SHA3-256 permanently
   and never follows the active profile. It governs corridor wire digests, on-chain anchor
   parity, and consensus digests, where changing the hash is a wire-format break rather
   than a configuration change (§8.3).

**Consequence for the security analysis.** Because the canonical lane is SHA3-256, the
concrete collision and preimage bounds in §3.3.1 are those of SHA3-256, not BLAKE3-256.
The two happen to have identical output length and comparable security margins, so the
numerical results are unchanged; the attribution is not.

**Relationship to the reference implementation.** The lane split is `canonical_hash()` /
`internal_hash()` / `spec_hash_bytes()` in `src/ltp/dual_lane/`, with static-analysis rules
that flag direct `hashlib` use outside that module. The rules are partial rather than
airtight — a handful of direct SHA-256/SHA-512 calls remain outside the lane API, notably
the HMAC-SHA256 in shard nonce derivation (§2.1.1) and the SHA-512 prehash in composite
signing (§8.2), both of which are fixed by their own specifications rather than
profile-selected.

---

## 2. The Three Phases of Transfer

The three phases provide cumulative security guarantees, formalized in §3.3:

| Phase | Source Authentication | Destination Confidentiality | Forward Secrecy | Formal Basis |
|-------|:-------------------:|:--------------------------:|:--------------:|-------------|
| **COMMIT** | ML-DSA-65 signed commitment | Encrypted shards (CEK-protected) | N/A | Theorems 3, 4 (§3.3.1, §3.3.2) |
| **LATTICE** | Signed commitment binds sender | ML-KEM-768 sealed to receiver (IND-CCA2) | Fresh encapsulation per transfer | Theorems 5, 8 (§3.3.3, §3.3.6) |
| **MATERIALIZE** | Signature + Merkle root verified | Plaintext reconstructed by receiver only | Preserved (ephemeral shared secret discarded) | Theorems 6, 7 (§3.3.4, §3.3.5) |

This follows the pattern established by the Noise Protocol Framework [23], where security properties are tracked per-message through the handshake. LTP's three phases correspond to a three-message protocol with strictly increasing security guarantees.

### 2.1 Phase 1: COMMIT

The sender does not prepare the entity for transmission. Instead, the sender **commits** the
entity to a distributed commitment layer.

#### 2.1.1 Deterministic Sharding

The entity is decomposed into `n` shards using deterministic erasure coding,
then each shard is encrypted with a random Content Encryption Key (CEK):

```
plaintext_shards = ErasureEncode(entity, n, k)
CEK = CSPRNG(256 bits)     # MUST be fresh per entity — see invariant below
PRK = HKDF_Extract(salt="ETP-SHARD-NONCE-v1", ikm=CEK)
nonces = [HKDF_Expand(PRK, info=entity_id ‖ uint32_be(i))[:nonce_len] for i in range(n)]
encrypted_shards = [
    AEAD_Encrypt(CEK, shard, nonce=nonces[i], aad=entity_id ‖ uint32_be(i))
    for i, shard in enumerate(plaintext_shards)
]
```

Where:
- `n` = total number of shards produced
- `k` = minimum number of shards needed to reconstruct (k < n)
- The encoding is deterministic: same input always produces same shards
- `CEK` = a random 256-bit Content Encryption Key, unique per entity
- Each shard is encrypted with AEAD (authenticated encryption) before distribution
- Each shard's AEAD **associated data** binds the ciphertext to its own (entity, index)
  position, so a shard cannot be replayed at a different index or under a different entity
  without failing tag verification
- Commitment nodes store **only ciphertext** — they cannot read shard content
- Each encrypted shard is integrity-checked: `ShardHash = H(encrypted_shard || entity_id || shard_index)`

**Reed-Solomon Canonical Parameters.** To guarantee interoperability — two conforming
implementations MUST produce identical shards and identical Merkle roots for the same
entity — the RS encoding is fully specified as follows:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Field | GF(2⁸) | 8-bit finite field |
| Primitive polynomial | $x^8 + x^4 + x^3 + x^2 + 1$ (0x11d) | Standard GF(2⁸) construction; same as used in AES, ISA-L, BackBlaze |
| Generator element | $\alpha = \texttt{0x02}$ | Primitive root of GF(2⁸) under 0x11d; used to construct the field's exp/log tables for GF(2⁸) multiplication |
| Evaluation points | $\{1, 2, \ldots, n\}$ (i.e., $\alpha_i = i + 1$ for row $i \in [0,n)$) | Distinct non-zero field elements; $n \leq 255$ |
| Encoding matrix | Vandermonde: $V[i][j] = \alpha_i^{\,j}$ for $i \in [0,n)$, $j \in [0,k)$ | Non-systematic; any $k$ rows form an invertible Vandermonde submatrix (MDS property) |
| Decoding | Gauss-Jordan elimination over GF(2⁸) | Select any $k$ available rows, invert $k \times k$ submatrix |
| Shard size | $\lceil (|\text{entity}| + 8) / k \rceil$ bytes | Entity is framed with an 8-byte big-endian length prefix, zero-padded to a multiple of $k$, then split into $k$ equal chunks (see the Complete Test Vector below) |

Note that $n \leq 255$: GF(2⁸) has only 255 distinct non-zero evaluation points. Larger
shard counts require a larger field and are out of scope for v1.

The `algorithm` field in the commitment record (see §2.1.3) MUST be `"reed-solomon-gf256"`
with the parameters above. Implementations MUST NOT use a different primitive polynomial,
generator, or matrix construction and claim conformance with this identifier.

**Interoperability test vector.** This vector illustrates the **bare matrix encoding** of
two already-split chunks, with the length-prefix framing omitted for pedagogical clarity —
the full pipeline including the 8-byte length prefix is shown in the Complete Test Vector
below. Encoding the chunks $c_0 = [\texttt{0x01}, \texttt{0x02}]$,
$c_1 = [\texttt{0x03}, \texttt{0x04}]$ (from the 4-byte input `[0x01, 0x02, 0x03, 0x04]`)
with $n=4$, $k=2$ under these parameters produces the following shards (in hex). For each
byte position $b$, the encoding evaluates
$p_b(x) = c_0[b] \oplus (c_1[b] \otimes_{\text{GF}} x)$ at evaluation points
$\alpha_i = i + 1 \in \{1, 2, 3, 4\}$. All arithmetic is in GF(2⁸) under 0x11d
(addition = XOR, multiplication = finite field multiply).

- Shard 0 ($\alpha_0 = 1$): `0x02 0x06`  *($p_0(1) = \texttt{0x01} \oplus \texttt{0x03} = \texttt{0x02}$, $p_1(1) = \texttt{0x02} \oplus \texttt{0x04} = \texttt{0x06}$)*
- Shard 1 ($\alpha_1 = 2$): `0x07 0x0A`  *($p_0(2) = \texttt{0x01} \oplus (2 \otimes_{\text{GF}} \texttt{0x03}) = \texttt{0x01} \oplus \texttt{0x06} = \texttt{0x07}$, $p_1(2) = \texttt{0x02} \oplus (2 \otimes_{\text{GF}} \texttt{0x04}) = \texttt{0x02} \oplus \texttt{0x08} = \texttt{0x0A}$)*
- Shard 2 ($\alpha_2 = 3$): `0x04 0x0E`  *($p_0(3) = \texttt{0x01} \oplus (3 \otimes_{\text{GF}} \texttt{0x03}) = \texttt{0x01} \oplus \texttt{0x05} = \texttt{0x04}$, $p_1(3) = \texttt{0x02} \oplus (3 \otimes_{\text{GF}} \texttt{0x04}) = \texttt{0x02} \oplus \texttt{0x0C} = \texttt{0x0E}$)*
- Shard 3 ($\alpha_3 = 4$): `0x0D 0x12`  *($p_0(4) = \texttt{0x01} \oplus (4 \otimes_{\text{GF}} \texttt{0x03}) = \texttt{0x01} \oplus \texttt{0x0C} = \texttt{0x0D}$, $p_1(4) = \texttt{0x02} \oplus (4 \otimes_{\text{GF}} \texttt{0x04}) = \texttt{0x02} \oplus \texttt{0x10} = \texttt{0x12}$)*
- Any 2 of 4 shards reconstruct the original chunks.

Note: Because the encoding is **non-systematic**, even shard 0 (at evaluation point
$\alpha_0 = 1$) computes $c_0[b] \oplus c_1[b]$, which does not equal the raw data chunk
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

  Shard 0 (α=1): 0x6C 0x6C 0x69 0x69 0x65
  Shard 1 (α=2): 0xAD 0xAD 0xAD 0x14 0xCA
  Shard 2 (α=3): 0xC1 0xC1 0xC4 0x7D 0xAF
  Shard 3 (α=4): 0x8E 0x8E 0xA6 0x17 0x89
  Shard 4 (α=5): 0xE2 0xE2 0xCF 0x7E 0xEC
  Shard 5 (α=6): 0x23 0x23 0x0B 0x03 0x43

Step 4: Any 3 of 6 shards reconstruct via Vandermonde inversion
  Reconstruction verified: decode({0,2,4}) = decode({1,3,5}) = decode({3,4,5})
  = original ("Hello!"), verified against the reference implementation
  (src/ltp/erasure.py)
```

Implementers SHOULD verify their erasure coding implementation against these vectors and the reference tests in `tests/test_erasure.py` and `tests/test_formal_math.py`. NIST ACVP vectors cover only the ML-KEM/ML-DSA primitives (`tests/test_acvp_mlkem.py`, `tests/test_acvp_mldsa.py`), not erasure coding.

Both vectors above are independently recomputed inside the Lean proof kernel from a
from-scratch GF(2⁸) implementation (`formal/lean/Ltp/TestVectors.lean`, checked in CI) and
pinned against the reference implementation by
`tests/test_production_assertions.py` — the printed bytes, the Lean kernel, and
`src/ltp/erasure.py` are three independent computations agreeing on the same constants
(see §3.3.8).

**Security Invariant — Nonce Derivation:**

Each shard's AEAD nonce is derived by HKDF (RFC 5869) rather than by a bare hash, so that
the construction rests on a standard KDF security argument rather than on an ad-hoc
truncation:

```
PRK     = HKDF-Extract(salt = "ETP-SHARD-NONCE-v1", ikm = CEK)
nonce_i = HKDF-Expand(PRK, info = entity_id ‖ uint32_be(shard_index))[:nonce_len]
```

where `nonce_len` is the AEAD algorithm's required nonce length. The extract step is
domain-separated by a fixed salt, so a CEK reused across protocol versions does not
produce colliding nonces. The expand step's `info` string binds the nonce to both the
entity and the shard index.

The salt is the literal ASCII string `ETP-SHARD-NONCE-v1`, retaining the protocol's former
name (see *Note on Terminology*). It is a frozen wire constant: every shard ever committed
derives its nonce from it, so renaming it to match the current protocol name would make
existing shards undecryptable. Implementations MUST use the byte string above verbatim and
MUST NOT "correct" it to `LTP-`.

Independently of the nonce, each shard's AEAD **associated data** is
`entity_id ‖ uint32_be(shard_index)`. This binds the authentication tag to the shard's
position: an adversary who moves a valid ciphertext to a different index, or reuses it
under a different entity, produces a tag failure rather than a silently misplaced shard.
Nonce derivation alone would not catch this, because the nonce is an input to decryption
rather than an authenticated field.

The reference implementation's AEAD is **XChaCha20-Poly1305** (24-byte /
192-bit nonce); AES-256-GCM and ChaCha20-Poly1305 (12-byte / 96-bit nonce) are conformant
alternatives. Standardization note: XChaCha20-Poly1305 is specified only in an expired
IRTF draft (`draft-irtf-cfrg-xchacha`), though it is widely and interoperably implemented
(libsodium, WireGuard, Tink, Go x/crypto); deployments constrained to standards-track or
FIPS-approved algorithms SHOULD select AES-256-GCM and accept the shorter nonce (with the
correspondingly larger collision term below). This construction
provides defense-in-depth: nonce uniqueness depends on both CEK freshness *and* the
entity's identity, meaning a (CEK, entity_id) pair is sufficient to guarantee distinct
nonces across all shards of a single entity.

The scheme remains safe even under partial CSPRNG failures: a nonce collision between two
different entities requires both an identical CEK *and* an identical entity_id, which is
computationally infeasible. This also eliminates catastrophic failure modes from
seed-state cloning (e.g., VM snapshot/restore) or cached CEK reuse across retry paths.

**CEK reuse across entities is mitigated** by the nonce derivation scheme: two different
entities with the same CEK but different entity_ids produce different nonces, so their
(CEK, nonce) pairs collide with negligible probability, bounded by the birthday bound
$q^2 / 2^{\text{nonce\_bits}+1}$ under the random oracle model, where $q$ is the number of
(entity\_id, shard\_index) pairs encrypted under the same CEK — i.e., $q^2 / 2^{97}$ for a
96-bit nonce (AES-256-GCM, ChaCha20-Poly1305) and $q^2 / 2^{193}$ for the reference
implementation's 192-bit XChaCha20-Poly1305 nonce. CEKs MUST still be generated fresh per entity from a
CSPRNG (e.g., `os.urandom`, `/dev/urandom`, `CryptGenRandom`) as a defense-in-depth
measure. Each commit operation MUST generate a fresh CEK regardless of content or entity_id.
Implementations SHOULD validate that the CEK is not degenerate (all-zero, all-one), and
SHOULD additionally track recently issued CEKs and fail closed on a repeat: the reference
implementation retains the last 100,000 and raises rather than proceeding, on the reasoning
that a CSPRNG returning a duplicate 256-bit value indicates a broken entropy source and
should halt the commit rather than encrypt under it.

#### 2.1.2 Distributed Shard Placement

Shards are placed across a distributed network of **commitment nodes**. Placement follows a
deterministic algorithm based on the EntityID:

```
placement(shard_i, replica_j) = ConsistentHash_internal(EntityID ‖ shard_index ‖ replica) → node
```

Placement uses the **internal** hash lane (§1.3): the result is a routing decision, never an
audited artifact, and it is evaluated once per (entity, index, replica) triple — the highest-
frequency hash call in the protocol. Collisions onto an already-selected node are resolved by
rehashing. Placement MUST additionally respect the failure-domain constraint of §5.4.1.1 and
MAY be filtered by a geo-fence policy where data-sovereignty rules apply.

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
  "entity_id": "sha3-256:7f3a8b...",
  "sender_vk": "ml-dsa-65:verification_key...  (1,952 bytes)",
  "shard_map_root": "sha3-256:merkle_root_of_encrypted_shard_hashes",
  "encoding_params": { "n": 64, "k": 32, "algorithm": "reed-solomon-gf256", "gf_poly": "0x11d", "eval": "vandermonde-powers-of-0x02" },
  "shape": "application/octet-stream",
  "shape_hash": "sha3-256:schema_hash...",
  "timestamp": 1740422400,
  "signature": "ml-dsa-65:sig...  (3,309 bytes, quantum-resistant)"
}
```

Note on the `eval` label: the string `"vandermonde-powers-of-0x02"` is a frozen historical
identifier retained for record-hash compatibility (`encoding_params` is hashed and signed).
The evaluation points it denotes are $\alpha_i = i + 1$ as specified in §2.1.1 — the
label's "powers-of-0x02" wording predates the re-baseline and MUST NOT be parsed
semantically. Conformance is defined by §2.1.1, not by the label.

Critical security property: the commitment record contains **no individual shard IDs**.
Only a Merkle root of hashes of **encrypted** shards is stored. This reveals nothing
about the plaintext content — they are hashes of ciphertext.

The record is the **proof that the entity exists and was committed**. It is small (5,824
bytes measured, §7.4), immutable, and independently verifiable. Its size is almost entirely
post-quantum key material: the 3,309-byte ML-DSA-65 signature and the 1,952-byte
verification key together account for **90.3%** of the record, leaving a 473-byte signable
payload and framing. Carrying the verification key inline — rather than a reference to it —
is deliberate: it makes each record independently verifiable by a party holding no prior
state about the sender, which is what allows the log to serve as evidence to an auditor who
was not present at commit time. The cost of that property is that a record cannot be
smaller than roughly 5 KB under NIST Level 3 parameters.

**Two serializations.** The signature covers a `signable_payload` encoding that
deliberately **excludes** the `predecessor` field, because the log assigns that field after
the signature is produced. The full `to_bytes` encoding — signable payload plus predecessor,
signature, and verification key — is what gets hashed into Merkle leaves and referenced by
`commitment_ref`. Implementations MUST NOT sign over the full encoding or verify against
the signable one.

### 2.2 Phase 2: LATTICE

The sender transmits a minimal **lattice key** to the receiver. This is the only data
that traverses the sender → receiver path directly.

#### 2.2.1 The Lattice Key

The lattice key contains exactly **three secrets** and a policy:

```
LatticeKey = {
  entity_id,              // 73-char "sha3-256:<64 hex>" — which entity to materialize
  content_encryption_key, // 32 bytes — CEK to decrypt shards
  commitment_ref,         // 73-char digest — hash of commitment record
  access_policy           // variable — materialization rules (§2.2.1)
}
```

Critically, the key does **NOT** contain:
- `shard_ids` — receiver derives shard locations from `entity_id` via consistent hashing
- `encoding_params` — receiver reads these from the commitment record
- `sender_id` — receiver reads this from the commitment record

The entire key is **sealed** via ML-KEM-768 (FIPS 203) key encapsulation. Each seal
operation generates a fresh encapsulation, providing forward secrecy per transfer.

The sealed key's wire format is
`kem_ciphertext(1088) ‖ nonce(24) ‖ aead_ciphertext ‖ aead_tag(16)`, giving a constant
**1,128-byte envelope overhead** on top of the encrypted inner payload.

The lattice key is:
- **Minimal** — 295-byte inner payload, **1,423 bytes sealed** under the default
  unrestricted policy, regardless of entity size (measured, §7.4). A time-limited policy
  with all optional fields populated raises this to 1,495 bytes; the growth is in the
  policy, not the entity.
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

> **Implemented, with stated scope.** As of v0.4.1 the reference implementation enforces
> this policy in `materialize()`, after unsealing and before any fetch, with semantics
> matching the machine-checked algebra of `formal/lean/Ltp/Policy.lean`: time window and
> count are checked for every type, `one-time` defaults to a limit of 1, and an unknown or
> malformed policy is rejected outright (fail-closed, per `minimal_is_sound`). The
> materialization slot is reserved atomically, so concurrent attempts under a one-time key
> admit exactly one; failed attempts release their slot, since the count tracks *completed*
> materializations. The sender side fails fast as well: `lattice()` structurally validates
> the policy at seal time — a malformed or unknown-type policy is refused rather than
> sealed into a key no conforming receiver will honor, while temporal checks are deferred
> to materialization, since sealing before a `not_before` window opens is legitimate. Two
> scope limits are inherent and permanent: enforcement is
> **receiver-side** — it constrains conforming receivers and is not a cryptographic
> guarantee against a receiver that modifies its own implementation — and the count lives
> in the enforcing protocol instance's **memory**, keyed by the sealed key's digest, so it
> bounds replay at that receiver and does not survive process restart or span receivers.
> Durable or shared counting is a deployment concern layered above the protocol.

- **Opaque** — an interceptor sees only random bytes (no metadata leaks)
- **Post-quantum** — ML-KEM-768 resists both classical and quantum adversaries

#### 2.2.2 Key Properties of the Lattice Key

The lattice key is **not the data**. It is the **proof of right to reconstruct**. This
creates several remarkable properties:

1. **Sender→receiver decoupling**: Transferring 1 KB and transferring 1 TB produce the same
   size sealed lattice key (1,423 bytes). The sender→receiver direct transmission is O(1).
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
   This guarantee holds for **ephemeral materialization**: a receiver that caches the
   unsealed CEK (e.g., for later re-materialization) voids forward secrecy for that
   transfer — a later compromise of the cached CEK exposes the entity.

   **Forward secrecy lifecycle:**
   1. `seal()` calls ML-KEM.Encaps(receiver_ek) → fresh (ss, kem_ct)
   2. ss is used as the AEAD key for the payload, then zeroized in memory
   3. kem_ct is embedded in the sealed output
   4. Only the holder of dk can recover ss from kem_ct (Module-LWE hardness)
   5. After the receiver processes the sealed key and zeroizes ss, the shared
      secret is unrecoverable — even if dk is later compromised
   6. For defense-in-depth, receivers SHOULD rotate ek/dk periodically;
      old dk values MUST be securely destroyed after rotation

### 2.3 Phase 3: MATERIALIZE

The receiver uses the lattice key to **reconstruct** the entity from the commitment layer.

#### 2.3.1 Reconstruction Process

```
1. Unseal lattice key with receiver's private key → extract entity_id, CEK, commitment_ref
2. Enforce access policy from the unsealed lattice key: verify the current time falls
   within [not_before, not_after] and the materialization count does not exceed
   max_materializations (§2.2.1) — abort before any shard fetch if the policy fails
3. Fetch commitment record from append-only log using entity_id
4. Verify commitment record: H(record) == commitment_ref (integrity check)
5. Verify commitment record signature (sender authenticity)
6. Read encoding params (n, k) from commitment record
7. Derive shard locations: ConsistentHash_internal(entity_id || shard_index || replica)
   for index in 0..n-1, replica in 0..r-1  (§2.1.2)
8. Fetch ENCRYPTED shards from nearest available commitment nodes (parallel). An
   implementation MAY fetch more than k — the reference implementation requests all n — so
   that shards failing tag verification in step 9 can be discarded and replaced without a
   second round trip. It fails only if fewer than k survive verification.
9. Decrypt each shard with the §2.1.1 derivation:
     nonce_i = HKDF-Expand(HKDF-Extract("ETP-SHARD-NONCE-v1", CEK),
                           info = entity_id || uint32_be(i))[:nonce_len]
     plaintext_i = AEAD_Decrypt(CEK, encrypted_shard_i, nonce=nonce_i,
                                aad = entity_id || uint32_be(i))
   — the AEAD authentication tag is verified BEFORE decryption (tamper detection), and the
   associated data binds each shard to its own (entity, index) position, so a shard replayed
   at the wrong index fails here rather than corrupting the decode
10. ErasureDecode(decrypted_shards, k) → entity content
11. Verify: H(entity_content || shape || timestamp || sender_pubkey) == entity_id
    — *End-to-end content integrity check.* This is distinct from the Merkle root verification
    in steps 4–5, which confirms commitment record integrity. This step independently verifies
    that the reconstructed content matches the EntityID, providing a second line of defense:
    an adversary who substitutes a valid-but-different commitment record (one whose signature
    and Merkle root internally check out, but which references a different entity) cannot
    pass this check, because the reconstructed content will hash to a different EntityID.
12. Entity materialized. Transfer complete.
```

#### 2.3.2 Why This Is Fast

Traditional transfer: **move all the data across one path (sender → receiver)**

LTP materialization: **pull k shards in parallel from the nearest nodes in the commitment network**

```
Traditional:    S ════════════════(entire payload)════════════════> R
                  Bottleneck: sender upload × distance to receiver

LTP:            S ──(1,423B sealed key)──> R
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

**Rotation gap (disclosed limitation).** A sealed-but-unmaterialized lattice key older
than the rotation grace period (default: 1 hour) becomes **permanently undecryptable**
once the old $dk$ is zeroized — no re-sealing mechanism exists in v1. Senders SHOULD
re-seal outstanding lattice keys to the receiver's new encapsulation key when they
observe a receiver key rotation.

**Key chain structure:**

```
KeyPair v1 (created: T₀, expires: T₁ + grace)
  └── KeyPair v2 (created: T₁, predecessor: H(v1.vk), expires: T₂ + grace)
       └── KeyPair v3 (created: T₂, predecessor: H(v2.vk))
```

The key chain provides **non-repudiation continuity**: if a sender rotates keys,
the chain proves that all historical commitment signatures are attributable to
the same identity (verifiable via the `predecessor_vk_hash` chain).

#### Deferred specification items

The exact serialization of the lattice-key inner payload, the sealed-key wire format, the
consistent-hashing variant and its parameters (Karger ring / jump hash / rendezvous), and
the commitment-record serialization are deliberately deferred to the wire-format
specification (LTP-corridor-v1) and are not normative in this paper. The reference
implementation's AEAD is XChaCha20-Poly1305.

---

## 3. Security Model

### 3.1 Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| Man-in-the-middle intercepts lattice key | Entire key is sealed (envelope-encrypted) to receiver's public key; interceptor sees opaque ciphertext with zero metadata |
| Attacker scrapes commitment log | Log contains only Merkle root of encrypted shard hashes — no shard IDs, no content, no CEK |
| Attacker fetches shards from nodes | Shards are AEAD-encrypted with CEK; without CEK, ciphertext is computationally useless |
| Attacker compromises < k nodes | Information-theoretic security: < k shards (even decrypted) reveal zero information about content that is not guessable/enumerable (see §3.3.5); guessable content requires ZK mode |
| Sender denies transfer occurred | Commitment record is on immutable append-only log with sender's signature |
| Receiver claims different data was sent | Entity ID is deterministic hash of content; both parties can verify |
| Replay attack (re-use lattice key) | Access policy can enforce one-time materialization; commitment nodes track access |
| Quantum computing threat | **Core transfer path: fully post-quantum** — ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), SHA3-256 (FIPS 202), information-theoretic erasure coding; no classical-only primitive on the COMMIT/LATTICE/MATERIALIZE path. **ZK mode and the corridor attestation quorum: NOT quantum-resistant** — both are pairing-based over BLS12-381 and broken by Shor's algorithm. Neither may be relied on under a quantum-adversary threat model (see §3.4 for the per-surface posture). |

### 3.2 Zero-Knowledge Transfer Mode

**Purpose.** ZK mode addresses the EntityID fingerprinting limitation identified in §3.3.3:
in standard LTP, `entity_id = H(entity_content || ...)` is published to the public commitment
log, allowing observers to fingerprint low-entropy entities by computing and matching candidate
hashes. ZK mode replaces the public entity_id with a hiding commitment, eliminating
fingerprinting while preserving immutability and non-repudiation.

**Scope.** This section specifies the core ZK mode instantiation sufficient to close the
confidentiality gap in §3.3.3. Content-property proofs (e.g., proving "this entity is a valid
JSON document" without revealing content) require additional circuit composition and are
deferred to a future protocol version (see §12, Open Question 6).

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

**Hash function:** ZK mode uses Poseidon [17] in place of SHA3-256 for all circuit-internal
hash operations. Poseidon is ZK-friendly (designed for low R1CS gate count). §1.2 specifies
SHA3-256 for content addressing; inside ZK circuits, implementations MUST use Poseidon
(circuit-efficient) as specified here.

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
   - **Near-term (STARK):** Replace Groth16 with a hash-based STARK (e.g., over SHA3-256 or
     Poseidon). No trusted setup required; security reduces to collision resistance of the
     hash function. Proof sizes grow to ~20–200 KB.
   - **Medium-term (lattice ZK):** Lattice-based proof systems (e.g., Ligero++, Spartan
     over a PQ-safe hash) may yield smaller proofs. No NIST-standardized lattice-based ZK
     system exists as of this writing.

   Until a post-quantum ZK instantiation is standardized and integrated, deployments
   requiring both content-privacy (hiding) and quantum resistance SHOULD forgo ZK mode and
   accept the EntityID fingerprinting limitation of §3.3.3, mitigated by ensuring entity
   content has sufficient min-entropy (§3.3.3 guidance). See §12, Open Question 6.

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
canonical-lane choice is **SHA3-256** ($n = 256$, FIPS 202); SHA-384 and SHA-512 are the
permitted alternatives, with correspondingly larger margins (§1.3). The classical birthday
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
| Preimage resistance (SHA3-256) | 256 bits | 128 bits (Grover) |
| Collision resistance (SHA3-256) | 128 bits (birthday) | **~85 bits (BHT)** |

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

**ML-KEM-768 Security Parameters.** The sealed lattice key's confidentiality reduces to the Module-LWE problem with parameters (k=3, q=3329, η₁=2, η₂=2), achieving NIST Security Level 3 — equivalent to AES-192 against quantum adversaries. The IND-CCA2 property is obtained via the Fujisaki-Okamoto transform applied to an IND-CPA-secure K-PKE scheme [20] (FIPS 203 §4 [24]). The recent formal verification of Signal's PQXDH protocol [21] — the first machine-checked post-quantum security proof of a real-world protocol using CryptoVerif — identified a KEM binding property requirement: the KEM ciphertext must be bound to the *receiver's encapsulation key*. **LTP's current sealed-key construction does NOT discharge this property**: the sealed lattice key binds entity_id (derived from the sender's verification key) but contains no receiver key material, so the ciphertext is not bound to the receiver's encapsulation key. A 2026-08 Verifpal symbolic analysis of the protocol (`docs/formal/`) independently found the corresponding weakness: sealed lattice keys can be replayed across sessions, because the sealed key carries no freshness or receiver binding. The planned mitigation — scheduled for a future protocol revision — is to include the receiver encapsulation-key fingerprint and the entity_id in the AEAD associated data of the sealed key, closing both findings. This mirrors the guidance in HPKE [26], which binds additional identities into the context/AAD rather than relying on the KEM alone. Protocol-level binding is necessary rather than optional here: in the X-BIND taxonomy of Cremers, Dax, and Medinger [27], ML-KEM itself provides LEAK-BIND-K-CT and LEAK-BIND-K-PK but is **not** MAL-BIND-K-CT or MAL-BIND-K-PK [28] — a maliciously generated key pair can break ciphertext binding at the primitive level, so no choice of KEM parameters alone can discharge the obligation.

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
enumerable, ZK mode MUST be used — *except* in deployments with a quantum-adversary threat
model, where ZK mode is prohibited (§3.2.4). In that intersection (guessable entities under
a quantum-adversary threat model), implementations MUST either raise the entity's
min-entropy — e.g., by including a random salt field in the entity envelope — or accept
the documented EntityID-fingerprinting risk. Relying on Theorem 5 alone in such settings
provides no confidentiality guarantee.

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
over GF(256) at $n$ distinct non-zero points ($\alpha_i = i + 1$ in the v1 parameter set). Any $t < k$ evaluations leave $k - t \geq 1$ degrees
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

**Formal basis.** The threshold secrecy of LTP's erasure coding follows from the MDS (Maximum Distance Separable) property of Reed-Solomon codes over GF(2⁸), first connected to secret sharing by McEliece and Sarwate [22]. For a uniformly random (high-min-entropy) entity, any k−1 shards leave exactly one degree of freedom in the polynomial coefficient space, revealing zero information about the entity content in the Shannon sense. This information-theoretic guarantee holds regardless of the adversary's computational power, including against quantum adversaries — but, per the note above, only for content the adversary cannot guess or enumerate; for guessable content the deterministic encoding is trivially distinguishable and AEAD encryption (or ZK mode) is the operative protection.

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
+ SHA3-256), ML-KEM and ML-DSA each provide $\geq 128$ bits of post-quantum security,
while SHA3-256 provides ~85-bit post-quantum collision resistance (BHT bound) and
128-bit post-quantum preimage resistance (Grover bound).

#### 3.3.7 What Cannot Be Formally Proven

| Claim | Why It Cannot Be Proven | Status |
|-------|------------------------|--------|
| "Faster than direct transfer" | Performance is empirical. Depends on topology, entity size, node placement. | Acknowledged in §6.4 (cost model) |
| "Geography-independent" | Requires commitment nodes near receivers. No protocol guarantees this. | Deployment-dependent |
| "Sub-latency transfer" | O(1) key size is proven; O(1) total latency is not. MATERIALIZE fetches O(entity) data. | Reframed as "bottleneck relocation" |
| "Secure without trust" | Requires honest append-only log and ≥ k honest shard replicas. These ARE trust assumptions. | Acknowledged in §5.1 |
| "Permanent storage" | Requires economic incentives to sustain nodes. Without incentives, rational nodes evict data. | Acknowledged in §5.4.4, §5.5 |

#### 3.3.8 Machine-Checked Verification Status

The theorems in this section are pen-and-paper reductions. Separately from
them, two machine-checked artifacts exist in the reference repository as of
2026-08-16. This subsection states exactly what they establish — and, in the
spirit of §3.3.7, exactly what they do not.

**Lean 4 proofs** (`formal/lean/`, CI-gated, `sorry`-free with a
negative-tested axiom audit; 52 audited theorems). Machine-checked claims
that correspond to statements made in this paper:

| Paper claim | Lean theorem |
|-------------|--------------|
| The sealed lattice key is the same size for a 1 KB and a 1 TB entity (§2.2.2) | `lattice_key_size_payload_independent`, `sealed_768_bounded` — see the size-bound note below |
| The commitment record cannot be smaller than its 3,309-byte ML-DSA-65 signature (§2.1.3) | `record_exceeds_1kb` |
| ρ = nr/k = 6 at default parameters, and the §6.4 break-even is N ≥ ρ, not N ≥ r | `rho_default`, `breakeven_iff` |
| Any k shards suffice, no shard index is privileged, and the k / k−1 reconstruction boundary is sharp (§4.3) | `no_index_privileged`, `at_threshold_decodable`, `below_threshold_undecodable` |
| The §2.2.1 access-policy algebra: one-time keys exhaust, the mandated fail-closed mode never over-grants, and attenuation never amplifies authority (§10.4) | `one_time_exhausts`, `minimal_is_sound`, `attenuate_no_amplify` |
| Two ≥ 2/3 governance supermajorities share an honest voter when < n/3 of operators are Byzantine (§5.1); the bound is tight at exactly n/3 | `supermajority_safety`, `safety_bound_tight` |
| The corridor 7-of-9 attestation quorum: any two attestations share an honest signer with ≤ 4 Byzantine super-nodes | `corridor_safety` |
| Both §2.1.1 interoperability test vectors, recomputed inside the Lean kernel over a from-scratch GF(2⁸) implementation and checked byte-for-byte | `vector1_matches`, `vector2_matches`, `vector2_framing` |

These are proofs **about small models of the specification, not about the
implementation**: the erasure theorems assume the MDS threshold shape rather
than proving it over GF(2⁸); cryptographic soundness (ML-KEM IND-CCA2,
ML-DSA EUF-CMA, BLS unforgeability) is assumed throughout; and nothing is
extracted to, or mechanically linked with, `src/ltp/`. Read
`formal/lean/README.md` § "What is NOT proved" before citing them.

**Size-bound note (a model/implementation divergence we do not paper over).**
`sealed_768_bounded` proves the sealed key is at most 1,300 bytes for any
policy of at most 96 bytes; the companion `sealed_768_min` / `sealed_768_max`
bracket the model at 1,220–1,250 bytes. The implementation produces **1,423
bytes** (§7.4). The 203-byte gap decomposes into two independent causes:

- **179 bytes of payload encoding.** The model assumes a compact 116-byte
  inner payload; the implementation seals 295 bytes of JSON whose `entity_id`
  and `commitment_ref` are 73-character prefixed digest *strings* rather than
  raw 32-byte values.
- **24 bytes of envelope.** The Lean model's envelope is
  `kem_ct(1088) + tag(16) = 1104` and has no nonce field at all; the
  implementation's wire format is
  `kem_ct(1088) ‖ nonce(24) ‖ ciphertext ‖ tag(16) = 1128`. The model is
  simply missing the nonce.

What the theorem establishes and the measurement confirms is the load-bearing
claim — that sealed size does not depend on entity size. The absolute constants
in the Lean model are stale in both respects. A compact binary encoding (the
`canonical_bytes` path, 244 bytes, already present but not on the sealing path)
would bring the implementation to 1,372 bytes. Aligning model and
implementation is tracked as future work; until then, cite 1,423 bytes for the
implementation and treat the Lean interval as a statement about the model.

**Verifpal symbolic analysis** (`docs/formal/etp-protocol.vp`, Verifpal
0.27.4, active Dolev-Yao attacker, unbounded sessions; first run recorded
2026-08-16 in `docs/formal/verifpal-run-2026-08-16.md`):

| Query | Verdict |
|-------|---------|
| `confidentiality? cek` | ✅ Verified |
| `confidentiality? content` | ✅ Verified |
| `authentication? commitment` | ❌ Fails — the signed record can be (re)delivered by the attacker; the signature holds, the delivery channel carries no authority |
| `authentication? sealed_key` | ❌ Fails — **cross-session replay** of sealed lattice keys; nothing binds a sealed key to a session, freshness value, or the receiver's encapsulation key |

The confidentiality verdicts are conditional on authentic identity-key
distribution (modeled as a guarded pre-protocol exchange). The sealed-key
replay finding independently corroborates the KEM ciphertext-binding gap
disclosed in §3.3.3; the planned mitigation (receiver encapsulation-key
fingerprint and entity_id in the sealed key's AEAD associated data, plus a
freshness component) is recorded there and in `docs/formal/ANALYSIS.md`.
Access policy (`max_materializations`, §2.2.1) is enforced as of v0.4.1 and
partially mitigates this finding: a sealed key replayed **to the same receiver
protocol instance** is bounded by its materialization count, atomically
reserved and rolled back on failure. The mitigation's boundary is exactly the
enforcement state's: counts are in-memory and per-instance, so a sealed key
replayed after a receiver restart, or to a different receiver instance holding
the same decapsulation key, is not counted. The full fix remains the planned
protocol-level binding (receiver encapsulation-key fingerprint, entity_id, and
a freshness component in the sealed key's AEAD associated data); until it
lands, the residual replay surface is cross-instance and cross-restart only.

Current status, per artifact class: symbolic confidentiality **verified
under stated assumptions**; symbolic authentication **failing with known,
disclosed findings and a planned fix**; specification arithmetic and
threshold logic **machine-checked in Lean**; game-based reductions
**pen-and-paper only** (a CryptoVerif/EasyCrypt treatment remains future
work, per `docs/FORMAL_VERIFICATION_STATUS.md`).

**Unspecified dependency.** Both verified confidentiality results are
conditional on authentic identity-key distribution, and LTP does not currently
specify how a deployment provides it. A key directory, an out-of-band
fingerprint comparison, and a PKI-rooted attestation are all compatible with
the model, and they are not equally strong. Until the paper specifies one, the
confidentiality verdicts should be read as *"verified given a solved key
distribution problem"* — which is a real assumption, not a formality.

### 3.4 Post-Quantum Posture, by Surface

LTP is often summarized as "post-quantum by default." That is true of the core
transfer path and false of the system as a whole, and the distinction matters enough
to state precisely. The following table is the authoritative per-surface posture;
where an earlier section says "LTP is post-quantum," it means row 1.

| Surface | Primitives | PQ-safe? | Notes |
|---------|-----------|:--------:|-------|
| **Core transfer path** (COMMIT / LATTICE / MATERIALIZE) | ML-KEM-768, ML-DSA-65, SHA3-256, XChaCha20-Poly1305, RS erasure coding | **Yes** | No classical-only primitive. This is the path every transfer traverses. |
| **Commitment log** (CT-style Merkle log, STHs) | SHA3-256, ML-DSA-65 | **Yes** | Same primitives as the core path. |
| **ZK transfer mode** (§3.2, optional) | Groth16 over BLS12-381, Poseidon | **No** | Pairing-based; broken by Shor. Opt-in; standard mode does not use it. |
| **Corridor attestation quorum** (§8.3, optional) | BLS12-381 aggregate signatures | **No** | Pairing-based; broken by Shor. Required only for deployments using the corridor/on-chain anchoring surface. |
| **Composite signature mode** (§8.2, opt-in) | ML-DSA-65 **+** Ed25519-SHA512 | **Hedged** | The ML-DSA component remains PQ-secure if Ed25519 falls; the pair is only as *available* as both. Present for transition-period assurance, not for PQ strength. |

**How to read this.** A deployment that uses standard mode with a CT-style log and no
corridor is post-quantum end to end. A deployment that anchors on-chain through the
corridor inherits a classical signature dependency at the attestation layer — the
transferred content stays PQ-protected, but the *attestation that it was anchored* does
not. This is a meaningful distinction for long-horizon non-repudiation: an adversary with
a future quantum computer could forge a historical corridor attestation, though not
decrypt the entity it attests to, and not forge the ML-DSA-65 commitment signature
underneath it.

**Why the corridor is not yet PQ.** Aggregate signatures are what make a 7-of-9 quorum
cheap to verify on-chain: BLS12-381 compresses nine signatures into 96 bytes. No
standardized post-quantum aggregate signature scheme offers a comparable compression
ratio today — the naive PQ construction carries nine ML-DSA-65 signatures at 3,309 bytes
each, or 29.8 KB, which is prohibitive as on-chain calldata. This is a real engineering
constraint rather than an oversight, and it is the same constraint the broader
proof-of-stake ecosystem faces. It is tracked in §12, Open Question 7.

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
  "entity_id": "sha3-256:new_hash...",
  "predecessor": "<64-hex log head at commit time — bare, no algorithm prefix>",
  "version": 2,
  ...
}
```

This creates an immutable **version chain**. Every version exists permanently. "Updating" is
actually "appending a new version." The full history is always auditable.

Two details matter for implementers. The `predecessor` field is set by the log at append
time, not by the sender, which is why it is excluded from the signable payload (§2.1.3) — it
carries the log head as a bare 64-character hex digest with no algorithm prefix, unlike every
other digest in the record. And because each version is a distinct entity with its own full
shard set, a version chain of $M$ revisions costs $M \cdot D\rho$ in storage; §6.4's
deduplication guidance applies directly (commit deltas, not snapshots).

### 4.3 Immutability ≠ Availability

A critical distinction that protocols often conflate:

| Property | Guarantee | Condition |
|----------|----------|-----------|
| **Immutability** | If data is reconstructed, it is *exactly* what was committed | CONDITIONAL on an honest append-only log (§5.1.4); given log integrity, content-addressing makes any valid reconstruction authentic — no mechanism exists to produce corrupted data with a valid EntityID. |
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
  "reconstruction_threshold_k": 3,
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
- At least $2k$ nodes (where $k$ = the deployment's minimum reconstruction threshold,
  declared as `reconstruction_threshold_k` in the genesis configuration), ensuring no single
  entity of $k$ nodes can reconstruct all shards even before considering encryption. The
  example above declares a small bootstrap threshold $k = 3$, so `"minimum_nodes": 6`
  satisfies the $2k$ constraint; a deployment using the document-default $k = 32$ requires
  `"minimum_nodes"` ≥ 64
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
> (SHA3-256 + ML-DSA-65), and requires no consensus protocol.
>
> **Reference implementation:** `src/ltp/merkle_log/` in the LTP repository.
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
| **Hash primitive** | SHA3-256 — the canonical lane (§1.3); tree heads are audited artifacts, so the internal-lane hash MUST NOT be substituted |
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

Terminology: "Option C" is the shard-level audit design adopted from the internal design
review (`docs/security/audits/internal/001-lattice-key-shard-exposure.md`); "LTP v2" refers
to the current protocol revision incorporating it.

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

##### 5.4.1.2 Common-Cause Failure and Software Monoculture

The most important limitation of both models above is one that no amount of geographic
distribution fixes: **every node in an LTP deployment is likely to run the same
implementation**. Region-aware placement defends against the failure of a place. It does
not defend against the failure of a program.

Concretely, if all nodes run the same LTP build, then a memory-safety bug, a panic on a
malformed shard, a dependency advisory forcing simultaneous emergency patching, or a
defect in the erasure decoder is a *single* event that can take the entire network below
the reconstruction threshold at once — regardless of how many regions those nodes occupy.
Under such an event, $p_d$ and $p_n$ are not the relevant parameters at all; the relevant
probability is that of a correlated software fault, which the model does not represent.

This is not hypothetical for content-addressed storage. A decoder that produces incorrect
output for a particular shard geometry would be caught by LTP's end-to-end EntityID check
(§2.3.1, step 11) — the failure would be *safe*, returning nothing rather than wrong data
— but it would be simultaneously unavailable everywhere. Immutability survives a
monoculture failure; availability does not.

Extending the model honestly requires an additional term. Let $p_{sw}$ be the probability
of a common-mode software failure in the deployment window. Then entity availability is
bounded above by:

$$P(\text{entity available}) \leq (1 - p_{sw}) \cdot P_{\text{model}}(\text{entity available})$$

where $P_{\text{model}}$ is the geographic model of §5.4.1.1. Because $p_{sw}$ multiplies
rather than adds, **it dominates once it exceeds the geographic failure probability** —
and at the nine-nines figures computed above ($\approx 10^{-8}$), essentially any credible
software-defect rate dominates. The honest reading of the "nine nines" result is therefore:
*that is the availability attributable to node and region failure, and it is an upper bound
that a real deployment will not reach.*

**Mitigations, none complete.**

| Mitigation | Reduces | Cost |
|-----------|---------|------|
| Independent implementations (a second conforming client) | $p_{sw}$ substantially — this is why §2.1.1's byte-exact test vectors and conformance rules matter beyond pedantry | High: a second implementation is a major undertaking, and divergence risks a consistency split |
| Staged rollout across failure domains; never upgrade all domains at once | Correlated *deployment* failures, not latent defects | Low; operationally standard, and a reason to keep domains administratively independent |
| Version skew tolerance — nodes on release $v$ and $v-1$ serving simultaneously | Blast radius of a bad release | Requires the wire-format stability guarantees of `docs/STABILITY_PROMISES.md` |
| Differential testing against the Lean kernel's independent GF(2⁸) implementation (§3.3.8) | Erasure-decoder defects specifically | Already in place; narrow scope |

LTP currently has **one** implementation. Until a second conforming implementation exists,
deployments should treat the availability figures in §5.4.1 as characterizing
infrastructure risk only, and should not quote them as end-to-end availability
guarantees. We regard this as the single largest gap between LTP's modeled and achievable
availability, and it is the reason §2.1.1 specifies the erasure coding to the byte.

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

The sealed lattice key is 1,423 bytes, of which 1,088 is the ML-KEM-768 ciphertext — the
honest cost of quantum resistance, against roughly 240 bytes for a comparable classical
construction. Its transmission is near-instantaneous on any network, and we measure the
whole LATTICE phase at 0.24 ms independent of entity size (§7.3). Shard fetching is
parallelized from the nearest nodes.

The bottleneck relocation principle is explained in §2.3.2; the formal latency equations
and sensitivity analysis are in §6.4.

### 6.2 Geographic Distance

**Traditional**: New York → Tokyo = ~200ms RTT minimum (speed of light through fiber).  
For a 1 GB file at 100 Mbps effective throughput: ~80 seconds, bottlenecked by the single path.

**LTP**: The sender in New York transmits a 1,423-byte sealed key to the receiver in Tokyo
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
- $L_{SR}$ = one-way latency between sender and receiver (sealed lattice-key delivery)
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
| Sender→receiver direct | $D$ | $O(1)$ (1,423 bytes) |
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
$D$ (local shard fetches) + 1,423 bytes (sealed key). Sender bandwidth is constant after commit.

**Latency costs:**

$$T_{direct} = L_{SR} + \frac{D}{\text{bandwidth}_{SR}}$$

$$T_{LTP} = \underbrace{L_{SR} + \frac{1300}{\text{bandwidth}_{SR}} + L_{RN} + L_{\log}}_{\text{sealed-key delivery + record lookup (negligible)}} + \underbrace{\frac{D/k}{\alpha \cdot \text{bandwidth}_{RN}}}_{\text{k parallel shard fetches}}$$

where $\alpha \in (0, 1]$ is a **parallelism efficiency factor** representing the fraction of
theoretical parallel bandwidth actually achieved. The ideal case $\alpha = 1$ (full parallelism)
requires dedicated per-shard connections with no receiver-side or node-side contention.
In practice $\alpha < 1$ due to:

- **TCP connection overhead**: Each shard fetch requires a connection (or stream), adding
  per-connection handshake latency, especially pronounced when $k$ is large.
- **Node-side I/O scheduling**: If multiple receivers are fetching from the same commitment
  node simultaneously, node disk I/O contention degrades throughput.
- **Receiver bandwidth cap**: If $k \cdot \text{bandwidth}_{RN} > \text{bandwidth}_{receiver}$,
  the receiver's downlink is the bottleneck: materialization time is
  $D / \text{bandwidth}_{receiver}$, and the parallel speedup is capped at
  $\text{bandwidth}_{receiver} / \text{bandwidth}_{RN}$ effective streams, not by node
  bandwidth.
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

### 6.5 Exact Cost of the Coding Layer

§7 shows empirically that the erasure coder is where an LTP implementation's time goes.
This section derives its cost exactly, and shows how far an implementation can reduce the
constant without changing a single shard byte. The analysis matters because the coding
layer's cost is *conformance-constrained*: §2.1.1 pins the shards to the byte, so the only
legal optimizations are ones that compute the same function faster.

**The counting identity.** Every byte of every shard is a $k$-term inner product over
GF(2⁸):

$$\text{shard}_i[b] \;=\; \bigoplus_{j=0}^{k-1} \alpha_i^{\,j} \otimes c_j[b]$$

Encoding produces $n$ shards of $D/k$ bytes, each byte requiring $k$ field multiplications,
so the total is exactly

$$W_{\text{enc}} \;=\; n \cdot k \cdot \frac{D}{k} \;=\; n \cdot D \quad\text{byte-multiplications, plus } \tfrac{k-1}{k}\, nD \text{ byte-XORs.}$$

The $k$s cancel: **encode cost depends on $n$ alone**, not on $n \cdot k$. Decoding
reconstructs $k$ chunks from $k$ selected shards through the inverse matrix, giving
$W_{\text{dec}} = k \cdot D$ by the same count. Two predictions follow, both tested in
§7.2: throughput at fixed $n$ is flat in $D$ and in $k$, and the encode:decode cost ratio
is $n : k$ — a factor of 2 at both parameter sets this paper uses.

**Reaching the bound in an interpreted implementation.** The identity above says nothing
about the *constant* per byte-multiplication, and the constant is where a naive
implementation loses two orders of magnitude: evaluating the inner product byte-by-byte in
interpreted code costs an interpreter dispatch per field operation. Two algebraic facts
remove the interpreter from the data path entirely:

1. *Multiplication by a constant is a byte substitution.* For fixed $c$, the map
   $b \mapsto c \otimes b$ is $\mathbb{F}_2$-linear on the 8-bit vector space — a
   function on 256 values, precomputable as a 256-entry table $T_c$. Multiplying an entire
   chunk by $c$ is then a single native byte-translation pass
   ($\texttt{bytes.translate}(T_c)$ in the reference implementation). At most 255 distinct
   tables exist (64 KiB in total), built lazily and cached.

2. *Accumulation is carry-free addition.* The XOR of two equal-length byte strings is
   addition in $\mathbb{F}_2^{8L}$, which arbitrary-precision integer XOR performs in one
   native pass.

Factoring the inner product by coefficient therefore turns each of the $nk$ coefficient
applications into two native passes over a $D/k$-byte chunk. The interpreter executes
$O(nk)$ operations *regardless of $D$*; the per-byte work is one table lookup and one XOR
in compiled code. The reference implementation adopted this factorization in place of the
byte-by-byte loop, with shards verified byte-identical against the scalar definition, the
§2.1.1 pinned vectors, and the Lean-kernel recomputation (§3.3.8). The measured effect is
a **100–150× throughput increase** with zero conformance impact (§7.2).

**The decode matrix in $O(k^2)$.** Reed-Solomon decoding *is* polynomial interpolation:
the message chunks are the coefficients of a degree-$(k{-}1)$ polynomial $p$, and the
shards are its evaluations $p(\alpha_i)$. Rather than inverting the $k \times k$
Vandermonde submatrix by Gauss-Jordan elimination ($O(k^3)$ field operations), the inverse
follows in closed form from the Lagrange basis. With
$P(z) = \prod_t (z \oplus \alpha_t)$, define $Q_i(z) = P(z)/(z \oplus \alpha_i)$
(exact by synthetic division, since $\alpha_i$ is a root of $P$) and
$d_i = Q_i(\alpha_i) = \prod_{t \neq i} (\alpha_i \oplus \alpha_t)$. Then

$$\left(V^{-1}\right)[m][i] \;=\; \left([z^m]\,Q_i\right) \otimes d_i^{-1}$$

— computable in $O(k^2)$ total: one $O(k^2)$ product for $P$, then one $O(k)$ division and
one $O(k)$ Horner evaluation per row. (In characteristic 2, subtraction is XOR, hence the
$\oplus$ in the linear factors.) At $k = 32$ this replaces roughly 130,000 interpreted
field operations with roughly 3,000; at large $k$ it keeps the matrix step negligible
beside the $O(kD)$ data path, where Gauss-Jordan would begin to rival it. The reference
implementation uses the Lagrange construction on the decode path and retains Gauss-Jordan
as an independent cross-check, with the two verified equal over randomized index sets in
the test suite.

**What remains on the table.** Two further reductions exist, one legal and one not:

- *SIMD field kernels* (Intel ISA-L, or the GFNI instruction set) evaluate the same
  Vandermonde products at several GiB/s per core — roughly another order of magnitude in
  the constant. This is conformance-preserving: same matrix, same shards, faster
  arithmetic. It is the remaining item in §12, Open Question 8.
- *Additive-FFT Reed-Solomon* (the Lin–Chung–Han line of work) reduces the exponent,
  encoding in $O(D \log n)$ rather than $O(D \cdot n)$. But it achieves this by changing
  the evaluation-point structure, which changes the shard bytes — non-conformant under
  §2.1.1 — and at this protocol's $n \leq 255$ the maximum asymptotic gain is
  $n / \log_2 n \leq 32$ before its larger constants are paid. The asymptotics are not
  where this protocol's performance lives; the constant is.

The conformance-preserving cost floor is therefore $n \cdot D$ byte-operations at whatever
rate the host executes table-lookup-plus-XOR — and §7.2 measures the reference
implementation running within a small factor of memory bandwidth on that kernel.

---

## 7. Empirical Evaluation

Prior revisions of this paper carried a cost model with no measurements behind it, and
external review round 003 correctly flagged the absence. This section supplies the missing
data. Every figure below is produced by `scripts/benchmark_whitepaper.py` in the reference
repository and can be regenerated with one command.

**What these numbers are.** Single-host measurements of the reference implementation, taken
on one machine, with no network between the parties. **What they are not.** A performance
claim about a deployed commitment network. They characterize the *implementation's* costs —
which primitives are expensive, how costs scale with $n$ and $k$, and what the protocol's
artifacts actually weigh. They say nothing about $\alpha$, the parallelism efficiency factor
of §6.4, which is a property of a real network topology and remains unmeasured (§7.5).

**Method.** Medians over repeated trials after warmup — 50 for the asymmetric primitives, 30
for hash throughput, 3–5 for erasure coding and protocol phases — timed with
`time.perf_counter`. Python 3.11.15 on Linux x86-64, 4 CPUs, shared virtual host. ML-KEM and
ML-DSA come from the `pqcrypto` package, AEAD (XChaCha20-Poly1305) from libsodium via
PyNaCl, BLAKE3 from the `blake3` package, SHA3-256 from `hashlib`. All at NIST Level 3
(`SecurityProfile(level=3, canonical=sha3-256, internal=blake3)`). The erasure coder is the
conformant table-driven kernel of §6.5 — pure Python orchestrating C-speed byte
primitives — not the optional non-conformant `zfec` path (§7.5).

### 7.1 Cryptographic Primitives

Typical latency, with the range observed across three independent runs. The host is a
shared 4-CPU VM, and sub-millisecond operations vary by tens of percent between runs; we
give the range rather than imply a precision the measurement does not support.

| Operation | Typical latency | Observed range |
|-----------|---------------:|---------------:|
| ML-KEM-768 keygen | 0.07 ms | 0.061–0.071 |
| ML-KEM-768 encapsulate | 0.07 ms | 0.057–0.109 |
| ML-KEM-768 decapsulate | 0.08 ms | 0.071–0.092 |
| ML-DSA-65 keygen | 0.18 ms | 0.157–0.198 |
| ML-DSA-65 sign (473-byte record) | 0.55 ms | 0.505–0.636 |
| ML-DSA-65 verify | 0.18 ms | 0.168–0.193 |

The precise values matter less than the order of magnitude: every post-quantum operation on
the critical path is **sub-millisecond**, and the whole asymmetric cost of a LATTICE phase —
one encapsulation plus one AEAD seal — is well under a fifth of a millisecond.

Hash throughput on 1 MiB, per lane (§1.3):

| Lane | Algorithm | Throughput |
|------|-----------|-----------:|
| Canonical | SHA3-256 | 350–464 MiB/s |
| Internal | BLAKE3-256 | 5,965–6,618 MiB/s |

The **14–17× gap** across runs is the quantitative justification for the dual-lane
split. It is also why the split is drawn where it is: the canonical lane runs once per
commitment record, the internal lane once per (entity, shard, replica) placement decision.

### 7.2 Erasure Coding

Reed-Solomon over GF(2⁸) on the conformant path. Two implementations of the *same
function* are compared: the original byte-by-byte scalar loop (the baseline this paper's
earlier revisions measured), and the table-driven kernel of §6.5, which produces
byte-identical shards. The change is pure constant-factor engineering guided by the
algebra — no parameter, no wire byte, and no security property moved.

**Baseline (scalar loop), retained for the record:**

| Parameters | Entity | Encode | Decode | Encode throughput |
|-----------|--------|-------:|-------:|------------------:|
| $n=8, k=4$ | 256 KiB | 453 ms | 257 ms | 0.55 MiB/s |
| $n=64, k=32$ | 256 KiB | 3,072 ms | 1,496 ms | 0.081 MiB/s |

**Current (table-driven kernel, §6.5):**

| Parameters | Entity | Encode | Decode | Encode throughput | Decode throughput |
|-----------|--------|-------:|-------:|------------------:|------------------:|
| $n=8, k=4$ | 64 KiB | 0.59 ms | 0.42 ms | 106 MiB/s | 149 MiB/s |
| $n=8, k=4$ | 256 KiB | 2.39 ms | 1.56 ms | 104 MiB/s | 160 MiB/s |
| $n=8, k=4$ | 1 MiB | 11.4 ms | 6.4 ms | 88 MiB/s | 155 MiB/s |
| $n=8, k=4$ | 4 MiB | 49.3 ms | 27.7 ms | 81 MiB/s | 145 MiB/s |
| $n=64, k=32$ | 64 KiB | 5.8 ms | 3.3 ms | 10.8 MiB/s | 18.8 MiB/s |
| $n=64, k=32$ | 256 KiB | 20.5 ms | 11.3 ms | 12.2 MiB/s | 22.1 MiB/s |
| $n=64, k=32$ | 1 MiB | 83.8 ms | 42.8 ms | 11.9 MiB/s | 23.4 MiB/s |
| $n=64, k=32$ | 4 MiB | 312.9 ms | 169.4 ms | 12.8 MiB/s | 23.6 MiB/s |

The speedup is **~100–150×** at matched configurations (e.g. 453 → 2.39 ms encode at
$n{=}8$; 3,072 → 20.5 ms at $n{=}64$), and the sweep now extends to 4 MiB where the
baseline was impractical to run. Three predictions from §6.5 can be read off the table.

**The $n \cdot D$ law, now with a stable constant.** Normalizing payload throughput by
$n$ gives the kernel's *coefficient-work rate* — the speed at which it executes the
underlying $n \cdot D$ byte-operations. Across every measured configuration it is nearly
constant: $8 \times 104 \approx 830$ MiB/s at $(8,4)$ and $64 \times 12.2 \approx 780$
MiB/s at $(64,32)$ on 256 KiB, and between 650 and 850 MiB/s over the full 64 KiB–4 MiB
sweep. The earlier scalar measurements deviated from the predicted $8\times$ ratio by
20% because interpreter fixed costs did not amortize uniformly; with those costs removed
from the data path, the measured $n{=}8$ : $n{=}64$ throughput ratios (6.4–9.9 across
sizes, centered on 8.0) bracket the prediction, and the residual variation tracks
allocator and cache effects rather than arithmetic.

**Decode:encode confirms $k : n$.** §6.5 predicts decode does $k/n = 1/2$ the work at both
parameter sets. Measured ratios run 1.4–1.9× — the factor of 2 attenuated by the decode
path's extra fixed costs (matrix construction, chunk reassembly), exactly the deviation a
constant-plus-linear cost model expects at these sizes.

**The matrix step no longer matters at any legal $k$.** With the Lagrange construction
(§6.5) the decode matrix costs $O(k^2)$ interpreted operations — about 3,000 at $k=32$ —
against millions of C-speed byte operations in the data path. Under Gauss-Jordan at large
$k$ the matrix step would have grown to rival the data path; that ceiling is gone.

### 7.3 End-to-End Transfer

Full three-phase transfer, 16-node network across 4 simulated regions, content verified
byte-identical on materialization. These figures use the §6.5 table-driven coder; the
pre-optimization equivalents (e.g. 479 ms and 3,099 ms COMMIT on the two 256 KiB rows) are
retained in the revision history for comparison.

| Parameters | Entity | COMMIT | LATTICE | MATERIALIZE | Sealed key |
|-----------|--------|-------:|--------:|------------:|-----------:|
| $n=8, k=4$ | 64 KiB | 3.2 ms | 0.188 ms | 1.2 ms | 1,423 B |
| $n=8, k=4$ | 256 KiB | 6.6 ms | 0.157 ms | 2.8 ms | 1,423 B |
| $n=8, k=4$ | 1 MiB | 20.9 ms | 0.143 ms | 9.9 ms | 1,423 B |
| $n=8, k=4$ | 4 MiB | 79.0 ms | 0.163 ms | 48.5 ms | 1,423 B |
| $n=64, k=32$ | 64 KiB | 9.3 ms | 0.169 ms | 4.2 ms | 1,423 B |
| $n=64, k=32$ | 256 KiB | 23.8 ms | 0.140 ms | 11.9 ms | 1,423 B |
| $n=64, k=32$ | 1 MiB | 88.0 ms | 0.145 ms | 42.6 ms | 1,423 B |
| $n=64, k=32$ | 4 MiB | 357.1 ms | 0.189 ms | 183.7 ms | 1,423 B |

A 256 KiB entity now completes an entire commit-lattice-materialize round trip in under
10 ms at the implementation default — down from roughly three-quarters of a second — and a
4 MiB entity in about an eighth of a second. The optimization changed no protocol byte:
the same commitment records, the same shard roots, the same sealed keys.

**The LATTICE phase is constant.** Across a 64× range of entity size and an 8× range of
$n$, it stays under 0.2 ms in every configuration (0.14–0.19 ms this run; 0.14–0.28 ms
across all recorded runs), while the sealed key stays byte-identical at 1,423. The timing
varies with host noise; the size does not vary at all. This is the paper's central
structural claim — that the sender→receiver path is $O(1)$ in entity size — observed
directly rather than argued, and it is the one headline claim these measurements actually
settle.

**Where the time goes.** Decomposing COMMIT on a 256 KiB entity, before and after the
§6.5 optimization:

| Component | $n=8, k=4$ before | $n=8, k=4$ after | $n=64, k=32$ before | $n=64, k=32$ after |
|-----------|-----------:|-----------:|-------------:|-------------:|
| Erasure encoding | 444.9 ms (99.3%) | 2.4 ms (50.6%) | 3,242.1 ms (99.9%) | 21.0 ms (88.5%) |
| AEAD encryption, all shards | 0.53 ms | 0.48 ms | 1.16 ms | 0.97 ms |
| Shard hashing (canonical lane) | 1.47 ms | 1.17 ms | 1.62 ms | 1.26 ms |
| ML-DSA-65 signature | 1.05 ms | 0.70 ms | 0.70 ms | 0.51 ms |
| **Cryptography, total** | **0.7%** | **49.4%** | **0.1%** | **11.5%** |

Read the after-columns carefully, because the percentages invert without the underlying
facts changing. Cryptography did not get more expensive — its absolute cost is essentially
unchanged (about 2.3 ms at either parameter set) — the coder got 100× cheaper, so at the
implementation default the commit is now split roughly evenly between the coding layer and
cryptography, and at the cost-model default the coder still dominates because its cost
scales with $n$ while the crypto is fixed-plus-symmetric.

Two conclusions survive the optimization intact, and one sharpens. First, the
*post-quantum asymmetric* operations remain a rounding error: the ML-DSA-65 signature is
0.5–0.7 ms per entity, paid once, and everything else in the crypto rows is symmetric work
(SHA-3, XChaCha20-Poly1305) that any transfer protocol pays. Trading away post-quantum
security for performance remains a bad trade at every measured configuration. Second, the
coder is still the right place for further optimization at large $n$ — a SIMD kernel is
the remaining lever (§6.5, §12 OQ8). What sharpens: at the implementation default, further
coder work now buys at most 2× end-to-end, because Amdahl's law has arrived — the next
bottleneck is the C-library crypto itself, which is to say the implementation is
approaching the floor set by the primitives rather than by the interpreter.

### 7.4 Artifact Sizes

Exact, not approximate:

| Artifact | Size | Composition |
|----------|-----:|-------------|
| Sealed lattice key (unrestricted policy) | **1,423 B** | 1,088 KEM ciphertext + 24 nonce + 16 tag + 295 encrypted payload |
| Sealed lattice key (time-limited policy, all fields) | 1,495 B | Growth is in the policy, not the entity |
| Constant envelope overhead | 1,128 B | Independent of payload |
| Commitment record | **5,824 B** | 3,309 signature + 1,952 verification key + 473 signable payload + framing |
| — signature + verification key share | **90.3%** | The record is essentially post-quantum key material |
| EntityID | 73 chars | `sha3-256:` + 64 hex digits |
| ML-KEM-768 ek / dk / ciphertext | 1,184 / 2,400 / 1,088 B | FIPS 203 |
| ML-DSA-65 vk / sk / signature | 1,952 / 4,032 / 3,309 B | FIPS 204 |

The sealed key was measured at 1,423 bytes for both a 1 KiB and a 256 KiB entity — identical
to the byte. §6.4's $O(1)$ row is now a measurement rather than an assertion.

Note the asymmetry these numbers reveal: the *commitment record* (5,824 B) is four times
the size of the *sealed key* (1,423 B). The record is fetched once per materialization from
the log; the sealed key crosses the sender→receiver link. LTP's constant-size claim applies
to the link that the design is trying to relieve, not to every artifact in the system.

### 7.5 Threats to Validity

We would rather state these than have a reviewer find them.

1. **The coding kernel still has headroom.** These figures use the conformant
   table-driven coder (§6.5), which runs its byte kernel at 0.65–0.85 GiB/s — within an
   order of magnitude of, but not at, what a SIMD field-arithmetic kernel (ISA-L, GFNI)
   achieves on the same matrix. Absolute wall-clock is therefore still a floor on
   achievable performance, now by roughly one order of magnitude rather than two-plus
   (§12, Open Question 8). The optional `zfec` backend remains **systematic** and
   therefore non-conformant (§2.1.1) — it is not a drop-in accelerator, and mixing the
   two within a deployment breaks interoperability.

2. **No network.** All parties are in one process. Every claim in §6.4 that depends on
   $\alpha$ — the parallelism efficiency of $k$ concurrent shard fetches — is untouched by
   these measurements. $\alpha$ remains the single most important unmeasured parameter in
   the paper, and the one a deployment must measure for itself.

3. **Single host, single configuration.** One machine, one Python version, one CPU
   architecture, no NUMA effects, no I/O contention, no competing tenants. Medians hide
   tail latency, and tail latency is what the straggler analysis in §6.4 says will dominate
   real materialization.

4. **Small entities.** The largest measured entity is 256 KiB, chosen so the pure-Python
   coder finishes in reasonable time. The scaling is linear and well-behaved across the
   measured range, but LTP's motivating use cases involve gigabyte entities, which we have
   not measured end to end.

5. **Simulated regions.** The 4 "regions" are labels on in-process nodes. They exercise the
   placement logic and nothing about geography — which is the entire mechanism §6.2 relies
   on.

What this section establishes: the $O(1)$ sender→receiver invariant, the artifact sizes, the
relative cost of every component, and the scaling laws in $n$ and $k$. What it does not
establish: that LTP is faster than direct transfer for any real deployment. That claim
still rests on the cost model, and the cost model still rests on $\alpha$.

---

## 8. Reference Implementation and Deployment Status

Sections 1–6 specify a protocol. This section describes what has actually been built, what
is deployed, and where the two diverge from the specification above. A reader evaluating
LTP should weigh this section at least as heavily as the security proofs: a protocol is a
claim, and an implementation is the evidence.

### 8.1 What Is Implemented

The reference implementation is a Python SDK of roughly 48,000 lines across 242 modules,
plus a Solidity contract suite and a corridor wire codec. The three-phase protocol of §2 is
a small fraction of it. The following inventory is included because the surrounding
subsystems materially affect the trust analysis, and a reader who knows only §§1–6 would be
surprised by several of them.

| Subsystem | Scale | Status relative to this paper |
|-----------|-------|-------------------------------|
| Core three-phase protocol, erasure coding, shard encryption, keys | — | Specified in §§1–2 |
| CT-style Merkle log with STHs, inclusion and consistency proofs | ~1,000 LOC | Specified in §5.1.4 |
| **DAG-BFT consensus engine** (Mysticeti-inspired; $f=(n-1)/3$, $2f+1$ quorums) | ~1,600 LOC | **Not specified here.** §5.1.2 argues LTP *does not require* BFT consensus; that remains true of the storage layer, but the SDK ships an engine for deployments that want ordered commitment. |
| **Multi-VM execution layer**, committee formation, DKG with threshold BLS | ~5,400 LOC | **Not specified here.** |
| **Corridor** (`LTP-corridor-v1`) — attestation, DA SLA, DID, state anchors | ~2,100 LOC | §8.3 below; wire format deliberately non-normative in this paper |
| **L1↔L2 bridge** with fraud proofs, challenge games, SP1 + RISC Zero provers | ~3,000 LOC | §8.4 below |
| Node runtime: gossip, handshake, peer management, admission, audit scheduling | ~4,700 LOC | Operational surface for §5 |
| Enforcement: PDP, programmable slashing, VDF-backed audits, dispute resolution | ~1,500 LOC | §5.2's audit protocol, considerably extended |
| Compliance: FIPS provider, RBAC, geo-fencing, GDPR deletion proofs, SIEM, HSM | ~1,700 LOC | Referenced in §10.8's regulatory paragraph |
| Economics engine: three-phase issuance, vesting, slashing tiers, fee split | ~870 LOC | **Contradicts §5.5**, which declines to specify economics — see §8.6 |
| Federation, streaming, ZK (Pedersen, Sigma, FRI/STARK), storage backends, observability | ~7,800 LOC | Several correspond to items §12 still lists as open |

The gap between "the protocol in §§1–6" and "the system in the repository" is wide, and it
is deliberate on the implementation's side rather than an oversight on the paper's: LTP the
protocol is intended to be implementable without a consensus engine, a bridge, or a token.
But a reader should not infer from §§1–6 that the reference implementation is a thin
artifact, nor that the security analysis covers everything the SDK does. It does not.

### 8.2 Cryptographic Agility and the Composite Signature Mode

The implementation selects primitives through a `SecurityProfile`, which fixes the KEM,
signature scheme, and both hash lanes together:

| Profile | KEM | Signature | Canonical | Internal |
|---------|-----|-----------|-----------|----------|
| Level 3 (default) | ML-KEM-768 | ML-DSA-65 | SHA3-256 | BLAKE3-256 |
| Level 5 | ML-KEM-1024 | ML-DSA-87 | SHA-384 | BLAKE3-256 |
| CNSA 2.0 | ML-KEM-1024 | ML-DSA-87 | SHA-384 | SHA-384 |

Profiles are init-time only; changing one mid-process is not supported, because the sizes
are class-level constants that signed artifacts already depend on.

**Composite signatures — a correction to earlier claims.** Revisions through 0.2.0 asserted
that LTP contains "no X25519 or Ed25519." That statement was true of the core transfer path
and false of the codebase. The implementation ships an opt-in composite signature mode
following IETF `draft-ietf-lamps-pq-composite-sigs`, pairing **ML-DSA-65 with
Ed25519-SHA512**:

- Signing message: `Prefix ‖ Label ‖ uint16_be(len(ctx)) ‖ ctx ‖ SHA-512(M)`
- Sizes: 1,984-byte public key, 3,373-byte signature (3,309 + 64)
- **Both** components must verify independently for the signature to be accepted
- Selecting it emits an explicit warning that Ed25519 is not post-quantum

The correct characterization is therefore: the default configuration uses no classical
primitive, and a deployment may opt into a hybrid that adds a classical signature alongside
the post-quantum one. Because verification requires both, the composite mode is *no weaker*
than ML-DSA-65 alone against a quantum adversary — an attacker must still forge ML-DSA-65 —
but it is also not stronger against one. Its purpose is transition-period assurance against
the possibility of an undiscovered weakness in the lattice assumptions, which is the same
rationale NIST and CRYPTREC give for hybrid KEMs (§10.8). The corresponding hybrid *KEM*
does not exist in LTP; that remains future work.

### 8.3 The Corridor: Cross-Chain Attestation

The **corridor** is LTP's third independently versioned surface, alongside the SDK and the
contracts. §10.9 compares its quorum design to Data Availability Sampling without ever
saying what it is; this subsection repairs that.

A corridor carries attestations that a commitment record has been anchored, from an LTP
deployment to an external chain (in the reference deployment, the SUWAPPU DAG L1). Its wire
format, `LTP-corridor-v1`, is mirrored byte-for-byte between the Python SDK and an
independent Rust implementation — currently LTP's only instance of the second-implementation
discipline §5.4.1.2 argues for.

| Parameter | Value |
|-----------|-------|
| Attestation quorum | **7-of-9** super-nodes |
| Signature scheme | BLS12-381 aggregate — 96-byte G2 signatures, 48-byte G1 public keys |
| Domain digest | SHA3-256 over `H(len(tag) ‖ tag ‖ data)`, length as `uint32` big-endian |
| Corridor BLS DST | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` |

**Two distinct BLS hash-to-curve domain separation tags exist** in the system: the corridor's
`…_SSWU_RO_NUL_` above, and `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` for general LTP
BLS signing. Threshold DKG signing deliberately reuses the general POP tag so that a
combined threshold signature verifies under the ordinary verification path; DKG's separation
from other message types is achieved by a message-prefix domain tag, not by a distinct DST.

A signature produced under the corridor DST will not verify under the general one, or vice
versa. This is correct design — domain separation is the point — but it is an
interoperability hazard worth stating plainly: the corridor DST must match the Rust
implementation's constant byte-for-byte, and a mismatch produces silent verification failure
rather than a clear error. Deployments SHOULD treat cross-implementation DST agreement as a
startup assertion rather than a code-review convention.

The 7-of-9 quorum's safety property — any two valid attestations share at least one honest
signer given at most 4 Byzantine super-nodes — is machine-checked as `corridor_safety`
(§3.3.8). Note the **asymmetry** that §10.9 omits: safety tolerates 4 Byzantine nodes, but
liveness tolerates only 2 unavailable ones ($9 - 7 = 2$). A corridor with 3 nodes offline
cannot produce attestations at all, even though it remains safe. Deployments should size
availability planning against the liveness bound, not the safety bound.

**The corridor is not post-quantum** (§3.4). Its BLS12-381 aggregate signatures are
pairing-based.

### 8.4 On-Chain Anchoring and Its Trust Assumptions

This subsection states trust assumptions that the paper's framing —
"security is cryptographic, not perimeter-based" — does not cover, and which a reader
would otherwise reasonably assume were discharged.

The contract suite comprises an upgradeable anchor registry (`LTPAnchorRegistry`, UUPS
proxy), an optimistic bridge challenge contract, a ZK bridge verifier, an N-of-M multisig,
a governance contract, and a bridge event emitter.

**The following are true of the deployed system as of this writing:**

1. **The registry does not verify the corridor's BLS aggregate on-chain.** It trusts the
   relayer to submit valid anchors. This is a deliberate "thin on-chain, thick off-chain"
   architecture, tracked as an accepted internal audit finding, not an oversight — but it
   means the on-chain record's integrity rests on the relayer and the off-chain quorum, not
   on the chain's own verification.

2. **The deployed ZK bridge verifier runs in a simulated mode.** Its fast-path verification
   accepts any value satisfying a hash relation whose inputs are entirely caller-chosen.
   This is not weak cryptography; it is the absence of a cryptographic check. It exists
   because **no audited production-grade ZK verifier for ML-DSA/lattice signatures exists in
   the industry today** — there is currently no real verifier to switch to. Source-level
   guards to prevent production use of this mode exist but are not yet deployed. Instant
   finality via this path MUST NOT be relied upon for anything of value.

3. **The optimistic path performs dispute *arbitration*, not fraud-proof *verification*.**
   Challenges resolve by administrator decision, designated arbiter, or time decay. The
   "fraud proof" is a bond-backed accusation adjudicated by parties, not a cryptographic
   object checked by the contract.

4. **Operator and challenger bonds are currently zero** on the live deployments, so
   slashing has no economic effect today. This is presumably intentional for testnet, and
   it means the economic-deterrent arguments of §5.2.2 are not currently operative on-chain.

None of this affects Theorems 3–8, which concern the transfer path and assume only an
append-only log. It affects a different question — *what does an on-chain anchor prove?* —
and the honest answer today is: that a relayer asserted an anchor, backed by an off-chain
quorum whose signatures the chain does not check. Deployments requiring on-chain
verification of the attestation itself should treat that as unbuilt. The full analysis is
in `docs/BRIDGE_TRUST_MODEL.md`, which is the most adversarial document in the repository
and should be read before relying on the settlement surface.

### 8.5 Deployment Status

§9's comparison table calls LTP a "research prototype." That is right about maturity and
wrong about deployment, which is worth stating precisely.

| Chain | Registry version | Bridge contracts | Status |
|-------|-----------------|------------------|--------|
| SUWAPPU Testnet (chain ID 103115120) | v5 | Deployed | Live |
| Base Sepolia (chain ID 84532) | v6 | Deployed | Live |

Roughly 53 on-chain transactions across both chains, all successful. Contract administration
has been irreversibly transferred to a timelock on both. **No mainnet deployment exists**,
timelock delays are set to 60 seconds (testnet values; production target is 24–48 hours),
and the multisig is 2-of-2. Governance hardening — higher multisig thresholds, a 24-hour
minimum timelock, a mainnet deploy script that refuses testnet chain IDs, and the production
lock for the ZK verifier — exists in source and is pending deployment.

So: deployed and exercised on testnets, with testnet-grade governance parameters and the
disclosures in §8.4. Not production, and not claimed as such.

### 8.6 Where the Implementation Diverges From This Paper

Consolidated, so a reader does not have to reconstruct it:

| Paper says | Implementation does | Resolution |
|-----------|--------------------|-----------|
| Default erasure parameters $n=64, k=32$ (§6.4, Appendix A) | Defaults to $n=8, k=4$ | Both are valid; $(64,32)$ is the *cost-model* default used for analysis, $(8,4)$ the *runtime* default (originally chosen for tractable encode time under the scalar coder; with the §6.5 kernel both are fast, and the choice now turns on the availability model of §5.4.1 rather than on encode cost). §7.2 measures both. A deployment should choose $(n,k,r)$ from its own availability target (§5.4.1), not from either default. |
| Default replication $r=3$ (§6.4) | Defaults to $r=2$ | Same: $\rho = nr/k$ is 6 at the paper's defaults, 4 at the implementation's. Cost-model conclusions are stated in terms of $\rho$ and hold for either. |
| §5.5 declines to specify economics | Ships a complete tokenomics engine with ~30 hard-coded parameters, and carries two conflicting sets of stake and penalty constants | Genuine divergence. §5.5's interface-only stance remains the protocol's position; the engine is one deployment's instantiation. A separate design document supersedes it with a stablecoin-collateral model that assumes no native token. |
| §5.1.2 "requires no consensus protocol" | Ships a DAG-BFT engine | Not a contradiction — the storage layer requires no consensus, and the engine serves deployments that additionally want ordered execution. But §5.1.2 should not be read as "LTP has no consensus code." |
| Sealed key ~1,300 B | 1,423 B | Corrected throughout this revision (§7.4). |
| Commitment record ≈3.5 KB | 5,824 B | Corrected (§2.1.3, §7.4); the earlier figure omitted the inline verification key. |
| EntityID uses BLAKE3-256 | Uses SHA3-256 (canonical lane) | Corrected throughout this revision; the dual-lane architecture is now specified in §1.3. |
| "No X25519 or Ed25519" | Opt-in composite mode includes Ed25519 | Corrected in §8.2 and §3.4. |
| The `eval` label `"vandermonde-powers-of-0x02"` | Evaluation points are $\alpha_i = i+1$ | Known and frozen: the label is hashed into signed records and cannot be corrected without invalidating them. Conformance is defined by §2.1.1, never by parsing the label. |
| §2.2.1 access policy is enforced at MATERIALIZE | **Enforced as of v0.4.1** — window + count for every type, fail-closed on unknown types, atomic slot reservation, rollback on failed attempts | Resolved (was: not enforced at all, disclosed in 0.3.0). Residual scope limits are documented in §2.2.1: enforcement is receiver-side and its count state is in-memory per protocol instance. The §3.3.8 replay finding is now partially mitigated within those limits. |
| §2.1.2 / §5.4.1.1 require replicas across distinct failure domains | Placement hashes `(entity_id, index, replica)` and never consults `node.region` | Genuine. A region-diversity *checker* exists (`check_cross_region_placement`) but is a read-only diagnostic, not a placement constraint. The availability figures of §5.4.1.1 assume a constraint the placement algorithm does not enforce, so a deployment must verify diversity out of band. Geo-fencing exists but is a jurisdiction allow-list, not a diversity rule. |
| Shared secrets and retired keys are "zeroized" (§2.2.2, Appendix B #26, #31) | Drops the reference (`del`) rather than overwriting the buffer | Real but lesser. Python cannot reliably zero an immutable `bytes` object; discharging this properly requires a mutable buffer or an HSM-backed path. The forward-secrecy argument of §2.2.2 is correspondingly weaker than stated against an attacker who can read process memory after use. |
| `ON_CHAIN_COMMITMENT_BYTES = 1600` | Matches no real field layout | A machine-checked negative result: the Lean development proves this constant unsatisfiable for any well-formed envelope and traces its provenance to a mislabeled ML-KEM-1024 ciphertext with the aggregate signature omitted. Real totals are 1,216 B (ML-KEM-768) and 1,696 B (ML-KEM-1024). The corresponding strict-total assertion is a dead forward-compatibility stub. |

We publish this table rather than quietly reconciling the two, because the divergences are
themselves evidence about the protocol's maturity, and because a reader comparing the paper
against the repository will find them anyway.

---

## 9. Comparison with Existing Approaches

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
| Forward secrecy (PQ) | TLS layer | No | No | No | No | **Yes (ML-KEM; ephemeral materialization)** |
| PQ signatures on commitments | No | No | No | No | No | **Yes (ML-DSA)** |
| ZK privacy mode | No | No | No | No | No | **Yes†** |
| Survives sender going offline | No | If pinned | If seeded | **Yes** | **Yes** | **Yes** |
| Receiver proximity optimization | No | Partial | Partial | No | Partial | **Yes** |
| Deterministic shard placement | No | DHT | DHT peers | Server-assigned | Server-assigned | **Consistent hash** |
| Append-only audit log | No | No | No | No | No | **Yes** |
| **Protocol complexity** | Low | Medium | Low | High | High | **Very High** |
| **Production deployment maturity** | Ubiquitous | Production | Ubiquitous | Limited | Production | **Research prototype — testnet only (§8.5)** |
| **Single-transfer overhead** | Minimal | Low | Low | Moderate | Moderate | **High (commit + lattice + materialize round-trips)** |

† ZK privacy mode uses Groth16 over BLS12-381, which is **not post-quantum safe** (broken by
Shor's algorithm). Standard mode provides full post-quantum security. ZK mode MUST NOT be
used under a quantum-adversary threat model. See §3.2.4 and the Abstract warning.

**Reading guide:** LTP's unique cells (only LTP has "Yes") are: O(1) sender→receiver path,
receiver-bound capabilities, per-message PQ forward secrecy, PQ-signed append-only audit log,
and ZK privacy mode (standard mode only is fully PQ-safe). The encrypted storage, erasure coding, and capability-based access that
LTP shares with Tahoe-LAFS and Storj are acknowledged as prior art — see Section 10. The final
three rows reflect dimensions where LTP is weakest: LTP's three-phase design introduces
significant protocol complexity compared to point-to-point alternatives; it is deployed on
two testnets with testnet-grade governance parameters and no mainnet deployment (§8.5); and
for single-receiver, small-payload transfers, the commit+lattice+materialize overhead
dominates (see §6.4).

**A caution about this table.** Every row is a property LTP was designed to have, compared
against systems that were designed for different goals, in a table written by LTP's authors.
That is a structurally biased instrument, and the bias runs one way. Tahoe-LAFS and Storj
score "No" on the O(1) sender→receiver row because they are storage systems that never set
out to relocate a transfer bottleneck; IPFS scores "No" on client-side encryption because
public content-addressing is its design goal, not an oversight. The rows LTP wins are the
rows LTP chose. Readers should weight the last three rows — complexity, maturity, and
single-transfer overhead — more heavily than the rest, because those are the ones where the
table's author had an incentive to look away.

### Erasure Coding Durability Comparison

Concrete durability measurements from production systems, measured in "nines" (e.g., 99.99% = four nines):

| System | Parameters | Expansion Factor | Durability (10% churn) | Repair Bandwidth |
|--------|-----------|:----------------:|:---------------------:|:----------------:|
| **LTP** | k=4, n=8, r=3 | 6x (ρ = nr/k) | 99.9999999% (theory, independent) | O(k) per shard |
| **Storj** | k=29, n=80 | 2.76x | 11 nines | ~55% of replication |
| **Storj** | k=16, n=32 | 2x | Higher than 10x replication | — |
| **Filecoin** | RS + PoRep | 3–10x | Cryptographic proof (PoSt) | Full sector re-seal |
| **Tahoe-LAFS** | k=3, n=10 | 3.33x | Provider-independent | Full re-encode |

Data sourced from Storj file redundancy documentation [storj.dev/learn/concepts/file-redundancy] and Filecoin specification. Expansion factors in this table are **total storage expansion**: LTP's figure is $\rho = nr/k$ (erasure expansion $n/k$ × replication $r$, per §6.4), directly comparable to Storj's 2.76x total expansion. LTP's theoretical availability assumes independent node failures (§5.4.1); correlated failure model in §5.4.1.1 provides more conservative estimates.

---

## 10. Related Work and Prior Art

LTP is not built in a vacuum. Its design draws from, recombines, and extends ideas pioneered by
decades of work in distributed systems, cryptography, and peer-to-peer networking. This section
honestly acknowledges the lineage and articulates what — if anything — LTP contributes beyond
its predecessors.

### 10.1 Content-Addressed Storage

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

### 10.2 Erasure-Coded Distributed Storage

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
This addresses the data availability problem that LTP's Section 12 (Open Questions) leaves open.

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

### 10.3 Append-Only Commitment Logs

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
deliberately does not specify a consensus mechanism (Section 12, Resolved Questions) — it could be
a blockchain, a CT-style Merkle log, or a permissioned ledger. The immutability guarantee
(Section 4) relies only on the append-only property and hash chaining, not on a specific
consensus protocol.

**Where LTP diverges:** LTP's commitment log is minimal by design: it stores only a Merkle root
of encrypted shard hashes, the entity_id, encoding params, and an ML-DSA signature. No shard
IDs, no content, no CEK. This is a tighter interface than most blockchain-based systems, which
tend to store more metadata. The log's purpose is *attestation* ("this entity was committed by
this sender at this time"), not general-purpose state management.

### 10.4 Capability-Based Security

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

**The closest precedent for KEM-bound envelopes is Signal's Sealed Sender (2018)** [34],
which encrypts an envelope (sender certificate + ciphertext) under a key derived from an
ephemeral sender key and the recipient's long-term identity key, so only the intended
recipient can open it. This is the same primitive shape LTP's sealed lattice key uses —
recipient-bound envelope encryption — applied to a different problem. Sealed Sender binds
a *live message* to hide sender metadata from a server relaying it in real time; the
sender and receiver are both online, or the message queues briefly for delivery. LTP binds
a *capability to reconstruct out-of-band data* that may sit uncollected for an arbitrary
period (subject to shard TTL, §5.4.4) while the entity itself lives in erasure-coded storage
rather than in the envelope. The cryptographic mechanism is not new; applying it to
asynchronous, capability-based storage retrieval — where the "message" is a pointer plus a
key rather than the payload — is the specific combination in §10.7 point 2. Note also that
Sealed Sender's binding is classical (X25519/Curve25519); LTP's is the post-quantum
instance of the same idea (ML-KEM-768), inheriting the KEM ciphertext-binding caveats
discussed in §3.3 [21, 27, 28] that classical DH-based sealing does not have.

### 10.5 Peer-to-Peer Content Distribution

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

### 10.6 Hybrid and Convergent Systems

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

**SUWAPPU DAG L1 + SUWAPPU-DB (2026)** [18][19] is the companion deployment surface for
LTP in the SUWAPPU stack. SUWAPPU DAG provides certificate-DAG ordering, validator-ring
consensus, and corridor super-node attestation. SUWAPPU-DB provides the canonical
state substrate below that chain: capability-gated mutation, dual EVM/Move
projections, OCC block execution, state-tree roots, anchor dispatch, recovery
replay, and L2 state sync. LTP remains the transfer and attestation layer; it
does not mutate the SUWAPPU-DB state substrate directly.

### 10.7 What LTP Contributes

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
   inline policy in a constant-size token is, to our knowledge, not present in prior
   systems. The individual technique of KEM-bound envelope encryption is not new — Sealed
   Sender (§10.4) [34] establishes it for live messaging — but Sealed Sender has no
   capability semantics, no inline access policy, and nothing analogous to constant-size
   erasure-coded storage retrieval; it solves a different problem (hiding sender metadata
   from a relay) with the same cryptographic shape. The claim here is narrower than
   "receiver-bound envelopes are new": it is that this specific bundle, applied to
   asynchronous capability-based data retrieval, is.

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

### 10.8 International Post-Quantum Standardization Landscape

LTP's post-quantum cryptography is aligned with NIST FIPS 203/204, but PQC standardization
is a global effort. The following national programs are developing or evaluating post-quantum
cryptographic standards, each of which may influence regional adoption requirements:

| Country | Body | Program | Status (2025) | Relevance to LTP |
|---------|------|---------|---------------|-----------------|
| **USA** | NIST | FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) | Standards final (Aug 2024); HQC selected as 2nd KEM | Primary alignment target |
| **China** | CACR (中国密码学会) [33] | Chinese PQC Algorithm Competition | Algorithm collection phase; openHiTLS [32] provides ML-KEM/ML-DSA | Critical for SUWAPPU L1 deployment |
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

**No hybrid PQ/classical KEM mode.** NIST and CRYPTREC currently recommend hybrid
constructions (e.g., ML-KEM combined with X25519) during the post-quantum transition, as
insurance against undiscovered weaknesses in the newer lattice assumptions; NIST IR 8547
[29] (the PQC transition roadmap) schedules deprecation of quantum-vulnerable algorithms around
2030 and removal by 2035, and deployed practice has converged on hybrids such as
X25519MLKEM768 in TLS 1.3. LTP v1 is
PQ-only by design — there is no classical fallback, which removes the downgrade attack
surface at the cost of forgoing the hybrid hedge. This is a deliberate trade-off. A hybrid
profile is possible via the crypto-agility mechanism above and is future work; a natural
candidate is a combined KEM in the style of X-Wing [30] (X25519 + ML-KEM-768 with a single
joint shared secret), which would slot into the existing `algorithm` negotiation without
changing the sealed-key envelope shape.

**Regulatory considerations.** Immutability can appear to conflict with deletion mandates
(e.g., GDPR/CCPA erasure rights). LTP stores only encrypted shards; destroying the CEK and
any outstanding lattice keys renders committed data permanently unreadable
(crypto-shredding), which is the deployment-level deletion mechanism. A full
multi-jurisdiction compliance matrix is future work, and this paper does not constitute a
compliance claim.

### 10.9 Data Availability Sampling and Verifiable Erasure-Coded Commitments

**Data Availability Sampling (DAS)** [35] addresses a structurally similar problem from a
different direction: a block proposer erasure-codes a block's data and publishes a compact
commitment (a Merkle or polynomial commitment) to it; light clients then verify the *data
is available* by sampling a few random positions, without downloading the block. Ethereum's
Danksharding roadmap [36] is the deployed instance of this idea, and "Foundations of Data
Availability Sampling" [37] gives it a general treatment: any linear erasure code, any
polynomial or vector commitment, adaptive sampling.

**What LTP's COMMIT phase and corridor quorum share with DAS:** both erasure-code a payload,
publish a small commitment (LTP: the Merkle root of encrypted shard hashes plus an ML-DSA
signature; DAS: a polynomial or vector commitment), and let a party verify availability
without holding the full data (LTP: corridor super-nodes attesting 7-of-9, §8.3; DAS: light
clients sampling positions). The corridor quorum's safety argument — two honest attestations
must intersect, formalized in `corridor_safety` (`formal/lean/Ltp/Quorum.lean`) — is the
same counting-argument shape used to reason about sampling-based availability guarantees.

**Where LTP diverges:** DAS verifies availability for a *permissionless light client* that
trusts no one and samples probabilistically; the guarantee is statistical (enough honest
samples across enough honest light clients). LTP's corridor quorum is a *fixed committee*
of 7-of-9 named super-nodes attesting deterministically, not a sampling protocol — it trades
DAS's trustlessness for a stronger per-attestation guarantee at a fixed committee size
(§8.3, and the machine-checked bound in `corridor_safety`/`corridor_liveness`). DAS also
targets a different consumer: light clients verifying a *blockchain's* data availability,
not a specific receiver materializing a specific entity. LTP's MATERIALIZE phase reconstructs
the actual content for one designated receiver holding a sealed key; DAS never reconstructs
the block for anyone in particular — availability, not delivery, is the guarantee.

We do not claim LTP's quorum design is superior to DAS for the problem DAS solves (base-layer
blockchain scaling); it solves a narrower problem under a different trust model. The
resemblance is worth stating because both traditions arrived independently at "erasure-code,
commit small, verify without downloading everything" as the right shape for availability
guarantees — DAS from the blockchain-scaling literature, LTP from the transfer-protocol
framing in §10.7.


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

[18] Suwappu Labs, "SUWAPPU DAG Layer 1," companion implementation and academic paper, 2026. https://github.com/Suwappu-Labs/suwappu-dag

[19] Suwappu Labs, "SUWAPPU-DB: A Polymorphic Dual-VM State Substrate with Capability-Gated Mutation," companion implementation, 2026. https://github.com/Suwappu-Labs/suwappu-db

[20] J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. M. Schanck, P. Schwabe, G. Seiler, D. Stehle, "CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM," IEEE EuroS&P, 2018. IACR ePrint 2017/634. https://eprint.iacr.org/2017/634

[21] K. Bhargavan et al., "Formal Verification of the PQXDH Post-Quantum Key Agreement Protocol for End-to-End Secure Messaging," USENIX Security, 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan

[22] R. J. McEliece, D. V. Sarwate, "On Sharing Secrets and Reed-Solomon Codes," Communications of the ACM, 24(9), 1981. https://doi.org/10.1145/358746.358762

[23] T. Perrin, "The Noise Protocol Framework," 2018. https://noiseprotocol.org/noise.html

[24] National Institute of Standards and Technology, "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS 203, Aug. 2024. https://doi.org/10.6028/NIST.FIPS.203

[25] National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard," FIPS 204, Aug. 2024. https://doi.org/10.6028/NIST.FIPS.204

[26] R. Barnes, K. Bhargavan, B. Lipp, C. A. Wood, "Hybrid Public Key Encryption," RFC 9180, IETF, Feb. 2022. https://www.rfc-editor.org/rfc/rfc9180.html

[27] C. Cremers, A. Dax, N. Medinger, "Keeping Up with the KEMs: Stronger Security Notions for KEMs and Automated Analysis of KEM-Based Protocols," IACR ePrint 2023/1933. https://eprint.iacr.org/2023/1933

[28] S. Schmieg, "Unbindable Kemmy Schmidt: ML-KEM Is Neither MAL-BIND-K-CT nor MAL-BIND-K-PK," IACR ePrint 2024/523. https://eprint.iacr.org/2024/523

[29] National Institute of Standards and Technology, "Transition to Post-Quantum Cryptography Standards," NIST IR 8547 (Initial Public Draft), Nov. 2024. https://csrc.nist.gov/pubs/ir/8547/ipd

[30] M. Barbosa, D. Connolly, J. Diogo Duarte, A. Kaiser, P. Schwabe, K. Varner, B. Westerbaan, "X-Wing: The Hybrid KEM You've Been Looking For," IACR ePrint 2024/039. https://eprint.iacr.org/2024/039

[31] B. Lipp, B. Blanchet, K. Bhargavan, "A Mechanised Cryptographic Proof of the WireGuard Virtual Private Network Protocol," IEEE EuroS&P, 2019. https://inria.hal.science/hal-02100345v3/document

[32] openHiTLS Community, "openHiTLS: Open-Source TLS Library with ML-KEM/ML-DSA Support," 2024. https://github.com/openHiTLS/openHiTLS

[33] Chinese Association for Cryptologic Research (中国密码学会), "Post-Quantum Cryptography Algorithm Competition," 2023. http://www.cacrnet.org.cn/

[34] Signal Foundation, "Technology Preview: Sealed Sender for Signal," Oct. 2018. https://signal.org/blog/sealed-sender/

[35] M. Al-Bassam, A. Sonnino, V. Buterin, "Fraud and Data Availability Proofs: Maximising Light Client Security and Scaling Blockchains with Dishonest Majorities," arXiv:1809.09044, 2018.

[36] Ethereum Foundation, "Danksharding," Ethereum Roadmap documentation, 2024. https://ethereum.org/roadmap/danksharding/

[37] M. Hall-Andersen, M. Simkin, B. Wagner, "Foundations of Data Availability Sampling," IACR ePrint 2023/1079. https://eprint.iacr.org/2023/1079

---

## 11. Use Cases

Each use case below states the parameters it implies and whether the break-even analysis of
§6.4 actually works out for it. A use case that does not clear $N > \rho$ receivers is not
one LTP improves, and we say so.

### 11.1 Large File Fan-Out

*The canonical case — the one LTP is designed for.*

A 50 GB dataset is committed once. Any number of receivers materialize it, each receiving a
1,423-byte sealed lattice key. Each receiver's materialization time is dominated by local
shard fetching from nearby nodes, not by the sender's bandwidth or availability.

| | Direct transfer | LTP |
|---|---|---|
| Sender upload | $50\text{ GB} \times N$ | $50\text{ GB} \times \rho$ (once) |
| Sender→receiver path | $50\text{ GB} \times N$ | $1{,}423\text{ B} \times N$ |
| At $N = 100$, $\rho = 6$ | 5,000 GB | 300 GB + 142 KB |

**Fit: strong.** Break-even at $N > 6$; at $N = 100$ the sender moves $16\times$ less data
and can go offline immediately after commit. Suggested parameters: $n=32, k=16, r=3$ across
$\geq 3$ regions, which gives $\rho = 6$ and tolerates the loss of 16 shard indices.

### 11.2 Immutable Audit Trail

A compliance system verifies: "Entity X was committed by Sender A at time T, and its
commitment record is at position $i$ of the log." The ML-DSA-65 signature makes this
non-repudiable (Theorem 6), and the record's inline verification key means an auditor who
holds no prior state about Sender A can still check it (§2.1.3).

**Fit: strong, for a reason unrelated to bandwidth.** The value here is the append-only log
and the signature, not the $O(1)$ path — this use case would work with $N = 1$. Note the
limit of the claim: the log proves a commitment *existed*, not that any receiver ever
materialized it, and if shards are evicted past their TTL the record survives while the
content does not (§5.4.4). Deployments needing "the content is still retrievable" must fund
storage renewal, not just retain the record.

### 11.3 Secure Messaging

A message is committed and lattice-linked; the lattice key serves as the notification. The
content never traverses the sender→receiver path as a readable payload, and an intercepted
lattice key is opaque without the receiver's decapsulation key.

**Fit: weak for typical messaging, and we would not recommend LTP for it.** Messages are
small and usually have one recipient, so $N = 1 < \rho$: LTP moves *more* total data than
sending the message directly, adds three round trips, and adds a 1,423-byte key to a payload
that may be smaller than the key. It also inherits the low-entropy confidentiality problem —
a short message drawn from a predictable set is fingerprinted by its EntityID unless ZK mode
is used (§3.3.3), and ZK mode is not post-quantum (§3.4). The case becomes reasonable only
for large attachments fanned out to many recipients, which is §11.1 wearing different
clothes. Purpose-built protocols (Signal, MLS) are the right tool for messaging.

### 11.4 State Synchronization

Two distributed systems synchronize by exchanging lattice keys, each materializing the
other's state from the commitment network.

**Fit: conditional on committing deltas rather than snapshots.** Because LTP does not
deduplicate (§1.2), committing a full state snapshot on every sync pays $D\rho$ storage
*per sync* — the version-control anti-pattern of §6.4's deduplication table. The workable
shape is to compute the delta at the application layer, commit the delta as its own entity,
and chain it to its predecessor via the version chain of §4.2. Done that way, $D$ is the
delta size and the economics work; done naively, storage grows without bound.

In the SUWAPPU stack, the state being synchronized is the SUWAPPU-DB state root produced
after SUWAPPU DAG ordering. The flow is one-directional: DAG-ordered blocks update
SUWAPPU-DB through its `suwappudb-bridge` capability gate; SUWAPPU-DB emits state roots and
anchors; LTP corridor super-nodes attest those anchors; receivers materialize
committed snapshots or deltas with lattice keys. A lattice key can authorize
materialization, but it cannot directly mutate SUWAPPU-DB state.

In the SUWAPPU stack, the state being synchronized is the SUWAPPU-DB state root produced
after SUWAPPU DAG ordering. The flow is one-directional: DAG-ordered blocks update
SUWAPPU-DB through its `suwappudb-bridge` capability gate; SUWAPPU-DB emits state roots and
anchors; LTP corridor super-nodes attest those anchors; receivers materialize
committed snapshots or deltas with lattice keys. A lattice key can authorize
materialization, but it cannot directly mutate SUWAPPU-DB state.

### 11.5 High-Latency Link Optimization

*Moved to [Appendix A](#appendix-a-high-latency-link-optimization-thought-experiment) to
maintain the technical focus of the main document. The two properties it demonstrates —
sender-independence and geographic optimization — are the same properties illustrated by
the grounded scenarios in §§11.1–11.4.*

### 11.6 Where LTP Is the Wrong Tool

A protocol paper that lists only favourable use cases is not being useful. These are cases
where LTP is a worse choice than the obvious alternative, and the reason is structural
rather than a matter of tuning.

| Workload | Why LTP is wrong | Use instead |
|----------|------------------|-------------|
| **Single-recipient transfer of a small payload** | $N=1 < \rho$, so total bandwidth is $(\rho+1)\times$ direct, and three phases replace one. The sealed key alone may exceed the payload. | Direct transfer over TLS |
| **Low-latency request/response** | The three phases serialize: commit must complete before the key is sealed, and the record must be fetched before shards. Round trips are additive, not amortizable. | Direct RPC |
| **Mutable shared state** | Every mutation is a new entity with a new EntityID and a full $D\rho$ storage cost. Immutability is the design, so "updating" is append-only by construction (§4.2). | A database |
| **High-churn versioned data committed as snapshots** | No deduplication (§1.2), so $M$ commits of near-identical content cost $M \cdot D\rho$. | Git, or delta-encode before committing (§11.4) |
| **Low-entropy or enumerable content on a public log** | EntityID fingerprinting succeeds with advantage 1 (§3.3.3). ZK mode fixes it but is not post-quantum (§3.4). | Raise entity min-entropy, or a different protocol |
| **Deployments needing on-chain verification of attestations today** | The registry does not verify the corridor's BLS aggregate on-chain, and the deployed ZK verifier performs no cryptographic check (§8.4). | Wait for the roadmap, or verify off-chain |
| **Anything requiring guaranteed retention** | Shards have a TTL and availability is probabilistic; the record outlives the content (§5.4.4). Immutability is guaranteed, availability is purchased. | Fund renewal explicitly, or use archival storage |

The unifying principle: **LTP trades single-transfer efficiency for fan-out efficiency,
provenance, and immutability.** Where a workload has none of the latter three to gain, the
trade is pure cost.

---

## 12. Open Questions

1. **Shard eviction**: When can shards be garbage collected? (Never? After TTL? After all authorized
   receivers materialize?) **Partially addressed in §5.4.4** — TTL-based eviction with renewal.
   Open: optimal TTL default, interaction between TTL expiry and in-flight lattice keys.

2. **Bandwidth for initial shard distribution**: The commit phase still requires distributing n
   shards. Can this be amortized or pipelined?

3. **Real-time streaming**: Can LTP support continuous entity streams (video, telemetry), or is it
   inherently batch-oriented? A chunked-streaming extension (64 KB chunks, pipelined commit and
   incremental materialization) exists as a design proposal and a partial implementation; the
   open question is the security analysis, since streaming breaks the "entity is a single
   immutable unit" premise that §3.3's theorems assume.

4. **Audit protocol formalization**: The storage proof challenge-response (§5.2.2) is lightweight
   but weaker than Filecoin's PoSt. A node that re-fetches data just before an audit passes
   dishonestly. Can time-bounded challenges be tightened without requiring SNARKs? The
   implementation now includes proof-of-data-possession and VDF-backed audits that go beyond
   what §5.2.2 specifies; the paper has not yet been updated to analyze them.

5. **Cross-deployment federation**: How do independently bootstrapped LTP networks discover and
   trust each other's commitment nodes? A federation subsystem with signed inter-network
   agreements and DNS-based discovery exists in the implementation; the trust-composition
   question — what it means for network A to accept network B's commitment log — is open.

6. **ZK Transfer Mode extensions**: §3.2 specifies a Groth16-based hiding commitment for
   entity_id privacy, but defers two significant capabilities: (a) content-property proofs —
   circuit composition for application-layer predicates (JSON schema, range proofs, etc.); and
   (b) post-quantum ZK — replacing the BLS12-381 pairing with a STARK or lattice-based proof
   system that resists Shor's algorithm. What is the appropriate circuit composition model for
   (a), and which post-quantum proof system best balances proof size, generation time, and
   absence of trusted setup for (b)?

7. **Post-quantum aggregate signatures for the corridor**: The corridor quorum (§8.3) relies on
   BLS12-381 aggregation to compress nine signatures into 96 bytes, and is therefore not
   post-quantum (§3.4). The naive PQ replacement carries nine ML-DSA-65 signatures at 29.8 KB,
   which is prohibitive as on-chain calldata. Is there a post-quantum aggregate or threshold
   signature construction with a compression ratio adequate for on-chain quorum attestation?
   This is not specific to LTP — it is the same obstacle facing post-quantum migration in
   proof-of-stake consensus generally.

8. **A conformant fast erasure backend**: *substantially addressed since first posed.* When
   this question was opened, the conformant coder consumed over 99% of COMMIT and the only
   fast backend (`zfec`) was *systematic* — different shards, different shard roots,
   non-conformant under §2.1.1. The table-driven kernel of §6.5 has since closed most of
   the gap in place: 100–150× faster, byte-identical shards, no new dependency, with the
   coder now at ~50% of COMMIT at the implementation default (§7.3). What remains open is
   the final order of magnitude — a SIMD field-arithmetic kernel (ISA-L or GFNI) driving
   the *same* Vandermonde matrix — and the original systematic-code question is now
   answerable: the compatibility break is not worth it, because the non-systematic
   construction has been shown to run at C-library speed without one.

9. **Independent second implementation**: §5.4.1.2 identifies software monoculture as the
   dominant residual availability risk, and the mitigation — a second conforming
   implementation — does not exist for the core protocol. The corridor wire format has one
   (Python and Rust); the transfer path does not. What is the minimum surface a second
   implementation must cover to meaningfully reduce $p_{sw}$?

10. **Specifying identity-key distribution**: Both verified confidentiality results (§3.3.8)
    are conditional on authentic distribution of identity keys, which this paper does not
    specify. Which mechanism should be normative — a key directory with its own transparency
    log, out-of-band fingerprint verification, or PKI-rooted attestation — and what does each
    choice do to the trust model?

### Resolved questions

The following questions from earlier drafts have been resolved and are retained here for
the record:

- ~~**Commitment network economics**: How are commitment nodes incentivized to store and serve shards?~~
  **Addressed in §5.5.** LTP defines economic interfaces (compensate, slash, pricing) without
  mandating a specific mechanism. Deployment-dependent: organizational SLA, mutual obligation,
  or token/staking (see §5.5 table).

- ~~**Commitment log consensus**: What consensus mechanism secures the append-only log?~~
  **Addressed in §5.1.2.** LTP does not require full BFT consensus. The commitment network is
  a storage network; the log requires only append-only integrity and hash chaining. A Certificate
  Transparency–style Merkle log with trusted operators is sufficient.

---

## 13. Conclusion

LTP inverts the data transfer paradigm. Rather than asking "how do I send this data to you," it
asks "how do I prove this data exists, and give you the right to reconstruct it near you."

The result is a protocol where:
- **The sender→receiver path is O(1)** — a constant-size sealed key, measured at 1,423 bytes
  for entities spanning three orders of magnitude (§7.3)
- **Total system bandwidth is higher than direct transfer** — but the bottleneck shifts from
  the sender-receiver link to receiver-local fetches, with amortized fan-out
- **Transfer is immutable** by mathematical construction, not policy
- **Security on the transfer path is cryptographic** rather than perimeter-based — though the
  optional on-chain settlement surface is not yet, and §8.4 says so plainly
- **Geography is optimized** because materialization pulls from nearby nodes
- **The sender can go offline** after commitment without affecting the transfer

This revision adds the measurements the design has been asserted without (§7). Two results
are worth carrying away. The first is that the constant-size claim holds exactly, not
approximately: the sealed key is byte-identical across entity sizes, which is the structural
property the whole design is built to obtain. The second is a correction to a common
intuition — post-quantum cryptography accounts for well under 1% of a commit, while a
finite-field routine accounts for over 99%. The expensive part of LTP is not the part that
makes it quantum-resistant.

What remains unproven is the performance claim itself. The cost model in §6.4 turns on
$\alpha$, the parallelism efficiency of $k$ concurrent fetches against a real network, and
$\alpha$ cannot be measured in a single process. Until it is measured on deployed
infrastructure, "LTP is faster" remains a prediction with a model behind it rather than a
result. We would rather say that than imply otherwise.

Data doesn't move. Proof moves. Truth materializes.
Bandwidth doesn't disappear. It redistributes to where it's cheapest.

---

## Appendix A: High-Latency Link Optimization (Thought Experiment) {#appendix-a-high-latency-link-optimization-thought-experiment}

*This appendix is an illustrative thought experiment demonstrating two specific LTP properties —
sender-independence and geographic optimization — in an extreme high-latency scenario. It is
not a practical deployment proposal; the infrastructure assumptions (Mars-local commitment
nodes, inter-planetary shard pre-replication) are deployment choices, not protocol features.
The same properties are demonstrated by the grounded use cases in §§11.1–11.4.*

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
- *Lattice phase (per receiver):* 1,423-byte sealed key transmitted in $< 1\text{ s}$ +
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
sufficiently large receiver population (break-even: $N > \rho$).

---

## Appendix B: Conformance Requirements {#appendix-b-conformance-requirements}

The normative requirements of this paper are stated in the sections that define them; this
appendix collects them so an implementer can check a candidate implementation against a
single list. Where this appendix and a section disagree, **the section governs**. Keywords
follow RFC 2119.

**B.1 Entity identity and shape**

| # | Requirement | §    |
|---|-------------|------|
| 1 | EntityID MUST be computed as `H(content ‖ shape ‖ timestamp ‖ sender_vk)` using a canonical-lane hash, with `timestamp` as an 8-byte big-endian IEEE 754 double and `sender_vk` the full ML-DSA-65 verification key | §1.2 |
| 2 | Shape MUST be canonicalized before hashing: type and subtype lowercased, parameters sorted lexicographically, whitespace stripped around `;` and `=` | §1.1.1 |
| 3 | New `x-ltp/` subtypes MUST be registered before use; unregistered experimental subtypes SHOULD carry a reverse-domain prefix | §1.1.1 |
| 4 | Implementations MUST NOT validate content against its declared shape — shape is metadata, not a constraint | §1.1.1 |

**B.2 Hash lanes**

| # | Requirement | §    |
|---|-------------|------|
| 5 | The canonical lane MUST reject any algorithm outside {SHA3-256, SHA-384, SHA-512}, unconditionally and without regard to a compliance-mode flag | §1.3 |
| 6 | Implementations MUST NOT substitute an internal-lane hash where a canonical-lane hash is specified | §1.3 |
| 7 | Specification-frozen digests (corridor wire, on-chain anchor parity, consensus) MUST use SHA3-256 regardless of the active profile | §1.3, §8.3 |

**B.3 Erasure coding**

| # | Requirement | §    |
|---|-------------|------|
| 8 | Encoding MUST use GF(2⁸) with primitive polynomial 0x11D, Vandermonde matrix $V[i][j] = \alpha_i^{\,j}$, and evaluation points $\alpha_i = i+1$ | §2.1.1 |
| 9 | The entity MUST be framed with an 8-byte big-endian length prefix and zero-padded to a multiple of $k$ before splitting | §2.1.1 |
| 10 | The code MUST be non-systematic; an implementation producing raw data chunks as the first $k$ shards is **not** conformant | §2.1.1 |
| 11 | $n$ MUST satisfy $k < n \leq 255$ | §2.1.1 |
| 12 | Implementations MUST validate against both §2.1.1 test vectors before deployment | §2.1.1 |
| 13 | The `algorithm` field MUST be `"reed-solomon-gf256"` only when all of the above hold | §2.1.1 |

**B.4 Shard encryption and placement**

| # | Requirement | §    |
|---|-------------|------|
| 14 | Each commit MUST generate a fresh 256-bit CEK from a CSPRNG, regardless of content or entity_id | §2.1.1 |
| 15 | Nonces MUST be HKDF-derived with a protocol-specific salt and `info = entity_id ‖ uint32_be(index)` | §2.1.1 |
| 16 | AEAD associated data MUST bind each shard to `entity_id ‖ uint32_be(shard_index)` | §2.1.1 |
| 17 | Implementations SHOULD reject degenerate CEKs and SHOULD fail closed on a repeated CEK | §2.1.1 |
| 18 | Commitment nodes MUST store ciphertext only; repair MUST operate on ciphertext without access to the CEK | §2.1.1, §5.4.2 |
| 19 | Replicas of one shard index MUST be placed across as many distinct failure domains as available | §5.4.1.1 |

**B.5 Commitment record and log**

| # | Requirement | §    |
|---|-------------|------|
| 20 | The signature MUST cover the signable payload, which excludes `predecessor`; verification MUST NOT be performed against the full serialization | §2.1.3 |
| 21 | The record MUST NOT contain individual shard IDs — only a Merkle root over encrypted-shard hashes | §2.1.3 |
| 22 | A CT-style log MUST use RFC 6962 domain separation: leaves `H(0x00 ‖ record)`, internal nodes `H(0x01 ‖ left ‖ right)` | §5.1.4.1 |
| 23 | Signed Tree Heads MUST be ML-DSA-65 signed over `sequence ‖ tree_size ‖ timestamp ‖ root_hash`, with per-operator monotonic sequence | §5.1.4.1 |
| 24 | A log MUST NOT modify or delete an appended record, MUST NOT issue an STH with a lower `tree_size` than its predecessor, and MUST NOT publish an unsigned STH | §5.1.4.1 |
| 25 | Two valid STHs from one operator at the same sequence with different roots MUST be treated as a self-contained equivocation proof | §5.1.4.1 |

**B.6 Lattice key and materialization**

| # | Requirement | §    |
|---|-------------|------|
| 26 | The lattice key MUST be sealed with a fresh ML-KEM-768 encapsulation per transfer; the shared secret MUST be zeroized after use | §2.2.1 |
| 27 | An implementation that does not enforce access policy MUST reject any policy whose `type` is not `"unrestricted"` | §2.2.1 |
| 28 | MATERIALIZE MUST enforce access policy **before** any shard fetch | §2.3.1 |
| 29 | MATERIALIZE MUST verify the AEAD tag before decrypting, and MUST verify the recomputed EntityID against the committed one as a final step | §2.3.1 |
| 30 | Implementations MUST enforce per-phase timeouts and MUST use jittered exponential backoff on retry | §2.3.3 |
| 31 | Retired decapsulation keys MUST be securely zeroized after the rotation grace period | §2.3.4 |

**B.7 Deployment posture**

| # | Requirement | §    |
|---|-------------|------|
| 32 | ZK mode MUST NOT be used under a quantum-adversary threat model | §3.2.4, §3.4 |
| 33 | The corridor attestation surface MUST NOT be relied upon for long-horizon non-repudiation under a quantum-adversary threat model | §3.4, §8.3 |
| 34 | Where committed entities may be guessable or enumerable, implementations MUST use ZK mode, raise entity min-entropy, or document acceptance of the fingerprinting risk | §3.3.3 |
| 35 | Production Groth16 deployments MUST use a multi-party trusted setup ceremony | §3.2.4 |
| 36 | ContentHash MUST NOT appear in the public commitment record where content equality is confidential | §1.2 |

**Interoperability test.** Two conforming implementations, given the same content, shape,
timestamp, and sender verification key, MUST produce identical EntityIDs, identical shard
bytes, and identical shard Merkle roots. This is the single test that subsumes most of the
above, and it is the reason §2.1.1 is specified to the byte.

---

## Appendix C: Companion Documents {#appendix-c-companion-documents}

This paper is one document in a larger set, and several of its claims are stated in full
elsewhere. Readers evaluating LTP seriously should not stop here — in particular, the trust
analysis of the settlement surface (§8.4) is summarized here and argued at length in
`BRIDGE_TRUST_MODEL.md`.

| Document | What it adds beyond this paper |
|----------|-------------------------------|
| `docs/THREAT_MODEL.md` | STRIDE analysis with 24 catalogued threats, likelihood/impact ratings, and an explicit out-of-scope list. §3.1's threat table is a summary of it. |
| `docs/BRIDGE_TRUST_MODEL.md` | The full adversarial analysis of the deployed bridge and ZK verifier, including the concrete attacks the simulated verification mode permits. **Read before relying on the settlement surface.** |
| `docs/FORMAL_VERIFICATION_STATUS.md` | The authoritative record of what is machine-checked, with the scope limits of each artifact class. |
| `formal/lean/README.md` | The Lean development, including its "What is NOT proved" section and the negative result on the 1,600-byte constant (§8.6). |
| `docs/CORRIDOR_INTEGRATION.md` | The corridor wire format, DST constants, and cross-language invariants summarized in §8.3. |
| `docs/DEPLOYED_CONTRACTS.md` | Deployed addresses, chains, block heights, and governance parameters behind §8.5. |
| `docs/STABILITY_PROMISES.md` | Which constructs in this paper are frozen public surface and which may change — the normative complement to §2.3.4's "deferred specification items". |
| `docs/design-decisions/` | Design proposals for streaming, enforcement, federation, ZK mode, and commitment-network backends — several correspond to items §12 still lists as open. |
| `docs/security/audits/` | Internal audit findings and the external whitepaper review rounds that shaped this document. |
| `docs/compliance/fedramp-high/` | The control matrix and trust-boundary analysis, including the distinction between *using FIPS-approved algorithms* and *running a FIPS 140-3 validated module* — a distinction this paper's §1.3 relies on but does not itself establish. |
| `scripts/benchmark_whitepaper.py` | Reproduces every measurement in §7. |

---

## Revision History

> **Section numbers in historical entries refer to the numbering in effect at that
> revision.** Version 0.3.0 inserted two sections (§7 Empirical Evaluation, §8 Reference
> Implementation) and renumbered the former §§8–11 to §§10–13. References inside the
> 0.1.0 and 0.2.0 rows below are left as originally written rather than rewritten, so that
> each entry remains an accurate record of what that revision changed. For the mapping,
> see the 0.3.0 entry.

| Version | Date | Summary |
|---------|------|---------|
| 0.1.0-draft | 2026-02-24 | Initial draft; reviewed by external review rounds 001–003 (formal + mathematical) and 004 (research landscape), `docs/security/audits/external/whitepaper-reviews/`. |
| 0.1.0-draft (rev) | 2026-03-29 | Post-review corrections: test-vector arithmetic, BHT collision bound (~85-bit), cost-model expansion factor ρ = nr/k, nonce-derivation invariant, TCONF log binding, ZK-mode specification, theorem-numbering note. |
| 0.2.0 | 2026-08-17 | Publication revision: threshold-secrecy claims conditioned per §3.3.5 throughout; erasure-coding spec re-baselined to the reference implementation (consecutive evaluation points, length-prefix framing) with regenerated test vectors — the evaluation points were re-baselined from the unimplemented powers-of-α scheme to the implemented consecutive-points scheme (α_i = i+1), test vectors regenerated from the reference implementation, superseding the §2.1.1 arithmetic checked in review rounds 001–002; the `encoding_params` `eval` label string is retained verbatim for record-hash compatibility; commitment-record size corrected; KEM-binding claim corrected to a disclosed limitation with planned mitigation; normative conflicts resolved (low-entropy × quantum threat model; extension registry created; log hash primitive unified on BLAKE3-256); disclosure paragraphs for deferred wire formats, hybrid KEM, regulatory posture, forward-secrecy caveats, key-rotation gap; machine-checked verification status section added (§3.3.8) covering the 52 Lean 4 theorems — including both §2.1.1 test vectors recomputed inside the Lean kernel — and the first recorded Verifpal run (2 confidentiality queries verified, 2 authentication replay findings disclosed with planned mitigation); literature positioning updated per the 2026-08-16 research round (X-BIND KEM-binding taxonomy, NIST IR 8547 transition posture, XChaCha20-Poly1305 standardization status); bibliography unified into a single consistent numbered style (37 references, every in-text citation resolves to exactly one entry and vice versa — previously three incompatible citation conventions coexisted and two citations, Cremers–Dax–Medinger and Schmieg, were referenced in §3.3 but absent from every reference list); FIPS 203/204, RFC 9180, NIST IR 8547, and X-Wing given first-class bibliography entries; new §8.9 positions LTP's corridor quorum against Data Availability Sampling (Al-Bassam et al., Danksharding, Hall-Andersen–Simkin–Wagner); §8.4 adds Signal's Sealed Sender as the closest KEM-bound-envelope precedent, and §8.7's constant-size-capability contribution claim is rescoped accordingly to the specific bundle rather than the underlying primitive; missing §8.8 TOC entry restored. |
| 0.3.0 | 2026-08-19 | Implementation-reconciliation and evaluation revision. **Corrections against the reference implementation:** the canonical hash is SHA3-256, not BLAKE3-256 — EntityIDs, commitment records, Merkle roots and tree heads are all `sha3-256:`-prefixed, and the previously undocumented dual-lane architecture (FIPS-approved canonical lane, BLAKE3 internal lane) is now specified in a new §1.3 with the 17x throughput measurement that motivates it; shard nonces are HKDF-derived rather than bare-hash-derived, and AEAD associated data binds each shard to its (entity, index) position (§2.1.1); the sealed lattice key is 1,423 B, not ~1,300 B; the commitment record is 5,824 B, not ~3.5 KB — the earlier figure omitted the inline 1,952-byte verification key, which with the signature accounts for 90.3% of the record (§2.1.3); the claim of 'no X25519 or Ed25519' is corrected to disclose the opt-in ML-DSA-65 + Ed25519 composite signature mode (§8.2); the post-quantum claim is rescoped from 'standard mode' to a per-surface table (new §3.4) that discloses the corridor's BLS12-381 attestation quorum as a second non-PQ surface alongside ZK mode. **New sections:** §7 Empirical Evaluation supplies the benchmarks external review round 003 requested and 0.2.0 shipped without — post-quantum primitive latencies, both hash lanes, erasure throughput at two parameter sets, end-to-end phase timings, exact artifact sizes, and a threats-to-validity subsection; the O(1) sender-receiver invariant is now measured (byte-identical sealed keys across entity sizes) and the COMMIT breakdown shows cryptography at 0.1-0.7% against erasure coding at 99.3-99.9%; all figures are reproducible via `scripts/benchmark_whitepaper.py`. §8 Reference Implementation and Deployment Status inventories the subsystems the paper does not specify (DAG-BFT consensus, multi-VM execution, bridge, federation, enforcement, compliance, economics), specifies the corridor surface §10.9 previously compared to DAS without defining (§8.3, including the safety/liveness asymmetry at 7-of-9), discloses the on-chain settlement trust assumptions (§8.4: the registry does not verify the BLS aggregate on-chain, the deployed ZK verifier runs in a simulated mode with no cryptographic check, dispute resolution is arbitration rather than verification, bonds are zero), records testnet deployment status (§8.5), and consolidates every known paper-implementation divergence into a single table (§8.6). New §5.4.1.2 addresses the software-monoculture and common-cause failure gap review 003 raised and 0.2.0 left open, with a multiplicative bound showing p_sw dominates the geographic model at nine-nines figures. New §11.6 states where LTP is the wrong tool, and §§11.1-11.4 now carry concrete parameters and an honest per-case fit assessment. New Notation table, new Appendix B consolidating 36 conformance requirements, and new Appendix C mapping the companion documents the paper depends on but had never cited. **Structural:** sections 8-11 renumbered to 10-13 to seat the two new sections; cross-reference errors fixed (KEM-binding gap cited §3.3.2, is §3.3.3; shard TTL cited §5.3, is §5.4.4; corridor quorum cited §5.1, now §8.3); Open Questions expanded from 6 to 10, adding post-quantum aggregate signatures, a conformant fast erasure backend, an independent second implementation, and normative identity-key distribution; a size-bound note discloses the divergence between the Lean model's proved 1,220-1,250 B interval and the implemented 1,423 B; a reading caution added to the §9 comparison table acknowledging its structural bias. **Disclosed as unimplemented:** access policy is specified here and proved sound in Lean but is not enforced anywhere in the SDK, so a one-time key can be materialized repeatedly — this also retracts the claim, made in 0.2.0's §3.3.8, that policy enforcement bounds the impact of the sealed-key replay finding; replica placement does not consult node region, so the failure-domain diversity the §5.4.1.1 availability figures assume is not enforced by the placement algorithm; and "zeroized" overstates what the implementation does to discarded key material. All three are in the §8.6 divergence table. **Post-release fact-check:** an independent verification pass over this revision corrected the HKDF salt to its true value (ETP-SHARD-NONCE-v1, a frozen legacy constant), reduced the claimed count of distinct BLS DSTs from three to two, repaired the Lean size-bound note (the model has no nonce field, so 24 B of the gap is envelope rather than payload encoding, and the 1,220-1,250 interval belongs to sealed_768_min/max rather than sealed_768_bounded), removed AEAD nonce derivation from the internal lane's scope, and updated §2.3.1, which had retained the superseded bare-hash nonce formula. §7.1 now reports ranges across two runs rather than single-run precision the shared host does not support. |
| 0.4.0 | 2026-08-21 | Coding-layer mathematics and performance revision. New §6.5 derives the exact cost of the coding layer — the counting identity W_enc = n·D byte-multiplications (independent of k) and W_dec = k·D; the factorization of the Vandermonde inner product into per-coefficient 256-entry byte substitutions plus carry-free big-integer XOR, which removes the interpreter from the data path while leaving every shard byte unchanged; the closed-form O(k²) Vandermonde inverse via Lagrange interpolation (master polynomial, exact synthetic division, Horner normalization) replacing O(k³) Gauss-Jordan on the decode path; and the frontier analysis (SIMD/GFNI kernels as the conformance-preserving next order of magnitude; additive-FFT ruled out as non-conformant and asymptotically capped at n ≤ 255). The reference implementation adopted both constructions: measured **100–150× erasure speedup** with byte-identical shards, gated by the §2.1.1 pinned vectors, the Lean-kernel recomputation, a randomized old-vs-new equivalence fuzz (72 parameter sets including n = 255), a Lagrange-vs-Gauss-Jordan cross-check (211 matrices), and four new permanent regression tests. §7 re-measured throughout: erasure encode now 81–106 MiB/s at (8,4) and 10.8–12.8 MiB/s at (64,32) with the sweep extended to 4 MiB; a 256 KiB three-phase transfer completes in under 10 ms (was ~740 ms); the COMMIT breakdown inverts from 99.3–99.9% erasure to 50.6% at (8,4) and 88.5% at (64,32), with the paper now noting that the absolute cost of cryptography is unchanged and that Amdahl's law caps further coder-only gains at the implementation default; the n·D law is validated by a kernel coefficient-work rate constant at 0.65–0.85 GiB/s across all sixteen configurations, replacing the scalar-era 6.4–6.8× anomaly. §7.1 ranges widened to three runs; §7.5 headroom note revised from two-plus orders of magnitude to one; §12 Open Question 8 marked substantially addressed, with the systematic-code escape hatch withdrawn. Baseline (scalar) measurements are retained in §7.2 and in this table's 0.3.0 entry for the record. |
| 0.4.1 | 2026-08-21 | Access-policy enforcement lands. `materialize()` now enforces §2.2.1 after unsealing and before any fetch, with semantics matching `formal/lean/Ltp/Policy.lean`: time window and count checked for every policy type, `one-time` defaulting to a limit of 1, unknown or malformed policies rejected fail-closed (`minimal_is_sound`), materialization slots reserved atomically so concurrent one-time attempts admit exactly one, and failed attempts releasing their slot because the count tracks completed materializations. Twenty new tests cover the algebra (aligned to the Lean boundary semantics: inclusive window bounds, strict count bound), end-to-end exhaustion, pre-fetch denial, rollback, per-seal capability identity, and the four-thread race. The §2.2.1 'not implemented' warning is replaced by a scope statement — enforcement is receiver-side, counts are in-memory per protocol instance — and §3.3.8's sealed-key replay finding is upgraded from unmitigated to partially mitigated within exactly those limits, the residual surface being cross-instance and cross-restart replay pending the planned KEM-binding fix. Seal-time structural validation is added to `lattice()` and surfaced as a 400 at the REST gateway. The §8.6 divergence row is resolved. Demo policies that used invented types (`availability-test`, `boundary-test`, …) — which only ever worked because nothing enforced them — are corrected to conformant types. |

---

*LTP v0.4.1 — Lattice Transfer Protocol*
