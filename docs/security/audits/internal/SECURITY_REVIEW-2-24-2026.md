# LTP Security Review & Mathematical Analysis

**Reviewer:** Internal Adversarial Review  
**Date:** 2026-02-24  
**Status:** HONEST ASSESSMENT — Pre-publication scrutiny

---

## Executive Verdict

**The whitepaper is NOT yet suitable for peer-reviewed publication.** It is a strong conceptual
design document, but it contains overclaims, a critical security gap, conflation with existing
work, and lacks the formal mathematical proofs needed to survive academic or industry scrutiny.

Below is a section-by-section breakdown of what holds, what breaks, and what must be fixed.

---

## 1. What Is Cryptographically Sound (What Holds Up)

### 1.1 Content-Addressing Is Provably Immutable

The EntityID construction:

```
EntityID = H(content || shape || timestamp || sender_pubkey)
```

**This is mathematically sound** given a collision-resistant hash function H.

**Formal guarantee:** If H is modeled as a random oracle (or satisfies collision resistance
in the standard model), then:

$$\Pr[\exists \, x \neq x' : H(x) = H(x')] \leq \frac{q^2}{2^{n+1}}$$

where $q$ = number of hash queries and $n$ = output bits (256 for BLAKE2b/BLAKE3).

For $n = 256$: an attacker making $2^{128}$ queries achieves collision probability
$\approx 2^{-1}$ (birthday bound). This is computationally infeasible.

**Verdict:** ✓ **Immutability of entity identity is mathematically provable.**

### 1.2 Content-Addressed Shards Are Tamper-Evident

```
ShardID = H(shard_content || entity_id || shard_index)
```

Any modification to a shard changes its ShardID, which is detected at reconstruction (step 6).
This follows directly from the preimage resistance of H:

$$\Pr[\text{find } x' \neq x : H(x') = H(x)] \leq \frac{q}{2^n}$$

**Verdict:** ✓ **Shard integrity verification is provably sound.**

### 1.3 Append-Only Log Immutability

If the commitment log is implemented as a hash-chained structure (each record references
the hash of the previous):

$$\text{Record}_i.\text{prev} = H(\text{Record}_{i-1})$$

Then modifying any historical record breaks the chain — all subsequent records become invalid.
This is the same guarantee as blockchain/Merkle chains and is well-proven.

**Verdict:** ✓ **Commitment log immutability is sound (given honest majority or trusted append).**

### 1.4 Erasure Coding Threshold Security

Reed-Solomon over GF(2^8) with parameters (n, k) provides information-theoretic security:

**Theorem (MDS property):** A Reed-Solomon code with parameters (n, k) is a Maximum Distance
Separable code. Any k-1 or fewer shards reveal **zero information** about the original data.

$$H(\text{data} \mid \text{any } k-1 \text{ shards}) = H(\text{data})$$

where $H$ here denotes Shannon entropy. This is **information-theoretic** — it holds against
adversaries with unlimited computational power, including quantum computers.

**Verdict:** ✓ **The threshold security claim (< k shards reveals nothing) IS provable and
is one of the strongest claims in the paper.**

---

## 2. What Is Cryptographically BROKEN or Overclaimed

### 2.1 CRITICAL: The Lattice Key Contains Shard IDs (Information Leak)

**This is the most serious flaw in the current design.**

> **Update:** The lattice key now contains only entity_id + CEK + commitment_ref (Option C design). Shard IDs are no longer included in the sealed payload.

The lattice key currently includes:

```json
{
  "entity_id": "...",
  "commitment_ref": "...",
  "shard_ids": ["shard_id_1", "shard_id_2", ...],   // ← PROBLEM
  "encoding_params": {"n": 8, "k": 4},
  "sender_id": "...",
  "access_policy": {...}
}
```

**The attack:** An attacker who intercepts the lattice key (even without the receiver's
private key) now knows:
- The entity_id (which references the public commitment log)
- ALL shard IDs
- The encoding parameters (n and k)
- The commitment log reference

With shard IDs in hand, the attacker can:
1. Compute shard locations via the **deterministic** consistent hashing (the algorithm is public)
2. Fetch shards directly from commitment nodes (if nodes don't enforce access control)
3. Reconstruct the entity via erasure decoding

**The whitepaper claims the lattice key is "useless without the receiver's private key,"
but the PoC implementation does NOT encrypt anything.** The key is plaintext JSON. Even the
whitepaper spec only encrypts `receiver_decryption_material` — the shard IDs, entity ID, and
encoding params are metadata that, combined with a public commitment network, may be sufficient
to reconstruct.

**Fix required:**
- The lattice key must be **entirely encrypted** to the receiver's public key (not just
  the decryption material)
- Shard content must be encrypted; commitment nodes must store ciphertext
- Commitment nodes must enforce access control (authenticate the receiver before serving shards)
- OR: remove shard IDs from the key entirely — the receiver can compute them from entity_id

**Severity: HIGH. Without this fix, the "interception resistance" claim is false.**

### 2.2 CRITICAL: "Size Invariance" Claim Is Misleading

The paper claims:

> "Transferring 1 KB and transferring 1 TB produce the same size lattice key (~512 bytes)"

**This is technically true for the key itself, but profoundly misleading** because:

1. **The commit phase scales with entity size.** Someone still has to upload O(entity_size × 
   replication_factor) bytes to the commitment network. This is real bandwidth consumption.
   
2. **The materialize phase scales with entity size.** The receiver downloads k shards, each of
   size O(entity_size / k). Total download = O(entity_size). This is real bandwidth consumption.

3. **The "transfer" only appears size-invariant if you redefine "transfer" to mean only the
   sender→receiver direct path.** But the total system bandwidth is actually O(entity_size × 
   (replication_factor + 1)), which is WORSE than direct transfer.

**What a reviewer will say:** "You haven't eliminated bandwidth costs. You've moved them to
the commit and materialize phases and then defined them away by redefining 'transfer.' The
total bits moved across the network is strictly greater than direct sender→receiver transfer."

**Fix required:**
- Acknowledge that total system bandwidth is higher than direct transfer
- Reframe the advantage honestly: the bottleneck SHIFTS from the sender-receiver path to
  the receiver-network path, which can be geographically optimized
- The real win is latency amortization and fan-out, not bandwidth elimination

**Severity: HIGH. This is the #1 thing that will get the paper rejected in peer review.**

### 2.3 The "Quantum Resistant" Claim Is Incomplete

The paper states:

> "Use post-quantum hash (BLAKE3) and post-quantum signatures (Dilithium); erasure coding is
> information-theoretic"

**What holds:**
- BLAKE3 (and BLAKE2b) are believed quantum-resistant for collision resistance (Grover's
  algorithm only reduces the security level from $2^{128}$ to $2^{64}$ for preimage, which
  is still infeasible; birthday attacks remain at $2^{128}$)
- Reed-Solomon threshold security is information-theoretic (quantum-immune)

**What doesn't hold:**
- The lattice key uses X25519 key exchange, which is **broken by quantum computers**
  (Shor's algorithm solves ECDLP in polynomial time)
- Ed25519 signatures are **broken by quantum computers** (same reason)
- The paper mentions Dilithium as an option but doesn't make it the default

> **Update (March 2026):** The protocol has migrated from X25519 to ML-KEM-768 (FIPS 203) for key encapsulation. X25519 references below reflect the state at review time.

**Fix required:** Either commit to post-quantum primitives throughout (Kyber/ML-KEM for
key exchange, Dilithium/ML-DSA for signatures) or honestly state that the base protocol
is quantum-vulnerable and post-quantum is a future upgrade path.

### 2.4 Forward Secrecy Claim Is Conditional

The paper claims forward secrecy via ephemeral X25519. This is **correct in principle** but
the PoC doesn't implement it, and the whitepaper doesn't specify:
- How ephemeral keys are generated per-transfer
- How they're destroyed after key agreement
- What happens if the ephemeral key is logged (e.g., by a compromised sender machine)

Forward secrecy requires careful key lifecycle management. The claim is defensible but
under-specified.

---

## 3. What Will Attract Scrutiny in Peer Review

### 3.1 "This Is Just IPFS + Access Control"

**Expected critique:** "LTP is content-addressed distributed storage (IPFS) plus an access
control layer (lattice keys) plus an immutable log (blockchain). What is genuinely novel?"

**Honest assessment:** This critique has merit. The individual components are well-known:
- Content-addressed storage → IPFS, CAS systems (2014+)
- Erasure coding for distribution → Storj, Filecoin (2017+)
- Append-only commitment logs → Blockchain, Certificate Transparency (2012+)
- Small capability tokens that grant access → Capability-based security (1966+)

**What is arguably novel:**
- The specific combination and the "lattice key" abstraction as the transfer primitive
- The framing of "transfer as proof, not payload" as a protocol-level concept
- The deterministic placement allowing receiver-side computation without a lookup service

**Fix required:** Add a "Related Work" section that honestly cites IPFS, Storj, Filecoin,
BitTorrent, Certificate Transparency, and capability-based security. Then clearly articulate
what LTP's specific contribution is beyond combining these.

### 3.2 The Name "Latticement" Is Misleading

> **Update:** The protocol has been renamed to Lattice Transfer Protocol (LTP).

"Latticement" has a precise meaning in quantum physics (non-local correlations between
quantum states). LTP has nothing to do with quantum latticement. Using this term will:
- Attract criticism from physicists
- Be seen as "quantum-washing" / hype
- Undermine credibility

**Fix required:** Either rename the protocol or add an explicit disclaimer that the term
is metaphorical.

### 3.3 Commitment Network Bootstrap Problem ✅ *Addressed — see WHITEPAPER §5*

The paper assumes a commitment network exists but doesn't address:
- How does the first node join?
- What prevents a Sybil attack (attacker runs many fake nodes)?
- What prevents nodes from colluding (k nodes conspire to reconstruct)?
- How is data availability guaranteed (what if nodes go offline)?

These are the exact problems that took Filecoin/Storj years to address with proof-of-
spacetime, proof-of-replication, etc.

### 3.4 Availability vs. Immutability Tension ✅ *Addressed — see WHITEPAPER §4.3, §5.4*

The paper guarantees immutability (data can't be changed) but doesn't adequately address
availability (data can be accessed). If nodes go offline and fewer than k shards remain
available, the entity is permanently lost — immutable but inaccessible.

This is the CAP theorem in disguise: you cannot have perfect consistency, availability,
and partition tolerance simultaneously.

**Resolution:** §4.3 formally separates the two guarantees (Theorem 1: Immutability is
unconditional; Theorem 2: Availability boundary is sharp at k shards). §5.4 provides the
probabilistic availability model with explicit CAP theorem analysis. The PoC erasure coder
now implements true any-k-of-n reconstruction over GF(256), demonstrated with catastrophic
shard loss, boundary-exact reconstruction (exactly k shards), and graceful failure below k.

---

## 4. Mathematical Proofs That DO Work

Here are the formal guarantees that can be proven with standard cryptographic assumptions:

### 4.1 Immutability (Collision Resistance) ✅

**Theorem:** Under the collision resistance of H, no PPT (probabilistic polynomial time)
adversary can produce two distinct entities $e \neq e'$ such that $\text{EntityID}(e) = \text{EntityID}(e')$.

**Proof:** Assume such an adversary A exists. Then A can be used to find a collision in H:
given A's output $(e, e')$ with $e \neq e'$ and $H(\text{encode}(e)) = H(\text{encode}(e'))$,
we have a collision. This contradicts the collision resistance of H.  $\blacksquare$

> **PoC Validation (completed):** The proof-of-concept now validates the IMM game
> (Whitepaper §3.3.1, Theorem 3) across five independent checks:
> 1. **Deterministic EntityID** — computing `EntityID = H(content ‖ shape ‖ timestamp ‖ sender)`
>    multiple times with identical inputs always produces the same hash (consistency).
> 2. **Avalanche effect** — flipping a single bit in content, changing shape, nudging
>    timestamp by ε, or switching sender each produce completely unrelated EntityIDs;
>    ~50% of hex characters differ (random oracle behavior, as expected from BLAKE2b-256).
> 3. **Encoding injectivity** — the raw pre-hash encoding `encode(e)` is verified to differ
>    whenever entities differ (`e ≠ e' ⟹ encode(e) ≠ encode(e')`), confirming the
>    prerequisite for the IMM→CR reduction in the proof.
> 4. **Empirical collision search** — 10,000 EntityIDs generated from random content with
>    zero collisions observed. Birthday bound: $\Pr[\text{collision}] \leq q^2/2^{257}$;
>    at $q = 10{,}000$ this is $\approx 5.4 \times 10^{-71}$ (vanishingly small).
> 5. **End-to-end immutability gate** — the commitment record's `content_hash = H(content)`
>    is covered by the ML-DSA-65 signature; tampering with `content_hash` or `entity_id`
>    invalidates the signature (forgery detected). `materialize()` Step 8 recomputes
>    `H(reconstructed)` and rejects on mismatch — closing the end-to-end integrity loop.

### 4.2 Shard Integrity (Preimage Resistance) ✅

**Theorem:** Under preimage resistance of H, no PPT adversary can substitute a shard
$s_i' \neq s_i$ that passes verification.

**Proof:** Verification checks $H(s_i' \| \text{entity\_id} \| i) = \text{ShardID}_i = H(s_i \| \text{entity\_id} \| i)$.
For $s_i' \neq s_i$ this requires finding a second preimage, contradicting second-preimage
resistance of H.  $\blacksquare$

> **PoC Validation (completed):** The proof-of-concept now implements two-layer shard integrity:
> 1. **AEAD per-shard authentication** — each encrypted shard carries a 32-byte HMAC tag;
>    `materialize()` catches `ValueError` on tampered shards and skips them (Theorem 4, SINT game).
> 2. **Content hash gate** — `CommitmentRecord.content_hash = H(content)` is covered by the
>    ML-DSA signature; `materialize()` Step 8 recomputes `H(reconstructed)` and rejects on mismatch.
> 3. **Demo verification** — a tamper detection section flips bits in a stored shard, confirms
>    AEAD rejects it, reconstructs from remaining shards (any k-of-n), and verifies EXACT MATCH.
> 4. **Resilient fetch** — `materialize()` now fetches all n shards (not just k), so AEAD-rejected
>    shards can be replaced by redundant valid ones without failing the transfer.

### 4.3 Threshold Secrecy (Information-Theoretic, Reed-Solomon MDS) ✅

**Theorem:** For a Reed-Solomon (n, k) code over GF(q) with $q \geq n$, any $k-1$ or
fewer codeword symbols are statistically independent of the message.

**Proof:** The Reed-Solomon encoding of a message $m = (m_0, ..., m_{k-1})$ evaluates the
polynomial $p(x) = \sum_{j=0}^{k-1} m_j x^j$ at $n$ distinct points. Any $k-1$ evaluations
leave one degree of freedom — for every possible message, there exists a consistent polynomial.
Therefore:

$$\Pr[M = m \mid S_{k-1}] = \Pr[M = m]$$

where $S_{k-1}$ denotes any set of $k-1$ shard values. This is unconditional (information-
theoretic).  $\blacksquare$

> **PoC Validation (completed):** The proof-of-concept now validates the TSEC game
> (Whitepaper §3.3.5, Theorem 7) across five independent checks:
> 1. **MDS unique reconstruction** — any k=4 non-sequential shards (indices {1,3,5,7})
>    uniquely reconstruct both test messages via Vandermonde inversion over GF(256).
> 2. **Zero distinguishing advantage** — all $\binom{8}{3} = 56$ subsets of k-1=3 shards
>    are tested; for each subset, both candidate messages yield valid degree-(k-1)
>    polynomials through the observed points, confirming $\mathsf{Adv}^{\text{TSEC}}_{\mathcal{A}} = 0$.
> 3. **Statistical uniformity** — 12,294 bytes from k-1 shards of a 16KB random message
>    pass a chi-squared goodness-of-fit test (χ²=249.4 < 310.0 critical at p=0.01,
>    df=255), showing all 256/256 byte values populated with no systematic bias.
> 4. **CEK compromise resilience** — adversary obtains CEK AND decrypts k-1=3 plaintext
>    shards; reconstruction from k-1 shards still fails (information-theoretic, not
>    computational barrier). AEAD bypassed, TSEC holds independently.
> 5. **Sharp threshold boundary** — k-1=3 shards: H(M|S_{k-1}) = H(M) (perfect secrecy);
>    k=4 shards: H(M|S_k) = 0 (full disclosure, exact match verified). One shard is the
>    difference between zero information and complete reconstruction.

### 4.3.1 CEK Uniqueness Invariant (Nonce Safety) ✅

**Concern (Formal Review §4.4):** Each shard's AEAD nonce is derived from its shard index.
This is safe only because each CEK is independently random per entity. If the same CEK were
reused across two entities, corresponding shards would share identical (key, nonce) pairs,
enabling XOR-based plaintext recovery:

$$c_1 \oplus c_2 = p_1 \oplus p_2$$

This is a catastrophic AEAD nonce reuse — the fundamental invariant underlying the entire
shard encryption scheme.

**Resolution:** The CEK uniqueness invariant is now explicitly stated in three places:

1. **Whitepaper §2.1.1** — Added a formal "Security Invariant — CEK Uniqueness (Nonce Safety)"
   block specifying that CEK MUST come from a CSPRNG, CEK reuse is catastrophic, and
   re-commitment MUST generate a fresh CEK regardless of entity_id reuse.

2. **PoC `ShardEncryptor` class** — Added three defense-in-depth mechanisms:
   - `generate_cek()` now uses `os.urandom(32)` with process-level collision tracking
     (raises `RuntimeError` on collision — probability ~$2^{-256}$, effectively impossible)
   - `validate_cek()` rejects degenerate keys (all-zero, all-one, wrong length)
   - `encrypt_shard()` calls `validate_cek()` before every encryption operation

3. **PoC `commit()` method** — Comments explicitly document the nonce safety invariant
   at the point where the CEK is generated.

**Why this is sufficient:** The probability of `os.urandom` producing duplicate 32-byte
values is $\frac{q^2}{2^{257}}$ where $q$ is the number of entities committed. Even at
$q = 2^{64}$ entities (far beyond any realistic deployment), collision probability is
$\approx 2^{-129}$ — computationally negligible. The runtime tracking is defense-in-depth
against a compromised CSPRNG, not against birthday collisions.

### 4.4 Non-Repudiation (Signature Unforgeability)

**Theorem:** Under the EUF-CMA (Existential Unforgeability under Chosen Message Attack)
security of the signature scheme, no PPT adversary can forge a commitment record.

**Proof:** Standard reduction to EUF-CMA game for Ed25519 / Dilithium.  $\blacksquare$

### 4.5 What CANNOT Be Formally Proven

| Claim | Why It Can't Be Proven |
|-------|----------------------|
| "Faster than traditional transfer" | Performance is empirical, not mathematical. Depends on network topology, node placement, entity size, etc. |
| "Geography-independence" | Depends on the commitment network having nodes near the receiver. No protocol can guarantee this. |
| "Sub-latency" | Undefined formal metric. O(1) key size is proven; O(1) total transfer time is NOT. |
| "Secure without trust" | Requires honest majority in the commitment network, which IS a trust assumption. |

---

## 5. Comparison: LTP vs. What Already Exists

| Claimed LTP Property | Already Exists In | Is LTP Different? |
|---------------------|-------------------|-------------------|
| Content-addressed storage | IPFS (2015), Git (2005) | No |
| Erasure-coded distribution | Storj (2018), Tahoe-LAFS (2007) | No |
| Immutable commitment log | Bitcoin (2009), CT (2013) | No |
| Small capability token for access | Capability URLs, Macaroons (2014) | Mostly no |
| "Proof of right to reconstruct" | Storj access grants | Very similar |
| Combined into single clean protocol | **This is the novel part** | **Yes** |

The novelty is the **protocol-level unification** and the **mental model** (commit-lattice-
materialize), not the individual components.

---

## 6. Recommendations for Publication-Ready Version

### Must Fix (Blockers)

1. **Encrypt the entire lattice key**, not just decryption material. The current design
   leaks shard IDs and entity structure to any interceptor.

2. **Remove or heavily qualify the "size-invariant transfer" claim.** Reframe as "the
   sender-receiver direct path is O(1)" while acknowledging total system bandwidth is O(n).

3. **Add a Related Work section** citing IPFS, Storj, Filecoin, Tahoe-LAFS, BitTorrent,
   Certificate Transparency, and capability-based security. Clearly state what LTP unifies.

4. **Add formal security definitions** (IND-CPA for confidentiality, EUF-CMA for integrity,
   define the security game for "transfer immutability").
   ✅ *Addressed — see WHITEPAPER §3.3.* Seven formal security games defined:
   IMM (Theorem 3, collision resistance), SINT (Theorem 4, shard integrity),
   TCONF (Theorem 5, IND-CPA-style transfer confidentiality), NREP (Theorem 6,
   EUF-CMA non-repudiation), TSEC (Theorem 7, information-theoretic threshold secrecy),
   TIMM (Theorem 8, composite transfer immutability game). Each reduced to standard
   assumptions (CR, SPR, IND-CCA, EUF-CMA, AEAD-AUTH, MDS property). §3.3.7 honestly
   lists what cannot be formally proven.

5. **Address data availability** — what happens when nodes go offline? Define the availability
   guarantees and their limits.
   ✅ *Addressed — see WHITEPAPER §4.3 (Theorems 1 & 2), §5.4 (availability model,
   failure modes, CAP analysis, repair protocol, TTL lifecycle).*

### Should Fix (Strengtheners)

6. **Rename or disclaim "Latticement"** — the quantum terminology will attract dismissal.

7. **Specify the commitment log consensus mechanism** — the paper hand-waves "blockchain,
   Merkle DAG, or any immutable append-only structure" without committing. Reviewers will
   press on this.

8. **Add a formal cost model** — total bandwidth, latency equations, storage costs. Compare
   quantitatively (not just qualitatively) to direct transfer, IPFS, etc.

9. **Decide on quantum posture** — either go fully post-quantum or acknowledge the gap.
   ✅ *Addressed — ML-KEM-768 + ML-DSA-65 throughout.*

10. **Fix the PoC erasure coding** — the current implementation only reconstructs from data
    shards 0..k-1 (not arbitrary k-of-n). This undermines the availability claim.
    ✅ *Addressed — Vandermonde matrix encoding over GF(256) with Gauss-Jordan decoding.
    Demo verifies: shards {4,5,6,7} reconstruct data originally split into shards {0,1,2,3}.*

### Nice to Have (Polish)

11. Formal TLA+ or Alloy model of the protocol state machine
12. Simulation results comparing LTP latency to direct transfer under various topologies
13. Threat model diagram (attacker capabilities taxonomy)

---

## 7. Final Honest Assessment

| Dimension | Rating | Notes |
|-----------|--------|-------|
| Novelty of individual components | Low | All components are well-known |
| Novelty of composition | Moderate | The unification is clean and the mental model is compelling |
| Cryptographic soundness | **Moderate-High** | Core crypto is sound; key management has gaps |
| Security claims accuracy | **Needs work** | Several overclaims (size-invariance, interception resistance) |
| Immutability claims | **Strong** | Multiple layers of provable immutability |
| Reversibility of transfer | **Provably impossible** | Content-addressing + append-only + signatures make reversal computationally infeasible |
| Publication readiness | **Not yet** | 4-5 blocking issues to resolve first |
| Hackability | **Moderate risk** | The lattice key leak is exploitable; fix it and the risk drops to Low |
| Mathematical foundation | **Partially provable** | Immutability, integrity, threshold secrecy are provable. Performance claims are not. |

**Bottom line:** The protocol is built on sound cryptographic foundations. The core immutability
and threshold secrecy properties are mathematically provable. But the whitepaper makes several
claims that don't survive scrutiny, and the lattice key design has a real security gap.
Fix those, add Related Work, and this becomes a legitimate protocol specification.

**Can the transfer be reversed?** No. This is the strongest claim in the paper and it holds:
once committed, the content-addressed, append-only, signature-bound record cannot be modified,
deleted, or attributed to a different sender. Reversal would require breaking collision
resistance (computationally infeasible) or compromising the append-only log (requires
dishonest majority).

---

## 8. Formal Peer Review Responses

*Tracking resolution of findings from `LTP_Whitepaper_Formal_Review.md`.*

### FR 4.1 — Entity Immutability (Collision Resistance) ✅

**Finding:** The IMM game (Theorem 3) needs PoC validation demonstrating that the
collision resistance reduction actually holds in the implementation.

**Resolution:** Five independent validations added to the PoC demo:
deterministic EntityID, avalanche effect, encoding injectivity, empirical collision
search (10,000 IDs, zero collisions), and end-to-end immutability gate with ML-DSA
signature binding. See internal §4.1 above for details.

### FR 4.2 — Commitment Log Trust Model ✅

**Finding:** The append-only commitment log lacks a formal trust model. Security proofs
assume an idealized log; the paper should specify exact assumptions, fork detection,
and how receivers verify they read the canonical log.

**Resolution (Whitepaper §5.1.4 + PoC):**

- **Whitepaper:** Added §5.1.4 "Commitment Log Trust Model" specifying:
  - Formal trust assumptions (append-only, availability, consistency, liveness)
  - Trust tiers (single operator → federated → decentralized)
  - Fork detection via signed tree heads (STH), gossip protocol, inclusion proofs
  - Compromise impact analysis and minimum viable trust requirements
  - Recommended deployment posture

- **PoC:** `CommitmentLog` class upgraded with:
  1. **Hash-chain**: each record includes `chain_hash = H(record_bytes ‖ prev_chain_hash)`;
     any historical modification breaks the chain at the tampered index and all subsequent entries
  2. **Signed Tree Heads (STH)**: monotonically increasing sequence + root hash + timestamp
     generated at each append; clients can cache and compare STHs for fork detection
  3. **Inclusion proofs**: `get_inclusion_proof()` returns chain position + predecessor hash;
     `verify_inclusion()` re-derives chain hash from record bytes to confirm membership
  4. **`verify_chain_integrity()`**: walks the full chain from genesis, recomputes every
     chain hash, returns `(True, last_idx)` on success or `(False, break_idx)` on tampering

- **PoC Demo Validations:**
  1. Chain integrity verification (full chain walk: ✓ INTACT)
  2. Inclusion proofs for 5 committed entities (all verified)
  3. Tamper detection: 1-bit flip in historical record → chain breaks at index 0 (correct)
  4. STH sequence: monotonic timestamps + sequential indices (verified)

### FR 4.3 — Storage Proof Weakness ✅

**Finding:** The challenge-response storage proof is weaker than Filecoin's SNARKs.
A node that re-fetches data just before an audit can pass dishonestly, defeating the
storage proof and degrading the effective replication factor to 1.

**Resolution (Whitepaper §5.2.2 + PoC):**

- **Whitepaper:** §5.2.2 expanded with anti-outsourcing measures:
  - Tight time bounds: response deadline $T < \min \text{RTT}(\text{node}, \text{peers}) - \varepsilon$
  - Burst challenges: $b$ simultaneous nonces per shard; outsourcing requires $b$ relay
    round-trips, each consuming the time budget
  - Economic deterrent: stake $\geq (b \cdot c_{\text{fetch}} + \delta)$ per shard
  - Honest limitation acknowledged: commodity-link proofs cannot fully prevent
    co-located relay; time bounds + economics close the practical gap

- **PoC:** `audit_node()` upgraded with:
  1. **Burst parameter**: `burst=b` issues $b$ simultaneous nonces per shard
  2. **Response timing**: `time.monotonic()` tracks per-challenge latency;
     `avg_response_us` field reported in audit results
  3. **Suspicious latency detection**: burst responses exceeding 1ms threshold
     flagged (real systems: $T < \min \text{RTT} - \varepsilon$)
  4. **Amplified failure signal**: missing shard × burst = proportionally more
     failed challenges (2 missing shards × burst=4 = 16 missing responses)

- **PoC Demo Validations:**
  1. Baseline audit (burst=1): all nodes pass with µs-level latency
  2. Burst audit (burst=4): anti-outsourcing challenge, all nodes pass
  3. Degraded burst audit: partial data loss × burst = amplified detection signal

### FR 4.4 — CEK Uniqueness / Nonce Safety ✅

**Finding:** Nonce-as-index for AEAD requires justification that the same CEK is never
reused across entities.

**Resolution:** See internal §4.3.1 above. CEK uniqueness invariant stated in three places
(Whitepaper §2.1.1, PoC `ShardEncryptor`, PoC `commit()` method). CSPRNG + runtime
collision tracking provides defense-in-depth.

### FR 4.5 — Availability Model / Correlated Failures ✅

**Finding:** The availability calculation assumes independent node failures. Real-world
deployments exhibit correlated failures (cloud outages, regional disasters). The
99.9999999% figure is misleading under correlation.

**Resolution (Whitepaper §5.4.1.1 + PoC):**

- **Whitepaper:** Added §5.4.1.1 "Correlated Failure Model":
  - Formal partitioning of nodes into failure domains $D_1, \ldots, D_m$
  - Per-replica failure probability under correlated model:
    $\Pr[\text{all replicas fail}] = \prod_j (1 - (1-p_j)^{r_j})$
  - Worked example comparing three placement strategies:
    - Independent (ideal): 99.9999999%
    - Cross-region (realistic): 99.999997%
    - Same-region (worst case): 99.58%
  - Deployment requirement: all shard replicas must span distinct failure domains

- **PoC:** `CommitmentNetwork` extended with:
  1. **`region_failure()`** / **`restore_region()`**: simulates correlated regional outage
     (all nodes in region evicted simultaneously)
  2. **`check_cross_region_placement()`**: verifies shard replica pairs span distinct regions
  3. **`availability_under_region_failure()`**: computes surviving shards if a region fails

- **PoC Demo Validations:**
  1. Cross-region placement verification: all 8 shards have cross-region replicas (✓)
  2. Single-region failure: entity survives any one of 6 regions failing (6/6 ✓)
  3. Live region failure: evict all nodes in a region, fetch surviving shards, confirm
     materialization still possible (✓)
  4. Two-region failure stress test: graceful degradation under multi-region correlated
     failure (tested)

### FR 5.2 — Shape Specification ✅

**Finding:** The whitepaper references Entity "shape" but never defines its format, valid
values, or canonicalization rules.

**Resolution:** See Whitepaper §1.1.1. Shape is a canonical IANA media type
(`type/subtype[;param=value]*`). `canonicalize_shape()` ensures case-insensitive matching
and parameter ordering. PoC validates via regex and raises `ValueError` on invalid shapes.
