# P11 — GSX-DAG Consensus Light Client (design spec; the real end-to-end-PQ trust root)

Date: 2026-06-08. Status: **DESIGN SPEC** (no code). Companion to P10 (source-event proof) and
P5b (on-chain PQ). Grounded in a read of the actual `gsx-dag` consensus crates.

## 0. Why this exists

P10 Phase C shipped two header-trust roots: `Sp1HeliosHeaderOracle` (real ZK light client, EVM
sources, **not PQ** — Groth16 wrapper) and `CommitteeHeaderOracle` (an honest **interim M-of-N
oracle** — committee trust, not consensus verification). Neither is the end-state for the GSX-DAG
corridor: a destination that verifies **real GSX-DAG consensus certificates** (PQ, trust-minimized).
This doc specifies that light client — and documents, honestly, why it is **not buildable today** and
what must land first.

## 1. What GSX-DAG finality actually is (from the code)

`gsx-dag/crates/suwappu-consensus/src/cert.rs`:
```rust
pub struct Certificate {
    author: AuthorityId,        // u32 index into the Authority Ring
    round: Round,               // u64
    parents: Vec<CertHash>,     // parent certs (empty iff round 0)
    payload_digest: [u8;32],    // block hash
    signature: Vec<u8>,         // ML-DSA-65 detached sig over hash(network_id), 3309 bytes
}
```
- **No separate finality certificate.** Finality is the **Mysticeti-C commit rule** (`commit.rs`): a
  leader cert at round R is committed once **≥ quorum** distinct Authority Ring members author
  round-R+1 certs that reference it as a parent. Quorum `q = n − ⌊(n−1)/3⌋` (BFT 2f+1).
- **Joint-quorum AND-gate** (`joint.rs`, paper Thm 2): a commit is *jointly ratified* only if BOTH
  (a) the Authority leg fires AND (b) Validator-Ring votes with **> 2/3 of validator stake** for the
  same payload. Two rings: Authority (30–50 members, certify) + Validator (100–500, stake-weighted
  vote). Both sign **individually with ML-DSA-65 (no aggregation)**.
- Sig binding: `BLAKE3("SUWAPPU-CERT-V1" || network_id || author || round || parents || payload)` for
  certs; `BLAKE3("SUWAPPU-VOTE-V1" || network_id || validator || candidate)` for votes. `network_id`
  prevents cross-chain replay.

## 2. What a destination light client must verify — and the gas wall

To accept "block B is final on GSX-DAG", a destination must check:
1. **Authority quorum:** ≥ q (21 for n=30, 34 for n=50) Authority members' ML-DSA-65 sigs over the
   R+1 supporter certs.
2. **Validator joint-quorum:** validators holding > 2/3 stake ML-DSA-65-signed the payload (dedup by
   id; ML-DSA is randomized so you cannot dedup by sig bytes).
3. **Payload binding:** `payload_digest` == B's hash.

**The wall:** ML-DSA-65 verify on EVM is **~5–12M gas per signature** (no aggregation possible; P5b §1).
- Authority leg: q × ~8M ≈ **170–270M gas**.
- Validator leg: (validators in the 2/3-stake quorum) × ~8M — realistically **600M–1.2B gas**, up to
  **6B** if the whole ring votes.
- **Total ≈ 1.2–2.2 billion gas per finality check** = ~40–70 Ethereum blocks ≈ tens of $M/verify.
  **Economically infeasible on any EVM destination.** This is the fundamental ML-DSA-no-aggregation
  problem: PQ signatures don't batch into one pairing the way BLS does.

## 3. The blocker before any light client: validator-set transitions are unimplemented

`suwappu-authority` / `suwappu-validator` registries are **in-memory only**. There is **no on-chain
validator-set contract and no epoch-transition mechanism** in gsx-dag Phase 1. A light client can
therefore verify finality for **exactly one bootstrapped epoch** (the validator set it was handed
offline); it cannot follow a set rotation, because there is no signed "set-update" object to verify
against the prior set. **This must be built first** (a real light client tracks the validator set by
verifying the chain's own transition rules — that machinery does not exist yet):
- On-chain (or canonically-encoded) Authority + Validator registries with stake + ML-DSA pubkeys.
- A signed **epoch-transition certificate**: the new set, quorum-signed by the *old* set, that a
  light client verifies before adopting the new set.

## 4. The trilemma — and the three real options

You cannot get **EVM-cheap + post-quantum + trust-minimized** simultaneously today.

| Option | Mechanism | Gas | PQ? | Trust-minimized? | Buildable now? |
|---|---|---|---|---|---|
| **A. Precompile-destination direct verify** | Verify the cert's ML-DSA-65 sigs via the native precompile (`0x0101`) | ~8–12k/sig → q×~10k ≈ **sub-1M** | ✅ FIPS-204 | ✅ real consensus | only where the precompile exists |
| **B. ZK proof of cert verification** | Prove "quorum of authorized validators ML-DSA-signed B" in a zkVM; verify the SNARK on EVM | ~280k | ❌ Groth16/BN254 Shor-broken (PQ-safe STARK = multi-M gas) | ✅ | partial (non-PQ) |
| **C. BLS super-node aggregate** | LTP 7-of-9 super-node BLS12-381 aggregate over the header | ~500k | ❌ BLS Shor-broken | ❌ 7-of-9 subset = committee | yes (= CommitteeHeaderOracle's class) |

- **Option A is the only end-to-end-PQ + trust-minimized path**, and it works **only on a destination
  that has the ML-DSA precompile** — i.e. the **GSX-DAG home chain** (and any future chain that adopts
  it), **not a generic EVM L1/L2**. Blocked on: (1) the precompile's `gsx-revm` registration at `0x0101`
  (built + tested, NOT yet registered — P5b §BUILD PROGRESS); (2) the §3 validator-set registry.
- **Option B** is the long-term path for *generic EVM* destinations, but is **not PQ** until a
  PQ-safe on-chain proof system is affordable (the same trap that makes SP1 Helios non-PQ). It is real
  trust-minimization (a SNARK of the actual quorum), just not quantum-safe end-to-end.
- **Option C** is the gas-feasible interim, but it is **committee trust** (7-of-9 super-nodes), i.e.
  exactly what `CommitteeHeaderOracle` already provides — do not relabel it "consensus verification."

## 5. Recommendation (honest, phased)

1. **Near term (interim, shipped):** keep `CommitteeHeaderOracle` for the GSX-DAG corridor and
   `Sp1HeliosHeaderOracle` for EVM sources. Both are documented as **not** end-to-end-PQ /
   not-full-consensus. Bind every mint to the header via the P10 storage proof (done).
2. **Unblock Option A (the real prize, GSX-DAG↔GSX-DAG):**
   a. Land the `gsx-revm` ML-DSA precompile registration at `0x0101` (P5b remaining Phase 1).
   b. Build the **on-chain validator-set registry + epoch-transition certificate** verification (§3) —
      a `GsxDagConsensusHeaderOracle` that, on a precompile-bearing destination, verifies the
      Authority+Validator quorum ML-DSA sigs over the header and tracks the set across epochs. This is
      a true consensus light client and is **PQ + trust-minimized**, but ONLY where `0x0101` exists.
3. **For generic EVM destinations:** pursue **Option B** (a zkVM circuit proving the GSX-DAG quorum)
   as the trust-minimized path, and state plainly it is **not PQ** until a PQ-safe affordable on-chain
   verifier exists. Do **not** present the BLS super-node path as anything but committee trust.

## 6. Why this isn't code yet (the honest blockers)
- **ML-DSA gas wall (§2):** direct cert verification is ~1–2B gas on EVM → only viable on a
  precompile-bearing destination (GSX-DAG home), which needs the `gsx-revm` registration first.
- **Validator-set transitions unimplemented (§3):** there is nothing on-chain to track the set across
  epochs → no autonomous light client is possible until that's built.
- **The PQ/gas trilemma (§4):** generic-EVM + PQ + trust-minimized is not simultaneously achievable
  with today's primitives.

The end-to-end-PQ, trust-minimized bridge is real **only** for the GSX-DAG↔GSX-DAG corridor, and even
there it is gated on the precompile registration + a validator-set registry. Everything to a generic
EVM destination is, today, either non-PQ (ZK/Helios/BLS) or committee-trust. **NO-GO for mainnet funds
stands**, and the PQ claim must remain the layered one from P5b §97 — not "the bridge is post-quantum."

---
Sources: `gsx-dag/crates/suwappu-consensus/{cert,commit,joint}.rs`, `suwappu-authority`,
`suwappu-validator`, `suwappu-mldsa-precompile/src/lib.rs`; `gsx-revm` precompiles (ML-DSA absent);
`P5b_ONCHAIN_PQ.md`; `P10_SOURCE_EVENT_PROOF.md`.
