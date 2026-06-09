# Research Plan: the first trustless **post-quantum** quorum verifier on a stock EVM

**Date:** 2026-06-09 · Status: **RESEARCH PROPOSAL — for go/no-go evaluation** (no commitment).
Companion to `REMAINING_GAPS_RESEARCH.md`. This turns the "open frontier" identified there into a
concrete, phased, kill-gated plan.

---

## 0. The goal, stated precisely

A **stock EVM** (Ethereum / Base — a chain whose VM we do NOT control) verifies, **trustlessly** and
**end-to-end post-quantum**, that a `>2/3`-stake quorum of gsx-dag validators attested a header — at a
gas cost that closes economically. Today this does not exist anywhere (see `REMAINING_GAPS_RESEARCH.md`
§Barriers). Being first to ship it in production is the prize.

---

## 1. The core bet (the one idea that makes it tractable)

**Stop trying to ZK-prove ML-DSA.** Lattice signatures (ML-DSA) are ZK-*hostile* — NTT + polynomial
arithmetic blow up in any proof system (this is the literal SP1 2 GB-heap wall we hit in Path C). Instead:

> **Switch the validators' *bridge-attestation* signature to a HASH-BASED scheme (XMSS / the
> [leanXMSS](https://pq.ethereum.org/) variant), and prove the quorum inside a HASH-BASED (post-quantum)
> succinct proof system (Binius / WHIR). Hash-based signatures are *all hash operations* (Merkle paths +
> hash chains) — exactly what [Binius binary-field provers accelerate 10–100×](https://arxiv.org/html/2512.13333v1)
> and what hash-based PCS verify on-chain.**

This simultaneously dodges both barriers from `REMAINING_GAPS_RESEARCH.md`:
- **PQ end-to-end, no classical wrapper:** hash-based signature + hash-based proof system = no elliptic
  curve anywhere ⇒ nothing Shor can break (unlike Groth16/SP1, whose BN254 wrapper is the quantum hole).
- **ZK-friendly:** the prover works over the proof system's native ops (hashes), not foreign lattice math.

And it is *not* a lone bet — it is **exactly the architecture the Ethereum Foundation is building for L1
consensus** ([Lean Ethereum, Vitalik Feb-2026 roadmap](https://pq.ethereum.org/); EF Post-Quantum team
formed Jan 2026; [leanMultisig zkVM](https://github.com/leanEthereum/leanMultisig); EIP-8141 targeted at
the Hegota fork, H2 2026). We would **repurpose their open-source primitives for a use case they are NOT
addressing — cross-chain quorum verification on a *foreign* stock EVM** — riding their tooling and
derisking, ~1–2 years ahead of it being routine.

---

## 2. Architecture

```
gsx-dag validators ──(1)── sign bridge header digest with leanXMSS (hash-based)
                                      │
off-chain aggregator ──(2)── prove in a hash-based zkVM (leanMultisig/Binius):
       "N validators whose leanXMSS pubkeys ∈ the committed set, with summed
        stake ≥ (2·total)/3 + 1, each signed header H"  →  ONE hash-based proof
                                      │
stock-EVM `PqQuorumVerifier.sol` ──(3)── verify the hash-based proof (WHIR/Binius
       EVM verifier) + bind the committed validatorSetRoot to the on-chain registry
       → finalize the header.  PQ ∧ trustless ∧ on a chain we don't own.
```

- **(1)** Reuses the validator-signing machinery we already built for ML-DSA header attestations
  (`gsx-consensus::bridge_header`, the daemon-feed slice) — swap the signature primitive to leanXMSS.
- **(2)** The hard new component: the aggregation circuit. Reuses `quorum-core`'s *logic* (threshold,
  strictly-increasing pkHash dedup, set membership) — swap `ml-dsa::verify` for an XMSS verify gadget.
- **(3)** Reuses the **already-built** binding: `Sp1QuorumVerifier.sol` + `registry.currentValidatorSetRoot()`
  already commit a `validatorSetRoot` and bind it to the registry. Swap the SP1-Groth16 verify call for a
  WHIR/Binius verify call; the rest of the contract (publicValues reconstruction, set-root binding,
  finalize, equivocation guard) is reusable as-is.

---

## 3. Phased plan with go/no-go gates

### Phase 0 — Feasibility + stack selection *(≈2–4 weeks, 1 cryptographer-leaning eng)*
- Pin the stack: **leanXMSS** (sig) × **Binius or WHIR** (PCS) × a zkVM/constraint frontend
  ([Spartan2 is PCS-agnostic](https://github.com/microsoft/Spartan2) and supports Binius/WHIR/Basefold —
  good for swapping).
- **Benchmark the EVM verifier gas TODAY** and its trajectory. Current anchor:
  [WHIR opening a 2^22 poly at 100-bit soundness ≈ 5.6 M gas](https://ethresear.ch/t/evm-verification-of-whir-over-a-31-bit-field/24902);
  [Spartan-WHIR proof ≈ 14 KB](https://arxiv.org/html/2512.13333v1). Map the quorum circuit's size to a
  gas estimate.
- **GATE 0 (kill):** if a credible 12-month trajectory does NOT get a quorum-proof EVM verification under
  **~1.5 M gas** (amortized over many bridge messages per proof), STOP and ship the two-leg pragmatic
  architecture instead. Everything below is contingent on passing Gate 0.

### Phase 1 — Native prototype: hash-based quorum proof *(≈2–3 months)*
- Add leanXMSS signing to gsx-dag validators (alongside ML-DSA; XMSS **statefulness** is a first-class
  operational concern — see Risks).
- Build the aggregation circuit: N XMSS verifies + set-membership + the `quorum-core` threshold/dedup
  logic, in the chosen hash-based system. Generate a proof off-chain; verify it **natively**.
- Non-vacuous bar (same discipline as `quorum-core`): real leanXMSS keys; 3-of-4 proves, sub-quorum is
  unprovable, tampered sig excluded, set-membership load-bearing.
- **GATE 1:** a real hash-based proof of a real >2/3 quorum verifies natively, and its measured size/prover
  cost is within the Phase-0 budget.

### Phase 2 — The crux: verify it on a stock EVM *(≈3–5 months)*
- Port/adapt the WHIR-over-31-bit-field (or Binius) **EVM verifier** to accept the quorum proof.
- `PqQuorumVerifier.sol` = `Sp1QuorumVerifier.sol` with the proof-verify call swapped; reuse the set-root
  binding + finalize. Verify a real proof on **anvil**, measure end-to-end gas.
- Drive optimization (binary-field/Binius speedups, soundness/field tuning, recursion to shrink the final
  verifier — keeping the WHOLE chain hash-based so PQ is preserved).
- **GATE 2 (the real one):** a real PQ quorum proof verifies on a stock EVM under the Gate-0 budget. Pass ⇒
  this is genuinely first-in-the-world for a cross-chain bridge.

### Phase 3 — Productionize *(≈3–6 months)*
- Epoch transitions (the leanXMSS validator-set root must update + be proven across epochs), DoS/soundness
  review, an independent cryptography audit of the gadget + the EVM verifier, bug bounty.

---

## 4. Reuse vs build vs depend-on-others

| Component | Status |
|---|---|
| Quorum logic (threshold, dedup, set membership) | **Reuse** `quorum-core` (built, tested) |
| On-chain set-root binding + finalize + equivocation guard | **Reuse** `Sp1QuorumVerifier.sol` + `registry.currentValidatorSetRoot()` (built, 9 tests green) |
| Validator signing pipeline | **Reuse** `bridge_header` + daemon-feed; swap ML-DSA → leanXMSS |
| leanXMSS signature scheme | **Adopt** EF's open spec/impl |
| Hash-based aggregation zkVM/circuit | **Build** (the core research; lean on leanMultisig/Spartan2/Binius) |
| WHIR/Binius **EVM verifier** | **Adapt** EF/community research code — *external maturity dependency* |

---

## 5. Risks & honest assessment

- **Gas may not close in time (primary risk).** ~5.6 M gas today is over budget; the bet is the trajectory
  (Binius, recursion, the EF's 2026 optimization push). Gate 0/2 exist precisely to kill the project if it
  doesn't. Mitigant: one proof per header/epoch amortizes over many bridge messages.
- **Immature, unaudited research code.** WHIR/Binius EVM verifiers move weekly and are not production-audited.
  We'd be productionizing the frontier — high reward, real fragility.
- **XMSS is STATEFUL.** Key-reuse = catastrophic forgery. Validators must manage signature state rigorously
  (or use the leanXMSS Merkle-budgeted variant / accept SPHINCS+ stateless-but-larger). This is an
  operational + consensus-integration hazard, not just a crypto one.
- **It is a research bet, not an engineering task.** Realistic: **12–18 months + a dedicated cryptographer**
  (not a sprint). Could yield a paper + a first-mover production system, or could stall at Gate 2.
- **"First" is real but narrow.** The EF builds leanMultisig for *L1 consensus*; nobody applies it to a
  *cross-chain bridge quorum on a foreign EVM*. That gap is the novelty — but it closes once L1 PQ tooling
  matures (~2027–2029 per the EF), so the first-mover window is finite.

---

## 6. The decision framing (what you're actually choosing)

- **Pursue this** if the goal is to be the **first end-to-end-PQ trustless bridge** and you can fund a
  cryptographer for 12–18 months on a Gate-gated bet. Upside: a genuine world-first + a research moat, fully
  aligned with the gsx-dag PQ thesis.
- **Don't** if you need mainnet-safe value movement *soon* — then the **two-leg architecture** (PQ settlement
  on the gsx-dag EVM, already proven; classical-but-trust-minimized BLS leg to legacy chains; track
  EIP-8051) ships now and the PQ-stock-EVM verifier becomes a *later upgrade-in-place* (the on-chain binding
  is already built to receive it).

These are not exclusive: **Phase 0 (the kill-gated feasibility study, ~1 month) is cheap and decides it.**
Recommended next concrete step regardless of the larger decision: **run Phase 0.**

---

## Sources
- [pq.ethereum.org — Lean Ethereum / leanXMSS / PQ roadmap](https://pq.ethereum.org/)
- [leanEthereum/leanMultisig — minimal zkVM for hash-based signature aggregation](https://github.com/leanEthereum/leanMultisig)
- [EVM Verification of WHIR over a 31-bit field (ethresear.ch)](https://ethresear.ch/t/evm-verification-of-whir-over-a-31-bit-field/24902)
- [Hash-Based Multi-Signatures for Post-Quantum Ethereum (cic.iacr.org)](https://cic.iacr.org/p/2/1/13)
- [Quantum Disruption SoK — gas costs of SNARK vs STARK on EVM (arXiv 2512.13333)](https://arxiv.org/html/2512.13333v1)
- [Spartan2 — PCS-agnostic (Binius/WHIR/Basefold) zkSNARK](https://github.com/microsoft/Spartan2)
- [poqeth — efficient PQ signature verification on Ethereum (eprint 2025/091)](https://eprint.iacr.org/2025/091.pdf)
