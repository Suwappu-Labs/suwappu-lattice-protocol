# Dual-Track Plan: ship a trust-minimized bridge now, land the world-first PQ verifier in parallel

**Date:** 2026-06-09 · Status: **ROADMAP**. North star: be the **first end-to-end post-quantum,
trustless cross-chain bridge** — verify a PQ validator quorum on a *foreign stock EVM*. Companion to
`PQ_STOCK_EVM_RESEARCH_PLAN.md` (Track B detail) and `REMAINING_GAPS_RESEARCH.md`.

---

## 0. Why both tracks run in parallel without waste

Every verification route this project has built or scoped funnels through **one seam**: the on-chain
quorum verifier that (a) checks a proof/signature-set and (b) binds the committed `validatorSetRoot` to
the on-chain registry, then finalizes the header. That seam is **already built and tested**
(`Sp1QuorumVerifier.sol` + `GsxDagValidatorRegistry.currentValidatorSetRoot()`, 9 forge tests green) and
it is **primitive-agnostic** — the proof/signature backend is a swap.

```
                    ┌─────────────────────────────────────────────┐
   validators ──▶   │  SHARED RAILS (built once, both tracks use)  │
   (multi-scheme    │  • multi-scheme signing pipeline             │
    signing)        │  • registry + validatorSetRoot + epochs      │
                    │  • relayer (aggregates sigs/proofs)          │
                    │  • the verifier SEAM (setVerifier swap)      │
                    └───────────────┬───────────────┬─────────────┘
                                    │               │
            TRACK A (ship now)  ◀───┘               └───▶  TRACK B (world-first)
            BLS / native-precompile verify                 hash-based PQ proof verify
            → drop into the seam                            → drops into the SAME seam (setVerifier)
```

**Consequence:** Track A delivers a *working, trust-minimized bridge on mainnet*, and simultaneously builds
the exact integration surface Track B needs. When Track B clears its gate, it ships as a **drop-in upgrade**
of an already-live system — not a rewrite. Track A de-risks; Track B moonshots; they meet at the seam.

---

## TRACK A — Pragmatic, ship-now (engineering; can drive immediately)

A trust-minimized bridge live on mainnet, PQ where we control the chain, classical-but-trust-minimized
where we don't (a documented exception zone with EIP-8051 as the migration target — matches the gsx-dag
PQ-conservative crypto policy).

| Milestone | What | Status / effort |
|---|---|---|
| **A1. PQ native leg** | Deploy/harden the destination on the **gsx-dag EVM** (suwappu-revm) — real ML-DSA via `0x0101`. **Both trust-min AND PQ.** | Proven end-to-end (suwappu-revm #2); needs a real deploy target + e2e on a node |
| **A2. Legacy leg** | **BLS-aggregate** header quorum verifier for stock EVMs — validators already hold BLS12-381 keys (LTP/fast-path). One aggregate verify, cheap on-chain. Trust-min, classical. | Buildable now (small — keys exist) |
| **A3. Shared rails** | Multi-scheme validator signing (ML-DSA + BLS now, leanXMSS later), epoch transitions, relayer hardening, deploy scripts, audit-prep | Partly built (bridge_header, relayer, registry); productionize |

Track A's exit = a mainnet-safe, audited, trust-minimized bridge. That alone is a real product.

---

## TRACK B — World-first PQ-on-stock-EVM (research; needs a cryptographer + scaffolding)

The north star. Detail + kill-gates in `PQ_STOCK_EVM_RESEARCH_PLAN.md`. Core bet: **hash-based signatures
(leanXMSS) + a hash-based PQ proof (Binius/WHIR)** — dodging both the lattice-ZK wall and the classical-SNARK
wrapper, riding the EF's [leanMultisig](https://github.com/leanEthereum/leanMultisig) primitives repurposed
for cross-chain quorum verification.

| Milestone | Gate |
|---|---|
| **B0. Phase 0 feasibility (~1 mo)** | Map the WHIR/Binius **EVM-verifier gas trajectory**; KILL if no credible path under ~1.5 M gas |
| **B1. Native hash-based quorum proof** | A real leanXMSS quorum proves natively (reuses `quorum-core` logic, swap ml-dsa→XMSS) |
| **B2. Stock-EVM verification under budget** | A real PQ quorum proof verifies on anvil under the Gate-0 budget = **world-first** |
| **B3. Productionize** | Epoch transitions, audit, bug bounty, and the *publication* (the "first" is also a paper) |

---

## Shared infrastructure (the convergence — built once)

1. **Multi-scheme validator signing** — generalize `gsx-consensus::bridge_header` so a validator can attest
   with ML-DSA (native leg), BLS (legacy leg), and leanXMSS (research leg) over the same header digest.
   *Both tracks consume this.*
2. **Registry + `validatorSetRoot` + epoch transitions** — built (`GsxDagValidatorRegistry`); the set-root
   getter is the binding both a BLS proof and a hash-based proof check against.
3. **The verifier seam** — `ISourceLockVerifier` / the quorum-verifier interface; `setVerifier()` swaps
   BLS → SP1 → hash-based-PQ with zero rail changes. Built.
4. **Relayer** — aggregates whatever the leg produces (sigs or a proof) and submits. Built; generalize.

---

## Resourcing — honest

- **Track A is engineering** — drivable now with the model-tiered subagent workflow (Sonnet build, Opus
  adversarial verify). No new hire required.
- **Track B's core is a research hire** — the hash-based aggregation circuit + the WHIR/Binius EVM verifier
  need a cryptographer. What can be scaffolded *without* one: Phase-0 benchmark harness, the integration
  seam (already built), the leanXMSS signing pipeline (engineering), and the precise gate spec. The novel
  crypto is the hire; everything around it is buildable in-house.
- **Parallelism is free of contention** because the two tracks touch *different* layers (A: rails +
  classical/native verify; B: the PQ proof) that meet only at the swap-in seam.

---

## Immediate next actions (both tracks start now)

- **Track A, now:** build the **BLS-aggregate header verifier** (A2) — small, ships stock-EVM reach with a
  trust-minimized (classical) quorum, and exercises the shared rails. *Pure engineering.*
- **Track B, now:** stand up **Phase 0** — clone `leanMultisig` + the WHIR-EVM-verifier, build a gas-benchmark
  harness, and write the Gate-0 criteria as a runnable check. *Scaffolding I can do; the gas verdict informs
  the hire decision.*
- **Convergence kept honest:** every Track-A verifier is written behind the seam so Track B is a `setVerifier`,
  never a rewrite. No overclaiming: Track A's legacy leg is classical (documented exception zone); only
  Track B (on pass) and Track A's native leg are post-quantum.

The world-first is the goal; the pragmatic track is how we stay alive — and solvent — while we chase it,
and it lays the exact track the moonshot lands on.
