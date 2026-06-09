# pq-quorum-circuit

**Status: RESEARCH SCAFFOLD — Track B, pre-Gate-0.**

Placeholder for the Track B hash-based post-quantum quorum circuit. This crate
will implement a hash-based aggregation circuit that proves a `>2/3`-stake quorum
of GSX-DAG validators — using **leanXMSS signatures** verified inside a
**hash-based proof system (Binius/WHIR)** — on a stock EVM, without any classical
elliptic-curve operations.

## Why this exists

The SP1-Groth16 path (`zkvm/sp1-quorum-verifier`) is blocked by a 2 GB-heap wall
on multi-sig ML-DSA proving, and its BN254 Groth16 wrapper is Shor-breakable
regardless. Track B replaces both: hash-based signatures (XMSS, no lattice
arithmetic) + a hash-based proof system (Binius/WHIR, no elliptic curves anywhere)
= end-to-end post-quantum, provable inside a ZK-friendly prover.

If Gate-0 passes (the WHIR/Binius EVM-verifier gas trajectory reaches
~1.5 M gas), this crate will:

1. Implement N leanXMSS signature verifications as hash-based gadgets.
2. Reuse `quorum-core`'s threshold + strictly-increasing-pkHash dedup + set-
   membership logic, swapping `ml-dsa::verify` for an XMSS verify gadget.
3. Produce a hash-based proof verifiable by `PqQuorumVerifier.sol` on any stock
   EVM, dropping into the existing `ISourceLockVerifier` seam via `setVerifier`.

## Current state

No source files are present. Gate-0 (Phase 0 feasibility, `~2–4 weeks`) must pass
before any implementation begins. Gate-0 criteria:

> A credible 12-month gas trajectory for a quorum-proof EVM verification
> under ~1.5 M gas (amortized over many bridge messages per proof), using
> WHIR over a 31-bit field or Binius binary-field polynomial commitment scheme.

Current anchor: ~5.6 M gas for a WHIR proof over a 2^22 polynomial. The bet is
the 2026 optimization trajectory (Binius field speedups, recursion, EF tooling).

## Trust model

Same as every other bridge path: honest `>2/3`-stake quorum of registered
validators (sync-committee trust class). What changes is the **cryptographic
guarantee**: the outer proof is hash-based (no elliptic curves), so a quantum
adversary cannot forge the proof even with Shor's algorithm. This is the only
path that achieves PQ + trust-minimized + stock EVM simultaneously — and it
does not yet exist anywhere in production.

## XMSS statefulness warning

XMSS is a stateful signature scheme. Key-reuse is catastrophic (it reveals the
signing key). The Track B plan addresses this as a first-class operational hazard:
validators must manage signature state rigorously, or use the leanXMSS
Merkle-budgeted variant (SPHINCS+ is stateless but larger). Do not implement
XMSS signing without resolving the state-management story.

## Related

- `zkvm/quorum-core/` — threshold + dedup + set-membership logic this circuit reuses.
- `docs/security/audits/suwappu/PQ_STOCK_EVM_RESEARCH_PLAN.md` — full phased plan
  with kill gates.
- `docs/security/audits/suwappu/DUAL_TRACK_PQ_BRIDGE_PLAN.md` — where this fits in
  the dual-track roadmap.
- `docs/BRIDGE_ARCHITECTURE.md` — verifier seam this proof plugs into.
