# Suwappu Bridge — Filling the Two Remaining Gaps (research)

**Date:** 2026-06-08 · Status: **RESEARCH / DESIGN** (no code). Grounded in a read of
the live code (suwappu-dag `gsx-execution`, suwappu-revm precompiles, the merged
`StorageProofSourceLockVerifier` / `Sp1HeliosHeaderOracle` / `GsxDagQuorumHeaderOracle`)
plus 2024–2026 SOTA. Companion to `NEXT_STEPS_SOURCE_SIDE.md` and
`P11_GSXDAG_QUORUM_ORACLE_DESIGN_UNBUILT.md`.

---

## 0. What the gaps actually are (grounded)

After the header-attestation loop (validators sign → relayer aggregates → oracle verifies a
>2/3-stake quorum), two gaps remain before the destination can verify the source
**cryptographically** rather than trusting a validator quorum's word:

1. **Real ML-DSA on-chain.** The quorum oracle verifies ML-DSA-65 via precompile `0x0101`,
   which exists **only in suwappu-revm** (the gsx-revm fork). On a stock EVM destination
   (Base/Ethereum) `0x0101` is absent; today the forge/anvil tests etch a *mock* that returns
   `keccak256("MOCK_MLDSA"||pk||digest)`. A pure-Solidity ML-DSA verifier for a full
   no-aggregation quorum is the ~1.2–2.2 B-gas "wall." So real ML-DSA verification of the
   quorum does not yet run on a stock destination chain.

2. **Provable source state.** `StorageProofSourceLockVerifier` proves a lock commit via an
   `eth_getProof` keccak-MPT storage proof. But gsx-dag's state root is **not** a keccak-MPT:
   `gsx_db_substrate.rs:241-253` computes it as `StateTree::from_state(&state).root()` — a
   **BLAKE3 `StateTree`** over the balance map (`gsxdb-state`). The gap is **not** a missing
   inclusion-proof primitive (see correction below); it is that (a) gsx-dag does not yet
   **expose** that proof to a relayer, and (b) the destination has no on-chain BLAKE3-StateTree
   verifier (the `0x0102` BLAKE3 precompile exists only in suwappu-revm; a stock EVM can't
   re-hash the path). The header attestation today carries only the *root*, opaque.

   > **CORRECTION (2026-06-08, grounded — supersedes an earlier draft claim).** An earlier
   > version of this doc said gsx-db's inclusion proofs are "stubbed (G2.2 phase 3)," inferred
   > from a stale comment in gsx-dag's `burn_nullifier.rs`. **That is false.** The BLAKE3
   > `StateTree` already exposes a public inclusion-proof API — `pub use tree::{Commitment,
   > Proof, ProofStep, StateTree}` with `StateTree::root()`/`verify()` and `ProofStep{byte,
   > siblings}` — and it is present in the **exact pinned revision gsx-dag compiles**
   > (`gsxdb-state` v0.1.0, commit `2fee806`, in `GlobalSettlementNetwork/gsx-db`). So **no
   > dependency migration is required** to get inclusion proofs; the primitive is already in
   > the binary. Separately, gsx-db has since rebranded to `Suwappu-Labs/suwappu-db`
   > (`gsxdb`→`suwappudb`) and gsx-dag still pins the old `GlobalSettlementNetwork` tag — a
   > **stale-pin cleanup**, independent of this gap. And the gsx-dag CI red is a **separate
   > missing-secret** issue (`ssh-private-key argument is empty`), which a `Cargo.toml`
   > repoint does **not** fix — that needs a CI workflow change (token-fetch) or the deploy-key
   > secret. Three distinct things; don't conflate them.

> **Important scoping correction (grounded):** Gap 2 is **already solved for *external-EVM*
> source chains** (e.g. a lock on Base). Those have a keccak-MPT, so the merged
> `StorageProofSourceLockVerifier` + `Sp1HeliosHeaderOracle` work directly. Gap 2 is only
> open for the **gsx-dag-native corridor**, because gsx-dag uses a BLAKE3 StateTree, not an
> MPT. Keep the two corridors distinct in the roadmap.

---

## 1. The unifying answer: one SP1 proof for *both* gaps

> **EMPIRICAL CORRECTION (2026-06-09, from actually building it — supersedes the optimism below).**
> The single-guest version of this does **NOT work on current SP1 (v4/v6)**. We built the guest
> (`zkvm/sp1-quorum-verifier`, wrapping `quorum-core`) and ran it: it compiles to a RISC-V ELF, but
> **executing the quorum OOMs** — SP1's zkVM hard-caps the guest heap at **2 GB** (`0x78000000`,
> `sp1-zkvm/src/syscalls/memory.rs`), and **ML-DSA-65 × 3 signers** exceeds it (each
> `VerifyingKey::decode` + `Signature::decode` allocates large lattice structures). A **single** ML-DSA
> verify fits (the existing `sp1-mldsa-verifier` and the public Dilithium-ZK demo both prove ONE sig) —
> but an N-signer quorum in one guest hits the wall. So "one SP1 proof of the whole quorum" is
> **infeasible as a single circuit today.** Viable routes: **(i) SP1 proof aggregation** — prove each
> signature in its own guest (each fits) and recursively aggregate to one on-chain proof (much more
> complex; not built); or **(ii) the native `0x0101` precompile path (§2 Path A)** — already built and
> green (suwappu-revm #2), and it is *both* trust-minimized AND post-quantum, where ZK is neither
> feasible-here nor PQ. **Net: Path A is now the recommended PQ route for the quorum; Path C single-guest
> is shelved pending aggregation.** What we DID land from the Path-C attempt is reusable on either route:
> `quorum-core` (the verification logic), `GsxDagValidatorRegistry.currentValidatorSetRoot()`, and
> `Sp1QuorumVerifier.sol` (the on-chain verifier + binding, 9 forge tests green — ready for an aggregated
> proof if one is ever produced).

The strongest 2024–2026 result is that both gaps collapse into a **single ZK proof**, because
gsx-dag is already a Rust program and SP1 compiles ordinary Rust to a provable circuit.

**Proposed circuit (one SP1 program):** prove, for a given `(blockNumber, stateRoot)`, that
> (a) a set of gsx-dag validators whose **stake clears the on-chain >2/3 threshold**
> ML-DSA-65-signed the header digest (the exact 148-byte `HEADER_DOMAIN ‖ networkId ‖ oracle ‖
> blockNumber ‖ stateRoot` preimage), **and**
> (b) the lock **commit `X` is included in that header's BLAKE3 `StateTree`**.

Public inputs: `(networkId, blockNumber, stateRoot, commitId, recipient, amount, validatorSetRoot)`.
On-chain: **one Groth16 verification (~300k gas) on any EVM** finalizes the mint — no `0x0101`,
no keccak-MPT, no per-signature on-chain cost.

Why this is the right shape, with evidence:

- **ML-DSA in ZK is production-ready.** The [Dilithium-ZK / SP1 library](https://dilithium-zk-landing.vercel.app/)
  verifies NIST ML-DSA signatures in zero knowledge with **~22 s proofs** and **~260-byte
  on-chain verification**; [SP1 Groth16 verifies for ~300k gas](https://blog.succinct.xyz/sp1-testnet/).
  This turns the ~1.2–2.2 B-gas no-aggregation wall into one ~300k-gas proof.
- **The BLAKE3 inclusion is *free* inside the circuit.** The MPT/keccak design is famously
  ZK-*un*friendly ([Historical and Multichain Storage Proofs, arXiv:2411.00193](https://arxiv.org/html/2411.00193v1));
  gsx-dag's BLAKE3 StateTree is the opposite — proving inclusion is just Rust `blake3` inside
  the SP1 program. The thing that blocks a *Solidity* inclusion verifier (no on-chain BLAKE3
  without `0x0102`) is a non-issue in-circuit.
- **This is the proven bridge architecture.** Succinct's SP1 runs a full Tendermint light
  client verifiable on Ethereum for **~200k gas, 25× cheaper than naive**; the [Gnosis
  OmniBridge](https://union.build/blog/consensus-verification) now secures **$40M TVL / $1.5B+
  flow on SP1 ZK consensus proofs instead of a multisig committee**. We already vendor the
  pattern: `Sp1HeliosHeaderOracle` + the live [SP1 Helios](https://github.com/succinctlabs/sp1-helios)
  deployments referenced in the P10 work.

**The honest catch — this is trust-minimized but NOT post-quantum.** SP1's wrapping proof is
**Groth16 over BN254, which Shor breaks.** A ZK proof *of* an ML-DSA verification does not make
the *bridge* post-quantum: a quantum adversary forges the BN254 proof, not the ML-DSA sig. So
the SP1 path removes **relayer/operator and quorum-liveness trust** but the end-to-end PQ claim
requires a PQ outer layer (next section). State this every time — it is exactly the kind of
overclaim this project has been corrected on.

---

## 2. The PQ-preserving paths (pick per destination)

| Path | ML-DSA verified by | Gas | Post-quantum? | Dependency |
|---|---|---|---|---|
| **A. Native precompiles on gsx-dag's own EVM** | `0x0101` (real ML-DSA) + `0x0102` (real BLAKE3) in **suwappu-revm** | ~12k + 30k | **YES** | Deploy the destination ON the gsx-dag EVM (the "graduate to GSX DAG L1" endgame). Already built — suwappu-revm #1. |
| **B. EIP-8051 precompile on a stock L1/L2** | [EIP-8051 `MLDSA_VERIFY` precompile](https://eips.ethereum.org/EIPS/eip-8051) (~4500 gas) | ~4.5k/sig | **YES** | External: EIP-8051 is a *draft*; no mainnet/L2 ships it yet. Timeline-uncertain. |
| **C. SP1 (Groth16) proof of {quorum + inclusion}** | inside the circuit (real FIPS-204 Rust) | ~300k once | **NO** (BN254 outer) | Proving infra (~22 s/proof). Works on **any** EVM today. |
| **D. STARK (FRI/hash-based) proof** | inside the circuit | high on-chain (FRI verify) | **YES** | On-chain STARK verification gas is currently impractical; revisit as STARK verifiers mature. |

**Reading of the table:**
- **Today, any stock EVM, trust-minimized:** Path **C** — it's buildable now, ~300k gas, and
  removes operator/relayer/quorum-liveness trust. Ship it as the cryptographic upgrade over the
  header-attestation interim, **labelled "not PQ — classical SNARK outer layer."**
- **End-state, fully PQ:** Path **A** — when the bridge graduates onto the gsx-dag EVM, the real
  `0x0101`/`0x0102` precompiles verify the quorum + BLAKE3 inclusion natively and post-quantumly.
  This is the only path that is *both* trust-minimized *and* PQ, and it's mostly already built;
  the gap is operational (run the destination on the gsx-dag EVM), not cryptographic.
- **B** is the clean stock-chain PQ answer but is gated on external EIP adoption — track it,
  don't depend on it.
- **D** is the "PQ on a foreign chain without a precompile" dream; not gas-viable yet.

---

## 3. Concrete next steps (in dependency order)

1. **Expose the (already-existing) inclusion proof through gsx-dag (prereq for both 2 & 3).**
   The `StateTree` proof API already exists in the pinned `gsxdb-state` (`Proof`/`ProofStep`,
   `root()`/`verify()`) — no implementation needed. The unblock is to **surface** it: a
   `gsx_getStateProof(key)` RPC that returns the `Proof` against the current state root (which
   matches the latest header attestation's `stateRoot`), so a relayer can carry
   `{header attestation + inclusion proof}` to the destination. Historical-round proofs need a
   snapshot (`snapshot.rs` exists); latest-header proofs are immediately feasible. (Stale-pin
   cleanup — repoint gsx-dag from `GlobalSettlementNetwork/gsx-db` to `Suwappu-Labs/suwappu-db`
   — is independent and can ride a separate PR.)
2. **Build the SP1 quorum+inclusion circuit (Path C).** A `zkvm/` Rust program reusing
   `gsx_crypto::mldsa::verify` + `gsx_consensus::bridge_header` (the exact preimage) + the new
   `StateTree::verify`. Public-input layout must bind `networkId`, `commitId`, `recipient`,
   `amount`, and the on-chain validator-set root. Add an `Sp1QuorumInclusionVerifier.sol`
   behind the existing `ISourceLockVerifier` seam (drop-in, like the storage-proof verifier).
   Honest NatSpec: trust-minimized, **classical SNARK outer layer → not PQ**.
3. **Path A operational readiness.** Document deploying the destination contracts onto the
   gsx-dag EVM (suwappu-revm) so the real `0x0101`/`0x0102` verify the quorum natively — the
   only both-trust-minimized-and-PQ configuration. Most pieces exist (precompiles registered,
   oracle/registry written); the work is a deploy target + an end-to-end test on a suwappu-revm
   node (the test the anvil mock could not run).
4. **Track EIP-8051 (Path B).** Watch for the first L2 shipping the precompile; if Base/Optimism
   adopt it, a 4.5k-gas-per-sig stock-chain PQ verifier becomes viable without ZK infra.

---

## 4. Honest framing (carry into every PR/comment)

- The **header-attestation loop already shipped** is the interim: trust = an honest >2/3-stake
  validator quorum (sync-committee class). Not trustless, not a proof.
- **Path C (SP1)** upgrades *trust* (removes operator/relayer/quorum-liveness trust) but is
  **classical, not post-quantum** — the BN254 SNARK is Shor-breakable. Never call it
  "end-to-end PQ."
- **Path A (gsx-dag-native precompiles)** is the only path that is **both trust-minimized and
  post-quantum**, and it is the blueprint's stated endgame ("graduate to GSX DAG L1").
- Gap 2 is **closed for external-EVM sources** already (storage proof + SP1 Helios); it is open
  only for the **gsx-dag-native** corridor, where Path A or C closes it.
- **NO-GO for mainnet funds stands** until an independent audit + bug bounty regardless of which
  path ships.

---

## Sources
- [EIP-8051: Precompile for ML-DSA signature verification](https://eips.ethereum.org/EIPS/eip-8051)
- [Dilithium-ZK — Post-Quantum Signatures in Zero Knowledge (SP1)](https://dilithium-zk-landing.vercel.app/)
- [SP1 Testnet — Groth16 ~300k gas, Rust→circuit](https://blog.succinct.xyz/sp1-testnet/)
- [Union.Build — ZK-Powered Consensus Verification (Gnosis OmniBridge, Tendermint-in-SP1 ~200k gas)](https://union.build/blog/consensus-verification)
- [succinctlabs/sp1-helios — on-chain light client in SP1](https://github.com/succinctlabs/sp1-helios)
- [Historical and Multichain Storage Proofs (arXiv:2411.00193) — MPT/keccak ZK-unfriendliness](https://arxiv.org/html/2411.00193v1)
- [Hacken — Quantum-Safe Signatures for Web3: ML-DSA](https://hacken.io/insights/ml-dsa-crystals-dilithium/)
