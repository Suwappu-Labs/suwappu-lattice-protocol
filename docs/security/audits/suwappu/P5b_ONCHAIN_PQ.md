# P5b — On-Chain Post-Quantum Signature Verification: Engineering Decision Doc

Date: 2026-06-07
Goal: Replace LTP-A-001 (trust-the-off-chain-relayer) so that **no mint/unlock/finalize happens without an on-chain-verified ML-DSA-65 (FIPS 204) check bound to the exact bridged commit.**
Chains: home = Suwappu DAG (Rust DAG L1 we control, can add precompiles); destinations = EVM mainnets we do NOT control (Ethereum L1, Base, Arbitrum, HyperEVM).

## 0. TL;DR

- **Home (Suwappu DAG):** native ML-DSA-65 **Rust precompile**. Cheap (~8–12k gas), trivially FIPS-204 PQ-sound, verifier already in-tree (genesis keygen uses ML-DSA). Ship first. **Effort S.**
- **EVM direct verifier:** real and exists (ZKNox ETHDILITHIUM) but **~5M (Keccak-substituted) to ~8M+ gas (faithful SHAKE)** at the benchmarked parameter set. Fits a 30M block but economically dead on L1 mainnet; viable on cheap L2s. Unaudited; the cheap variant is not standard FIPS 204.
- **ZK proof-of-verification:** the standard SP1/RISC0/Plonky3 on-chain path wraps the hash-based STARK in a **Groth16/PLONK SNARK over BN254** → **Shor-broken → NOT PQ-sound end-to-end.** The ~270k-gas "PQ verify" is an illusion. A hash-based-only (FRI) STARK verified directly on EVM is multi-million-gas split across many txs (StarkWare SHARP) — not a per-bridge-tx verify.
- **Only demonstrated end-to-end on-chain PQ** (hash-based STARK + PQ sig, no pairing wrapper) is the Solana study (eprint 2025/1741), feasible only because Solana gives ~1.4M CU/tx + a SHA-256 syscall, and even then chunked across many txs. No EVM equivalent.
- **SLH-DSA (FIPS 205):** hash-only verify, natively PQ, likely the cheapest *standardized PQ-sound no-wrapper* on-chain verify (~sub-1M gas for 128s) — but 7.8–17KB+ sigs are calldata-heavy and it's a different scheme than ML-DSA.

**Bottom line:** End-to-end on-chain PQ is feasible **now on the home chain** via precompile. On EVM destinations it is **not** cleanly feasible today for ML-DSA-65 at L1 economics; the realistic destination story is (a) verify on Suwappu DAG and bridge a Suwappu DAG consensus attestation, and/or (b) a direct ETHDILITHIUM-style verifier on cheap L2s as hardening. **The relayer-trust problem (LTP-A-001) bites hardest at mint on the destination EVM chain — exactly where you cannot add a precompile — so the destination guarantee is transitive-through-consensus, not local, until the standard matures.**

## 1. Direct ML-DSA-65 verification gas on EVM

ML-DSA verify = expand A (SHAKE128), recompute w, hash challenge c (SHAKE256), NTT/INTT mults mod q=8380417, norm/hint checks. Cost centers on the **XOF (SHAKE)** and the **NTT**.

Real measured implementation — **ZKNox ETHDILITHIUM** (only credible Solidity ML-DSA verifier; experimental, *not audited*):

| Variant | Gas | Notes |
|---|---|---|
| `Dilithium` (faithful FIPS 204, SHAKE) | **~8.1M** | passes NIST ML-DSA KAT |
| `ETHDilithium` (Keccak-substituted XOF + pubkey precompute) | **~4.9M** | passes a *modified* KAT — **NOT standard FIPS 204** |

ZKNox separately reports reducing a prior Solidity NTT from **20M → 1.5M gas**; after that the **hash/XOF dominates**.

Assumption flag: unclear whether ZKNox benchmarks are ML-DSA-44 (EIP-8051 references level II) or already ML-DSA-65; if level-II, scale ~1.4–1.8× for 65 → ~7M (Keccak) to ~12M+ gas (SHAKE). Verdict unchanged: multi-million gas. **L1:** ~0.1–0.3 ETH/action — economically dead. **L2:** cents-to-low-dollars — feasible as hardening.

Sources: https://github.com/ZKNoxHQ/ETHDILITHIUM · https://zknox.eth.limo/posts/2025/03/21/ETHFALCON.html · https://eips.ethereum.org/EIPS/eip-8051

## 2. SHAKE256/Keccak — why it dominates

ML-DSA uses **SHAKE128/256** (XOFs over Keccak-f[1600]). EVM exposes **KECCAK256** opcode but **NOT SHAKE/raw Keccak-f** (different padding/rate) → must implement Keccak-f[1600] in bytecode, the expensive part. EIP-8051 confirms SHAKE256 is expensive on EVM precisely because `Keccak_f` has no opcode; ETHDILITHIUM's cheap variant swaps SHAKE for a Keccak256-precompile PRNG (4.9M) vs faithful SHAKE (8.1M). After NTT optimization the XOF is the dominant term.

Sources: https://eips.ethereum.org/EIPS/eip-8051 · https://eips.ethereum.org/EIPS/eip-7667

## 3. ZK proof-of-verification — and the PQ trap

Run ML-DSA verify in a zkVM off-chain, verify a succinct proof on-chain. **Hard constraint: the proof system itself must be PQ-sound.**

A production ML-DSA-in-SP1 verifier exists (~22s proofs, ~260-byte on-chain proof). **The trap:** SP1/RISC0/Plonky3 STARKs are FRI/hash-based internally but the standard **on-chain** path wraps the STARK in a **Groth16/PLONK SNARK over BN254** for the ~270k-gas verify — **BN254 is Shor-broken → the wrapper defeats PQ.** A 270k-gas SP1-Groth16 "PQ verify" is **NOT PQ-sound end-to-end** and must not back the bold claim.

Staying hash-based to the chain (verify FRI STARK directly on EVM) = multi-million gas split across many txs (StarkWare SHARP amortizes one proof over ~220K rollup txs) — not a per-bridge-action verify. The only demonstrated end-to-end hash-based on-chain PQ is on **Solana** (eprint 2025/1741: SLH-DSA + Winterfell STARK bound via SHA-256, no SNARK wrapper, exploiting ~1.4M CU/tx + a sha256 syscall, chunked). No EVM equivalent.

Sources: https://docs.succinct.xyz/docs/sp1/security/security-model · https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types · https://blog.zksecurity.xyz/posts/stark-evm-adapter/ · https://docs.starknet.io/learn/protocol/sharp · https://eprint.iacr.org/2025/1741

## 4. SLH-DSA (FIPS 205) as the on-chain signature instead

Hash-based ⇒ verification is only hash calls, natively PQ, no NTT. Sizes: 128s = 7,856 B sig / 32 B pk; 192s = 16,224 B / 48 B (≈ML-DSA-65 strength); 256s = 29,792 B. On EVM: calldata for 192s ≈ 16,224 × ~16 ≈ ~260K gas (blobs don't help — verifier needs bytes in EVM memory); compute = thousands of hash calls. Net likely sub-1M gas for 128s — cheaper than direct ML-DSA's 5–8M, but 5–10× the calldata and a **different scheme** than ML-DSA-65. The scheme that actually got verified fully on-chain end-to-end (Solana).

Sources: https://en.wikipedia.org/wiki/SPHINCS+ · https://csrc.nist.gov/pubs/fips/205/final

## 5. Suwappu DAG precompile (home chain) — confirmed correct

Add a native **ML-DSA-65 verify precompile** in Rust wrapping the existing in-tree verifier (suwappu-dag already uses ML-DSA in genesis keygen).
- **PQ-soundness:** native FIPS 204 ML-DSA-65, no SNARK, no scheme substitution. **Full, no caveats.**
- **Gas to set:** EIP-8051 prices an ML-DSA-44 precompile at ~4,500 gas; set Suwappu DAG ML-DSA-65 to ~**8,000–12,000 gas** (heavier params + DoS-underprice margin, then benchmark/tighten). ~1000× cheaper than the Solidity verifier; native Rust does real SHAKE256.
- **Bind to the exact commit:** `ML-DSA-65.Verify(pk, msg = canonical_commit_encoding, sig)` with `pk` pinned to the validator/committee key in consensus. This is the LTP-A-001 fix.

Source: https://eips.ethereum.org/EIPS/eip-8051. **Effort S.**

## 6. Recommendation matrix

| Chain class | Recommended path | Rough gas | PQ-soundness | Effort |
|---|---|---|---|---|
| **Suwappu DAG (home)** | Native ML-DSA-65 Rust precompile, bound to exact commit + pinned key | **~8–12k** | **Full FIPS 204, no caveat** | **S** |
| **EVM L2 (Base/Arbitrum/HyperEVM)** | Direct ETHDILITHIUM verifier (hardening) OR trust Suwappu DAG attestation | ~7–12M (65); ~5M Keccak | SHAKE variant PQ-sound but unaudited; Keccak variant not FIPS 204 | M code / L audit |
| **EVM L1 (Ethereum)** | **Do NOT direct-verify per tx.** Bridge a Suwappu DAG consensus attestation; verify that cheaply | attestation ≪ 100k | Transitive through Suwappu DAG consensus (see caveat) | M–L |

**Rejected:** SP1-Groth16 (~270k gas) — BN254 wrapper is Shor-broken, would let us *claim* on-chain PQ without having it.

**Attestation caveat (L1/L2 destinations):** bridging "Suwappu DAG verified this ML-DSA sig" reduces destination trust to Suwappu DAG's consensus/light-client proof. For *that* to be PQ-sound, Suwappu DAG's consensus signatures presented to the destination (BLS today) must eventually be PQ too — otherwise we've MOVED, not eliminated, the non-PQ link. Acceptable as a staged posture, **but document honestly: on EVM destinations the PQ guarantee is currently transitive through Suwappu DAG, not local — and destination mint is exactly where LTP-A-001 hurts most.**

### Phased rollout
- **Phase 1 (ship now, S):** Suwappu DAG ML-DSA-65 precompile; wire Vault/MintAdapter/Escrow finalize/mint/unlock to call it with `msg = canonical commit encoding`, `pk` pinned in consensus. After this the bold claim is **literally true on Suwappu DAG** and LTP-A-001 is closed for home-chain custody.
- **Phase 2:** Suwappu DAG light-client/attestation verifier on EVM destinations; mints accepted only against proof the home-chain precompile verified the commit. Document the transitive PQ property.
- **Phase 3 (optional, L2 first):** audited ETHDILITHIUM-style direct verifier as defense-in-depth; faithful-SHAKE (true FIPS 204, ~8M+) vs Keccak variant; consider SLH-DSA dual-signing.
- **Phase 4:** track EIP-8051 toward L1; if an ML-DSA precompile lands on a destination, direct-verify economics flip from dead to trivial.

## BUILD PROGRESS (2026-06-07) — decision: Phase 1+2+3, honest layered claim

**Phase 1 core SHIPPED & locally verified:** new crate `suwappu-dag/crates/suwappu-mldsa-precompile`
implements `verify(pubkey||sig||message) -> 32-byte EVM word` wrapping the same
`pqcrypto-mldsa` ML-DSA-65 verifier `suwappu-crypto` uses. `cargo test -p suwappu-mldsa-precompile`
= **8/8 green** against real FIPS-204 keys (sizes pk=1952/sig=3309, valid accepted,
tampered msg/sig/wrong-key/truncated/empty all correctly handled, no panic). Genuinely
PQ-sound — no SNARK wrapper. Reusable by both the suwappu-revm EVM precompile AND the
suwappu-dag intent-handler path.

**Remaining Phase 1:** thin suwappu-revm registration adapter (`Precompile::new(PrecompileId::custom("MLDSA65_VERIFY"), 0x0101, run_fn)`, gas ~8–12k) — CI-verified (cold revm build can't run locally). End-to-end mint/unlock/finalize wiring is **blocked on the EVM-integration PRs #25-31** landing on suwappu-dag main (EVM not yet enabled there). Until then, the intent-handler path can enforce the check.

**Phase 2 (attestation verifier on EVM destinations)** and **Phase 3 (audited ETHDILITHIUM direct verifier on L2s)** — not yet started; sequence after Phase 1 wiring + the EVM substrate lands.

**Claim posture (chosen):** "PQ-secured settlement on Suwappu DAG (on-chain FIPS-204 ML-DSA-65); off-chain transport/attestation PQ (ML-KEM-768/ML-DSA-65); EVM-destination bridges inherit PQ transitively via Suwappu DAG consensus." NOT a flat "the bridge is post-quantum."

## VERDICT
Ship a native ML-DSA-65 Rust precompile on Suwappu DAG — that makes end-to-end on-chain FIPS-204 PQ verification real and cheap NOW for home-chain custody. On EVM destinations local on-chain PQ is NOT cleanly feasible today (direct ML-DSA-65 ≈ 5–12M gas / ~0.1–0.3 ETH on L1; the cheap SP1-Groth16 shortcut is Shor-broken), so the destination PQ guarantee must be carried transitively via a Suwappu DAG attestation until an ML-DSA precompile or affordable hash-based STARK/SLH-DSA-on-EVM path matures.
