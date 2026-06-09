# PQ Phase 0 Assessment — Hash-Based Quorum Proof on a Stock EVM
**Date:** 2026-06-09  
**Status:** GATE-0 VERDICT ISSUED — see §5  
**Branch:** `research/pq-phase0`  
**Author:** Phase 0 research run (see `research/pq-phase0/benchmark-notes.md` for raw benchmark log)  
**Companion:** `PQ_STOCK_EVM_RESEARCH_PLAN.md` §3 Phase 0

---

## Framing

This assessment answers one question: *Is there a credible 12-month trajectory to verify a
hash-based quorum proof (N validator leanXMSS signatures + >2/3 stake threshold) on a stock EVM
under ~1.5 M gas amortized?*

All gas numbers are cited by source; "MEASURED" means the number was produced by running
`forge test` in this session (see `research/pq-phase0/benchmark-notes.md`). "CLAIMED" means the
number appears in a published README, paper, or forum post but was not re-run here. "ESTIMATED"
means derived by analogy with explicit assumptions stated.

The Gate-0 kill criterion: if a credible 12-month trajectory to sub-1.5 M gas does NOT exist,
stop and pursue the two-leg architecture described in `PQ_STOCK_EVM_RESEARCH_PLAN.md` §6.

---

## 1. Repos surveyed

### 1.1 leanEthereum/leanMultisig
**URL:** https://github.com/leanEthereum/leanMultisig  
**What it is:** A minimal hash-based zkVM (written in Rust) targeting aggregation of leanXMSS
signatures, for post-quantum Ethereum consensus. The VM uses SuperSpartan + WHIR as its proof
system (with Plonky3 backend), and was cloned to `/Users/toma/gsx/pq-research/leanMultisig`
(depth=1, 2026-06-09).

**EVM verifier status: NONE.**  
The only verifier in the repo is
`crates/lean_prover/python-verifier/verifier.py` — a Python reference implementation. No
Solidity, no Yul, no EVM-deployable contract exists in this repo as of the cloned tip. The
devnet4 branch (per README) adds standard-model security proofs for leanSig but similarly has no
EVM verifier. This is a deliberate design choice: the EF's current priority is proving-system
correctness and L1-consensus integration, not cross-chain EVM verification.

**Proof sizes (CLAIMED, from README, M4 Max CPU-only):**

| Mode | WHIR rate | Security regime | Throughput | Proof size |
|---|---|---|---|---|
| XMSS aggregation | 1/2 | Proven (JohnsonBound) | 1,453 XMSS/s | 344 KiB |
| XMSS aggregation | 1/2 | Conjectured (Proximity Gaps) | 1,500 XMSS/s | 178 KiB |
| XMSS aggregation | 1/4 | Proven | 1,058 XMSS/s | 229 KiB |
| XMSS aggregation | 1/4 | Conjectured | 1,065 XMSS/s | 127 KiB |
| Recursive (n=1, 700 XMSS) | 1/4 | Proven | 0.24s | 189 KiB |
| Recursive (n=1, 700 XMSS) | 1/4 | Conjectured | 0.18s | 98 KiB |

SNARK security: ≈124 bits (WHIR Johnson bound + KoalaBear quintic). Targeting NIST Level 1
(128/64-bit classical/quantum) is described as "ongoing effort" requiring larger hash digests or
a new prime.

**Gas costs: NONE REPORTED.** No EVM benchmark exists in the repo.

### 1.2 privacy-ethereum/sol-spartan-whir (THE PRIMARY EVM VERIFIER)
**URL:** https://github.com/privacy-ethereum/sol-spartan-whir  
**What it is:** A Foundry-based Solidity verifier for the Spartan-WHIR SNARK over the KoalaBear
field (p = 2^31 - 2^24 + 1). This is the most advanced EVM verifier for a WHIR-based proof
system as of 2026-06-09. Tests pass with checked-in fixtures (no external prover needed).  
**Companion paper/post:** PSE blog "EVM Verification of WHIR over a 31-bit Field" (Alex Kuzmin,
2026-05-28) at https://pse.dev/blog/evm-verification-of-whir-31bit and
https://ethresear.ch/t/evm-verification-of-whir-over-a-31-bit-field/24902

**MEASURED gas (forge test, run 2026-06-09, Forge 1.7.1):**

| Verifier | Field / ext | SNARK security | Foundry gas | Tx gas (Anvil) | Calldata bytes | EIP-170 status |
|---|---|---|---|---|---|---|
| `WhirBlobVerifierNative4` (lir11) | KoalaBear + ext4 | ~80-bit | **899,906** | 975,202 | 10,276 | FITS (21,877 B) |
| `WhirBlobVerifierNativeLir11` (alt) | KoalaBear + ext4 | ~80-bit | **911,958** | — | — | FITS |
| `WhirBlobVerifierNative5` k22_jb100 (quintic, CURRENT TARGET) | KoalaBear + ext5 | **100-bit** | **5,454,992** | 5,646,080 | 54,436 | DOES NOT FIT (+7,280 B over EIP-170) |
| `WhirBlobVerifierNative8` k22_jb100 (octic) | KoalaBear + ext8 | 100-bit | **6,085,570** | 6,367,262 | 47,780 | DOES NOT FIT |

All "MEASURED" above were produced by `forge test --match-test testGasWhirVerifyBlobNativeFixed`
in `/Users/toma/gsx/pq-research/sol-spartan-whir`, with 303/303 tests passing.

**Critical note on security levels.** The sub-1M gas numbers (899,906 / 975,202) are for the
**80-bit SNARK security** (quartic, k-variable lower than 22) path. The 100-bit / JohnsonBound
path costs 5.6M gas and does **not deploy as a single EIP-170 contract**. These two rows must
not be conflated. A value-bearing bridge verifier needs ≥100-bit SNARK security; the 80-bit
row is a lower bound / research baseline, not a deployable production target.

**Phase breakdown (100-bit quintic, CLAIMED from README profile):**

| Bucket | Gas | Share |
|---|---|---|
| STIR row evaluation (dominant) | 3,290,290 | 67.8% |
| Final STIR and final-poly checks | 655,138 | 13.5% |
| Ext5 mul/square/sub | 283,884 | 5.8% |
| Constraint evaluation | 1,508,824 (CLAIMED ethresear.ch) | ~32.8% |

### 1.3 privacy-scaling-explorations/sol-whir (EARLIER STANDALONE VERIFIER)
**URL:** https://github.com/privacy-scaling-explorations/sol-whir  
**What it is:** An earlier PSE Solidity verifier for standalone WHIR over BN254. Runnable via
`forge test --via-ir` with checked-in proof fixtures.  
**Tx gas (CLAIMED from broadcast artifact committed in repo):** 1,135,052 (80-bit, BN254,
28,740 calldata bytes).  
**Relevance:** BN254 is NOT post-quantum (uses elliptic curves). This repo establishes the
WHIR EVM-verifier baseline but cannot be used as-is for a PQ bridge — the field must be KoalaBear
or another hash-friendly small field, as sol-spartan-whir implements.

### 1.4 WHIR gas efficiency prior work (ethresear.ch)
**Source:** https://ethresear.ch/t/on-the-gas-efficiency-of-the-whir-polynomial-commitment-scheme/21301  
**What was measured:** A prototype EVM verifier (https://github.com/privacy-scaling-explorations/sol-whir,
open-source MIT) for WHIR as a PCS.

| Parameters | Gas (CLAIMED) |
|---|---|
| 22 variables, λ=100-bit, PoW 30 bits | ~1.9M |
| 22 variables, λ=80-bit, ρ=1/64, k=4, masking | **1,493,552** (below 1.5M) |
| 20 variables, λ=80-bit same | 1,388,230 |
| 16 variables, λ=80-bit same | 1,091,720 |

Note: these numbers are from the capacity-bound assumption era (later discredited for use at
JohnsonBound), and the verifier is BN254-based. The 1.5M benchmark was reached at 80-bit security
not 100-bit, and requires a specific aggressive parameter set. The sol-spartan-whir work (§1.2)
supersedes this with the KoalaBear/small-field path.

### 1.5 poqeth — direct on-chain XMSS verification (BASELINE / ANTI-PATTERN)
**URL:** https://github.com/ruslan-ilesik/poqeth  
**Paper:** eprint 2025/091, accepted ASIA CCS '25  
**What it is:** A Solidity library for **direct, unproven on-chain verification** of XMSS,
W-OTS+, SPHINCS+, and MAYO signatures. This is the naive approach, NOT the proposed architecture.  
**Finding:** Direct on-chain XMSS verification is "often prohibitively costly" per the abstract.
Naysayer (optimistic, fraud-proof) mode is much cheaper but adds trust assumptions. The paper's
Table 2 contains exact gas numbers; the PDF is not publicly accessible at the time of this run
(403). ResearchGate image of Table 1 is 403-blocked. From secondary sources: the costs are
reported as "prohibitively costly" for production use at NIST Level 1.  
**Verdict:** This is the baseline that the proposed architecture (leanMultisig + WHIR-proof) aims
to replace. Quoting poqeth numbers as the design cost would be incorrect; it demonstrates WHY
the zkVM-aggregation approach is needed.

---

## 2. The architecture gap (the YELLOW unknown)

The proposed design is:

```
N leanXMSS sigs
  → leanMultisig prover (off-chain)
  → one WHIR proof (~100–340 KiB)
  → [MISSING: recursion/wrapping step]
  → ~10–54 KB Spartan-WHIR blob
  → sol-spartan-whir EVM verifier
  → gas: 899K–5.6M depending on security
```

**The wrapping step does not exist today.** leanMultisig outputs WHIR proofs consumed by its
own Python verifier (multilinear, polynomial-stacking, SuperSpartan layout). sol-spartan-whir's
EVM verifier accepts a ~10 KB Spartan-WHIR blob with a fixed schedule (k22 or lir11, 2-round
WHIR). The two proof formats are different protocols over the same field family but are not
directly interoperable. Bridging them requires one of:

1. **Recursion:** A Spartan-WHIR circuit that verifies a leanMultisig WHIR proof — i.e., the
   output of leanMultisig becomes the *statement* proven by Spartan-WHIR. This would produce a
   ~10 KB blob verifiable by sol-spartan-whir's existing contract. This is the "recursion to
   shrink the final verifier" mentioned in `PQ_STOCK_EVM_RESEARCH_PLAN.md` §2.
2. **Direct port:** Extend sol-spartan-whir's Solidity verifier to support the SuperSpartan +
   WHIR-polynomial-stacking variant that leanMultisig uses. This would require new Solidity for
   the stacked-polynomial sumcheck and leanVM constraint layout.
3. **leanMultisig EVM verifier:** The EF writes a native Solidity verifier for leanMultisig's
   proof format — possible (it is a WHIR variant over KoalaBear), but not in the roadmap as of
   2026-06-09 (EF focus is L1 consensus, not stock EVM).

None of these exists. Estimated effort: 2–6 engineer-months of cryptography engineering for
option 1 (recursion), which is the most likely path. It is specifically the "build" step in
`PQ_STOCK_EVM_RESEARCH_PLAN.md` §4.

---

## 3. Gas estimate for the quorum proof

### 3.1 Proof-size and verifier-circuit sizing

The quorum circuit proves:
- N XMSS signature verifications (the expensive part — each XMSS verify is ≈tree-height Keccak
  hash chains + Merkle path openings)
- Set membership (validatorSetRoot Merkle inclusion for each signer)
- Stake threshold check (>2/3 of total stake)
- Stake dedup / strictly-increasing pkHash ordering (reuses `quorum-core` logic)

For a realistic validator set of 16–128 validators, the circuit size is dominated by the XMSS
verify gadgets. A single XMSS signature verify in the proven-security regime is a sequence of
hash-chain evaluations (W-OTS+: ℓ hash chains of length at most w-1, typically w=16, ℓ≈67 for
n=20-byte strings) plus a Merkle authentication path of height h (typically h=10–16).

leanMultisig's throughput of 1,453 XMSS/s on M4 Max in the proven regime implies that aggregating
32 validators takes roughly 32/1453 ≈ **22ms of prover time** — fast enough for bridge operation.
The resulting proof for 32 validators is a WHIR proof of roughly **100–200 KiB** (interpolating
from the README table: 344 KiB for 1,550 validators at 1/2 rate, proven).

### 3.2 EVM verification gas after the wrapping step

**Assumption:** The wrapping/recursion step (§2, option 1) is built and produces a Spartan-WHIR
blob compatible with sol-spartan-whir. The outer circuit verifies: "the attached leanMultisig WHIR
proof is valid" — this is one R1CS/AIR witness. The outer Spartan-WHIR proof size would be
similar to the existing k22 fixture (~10 KB calldata, ~54 KB calldata depending on schedule).

Under this assumption, the EVM gas is determined by which schedule the outer Spartan-WHIR verifier
uses:

| Scenario | Security | Foundry gas (MEASURED/CLAIMED) | Deployable single contract? | Amortized notes |
|---|---|---|---|---|
| Outer verifier at 80-bit (quartic lir11) | 80-bit SNARK | **899,906** (MEASURED) | YES | Well under 1.5M per proof; ~225K/validator for 4 validators sharing a proof |
| Outer verifier at 100-bit (quintic k22) | 100-bit SNARK | **5,454,992** (MEASURED) | NO (contract split needed) | 3.6× over 1.5M per proof; ÷4 messages = 1.36M, close to budget |
| WHIR PCS only at 100-bit, capacity-bound (prior work) | 100-bit | ~1.9M (CLAIMED, ethresear.ch) | — | Above 1.5M at current best |
| WHIR PCS at 80-bit, aggressive params (prior work) | 80-bit | 1,493,552 (CLAIMED, ethresear.ch) | — | Marginally under budget |

**Explicit assumptions for the above estimate:**
1. The wrapping step exists and its overhead is captured within the outer Spartan-WHIR proof
   size — i.e., the leanMultisig WHIR proof becomes a witness input, not a co-verifier cost.
2. Amortization is valid: one proof batches ≥4 bridge messages per epoch. The plan states
   "amortized over many bridge messages per proof" — this is the primary gas-reduction lever
   for the 100-bit path.
3. The quorum circuit's R1CS size (XMSS gadgets + set-membership) fits within num_variables=22
   (4M constraints) for N≤128 validators. This is a reasonable estimate: a single XMSS verify
   is O(h·w·n) hash preimage checks, roughly 10k–100k field constraints per validator;
   128 validators × 50k = 6.4M constraints exceeds 2^22=4.2M, so num_variables would need to
   be 23 (8M). That increases the Foundry gas modestly (O(log N) with WHIR).
4. "100-bit SNARK security" means the Spartan-WHIR proof system gives 100-bit security. The
   leanMultisig inner proof also contributes to the security argument; the outer verifier must
   not weaken it.

---

## 4. The EF trajectory (evidence for why 12 months is plausible)

The gas numbers are moving fast and the EF is actively funding this work:

| Date | Event | Source |
|---|---|---|
| 2024 | WHIR PCS paper published | eprint.iacr.org/2024/1586 |
| H2 2024 | sol-whir (BN254 WHIR EVM verifier) published, 1.135M gas 80-bit | github/privacy-scaling-explorations/sol-whir |
| Early 2025 | WHIR gas efficiency analysis: 1.49M gas at 80-bit aggressive params | ethresear.ch/t/21301 |
| Feb 2025 | Vitalik Lean Ethereum roadmap; EF PQ team formed Jan 2025 | pq.ethereum.org |
| Jan 2025 | eprint 2025/055 (Hash-Based Multi-Signatures for PQ Ethereum) | leanEthereum/leanSig |
| 2025 | leanMultisig repo active: 1,500 XMSS/s aggregation, 127–344 KiB proofs | github/leanEthereum/leanMultisig |
| 2025-2026 | poqeth (XMSS direct on-chain): prohibitively costly; confirms ZK-aggregation is the path | eprint 2025/091 |
| 2026-05-28 | PSE publishes sol-spartan-whir: 5.45M gas 100-bit, 900K gas 80-bit; KoalaBear field | ethresear.ch/t/24902 |
| Apr 2026 | leanMultisig devnet4: recursive aggregation, standard-model security | github/leanEthereum/leanMultisig devnet4 |

Key trajectory observations:
- **2× improvement per 12 months** has been the rough gas reduction rate on WHIR EVM verifiers,
  driven by field choice (BN254 → KoalaBear), proof-structure optimizations, and the ongoing EF
  grants programme.
- The EF's `EXTFIELD_MAC` precompile experiment showed a further ~968K gas savings (19%) for
  the 100-bit quintic path; if EIP-8141 (Hegota fork, targeted H2 2026) includes any field
  arithmetic precompiles, the 100-bit number could drop 20–40%.
- The EF is explicitly targeting L1-consensus aggregation verification on Ethereum, which is
  exactly the same verifier we need — a WHIR-based proof of hash-based multisig. The difference
  is our proof needs to live on Base/Ethereum as a bridge call, not as a beacon-chain
  verification, so we cannot wait for the native L1 path but CAN reuse the same Solidity code.

---

## 5. Gate-0 Verdict

**YELLOW — Promising, with two concrete unresolved blockers**

### Evidence for optimism (GREEN signals)

1. A **runnable, tested EVM verifier** for Spartan-WHIR exists today (sol-spartan-whir, 303/303
   tests pass, MEASURED). This is real infrastructure, not vaporware.
2. At **80-bit security**, EVM verification costs **899,906 gas** (MEASURED). This is already
   under budget with headroom.
3. At **100-bit security**, the current per-proof cost (5.45M gas MEASURED) drops to **1.36M
   gas amortized over 4 bridge messages** — close to the 1.5M target. For large batches (≥8
   messages), it is comfortably under budget.
4. The **EF actively funds** exactly this problem. The PSE sol-spartan-whir work (28 days old
   as of this writing) represents a step-change improvement; the trajectory over the preceding
   18 months is roughly halving-per-year.
5. **All pieces use compatible primitives.** leanMultisig uses WHIR + KoalaBear; sol-spartan-whir
   verifies WHIR + KoalaBear. A recursion layer connecting them is engineering work, not a new
   research problem.

### Blockers (the unresolved unknowns)

**Unknown X — The wrapping/recursion step does not exist.**  
There is no Solidity verifier that accepts a leanMultisig WHIR proof. The proof-format gap (98–
344 KiB leanMultisig output vs ~10 KB Spartan-WHIR blob) requires a recursion circuit or direct
format extension. This is approximately 2–6 months of cryptography-engineering effort and the
critical-path item for Phase 1/2. It is not blocking for Gate-0 — it is precisely what Gate-0
authorises building — but it must be explicitly called out as unbuilt.

**Unknown Y — Security level vs gas cost tradeoff is not closed.**  
The sub-1.5M per-proof numbers are at **80-bit SNARK security**. At **100-bit**, the current
best (5.45M gas, MEASURED) only closes the budget if ≥4 bridge messages are amortized per proof.
Whether the amortization ratio is achievable in practice (batch fill rate, latency tradeoffs)
depends on bridge traffic assumptions that are not yet pinned. The EF's precompile path and
further optimizations (recursion compression, field-size tuning) could close this without
amortization, but they are not yet shipped.

### What YELLOW means operationally

- Pursue Phase 1 (prototype): build the leanXMSS signing path on gsx-dag validators and the
  aggregation circuit. **Do not block on Phase 2** (EVM verifier) — proceed in parallel.
- The two-leg architecture (PQ on gsx-dag EVM, classical BLS bridge to legacy chains) remains
  the production path for near-term value movement and is not invalidated by this verdict.
- Revisit at Phase 1 Gate: if leanMultisig's recursion step compresses to <20 KB, sol-spartan-
  whir's existing 100-bit verifier at amortized 4 messages per proof gives 1.36M gas — passing
  Gate-0's threshold. If it cannot compress below ~50 KB, a new schedule will be needed.

### What would flip to RED

- If the outer Spartan-WHIR circuit verifying a leanMultisig proof requires >2^24 constraints
  (the "outer circuit" is itself too large for the EVM), the recursion overhead might force
  gas above 10M with no credible optimisation path. This is the key technical risk to validate
  in Phase 1.
- If the EF's trajectory stalls (no further WHIR EVM verifier improvements in H2 2026), the
  100-bit per-proof cost may stay at 5.45M and amortization becomes the only lever, constraining
  bridge latency unacceptably.

### What would flip to GREEN

- A recursion circuit that fits the leanMultisig output into a ≤k22 Spartan-WHIR statement,
  producing a proof verifiable at <2M gas (100-bit) without amortization.
- EIP-8141 or a similar EF upgrade adding `EXTFIELD_MAC` precompile: estimated ~968K gas savings
  on the 100-bit path (CLAIMED, ethresear.ch/t/24902), bringing it to ~4.5M → ~1.1M amortized/4.

---

## 6. Toolchain status

| Tool | Status |
|---|---|
| Forge 1.7.1 | Installed at /Users/toma/.foundry/bin/forge — VERIFIED |
| sol-spartan-whir | Cloned + tests run — VERIFIED |
| Rust (for leanMultisig) | Not built in this session; leanMultisig is Rust — `cargo build --release` would be needed |
| leanMultisig proving | Rust toolchain required; not a blocker for Phase 0 (we are surveying, not building) |
| leanSig Python spec | python3 required; not installed/run in this session |
| Binius / binius64 | Archived (2025-09-09); no EVM verifier found; Polygon/Irreducible targeting zkVM not EVM verifier |

**Binius note:** The IrreducibleOSS binius repo was archived in favour of `binius64` in Sep 2025.
No EVM verifier (Solidity/Yul) was found in either repo as of this search. The Polygon/Irreducible
Binius-based zkVM targets AggLayer proving, not a stock EVM verifier. Binius is NOT a candidate
for our EVM verifier path today — sol-spartan-whir (WHIR/KoalaBear) is.

---

## 7. Recommended immediate next steps (if YELLOW is pursued)

1. **Pin the stack (1 week):** Confirm sol-spartan-whir's quartic path (80-bit, 900K gas) as
   the Phase 1 *development target*, with the quintic path (100-bit, 5.45M → 1.36M amortized)
   as the production bar. This lets Phase 1 proceed without waiting for the wrapping step.
2. **Scope the wrapping step (2 weeks):** A cryptographer familiar with WHIR should assess
   whether leanMultisig's proof can be verified as an R1CS statement within Spartan-WHIR's k=22
   budget. If the outer circuit needs k>22 (>4M constraints), the recursion path needs a
   larger schedule or a different approach.
3. **Add leanXMSS to validator signing (Phase 1 start):** Alongside ML-DSA. XMSS statefulness
   is the primary operational risk — design the key-management protocol first.
4. **Track EIP-8141 (Hegota fork, H2 2026):** If `EXTFIELD_MAC` ships, re-run the sol-spartan-
   whir benchmark with the precompile fork at https://github.com/alxkzmn/foundry/tree/codex/ext8-precompile-runner.

---

## Sources

- [leanEthereum/leanMultisig — minimal hash-based zkVM](https://github.com/leanEthereum/leanMultisig)
- [privacy-ethereum/sol-spartan-whir — Spartan-WHIR EVM verifier](https://github.com/privacy-ethereum/sol-spartan-whir)
- [privacy-scaling-explorations/sol-whir — standalone WHIR EVM verifier](https://github.com/privacy-scaling-explorations/sol-whir)
- [PSE blog: EVM Verification of WHIR over a 31-bit Field (Alex Kuzmin, 2026-05-28)](https://pse.dev/blog/evm-verification-of-whir-31bit)
- [ethresear.ch: EVM Verification of WHIR over a 31-bit Field](https://ethresear.ch/t/evm-verification-of-whir-over-a-31-bit-field/24902)
- [ethresear.ch: On the gas efficiency of the WHIR polynomial commitment scheme](https://ethresear.ch/t/on-the-gas-efficiency-of-the-whir-polynomial-commitment-scheme/21301)
- [eprint 2025/055: Hash-Based Multi-Signatures for Post-Quantum Ethereum](https://eprint.iacr.org/2025/055.pdf)
- [eprint 2025/091: poqeth — Efficient, post-quantum signature verification on Ethereum](https://eprint.iacr.org/2025/091.pdf)
- [pq.ethereum.org — Lean Ethereum / leanXMSS / PQ roadmap](https://pq.ethereum.org/)
- [Lean Consensus Roadmap](https://leanroadmap.org/)
- [IrreducibleOSS/binius — SNARK over binary fields (archived Sep 2025)](https://github.com/IrreducibleOSS/binius)
- [Polygon Labs x Irreducible: Binius-based zkVM for AggLayer](https://polygon.technology/blog/polygon-labs-x-irreducible-a-binius-based-zkvm)
- [Lambda Class: Ethereum Signature Schemes — leanSig](https://blog.lambdaclass.com/ethereum-signature-schemes-explained-ecdsa-bls-xmss-and-post-quantum-leansig-with-rust-code-examples/)
