# pq-quorum-circuit — Track B Phase 1 skeleton

**Attention: @Jacob-Strokus** — this is the scaffold for the hash-based PQ quorum
circuit.  All quorum logic is wired and tested.  Your work starts at the `todo!()` stubs.
Read `§ What is stubbed` and `§ Open problems` before touching anything.

---

## What this is

A compiling, tested scaffold for the bridge's post-quantum quorum verifier.
The **quorum logic** (sorting, dedup, membership, stake threshold) is identical
to the existing ML-DSA path and is **directly reused** from `quorum-core`.
The **signature primitive** is swapped: ML-DSA → leanXMSS (hash-only, no
elliptic curves).

The crate does NOT pull in leanMultisig as a Cargo dep — it references its
types and functions by name in doc comments.  The `todo!()` stubs are where
you wire them up.

---

## Full pipeline

```
gsx-dag validators
  │
  │  [BUILT — quorum-core]
  │  leanXMSS keypairs live alongside ML-DSA keypairs.
  │  xmss_key_gen(seed, start_slot, end_slot, false)
  │    → (XmssSecretKey, XmssPublicKey)
  │      file: leanMultisig/crates/xmss/src/xmss.rs
  │
  │  [BUILT — quorum-core]
  │  Sign bridge header digest (8 KoalaBear FEs = MESSAGE_LEN_FE):
  │  xmss_sign(&mut rng, &sk, &message, slot)
  │    → XmssSignature
  │      file: leanMultisig/crates/xmss/src/xmss.rs
  │
  ▼
Off-chain aggregator (pq-quorum-circuit::aggregate_and_prove — STUB)
  │
  │  [STEP 1 — implement in this crate]
  │  aggregate_single_message_signatures(&[], raws, message, slot, log_inv_rate)
  │    raws: Vec<(XmssPublicKey, XmssSignature)>
  │    → SingleMessageAggregateSignature  (WHIR proof, 98–344 KiB)
  │      file: leanMultisig/crates/rec_aggregation/src/lib.rs
  │
  │  Native verify (non-EVM, for Gate-1):
  │  verify_single_message_aggregate(&agg) → Result<(), ProofError>
  │    file: leanMultisig/src/lib.rs (re-export)
  │
  │  [STEP 2 — the missing wrapping step; see §Open problems]
  │  Recursion circuit: a Spartan-WHIR circuit that takes the
  │  leanMultisig WHIR proof as its statement and outputs a ~10–54 KB blob.
  │
  ▼
sol-spartan-whir EVM verifier  (external, pq-research/sol-spartan-whir)
  │
  │  Entry point:
  │  WhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28::verify(
  │      bytes32 expectedCommitment,
  │      bytes calldata blob     ← the ~54 KB Spartan-WHIR blob
  │  ) external view returns (bool)
  │
  │  Decoded internally by:
  │  WhirBlobCodec5.decode(blob)
  │    → (WhirStructs.WhirStatement, WhirStructs.WhirProof)
  │      file: sol-spartan-whir/src/spartan/SpartanStructs.sol
  │
  │  Gas (MEASURED, 2026-06-09):
  │    80-bit security (quartic lir11):  899,906 gas  ← Phase 1 development target
  │   100-bit security (quintic k22):  5,454,992 gas  ← production bar (amortize ÷4 = 1.36M)
  │
  ▼
On-chain binding (drop-in via setVerifier)
  │
  │  Sp1QuorumVerifier.sol (already built, feat/sp1-quorum-verifier) has the
  │  public-values layout and the validator-set-root binding.
  │
  │  THE DROP-IN POINT:
  │  In Sp1QuorumVerifier.sol, replace:
  │    sp1Verifier.verifyProof(vkey, publicValues, proofBytes)  ← classical Groth16/BN254
  │  with:
  │    whirVerifier.verify(expectedCommitment, blob)            ← hash-only, PQ
  │
  │  setVerifier(address newVerifier) — the contract already has this seam;
  │  confirm the interface in contracts/src/verifiers/Sp1QuorumVerifier.sol.
  │
  │  PublicInputs layout (128 bytes, abi.encodePacked):
  │    [0..32]   networkId          (bytes32)
  │    [32..64]  blockNumber        (uint256 BE)
  │    [64..96]  stateRoot          (bytes32)
  │    [96..128] validatorSetRoot   (bytes32)
  │
  ▼
Header finalized on Base/Ethereum — trustless, end-to-end post-quantum.
```

---

## What is REUSED (unchanged from quorum-core)

| Symbol | Where it lives | Notes |
|--------|---------------|-------|
| `Validator` | `quorum-core/src/lib.rs` | `(pk_hash: [u8;32], stake: u128)` — identical for both paths |
| `keccak256(pubkey_bytes)` | `quorum-core::keccak256` | pkHash — same as Solidity `keccak256(pubkey)` |
| `quorum_threshold(total_stake)` | `quorum-core::quorum_threshold` | `(total*2)/3+1`, overflow-safe saturating math |
| `quorum_reached(sig_stake, total_stake)` | `quorum-core::quorum_reached` | `sig_stake >= threshold` |
| Sorting/dedup invariant | `verify_pq_quorum_stake` (this crate) | Strictly-increasing pkHash, same as `_verifyQuorum` in Solidity |

**What is NOT reused from quorum-core:**
`quorum_core::verify_quorum_stake` hard-codes `mldsa_valid` inside its loop.
We cannot call it for the PQ path.  We re-expressed the same loop in
`verify_pq_quorum_stake`, generic over `HashBasedSigVerify`.  The logic is
identical; only the signature-check call changes.  The `quorum-core` tests
for threshold/dedup/membership are passing (see `src/lib.rs` tests).

---

## What is STUBBED

### 1. `LeanXmssVerify::verify` — one real signature check

```rust
// pq-quorum-circuit/src/lib.rs
pub struct LeanXmssVerify;
impl HashBasedSigVerify for LeanXmssVerify {
    fn verify(&self, _pubkey, _sig, _message, _slot) -> bool {
        todo!("...")
    }
}
```

**To implement:**
1. Add `lean_multisig` as a path-dep (coordinate on dep story first — it uses
   a custom arena allocator and must be `setup_prover()`-initialized once).
2. Deserialise `pubkey` → `XmssPublicKey` and `sig` → `XmssSignature` using
   `postcard` (the same serde leanMultisig uses internally).
3. Encode `message: &[u8; 32]` → `[KoalaBear; MESSAGE_LEN_FE]`.
   **The encoding convention is not yet specified** — this must be pinned and
   documented here.  It is a protocol constant (prover and verifier must agree).
4. Call `xmss_verify(&pk, &encoded_message, &signature, slot)`.

Reference: `leanMultisig/tests/test_multisignatures.rs::test_xmss_signature`
is a working end-to-end example.

### 2. `aggregate_and_prove` — the proving pipeline

```rust
pub fn aggregate_and_prove(_public_inputs, _witness, _log_inv_rate)
    -> Result<(LeanMultisigProof, SpartanWhirBlob), AggregationError>
{
    todo!("...")
}
```

Two sub-steps, see the doc comment in `src/lib.rs` for details:
- **Step 1** (implement this sprint): call `aggregate_single_message_signatures`.
- **Step 2** (the missing recursion): see §Open problems below.

---

## Open problems (the real research)

### Unknown X — the wrapping / recursion step (CRITICAL PATH)

leanMultisig outputs a WHIR proof (~98–344 KiB) in its own proof format
(multilinear / SuperSpartan layout over KoalaBear).  sol-spartan-whir's
EVM verifier accepts a ~10–54 KB Spartan-WHIR blob with a fixed schedule.

**These are different protocols over the same field — they are not currently
interoperable.**  To bridge them you need one of:

1. **Recursion (most likely):** A Spartan-WHIR circuit that verifies a
   leanMultisig WHIR proof as its R1CS statement.  The outer Spartan-WHIR proof
   is the ~10 KB blob the EVM verifier accepts.  Estimated: 2–6 months of
   cryptography-engineering effort.

2. **Direct port:** Extend sol-spartan-whir's Solidity verifier to support the
   SuperSpartan + WHIR-polynomial-stacking variant leanMultisig uses.

3. **leanMultisig EVM verifier:** The EF writes a native Solidity verifier for
   leanMultisig's proof format.  Not on the EF roadmap as of 2026-06-09.

**The key question for Gate-1:** does the outer Spartan-WHIR circuit verifying a
leanMultisig proof fit within 2^22 constraints (~4M)?  If the outer circuit
needs k>22, the gas will exceed 5.45M even before amortization.  Assess this
before committing to recursion.

### Unknown Y — 80-bit vs 100-bit security tradeoff

- 80-bit (quartic, lir11): 899,906 gas — **under budget without amortization**.
  Use as the Phase 1 development target.
- 100-bit (quintic, k22): 5,454,992 gas — **over budget by 3.6×**, but
  1.36M amortized over 4 bridge messages.  The production bar.

The 100-bit path does not fit in a single EIP-170 contract (contract too large);
it needs a split-deploy approach.  Track EIP-8141 (Hegota fork, H2 2026): if
`EXTFIELD_MAC` precompile ships, re-run the sol-spartan-whir benchmark — claimed
~968K gas savings on the quintic path.

### XMSS key state management (operational risk)

leanXMSS is **stateful** — each signing operation advances the slot counter, and
reusing a slot is a catastrophic forgery.  Before validators sign with leanXMSS:
- Design the key-management protocol (persistent state storage, recovery,
  epoch rollover).
- Decide between XMSS (stateful, fast) and SPHINCS+ (stateless, larger sigs).

### Rogue-key / proof-of-possession

Not relevant for the hash-based path itself (leanXMSS keys are Merkle trees,
not group elements; rogue-key attacks require algebraic structure).  Only
matters if there is a classical fallback path that aggregates group-based sigs.

---

## Integration points — exact file/function names

### leanMultisig (`/Users/toma/gsx/pq-research/leanMultisig`)

| Symbol | File |
|--------|------|
| `xmss_key_gen(seed, start_slot, end_slot, false)` | `crates/xmss/src/xmss.rs` |
| `xmss_sign(&mut rng, &sk, &message, slot)` | `crates/xmss/src/xmss.rs` |
| `xmss_verify(&pk, &message, &sig, slot)` | `crates/xmss/src/xmss.rs` |
| `XmssPublicKey`, `XmssSecretKey`, `XmssSignature` | `crates/xmss/src/lib.rs` |
| `MESSAGE_LEN_FE = 8` | `crates/xmss/src/lib.rs` |
| `aggregate_single_message_signatures(&prev, raws, message, slot, rate)` | `crates/rec_aggregation/src/lib.rs` |
| `verify_single_message_aggregate(&agg)` | `src/lib.rs` (re-export) |
| `SingleMessageAggregateSignature::to_bytes() / from_bytes()` | `crates/rec_aggregation` |
| `setup_prover()` | `src/lib.rs` — call once before any proving |
| `AggregationTopology { raw_xmss, children, log_inv_rate, overlap }` | `crates/rec_aggregation/src/benchmark.rs` |

Working example: `tests/test_multisignatures.rs::test_single_message_aggregation`

### sol-spartan-whir (`/Users/toma/gsx/pq-research/sol-spartan-whir`)

| Symbol | File |
|--------|------|
| `WhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28::verify(expectedCommitment, blob)` | `src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifier5_....sol` |
| `WhirBlobVerifierNative4` (lir11, 80-bit) | `src/whir/lir11_.../WhirBlobVerifierNative4_....sol` |
| `WhirBlobCodec5.decode(blob)` | `src/whir/.../WhirBlobCodec5_....sol` |
| `WhirStructs.WhirStatement`, `WhirStructs.WhirProof` | `src/spartan/SpartanStructs.sol` |

### On-chain binding (this repo)

| Symbol | File |
|--------|------|
| `Sp1QuorumVerifier.sol` | `contracts/src/verifiers/Sp1QuorumVerifier.sol` (feat/sp1-quorum-verifier) |
| `GsxDagValidatorRegistry.sol` | `contracts/src/verifiers/GsxDagValidatorRegistry.sol` |
| `publicValues` layout (128 bytes) | `Sp1QuorumVerifier::submitProvenHeader` |

---

## TODO checklist for Jacob

- [ ] **Pin the message encoding** — define how `header_digest: [u8; 32]` maps to
      `[KoalaBear; MESSAGE_LEN_FE]`.  Document it here; it is a protocol constant.
- [ ] **Implement `LeanXmssVerify::verify`** — the one real signature-check call
      (4 steps in the doc comment in `src/lib.rs`).
- [ ] **Add the leanMultisig dep** — decide the workspace/dep story (path-dep from
      outside the repo, or vendor it).  Do not add until the encoding is pinned.
- [ ] **Implement `aggregate_and_prove` Step 1** — call
      `aggregate_single_message_signatures`; verify natively with
      `verify_single_message_aggregate`.  This is Gate-1.
- [ ] **Assess recursion feasibility** — estimate the outer Spartan-WHIR circuit size
      for a leanMultisig proof.  Does it fit in k=22 (~4M constraints)?  This
      determines whether the EVM path is viable.
- [ ] **Implement `aggregate_and_prove` Step 2** — the wrapping / recursion step.
      This is Phase 1 → Phase 2 transition.
- [ ] **Write `PqQuorumVerifier.sol`** — swap `sp1Verifier.verifyProof(...)` for
      `whirVerifier.verify(...)` in the contract.  Reuse the public-values layout
      and the validator-set-root binding verbatim.
- [ ] **Measure end-to-end gas on anvil** — use the 80-bit (quartic) verifier first,
      then the 100-bit (quintic).
- [ ] **Track EIP-8141** — re-run sol-spartan-whir benchmark after Hegota fork.

---

## Running tests

```bash
# From this crate (standalone workspace, no external deps)
cargo test -p pq-quorum-circuit

# Expected: 6 tests pass, all quorum-logic paths covered.
# The crypto stubs (LeanXmssVerify, aggregate_and_prove) are not called by tests.
```

---

## Sources

- [PQ_PHASE0_ASSESSMENT.md](../../docs/security/audits/suwappu/PQ_PHASE0_ASSESSMENT.md) — Gate-0 verdict, gas measurements, the wrapping-step gap
- [PQ_STOCK_EVM_RESEARCH_PLAN.md](../../docs/security/audits/suwappu/PQ_STOCK_EVM_RESEARCH_PLAN.md) — phased plan, architecture, risks
- [leanEthereum/leanMultisig](https://github.com/leanEthereum/leanMultisig) — the zkVM and XMSS implementation
- [privacy-ethereum/sol-spartan-whir](https://github.com/privacy-ethereum/sol-spartan-whir) — the EVM verifier (gas measured)
- [eprint 2025/055 — Hash-Based Multi-Signatures for PQ Ethereum](https://eprint.iacr.org/2025/055.pdf)
- [PSE blog: EVM Verification of WHIR over a 31-bit Field](https://pse.dev/blog/evm-verification-of-whir-31bit)
