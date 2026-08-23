# LTP Lean proofs

Machine-checked proofs about the LTP corridor bridge and the whitepaper's
arithmetic claims, in Lean 4.

```bash
formal/lean/verify.sh        # build + hole scan + axiom audit
scripts/verify.sh formal     # same, via the repo's lane runner
```

No Mathlib. The development depends on Lean 4 core only — the counting
lemmas it needs are ~40 lines, and a Mathlib dependency would put a
multi-gigabyte download in front of every CI run for no gain in proof
strength. A cold `lake build` takes seconds.

## What is proved

| Theorem | File | Claim |
|---|---|---|
| `corridor_intersection` | `Ltp/Quorum.lean` | Any two 7-of-9 attestations share ≥ 5 signers |
| `corridor_safety` | `Ltp/Quorum.lean` | With ≤ 4 Byzantine super-nodes, any two attestations share an **honest** signer — so two conflicting attestations cannot both be valid |
| `corridor_liveness` | `Ltp/Quorum.lean` | With ≤ 2 unavailable super-nodes, a quorum is still formable |
| `commitment_size_payload_independent` | `Ltp/Commitment.lean` | The on-chain commitment size does not depend on the payload (Paper §10.2 / DAG Invariant 3) |
| `strict_total_unsatisfiable` | `Ltp/Commitment.lean` | No valid envelope totals the pinned 1,600 B — see below |
| `lattice_key_size_payload_independent` | `Ltp/LatticeKey.lean` | The sealed lattice key is the same size for a 1 KB and a 1 TB entity — the whitepaper's O(1) sender→receiver claim (Paper §2.2, §3.3.7) |
| `sealed_768_min` / `sealed_768_max` / `sealed_768_bounded` | `Ltp/LatticeKey.lean` | The ML-KEM-768 sealed key is 1,220–1,250 B for the specified policy range, within the advertised ~1,300 B |
| `record_exceeds_1kb` | `Ltp/LatticeKey.lean` | A record carrying an ML-DSA-65 signature (3,309 B, FIPS 204) can never be "< 1 KB" — pins the corrected §2.1.3 size claim |
| `rho_default` / `breakeven_iff` | `Ltp/Bandwidth.lean` | ρ = n·r/k = 6 at defaults, and B_LTP ≤ 2·B_direct ⟺ N ≥ ρ — the §6.4 break-even where math review 001 found a critical error |
| `commit_overhead_constant` | `Ltp/Bandwidth.lean` | The commit cost D·ρ is paid once, independent of receiver count |
| `no_index_privileged` / `at_threshold_decodable` / `below_threshold_undecodable` | `Ltp/Erasure.lean` | Any k shards suffice, no index is privileged, and the k / k−1 failure boundary is sharp (Paper §4.3) — derived from the MDS threshold shape, which is assumed (see the file header) |
| `loss_budget` / `decodable_monotone` | `Ltp/Erasure.lean` | Losing up to n−k shards is survivable; losing shards never helps |
| `permits_antitone_count` / `one_time_exhausts` | `Ltp/Policy.lean` | The §2.2.1 access-policy count check cannot wedge, and one-time keys are one-time |
| `minimal_is_sound` | `Ltp/Policy.lean` | The mandated fail-closed mode ("reject any policy other than unrestricted") never over-grants |
| `attenuate_no_amplify` | `Ltp/Policy.lean` | Macaroon-style attenuation never grants what the parent policy denies (the §8.4 capability claim) |
| `supermajority_safety` / `supermajority_liveness` | `Ltp/Governance.lean` | Classical BFT bounds for §5.1 governance: two 2/3 supermajorities share an honest voter when < n/3 are Byzantine; < n/3 unavailable still leaves a supermajority |
| `safety_bound_tight` | `Ltp/Governance.lean` | Concrete counterexample at exactly n/3 Byzantine — the hypothesis cannot be weakened to ≤ |
| `vector1_matches` / `vector2_matches` / `vector2_framing` | `Ltp/TestVectors.lean` | Both §2.1.1 interoperability test vectors recomputed in-kernel over a from-scratch GF(2⁸) (0x11D) and `decide`d byte-for-byte — the paper, the Lean kernel, and `src/ltp/erasure.py` are three independent computations agreeing on the same constants |
| `leak_plus_residual` / `leak_per_shard` / `one_short_residual` | `Ltp/Ramp.lean` | §3.3.5's corrected entropy ledger: t shards leak exactly t·8 bits per byte position, each shard moves exactly one symbol of entropy, and t = k−1 leaves exactly 8 bits — pins the Theorem 7 correction (v0.2.1) the way `Bandwidth.lean` pins the ρ correction |
| `candidates_step` / `candidates_at_threshold` / `candidates_eq_two_pow_residual` | `Ltp/Ramp.lean` | The 256^(k−t) candidate count: divided by 256 per shard, a singleton at t = k, and consistent with the entropy bound (256^(k−t) = 2^residual) — §2.1.1's k = 2 worked example (65,536 → 256 after one shard) is `decide`d in-kernel |
| `no_blinding` / `shamir_extreme` / `blinding_costs_more` | `Ltp/Ramp.lean` | The §3.3.5 (t_p, k; n) blinded-ramp trade: LTP today is the t_p = 0 extreme (shares D/k), Shamir is t_p = k−1 (shares as large as the payload), and privacy threshold is bought monotonically with share size |

Plus the generic forms (`quorum_intersection_general`) so the results are
not specific to 7-of-9, and the counting lemmas they rest on.

### Why this, and not Verifpal

[`docs/FORMAL_VERIFICATION_STATUS.md`](../../docs/FORMAL_VERIFICATION_STATUS.md)
records the corridor threshold quorum as **out of reach** for the existing
symbolic model — *"Verifpal doesn't natively model threshold
signatures"* — and lists a Tamarin/ProVerif model of the 7-of-9 flow as
wanted work. The quorum guarantee is a counting argument, which is what a
proof assistant is for. These proofs cover that specific gap; they do not
replace the symbolic model, which covers confidentiality and
authentication properties Lean says nothing about here.

### The 1,600 B discrepancy

`ON_CHAIN_COMMITMENT_BYTES = 1_600` matches no actual field layout:

- ML-KEM-768: `1088 + 96 + 32 = 1216`
- ML-KEM-1024: `1568 + 96 + 32 = 1696`

`src/ltp/corridor/envelope.py` already says this in prose and marks
`assert_strict_total()` as a forward-compatibility stub. The proofs pin it
as a checked fact (`strict_total_unsatisfiable`), along with where 1,600
appears to have come from (`provenance_of_1600`: it is the ML-KEM-**1024**
ciphertext plus the SHA3 root, with the aggregate signature dropped and
the ciphertext mislabeled as ML-KEM-768).

The invariant that actually matters — payload independence — is true and
proved. Only the specific number is wrong.

## What is NOT proved — read this before citing these results

**These are proofs about a model, not about the implementation.** The
model is a few dozen lines of Lean; `src/ltp/` is thousands of lines of
Python and Solidity. Nothing here is extracted to, or mechanically linked
with, the running code. Specifically out of scope:

- **That the Python matches the model.** `attestation.py` counting
  distinct signers, rejecting duplicate witnesses, and verifying PoPs is
  asserted by the model's shape, not verified against the code. The
  binding is by review and by the CI trigger on `constants.py`.
- **Cryptographic soundness.** BLS aggregate-signature unforgeability,
  ML-KEM IND-CCA2, ML-DSA EUF-CMA — all assumed. A signer "signing" is an
  uninterpreted predicate. Rogue-key resistance comes from the PoP
  requirement (LTP-A-015), which is a protocol-level mitigation this model
  does not analyse.
- **That an honest node signs at most one attestation per slot.** This is
  an *assumption* of `corridor_safety`, discharged operationally (an
  honest implementation does not equivocate), not proved.
- **Liveness under partition, timing, or DoS.** No temporal or network
  model here at all.
- **Everything the symbolic model covers** — confidentiality,
  authentication, the Dolev-Yao attacker. Different tool, different file.
- **The MDS property itself.** `Ltp/Erasure.lean` derives the paper's
  operational claims *from* the k-of-n threshold shape; that the
  GF(2⁸) Vandermonde code actually has that shape is assumed there
  (hypothesis `hmds`), evidenced by `tests/test_erasure.py` and external
  math review 002 — not proved in Lean.
- **Policy enforcement in the SDK.** `Ltp/Policy.lean` proves the
  *algebra* is sound; whether `src/ltp/` implements `permits` is a
  code-review question.

The honest summary: this converts the corridor's quorum arithmetic and
commitment-size invariant from prose claims into machine-checked ones. It
does not verify the bridge.

## Layout

```
formal/lean/
  lakefile.lean        package (no dependencies)
  lean-toolchain       pinned Lean version
  Ltp.lean             root import
  Ltp/Counting.lean    countP lemmas, proved from core
  Ltp/Quorum.lean      corridor quorum safety + liveness
  Ltp/Commitment.lean  constant-size commitment
  Ltp/LatticeKey.lean  constant-size sealed lattice key + record size
  Ltp/Bandwidth.lean   §6.4 cost model and break-even
  Ltp/Erasure.lean     k-of-n reconstruction threshold consequences
  Ltp/Policy.lean      access-policy algebra (attenuation, fail-closed)
  Ltp/Governance.lean  2/3-supermajority BFT bounds
  Ltp/TestVectors.lean §2.1.1 test vectors recomputed over GF(2⁸)
  Ltp/Audit.lean       #print axioms for every headline theorem
  verify.sh            build + hole scan + axiom audit
```

## Why `verify.sh` and not just `lake build`

A file containing `sorry` compiles — with a warning that is easy to lose
in CI output. `verify.sh` adds two gates on top of the build: it scans
sources for `sorry`/`admit` (excluding comments, since this README and
`Audit.lean` both discuss the word), and it checks that no theorem depends
on `sorryAx`, which catches a hole reached through any import. The gate is
negative-tested: adding a `sorry` makes it exit non-zero.

Expected axiom base is at most Lean's standard three
(`propext`, `Classical.choice`, `Quot.sound`); today the proofs use only
`propext` and `Quot.sound`, and several are axiom-free.
