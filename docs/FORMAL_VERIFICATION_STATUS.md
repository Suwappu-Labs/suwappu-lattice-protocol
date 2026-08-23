# Formal Verification Status

What's verified, by what tool, and what's not — for outside cryptographic reviewers.

## What's in `docs/formal/`

| Artifact | Tool | Status |
|---|---|---|
| [`ANALYSIS.md`](formal/ANALYSIS.md) | (overview doc) | Methodology, attacker model, cryptographic abstractions, query list, **and recorded results as of 2026-08-16** |
| [`etp-protocol.vp`](formal/etp-protocol.vp) | Verifpal v0.27.4 | Symbolic model of the 3-phase COMMIT / LATTICE / MATERIALIZE protocol. **Run 2026-08-16**: 2 of 4 queries verified, 2 replay findings — see below. |
| [`verifpal-run-2026-08-16.md`](formal/verifpal-run-2026-08-16.md) | Verifpal v0.27.4 | Recorded output of the first verification run |
| [`../formal/lean/`](../formal/lean/) | Lean 4 (core, no Mathlib) | **Machine-checked.** Corridor 7-of-9 quorum safety + liveness, constant-size commitment **and sealed-lattice-key** invariants, §6.4 bandwidth break-even, erasure k-of-n threshold consequences, access-policy algebra, 2/3-supermajority BFT bounds, both §2.1.1 test vectors recomputed in-kernel over GF(2⁸), the §3.3.5 ramp-scheme entropy ledger (leakage/candidate-count arithmetic and the blinded-ramp share-size trade), and the §3.3.1 concrete-security integers (BHT/birthday/Grover exponents, nonce margin, backoff law). 82 audited theorems. Gated in CI by `.github/workflows/formal.yml`. |

## Machine-checked (Lean 4)

Added 2026-08-15 to cover the threshold-quorum gap this document itself
identified as out of reach for Verifpal; extended 2026-08-16 to the
whitepaper's arithmetic claims (sealed-key size, bandwidth break-even,
erasure threshold, policy algebra, governance supermajority) as part of
the publication pass. Run `formal/lean/verify.sh`. Headline theorems
(full table in [`../formal/lean/README.md`](../formal/lean/README.md)):

| Theorem | Claim |
|---|---|
| `corridor_intersection` | Any two 7-of-9 attestations share ≥ 5 signers (`7 + 7 - 9`) |
| `corridor_safety` | With ≤ 4 Byzantine super-nodes, any two attestations share an **honest** signer — two conflicting attestations cannot both be valid |
| `corridor_liveness` | With ≤ 2 unavailable super-nodes a quorum is still formable; note the asymmetry (safety tolerates 4, liveness only 2) |
| `commitment_size_payload_independent` | On-chain commitment size is independent of payload — the operative content of Paper §10.2 |
| `strict_total_unsatisfiable` | No valid envelope totals the pinned `ON_CHAIN_COMMITMENT_BYTES = 1_600`; ML-KEM-768 gives 1,216 and ML-KEM-1024 gives 1,696 |
| `lattice_key_size_payload_independent` | The sealed lattice key is the same size whatever entity it unlocks — the whitepaper's O(1) sender→receiver claim, machine-checked (added 2026-08-16) |
| `sealed_768_bounded` / `record_exceeds_1kb` | ML-KEM-768 sealed key stays ≤ 1,300 B; a record with an ML-DSA-65 signature can never be "< 1 KB" |
| `rho_default` / `breakeven_iff` | ρ = n·r/k = 6 at defaults and the §6.4 break-even N ≥ ρ — the arithmetic where math review 001 found a critical error |
| `no_index_privileged` / `at_threshold_decodable` / `below_threshold_undecodable` | Paper §4.3's sharp k-of-n boundary and "no shard index privileged", derived from the assumed MDS threshold shape |
| `permits_antitone_count` / `one_time_exhausts` / `minimal_is_sound` / `attenuate_no_amplify` | §2.2.1 access-policy algebra: count checks can't wedge, one-time is one-time, the mandated fail-closed mode never over-grants, attenuation never amplifies |
| `supermajority_safety` / `supermajority_liveness` | §5.1 governance BFT bounds (2/3 supermajority, < n/3 Byzantine), with a tightness counterexample at exactly n/3 |
| `leak_plus_residual` / `leak_per_shard` / `candidates_eq_two_pow_residual` | §3.3.5's corrected entropy ledger: t shards leak exactly t·8 bits per byte position, one symbol per shard, with 256^(k−t) surviving candidates = 2^residual — pins the Theorem 7 correction (added 2026-08-23) |
| `no_blinding` / `shamir_extreme` / `blinding_costs_more` | §3.3.5's (t_p, k; n) blinded-ramp trade: LTP is the t_p = 0 extreme, Shamir the t_p = k−1 extreme, privacy threshold bought monotonically with share size |

The proofs use no `sorry` (CI enforces this via an axiom audit, and the
gate is negative-tested). **They are proofs about a model, not about
`src/ltp/`** — cryptographic soundness is assumed, and nothing is
extracted to the running code. Read
[`formal/lean/README.md`](../formal/lean/README.md#what-is-not-proved--read-this-before-citing-these-results)
before citing them.

## The Verifpal model was first run on 2026-08-16

Until 2026-08-16 this section warned that the model had been **written
but never run**. It has now been run (Verifpal 0.27.4, built from
source; the model needed corrections to pass Verifpal's model checks at
all — change log at the top of `etp-protocol.vp`). Results, with the
attacker as the standard Dolev-Yao active adversary (unbounded sessions,
fresh values, full message-modification capability):

| Property | Verifpal query | Outcome |
|---|---|---|
| CEK confidentiality | `confidentiality? cek` | ✅ **Verified** |
| Content confidentiality | `confidentiality? content` | ✅ **Verified** |
| Commitment authentication | `authentication? Sender -> Receiver: commitment` | ❌ Fails — attacker can (re)deliver the signed record; delivery is unauthenticated (the signature itself holds) |
| Sealed key authentication | `authentication? Sender -> Receiver: sealed_key` | ❌ Fails — **cross-session replay**: no freshness or receiver binding on the sealed key |

The confidentiality results are conditional on authentic identity-key
distribution (the model guards the pre-protocol key exchange — the same
assumption `ANALYSIS.md` always made in prose). The sealed-key replay
finding corroborates the KEM ciphertext-binding gap disclosed in
whitepaper §3.3; the planned mitigation (receiver-key fingerprint +
entity_id in the sealed key's AEAD associated data) is recorded in
[`formal/ANALYSIS.md`](formal/ANALYSIS.md) and the whitepaper. Full
traces: [`formal/verifpal-run-2026-08-16.md`](formal/verifpal-run-2026-08-16.md).

## What is NOT in scope of the symbolic model

The Verifpal model intentionally abstracts these components — they are outside the symbolic verifier's reach and must be argued by other means:

| Out-of-scope component | Why | Where it's addressed |
|---|---|---|
| ML-KEM-768 reduction | Verifpal has no native KEM primitive; we model it as DH, which has equivalent confidentiality guarantees in the symbolic setting but a different concrete reduction | NIST FIPS 203, plus `tests/test_acvp_mlkem.py` against ACVP test vectors |
| ML-DSA-65 reduction | Modeled as a generic SIGN primitive | NIST FIPS 204, plus `tests/test_acvp_mldsa.py` |
| Erasure coding `k-of-n` threshold | Information-theoretic; the symbolic model cannot express "any `k` shares determine the secret, any `k-1` do not" | `tests/test_erasure.py` plus the entropy-bound proof in `docs/WHITEPAPER.md` §3.3.5 and the Lean threshold theorems (`at_threshold_decodable` / `below_threshold_undecodable`) |
| Side-channel resistance of the implementation | Symbolic verifiers don't model timing or power channels | `docs/security/audits/internal/SECURITY_REVIEW-2-24-2026.md` §4, plus the `assert_bls_production()` gate in `src/ltp/bls.py` that blocks the unaudited `py_ecc` keygen fallback under `LTP_ENV=production` |
| Commitment-network topology | Shard placement, retrieval, gossip — infrastructure-level, not protocol-level | `docs/THREAT_MODEL.md` §3 (Threat Sources) and §4.D (DoS) |

## Other formal artifacts

The following adjacent reviews have already been published:

| Document | What it covers |
|---|---|
| [`security/audits/internal/SECURITY_REVIEW-2-24-2026.md`](security/audits/internal/SECURITY_REVIEW-2-24-2026.md) | Formal security review of the full protocol and implementation, dated 2026-02-24 |
| [`security/audits/internal/001-lattice-key-shard-exposure.md`](security/audits/internal/001-lattice-key-shard-exposure.md) | Attack-chain analysis of the lattice-key shard exposure surface, with Option A-D mitigation comparison |
| [`security/audits/external/whitepaper-reviews/001/001-Mathematical-Review.md`](security/audits/external/whitepaper-reviews/001/001-Mathematical-Review.md) | Math review #1 (2026-03-19) — flagged 3 critical errors; all resolved per review #2 |
| [`security/audits/external/whitepaper-reviews/002/002-Mathematical-Review.md`](security/audits/external/whitepaper-reviews/002/002-Mathematical-Review.md) | Math review #2 (2026-03-27) — confirms prior errors fixed; 5 open issues for future work |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | STRIDE + PQC-specific threat model |

## How to run the symbolic verification yourself

```bash
# Verifpal 0.27.4 — the last Go release. The Rust 1.0 rewrite changed
# the model syntax (PUBKEY/DH_KEX instead of G^), so build the tag the
# model targets. `go install` of the bare module path no longer works.
git clone --branch v0.27.4 https://github.com/symbolicsoft/verifpal
cd verifpal && go build -o verifpal ./cmd/verifpal

# run from the repo root
./verifpal verify docs/formal/etp-protocol.vp
```

Expected output as of 2026-08-16: both confidentiality queries pass
(absent from the failed-query summary); both authentication queries fail
with the replay traces recorded in
[`formal/verifpal-run-2026-08-16.md`](formal/verifpal-run-2026-08-16.md).
Open an issue with the `verifpal-output` label if you see anything
*different from that*, so we can update the documented status.

## What would strengthen the case

Items the maintainers know are missing and welcome contributions on:

- ~~Running the Verifpal model and recording the output~~ — done 2026-08-16; the next cheapest item is now re-running it once the sealed-key AAD binding lands, to confirm the replay finding closes
- ~~A **Tamarin** or **ProVerif** model of the corridor 7-of-9 BLS attestation flow~~ — the *quorum* half of this is now covered by the Lean proofs above. A symbolic model is still wanted for the parts Lean does not touch: aggregate-signature unforgeability under a Dolev-Yao attacker, and the PoP exchange (LTP-A-015)
- A **Certora** prover spec for `LTPAnchorRegistry.sol` covering sequence monotonicity, entity-signer binding, and the UUPS upgrade-admin gate
- A **`hypothesis`**-based fuzz harness for `src/ltp/corridor/wire.py` deserialization (one shipped in PR #8 as `tests/test_corridor_wire_validation.py` but it's table-driven; property-based would catch more edge cases)
- A side-channel evaluation of the `py_ecc` keygen path, or a contributed Rust binding for an audited constant-time KEM library

If you're a cryptographic reviewer reading this and want a longer evidence pack, file an issue with the `formal-review-request` label and reference the property you want strengthened.
