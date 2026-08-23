import Ltp.Counting

/-
# Ramp-scheme entropy bookkeeping (Paper §3.3.5, v0.2.3)

Whitepaper v0.2.1 corrected Theorem 7 (Threshold Secrecy) from a false
zero-leakage claim to a proportional entropy bound, and v0.2.3 named the
construction: LTP's erasure layer is a (0, k; n) *ramp scheme*
(Blakley–Meadows), leaking exactly one symbol's worth of entropy —
log₂ 256 = 8 bits per byte position — per observed shard, with 256^(k−t)
equally-likely candidate coefficient vectors surviving t observations.

This is exactly the kind of corrected arithmetic that drifts back if
nothing pins it (cf. `Ltp/Bandwidth.lean`, which pins the ρ = nr/k
correction from math review 001). The theorems below pin:

  * the entropy ledger — leaked(t) + residual(k, t) = total(k), each
    shard moving exactly 8 bits from one column to the other;
  * the residual at the paper's edge cases — 8 bits at t = k−1 (the
    "one symbol short" discussion), 0 exactly at t = k;
  * the candidate counts — 256^(k−t), halving..., i.e. dividing by 256
    per shard, including the §2.1.1 worked example (k = 2: 65,536
    candidates before any observation, 256 after one shard);
  * the candidates/entropy consistency identity 256^(k−t) = 2^residual;
  * the blinded-ramp trade recorded in §3.3.5 — share size D/(k−t_p),
    reducing to D/k at t_p = 0 (LTP today) and to D (Shamir-style,
    every share as large as the secret) at t_p = k−1, monotone in
    between: privacy threshold is bought with share size.

## What is assumed, what is derived

Nothing probabilistic is formalised here. Theorem 7's probabilistic
content — that the surviving candidates are *equally likely* under a
uniform prior (the Bayes step) — is a pen-and-paper argument in the
paper, out of scope for this Mathlib-free development. What is proved
is the arithmetic scaffolding that every quantitative sentence of
§3.3.5 rests on, so none of those numbers can silently regress.
-/

namespace Suwappu.LTP.Ramp

/-- Bits of entropy carried by one GF(2⁸) symbol: log₂ 256 = 8. -/
def bitsPerSymbol : Nat := 8

/-- Entropy (bits, per byte position) leaked by observing `t` shards. -/
def leaked (t : Nat) : Nat := t * bitsPerSymbol

/-- Residual entropy (bits, per byte position) with `t` of `k` shards
observed. -/
def residual (k t : Nat) : Nat := (k - t) * bitsPerSymbol

/-- Number of coefficient vectors consistent with `t` observed shards:
`256^(k−t)` (Theorem 7's counting argument). -/
def candidates (k t : Nat) : Nat := 256 ^ (k - t)

/-! ## The entropy ledger -/

/-- **The ledger balances.** Leaked plus residual entropy is the joint
entropy `k · 8` — §3.3.5's "exactly t·log₂ 256 bits of the k·log₂ 256-bit
joint entropy … no more, no less" bookkeeping. -/
theorem leak_plus_residual (k t : Nat) (h : t ≤ k) :
    leaked t + residual k t = k * bitsPerSymbol := by
  unfold leaked residual bitsPerSymbol
  omega

/-- **Each shard leaks exactly one symbol.** Observing one more shard
moves exactly `bitsPerSymbol` bits from the residual column to the
leaked column — the "linear ramp" in the ramp-scheme leakage profile. -/
theorem leak_per_shard (k t : Nat) (h : t < k) :
    residual k t = residual k (t + 1) + bitsPerSymbol := by
  unfold residual bitsPerSymbol
  omega

/-- Leakage is monotone in the number of observed shards — more shards
never leak less. -/
theorem leak_monotone (t₁ t₂ : Nat) (h : t₁ ≤ t₂) :
    leaked t₁ ≤ leaked t₂ := by
  unfold leaked bitsPerSymbol
  omega

/-- **Residual entropy hits zero exactly at the threshold.** Below `k`
observed shards there is always residual uncertainty; at `k` there is
none — the entropy-side statement of §4.3's sharp reconstruction
boundary. -/
theorem residual_zero_iff (k t : Nat) (h : t ≤ k) :
    residual k t = 0 ↔ t = k := by
  unfold residual bitsPerSymbol
  omega

/-- **One shard short leaves one symbol of uncertainty.** At `t = k − 1`
the residual is exactly 8 bits per byte position — the quantitative core
of §3.3.5's "practical consequence at t = k−1" discussion. -/
theorem one_short_residual (k : Nat) (h : 1 ≤ k) :
    residual k (k - 1) = bitsPerSymbol := by
  unfold residual bitsPerSymbol
  omega

/-! ## Candidate counting -/

/-- **Each shard divides the candidate set by 256.** The counting form
of `leak_per_shard`. -/
theorem candidates_step (k t : Nat) (h : t < k) :
    candidates k t = 256 * candidates k (t + 1) := by
  unfold candidates
  have hk : k - t = (k - (t + 1)) + 1 := by omega
  rw [hk, Nat.pow_succ, Nat.mul_comm]

/-- At the threshold the candidate set is a singleton — `k` shards
determine the polynomial (unique decoding). -/
theorem candidates_at_threshold (k : Nat) : candidates k k = 1 := by
  unfold candidates
  rw [Nat.sub_self, Nat.pow_zero]

/-- One shard short of the threshold, exactly 256 candidates per byte
position survive — §3.3.5's `256^(k−t) = 256` at `t = k − 1`. -/
theorem candidates_one_short (k : Nat) (h : 1 ≤ k) :
    candidates k (k - 1) = 256 := by
  unfold candidates
  have hk : k - (k - 1) = 1 := by omega
  rw [hk, Nat.pow_one]

/-- **Candidates and residual entropy agree**: `256^(k−t) = 2^residual`.
The counting argument and the entropy bound are the same fact in two
units. -/
theorem candidates_eq_two_pow_residual (k t : Nat) :
    candidates k t = 2 ^ residual k t := by
  unfold candidates residual bitsPerSymbol
  rw [Nat.mul_comm, Nat.pow_mul]

/-- §2.1.1's worked example (`k = 2`), in-kernel: 65,536 equally-counted
`(c₀, c₁)` pairs before any observation… -/
theorem worked_example_pairs : candidates 2 0 = 65536 := by decide

/-- …and exactly 256 after one shard — the 8-bit reduction §3.3.5 uses
to refute the old zero-leakage claim. -/
theorem worked_example_one_shard : candidates 2 1 = 256 := by decide

/-! ## The blinded-ramp trade (§3.3.5, "ramp-scheme characterization")

A `(t_p, k; n)` blinded ramp dedicates `t_p` of the `k` coefficients per
byte position to blinding randomness, so `D` payload bytes need
`D / (k − t_p)` byte positions — and each shard carries one symbol per
position, giving share size `D / (k − t_p)`. -/

/-- Share size of a `(t_p, k; n)` blinded ramp carrying `D` payload
bytes (exact when `(k − t_p) ∣ D`). -/
def shareSize (D k tp : Nat) : Nat := D / (k - tp)

/-- **LTP today is the `t_p = 0` extreme**: shards of size `D / k`,
zero privacy threshold. -/
theorem no_blinding (D k : Nat) : shareSize D k 0 = D / k := rfl

/-- **Shamir sits at the `t_p = k − 1` extreme**: every share is as
large as the payload itself. -/
theorem shamir_extreme (D k : Nat) (h : 1 ≤ k) :
    shareSize D k (k - 1) = D := by
  unfold shareSize
  have hk : k - (k - 1) = 1 := by omega
  rw [hk, Nat.div_one]

/-- The share-size accounting is exact: `shareSize · (k − t_p) = D`
whenever the payload divides evenly — no bytes are lost or smuggled in
by the division. -/
theorem share_cost_exact (D k tp : Nat) (hdiv : (k - tp) ∣ D) :
    shareSize D k tp * (k - tp) = D := by
  unfold shareSize
  exact Nat.div_mul_cancel hdiv

/-- **Privacy threshold is bought with share size**: raising `t_p` never
shrinks the shares. Together with `no_blinding` and `shamir_extreme`
this pins §3.3.5's claim that the `(t_p, k; n)` intermediate points
trade share size against privacy monotonically. -/
theorem blinding_costs_more (D k tp₁ tp₂ : Nat)
    (h₁₂ : tp₁ ≤ tp₂) (h₂ : tp₂ < k) :
    shareSize D k tp₁ ≤ shareSize D k tp₂ := by
  unfold shareSize
  have hb : 0 < k - tp₂ := by omega
  rw [Nat.le_div_iff_mul_le hb]
  calc D / (k - tp₁) * (k - tp₂)
      ≤ D / (k - tp₁) * (k - tp₁) :=
        Nat.mul_le_mul_left _ (by omega)
    _ ≤ D := Nat.div_mul_le_self D (k - tp₁)

end Suwappu.LTP.Ramp
