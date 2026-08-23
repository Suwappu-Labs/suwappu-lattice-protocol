/-
# Correlated-failure availability arithmetic (Paper §5.4.1, §5.4.1.1)

External math review 002 hand-verified §5.4.1.1's correlated failure
model: the per-replica identity p_replica = p_d + (1−p_d)·p_n
= p_d + p_n − p_d·p_n, the cross-region worked figure 0.0595³ ≈ 2.1×10⁻⁴,
and the same-region anti-pattern figure ≈ 0.01012. This module puts the
same facts inside the kernel, so the reviewed numbers cannot drift.

Probabilities are represented as scaled integers: a probability p
becomes `a` with denominator `S` (p = a/S), products acquire denominator
S², and every identity is stated additively — Lean's truncated `Nat`
subtraction makes `x + c = y` the honest form of `x = y − c`.

The two general identities:

  * `replica_complement` — (1 − p_replica) = (1 − p_d)(1 − p_n), the
    complement form of §5.4.1.1's per-replica failure probability, as a
    polynomial identity over any scale S;
  * `replica_two_forms`  — p_d + (1 − p_d)·p_n = p_d + p_n − p_d·p_n,
    the equality of the two ways §5.4.1.1 writes p_replica (the same
    lemma instantiated at b := p_nʳ gives the same-region worst-case
    form p_d + (1 − p_d)·p_nʳ).

The worked numbers (S = 10⁴, p_d = 0.01 → 100, p_n = 0.05 → 500):
the 595 scaled p_replica, 595³ = 210,644,875 with its ≈ 2.1×10⁻⁴
bracketing, the ≈ 0.99979 per-shard availability, the same-region
1,012,375 (≈ 0.01012), and the ≥ 48× penalty for same-region
colocation that motivates the `minimum_regions ≥ 3` genesis rule.
-/

namespace Suwappu.LTP.Availability

/-- **Complement identity.** Over any scale `S`, with `a = p_d·S` and
`b = p_n·S`: (S−a)(S−b) + (aS + bS) = S² + ab — i.e., dividing by S²,
(1 − p_replica) = (1 − p_d)(1 − p_n) with
p_replica = p_d + p_n − p_d·p_n. §5.4.1.1's per-replica failure law in
its complement form: a replica survives iff its domain survives AND the
node itself survives. -/
theorem replica_complement (S a b : Nat) (ha : a ≤ S) (hb : b ≤ S) :
    (S - a) * (S - b) + (a * S + b * S) = S * S + a * b := by
  calc (S - a) * (S - b) + (a * S + b * S)
      = (S - a) * (S - b) + (a * ((S - b) + b) + b * ((S - a) + a)) := by
        rw [show S - b + b = S from by omega, show S - a + a = S from by omega]
    _ = ((S - a) + a) * ((S - b) + b) + a * b := by
        simp [Nat.mul_add, Nat.add_mul, Nat.mul_comm, Nat.mul_left_comm,
              Nat.add_comm, Nat.add_left_comm, Nat.add_assoc]
    _ = S * S + a * b := by
        rw [show S - a + a = S from by omega, show S - b + b = S from by omega]

/-- **The paper's two expressions for p_replica agree.** Additively:
aS + (S−a)·b + ab = aS + bS — i.e., p_d + (1−p_d)·p_n = p_d + p_n − p_d·p_n
after dividing by S². Instantiating `b := p_nʳ` (scaled) gives the
same-region worst-case form p_d + (1−p_d)·p_nʳ of §5.4.1.1. -/
theorem replica_two_forms (S a b : Nat) (ha : a ≤ S) :
    a * S + ((S - a) * b + a * b) = a * S + b * S := by
  rw [← Nat.add_mul, show S - a + a = S from by omega, Nat.mul_comm S b]

/-! ## Worked example (S = 10⁴: p_d = 0.01 → 100, p_n = 0.05 → 500) -/

/-- p_replica at the worked parameters: (100·10⁴ + 500·10⁴ − 100·500)/10⁴
= 595, the paper's 0.0595. -/
theorem replica_default :
    (100 * 10 ^ 4 + 500 * 10 ^ 4 - 100 * 500) / 10 ^ 4 = 595 := by decide

/-- The cross-region shard-unavailability numerator: 595³ = 210,644,875
(denominator 10¹²). -/
theorem cross_region_cube : 595 ^ 3 = 210644875 := by decide

/-- The paper's "≈ 2.1 × 10⁻⁴" is bracketed exactly:
2.10×10⁻⁴ ≤ 595³/10¹² < 2.11×10⁻⁴. -/
theorem cross_region_bracket :
    210 * 10 ^ 6 ≤ 595 ^ 3 ∧ 595 ^ 3 < 211 * 10 ^ 6 := by decide

/-- The paper's "≈ 0.99979" per-shard cross-region availability:
0.99978 ≤ 1 − 595³/10¹² < 0.99980. -/
theorem cross_region_avail_bracket :
    99978 * 10 ^ 7 ≤ 10 ^ 12 - 595 ^ 3 ∧
    10 ^ 12 - 595 ^ 3 < 9998 * 10 ^ 8 := by decide

/-- The same-region anti-pattern numerator: 0.01 + 0.99·0.05³ scaled by
10⁸ is 10⁶ + 99·125 = 1,012,375 — the paper's ≈ 0.01012 (it lies in
[0.01012, 0.01013)). -/
theorem same_region_worst :
    10 ^ 6 + 99 * 125 = 1012375 ∧
    1012 * 10 ^ 3 ≤ 1012375 ∧ 1012375 < 1013 * 10 ^ 3 := by decide

/-- **Colocation is ≥ 48× worse.** On the common 10¹² denominator, the
same-region unavailability (1,012,375·10⁴) exceeds 48 times the
cross-region one (595³) — the quantitative teeth behind §5.4.1.1's
"stark difference" and the genesis rule `minimum_regions ≥ 3`. -/
theorem colocation_penalty : 48 * 595 ^ 3 < 1012375 * 10 ^ 4 := by decide

end Suwappu.LTP.Availability
