/-
# Bandwidth cost model and break-even point (Paper §6.4, Appendix A)

The whitepaper's cost model:

    B_LTP(N)    = D·ρ + D·N      where ρ = n·r/k  (erasure expansion)
    B_direct(N) = D·N

with the claims: the commit cost `D·ρ` is paid **once** regardless of the
number of receivers `N`; a single receiver always costs more than direct
transfer; and the overhead is amortised at `N ≥ ρ` — at the default
parameters (n = 64, k = 32, r = 3), ρ = 6.

This family of claims is where external math review 001 found a critical
error (the expansion factor was stated as `r` = 3 instead of ρ = n·r/k
= 6, shifting the break-even). The fix propagated through §6.4 and
Appendix A; these theorems pin the corrected arithmetic so it cannot
drift back.

Everything is over `Nat`. `D` is the entity size in bytes, `ρ` the
expansion factor, `N` the receiver count.
-/

namespace Suwappu.LTP.Bandwidth

/-- Total bytes moved by an LTP transfer to `N` receivers: one commit at
expansion `ρ`, then one materialization per receiver. -/
def bLTP (D ρ N : Nat) : Nat := D * ρ + D * N

/-- Total bytes moved by `N` direct sender→receiver transfers. -/
def bDirect (D N : Nat) : Nat := D * N

/-! ## Default-parameter arithmetic -/

/-- ρ = n·r/k at the default parameters: 64 · 3 / 32 = 6. Review 001's
critical finding was precisely that this is 6, not r = 3. -/
theorem rho_default : 64 * 3 / 32 = 6 := by decide

/-- The division above is exact (no truncation is hiding in `Nat.div`). -/
theorem rho_default_exact : 32 * 6 = 64 * 3 := by decide

/-- The corrected break-even is *not* the replication factor. Appendix A's
closing line said "break-even: N > r" long after the body was corrected
to ρ; this pins the two apart. -/
theorem rho_default_ne_r : 64 * 3 / 32 ≠ 3 := by decide

/-! ## Structural claims -/

/-- **The commit cost is paid once, regardless of N.** LTP's total cost
is exactly the direct-transfer cost plus a constant (in `N`) commit
overhead `D·ρ`. -/
theorem commit_overhead_constant (D ρ N : Nat) :
    bLTP D ρ N = bDirect D N + D * ρ := by
  simp [bLTP, bDirect]
  omega

/-- **A single receiver always costs more than direct transfer** (for a
nonempty entity and any real expansion, ρ ≥ 1): `B_LTP(1) > B_direct(1)`.
This is §6.4's honest concession — LTP is not a bandwidth win for
point-to-point transfer. -/
theorem single_receiver_costs_more (D ρ : Nat) (hD : 0 < D) (hρ : 0 < ρ) :
    bDirect D 1 < bLTP D ρ 1 := by
  simp [bLTP, bDirect]
  exact Nat.lt_add_of_pos_left (Nat.mul_pos hD hρ)

/-- **Break-even.** The commit overhead is no larger than the useful
transfer volume exactly when `N ≥ ρ` — equivalently, `B_LTP(N)` is within
2× of `B_direct(N)` exactly from the break-even point on. At the default
parameters this is the paper's "break-even occurs at N ≥ ρ = 6 receivers
(not N ≥ r = 3)" — §6.4 was aligned to this inclusive form in v0.2.2. -/
theorem breakeven_iff (D ρ N : Nat) (hD : 0 < D) :
    bLTP D ρ N ≤ 2 * bDirect D N ↔ ρ ≤ N := by
  constructor
  · intro h
    have hmul : D * ρ ≤ D * N := by
      simp [bLTP, bDirect] at h
      omega
    exact Nat.le_of_mul_le_mul_left hmul hD
  · intro h
    have hmul : D * ρ ≤ D * N := Nat.mul_le_mul_left D h
    simp [bLTP, bDirect]
    omega

/-- Amortisation: past break-even, adding receivers only improves the
ratio — the overhead `D·ρ` is fixed while the direct-cost baseline grows.
Stated additively: for `N₁ ≤ N₂`, the *gap* `2·B_direct − B_LTP` is
monotone in `N`. -/
theorem amortisation_monotone (D ρ N₁ N₂ : Nat) (h : N₁ ≤ N₂) :
    2 * bDirect D N₁ + bLTP D ρ N₂ ≤ 2 * bDirect D N₂ + bLTP D ρ N₁ := by
  have : D * N₁ ≤ D * N₂ := Nat.mul_le_mul_left D h
  simp [bLTP, bDirect]
  omega

end Suwappu.LTP.Bandwidth
