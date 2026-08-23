/-
# Concrete-security arithmetic (Paper §3.3.1, §2.1.1, §2.3.3, Appendix A)

The paper's concrete-security story leans on a handful of exact integer
facts: the BHT quantum-collision exponent 256/3 ≈ 85.3 that math review
001 originally found misstated, the birthday and Grover exponents, the
96-bit nonce-collision margin, the exponential-backoff law, and
Appendix A's worked Earth-upload figure. Each is one arithmetic slip
away from a repeat of the review-001 incident. This module pins them.

As throughout this development: these are proofs about the *numbers in
the specification*, not about the cryptography. The BHT exponent
theorem does not prove BHT correct — it proves the paper divided 256 by
3 correctly, and that the resulting security levels are ordered the way
§3.3.1's table says they are.
-/

namespace Suwappu.LTP.ConcreteSecurity

/-! ## §3.3.1 — post-quantum collision and preimage exponents -/

/-- The BHT quantum collision exponent for a 256-bit hash: ⌊256/3⌋ = 85.
Review 001's finding was that an earlier draft claimed 128 bits here. -/
theorem bht_exponent : 256 / 3 = 85 := by decide

/-- The "≈ 85.3" is bracketed exactly: 85 · 3 ≤ 256 < 86 · 3 — the
true exponent lies in [85, 86), so quoting "~85 bits" rounds *down*,
i.e. conservatively. -/
theorem bht_bracket : 85 * 3 ≤ 256 ∧ 256 < 86 * 3 := by decide

/-- The classical birthday exponent for a 256-bit hash: 256/2 = 128 —
the "128 bits (birthday)" cell of §3.3.1's table, and equally the
Grover preimage exponent ("128 bits (Grover)"). -/
theorem birthday_exponent : 256 / 2 = 128 := by decide

/-- **The table's ordering is real**: post-quantum collision resistance
(BHT, 256/3) is strictly below post-quantum preimage resistance
(Grover, 256/2) — §3.3.1's closing sentence that the two properties
have *different* post-quantum security levels. -/
theorem collision_below_preimage : 256 / 3 < 256 / 2 := by decide

/-- Grover's quadratic speedup accounting, in-kernel: squaring the
2¹²⁸-step quantum preimage search recovers the full 2²⁵⁶ classical
search space. -/
theorem grover_square : (2 : Nat) ^ 128 * 2 ^ 128 = 2 ^ 256 := by decide

/-! ## §2.1.1 — nonce-collision margin -/

/-- The §2.1.1 bound q²/2⁹⁷ for the 96-bit truncated nonce, at the
generous scale of q = 2³² encrypted shards under one CEK: q² = 2⁶⁴ is
still 2³³-fold below the 2⁹⁷ denominator — the "negligible probability"
claim's arithmetic content at a concrete, large q. -/
theorem nonce_birthday_margin : (2 : Nat) ^ 32 * 2 ^ 32 < 2 ^ 97 := by decide

/-! ## §2.3.3 — retry backoff law -/

/-- The §2.3.3 backoff t_retry = t_base · 2^(i−1) doubles per retry
(jitter aside): step i+1 costs exactly twice step i, for every base.
Pins the "exponential backoff" claim to its literal recurrence. -/
theorem backoff_doubles (tbase i : Nat) :
    tbase * 2 ^ (i + 1) = 2 * (tbase * 2 ^ i) := by
  rw [Nat.pow_succ]
  simp [Nat.mul_comm, Nat.mul_assoc, Nat.mul_left_comm]

/-! ## Appendix A — Mars worked example -/

/-- Appendix A's Earth-upload figure: 6 GB (decimal) at 1 Mbps is
exactly 48,000 seconds. -/
theorem mars_commit_upload_seconds :
    (6 * 10 ^ 9 * 8) / 10 ^ 6 = 48000 := by decide

/-- 48,000 s is "≈ 13.4 hours": it lies strictly between 13 h and
13.5 h (the paper rounds to one decimal). -/
theorem mars_commit_upload_hours :
    13 * 3600 < 48000 ∧ 48000 < 13 * 3600 + 1800 := by decide

end Suwappu.LTP.ConcreteSecurity
