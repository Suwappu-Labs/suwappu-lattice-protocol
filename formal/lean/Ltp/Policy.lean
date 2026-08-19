/-
# Access-policy algebra (Paper §2.2.1)

The lattice key carries an access policy:

    { "type": "unrestricted" | "one-time" | "time-limited" | "delegatable",
      "not_before": …, "not_after": …,
      "max_materializations": …, "delegate_to": [...] }

with the normative rules: the receiver MUST verify that the current time
falls within [not_before, not_after] and that the materialization count
does not exceed max_materializations; and *"implementations that do not
support policy enforcement MUST reject any policy with type other than
unrestricted"*.

Four properties the paper relies on but never argues:

1. `permits_antitone_count` — having materialized *fewer* times never
   revokes access (the count check is monotone, so enforcement state
   can't wedge).
2. `one_time_exhausts` — a one-time key really is one-time.
3. `minimal_is_sound` — the mandated fail-closed behaviour of a
   non-enforcing implementation is *safe*: it never grants access a
   fully-enforcing implementation would deny. This is the actual safety
   content of that MUST, formalised.
4. `attenuate_no_amplify` — macaroon-style attenuation (§10.4's comparison
   to capability systems): tightening a policy's window or count bound
   never grants access the original denied. Delegation that only
   attenuates cannot amplify authority.

Time and counts are `Nat`. `none` for a bound means "unbounded", matching
the optional JSON fields.
-/

namespace Suwappu.LTP.Policy

/-- The four policy types of §2.2.1. -/
inductive PolicyType where
  | unrestricted
  | oneTime
  | timeLimited
  | delegatable
  deriving DecidableEq, Repr

/-- An access policy. Absent optional fields are `none`. -/
structure Policy where
  ptype : PolicyType
  notBefore : Option Nat
  notAfter : Option Nat
  maxMaterializations : Option Nat
  deriving Repr

/-- An optional lower bound, `none` = unbounded. -/
def lowerOk : Option Nat → Nat → Bool
  | none, _ => true
  | some lo, now => decide (lo ≤ now)

/-- An optional upper bound, `none` = unbounded. -/
def upperOk : Option Nat → Nat → Bool
  | none, _ => true
  | some hi, now => decide (now ≤ hi)

/-- An optional count bound: `count` prior materializations exhaust a
`some m` bound once `count ≥ m`. -/
def countOk : Option Nat → Nat → Bool
  | none, _ => true
  | some m, count => decide (count < m)

/-- Full enforcement, §2.2.1: time window and materialization count. -/
def permits (p : Policy) (now count : Nat) : Bool :=
  lowerOk p.notBefore now && upperOk p.notAfter now
    && countOk p.maxMaterializations count

/-- The mandated degraded mode: an implementation that does not support
policy enforcement MUST reject any policy with type other than
`unrestricted`. (For an `unrestricted` policy it still honours the
window/count fields if present — rejecting more is always allowed.) -/
def permitsMinimal (p : Policy) (now count : Nat) : Bool :=
  match p.ptype with
  | .unrestricted => permits p now count
  | _ => false

/-! ## 1. Count-monotonicity -/

/-- `countOk` is antitone in the count. -/
theorem countOk_antitone (b : Option Nat) (c₁ c₂ : Nat)
    (hc : c₁ ≤ c₂) (h : countOk b c₂ = true) : countOk b c₁ = true := by
  cases b with
  | none => rfl
  | some m => simp [countOk] at h ⊢; omega

/-- Having materialized fewer times never turns a grant into a denial:
if the policy permits at count `c₂`, it permits at any `c₁ ≤ c₂`. -/
theorem permits_antitone_count (p : Policy) (now c₁ c₂ : Nat)
    (hc : c₁ ≤ c₂) (h : permits p now c₂ = true) :
    permits p now c₁ = true := by
  unfold permits at h ⊢
  rw [Bool.and_eq_true, Bool.and_eq_true] at h ⊢
  exact ⟨h.1, countOk_antitone _ _ _ hc h.2⟩

/-! ## 2. One-time is one-time -/

/-- A policy with `max_materializations = 1` denies after a single
materialization, at every time. -/
theorem one_time_exhausts (p : Policy) (now count : Nat)
    (h1 : p.maxMaterializations = some 1) (hcount : 1 ≤ count) :
    permits p now count = false := by
  unfold permits
  simp [countOk, h1]
  omega

/-! ## 3. The degraded mode is fail-closed, hence sound -/

/-- **A non-enforcing implementation never over-grants.** Whatever the
minimal implementation permits, full enforcement also permits — so the
§2.2.1 MUST ("reject any policy with type other than unrestricted") makes
degraded implementations *safe*, not merely compliant. -/
theorem minimal_is_sound (p : Policy) (now count : Nat)
    (h : permitsMinimal p now count = true) :
    permits p now count = true := by
  unfold permitsMinimal at h
  cases hp : p.ptype <;> simp [hp] at h <;> first | exact h | exact h.elim

/-! ## 4. Attenuation cannot amplify -/

/-- `q` attenuates `p` when every bound in `q` is at least as tight:
the window is narrower and the count budget is no larger. This is the
partial order under which macaroon-style delegation operates (§10.4). -/
def Attenuates (q p : Policy) : Prop :=
  (∀ lo, p.notBefore = some lo → ∃ lo', q.notBefore = some lo' ∧ lo ≤ lo')
    ∧ (∀ hi, p.notAfter = some hi → ∃ hi', q.notAfter = some hi' ∧ hi' ≤ hi)
    ∧ (∀ m, p.maxMaterializations = some m →
        ∃ m', q.maxMaterializations = some m' ∧ m' ≤ m)

/-- **Attenuation never grants what the parent denies.** If the
attenuated policy `q` permits an action, the original `p` permits it
too — delegating a capability can only shrink authority. The whitepaper
stakes its §10.4 capability-system comparison on exactly this shape and
never states it; here it is. -/
theorem attenuate_no_amplify (q p : Policy) (hatt : Attenuates q p)
    (now count : Nat) (h : permits q now count = true) :
    permits p now count = true := by
  obtain ⟨hlo, hhi, hm⟩ := hatt
  unfold permits at h ⊢
  rw [Bool.and_eq_true, Bool.and_eq_true] at h
  obtain ⟨⟨hqlo, hqhi⟩, hqc⟩ := h
  rw [Bool.and_eq_true, Bool.and_eq_true]
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · cases hplo : p.notBefore with
    | none => rfl
    | some lo =>
      obtain ⟨lo', hq, hle⟩ := hlo lo hplo
      simp [lowerOk, hq] at hqlo
      simp [lowerOk]
      omega
  · cases hphi : p.notAfter with
    | none => rfl
    | some hi =>
      obtain ⟨hi', hq, hle⟩ := hhi hi hphi
      simp [upperOk, hq] at hqhi
      simp [upperOk]
      omega
  · cases hpm : p.maxMaterializations with
    | none => rfl
    | some m =>
      obtain ⟨m', hq, hle⟩ := hm m hpm
      simp [countOk, hq] at hqc
      simp [countOk]
      omega

end Suwappu.LTP.Policy
