import Std
import Lean.Elab.Tactic.Omega

/-
Q76.5 supporting model, Lean 4.34.1 core/Std only.

Closed arithmetic screens are proved here. Representation lemmas explicitly
assume CRT/NTT left inverses. The state lemma assumes a trusted nonrollback
transition. These assumptions are NOT proofs of BGV semantic validity, native
C++ refinement, a signature/RLWE reduction, private timing or deployed release.
No user axioms, admissions or native_decide computation are used.
-/

namespace SharedQuery

structure Profile where
  n : Nat
  d : Nat
  padded : Nat
  levels : Nat
  t : Nat
  eta : Nat
  q : Nat
  p : Nat
  prime0 : Nat
  prime1 : Nat

def small0 : Profile :=
  ⟨16, 3, 4, 2, 11, 1, 1329227995784911300417119789528939649, 33554267,
    1152921504606845473, 1152921504606844513⟩

def small1 : Profile :=
  ⟨32, 5, 8, 3, 19, 1, 1329227995784909824677593892767984513, 33554291,
    1152921504606844417, 1152921504606844289⟩

def large : Profile :=
  ⟨16384, 512, 512, 9, 1031, 21, 1329227995784613643754746428306227201, 33548413,
    1152921504606748673, 1152921504606683137⟩

def ceilDiv (a b : Nat) : Nat := (a + b - 1) / b
def fresh (p : Profile) : Nat := p.t / 2 + p.t * p.eta
def switch (p : Profile) : Nat := p.t * p.eta * p.n * 4 * (2^30 - 1)
def phase (p : Profile) : Nat → Nat
  | 0 => fresh p
  | k + 1 => 2 * phase p k + switch p
def contracted (p : Profile) : Nat := p.n * p.d * fresh p * phase p p.levels
def output (p : Profile) : Nat := contracted p + switch p
def terminal (p : Profile) : Nat :=
  ceilDiv (p.p * output p) p.q + ceilDiv ((p.n + 1) * p.t) 2

def Guards (p : Profile) : Prop :=
  p.padded = 2^p.levels ∧ p.d ≤ p.padded ∧ 2*p.padded ≤ p.n ∧
  2*p.padded < p.t ∧ Nat.gcd p.padded p.t = 1 ∧
  p.q = p.prime0*p.prime1 ∧ Nat.gcd p.prime0 p.prime1 = 1 ∧
  (p.prime0-1) % (2*p.n) = 0 ∧ (p.prime1-1) % (2*p.n) = 0 ∧
  p.p % p.t = p.q % p.t ∧
  (∀ k ∈ List.range (p.levels+1), 2*phase p k < p.q) ∧
  2*output p < p.q ∧ 2*terminal p < p.p

-- Closed kernel reductions, not a sampled phase oracle or a security estimate.
set_option maxRecDepth 20000 in
theorem small0_guards : Guards small0 := by
  unfold Guards
  decide
set_option maxRecDepth 20000 in
theorem small1_guards : Guards small1 := by
  unfold Guards
  decide
set_option maxRecDepth 20000 in
theorem large_guards : Guards large := by
  unfold Guards
  decide
theorem large_terminal : terminal large = 8450122 := by decide

def radix : Nat := 1073741824
def digit (x i : Nat) : Nat := (x / radix^i) % radix

theorem every_digit_bounded (x i : Nat) : digit x i < radix := by
  exact Nat.mod_lt _ (by decide)

-- Four canonical unsigned digits encode any 120-bit whole integer, before
-- either prime lowering. This does not justify independent per-prime digits.
theorem four_digit_reconstruction (x : Nat) (hx : x < 2^120) :
    x % radix + radix*((x/radix) % radix) +
    radix*radix*((x/radix/radix) % radix) +
    radix*radix*radix*((x/radix/radix/radix) % radix) = x := by
  unfold radix
  omega

-- The binary score decoder is unique once valid signed-score semantics hold.
theorem score_injective (d h₀ h₁ : Int) (same : d-2*h₀ = d-2*h₁) : h₀ = h₁ := by
  omega

theorem signed_score_range (d h : Int) (nonnegative : 0 ≤ h) (bounded : h ≤ d) :
    -d ≤ d-2*h ∧ d-2*h ≤ d := by
  omega

-- Actual CRT and negacyclic NTT validity remain explicit refinement premises.
-- The abstract result requires every position and the complete transformed
-- residue object, not a sampled frequency or just one actual prime.
theorem complete_representation_equal
    {q n : Nat} {RNS NTT : Type}
    (lower : Fin q → RNS) (crt : RNS → Fin q)
    (forward : RNS → NTT) (inverse : NTT → RNS)
    (crtValid : ∀ x, crt (lower x) = x)
    (nttValid : ∀ r, inverse (forward r) = r)
    (candidate reference : Fin n → Fin q)
    (completeCheck : ∀ i, forward (lower (candidate i)) = forward (lower (reference i))) :
    ∀ i, candidate i = reference i := by
  intro i
  have residues := congrArg inverse (completeCheck i)
  rw [nttValid, nttValid] at residues
  have whole := congrArg crt residues
  rw [crtValid, crtValid] at whole
  exact whole

theorem deterministic_frame_equal
    {q n : Nat} {Frame : Type}
    (codec : (Fin n → Fin q) → Frame) (candidate reference : Fin n → Fin q)
    (complete : ∀ i, candidate i = reference i) : codec candidate = codec reference := by
  exact congrArg codec (funext complete)

structure State where
  currentPin : Nat
  consumed : List Nat

def Allowed (s : State) (request pin : Nat) : Prop :=
  pin = s.currentPin ∧ request ∉ s.consumed

def consume (s : State) (request : Nat) : State :=
  {s with consumed := request :: s.consumed}

-- This is an abstract nonrollback state transition, not a proof of SQLite,
-- host freshness, crash delivery or an actual protected private callback.
theorem no_second_release (s : State) (request pin : Nat) :
    ¬ Allowed (consume s request) request pin := by
  simp [Allowed, consume]

theorem stale_pin_rejected (s : State) (request pin : Nat) (stale : pin ≠ s.currentPin) :
    ¬ Allowed s request pin := by
  intro admitted
  exact stale admitted.1

end SharedQuery

#print axioms SharedQuery.small0_guards
#print axioms SharedQuery.small1_guards
#print axioms SharedQuery.large_guards
#print axioms SharedQuery.large_terminal
#print axioms SharedQuery.every_digit_bounded
#print axioms SharedQuery.four_digit_reconstruction
#print axioms SharedQuery.score_injective
#print axioms SharedQuery.signed_score_range
#print axioms SharedQuery.complete_representation_equal
#print axioms SharedQuery.deterministic_frame_equal
#print axioms SharedQuery.no_second_release
#print axioms SharedQuery.stale_pin_rejected
