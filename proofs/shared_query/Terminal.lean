import Std
import Lean.Elab.Tactic.Omega

/-
Q78 supporting integer model for the unchanged Q77 terminal boundary.

The native scaler first produces an unwrapped integer congruent modulo t,
then emits its canonical residue modulo P. That second operation is NOT
componentwise congruence modulo t. The phase argument must retain the paired
Q/P wrap and establish the actual centered-phase bounds separately.

These four assertions prove integer facts, not C++ refinement, noise/origin
validity, privacy, crash-safe consumption, attestation or production security.
No existing Model.lean assertion is recompiled by importing it here.
-/

namespace SharedQueryTerminal

-- Signed weights cover one negacyclic coefficient when native indexing and
-- full coverage refine this finite dot product. That refinement stays open.
def signedDot : List Int → List Int → Int
  | x :: xs, s :: ss => x * s + signedDot xs ss
  | _, _ => 0

-- Core/Std-only complete aligned relation; neither list can omit a component
-- supplied by the other. Native array/secret coverage remains a separate gate.
inductive ComponentwiseMod (t : Int) : List Int → List Int → Prop where
  | nil : ComponentwiseMod t [] []
  | cons {x y : Int} {xs ys : List Int}
      (same : x % t = y % t) (rest : ComponentwiseMod t xs ys) :
      ComponentwiseMod t (x :: xs) (y :: ys)

theorem signed_dot_congr {t : Int} {xs ys : List Int}
    (components : ComponentwiseMod t xs ys)
    (secret : List Int) :
    signedDot xs secret % t = signedDot ys secret % t := by
  induction components generalizing secret with
  | nil => cases secret <;> rfl
  | @cons x y xs ys same rest ih =>
    cases secret with
    | nil => rfl
    | cons s ss =>
      change (x * s + signedDot xs ss) % t = (y * s + signedDot ys ss) % t
      rw [Int.add_emod (x * s) (signedDot xs ss) t,
          Int.add_emod (y * s) (signedDot ys ss) t,
          Int.mul_emod x s t, Int.mul_emod y s t, same, ih ss]

-- This is the unwrapped integer rounded*t + residue in Query::terminal,
-- before mpz_fdiv_ui(..., P). It holds for any integer rounding choice.
theorem unwrapped_rounding_congr (t x rounded : Int) :
    (rounded * t + x % t) % t = x % t := by
  simp [Int.add_emod]

-- The caller must establish the actual paired lift and centered bounds.
-- Merely checking P % t = Q % t does not establish these premises.
theorem wrapped_terminal_preserves_message
    (t q p oldRaw roundedRaw phaseQ phaseP wrap : Int)
    (moduli : q % t = p % t)
    (unwrapped : oldRaw % t = roundedRaw % t)
    (oldLift : oldRaw = phaseQ + q * wrap)
    (newLift : roundedRaw = phaseP + p * wrap) :
    phaseQ % t = phaseP % t := by
  have difference : (oldRaw - q * wrap) % t = (roundedRaw - p * wrap) % t := by
    rw [Int.sub_emod oldRaw (q * wrap) t,
        Int.sub_emod roundedRaw (p * wrap) t,
        Int.mul_emod q wrap t, Int.mul_emod p wrap t, unwrapped, moduli]
  have oldDifference : oldRaw - q * wrap = phaseQ := by omega
  have newDifference : roundedRaw - p * wrap = phaseP := by omega
  rw [oldDifference, newDifference] at difference
  exact difference

def q : Int := 1329227995784613643754746428306227201
def p : Int := 33548413
def t : Int := 1031

-- Literal scalar GMP floor-division expression from Query::terminal.
-- The denominator is positive on the frozen profile, so Int's Euclidean
-- division matches mpz_fdiv_q, including a negative numerator.
def nativeRounded (x : Int) : Int :=
  ((2 * (p * x - q * (x % t)) + q * t) / (2 * q * t)) * t + x % t

def nativeCanonical (x : Int) : Int := nativeRounded x % p

-- One public coefficient, not a complete ciphertext or an attack transcript.
-- It rules out the overstrong shortcut that canonical P-components each
-- keep their previous residue modulo t; the actual wrapped phase may be valid.
set_option maxRecDepth 20000 in
theorem canonical_component_counterexample :
    nativeRounded 1030 = -1 ∧ nativeCanonical 1030 = 33548412 ∧
    nativeRounded 1030 % 1031 = 1030 ∧ nativeCanonical 1030 % 1031 = 703 ∧
    nativeCanonical 1030 % 1031 ≠ 1030 % 1031 := by
  decide

end SharedQueryTerminal

#print axioms SharedQueryTerminal.signed_dot_congr
#print axioms SharedQueryTerminal.unwrapped_rounding_congr
#print axioms SharedQueryTerminal.wrapped_terminal_preserves_message
#print axioms SharedQueryTerminal.canonical_component_counterexample
