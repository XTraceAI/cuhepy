import Std
import Lean.Elab.Tactic.Omega

/-
Four supporting integer assertions for the unchanged profile.
This integer model does not establish native refinement, noise/origin induction,
privacy or a creative extension. Actual compiler receipts are retained separately.

rawQ/rawP are complete signed phases of UNWRAPPED components. Canonical wire
components are connected only modulo P. The aggregate residual premise must
be derived from complete native convolution and ternary-secret coverage.
-/

namespace SharedQueryPhaseBridge

def q : Int := 1329227995784613643754746428306227201
def p : Int := 33548413
def t : Int := 1031
def outputBound : Int := 144762438280919092281917477552128
def gamma : Int := 16385

def rounded (x : Int) : Int :=
  ((2 * (p * x - q * (x % t)) + q * t) / (2 * q * t)) * t + x % t

def centeredPhase (raw : Int) : Int :=
  if raw % p > p / 2 then raw % p - p else raw % p

-- Exact coset-nearest rounding, including negative numerators/tie direction.
-- Int Euclidean division agrees with GMP floor for this positive denominator.
theorem native_rounding_residual (x : Int) :
    -(q * t) < 2 * (q * rounded x - p * x) ∧
    2 * (q * rounded x - p * x) ≤ q * t := by
  dsimp [rounded, q, p, t]
  omega

-- This is the paired-lift implication missing from the earlier four facts.
-- Do not apply it to a canonical wire phase as though it were unwrapped rawP.
theorem paired_phase_bounds (rawQ rawP phaseQ wrap : Int)
    (oldLift : rawQ = phaseQ + q * wrap)
    (noiseLower : -outputBound ≤ phaseQ)
    (noiseUpper : phaseQ ≤ outputBound)
    (errorLower : -(gamma * q * t) ≤ 2 * (q * rawP - p * rawQ))
    (errorUpper : 2 * (q * rawP - p * rawQ) ≤ gamma * q * t) :
    -p < 2 * (rawP - p * wrap) ∧ 2 * (rawP - p * wrap) < p := by
  dsimp [q, p, t, outputBound, gamma] at *
  omega

-- Centered reduction identifies the same lift once the strict interval holds.
theorem centered_phase_recovers_lift (rawP wrap : Int)
    (lower : -p < 2 * (rawP - p * wrap))
    (upper : 2 * (rawP - p * wrap) < p) :
    centeredPhase rawP = rawP - p * wrap := by
  -- Branch before normalizing p, keeping the Decidable instance type-correct.
  by_cases high : rawP % p > p / 2
  · simp only [centeredPhase, high, ite_true]
    dsimp [p] at *
    omega
  · simp only [centeredPhase, high, ite_false]
    dsimp [p] at *
    omega

-- The actual wire phase need only agree modulo P; it need not agree modulo t.
-- Complete signed-dot and component-rounding facts supply the residue premise.
theorem admitted_phase_message (rawQ rawP phaseQ wrap wireRaw : Int)
    (oldLift : rawQ = phaseQ + q * wrap)
    (noiseLower : -outputBound ≤ phaseQ)
    (noiseUpper : phaseQ ≤ outputBound)
    (errorLower : -(gamma * q * t) ≤ 2 * (q * rawP - p * rawQ))
    (errorUpper : 2 * (q * rawP - p * rawQ) ≤ gamma * q * t)
    (unwrappedResidue : rawQ % t = rawP % t)
    (wireResidue : wireRaw % p = rawP % p) :
    centeredPhase wireRaw % t = phaseQ % t := by
  have interval := paired_phase_bounds rawQ rawP phaseQ wrap oldLift
    noiseLower noiseUpper errorLower errorUpper
  have centered := centered_phase_recovers_lift rawP wrap interval.1 interval.2
  have sameCenter : centeredPhase wireRaw = centeredPhase rawP := by
    simp only [centeredPhase, wireResidue]
  rw [sameCenter, centered]
  have moduli : q % t = p % t := by decide
  have difference : (rawQ - q * wrap) % t = (rawP - p * wrap) % t := by
    rw [Int.sub_emod rawQ (q * wrap) t,
        Int.sub_emod rawP (p * wrap) t,
        Int.mul_emod q wrap t, Int.mul_emod p wrap t,
        unwrappedResidue, moduli]
  have oldDifference : rawQ - q * wrap = phaseQ := by omega
  rw [oldDifference] at difference
  exact difference.symm

end SharedQueryPhaseBridge

#print axioms SharedQueryPhaseBridge.native_rounding_residual
#print axioms SharedQueryPhaseBridge.paired_phase_bounds
#print axioms SharedQueryPhaseBridge.centered_phase_recovers_lift
#print axioms SharedQueryPhaseBridge.admitted_phase_message
