# Proposed cyclotomic-specific finite Fourier certificate

2026-10-03. **Theorem-research proposal only; no scientific GO.** No source
energy, root, field, Fourier sum, probability, numerical constant, parameter,
key, test, HE, estimator, kernel or timing was evaluated. This does not select
an original main. It follows the [static eligibility card](source-certificate-eligibility-screen-20261003.md)
and [known-envelope stop](known-joint-root-envelope-card-20261003.md), retaining
their unresolved enrollment, failure-allocation and complete-frontier premises.

The known-envelope stop is about the size of an upper-bound allowance through
one ordinary union adapter, not the true bad-key probability. The intended
new target must improve a proved finite certificate, not reinterpret that
allowance or a finite census as a probability lower bound.

## 1. Exact finite object and ordinary Fourier control

Let N be a power of two with N>=4, p an odd prime with `p=1 mod2N`, and
`alpha_1,...,alpha_4` four DISTINCT primitive2N-th roots in F_p. They are odd
powers of a primitive root; no arbitrary low-order multiplier is included.
For u in F_p^4 and j=0,...,N-1, define

    a_j(u) = sum_i u_i*alpha_i^j in F_p,
    r_j(u) = its unique integer representative in [-(p-1)/2,(p-1)/2],
    E_T(u) = sum_j r_j(u)^2/p^2.

This is exactly the distance-to-Z energy in the proposed target. Modular
division is not a floating division of arbitrary unreduced integers. E is an
exact rational object, although no E was computed in this proposal.

For independent raw uniform ternary secret coefficients, the characteristic
function at x is `phi(x)=(1+2*cos(2*pi*x))/3`. The ordinary bound

    |phi(x)| <= exp(-4*dist(x,Z)^2)

is valid including negative phi. One elementary symbolic check takes
z=dist(x,Z) in[0,1/2]. For z<=1/3, phi>=0 and concavity gives
`sin(pi*z)>=2*z`, hence phi<=exp(-16*z^2/3)<=exp(-4*z^2).
For z>=1/3, |phi|<=1/3<exp(-1)<=exp(-4*z^2), using e<3.
This is a known trigonometric/characteristic control, not an original theorem.

Fourier inversion isolates the zero dual character EXACTLY:

    P[S(alpha_i)=0 for all i]
      = p^-4 * sum_{u in F_p^4} product_{j=0}^{N-1} phi(a_j(u)/p),
    |P[the quartet event]-p^-4|
      <= p^-4 * sum_{u!=0} exp(-4*E_T(u))
      <= (1-p^-4)*exp(-4*min_{u!=0} E_T(u)).

The zero dual term is1; the remaining prefactor is `(p^4-1)/p^4`, not p^4.
Products may have either sign, so the triangle inequality/absolute values
remain necessary. This controls an unconditional raw-law quartet event;
conditioning on a unit or a selected secret changes that law.

Zero coordinates of u are permitted. An argument proved only for four nonzero
coordinates is insufficient. Let d be the number of active coordinates,1..4.
If L_d is a uniform energy lower bound for every such support/root tuple, the
equally informed generic also receives the elementary refinement

    discrepancy <= p^-4 * sum_{d=1}^4 choose(4,d)*(p-1)^d*exp(-4*L_d).

This support split may be less wasteful than one worst dual minimum. It is
known counting/Fourier machinery and is not a proposed original mechanism.

## 2. Mandatory symbolic falsifiers and exact dyadic reductions

**Unscoped lower-bound conjecture is false.** At N=d=4, take all primitive8-th
roots and u_i=4^-1 in the prime field. Their first four power sums give
`a_j=(1,0,0,0)`. Thus E=1/p^2. Vandermonde invertibility also shows that a
nonzero u has some nonzero residue, proving the exact minimum1/p^2 in this
formal family. As p grows through primes1 mod8, no positive absolute c can
give `E>=c*N/(d*log(p))` without a degree/field regime. No prime, root or c was
selected or tested to obtain this symbolic falsifier.

**Scalar characters are always present.** With one active coordinate, energy
is precisely that of a scalar geometric progression. Scalar estimates cannot
be replaced by independent-root heuristics or by a typical-multiplier theorem.

**Complete dyadic packets reduce to shorter scalar problems.** For
k in{2,4}, k|N, a primitive2N root alpha, and primitive k-th root omega,
the roots `alpha*omega^ell`, ell=0,...,k-1, remain primitive2N roots.
For `u_ell=b*omega^(-ell*r)`, b!=0 and r=0,...,k-1, the sequence vanishes unless j=r modk,
and equals `k*b*alpha^j` there. Its energy is exactly the scalar energy of
length N/k, multiplier alpha^k (order2N/k), and amplitude k*b*alpha^r.
Both parity choices and all residue classes are paid. Two opposite pairs
can likewise reduce to two-frequency parity subsequences. These are exact
algebraic controls, not independent-coordinate assumptions.

**The strongest packet control is the exact scalar PRODUCT, not a worst
character.** Write `S(X)=sum_{r=0}^{k-1}X^r*C_r(X^k)`. The k evaluations
vanish iff every `C_r(alpha^k)` vanishes; those residue-class coefficient
blocks are genuinely independent raw ternary polynomials. Thus

    P[all k packet roots vanish] = P[C_0(alpha^k)=0]^k.

On the dual side the invertible k-point field DFT maps u to
`v_r=sum_ell u_ell*omega^(ell*r)`, and energy is the SUM of k scalar energies
at amplitudes `alpha^r*v_r`. All v_r vary independently in that sum. The
one-active transformed-v stratum has `k*(p-1)` characters out of p^k;
its inverse image has every original u coordinate nonzero. Its minimum energy
is the scalar length-N/k minimum, but giving that minimum to every p^k-1
nonzero character loses the stratum weight and can be much weaker than the
exact product. The equally informed generic receives this product and the
factorized energy-spectrum control. For two opposite pairs it also receives
the exact square of the corresponding two-root probability at length N/2.
None of these quantities was calculated.

Therefore any claimed uniform improvement must survive scalar, antipodal and
four-root packet cases in the SAME regime, with their reduced length/order.
Neither structured-packet probability extremality nor average dual energy is
a justified shortcut; E122's probability counterexample does not establish
which packet minimizes this different energy functional.

## 3. Additional ordinary rank/norm competitors

Distinct active roots give an invertible consecutive d-column Vandermonde
matrix. No length-d consecutive sequence window can be identically zero;
disjoint windows give the known weak control

    E_T(u) >= floor(N/d)/p^2.

Do not strengthen this to an arbitrary-subset/MDS assertion: dyadic packets
already have many zero positions.

A stronger ordinary determinant control applies directly to the DUAL energy.
Let R(X)=sum_j r_j X^j. Its modular evaluation is zero at every root gamma
except the inverses of the d active alpha_i: the geometric sum is0 unless
alpha_i*gamma=1, where it is N*u_i. Consequently multiplication by R has
nullity N-d modulo p. R is a nonzero integer polynomial of degree below N;
irreducibility of `X^N+1` over Q makes its integer determinant nonzero.
Smith divisibility and Hadamard therefore give

    p^(N-d) divides Delta_R,
    |Delta_R| <= ||r||_2^N,
    E_T(u)^N >= p^(-2*d), equivalently E_T(u)>=p^(-2*d/N).

These are the same known cyclotomic norm/divisibility ingredients used by
existing controls, not a new energy theorem. A claimed shorter proof must not
present this implication as original or omit it from the generic comparator.
No source value of either lower bound was computed here.

## 4. The narrowly different proof target

The proposed target is an explicit **finite, cyclotomic-specific** certificate
for all active d<=4, all distinct primitive odd roots, and all nonzero
amplitudes, in a stated regime that can be checked at the already fixed E120
source profile. Minimum energy is one possible supporting primitive. A
schematic possible bound is

    E_T(u) >= c*N/(d*log(p)),
    subject to an explicit degree/field growth condition, e.g. N>=A*d*log(p).

This is an UNPROVED research target, not a chosen c or A or a claim that this
particular schematic condition suffices. A rigorous different explicit L_d
is admissible only in a new reviewed target, not an after-result constant
substitution. The N=d falsifier must remain excluded by justified premises;
the shortened dyadic scalar cases must remain INCLUDED and proved.

The preferred alternative research target is a COMPLETE weighted low-energy
strata/count or Laplace-spectrum certificate, so rare bad characters are not
charged as every character. For h distinct roots (h<=4), define

    Z_T = p^-h * sum_{u in F_p^h, u!=0} exp(-4*E_T(u)).

A proved uniform upper bound on Z_T supplies the ordinary discrepancy bound.
A prospective certificate may instead upper-bound all cumulative energy counts
`#{u!=0:E_T(u)<=L}` and give a justified full-bin/tail integration. No threshold,
binning precision, count or source value is selected here. A small subspace
stratum has its true p^-h-normalized cardinality: codimension-c weights require
a PROVED cardinality/cover, not labeling an arbitrary energy level a subspace.
Overlapping covers must be handled as justified upper bounds or made disjoint;
neither missed strata nor lower counts may substitute for complete coverage.

For a complete packet the generic already gets
`sum_u exp(-4*E_T(u))=(sum_v exp(-4*E_scalar(v)))^k`, including the zero term,
followed by subtraction of that term. Generic Fourier/support/subspace
stratification and this factorization are known, so they are not the novelty
claim. A potential difference would be a strictly stronger proved finite
spectral/stratum certificate for arbitrary primitive-root tuples, with complete
coverage and source-useful costs. No such certificate is established. The
three exceptional toy census orbits supply no source-stratum extrapolation.

The concrete proof work is to improve the known low-energy-to-low-height
recurrence/annihilator argument using the power-of-two primitive-order
restriction. Identify the exact lemma and logarithmic/constant loss removed,
derive every constant and boundary, and prove reduced-support/dyadic branches.
Merely repeating multivariate Fourier, invoking a determinant bound, or naming
NTT/cyclotomic structure is contained by existing controls. No improved lemma
or full argument has yet been supplied.

[HPXv2](https://arxiv.org/abs/2201.06156v2) already treats prescribed multiple
roots, reduced dual supports and quantitative degree/order Fourier conditions;
the retained [full-text comparison](joint-root-census-prior-comparison-20261003.md)
records its unresolved explicit constants. [Breuillard–Varju v2](https://arxiv.org/html/1909.09053v2)
§2, Lemma6/Theorem5, supplies scalar high-order energy/mixing controls and
their low-Mahler/low-order alternative. Its typical-multiplier results do not
automatically cover a fixed cyclotomic subgroup. These are direct mechanism
controls. This bounded reading does not establish that the proposed sharper
finite bound is new or attainable. Existing ALS/binomial-law and deterministic
invertibility comparisons remain [paid priors](joint-root-prior-comparison-20261003.md).

## 5. Executable research milestones and coverage bill

1. Freeze the theorem's exact domain/growth premises and ONE output contract:
   supporting L_d or the preferred complete weighted Z_T/count certificate.
   Do not choose constants, bins or a route from source energy samples. First
   apply the cheapest symbolic packet-product/DFT control; stop an originality
   claim if it only recreates factorization or loses to that stronger control.
   Return a proof outline naming the ONE improved lemma and matching prior.
2. Independently review the symbolic falsifier, characteristic/prefactor,
   determinant and packet reductions. A proposed proof must cover each active
   support and all roots/amplitudes, not only a generic or observed branch.
3. Supply a complete explicit constant/exception/stratum certificate and a
   verifiable proof or checker with stated source/time/state cost. An average,
   numerical sample, omitted transformed subspace or solver-found local minimum
   does not certify the global lower bound or upper-bound the full spectrum.
4. Only after the existing eligibility/budget/usefulness gates close, freeze a
   separate scalar application/method/resource cap and obtain root GO. No larger
   toy scan, exact source Fourier enumeration, key draw or backend follows from
   this proposal. A failed premise or cap is a stop, not a tuned retry.

Naive full coverage costs `choose(N,4)*(p^4-1)` energy records per field,
each with N terms, plus roots, arithmetic and receipts. No such enumeration
is proposed. A theorem/checker must pay how it covers all of that domain.
Signed negacyclic sequence shifts and odd-power ring substitutions preserve
energy and can support PROVED reductions; they are ordinary symmetries.
Scalar normalization of u is not free: general field rescaling changes centered
Euclidean energy. Root-exponent translation is not automatically an invariant.
Construction-A lattice minimum alone is also insufficient: vectors in p*Z^N
have zero modular codeword and must be excluded by a correct relative/coset
certificate. No source orbit/certificate cardinality was constructed here.

## 6. Full consequence and originality stop

A proven energy bound gives an ordinary Fourier quartet allowance, then only
the existing zero-once/all-subset/all-limb/setup adapter under its actual
premises. Honest enrollment counts, allocated complete failure budget and
same-domain A_other are unresolved; do not guess them or evaluate a source
failure/security level. A source root lemma alone cannot admit drop87 or verify
that a malicious server followed the complete original/terminal graph.

The generic receives all proved new lemmas and identical source/owner inputs.
An originality claim needs a genuinely stronger finite certificate than known
controls or a separately justified complete-system consequence. The ledger must
include proof/certificate generation and checking, global context/input counters,
owner re-enrollment/updates, keys/state, source/all-coefficient binding, receipt/
attestation/transport, private release and side-channel/parameter assurance.
Matched costs and actual benefit remain UNKNOWN. Permitted full plaintext cache,
protected replay/affine controls and reviewed ring/PCS proof alternatives remain
mandatory comparators. No omitted cost is zero and no memory restriction is
invented to favor outsourcing.

Stop the source-application/originality lead if the stronger proof is contained,
its constants/premises do not cover the fixed profile, complete coverage cannot
be certified, lifecycle/failure assumptions remain unjustified, or a fully paid
frontier cannot improve. A useful known supporting bound can be retained without
calling it an original main. The [external proposal receipt](../../../research-data/joint-root-census-20261003/fourier-target-draft/proposal-receipt.json)
records source pins and bounded primary-browser scope; registry and old cards
remain unchanged.
