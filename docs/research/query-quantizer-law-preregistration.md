# E114 ideal query-quantizer law: frozen two-card discriminator

2026-10-03 UTC. One analytic law/certificate component and only two cards.
N16384,d512,count8192,t1031,eta21,radix15. Q is the actual first60-bit source
prime, P the actual compact32 prime already recorded by E113. Compare drops22
and23 only. No new keys, masks, sampler, benchmark, native/GPU execution, proof
backend, estimator, parameter approval or additional grid. Keep old evidence
and source unchanged. The root returns to the plan after this bounded screen.

## Ideal assumptions, distinct from the actual deployment

Condition on a fixed owner-enrolled index and fixed supported evaluation-key
errors, ternary secret support, and the additional IDEAL premise that the secret
is a unit in R_Q. Every fresh query message is chosen before a genuinely uniform
fresh full-Q mask polynomial, independent of the fresh CBD_eta query errors.
The mask coefficients are independent uniform residues, not a256-bit SHAKE seed
instantiation. Multiplication by a unit is a permutation of R_Q, so original c0
is uniform over the full coefficient vector and independent of CBD errors,
conditional on any chosen query. This supplies IID quantizer errors independent
of the original fresh E. It does NOT make reused key/digit terms independent.

Actual SHAKE fresh seeds, pseudorandom-stream/ROM composition, nonunit actual
secret probability, admitted malicious traces, accepted-query binding, adaptive
feedback, real setup/sample security and private side channels remain OPEN.
A conditional ideal-law fact is not a protocol or actual parameter approval.

## Exact codec law and certificate

Read the actual compressed_query_bgv c0 map: R=2^drop, K=floor((R-1)/t),
center=t*floor(K/2), word=t*floor(c/R)+(c modR modt), and reconstructed
c0=(R*floor(c/R)+(c modR modt)+center) modQ. Its unique centered added lift is

    delta = t*(floor(K/2)-floor((c modR)/t)).

For Q=F*R+T and bin k, exact mass is

    F*length([k*t,(k+1)*t) intersect [0,R))
      +length([k*t,(k+1)*t) intersect [0,T)),

with denominator Q. Derive this by quotient/remainder counting, including the
last partial Q cycle/bin. Retain exact signed bias, support and masses. Do not
enumerate Q or assume the error law symmetric. Tiny exhaustive tests may compare
this formula against the literal map and existing coefficient_encoding.

Use Z=E+delta/t with original CBD_eta. Its exact power MGF is the quantizer MGF
from finite geometric sums times ((1+z)*(1+1/z)/4)^eta. Fix one rational base
z=16385/16384; no searched base or tuned concentration grid. Round each exact
MGF upward to a2^-32 dyadic rational and use their maximum for both signs.
For every fixed index-phase coefficient |a_i|<=W=1+t*eta, convexity gives
E[z^((a_i/W)*Z_i)] <=max(M_Z(z),M_Z(1/z)). The same endpoint domination and exact
PMF are provided to the equally informed generic control.

Use the existing joint-support identity and pointwise COMMON bounded gadget
digits: S=t*eta*N*L*(2^radix15-1), with L=ceil(bit_length(Q)/15). This covers
canonical and bounded alternative common recompositions modulo Q; it supplies
no independent key/digit probability. Complete maintenance cap is(2D-1)*S,
D=512. The original message/index contribution is at most D*d*W. Each complete
output coefficient uses the same fresh query vector through its exact source
product, whose random part is t*sum_i a_i*Z_i. The D trace factor is charged.
The uniform pointwise maintenance remains outside the stochastic calculation.

Terminal rounding cap C=ceil((N+1)*t/2). The greatest safe integer Q-phase
radius is B=min(floor((Q-1)/2),floor(Q*(floor((P-1)/2)-C)/P)). Set
h=floor((B-(2D-1)*S)/D)-d*W+1. Only |t*sum_i a_i*Z_i|>=h can escape the stated
complete sufficient margin. Retain all strictness/floor guards and stop unknown
if h<=0 or the certificate cannot be derived.

Let J=floor(h/(t*W)) and Mplus be the upward rational MGF maximum. Exact
inequalities log(Mplus)<=Mplus-1 and log(z)>=(z-1)/z give

    A = J*(z-1)/z - N*(Mplus-1).

For positive A, a two-sided per-output tail is at most2*exp(-A), hence at most
2^(1-floor(A)) using e>2. This conservative dyadic rational bound avoids floating
logs, Gaussian tails or enormous rational powers. If A<=0 return the trivial
upper bound1, not a fabricated certificate. The exact PMF/MGF and inequalities
are auditable; the log certificate is deliberately conservative.

Lifetime Lqueries=2^32 and COMPLETE output count U=N*ceil(count/N)=16384 include
unused coefficients. Apply a union bound Lqueries*U times the two-sided bound;
no independence across outputs, reused keys, adaptive history or queries is
assumed by that union. The IDEAL fresh-mask premise is required for each query
chosen before that query's mask. Record the exact rational upper bound and target
comparison if derivable, with ideal assumptions attached. No actual sampler,
security/lifetime theorem, ROM or2^-128 deployment forecast follows.

## Controls, tests and stop

Two cards preserve deterministic drop22/drop23 complete bound outcomes, exact
law/bias/radius, complete terminal allowance, MGF/certificate values, union count,
and declared query/response schema bytes. All PMF/concentration/byte controls are
identical for candidate and equally informed generic, so originality ratio1.
Optional known Hoeffding is unnecessary if this registered exact-MGF route works;
no additional control grid is authorized. Whether drop23 fails or passes IDEALLY,
the literal recipe stops as known law/concentration; a pass is only a conditional
parameter/body fact, not a surviving paper mechanism or implementation request.

Meaningful scoped tests: tiny literal PMF mass/bias/last-cycle exhaustion; actual
codec coefficient map at its smallest supported widths; exact finite geometric
MGF versus direct rational sums; CBD moment identities; unit/permutation versus
nonunit mask counterexample; endpoint convexity where rational exponents can be
compared exactly; strict terminal threshold; outward MGF rounding; exact sign and
union factors; rejection of bool/float/malformed contexts. No tests mirror only
chosen large-card formulas. No large timing, native/GPU, setup or model grid.

Owned paths: only new query_quantizer_law* implementation/tests under
experiments/bfv_search_lab, benchmarks/query_quantizer_law_lab.py, selected raw
publication-query-quantizer-law-20261003.json, this preregistration and matching
screen report, outside research-data/query-quantizer-law-20261003. Freeze this
specification before code, tests or main law evaluation; record source/raw hashes,
commands, failures and meaningful scoped validation. No staging/commit/branches
or canonical plan edits by this agent. Return scoped unknown rather than widening
or changing a predicate if a rigorous boundary proves unmanageable.
