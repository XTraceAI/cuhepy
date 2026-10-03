# Q33/E107: existing-target-prime exact lifting screen

2026-10-03 UTC. Freeze before new implementation/evaluation. This follows the
[E106 return](native-boundary-screen.md); it is a **candidate known control**,
not an accepted original mechanism or an implemented proof system.

## Exact candidate and strongest shared control

Use odd coprime Q=p0*p1 and P, odd t>=3 with gcd(QP,t)=1, P>t and P≡Q modt.
For canonical source0<=c<Q and output0<=y<P, supply k∈{-1,0,1}, l=y+Pk and
signed integer r with |r|<Q/2. Require l≡c modt and
D=Ql−Pc−tr≡0 modulo BOTH p0,p1 and existing targetP.
The bounded-wrap/modt argument will be checked independently against exact
integer equality and nearest-congruent rounding. Narrow lift bounds are a
derived consequence, not a mandatory extra gate or a new saving.

Generic CRT/range verification receives the identical congruence, wrap-trit,
source ranges, batching and existing-P reuse. Also price an ordinary auxiliary
prime L>2P+t/2, which alone makes QL>|D| and permits exact lifting without modt
wrap exclusion (rounding congruence is still needed for the final statement).
These are complete scalar terminal relations ONLY: canonical switching,
source binding, commitments/range proof and authenticated release remain
additional. Do not infer an efficient remote proof from a Python predicate.

## Frozen finite domains and falsifiers

Exhaust every canonical c,y, every centered r and all three k for:
(p0,p1,P,t)=(3,7,11,5),(5,7,11,3),(5,7,17,3),(5,11,7,3).
There are180,978 literal witness tuples. Accepted tuples must be exactly one
nearest-congruent integer lift/compact output per c:146 accepted tuples.
Independently validate every predicate against integer equality plus congruence
and the signed error bound, not a copied rounding implementation.

Reuse the immutable E106 fixture and raw source versions. Public-only scalar
checks cover its256 terminal coordinates and143 threshold coefficients;
never submit a malformed diagnostic to a private decoder. No new key sample.

Record explicit omission falsifiers for targetP, each Q limb, modt,
source/output/r/wrap bounds, malformed types and changed contexts. A large
unbounded wrap l'=l+Pt can preserve the honest output and all residue equations
while falsifying exact equality. Counterexamples may be constructed explicitly
outside the finite honest domain; their scopes must be named.

## Paid consequence and return

Charge original-source/canonical evidence, r signed width, y/wrap trit,
all field/range equations, commitments/challenges, links/prover/checker/state
and protected release. Compare generic exact CRT/range with the SAME reusedP,
and a fresh auxiliary L control; identify modulus widths and additional setup
only as counts. Source-derived proof/cycle costs not implemented stay unknown.
Small-prime SNARK, lattice vFHE and ring public-vFHE adaptations remain primary
comparators. No claim that differing field premises imply originality.

Initial cap: one relation/containment component and one tiny exact/count
component. Literal containment stops a novelty claim; a surviving practical
representation needs its own concrete mechanism, full-native integration,
measured proof costs and separate preregistration. No timing/GPU/BFV edits,
parameter reduction, durable/protocol/private assurance or E104 activation.

Proposed files: `target_prime_lift.py`, `test_target_prime_lift.py` under
`experiments/bfv_search_lab`, runner `benchmarks/target_prime_lift_lab.py`, raw
`benchmarks/results/publication-target-prime-lift-20261003.json`, and report
`docs/research/target-prime-lift-screen.md`. Return to R6 after this cap.
