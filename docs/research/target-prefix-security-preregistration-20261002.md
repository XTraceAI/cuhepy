# E96 prerequisite: security dimension of the publicly known target prefix

2026-10-02. Parent `2290f4b`; branch `experiment/late-owner-precision-20261002`.
This is the R6 return after bounded E95. Freeze before the first estimator run.
Correct conditional rounding does not establish confidentiality. A public
512-coefficient prefix in a much larger ring is not a full-ring secret.

## Exact sample relation, without a rotation-independence heuristic

For a public honest owner zero `(-rho*T+E0,rho)` in R_Q, assume the secret T
has p unknown ternary coefficients at positions0..p-1 and known zeros elsewhere.
At positions `p-1,2p-1,...,floor(N/p)*p-1`, negacyclic multiplication has no
wrap and uses disjoint p-coefficient chunks of rho. Negating the zero body
therefore gives `b_k=sum_j rho[k-j]*T_j-E0[k] mod Q`. Each chosen row is a
genuine independent uniform p-dimensional LWE row, with independent CBD_eta
error, when rho/error coefficients and different owner zeros are honestly fresh.
One zero supplies floor(N/p) such rows; L published zeros supply that many times L.
This is an exact subset argument, not a claim that all N rotations are independent.
It differs from random-location sparse ternary keys: the zero positions here
are publicly known. Do not feed full N or SparseTernary(N,p) to this screen.

Exhaust small polynomial supports and independently match the coefficient
equation, disjoint masks, uniform row distribution and CBD sign symmetry.
Use no customer's data/key or live service. No production attack is executed.
The chosen rows may be computed from public diagnostic ciphertexts; the test
keeps secret/error witnesses private and reports only counts/context.

## Pinned estimator screen and stop rule

Use the already installed Sage10.9 and lattice-estimator revision
`53da5982597709ba0fdf94ea37a84d822310fd84`, tracked tree unchanged. Source
code for HE schemes remains homemade; this external tool estimates generic
LWE attack costs. Retain a source snapshot/dependency hash. Read the primary
[security guidelines](https://eprint.iacr.org/2024/463) and
[estimator documentation](https://github.com/malb/lattice-estimator).

Use the six unique frozen E94 original-Q/N contexts and eta21. Test public
prefix p512/1024/2048/4096 when p<=N, with L4096 published fresh zeros and
exact independent sample count L*floor(N/p). Use ND.Uniform(-1,1) at dimension p
and ND.CenteredBinomial(21). Do not use t*error, rounded noise, a changed prime
or a full-ring security claim. Try usvp/bdd/dual/dual_hybrid serially under
MATZOV classical costs/GSA, with a10-second cap per call; preserve missing,
nonfinite and failed attacks, configured beta cap and any assumptions.
Do not run secret recovery or lattice reduction on production parameters.

Raw outputs checkpoint each attempted call and are immutable after completion.
Run an initial/repeat pair. Compare model/context/source and finite returned
cost fields; elapsed/UTC/command are execution metadata, not cryptographic
performance measurements. If timeouts differ, preserve them and qualify rather
than declare every attack repeated. No positive assurance from this small
selection: quantum, hybrid/BKW/GB omissions, structured/key-graph/seed details,
malicious provenance and private channels remain open.

Any returned cost below128 bits stops treating that prefix/context as a
128-bit design candidate under this heuristic model. Above128 only passes
this named screen, not security approval. This does not negate E95's arithmetic
law, implicate the production full-ring BFV/BGV keys or show actual attack time.
Do not inherit prior full-N parameter estimates for this different target key.

## Coupled precision and R6

After the screen, recalculate E95's source/zero/key-error/residual/finite-LUT
budgets with the screened candidate supports. Retain p512 as a qualified
historical arithmetic control, not an equal-security winner. Include p=N as
the conventional full-ring control; extra supports may exceed the prior degree
grid, which must be reported without inventing a PBS or speed result.

Return to the main plan. Stop generic rerandomization originality; do not
promote Q6–Q10. Next must close a real competitive/assurance bottleneck, such
as a complete owner-bound stochastic-rounding control or compressed-query
binding with its actual correlated noise, rather than another unpriced MGF.
Full original-score verification, private decryption and meaningful matched
cache/network results remain necessary for a selected research contribution.
