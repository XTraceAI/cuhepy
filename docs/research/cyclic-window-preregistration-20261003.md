# Frozen Q47/E121 first public assurance component

Root froze this specification before new code, tests or law evaluation. The draft-stage stop language below describes its earlier state; this header authorizes ONLY the listed tiny public gate on `experiment/cyclic-window-assurance-20261003` from checkpoint `b7ab15259d153b78da6f958bdc3a756a15f414b8`. Draft SHA256: `1a4ef675ce0165f41c76cb22321de9afd1a808bda0be44324465674720e95e7c`. No large tail/setup/lifetime card, HE, sampler or production change is authorized. The implementation paths were absent before this freeze. A separate main GO and source/argv freeze are required after independent source review and scoped tests.

---

# Q47/E121: prospective cyclic-window finite assurance gate

2026-10-03. **Scope only, not activated.** No new calculation, oracle, code,
test, law evaluation or selector has run for this packet. Root must freeze this
specification and give a separate GO before implementation or execution. The
completed E120 source, raw, report and receipts remain unchanged.

This specification selects only the first tiny gate from the archived
`proposed-next-packet.md` (SHA256
`65cbbef510f9835fad6d7412d08123441a0d775664b15a845eeef6161653909b`)
and `tiny-gate-supplement.md` (SHA256
`775f3beb73241d9a4235b56e11e400f2a31773098ba688b852a9a5ac5cc29ad2`),
both in `research-data/multilimb-consequence-20261003/prospective-cyclic-window/`.
Their larger owner-norm, lifetime, terminal and byte consequence is **not**
activated. The rejected full-vector codec/CBD factoring shortcut in the
supplement remains preserved.

## Fixed public contexts and observable work

* N8/Q17, primitive 16th root 3, the inherited ternary polynomial
  `(-1,0,-1,1,0,0,0,0)` (X^3-X^2-1), public norm 3 and window length 7:
  exactly eight cyclic-window projection-rank checks. Compare the proposed
  public matrix/window construction with an independent schoolbook modular
  matrix/rank control. No N8 image, mask, CBD, histogram or MGF enumeration.
* N4/Q17, primitive eighth root 2, X-2 = `(-2,1,0,0)`, window length 3,
  inherited rank 3/image 4913/fibre 17; and X^2-4 = `(-4,0,1,0)`, window
  length 2, inherited rank 2/image 289/fibre 289. These are nonternary public
  algebra controls, not supported HE secret samples. Independently select
  column bases, verify their span and rank against schoolbook controls, and
  enumerate each image **once** (4913 and 289 vectors). Image uniqueness plus
  rank-nullity certifies completeness and constant full-mask fibres; do not
  repeat either old 83521-mask cohort.
* For each N4 context check all four literal ordered cyclic windows,
  including wrapped starts. Verify each projected image has uniform bins
  over `17^m` values. Retain histograms for exactly two translated images,
  using `M=(1,-1,0,0)`, `t=3`, and E equal to `(0,0,0,0)` and
  `(1,0,0,0)`: two shifts times four windows per context. No 81 histogram
  panels. Matrix-minor signs prove rank; they never alter actual coefficient
  positions or reverse the biased codec law.

The sole scalar quantizer context is the formal whole-Q mathematical map
`QuantizerLaw(Q=17,t=3,drop=2)`. Q17 is below the existing HE coefficient
codec's 16-bit modulus floor; this creates no HE context, key, query, codec
guard bypass or accepted production parameter. Fixed rational base is 2;
fixed signed weights are `(1,-2,0,1)`.

## Literal joint law and exact controls

E ranges over all `{-1,0,1}^4`, with weight
`w(E)=product_i binom(2,1+E_i)` and probability `w(E)/4^4`. No randomness
is sampled. For every E and every uniform image element v, preserve

```
c0_i = (M_i + 3*E_i - v_i) mod 17
Z_i = E_i + delta(c0_i)/3
Y_i = weights_i * Z_i
mass(E,v) = w(E) / (4^4 * image_count).
```

The full-vector codec law can depend on E through this coset. The main LHS
must average the **complete same-E joint law**, rather than multiply an
untranslated full-image codec MGF by an independent CBD MGF. The exact
root-free observable, for each context separately, is

```
L = [sum_(E,v) mass(E,v) * 2^(m * sum_i Y_i)]^N
R = product_j [sum_(E,v) mass(E,v) *
               2^(N * sum_(i in W_j) Y_i)]
L <= R.
```

Stream the literal laws with exact integer exponent counters and Fraction
arithmetic. The fixed Cartesian counts are `81*4913` and `81*289` tuples;
each has four scalar codec evaluations and four window sums. Reuse the two
single-image caches for all E, histograms and the indicator control. Retain
weighted normalization, visited tuple/scalar counters, signed scalar codec
PMF/mean, L, R and the inequality result. No complete joint tuple archive
is needed. These work products are scope expressions, not executed results.

Independently construct the window RHS from the exact one-coordinate uniform
codec PMF and CBD PMF. This factoring is justified **only within a window**:
its uniform projection is independent of the entire E. Require exact equality
between the literal joint-window R and this factored R. The matched ordinary
independence-system/Hölder adapter receives the same windows, actual joint
law, weights, translation, codec bias and all cache/normalization options.
It must produce the same bound; no candidate-only preprocessing advantage.

## Separate arbitrary-subset falsifier

Use only the existing **untranslated** X^2-4 image (M=0/E=0), reusing its
enumeration. Let U0 and U2 indicate zero at positions 0 and 2. The inherited
relation `c2=4*c0 mod17` makes these indicators equal. Check the registered
ordinary moment `E 2^(U0+U2)=20/17`, which differs from the false full-IID
product `(18/17)^2`, and check that ordinary all-window Hölder gives 20/17
at this same unscaled moment. Do not conflate this with the main powered
root-free inequality, which scales exponents by m/N, or extend the relation
to arbitrary translated cosets. No additional context or counterexample
search is authorized.

## Known method, limits and stop rule

Pelekis–Ramon–Wang, arXiv:1511.07204v1, §3's equal-multiplicity
independent-set argument and §5's explicit independence-system extension
directly contain the concentration mechanism. I read the archived exact
text for those sections; text SHA256
`369eff58c266db479a9c6976fa23e6923f320a68c9771052839cf6a38f41a14d`.
The N cyclic windows cover each coordinate m times. Ordinary Hölder needs
neither independence between windows nor an inferred dependency graph,
Finner or read-k representation. The method is a known assurance control;
generic equality does not itself resolve originality of a later complete
authenticated-owner/CRT/codec/lifecycle consequence.

This packet can establish only exact finite public-law evidence and retain
homemade assurance code. It cannot claim a novel concentration mechanism,
large-profile tail, byte or speed win, secret-distribution statement,
cryptographic reduction, parameter/security approval or production release
gate. Full client plaintext caching remains an allowed eventual comparator.

The single main cohort has a 60-second wall/CPU and 256-MiB address-space
ceiling. Stop and preserve a failure if the fixed exact work cannot complete;
do not retune contexts, base, budget or arithmetic precision. No new sampler,
HE key/ciphertext, setup model, source-profile calculation, MGF tail/lifetime
card, native/GPU/build, estimator, proof backend, service or timing benchmark.
Unit tests may use disclosed tiny algebra/grammar/omission cases, not a new
scientific cohort or the N8 image. Strict exact-int, prime/root/window, mass
and law grammar must reject aliases and malformed/composite fields.

After GO, freeze final source/argv and relevant source/anchor hashes before
one main; preserve initial failures and fixes, stdout/stderr/exit, source
copies, unique scoped test IDs and three explicit nonempty Ruff paths. Root
owns file assignment, governance and commits. The E118/E119 result anchors
are respectively SHA256
`5a8de3b3878cbe7c207c863c665e754e590756febe9382c919b64970a1e8547e` and
`214706d4077dd142dec24c2933910284389a8cfdcd6a59888d1873869320c4d3`;
E120 raw and report anchors remain SHA256
`42dc827307ac568ad9fa30b85adecf11a4d69732933d46bf329940863f5b9054` and
`02523758201f356d6bd801c35402b70fc7f67280eccb71c4c1429401f6652a26`.
