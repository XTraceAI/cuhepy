# Q47/E121: exact cyclic-window public-law assurance

2026-10-03. **Completed first tiny component; retain the known control and
return to the plan.** One frozen main process exited 0 with empty stderr,
inside the registered 60-second CPU/wall and 256-MiB address-space ceilings.
Those ceilings are resource guards, not performance measurements. No main
retry, new context, large-profile calculation, HE operation, private material,
sampler, native/GPU build or probability/lifetime certificate was run.

The frozen [specification](cyclic-window-preregistration-20261003.md) follows
the [prospective plan](cyclic-window-consequence-plan-20261003.md). The code is
our public exact-arithmetic assurance implementation, using the repository's
earlier homemade matrix/quantizer helpers. It does not import SEAL or a proof
backend. It is not encryption or an authenticated private-release protocol.

## What the exact run established

For the single N8/Q17 ternary witness X^3-X^2-1, all eight literal cyclic
length-7 window projections have rank 7, including wrapped starts. Independent
schoolbook matrices and division-free field elimination match the matrix and
rank helpers. This context was rank-only: no N8 image, full mask, CBD,
histogram or MGF law was enumerated. Its inherited public squared norm 3 is
not the norm envelope of every secret sampled by the implementation.

For the two N4/Q17 **nonternary public** controls, each multiplication image
was enumerated once through a column basis. An independently selected basis
has the same rank/span. Unique canonical image points, membership in the
actual span and exact cardinality certify completeness; constant full-mask
fibre counts follow from rank-nullity. The old full-mask cohorts were not
rerun.

| Public polynomial | Window length/rank | Image points | Full-mask fibre by rank-nullity | Supported E/image tuples | Weighted law denominator |
|---|---:|---:|---:|---:|---:|
| X-2 | 3 | 4,913 | 17 | 397,953 | 1,257,728 |
| X^2-4 | 2 | 289 | 289 | 23,409 | 73,984 |

All four literal windows in each N4 context have full window rank. Exactly
16 retained histogram panels cover the two preregistered translations
E=(0,0,0,0) and E=(1,0,0,0), at every cyclic start. Each histogram is uniform
over all `17^m` ordered window values. These panels are a diagnostic; they do
not substitute for all 81 E vectors in the joint law.

The formal whole-Q codec has Q17/t3/drop2. Under a uniform coefficient its
delta/t PMF is 13/17 at zero and 4/17 at -1, with signed mean -4/17. We retain
that bias. Q17 is below the actual HE coefficient codec's 16-bit modulus
floor; the scalar mathematical oracle neither creates a supported HE context
nor bypasses an API guard.

The joint oracle keeps the same E in `c0=M+3E-v mod17` and in
`Y_i=w_i*(E_i+delta(c0_i)/3)`, with M=(1,-1,0,0), w=(1,-2,0,1), and literal
CBD1 weights `(1,2,1)` per coordinate. All 81 E vectors contribute to each
translated uniform-image law. There are 421,362 joint tuple visits in total,
1,685,448 scalar codec-cache lookups and the same number of window sums.
These are logical counters, not elapsed times or an optimized cost bound;
the 17-entry scalar lookup cache and every normalization are shared with the
generic control. Basis/membership validation and preparation are additional
work. No complete Cartesian tuple table was retained.

Both root-free exact comparisons are strict:

```
[E_joint 2^(m*sum_i Y_i)]^N
    < product_j E_joint 2^(N*sum_(i in W_j) Y_i).
```

For X-2 the full moment before its fourth power is
`5435963842725/5151653888`; for X^2-4 it is `321390125/9469952`.
The exact powered LHS/RHS, all weighted exponent laws and every window
moment are archived, rather than rounded for a probability claim. Each
literal joint-window moment matches both the existing exact geometric
scalar MGF/CBD control and an independent explicit 17-coefficient/three-CBD
outcome scalar control. Factoring is used **only for the window RHS**:
surjective window projections are uniform independent of the entire E.
The full-vector LHS retains its E-dependent coset. No full-vector IID or
untranslated-codec/CBD factorization follows.

The separate untranslated X^2-4 indicator check reuses its image cache.
The relation c2=4*c0 modulo17 makes the two zero indicators equal, giving
`E 2^(U0+U2)=20/17`; the false full-IID product is `(18/17)^2=324/289`.
Ordinary all-window Hölder gives exactly 20/17 at this **unscaled** moment
(verified via equal fourth powers). This is distinct from the powered
codec/CBD observables above and does not assert the same coordinate relation
in arbitrary translated cosets.

## Method status and useful limits

The concentration mechanism is directly known. The archived primary
[Pelekis–Ramon–Wang paper](https://arxiv.org/abs/1511.07204v1), §3's
equal-multiplicity independent-set argument and §5's independence-system
extension, contains the ordinary Hölder regular-cover method. Each coordinate
belongs to m of the N windows; neither independence between windows nor a
dependency graph, Finner or read-k premise is required. The matched generic
gets the same windows, law, weights, bias, caches and factoring, and its
exact bound ratio is 1. The archived PDF/text, reading receipt and frozen
comparison are retained outside Git and pinned in the source/argv receipt.

This is a useful homemade finite assurance baseline. It is **unselected as
an original concentration mechanism**. The run does not settle whether a
complete authenticated-owner/nonunit/CRT/exact-codec/lifecycle consequence
has already been published; it also does not demonstrate a material whole
system benefit. No setup/owner-index squared-norm event, large-profile MGF
tail, query precision, lifetime, communication saving, cryptographic
reduction or security/parameter approval was evaluated. Full client plaintext
caching remains an allowed eventual baseline. Original-query admission,
shared canonical witnesses, complete terminal/wire checks and the protected
verifier's residency, preparation, recomputation, lifecycle and traffic stay
outside this public-law gate. None receives an assigned zero cost.

## Validation and provenance

**81 distinct scoped tests passed**; three explicit nonempty Ruff paths
passed. Tests independently enumerate tiny full masks to check image fibres
and the same-E literal codec law, enumerate CBD coins to check weights,
exercise shifted full cosets and uniform windows, reject false IID indicator
factoring, and reject malformed/aliased field, image, cover and law inputs.
They do not rerun either registered N4 main context or an N8 image. The initial
59 passing tests and source copies remain separate. Independent review then
identified a local diagnostic grammar gap (counter float aliases/outer list/
unchecked scalar-cache field); it was corrected before main, with 22
regressions. No scientific main had run then. A default Ruff invocation that
excluded the files is preserved but not counted as lint; the successful
explicit invocation disables forced exclusion and gitignore filtering.

The first source/argv preparation stopped before writing a freeze because the
peer review file was not yet present. That metadata failure is preserved;
after the peer file arrived, a single freeze was written and one main was
executed. No scientific failure or main retry occurred. The 555 pinned source,
prior, specification and validation inputs remained unchanged through main.

* Source: [cyclic_window.py](../../experiments/bfv_search_lab/cyclic_window.py),
  [tests](../../experiments/bfv_search_lab/test_cyclic_window.py),
  [runner](../../benchmarks/cyclic_window_lab.py).
* Selected [raw result](../../benchmarks/results/publication-cyclic-window-20261003.json)
  SHA256 `2265929df83440fba32ef0d3d4f628e5b649831b6bc45ad7d798fabc4db61b08`.
* Frozen specification SHA256
  `506e1a5a1f3f1d374dab6371c45069b517dc265422b3a0ace79c17019509553a`;
  source/argv freeze SHA256
  `059f57214b902767fa694783e6ec27c9c2a30598936924efd9f21b3e00ce079f`.
* External cache: `/home/pete/yavor-projects/xtrace-work/research-data/cyclic-window-20261003/`;
  `image-{2,3}.json`, `window-histograms-{2,3}.json`,
  `joint-exponent-laws-{2,3}.json`, `main.stdout`, `main.stderr`,
  `final-tests.xml`, `final-test-case-ids.json`, `final-tests-receipt.json`,
  `source-argv-freeze.json`, and `execution-receipt.json`.

The default result directory is Git-ignored; root owns any explicit selected
raw checkpoint. Full image/histogram/exponent caches remain external. The
decision is to retain this exact control and return to the research plan;
any larger consequence needs its own frozen specification and comparison.
