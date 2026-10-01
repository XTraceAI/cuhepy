# E74: public-code mask programming loses against the block factory

2026-10-01. Executed R4's
[preregistration](programmed-mask-preregistration-20261001.md). Homemade
[oracle](../../experiments/bfv_search_lab/programmed_mask_oracle.py),
[tests](../../experiments/bfv_search_lab/test_programmed_mask_oracle.py),
[runner](../../benchmarks/programmed_mask_lab.py) and immutable
[raw](../../benchmarks/results/publication-programmed-mask-block-screen-20261001.json).
No proposed pads are enabled in an HE client or production code.

## The proposal and strongest control

A public n-by-k field code A and private fresh s/error e give `r=A s+e`.
Precompute `P=M A`; then `M r=P s+M e`. All 81 exhaustive F3 products and
42 real CRT schedule recombinations, including shared forms, match the
independent ordinary matrix product. **20 scoped tests pass**. This algebra
does not implement a PCG, a privacy guarantee or an encrypted protocol.

[Vaikuntanathan–Zamir §3.1–3.2](https://arxiv.org/abs/2502.13065v2) already
use finite-field Bernoulli LPN and low-rank-plus-sparse/recursive trapdoored
matrices for faster products. Code/noise programming is a known ingredient.
Their pseudorandom-matrix construction is different from this public-code
fixed-weight pad, and supplies no automatic concrete security for it. Secret
dual-code EMVP, recursive BNTM and programmable PCGs remain different controls.

The actual owner factory has **small blocks**, not a dense m-by-n matrix.
Each row uses at most F local forms. Uniform A generally densifies P; its
literal row multiplication costs k products. Uniform private support of
weight tau contributes expected F*tau/n sparse products, before support
generation, index gathers, A*s, setup/state and fresh encryption. Hence the
optimistic comparison is `k+F*tau/n` versus F. Using maximum F rather than the
measured average already favors this proposal. Factoring P back through the
original block recovers the existing factory instead of the claimed saving.

## Privacy controls and exact count frontier

No noise leaves a left-nullspace query syndrome. Public error support also
leaves a syndrome whenever A and that support do not span the ambient space.
Both leakage cases are exact tests. A tiny Vandermonde n=12/k=2/t=17/weight=1
sample is recovered after twelve deterministically enumerated information
sets, and distinguishes a known query pair. These are explanatory public-code
controls, **not attacks on production masks, BGV keys or reviewed schemes**.

Uniformly guessing k clean coordinates has probability
`binom(n-tau,k)/binom(n,k)`. For a uniform square code submatrix, inversion also
needs full rank; rank loss/inversion/residual checks are separately excluded
from the reported **trial exponent**. It is not total attack work or a security
estimate. Fixed-weight noise, multiple samples and improved decoding need
their own analysis. The secret-guessing entropy filter is necessary only.

Monotonicity reduces the exact >=20% row-saving search to the largest feasible
tau for each k; independent tiny exhaustive search checks the optimization.
Eight retained geometries are screened without pretending to run large HE:

| Geometry | n / maximum F | Largest clean-set trial exponent among >=20% row-saving recipes | Cheapest recipe passing both incomplete 128-bit filters |
|---|---:|---:|---:|
| Mushroom | 523 / 32 | 9.76 bits | 52.65 products/row, **1.645x** baseline |
| Semeion | 1401 / 23 | 6.96 bits | 39.72 products/row, **1.727x** baseline |
| Connect-4 raw | 126 / 126 | 51.26 bits | None under the specified trial filter |
| Connect-4 affine | 82 / 82 | 33.09 bits | None under the specified trial filter |

These trial filters are deliberately conservative discriminators, **not an
approved parameter criterion** or a claim that no secure mask exists at these
dimensions. The fixed-weight clean-set count omits polynomial attack work and
other attacks. Sparse secret-index gathers also need private-timing protection;
an oblivious implementation can erase the apparent savings. Fresh independent
answer encryption, token provisioning and full-Q verification are unchanged.

## Return to R6

**Stop the specified one-level public-code recipe before HE/native work.**
It buys row savings only where the simple clean-set control is weak, and the
two larger query spaces already have much cheaper local row blocks. Preserve
this restricted negative; do not extrapolate to all correlations or call it
a novel impossibility theorem. Further R4 needs a construction that programs
the actual block operator safely, with a matched secret-code/recursive/PCG
baseline. The useful-system discriminator now returns to R2's same-harness
acquisition panel. R3's carry-aware/public-certificate mechanisms remain open.

```bash
.venv/bin/python benchmarks/programmed_mask_lab.py \
  --json-out /tmp/e74-new-run.json
```
