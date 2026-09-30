# P01: first matched author-baseline reproduction

2026-09-30. Preliminary serial CPU results, **two measured requests plus one
warmup per profile**. These establish adapters and catch incorrect comparisons;
they are not the publication's multi-instance/p95 evaluation.

## Sources and exact metric

The unified-search author artifact is pinned at
[`519148cf3fddc11277a111774ca8cb92d891e0e3`](https://github.com/sacs-epfl/secure-vector-search/tree/519148cf3fddc11277a111774ca8cb92d891e0e3).
Its selected CPU crates passed **48 BNTM and 30 EMVP tests**. This is the unified
paper's BNTM implementation, not an original Braverman–Newman author artifact.
The artifact requests Rust 1.95.0; the installed 1.98.1 was used explicitly.
The external source is unchanged. The adapter has its own pinned Cargo lock.

Our [Rust adapter](../../experiments/bfv_search_lab/references/secure_vector_search_adapter/src/main.rs)
uses each native flat scorer and its measured stage breakdown, including BNTM
with verification both off and on. It transforms binary x to `1-2x`, so the
signed dot product is `d-2H`. With Q=2^20, d<=512, all integer products are
within the field's centered range; these power-of-two-scaled small integers
are exactly representable through the APIs' f32 output. Every score and stable
ID top-3 is compared, not only recall or the nearest result.

The first adapter failed because the BNTM API returns the **quantized** signed
field product, whereas EMVP divides by Q^2. The corrected adapter applies that
known scale and then asserts integer distances. No rounding tolerance or
author arithmetic modification hides the failure. Error logs are retained in
the external reference cache.

Both sides use the same SHA-verified UCI row split, enrollment IDs and adaptive
held-out query sequence, seed 3001. Author Rayon threads are pinned to one;
our existing native CPU evaluator/checker are single-threaded. Their trust,
parameter and state assumptions remain different and visible.

## Preliminary results

| Dataset / rows / dimensions | Backend | Query body | Response body | Local time |
|---|---|---:|---:|---:|
| Mushroom / 7,996 / 126 | Own BGV Q32, native polynomial gate | 523 B | 131,072 B | about 53.2 ms, measured stage sum |
| same | EMVP, author HBC | 10,336 B | 4,861,568 B | 84.7 ms elapsed |
| same | BNTM, author HBC | 8,192 B | 63,968 B | 20.0 ms elapsed |
| same | BNTM, author full Freivalds | 8,192 B | 63,968 B | 109.1 ms elapsed |
| Semeion / 1,465 / 256 | Own BGV Q32, native polynomial gate | 2,802 B | 131,072 B | 55.9 ms, measured stage sum |
| same | EMVP, author HBC | 10,336 B | 890,720 B | 13.7 ms elapsed |
| same | BNTM, author HBC | 8,192 B | 11,720 B | 3.6 ms elapsed |
| same | BNTM, author full Freivalds | 8,192 B | 11,720 B | 14.0 ms elapsed |

Own body sizes were serialized and round-tripped. Author body sizes are its
analytical u64 payload models; no socket timing is measured. Own totals add
paired timed stages; author elapsed totals additionally contain its async
scheduling and adapter work. A precise head-to-head latency claim needs the
new unified service harness. All ciphertext coefficients, integer phase checks,
four verifier controls, distances and stable selections passed our own anchor
reproduction; the author adapter passed every distance in all three modes.

This contradicts any blanket claim that BGV is always faster or communicates
less than other schemes. BNTM communicates less on both fixtures. EMVP's
76-share response is much larger. The BNTM verification slowdown is expected
from its **actual code**: three full `u*M_enc` reductions per reply, rather than
a stored small adjoint check.

## State and security qualifications that matter

The pinned BNTM Protocol-1 implementation retains native-word `M_plain` for
the `M*T` correction, plus `AL`, `H`, sparse `S` and `L`. Verified mode also
needs the full `M_enc` on the client. Dense bodies alone are at least
`m*(1024+2*128)*8 + 1024*128*8` bytes for decoding, and another `m*1024*8`
for verification. They are body counts, not an RSS measurement. The author
artifact does **not** implement the recursive Protocol-3 low-state variant.
That variant and a preprocessed verifier are necessary stronger follow-ups,
not competitors we may omit to manufacture a state advantage.

The artifact's optional verifier is a complete per-response Freivalds check
over retained encrypted matrix data. Distinguish it from the BNTM paper's
separate discussion of detecting a fraction of bad executions. The artifact
labels its LPN parameters as heuristic and does not estimate concrete hardness.
Own BGV profiles also remain research-only; passing correctness/checking tests
does not make their HE assumptions equivalent or production-approved.

Complete local packed/compressed-corpus caching remains a mandatory control.
Our Semeion full-cache timing is about 0.45 ms. IDs, permutation, private maps
and actual retained Python/GMP objects must be counted fairly before asserting
that outsourcing is useful on these small corpora. Model state is not actual
online-device RAM, especially in an in-process benchmark.

## Reproduction and evidence

From the research checkout, after the documented pinned external clone:

```bash
.venv/bin/python benchmarks/verification_frontier_lab.py \
  --cache-dir ../research-data/uci-20260927 --dataset semeion \
  --seed 3001 --repeats 2 \
  --json-out benchmarks/results/publication-anchor-semeion-20260930.json
.venv/bin/python benchmarks/run_secure_vector_reference.py \
  --anchor benchmarks/results/publication-anchor-semeion-20260930.json \
  --cache-dir ../research-data/uci-20260927 \
  --json-out benchmarks/results/publication-reference-semeion-20260930.json
```

Repeat for Mushroom. Raw artifacts are
[`publication-anchor-mushroom-20260930.json`](../../benchmarks/results/publication-anchor-mushroom-20260930.json),
[`publication-anchor-semeion-20260930.json`](../../benchmarks/results/publication-anchor-semeion-20260930.json),
[`publication-reference-mushroom-20260930.json`](../../benchmarks/results/publication-reference-mushroom-20260930.json),
[`publication-reference-semeion-20260930.json`](../../benchmarks/results/publication-reference-semeion-20260930.json).
Reference input, fixture, compiler, source/lock and binary hashes are retained.
The driver checks the commit and rejects edits to the selected author crates.

**P01 remains partial:** code-based low-state variants and checks, native vLHE
registration/norm modes, approximate/proof baselines, actual separated-state
memory, three instances, serial sessions, larger samples and GPU comparisons
remain. The GPU is accessible with approved execution outside the sandbox
(RTX 3080, driver 595.91.07); no new GPU timings are implied here.

## Stronger original author and cache controls

The original EMVP Go/C++ implementation is now separately reproduced at
`856762f5925fe873bb5cbc0401ceb5a44568efa9`, via a retained exact-Hamming adapter:
[original-author report](original-emvp-results.md). It is much faster than the
unified Rust EMVP control here and has different code dimensions/response sizes.
Private full-response gates and cached/key-only modes are charged separately.
An OS-thread-affinity adapter failure is retained; pinned forced-GC tests and
both exact datasets pass. Upstream's selected Slsn score assertion is commented
out, so its three passing tests alone were not exact-score evidence. No author
source is modified; entropy/concrete-parameter assurance remains unreviewed.

The latest [authenticated cache acquisition](cache-acquisition-results.md),
[dynamic private-buffer controls](client-buffer-results.md) and
[larger real encrypted/cache comparison](connect4-encrypted-controls.md)
supersede any implication that plaintext retention is prohibited or only tiny
cache queries were tested. The user expressly permits retention. Recursive
BNTM/strongest compatible vLHE and a publication-size controlled comparison
remain open; partial reproduction is not complete P01 acceptance.
