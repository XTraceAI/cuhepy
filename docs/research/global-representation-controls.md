# E51 supplement: global raw/affine controls change the preferred plan

2026-09-30. [Extended benchmark](../../benchmarks/score_layout_lab.py).
Same public split, held-out query prefix, exact full scores/IDs, field,
full-ring key distribution and complete pre-decryption fingerprint gate.
The stronger controls use one global CRT component, with raw identity or a
certified whole-index affine map. All fresh owner preparation is vectorized;
this is an ordinary baseline improvement, not a new cryptographic construction.

Three timed samples plus a warmup per configuration, no simultaneous timing
benchmark. Full serialization/parsing/check/decrypt/selection stages are paid;
initial key, owner backend, index/check setup and map discovery are reported.
Every score and stable top-three, native/GMP ciphertext and unreduced integer
phase agrees. N=2,048/Q32 remains an unreviewed research candidate despite the
[pinned heuristic screen](parameter-frontier-results.md).

| Fixture / representation | Full N | Reply body | Online stage sum | Offline fresh answer + check | Private map body |
|---|---:|---:|---:|---:|---:|
| Mushroom / global raw | 16,384 | 128 KiB | 52.176 ms | 33.225 ms | 150 B |
| Mushroom / global affine, rank 85 | 16,384 | 128 KiB | 49.047 ms | 32.720 ms | 565 B |
| Mushroom / global raw | 2,048 | 64 KiB | 28.042 ms | 18.435 ms | 150 B |
| Mushroom / global affine, rank 85 | 2,048 | **64 KiB** | **25.933 ms** | **17.962 ms** | 565 B |
| Semeion / global raw | 16,384 | 128 KiB | 60.832 ms | 31.134 ms | 296 B |
| Semeion / global affine, rank 256 | 16,384 | 128 KiB | 61.383 ms | 31.155 ms | 296 B |
| Semeion / global raw | 2,048 | **16 KiB** | **9.826 ms** | **5.205 ms** | 296 B |
| Semeion / global affine, rank 256 | 2,048 | 16 KiB | 9.776 ms | 5.297 ms | 296 B |

The local N=2,048 layouts measured about 45 ms/112 KiB on Mushroom and
19 ms/16 KiB on Semeion. The global controls are stronger in these online
profiles: they avoid local occupancy imbalance and expensive private map
contraction. Their corrections are scalar, eliminating a larger correction
subring. A larger F alone does not determine work. Semeion has full global rank,
so global affine adds no compression; the raw control is sufficient.

These gains have real server costs. At N=2,048 the canonical expanded index is
5,570,560 bytes for Mushroom global affine and 4,194,304 bytes for Semeion raw;
native word arrays cost more. Global coordinates require more private owner
storage than partitioned low-rank coordinates. Private map bytes alone are not
total client state: IDs/permutation, retained public/secret key, fingerprint,
tokens and Python objects remain. Raw/zlib local caches are still much faster
when plaintext retention is allowed; the outsourced-usefulness gate remains
open.

The preferred static profile changed twice after stronger controls. This is
why publication evidence must compare raw/global/equality/simple-layout choices
before crediting a more elaborate compiler. The results support an honest
representation/parameter frontier and a better company fallback; they do not
establish a novel paper or a full-life held-out gain. Return to E52's calibrated
dynamic reserve/noise policy and low-state baselines, with these controls.

Raw [Mushroom](../../benchmarks/results/publication-global-control-mushroom-20260930.json),
[Semeion](../../benchmarks/results/publication-global-control-semeion-20260930.json).
Reproduce with `.venv/bin/python benchmarks/score_layout_lab.py --dataset
semeion --cache-dir ../research-data/uci-20260927 --representations global_raw
global_affine --vectorized-owner --json-out /tmp/global.json`.
