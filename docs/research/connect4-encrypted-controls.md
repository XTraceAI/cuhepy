# E61: larger real encrypted/cache controls on a declared Connect-4 prefix

2026-09-30. P00/P01/P03/P06 scale discriminator after E58's67,429-row cache
pilot. The encrypted compiler has an implemented **correctness-oracle bound**, not
a security approval, of32768 rows. This experiment explicitly enrolls the
first32768 IDs of split seed3001's shuffled enrolled list; it does not enlarge
that bound or claim a full67,429-row HE run. All32768 vectors are distinct;
held-out query IDs remain outside every owner fit.

One warmup plus three timed queries per global raw/affine control; single full
N2048/t193/Q32/eta21 profile. Homemade native public evaluation, lossless body
serialization/parsing, full-vector pre-decryption checking, secret decryption,
every score/ID/top3 and unreduced integer/native/GMP diagnostics pass. Raw/
zlib1/zlib9 AEAD cache controls use **the same IDs and four query words**;
every HE/cache complete-score hash agrees. This is one instance, not p95 or
publication-size independent repetitions; no GPU or network is measured.

| Control | Rank/F | Actual reply / cache packet | Mean timed online CPU | Fresh offline answer+check |
|---|---:|---:|---:|---:|
| Global raw BGV | 126 | 262,144 B per reply | 110.96 ms | 72.44 ms |
| Global affine BGV | 82 | 262,144 B per reply | 102.46 ms | 71.16 ms |
| Raw AEAD → raw cache | — | 786,524 B once | 2.94 ms | no token |
| zlib1 AEAD → raw cache | — | 305,261 B once | 3.08 ms | no token |
| zlib9 AEAD → raw cache | — | **247,388 B once** | 3.02 ms | no token |

Ordinary affine reduction saves about7.66% online compute,34.92% canonical
expanded index (33,030,144→21,495,808 B) and native word arrays
(66,060,288→42,991,616 B). It does not change the16 replies. Global affine fit
costs1.816 s and every row is certified. Per-case compilation, keys, owner,
enrollment, native and gate preparation are reported separately; no complete
lifetime gain is inferred. The rank82 reflects known categorical/fixed-count
relations in this board representation, not novel factorization.

Cache owner+client acquisition costs30.62/28.10/400.48 ms for raw/level1/level9.
First-use AES initialization is charged and visible. The most compressed
**whole cache is smaller than one HE reply** here, yet costs more owner work
than level1; separately model prepaid owner preparation and current client
acquisition. State bodies are not RSS; no compressed-length-free privacy claim.

Raw: `benchmarks/results/publication-connect4-encrypted-controls-20260930.json`.
Entry point `benchmarks/score_layout_lab.py --dataset connect4 --connect4-file
../research-data/uci-connect4-20260930/connect-4.data --max-index-rows 32768`
(use separate arguments as in the raw command). Source provenance/license and
all hashes are in [the cache report](cache-acquisition-results.md).

Return to the plan: growing the real corpus beyond the original small fixtures
does not establish outsourcing usefulness in this pilot. Retain this strong
adverse control. Larger full corpora, devices, one-shot provisioning/RTT and
reviewed profiles remain necessary before promoting a system advantage.
