# Adaptive queries and a joint field/geometry frontier

Eleventh creative cycle, 2026-09-29. E34 implements exact ideal-mask transcript
oracles and failure controls. E35 separates private rank discovery from final
plaintext CRT geometry and selects a field using index data alone. The source
checkpoint is `461bb10f75f23a5f230bb7375cfd08e61e2b9c24` on
`experiment/creative-search-algebra`. All encrypted arithmetic is homemade
GMP/Python and the existing single-thread C++ short-NTT evaluator; this cycle
does not import SEAL or change company clients, CUDA kernels or production APIs.

The main result is **the same 20% response/index body reduction as E32, now
using the existing deterministic correctness bound with queries chosen after
enrollment and offline-answer preparation**. This is not another 20% reduction
on top of E32. Mushroom also halves its query body. Checked local CPU time
increases because q32 needs five fingerprint rounds rather than q40's four.
These are representation and scheduling results, not a new security proof or
an established novel contribution.

## E34: which adaptive transcript admits the ideal argument?

Let the reused encryption errors be E. At request i, a policy fixes w_i using
E and previous history, then receives an independent uniform mask r_i in
F_t^h. The correction is delta_i = w_i - r_i. For every e, previous history
and a, the map r_i -> w_i-r_i is a bijection, so

```text
Pr[delta_i=a | E=e, previous history] = t^(-h).
Pr[delta_1=a_1, ..., delta_k=a_k | E=e] = t^(-hk).
```

Induction gives joint independence of the correction transcript and E in this
ideal model, even though the policy sees earlier error-weighted toy phases.
The timing restriction is essential: it cannot see anything about the current
mask before fixing its query or choosing the token.

[adaptive_masking_oracles.py](../../experiments/bfv_search_lab/adaptive_masking_oracles.py)
enumerates entropy exactly. At t=5, h=2, independent CBD(1) errors, the distance
below is total variation between the joint distribution of **errors and
corrections** and the product of its marginals. It is not a cryptographic
distinguishing advantage or a claimed attack on the current HE protocol.

| Model | Requests | Weighted enumeration mass | Exact independence distance |
|---|---:|---:|---:|
| Fresh independent masks; query committed first | 2 | 10,000 | 0 |
| Reuse the first mask | 2 | 400 | 11/16 |
| Reveal only the sum of the current mask first | 2 | 10,000 | 5/8 |
| Reveal two candidates and select using errors | 1 | 10,000 | 9/50 |

The early-disclosure control forces sum(delta) to equal the sign of one error;
recovering the entire mask is unnecessary. The selection control chooses the
larger error-weighted phase. These are deliberately stronger chooser views
than the intended remote server receives, useful for ruling out overly broad
claims. Tests also enumerate single-step bijections and adaptive joint
independence over multiple tiny fields and dimensions.

**The real-transcript gap remains.** Real preprocessing exposes an encrypted
index, encrypted mask answers, public expansion seeds and protocol metadata.
An owner/caller may also have a key or plaintext coordinates that reveal
linear forms of a mask. Replacing that view with an ideal fresh pad requires
an explicit computational argument and owner/caller/collusion model. Naming
HE privacy or SHAKE does not by itself establish independence from the HE
errors under the conditioning needed for a concentration proof.

Consequently E32's fixed-before-enrollment statistical type and rejecting old
key gates remain unchanged. This experiment does not relax E32 to accept
adaptive queries. E35 instead obtains a useful q32 result from an absolute
bound, which needs no correction/error independence argument.

## E35: private discovery cuts are not polynomial factors

The inherited plaintext prime was t=1,153. Its large range increases centered
correction magnitudes and the message/error bound even where a smaller field
can represent every exact distance. Each candidate field must satisfy:

1. t exceeds the binary dimension, so the decoded distance cannot wrap.
2. Every map is fitted afresh over F_t and certified against every enrolled row.
3. The **final** dyadic cover has valid factors and enough capacity. A depth-D
   split requires an element of order 2^(D+1), hence 2^(D+1) divides t-1.
4. The deterministic phase bound fits the chosen Q; fingerprint rounds meet
   the declared conditional lifetime target.

The old rank-repair routine used one tree for private grouping and temporary
CRT geometry. Mushroom's useful grouping reaches depth six. At t=193 the
eventual 32-slot geometry requires only depth five, but the old routine rejects
the temporary deeper grouping for lack of roots.

[field_frontier.py](../../experiments/bfv_search_lab/field_frontier.py) separates
those steps. It discovers private source groups without requiring roots for
their temporary paths, then uses the existing exact fixed-map allocation and
factor/CRT oracle to construct a valid final cover. It does not use invalid
factors, shrink encryption degree, expose private maps, or reinterpret a map
from another field as a certified one. A tiny control has valid depth-four
private groups over F_17 and a valid depth-three final cover even though its
private paths cannot themselves be polynomial factors there.

The benchmark tries local rank targets 16, 32 and 64, each admissible final
slot count in {1,2,4,8,16,32,64}, and a global affine control. Mushroom fields
are {127,193,257,1153}; Semeion fields are {251,257,769,1153}. Failed fits,
insufficient roots and allocation failures are retained with reasons.
Selection minimizes query plus response coefficient bodies under the old
q40 local canonical-index cap, then index/map bytes and correction degree.
This is a finite heuristic frontier, not a global optimum or latency selector.

At full encryption N=16,384 and bounded fresh CBD(eta=21) errors, put b=floor(t/2)
and let W be the sum of public correction degrees. The existing absolute bound
is

```text
fresh_phase <= b + t*eta
sum of absolute centered correction coefficients <= W*b
B_absolute = (b + t*eta) * (1 + W*b) < Q/2.
```

It covers all centered corrections, including choices dependent on previous
results or encryption randomness. It assumes the trusted inputs have the
bounded fresh phases and the prescribed honest linear circuit is executed;
it is not an authentication claim for arbitrary server ciphertexts.

| Dataset | Old t / W / bound | Selected t / W / bound | Selected geometry |
|---|---|---|---|
| Mushroom | 1,153 / 1,024 / 14,621,171,925 | 193 / 1,024 / 407,867,445 | F=32, 32 slots, one reply |
| Semeion | 1,153 / 1,472 / 21,017,923,797 | 257 / 1,472 / 1,041,003,925 | F=23, 64 slots, one reply |

The selected bounds fit q32=4,294,475,777. The old paired control uses
q40=1,099,510,054,913. Ciphertext degree, number of public columns and reply
capacity stay unchanged. These are correctness parameters, not an RLWE
security estimate. The analytic frontier also projects smaller moduli, but
the existing owner/key APIs require at least 32 bits: **below-q32 entries are
models, not implemented encryption profiles**. Fixed-CBD entries in the
frontier CSV retain E32's separate fixed-query contract.

Each selected field is also refitted on the original t=1,153 memberships.
All four refit controls reproduce the selected layout and maps exactly, so
there is no extra benefit from changing source memberships in these runs.
Duplicate encrypted cases are skipped and explicitly labeled as such. The
legacy root-limited fit fails on both Mushroom splits and succeeds on both
Semeion splits; decoupling is necessary for these Mushroom controls.

## Retained paired measurements

The pinned public datasets use two independent index splits, seeds 3001 and
3002. Mushroom has 7,996 index rows in 126 categorical-indicator dimensions;
Semeion has 1,465 index rows in 256 binary-pixel dimensions. Dataset attribution
and schema are in the [original public-data report](dictionary-witness-results.md)
and [fixture loader](../../experiments/bfv_search_lab/binary_fixtures.py).
Timings were collected serially on a Ryzen 5800X under Python 3.12.3, with one
warmup and eight measured searches per case. Case order reverses between splits
and GMP/native evaluation order alternates. No GPU or network timing is used.

| Dataset / seed | Query body, old -> new (B) | Response body, old -> new (B) | Query + response, old -> new (B) | Canonical index, old -> new (B) |
|---|---:|---:|---:|---:|
| Mushroom / 3001 | 1,046 -> 523 | 163,840 -> 131,072 | 164,886 -> 131,595 | 5,242,880 -> 4,194,304 |
| Mushroom / 3002 | 1,192 -> 596 | 163,840 -> 131,072 | 165,032 -> 131,668 | 5,242,880 -> 4,194,304 |
| Semeion / 3001 | 2,802 -> 2,802 | 163,840 -> 131,072 | 166,642 -> 133,874 | 3,768,320 -> 3,014,656 |
| Semeion / 3002 | 2,802 -> 2,802 | 163,840 -> 131,072 | 166,642 -> 133,874 | 3,768,320 -> 3,014,656 |

Query plus response bodies decrease by 20.19–20.22% on Mushroom and 19.66%
on Semeion. Mushroom's field now fits one byte; t=257 on Semeion still needs
two. These counts exclude transport framing, receipts, keys and offline token
traffic. They are not a comparison with Paillier or a universal network ratio.

| Dataset / seed | Native server ms, old -> new | Verification ms, old -> new | Decrypt ms, old -> new | Checked native local ms, old -> new | GMP server ms, old -> new |
|---|---:|---:|---:|---:|---:|
| Mushroom / 3001 | 12.22 -> 12.19 | 35.01 -> 42.09 | 17.04 -> 16.26 | 82.62 -> 88.62 | 851.71 -> 830.09 |
| Mushroom / 3002 | 12.59 -> 12.17 | 35.46 -> 42.12 | 17.22 -> 16.20 | 84.16 -> 88.72 | 868.44 -> 830.97 |
| Semeion / 3001 | 13.38 -> 13.02 | 37.22 -> 44.01 | 17.19 -> 16.22 | 87.00 -> 91.98 | 651.38 -> 612.21 |
| Semeion / 3002 | 13.50 -> 12.68 | 37.35 -> 43.71 | 16.95 -> 16.12 | 86.93 -> 91.23 | 650.37 -> 609.62 |

Entries are medians, rounded independently. The checked local total includes
owner transform/ticket consumption, query packing and public parsing, server
evaluation, response packing and public parsing, verification, secret
decryption, and complete score decoding/stable selection. It excludes offline
work, GMP reference comparison, integer-phase diagnostics and assertion time.
It is a sum of measured stages, not elapsed network or pipelined latency.
Response packing costs about 3.4–3.6 ms and parsing about 6.3 ms in both fields.
Medians of stages need not sum to the median total.

**Why the smaller payload does not give a CPU speedup:** N, ciphertext count,
public correction degrees and C++ u64 NTT storage remain the same. Native
server work therefore changes little; converting 32,768 response coefficients
also remains necessary. The additional verification round costs about
6.4–7.1 ms, exceeding the small decryption/decoding savings. Local time rises
4.3–6.0 ms. A serial payload-only model gives break-even link rates around
44–61 Mb/s, but omits overlap, latency, authentication and offline traffic;
it is not a measured network result.

### Setup, state and negative controls

The retained frontier has 61 accepted candidate layouts and 171 rejected
candidates across the four runs. Each accepted layout has deterministic and
fixed-CBD **modeled** profiles, giving 122 exported rows. Global affine
controls require 11,141,120 B canonical index bodies on Mushroom and
33,554,432–41,943,040 B on Semeion, exceeding the local cap. A lower correction
degree alone is therefore not the selector's objective. Semeion's t=251 fails
the score-range guard; roots and capacity reject further candidates.

| Dataset / seed | Private map body B, old -> new | Owner coordinate 2-bit body model B | Standalone setup stage sum s, old -> new | Nine-answer pool stage sum s, old -> new |
|---|---:|---:|---:|---:|
| Mushroom / 3001 | 9,542 -> 8,027 | 50,456 | 6.96 -> 42.39 | 0.72 -> 0.76 |
| Mushroom / 3002 | 11,386 -> 9,600 | 48,771 | 7.13 -> 43.02 | 0.71 -> 0.77 |
| Semeion / 3001 | 551,460 -> 551,460 | 8,020 | 7.80 -> 47.70 | 0.63 -> 0.69 |
| Semeion / 3002 | 549,678 -> 549,678 | 8,020 | 7.83 -> 47.78 | 0.63 -> 0.68 |

The baseline preparation charges its recorded same-field fit/allocation work;
the selected case charges the **entire field frontier search**, including
rejected attempts. That frontier ran once in the paired experiment. These are
standalone recorded-stage accounting models, not repeated elapsed setup
benchmarks. A deployment that reuses a prior field decision has a different
cost; it must not silently drop search cost from this table. Diagnostic audit
preparation is excluded, and complete token-pool work is shown separately.

Expanded canonical index bodies shrink by 20%, while native NTT words remain
8,388,608 B on Mushroom and 6,029,312 B on Semeion. Actual seeded index packets
are 2,624,832 -> 2,100,544 B and 1,886,598 -> 1,509,766 B respectively. Each
actual seeded offline-answer packet is 82,026 -> 65,642 B; all nine are charged,
even when only one or four searches are completed. Expanded answers consume
1,474,560 -> 1,179,648 B for the nine-token pool, plus mask/check state.
The two-bit owner coordinate figure models ternary plaintext coordinate cells;
it is not an implemented compact codec or Python heap measurement. Private
map bytes are canonical bodies, also excluding object overhead.

A separate complete plaintext cache answers the same queries in about
2.9–3.0 ms on Mushroom and 0.46–0.47 ms on Semeion. Raw row bodies are
127,936 / 46,880 B; zlib bodies are 28,889–28,985 / 25,962–25,989 B. Timings
include full Hamming scoring and stable sorting, with plaintext already in RAM.
This changes client state and the outsourced encrypted-search contract. It is
an essential alternative: Semeion's private maps alone are much larger than
the compressed full data. The experiment does not establish that this
preprocessing/state tradeoff is preferable in a deployment.

Public geometry still reveals its sizes, capacities, final cover and map
equality selectors. Data-dependent field/layout decisions are not an oblivious
index-construction protocol. The [correlation contract](authenticated-correlation-contract.md)
records the separate setup, collusion, state and leakage obligations.

Maximum measured unreduced phases, including warmups, are 5,091,331–5,597,108
for selected Mushroom and 10,668,327–11,787,305 for selected Semeion. They are
below the universal absolute bounds. These observations do not certify a
failure probability; the guarantee being exercised is the existing absolute
bound for the prescribed bounded-input circuit.

## Verification, diagnostics and limits

All queries are chosen after the entire index and nine independently encrypted
offline answers have been prepared. Starting with winner=0, query i selects
candidate 2*i+(previous authenticated winner source ID mod 2). Only then is its
private affine query transformed and its one-use ticket consumed. The next
choice uses the authenticated full-score result, not a predeclared schedule.
Paired fields follow identical query paths and stable tie-breaking.

The existing hidden full-coefficient fingerprint verifies the parsed response
before any HE secret product on that server response. At budget 1,024 and
target 128 conditional
integrity bits, the least round count satisfies Q^rounds >= 1,024*2^128:
four for q40, five for q32. That target is distinct from correctness bits and
lattice security. This local conditional verifier assumes trusted enrollment,
trusted independently encrypted offline answers and the existing hidden
challenge/seed assumptions. It is not the production TEE receipt path and
does not solve malicious setup, collusion or durable token state.

[integer_phase_audit.py](../../experiments/bfv_search_lab/integer_phase_audit.py)
is an owner-only diagnostic excluded from online timing. It reconstructs fresh
phases and every response coefficient modulo an auxiliary integer modulus
larger than twice the universal absolute bound, then checks the unreduced
integer phase against the actual ciphertext modulo Q and its runtime bound.
A tiny test independently reconstructs schoolbook secret phases and correction
products. Private phase vectors are not serialized; report digests are local
diagnostics, not wire fields or secure-error-disclosure APIs.

The body parser is a local lossless benchmark helper, not a new hardened or
authenticated wire format. Full body packing and parsing are timed. This is
broader than E32's local-total definition, so compare the paired controls in
this report rather than comparing local totals directly across cycles.

A checking prime independent of Q is not a free way to regain four rounds.
The retained scalar counterexample has Q=5, checking P=7, c=4, alpha=2:
the honest Q residue is 3, but naive P checking expects 1. That both rejects
the honest result and accepts the wrong Q residue 1. Complete integer
Q-reduction carry and range relations are needed for such a redesign.

## Prior work and contribution ledger

[Alexandru et al., Application-Aware Approximate Homomorphic Encryption](https://eprint.iacr.org/2024/203.pdf)
is read at abstract/introduction and Sections 2.1–2.2, including the adaptive
correctness game. It emphasizes an allowed application/circuit class rather
than treating a successful parameter estimate as generic assurance. This is a
modeling precedent; the prototype has not been proved to satisfy their model.

[Slalom](https://arxiv.org/html/1806.03287v2), Sections 3.2–3.3 and Appendix B,
provides known secret preprocessing, one-use blinding and a PRG-to-ideal-pad
hybrid. Its proof does not establish our encryption-error-conditioned
independence or authenticate our encrypted-matrix preprocessing.

[Halevi and Shoup, Design and Implementation of a Homomorphic-Encryption Library](https://people.csail.mit.edu/shaih/pubs/he-library.pdf),
Section 1.1 and the introduction to Section 1.2, provides the established
plaintext factor/slot and arithmetic context. Field-dependent packing and CRT
are known. Our private grouping/final-cover separation and coupled cost
frontier are experiments, not automatically a new primitive.

The tested difference is a search representation whose private grouping,
final packing, field, absolute noise allowance and verifier cost are selected
together. The positive prediction is confirmed on two datasets/two splits:
the old same-capacity q40 circuit runs deterministically at q32 after refitting
the field. The negative prediction is also confirmed: this alone does not
reduce checked local latency. The ideal transcript experiment preserves a
specific proof gap rather than resolving it by changing the API.

## Next discriminating experiments

E36 should bound the norm of the **actual correction image**, not the full
coefficient cube. Delta has h coordinates while corrections have W coefficients;
duplication, unused coordinates and linear relations may tighten a uniform
worst-case bound without a concentration assumption. Start with exact tiny
linear-code/lift oracles and rigorous upper/lower bounds. If Z correction
coefficients are nonzero linear forms of a uniform delta, each is individually
uniform, giving the obstruction

```text
max_delta sum_j |center(alpha_j(delta))| >= Z*b*(b+1)/t.
```

This uses expectation and needs no independence between coefficients. It is
not yet implemented or asserted for a particular measured layout; determine
Z rather than assuming Z=W. A weak bound or unchanged byte boundary is a
useful negative result. A surviving bound must include private maps, carries,
universal correctness, verifier rounds and full setup costs.

E33's authenticated two-field conversion remains a competing direction,
subject to the retained false-accept/false-reject example. E34's real encrypted
transcript requires a separate protocol argument. Native narrow-word storage,
CUDA integration and production assurance can follow a discriminating
mathematical result; they are not the default creative experiment.

## Validation and artifacts

The [retained test transcript](../../benchmarks/results/field_frontier_validation_pytest.txt)
records **405 passed in 9.88 s**; Ruff and Mypy pass on the new source. The
18 added tests include ideal entropy/failure oracles, invalid roots and stale
maps, characteristic-dependent rank, all binary queries for tiny exact scores,
32 encrypted adaptive searches, independent schoolbook phase checking, and
the two-field carry counterexample. No new tests are claimed to constitute
independent cryptographic review.
The [validation record](../../benchmarks/results/field_frontier_validation.md)
gives the exact selected regression command and audit scope.

The four retained benchmark reports contain **72 full-size encrypted searches,
36 distinct dataset/query IDs, and 1,179,648 unreduced phase coefficients
checked**. Every complete distance list and stable top-three answer matches
plaintext; every GMP/native coefficient and every body round trip agrees.
The [manifest](../../benchmarks/results/field_frontier_manifest_20260929.json)
records 108 source/binary hash checks, matches tracked source against the
recorded measurement commit, and hashes the reports, logs, exports, summarizer
and test transcript. This is reproducibility checking, not a security proof.

Entry points and retained data:

- [Benchmark harness](../../benchmarks/field_frontier_lab.py) and
  [audit/export script](../../benchmarks/field_frontier_summary.py).
- Raw reports: [Mushroom 3001](../../benchmarks/results/field_frontier_mushroom_3001_20260929.json),
  [Mushroom 3002](../../benchmarks/results/field_frontier_mushroom_3002_20260929.json),
  [Semeion 3001](../../benchmarks/results/field_frontier_semeion_3001_20260929.json),
  [Semeion 3002](../../benchmarks/results/field_frontier_semeion_3002_20260929.json).
- [Stage/body measurements](../../benchmarks/results/field_frontier_stages_20260929.csv),
  [paired comparisons](../../benchmarks/results/field_frontier_comparisons_20260929.csv),
  [pool utilization models](../../benchmarks/results/field_frontier_utilization_20260929.csv),
  [accepted frontier models](../../benchmarks/results/field_frontier_accepted_models_20260929.csv),
  [rejected candidates](../../benchmarks/results/field_frontier_rejected_models_20260929.csv).

Reproduce with the pinned cache already present, running the four dataset/seed
combinations serially:

```bash
.venv/bin/python benchmarks/field_frontier_lab.py \
  --cache-dir /path/to/pinned/uci/cache --dataset mushroom --seed 3001 \
  --repeats 8 --json-out benchmarks/results/field_frontier_mushroom_3001_20260929.json
.venv/bin/python benchmarks/field_frontier_summary.py
```

The retained summarizer intentionally expects eight measured samples and one
warmup; pilot runs are not pooled into these timings. The source at the
measurement commit and the separately recorded native binary hash must match
before regenerating its manifest. Future forks should use a new stamp and
record their own source and profile assumptions.
