# P01: the original EMVP author artifact

2026-09-30. This supplements the earlier unified Rust reference rather than
replacing its retained runs. The original Go/C++ source is pinned, unchanged,
at `856762f5925fe873bb5cbc0401ceb5a44568efa9` in the workspace cache.
The repository is linked by Appendix F of the
[EMVP paper](https://eprint.iacr.org/2025/858.pdf):
[author source](https://github.com/SecretKeyCrypto/Encrypted-Matrix-Vector-Products).
Our isolated adapter is
`experiments/bfv_search_lab/references/emvp_author_adapter/`; our homemade
BFV/BGV deliverable implementations still use their own arithmetic.

## Measured complete scans

`benchmarks/emvp_author_lab.py` uses the same pinned binary fixtures and seed3001
enrollment/held-out query split as the other public controls. Each mode has two
rotating repetitions with eight queries. Every score and stable top3 is compared
with an independent popcount oracle outside timing. Online time includes binary
query conversion, masking/query generation, server answer, optional full gate,
private decoding and stable selection. Setup and body/state models are recorded
separately. These are CPU stage sums, excluding JSON and network transport.

| Original artifact mode | Mushroom online mean | Semeion online mean |
|---|---:|---:|
| Cached code, honest server | 3.702 ms | 0.979 ms |
| Cached code, own complete gate | 5.942 ms | 1.363 ms |
| Regenerate code per query, honest server | 4.002 ms | 2.259 ms |
| Regenerate code per query, own complete gate | 6.265 ms | 2.845 ms |

| Resource | Mushroom, 7,996 rows / 126 bits | Semeion, 1,465 rows / 256 bits |
|---|---:|---:|
| Query body (uint32 field words) | 2,024 B | 4,200 B |
| Response body (uint32 field words) | 1,471,264 B | 205,100 B |
| Encoded server index | 16,183,904 B | 6,153,000 B |
| Cached private code matrix | 191,520 B | 813,056 B |
| Additional private complete-gate body | 18,504 B | 38,088 B |
| Complete gated setup, cached mode mean | 0.567 s | 0.613 s |

The code-regeneration mode has no persistent preloaded code matrix; it needs
the same matrix size as transient scratch on each query. The gate generates
an additional m-word challenge scratch array. Key/context and query-mask
scratch models are in the raw runs. These are mathematical word-body models,
not measured peak RSS; the benchmark harness also retains owner/oracle data.

Our stronger global homemade BGV controls previously measured 25.933 ms with
65,536 B replies on Mushroom and 9.826 ms with 16,384 B replies on Semeion.
Thus the original gated EMVP control is substantially faster on this CPU,
but uses about 22.45x / 12.52x the reply bodies of those BGV controls. These
are distinct, unreviewed parameter/protocol profiles, not an equal assured
security comparison. Local raw/zlib caches remain mandatory and faster when
the authorized client may retain them. Actual bandwidth, reuse and client
retention constraints determine usefulness; CPU time alone does not.

Raw completed runs:

- `benchmarks/results/publication-original-emvp-mushroom-pinned-20260930.json`
- `benchmarks/results/publication-original-emvp-semeion-pinned-20260930.json`

## Parameters, gate and correctness controls

The adapter uses the author's `SlsnMVP` and `utils.Prms(128,4.0,d)` with
F65537. Mushroom has (l,k,n,b,S)=(126,380,506,11,46); Semeion has
(256,794,1050,30,35). The paper's 32-bit-field plots and other modes are
not reproduced by this 17-bit artifact configuration. Two implemented
algebraic inequalities pass; this does not certify the cryptanalytic target,
trapdoor matrix distribution, LSN assumptions, seeded entropy or composition.
The artifact uses math/rand/64-bit seed APIs; fixed profiling seeds are not
production cryptographic sampling. The earlier E42 floor is specific to its
unified-artifact profile and must not be generalized to these parameters.

The optional gate is our own addition. Trusted enrollment computes nine
hidden field fingerprints of the full public encoded matrix. A complete
encoded response is checked against the pinned query before any private
decoding. Uniform ideal field challenges give first-false-accept bound
1024/65537^9; the implemented AES-CTR expansion adds a PRG premise. Trusted
setup, hidden state, bounded global attempts and no private timing leakage
are required. This conditional argument is not a proof of the whole author
protocol. Honest, altered, truncated, consumed and exhausted-gate controls
pass in the adapter tests.

An initial unpinned Semeion code-regeneration run failed the independent score
range check. Native code generation seeds and reads a thread-local AES RNG
across separate C calls. GOMAXPROCS=1 does not bind those calls to one OS thread.
The adapter now pins its OS thread across the sequence, and regression tests
check code regeneration/transpose across forced GC cycles. Both pinned datasets
then pass all 64 queries each. The original failed run and successful unpinned
Mushroom run are retained; this is an adapter execution constraint, not a
claim of a published protocol break. Multithreaded integrations need explicit
native RNG-context handling. The author Slsn test's score assertion is commented
out, so passing upstream tests alone would not have found this discrepancy.

A separate exact negative control shows why an ordinary static encoding
cannot simply reuse its trapdoor mask during plaintext row edits: a systematic
encoded-column difference directly exposes a binary coordinate change.
It does not attack the static author protocol. Any incremental extension
needs fresh masking or a new privacy argument, and the planner must price it.

Build uses the unchanged reviewed author `run.sh`, Go1.23.12, C++ O3/march=native,
adapter `-buildvcs=false`, GOMAXPROCS=1 and `runtime.LockOSThread`. Go was downloaded
from [the official release list](https://go.dev/dl/) and checked against SHA256
`d3847fef834e9db11bf64e3fb34db9c04db14e068eeb064f49af747010454f90`.
Exact source, static-library and executable hashes are retained in each raw run.

Return to P01/P03: keep this stronger control, investigate safe exact affine
adaptation without assuming the earlier dimension floor, and retain the
recursive BNTM/low-state reproduction gap. No new GPU work or production
promotion follows from these timings.
