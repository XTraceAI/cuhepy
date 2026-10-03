> Latest bounded return2026-10-03: [E115/E117–E119](seeded-correctness-return-20261003.md)
> and [machine queue](publication-work-packages.json). The unit-free fixed-prefix
> ideal consequence now has independent public oracles; the squarefree extension
> uses prime-limb bounds. Protected-checker costs are explicitly paid.
> [Q46/E120](multilimb-owner-consequence-plan-20261003.md) is proposed, not executed.
> No new timing, original-main selection, actual cryptographic/parameter approval
> or production change. Earlier amendment/body below remains historical.

> Current execution amendment2026-10-03: see the
> [E109–E115 return](verification-aware-screens-return-20261003.md) and
> [queue](publication-work-packages.json). E109–E114 bounded components now have
> actual/scoped results; E115 remains partial. The planning/reassessment body
> below is preserved historical evidence, not current execution status. No new
> timing, original-main selection or parameter approval occurred.

# Results that govern the next contribution plan

2026-10-03. Read-only reassessment at `8fdc431aa480634cd26bee8e3f73a53ef41b6d4c`
(`checkpoint/native-proof-interface-2026-10-03`). This revision runs no benchmark,
HE evaluator, proof backend, security estimator or correctness suite. Earlier
raws, failed attempts, measurement cohorts and source identities remain intact.
Use the [new plan](contribution-plan-20261003.md) and
[closest-work comparison](closest-work-comparison-20261003.md).

## 1. The company system is useful; a paper mechanism is still conditional

Homemade Paillier, BFV and shallow BGV, Python/GMP references, C++/RNS and CUDA
evaluators are valuable deliverables. SEAL remains a separately labeled oracle
and performance control. Strong measured arithmetic and payload gains survive
the monitored reassessment. They do not establish equal-security comparisons,
an authenticated GPU service, or an original cryptographic construction.

The main unresolved opportunity is the **complete cost of safely accepting a
native encrypted answer**. Making the evaluator faster does not automatically
make proving, checking, provisioning or decoding it cheaper. Our accumulated
experiments expose several points where an isolated saving moves work into
another component. This is evidence for studying those boundaries, rather than
continuing to present individual identities as new protocols.

## 2. Matched timing and payload anchors

These are existing observations, not new measurements. The source of record is
the [monitored revalidation report](measurement-revalidation-20261001.md), which
links frozen raw/source/resource accounting. Medians, stage measurements and
process/block uncertainty have their recorded scopes; do not combine fixtures.

| Same matched 8,192-vector, 512-bit comparison | Recorded local elapsed (ms) | Interpretation |
| --- | ---: | --- |
| Paillier CPU | 56,316.163 | Package baseline |
| Paillier CUDA | 2,147.631 | CUDA arithmetic control |
| Paillier lookup CPU | 8,611.322 | Lookup control |
| Paillier lookup CUDA | 632.319 | Lookup plus CUDA control |
| Paillier lookup hybrid: CPU server, GPU client | **344.524** | Strongest Paillier control in this cohort; client GPU is paid |
| Homemade BFV CPU | 19,853.807 | Homemade CPU control |
| Homemade BFV CUDA | 486.336 | Public evaluator CUDA control |
| Homemade BFV prepared CUDA | **395.213** | Prepared-index control; CPU client |

Prepared BFV is **14.71% slower** than the lookup hybrid on this local cohort.
Its client preparation/server/client finish stages are 197.114/171.007/27.157 ms.
The hybrid's CPU-server/GPU-client finish stages are 48.843/291.524 ms. Report
observed elapsed separately from stages; stage sums are not a replacement for
the measured whole operation.

| Communication on that same fixture | BFV prepared CUDA | Paillier lookup hybrid | Reduction |
| --- | ---: | ---: | ---: |
| Response bytes | 204,900 | 4,226,953 | **20.63×** |
| Query plus response bytes | 942,294 | 4,227,497 | **4.49×** |

The Paillier/BFV parameters and hardware roles differ: the recorded Paillier
modulus is 2,047 bits with alpha 280/exponent 279; BFV uses N16,384, t65,537,
Q180, radix30, eta21 and response50. No equal-hardness claim follows. Index/key
enrollment, full authentication, WAN, fetched content and production lifecycle
are outside this timing comparison. The smaller BFV response can change a
bandwidth-limited operating point; that remains a network model until measured.

| Other existing panel | Observation | Scope that must remain separate |
| --- | --- | --- |
| BGV/BFV 8k paired panel | BGV workspace **60.047 ms**, response **102,488 B**, exchange **348,354 B**; BFV **396.411 ms**; all-CUDA Paillier lookup **661.781 ms** | Different corpus/seed from the hybrid cohort; no paired BGV/hybrid ratio |
| BFV prepared server APIs, 1,024 / 8,192 / 32,768 vectors | CPU 2.441 / 19.570 / 78.381 s; GPU 0.03445 / 0.17104 / 0.64635 s; **70.87 / 114.42 / 121.27×** | Server-only, setup excluded; not full client/server speedups |
| E27 complete matching CUDA blocks | Allocation and repair ratios **1.00153 [0.99966,1.00340]** and **1.00075 [0.99980,1.00171]** | Both intervals include a tie; no robust practical GPU gain |
| E79 two small isolated service/acquisition fixtures | Permitted cache **0.708 / 0.141 ms** versus fresh HE **47.288 / 17.349 ms** | Strong local/cold-client controls; no general outsourcing advantage shown |

The resource audit sampled shared-desktop activity, retained flagged and failed
jobs, and completed the user's requested idle-window comparison. It does not
certify exclusive hardware use or identify prior contention as the cause of a
difference. Missing dirty historical source closures and runtime/toolchain
changes remain qualified. Frozen measurement accounting is unchanged.

## 3. What the experimental portfolio taught us

This is a decision summary of E01–E108, not a claim that every possible
hypothesis has been exhausted. Follow the linked reports and
[historical synthesis](research-synthesis-and-system-roadmap.md) for exact scopes.

| Family | Evidence worth retaining | Consequence for the next experiment |
| --- | --- | --- |
| E01–E16 arithmetic, packing, workspaces and precision | Shallow BGV, prepared transforms, partial reductions, native codecs and GPU reuse improve particular measured stages. Concurrency trades latency and memory. | Keep these as strong common baselines; ordinary RNS/NTT, fusion and packing are established ingredients. |
| E19–E28 representation, filters, rank and CRT | Structured data can admit exact folding; unstructured data, rank repair and complete refinement can defeat it. Large CPU savings do not imply similar GPU savings. | Require irregular, unstructured and update fixtures; give the competitor vectorized/native arithmetic. |
| E29–E40 reusable answers, masks and output semantics | Fresh one-use owner answers remove online products at substantial preparation/state cost. Public linear mask banks leak joint queries. Histogram moments alone do not recover IDs. | Separate token amortization and output modes. Every query, unused token and exact stable-ID coverage remains paid. |
| E41–E65 static/lifetime models and update/service controls | Exact grammar/frontier oracles exist. E43 pending repair loses 9.25%/7.88% to vectorized fresh; E57's tested online rule always keeps deltas. Permitted caches beat measured HE reuse regimes. | An optimizer needs real competing actions and held-out effect; never manufacture a cache prohibition or infer an online win from hindsight DP. |
| E66–E81 complete release/registration controls | Exact extraction, composed graphs, once-compiled adjoints, original-query binding, private bootstrap and bounded alternative traces are implemented in scoped controls. E77 factoring loses after trusted factory work; E80's literal module replies grow 2.41–2.57×. | Price state and preparation at every party. Canonical and semantic release are distinct relations; neither a checksum nor an affine identity is a complete protocol. |
| E82–E99 construction and precision screens | Known modular conversion, signed LUTs, conditional owner randomness and exact sample laws survive. Specific correlation/orbit/precision recipes are contained or fail their targets. Some public-prefix security profiles fail named heuristic screens. | Retain controls and counterexamples; stopped recipes do not prove whole classes impossible. No smaller modulus is approved by a correctness-only bound. |
| E101–E105 complete boundary, lifetime, summaries and carry laws | Honest-output false canonical witnesses pass affine-only checks. E102's matched standard adapter equals all648 registered formulas. E103 coverage is an oracle, not private retrieval. E105 preserves dependent noise exactly, but all6,561 full states are distinct per query. | Seek a different representation or certified summary; do not repeat generic folding, union bounds, or full-state merging. |
| E106–E108 actual native boundary and complete scalar relation | Native/Python agreement, terminal lift, common integer/RNS linkage and three complete transparent R1CS models are preserved. Strong generic folding gets the same counts as the candidate. | Execute an actual proof control to locate complete costs; separately screen new graph/noise algorithms before investing in integration. |

## 4. E108 is a proof frontend, not a proven speedup

The [complete relation report](native-proof-interface-screen.md) uses a tiny
N8/D4 fixture: all eight original three-bit queries, nine records including
ties, 72 exact distances, and 256 preterminal plus 256 terminal coefficients
per model. All match the pinned E106 native-agreed output. This is a complete
transparent scalar relation for that fixture, not an external proof execution.

| Model | Logical R1CS constraints | Witness field bytes | Sparse instance stream bytes |
| --- | ---: | ---: | ---: |
| Baseline tight | 109,942 | 3,493,056 | 38,958,979 |
| Folded tight | 31,502 | 988,096 | 23,932,479 |
| Folded width-only | **29,247** | **924,128** | **23,501,692** |

The 73.4% logical-constraint reduction is generic elimination and tighter
quotients. The best generic compiler receives every optimization and obtains
the **same** count: candidate/control ratio 1. It is neither a search-time
ratio nor a proof-time prediction. Bit booleans still dominate: 26,880 variables
represent 112 pairs of canonical 120-bit sources. Backend padding, commitments,
openings, range checks and public preprocessing can change the actual cost.

The bare toy response is 211 B. The strongest literal bit tape is 3,610 B;
response plus tape is 3,821 B, about18.1× the bare response. A tape is **not a
cryptographic proof**, and this is not a proof-size forecast. Current Context
pinning/admission hashes and traverses the full index and keys; the local
compiled object retains full context/static rows. No low-state or sublinear
client has been implemented by this interface.

The 103 final E108 scoped tests, earlier184+43 E106/E107 runs, 113 later-scoped,
448 prior-scoped and1,965 historical/revalidation cases have different scopes
and may overlap. None is rerun or added together in this planning revision.
They are correctness/negative evidence, not a security reduction or private
side-channel proof.

## 5. Measurements we still need before choosing a paper main

1. A matched BGV/BFV/Paillier-hybrid/cache cohort using the same dataset,
   outputs, starting state and monitored hardware; security assumptions must
   be disclosed rather than silently equated.
2. Actual complete proof costs with the strongest applicable range/oracle
   controls, including BitZ and corrected ring/CMC methods where interfaces fit.
   An unavailable adaptation stays unknown.
3. Cold registration, new-client acquisition, returning sessions, update and
   revocation costs for any surviving graph/preprocessing construction.
4. A paid operating point where remote execution has value despite allowed
   full caching: actual owner effort, cold acquisition, scale, concurrency or
   device capacity measured as conditions, not assumed restrictions.
5. Finite correctness and malicious-release composition arguments matching
   the implemented distribution, adaptive lifetime and every accepted witness.
6. Real TEE attestation/lifecycle integration and private-arithmetic assurance
   for any production claim. The current public GPU is not covered by a Nitro
   CPU receipt merely because it computes the same formula.

No missing item is a reason to discard the company implementation. It is a
reason to keep the engineering result separate from a conditional research
claim and to run the next decisive experiment with complete accounting.
