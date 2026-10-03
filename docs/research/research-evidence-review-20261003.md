# Accumulated evidence and decisions for the system blueprint

2026-10-03. Review of existing reports and the Q0–Q55 queue at commit
`2a973550d4a23d4aaf6708d7e2d281c77ccb5a87`. No experiments, tests of HE code,
timing panels or parameter estimates were run for this planning review.
The [blueprint](system-research-blueprint-20261003.md) selects future work;
this document distinguishes the evidence supporting that choice from open work.
“Complete” below always refers to the specified experiment, not the project or
production security. Archived reports retain historical “next” recommendations;
the new blueprint determines current execution order.

## 1. What is already useful

The repository contains homemade BFV and BGV arithmetic, CPU/native/RNS/CUDA
implementations, compact query/reply formats, prepared workspaces, exact search
oracles and protection prototypes. SEAL remains an external sanity control.
The [initial search-lab results](search-lab-first-results.md) and subsequent
BGV reports explain the engineering lineage; their historical timing panels
are not substituted for the later matched comparisons.

The large [measurement revalidation](measurement-revalidation-20261001.md)
retains 272 successful measurement/model outer receipts, 290 normalized
observations and 297 historical/fresh pairs. These are different units, not 272
independent experiments. It accounts for 215 of 224 primary historical JSONs
through comparisons and documents the remaining typed cases, unavailable
historical sources, compiler/runtime drift and profiler limitations. The full
suite plus separately enabled SEAL oracle supplied 1,965 unique passing cases;
one live Nitro check was unavailable. None is rerun or added to a new test count
in this review.

The revalidation supports large CPU arithmetic improvements and a much smaller
complete-query GPU benefit for some later refinements. In the matching E27
process blocks, small CUDA differences were effectively ties. A stronger
Paillier hybrid also changed the BFV comparison. This is why the new plan
requires complete costs and equally optimized controls.

## 2. Latest matched 32k anchor

Source: [S1/Q52 detailed return](system-selection-measurement-return-20261003.md).
Same 32,768 records × 512 bits, five measured queries, one warmup and one
post-update check per variant. All 35 searches, 1,146,880 distances and stable
top-three results passed, including five update checks. These repetitions share
one process/key/index block; they do not provide population confidence intervals.

| Variant | Local query median ms | First measured reply bytes | First query + reply bytes | Sequential setup stages s | One 32-row update s |
|---|---:|---:|---:|---:|---:|
| Public-index BGV CUDA |117.298|204,895|450,761|145.474|7.279|
| Prepared BFV CUDA |892.813|409,770|1,147,164|226.759|0.724|
| Paillier lookup CUDA |2,599.103|16,908,071|16,908,615|3.827|0.0052|
| Paillier lookup hybrid |1,418.960|16,907,985|16,908,529|3.761|0.0055|
| Authenticated retained raw cache |4.384|0 returning-query bytes|0 returning-query bytes|0.958|0.0269|

Paillier serialized lengths vary; the detailed return retains every observation
and range. Setup is a sum of reported sequential stages excluding common startup
and corpus generation, not full cold-process/new-client acquisition. Cache update
is full reseal/reacquire, not a strong mutable delta implementation. The hybrid
uses a CPU server and GPU client; the BGV/BFV clients here use CPU arithmetic.

BGV's median paired hybrid/BGV ratio is 12.124; its first reply is 82.52 times
smaller and its exchange 37.51 times smaller. Cache is about 26.76 times faster
locally than BGV. These are **experimental-profile, unverified local comparisons**.
They exclude a complete protected checker, network transit and content retrieval.
Setup swap qualifies the complete panel, although all observed swap intervals
preceded warmup and no foreign GPU compute or sustained high foreign CPU activity
was observed. The new plan does not advertise these as secure-service ratios.

BGV's actual encrypted-index packet is 503,327,833 bytes and setup keys are
20,152,860 bytes. The raw cache snapshot is 2,359,388 bytes plus a 96-byte trusted
key/manifest body. The BGV resident workspace rebuild accounts for about
7.1466 seconds of its update. Its public-index N=16384/t=1031/Q120 profile is
distinct from earlier owner-index variants. BFV uses a different Q180/t=65537
profile, and Paillier uses approximately 2048-bit n with the lookup exponent
disclosed in the original report. None of these rows constitutes equal-security
parameter approval.

This updates the old open question about a matched larger BGV/hybrid comparison.
It does **not** replace the separate clean 8k observation: prepared BFV took
395.213 ms versus hybrid 344.524 ms; the separate owner-BGV study took 60.047 ms
on a different fixture. Do not merge those into one paired table.

## 3. Experiment families: retain, stop, or carry forward

| Evidence family | What the accumulated record establishes | Decision for the new system |
|---|---|---|
| Early BFV/BGV, native/RNS/CUDA, seeded queries, compact replies and layouts | Working homemade implementations and large arithmetic/payload benefits, with setup/refill costs documented. | Reuse the evaluator; keep BFV/Paillier and owner/public-index variants distinct. These are company assets, not automatic originality. |
| E26/E27 and timing revalidation | Large CPU changes reproduce; small complete CUDA allocation/repair effects remain near ties. | Do not build a paper around unresolved sub-percent effects or only a server-stage speedup. |
| E41–E81 representation, factory, acquisition, caching, update/lifetime and earlier verification screens | Stronger vectorized/helper/cache controls often absorb or reverse gains. E77's smaller client vector moves work/state to a trusted factory; E79 bounds its actual acquisition scope. | Preserve negative controls; charge owner/helper work and fresh-client costs. No invented client-memory constraint. |
| Q0–Q5, E82–E84 fixed private correlations, coded operators and selection | Literal shared/noiseless-mask and common-slope recipes stop; ordinary row retrieval has poor complete bytes; small-field multiplicity does not establish exact ID/count binding. | Park these recipes. Do not reopen because they sound different from BGV. [Return](construction-selection-20261002.md). |
| Q11–Q18, E85–E92 conversion/orbit/LUT/remainder/partial-switch interfaces | Useful exact conversion identities and counterexamples; missing authenticated carries/terminal context and known-method containment block literal main claims. | Keep exact oracles as regression inputs. A different output/crypto bridge needs its own contract. [Selection history](construction-selection-20261002.md). |
| Q19–Q25, E93–E99 precision, epochs, late zero, prefix security and coupled gadget laws | Known conditional controls survive; arbitrary independence/target-security shortcuts do not. | No unchecked ring reduction or phase independence assumption in H1/H2. Retain source and actual key-sample qualifications. |
| Q26/E100 remainder-first binding | Conditional predecessor, not a completed new mechanism. | Park off the main path; do not infer an original relation from its proposal. |
| Q27/E101 whole trace | On the tested E73 graph, generic affine elimination contains the literal shared-cut recipe; full-wire counterexamples and limb checks are valuable. | **Keep the negative.** Only the unexecuted rotated-native/shared-state planning distinction can motivate Q57; no rebranding. [Exact return](joint-binding-screen.md). |
| Q28/E102 and Q31/E105 reused-key noise/carries | Conditioned analyses are known; all 6,561 source states in each full tiny E105 law remain distinct; independent marginal noise convolution fails. | Do not restart full-state enumeration as a compression mechanism. [Return](boundary-reuse-selection-20261003.md). |
| Q29/E103 owner summaries | Exact coverage controls work, but the literal centroid/radius recipe is known and private retrieval/padding remain unpaid. | Separate future output-contract research, not a shortcut to the current paper. [Return](boundary-reuse-selection-20261003.md). |
| Q32–Q35, E106–E109 complete native boundary/terminal/opening/proof | Tiny whole BGV graph and canonical relations exist; actual Spartan control has a 135,200-byte proof and 553,648,696-byte materialized prover instance for its fixture. Full deployment contract remains partial. | Reuse full response oracles; do not generalize that backend's cost to ring/binary proofs. [Return](verification-aware-screens-return-20261003.md). |
| Q36/E110 functional-orbit compilation | Ordinary/product/full-orbit graphs agree; key/work tradeoffs are measured as counts; GGSW/Bae containment stops the literal original claim. | Do not build the proposed compiler by reviving E110's gadget-key identity. [Return](verification-aware-screens-return-20261003.md). |
| Q37/E111 dependent decoder events | Exact finite domain; the generic deterministic bound certifies the same event. | Keep as assurance/control; no novel event-compression result. [Return](verification-aware-screens-return-20261003.md). |
| Q38/E112 and Q43/E117 TEE/proof/affine checks | A signed tape hash is not a proof-oracle commitment. The pinned backend lacks the required external binding interface. A complete tiny protected-affine control has a paid state ledger and conditional first-false-accept argument. | Use the full protected control first. Treat witness commitment equality, hidden state and canonical bit parsing as real costs. [Ledger](protected-affine-ledger-20261003.md). |
| Q39/E113 and Q42/E116 one-prime setup | Owner-only whole-support mathematical feasibility for some profiles; general public-index/keygen guard does not admit them. The distinct owner-only implementation is optional and unbuilt. | Useful later engineering; not a production guard change or prerequisite for this system. [Return](verification-aware-screens-return-20261003.md). |
| Q40/Q41, E114/E115 ideal query law and actual seed | Literal ideal-quantizer gains are small/known; stopped-prefix correctness and a finite stream bound have scoped proofs. Actual all-witness protocol/security is unresolved. | Preserve samplers/guards; no promotion from ideal uniform masks to real public-seed privacy. [Return](verification-aware-screens-return-20261003.md). |
| Q44–Q51, E118–E124 nonunits, CRT prefix, cyclic windows and joint roots | Exact supporting oracles; E120's suffix consumes the candidate margin; E122 refutes structured-quartet extremality; E123 completes its toy census. Source input budgets and stronger useful certificates remain open. | Archive as supporting theory; no larger census on the critical path. [Census return](joint-root-census-return-20261003.md). |
| Q52/E125 matched measurement | The qualified 32k results above, including setup/update/cache. | Select BGV as HE engineering foundation; prioritize complete verification and update cost. |
| Q53/E126 complete admission | Eight tiny exact packets, 24 checked blocks and 256 complete coefficients; 89 distinct scoped tests. No actual GPU/enclave/private signing service. | Reference invariant for Q56; large product-boundary traffic and trusted suffix must be measured. [Return](system-selection-gpu-admission-return-20261003.md). |
| Q54/E127 Fourier attempt | Complete symbolic support/zero accounting; generic method obtains the identical bound, ratio one. | Stop this recipe as original. The stronger theorem remains unproved and optional. [Return](system-selection-fourier-attempt-20261003.md). |
| Q55 construction handoff | Finite selection cap closed, no original main selected. | Execute a focused native system/control plan; do not treat every old conditional item as a required preliminary experiment. |

The machine queue preserves every old row and its exact status. Grouping here
does not upgrade partially executed work or claim a complete review of every
historical source line. No counts from overlapping suites are summed.

## 4. What remains before selecting the full system

The [new ledger](system-research-blueprint-20261003.json) has six bounded
packages: native control, operator-sharing discriminator, cut prototype, update
discriminator, matched complete pilot, and selection. Only the middle design
packages test candidate originality. Dependent work stops if its premise fails.
After selection, protected service/security closure and paper evaluation are
separate full-system milestones.

The earliest unfinished dependency is a **complete native admission/control
with an explicit resource ledger**. The strongest unresolved scientific question
is whether a new representation or planning algorithm remains once ordinary
sharing, canonical affine elimination and incremental updates are granted to
the baseline. We have promising implementation building blocks and a concrete
question, but no already-accepted original main mechanism. That distinction is
the basis for the executable plan, not a reason to prolong all earlier screens.
