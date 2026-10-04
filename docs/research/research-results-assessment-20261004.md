> Current system handoff, 2026-10-04: the [execution plan](system-contribution-execution-plan-20261004.md), [contract-level closest comparison](closest-work-contract-matrix-20261004.md) and [current ledger](research-contribution-progress-20261004.json) now control execution. Q74/Q75 are complete within their bounded scope; the next task is Q76.1, the public-native retained-fixture gate. The compiled native draft is unvalidated. The review adds corrected Laminate and compiler/assurance controls; no new HE tests, timings, original main or security/parameter approval. Local lifecycle is at-most-once authorization, not exactly-once delivery or adversarial rollback protection. The earlier document below remains byte exact.

> Execution return, 2026-10-04: [Q74/Q75 results](shared-query-gates-20261004.md) and the [current ledger](research-contribution-progress-20261004.json) now complete the two bounded preliminary gates. Shared-query exact semantics passed; the Q120 derived/public-index variants failed their public bounds, and one paid Q180 rescue was screened. The strongest known composition contains the new algebra. The next selected build is owner canonical Q120 shared-query native admission versus equally prepared replay, with permitted cache/acquisition and all lifetime costs. No new service speedup, original main claim, security/parameter approval or production change is established. This supersedes earlier next-task/selection pointers for future work; the complete earlier document below is byte exact.

# What the accumulated results support

2026-10-04. Review through `4bbd55056d14405b617ae0c251b1f2bacc71e74c`;
no new HE tests or timings. Read the [closest comparison](closest-work-contribution-design-20261004.md)
and [current plan](research-contribution-plan-20261004.md).

## Foundation and performance evidence

Homemade BGV CPU/native/RNS/CUDA is the strongest current HE engineering
foundation. Retain BFV, Paillier, optional SEAL controls, all earlier experiments,
and production paths. The owner may keep their plaintext; the allowed cache
remains a main competitor.

The [revalidation](measurement-revalidation-20261001.md) retained 272 successful
outer receipts, 290 normalized observations, and 297 historical/fresh pairs.
These are different units, not 272 independent experiments. Contention, runtime
drift, limits, and failures remain recorded; overlapping suites are not summed.

The [matched 32k panel](system-selection-measurement-return-20261003.md) uses
32,768 records × 512 bits and five measured queries in one process/key/index block:

| Variant | Local query median ms | First reply bytes | First query + reply bytes | Sequential setup stages s | One 32-row update s |
| --- | ---: | ---: | ---: | ---: | ---: |
|Public-index BGV CUDA|117.298|204,895|450,761|145.474|7.279|
|Prepared BFV CUDA|892.813|409,770|1,147,164|226.759|0.724|
|Paillier lookup CUDA|2,599.103|16,908,071|16,908,615|3.827|0.0052|
|Paillier lookup hybrid, CPU server/GPU client|1,418.960|16,907,985|16,908,529|3.761|0.0055|
|Authenticated retained raw cache|4.384|0 returning-query bytes|0 returning-query bytes|0.958|0.0269|

All 35 searches, 1,146,880 distances, stable top-three answers, and five
post-update checks agreed. These are **unverified local experimental-profile**
results excluding network, a complete protected checker, and content retrieval.
Setups retain a swap qualification; observed swap preceded warmup. Parameters
differ and are not approved as equal-security choices. Paillier bytes vary by
observation. Cache update used full reseal/reacquisition; a stronger mutable
cache may improve it. Setup stages are not full fresh-process acquisition.

These results justify prioritizing BGV, not claiming a secure service speedup.
Its resident workspace rebuild accounts for about 7.1466 s of update time.
The permitted cache wins in this local scenario. The paper must identify where
outsourcing earns its cost, rather than omit the cache or invent a prohibition.

## Latest verification evidence

The [Q71 return](gadget-cut-fusion-results-20261004.md) uses a modeled
N=16,384, D=512, actual two-prime Q120, P=33,548,413, t=1031, eta=21 profile.
These are sufficient graph/schedule models, not latency or state lower bounds:

| Vectors / schedule | Server-to-verifier source + terminal-Q body MiB | Input forward prime NTTs | DAG word products, both primes | Cached multiplier body MiB |
| --- | ---: | ---: | ---: | ---: |
|8,224 canonical30, direct|180.468750|6,152|335,708,160|212.75|
|8,224 no-seed30, direct|150.703125|5,136|473,038,848|216.75|
|8,224 no-seed14, 30-bit suffix, direct|135.937500|7,212|1,570,734,080|260.75|
|16,384 canonical30, direct|240.234375|8,192|486,113,280|404.00|
|16,384 seeded18, paired|180.234375|6,172|846,790,656|2,198.00|

At 8,224, no-seed30 saves **16.49% of this witness body**, 16.51% of input
transforms, and adds about 41% pointwise work. Client replies are unchanged.
Radix14 saves more body but increases work substantially. Seeded18 paired
fusion reduces its own direct word work about 7.75×, yet remains above canonical
with about 2.15 GiB of modeled tables. An internal adapter ratio is not a service gain.

Direct no-seed30 working arrays occupy 8.25 MiB versus canonical 7 MiB, before
roots/maps, NTT scratch, allocations, wire, and concurrency. The earlier large
greedy adapter hit explicit caps for every selected rule; limited rows have
no complete cost or optimum.

Prepared replay has **zero source-witness traffic**, returns the same compact
client contract, and gets the same rewrites. At 8,224 the allowed binary cache
is only 514 KiB, versus an original encrypted-index coefficient body of
120.46875 MiB. Both controls are mandatory.

## Transfer break-even illustration

The 8,224 no-seed30 rule saves exactly 31,211,520 witness bytes. If transfer were
the only changed IO and setup/update effects canceled, extra compute would
have to fit within the ideal transfer savings below:

| Assumed witness-link throughput | Ideal time saved |
| --- | ---: |
|100 MiB/s|297.656 ms|
|1 GiB/s|29.068 ms|
|10 GiB/s|2.907 ms|

This is exact accounting on existing byte counts, **not network measurement**.
Producer extraction, parsing, serialization, overlap, and preparation can
change the result. The server-local verifier link differs from client Internet IO.

## Correctness and assurance scope

- Three fusion adapters reuse 112 retained/control relations and 224 targeted
  mutations; these are not 336 independent encryptions.
- Local/paired screens each report ten rows but reuse eight distinct models.
- Two fresh actual two-prime toy keys at N16/N32 give 16 geometry/query pairs,
  32 canonical/variant relations, and 64 changed tapes checked in both limbs
  against an independent schoolbook oracle.
- The parser reuses that cohort and rejects 96 additional malformed bodies.
- The deterministic C++ kernel uses our PrimeNTT and GMP and checks every
  physical NTT coordinate. It is not a statistical shortcut or SEAL import.
- Previous validation recorded 186 combined regression cases; none were rerun
  in this documentation/literature review.

Source-scale preparation, authoritative enrollment, packet/epoch/ID binding,
private release, durable updates, attestation, and private side channels remain
open. A small equality kernel/parser is not a deployed admission service.

## Keep, stop, and carry forward

| Family | Evidence and decision |
| --- | --- |
|Homemade schemes, CUDA/RNS, compact replies, workspaces|Retain company assets and baselines; build on BGV.|
|E07 feature-major delayed switching; E73 query expansion|Known implemented controls with explicit costs. A combined complete verified graph is unbuilt; neither ingredient is new.|
|E101 whole-trace affine elimination|Generic containment and range counterexamples. Do not revive as a sharing primitive.|
|E110 functional/orbit compilation|Useful identities contained by known gadget methods.|
|Q57/H1 operator state; Q59/H2 affine updates|Generic controls obtain the same choices/state. Shared preprocessing or a linear delta alone is not a main contribution.|
|Fourier, root census, ideal query laws, conversion/selection forks|Scoped supporting/negative results. Leave off the critical path unless a precise missing theorem or changed contract justifies a bounded task.|
|Q64–Q71 relation/native components|Practical no-seed30 fallback with paid tradeoffs. Complete its controller as shared infrastructure or a selected engineering build; avoid another radix grid.|

The [earlier review](research-evidence-review-20261003.md) retains the complete
family lineage. We have not tried every possible hypothesis or established an
original main. The [new plan](research-contribution-plan-20261004.md) uses two
bounded preliminary gates before a full build, with explicit selection/stop decisions.
