# SB01 matched measurement: execution return

2026-10-03. The single registered 32,768-vector × 512-bit cohort completed correctly across all five fixed implementations. **All timings remain resource-qualified because system-wide swap counters advanced during setup.** This closes the missing paired arithmetic/acquisition comparison; it does not establish a secure remote service, equal security profiles, production parameters or an original paper contribution.

The [frozen design](system-selection-measurement-plan-20261003.md) remains unchanged. This return goes back to the [three-package selection handoff](system-selection-return-20261003.md). No backend, parameter, implementation or trial was replaced after seeing main results.

## Completion and retained execution

* Main: one attempt, exit0, 35 searches and 1,146,880 checked distances; every complete score vector and stable top3 matches the independent plaintext oracle. There are 30 warmup/measured calls and five separate post-update validations. All five updated score digests and top3 agree. Cleanup failures: none.
* Source integrity: all 579 frozen source, binary, interpreter, helper, contract and retained-bound inputs match before/after main and at this post-run validation. The report carries 424 repository provenance entries; the larger execution freeze also pins helpers and external inputs.
* Events: 644 retained entries, including 292 paired phase starts/ends and 30 paired warmup/measured sample starts/ends. All events and raw artifacts match the supervisor’s published hashes.
* Final scoped controller QA: 20 distinct cases, zero failures/errors, Ruff exit0. Earlier 19-case runs overlap this final suite and are not added to it.
* Main worker: 433.327929 seconds, from 18:36:23.979015Z to completion at 18:43:37.341424Z. This includes all five setups, correctness work, serialization, queries, updates and cleanup; it is not a cold latency for one selected scheme.

Exact [raw report](../../../research-data/system-selection-20261003/measurement-design/main/report.json), [supervisor receipt](../../../research-data/system-selection-20261003/measurement-design/main/supervisor-receipt.json), [execution freeze](../../../research-data/system-selection-20261003/measurement-design/main-freeze.json), [events](../../../research-data/system-selection-20261003/measurement-design/main/events.jsonl), [telemetry](../../../research-data/system-selection-20261003/measurement-design/main/telemetry.jsonl) and [final author receipt](../../../research-data/system-selection-20261003/measurement-design/final-execution-receipt.json) retain the full evidence. The NEW [checkpoint report](../../benchmarks/results/publication-system-selection-measurement-20261003.json) is a byte-identical copy of the external raw report.

## Workload and implementation boundaries

The corpus uses unchanged `make_data(32768,512,1701)`, IDs equal to positions, and corpus SHA256 `a51574ee3dd4a944dbc8f552ff47514994483df46259337b7b5e025ebfbd1cc7`. One excluded warmup exercises equal/complement/equal rows and stable ties. Measured queries are all-zero, all-one, alternating bits and two fixed pseudorandom binary words. Each encrypted request uses fresh OS randomness; variant order is shuffled using the registered separate seed. The five common queries share one process/key/index block, so they are not five independent datasets or setups.

| Label | Fixed implementation | Client / server |
|---|---|---|
| BGV public index | Homemade BGV, N16,384/t1,031/Q120 two-prime RNS, eta21, gadget30, terminal25, public-key index, owner-seeded queries, CUDA level4/baseline NTT/persistent workspace | CPU native owner / GPU |
| BFV prepared | Homemade BFV, N16,384/t65,537/Q180 three-prime RNS, eta21, gadget30, terminal50, current fused CUDA/batch32 and native private decoder | CPU / GPU |
| Lookup CUDA | Existing homemade Paillier Lookup, key_len1,024 prime bits, alpha280; actual modulus2,048 bits/decryption exponent280 bits | GPU / GPU |
| Lookup hybrid | Independently generated same-profile Paillier Lookup; actual modulus2,048 bits/decryption exponent279 bits; batched CUDA client and GMP server | GPU / CPU |
| Raw cache | AES-256-GCM authenticated raw snapshot; full plaintext retention permitted; explicit8-byte IDs; CPU XOR/popcount and heap top3 | CPU / storage only |

BGV is a **public-index reference**, not “best BGV.” [E16 owner-index/radix/precision controls](bgv-layout-planning.md) remain separate competitors with different index laws, moduli, rounding and assurance premises. They were not silently substituted. Stronger compressed/mutable/vectorized/GPU cache variants remain omitted controls; this raw cache already dominates returning local-query latency. The expensive CPU-only Paillier grid was intentionally not repeated.

BGV’s full512-tile public metadata guard passes with original phase bound600064391575846951911424, terminal bound8,446,469 and terminal modulus33,548,413. It uses the frozen previously measured public-index bound and the unchanged formula, not a new large zero-input HE trial or private samples. It establishes this fixture’s existing guard eligibility, not approved cryptographic security.

## Returning-query timings

Every duration below is local sequential fixture time. Client preparation includes encoding/encryption/framing; server includes request parsing/evaluation/response framing; finish includes parsing/decryption/decoding/stable top3. The total is independently measured. Separate component medians need not sum to the total median. No actual network, TLS, EC2, TEE signing, admission proof or content fetch is included. All five original trials remain present, including any flagged or slower values.

| Fixed variant | Client preparation median ms [min,max] | Server median ms [min,max] | Client finish median ms [min,max] | Total median ms [min,max] |
|---|---:|---:|---:|---:|
| BGV public index | 12.101 [11.593,12.464] | 83.193 [82.667,83.486] | 22.246 [21.821,22.416] | 117.298 [116.911,118.184] |
| BFV prepared | 189.592 [187.264,200.422] | 645.382 [644.183,646.472] | 57.081 [56.862,57.441] | 892.813 [888.424,904.302] |
| Lookup CUDA | 3.864 [0.659,3.993] | 1375.802 [1375.194,1461.523] | 1215.281 [1200.264,1224.671] | 2599.103 [2586.433,2662.599] |
| Lookup hybrid | 3.846 [0.690,4.002] | 270.169 [201.097,287.149] | 1196.933 [1122.468,1217.026] | 1418.960 [1409.050,1474.750] |
| Raw cache | 0.037 [0.024,0.056] | 0.000 [0.000,0.000] | 4.305 [4.203,4.431] | 4.384 [4.258,4.493] |

| Fixed variant | Query1 total ms | Query2 | Query3 | Query4 | Query5 |
|---|---:|---:|---:|---:|---:|
| BGV public index | 117.038084 | 117.298359 | 116.911432 | 117.577224 | 118.184487 |
| BFV prepared | 888.423870 | 892.813356 | 890.472207 | 904.302231 | 902.320231 |
| Lookup CUDA | 2662.598824 | 2604.007490 | 2586.433377 | 2596.961356 | 2599.103403 |
| Lookup hybrid | 1418.960300 | 1474.750172 | 1469.897682 | 1409.049697 | 1415.042064 |
| Raw cache | 4.274345 | 4.383597 | 4.404567 | 4.492729 | 4.258185 |

Public evaluation-only medians/ranges are BGV73.443ms [73.031,73.829], BFV644.712ms [643.553,645.797], Lookup CUDA1,350.255ms [1,349.170,1,352.139], and Lookup hybrid175.850ms [174.424,244.498]. These are different algorithmic stages, not complete request costs.

All ten paired comparisons follow. A/B is the local elapsed for A divided by B on the **same plaintext query**; above1 means A took longer. Medians are computed from the five paired ratios, not by dividing separately summarized medians. The final author receipt retains every ratio. One process/key block with five queries supplies observed ranges; it does not supply a population confidence interval or a latency guarantee.

| A / B | Median ratio | Full five-query range |
|---|---:|---:|
| BFV prepared / BGV public index | 7.616639 | 7.590896–7.691134 |
| Lookup CUDA / BGV public index | 22.123015 | 21.991917–22.749850 |
| Lookup hybrid / BGV public index | 12.123919 | 11.973162–12.572746 |
| BGV public index / Raw cache | 26.758472 | 26.170558–27.754662 |
| Lookup CUDA / BFV prepared | 2.904564 | 2.871785–2.996992 |
| Lookup hybrid / BFV prepared | 1.597166 | 1.558162–1.651801 |
| BFV prepared / Raw cache | 203.671404 | 201.281278–211.902544 |
| Lookup CUDA / Lookup hybrid | 1.836768 | 1.759601–1.876443 |
| Lookup CUDA / Raw cache | 594.034418 | 578.036506–622.925576 |
| Lookup hybrid / Raw cache | 332.311083 | 313.628912–336.424670 |

The stronger Lookup hybrid is12.124 times slower than the BGV reference on the paired observed query ratios; the cache is26.758 times faster than BGV. These fixture results preserve the swap qualification, unequal security profiles, different client hardware and paid setup/update boundaries.

## Actual communication and retained bodies

Packet counts are actual serialized bytes. Returning queries begin after key/index preparation or cache acquisition. All data is local: byte counts do not measure a transport time. BGV public/evaluation keys use the declared benchmark fixed-width coefficient frame; BFV and Paillier retain their existing export formats. HE uses implicit candidate positions; cache includes explicit IDs. No keys, ciphertext packets, nonces or plaintext vectors are persisted in the results.

| Fixed variant | Public/evaluation setup keys B | Serialized encrypted index/snapshot B | Query B | Reply median B [min,max] | Query+reply median B [min,max] |
|---|---:|---:|---:|---:|---:|
| BGV public index | 20,152,860 | 503,327,833 | 245,866 | 204,895 [204,895,204,895] | 450,761 [450,761,450,761] |
| BFV prepared | 171,204,800 | 755,062,814 | 737,394 | 409,770 [409,770,409,770] | 1,147,164 [1,147,164,1,147,164] |
| Lookup CUDA | 4,354 | 16,908,115 | 544 | 16,908,110 [16,908,071,16,908,126] | 16,908,654 [16,908,615,16,908,670] |
| Lookup hybrid | 4,352 | 16,907,967 | 544 | 16,907,985 [16,907,952,16,907,991] | 16,908,529 [16,908,496,16,908,535] |
| Raw cache | 0 | 2,359,388 | 0 | 0 [0,0] | 0 [0,0] |

BGV’s reply is82.520 times smaller than the hybrid’s median actual reply, and its query+reply is37.511 times smaller. BFV replies are approximately twice BGV’s bytes here. The BGV encrypted index and setup keys are substantially larger than Paillier’s; small recurring replies do not imply small setup. Paillier’s reply widths vary with its canonical serialized integers. The receipt retains every byte width and paired byte ratio.

Cache has zero returning-query exchange **after** acquiring its2,359,388-byte encrypted snapshot and a trusted96-byte key/current-manifest body. Its retained canonical plaintext body is2,359,296bytes (72bytes/row); this is not complete Python RSS. Key/manifest delivery and freshness persistence are trusted/unbuilt premises, not a measured production protocol. Do not divide by its zero recurring bytes or compare a cache returning query with an HE cold session.

BGV reports536,870,912 resident index coefficient bytes and1,745,354,752 workspace coefficient bytes; BFV reports805,306,368 resident index bytes and174,328,848 native plan bytes. These API counts omit other state. Actual monitored peaks below aggregate all resident variants and must not be treated as per-scheme memory measurements.

## Paid setup and fresh-client acquisition

Common dependency import took0.075691s and common corpus creation1.278827s, outside crypto phases. Oracle/digest work and other harness overhead are also outside the setup-stage sums. Every scheme pays its own key/index setup. The table sums individually measured sequential phases; it is not a whole cold-process cost. Owner preparation includes keys, encoding/encryption and framing. Server preparation includes public imports, index parsing and resident public state. Cache fresh-client acquisition is separated from owner encoding/sealing.

| Fixed variant | Owner stage sum s | Server stage sum s | Fresh-client acquisition s | Total recorded setup stages s |
|---|---:|---:|---:|---:|
| BGV public index | 133.037711 | 12.436189 | not separately measured | 145.473933 |
| BFV prepared | 222.171287 | 4.588125 | not separately measured | 226.759413 |
| Lookup CUDA | 3.740578 | 0.086229 | not separately measured | 3.826808 |
| Lookup hybrid | 3.674280 | 0.086725 | not separately measured | 3.761005 |
| Raw cache | 0.943606 | storage only | 0.013960 | 0.957566 |

BGV additionally has a separately timed0.000033s public eligibility guard, included in its total. HE owner setup does not represent delivery of private material to a new client. The fixture retains the owner’s private context; neither a remote fresh-client onboarding protocol nor WAN transfer of setup keys/index is timed.

| Dominant setup stage | Observed s |
|---|---:|
| BGV index encryption |126.479734|
| BGV immutable resident index preparation |6.908700|
| BFV index encryption |211.002547|
| BFV key generation |8.291924|
| BFV public plan import |3.189086|
| Lookup CUDA key generation / index encryption |2.957503 /0.750230|
| Lookup hybrid key generation / index encryption |2.946454 /0.695831|
| Cache owner body encoding / sealing / fresh-client acquisition |0.924337 /0.019265 /0.013960|

The raw report keeps every remaining setup stage, including parsing, serialization, key import/export and private preparation. HE setup amortization cannot be removed from a session comparison while charging cache its snapshot acquisition. The one observed block does not establish an unlimited epoch or an update-rate break-even frontier.

## One aligned32-row replacement

After the five measured queries, rows0..31 are complemented while IDs, keys, count and dimension remain fixed. This is one packed tile in both HE layouts. Present immutable resident APIs require a complete BGV/BFV resident re-prepare; Paillier replaces host rows directly. Cache performs a full snapshot reseal and acquisition under its retained key with fresh nonce/manifest. Logical transition metadata is trusted harness data.

| Fixed variant | Actual update packet B | Owner encryption/encoding s | Full resident re-prepare s | Complete local update s | Separate post-update validation query s |
|---|---:|---:|---:|---:|---:|
| BGV public index | 491,721 | 0.124034 | 7.146586 | 7.278780 | 0.123423 |
| BFV prepared | 737,485 | 0.208179 | 0.514986 | 0.724348 | 0.910143 |
| Lookup CUDA | 16,634 | 0.005056 | 0.000000 | 0.005187 | 2.572394 |
| Lookup hybrid | 16,635 | 0.005362 | 0.000000 | 0.005479 | 1.407911 |
| Raw cache | 2,359,388 | 0.001225 | full reseal0.011365 + acquire0.013442 | 0.026924 | 0.003879 |

All five post-update queries match all32,768 distances and stable top3 `[1,32767,21714]`; updated score SHA256 is `cbeccd9c5db52826540c07b34015dea545a1dfbdb34067e4c4aa902d80fe34a6`. These single update observations are not medians and are kept outside the five-query summaries.

BGV’s7.279s complete update is dominated by7.147s full resident re-preparation. This reveals a present public-API engineering cost worth charging in the next system design; it does not imply that every BGV layout must pay it. Lookup’s observed update is roughly5ms. Cache pays a full2.36MB snapshot here; a stronger authenticated mutable/compressed cache is still a required competitor before an HE update advantage can be claimed.

## Resource qualification and cap compliance

The host is an AMD Ryzen7 5800X8-core CPU with32,777,836KiB system RAM and an NVIDIA GeForce RTX3080/10,240MiB GPU, driver595.91.07; Python3.12.3. The supervisor uses the frozen minimal environment (OMP8/OpenBLAS1/passive waiting) and one owned process group. All five key/index configurations remain resident together. There was no driver install, clock/power change, source rebuild, automatic retry or termination of unrelated user jobs.

| Supervisor observation | Actual outcome |
|---|---|
| Caps |worker wall1,200s; CPU3,600s; sampled RSS16GiB; sampled owned GPU8GiB|
| Worker wall |433.327929s; exit0; one main attempt|
| Preflight |15 samples over30s; all registered flags false|
| Worker telemetry |217 samples; memory/owned-process monitor213 samples|
| Foreign CPU above0.75 cores |0 observed threshold samples|
| Foreign GPU compute PIDs |none observed|
| Missing GPU samples / telemetry errors |0 /none|
| Short-panel insufficient assurance |false|
| New swap activity |true|
| timing_qualified / machine_exclusive_assurance |true /false|
| Peak sampled owned RSS |9,125,978,112bytes =8.499229GiB|
| Peak sampled owned GPU memory |4,412,407,808bytes =4.109375GiB|

Memory sampling covers the worker and descendants using actual compute PIDs. Sampling can miss instantaneous peaks and cannot prove host exclusivity. No cap was breached. System-wide swap counters moved from `pswpin=0, pswpout=167` at the last preflight sample to `pswpin=32, pswpout=2183` at the final worker sample: **+32 pages in and+2,016 pages out**, with4,096bytes/page (131,072bytes in and8,257,536bytes out). Counters identify host activity, not the responsible process or a timing cause.

Every observed changed-counter interval precedes the first warmup at18:42:48.565703Z. The first/last changed intervals occur during setup. This temporal observation does not lift the preregistered whole-cohort qualification or permit dropping trials. Exact changed intervals below use UTC and preserve both directions; phase timestamps and full counters remain in the receipt.

| UTC sample interval on2026-10-03 | Input pages added | Output pages added |
|---|---:|---:|
| 18:37:50.035999–18:37:52.037082 | 0 | 123 |
| 18:37:54.035824–18:37:56.036946 | 0 | 131 |
| 18:38:00.049066–18:38:02.042501 | 0 | 347 |
| 18:38:08.040435–18:38:10.037781 | 17 | 271 |
| 18:38:14.040611–18:38:16.038846 | 0 | 108 |
| 18:38:22.045634–18:38:24.038755 | 0 | 118 |
| 18:38:26.041936–18:38:28.039655 | 0 | 47 |
| 18:38:28.039655–18:38:30.040173 | 0 | 78 |
| 18:38:32.039923–18:38:34.040169 | 0 | 143 |
| 18:38:36.040303–18:38:38.042302 | 0 | 64 |
| 18:38:38.042302–18:38:40.037806 | 0 | 440 |
| 18:38:40.037806–18:38:42.042304 | 0 | 131 |
| 18:38:42.042304–18:38:44.039142 | 0 | 9 |
| 18:40:00.051988–18:40:02.045512 | 15 | 0 |
| 18:42:34.052023–18:42:36.048387 | 0 | 6 |

## Intrinsic correction and immutable evidence

The first intrinsic attempt is retained in `intrinsic/`: exit1, failed before any search, because the NEW BGV adapter’s decoder context omitted `pk` required by existing `Case.unpack` to check `pk.fresh_bound`. It supplies zero search correctness or performance evidence. Its original source versions and579-pin freeze were preserved before correction.

The only correction adds the same enrolled public key to the NEW context and an AST-only public-context regression. No scheme, bound law, parameter, kernel or guard changed. A separately frozen/root-authorized corrected intrinsic in `intrinsic-corrected/` completes15 searches/240 distances across all five variants, including all five updates. It too is swap-qualified and serves compatibility only. Main then runs once against the corrected sources. Final20-case QA replaces the earlier overlapping19-case count.

| Frozen artifact | SHA256 |
|---|---|
| Main execution freeze,579 inputs | `e833e941e50cbd96a6fbb9ff4699b0473e5052adbaa4ac8a7d0497bea7029539` |
| Main raw report and exact checkpoint copy | `599c5f2bd44b81a4622c2ab12ecb762ac23c12ec4872ad2085e24f76982373dc` |
| Main supervisor receipt | `77517886a0a79b52a462030b5a325c757d3c5fab3556bbe1f00fef57216bce96` |
| Corrected intrinsic report | `a879cee1d4de2eb277cfeaef6a5025bade23a985b2853ff18ce8603d8c9c3c68` |
| Failed intrinsic report | `2c673cf5e403ab75bc5f5abce476ffbb9e0156e2eef6ef7e3c1572a0769facf7` |
| Final20-case JUnit | `dd5f931c21bc5763d1c0cd17a4ad50792065912b39a588f10c94dd18b4447bae` |
| Runner | `85cb9f9657862e920754db96c1202e71b83cf7230505ea237ecdbfc172b9dc1a` |
| Tests | `35a47155b5bfe1a37147e6f3c862f6093cf85088389741ae6a0be0d548c21c27` |
| Plan | `6c511b043fe125fa8c03ae469c3eadba68970de9287dac93b5a36807547b843e` |
| Supervisor | `bd11bf64b9a64043751f1adce39fe783be5156308f6d0cb8e5cb87dc17291cf5` |
| Metadata freezer | `31dd143179cfd92188e435851c94bfeaf35de59af5ff9ac89d547767b648553c` |

## Consequence for the finite system plan

Ordinary homemade BGV is a useful HE engineering reference at this geometry: it beats both current Paillier configurations and prepared BFV on observed returning-query arithmetic and returns far fewer bytes. Retain BFV/Paillier fallbacks and the existing SEAL sanity control. This comparison does not identify the best BGV profile or a production encryption choice.

Full client caching is allowed and already wins these local recurring queries. BGV pays much larger initial encryption/state and a present immutable-update cost. The system claim must therefore specify a paid operating point where outsourcing or protected execution offers a meaningful advantage over permitted strong caches and other equally informed alternatives; it cannot assume the client is forbidden to keep its own data.

The next selection decision combines this qualified measurement with the complete GPU-admission composition and bounded Fourier attempt. A complete safe-release boundary must price checking, trusted continuation, internal protected traffic, setup/state, updates and fresh-client acquisition. Strong E16 profiles, equally specialized randomized delegation, full native replay, protected plaintext search and strong caches remain mandatory controls before a best-system or original-contribution claim. Missing adapters are unknown costs, not defeated competitors.

All HE private finishing here receives locally generated legitimate replies. No malicious-server response is authorized for release, no TEE/GPU attestation is evaluated, and no deployed freshness or private-side-channel/parameter assurance is established. The observed arithmetic result cannot close the authentication problem by itself. No additional cohort, grid, scheme tuning or service deployment is activated by this return.
