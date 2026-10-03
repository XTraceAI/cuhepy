# Q29 / E103: exact owner coverage survives; the literal mechanism stops

Executed 2026-10-03 under the [frozen preregistration](owner-summary-preregistration.md)
and [separate exact-top-three contract](owner-summary-contract.md). The complete
plaintext coverage oracle is correct in the bounded checks. **The literal
centroid/radius/minimum-ID composition stops at the mechanism gate:** it is a
known metric bound with trusted owner metadata, not an original cryptographic
protocol. The geometry and public padding observations also reject a broad
performance claim for the tested layouts.

[Oracle](../../experiments/bfv_search_lab/owner_summary_oracle.py),
[tests](../../experiments/bfv_search_lab/test_owner_summary_oracle.py),
[runner](../../benchmarks/owner_summary_lab.py),
[raw counts](../../benchmarks/results/publication-owner-summary-20261003.json).
There are no HE, PIR, CPU/GPU speed, remote service or assured-privacy results
in this packet. Source hashes and command are in the raw record; the UTC
preregistration receipt is retained outside the repository under
`../research-data/owner-summary-20261003/`.

## Exactness and trust result

The run exhausts every ordered dimension-3 corpus of length 0 through 3,
including duplicate words with distinct IDs, each of its eight queries, and
both a single-block and uneven/empty-three-block layout. That is **9,360
dataset-layout-query cases**, with both variable and full fixed schedules
checked against a separately sorted complete scan: **18,720 exact results**.
All pass. Eleven scoped tests additionally cover every dimension-4 query on
tied-ID, far-query, deletion and short-live-set examples, the full dimension-8
adversarial query universe, and canonical-input/traffic checks.

Trusted enrollment compares the entire live owner dataset with all partition
records. Omissions, changed contents and duplicate IDs reject. The client
retains an owner-pinned full manifest: per-group content digest, maximum
radius, count and minimum ID, plus dimension, capacity, total count, dataset
digest and epoch. Modified radii/IDs, dropped metadata groups, substituted or
missing records, duplicate block replies and old revisions reject against
the current pin. A malicious server cannot create that trusted pin itself.
This is a **trusted provisioning premise**, not an implemented signature,
AEAD channel, durable rollback protection or a new coverage-proof protocol.

The stopping rule conservatively compares all omitted-group lower bounds
with the kth exact `(distance, ID)` pair; strict comparison preserves ties.
Less than three live fetched rows forces all remaining nonempty groups to be
considered. Duplicate words remain distinct records. Empty live corpora work.
The proof is the standard Hamming triangle inequality plus a conservative
minimum-ID bound; it is not a new reduction result.

## Geometry and fixed-budget costs

Two frozen index-only layouts were tested: sorted contiguous blocks of 128
records, and 16 nearest-seed groups with deterministic evenly spaced seeds.
Each block's actual center is coordinate-majority with zero at ties. Semeion
and Mushroom use seed 3001 and heldout queries 32:40. Connect-4 uses the same
split/query slice and only the first 4,096 enrolled rows; it is **not** a
67,429-row search measurement. Synthetic rules/seeds are retained in the raw.

The variable oracle is a query-dependent work diagnostic. The fixed count
mode pays exactly B equal-capacity public slots, including dummy records and
dummy distances after logical completion. Its preregistered budgets are
1, ceil(G/4), ceil(G/2), and G. Insufficient budgets return local inconclusive
results, without an unpriced query-dependent fallback or approximate output.

| Geometry / layout | Live rows | Mean variable scored rows | Smallest tested budget exact on all observed queries | Paid row distances at that budget | Padded record packet bytes at that budget | Raw cache body |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Uniform 64-bit / sorted128 | 1,024 | 1,024 | 8 / 8 groups | 1,024 | 16,704 B | 16,384 B |
| Uniform 64-bit / prototype16 | 1,024 | 1,024 | 16 / 16 | 1,872 | 30,592 B | 16,384 B |
| Favorable duplicate clusters / sorted128 | 256 | 192 | 2 / 2 | 256 | 3,152 B | 3,072 B |
| Favorable duplicate clusters / prototype16 | 256 | 16 | 1 / 16 | 16 | 232 B | 3,072 B |
| Complementary pairs / forced pair groups | 256 | 237.33 | 128 / 128 | 256 | 7,424 B | 2,304 B |
| Semeion / sorted128 | 1,465 | 1,465 | 12 / 12 | 1,536 | 61,920 B | 58,600 B |
| Semeion / prototype16 | 1,465 | 1,465 | 16 / 16 | 2,736 | 110,080 B | 58,600 B |
| Mushroom / sorted128 | 7,996 | 3,636.50 | 63 / 63 | 8,064 | 196,056 B | 191,904 B |
| Mushroom / prototype16 | 7,996 | 6,171.38 | 16 / 16 | 20,576 | 494,464 B | 191,904 B |
| Connect-4 capped / sorted128 | 4,096 | 4,032 | 32 / 32 | 4,096 | 99,584 B | 98,304 B |
| Connect-4 capped / prototype16 | 4,096 | 3,957.88 | 16 / 16 | 7,152 | 172,288 B | 98,304 B |

All 13 retained cases are in the raw record, including the additional sorted
and prototype layouts of the adversarial corpus. Packet bytes are the
**plaintext serialized-record model**, not measured private transport:
40 bytes of epoch/index/count plus `capacity * (8 + ceil(d/8))` per slot.
Every query additionally pays G summary Hamming distances. Client-pinned
metadata is charged separately; for example Semeion sorted128 retains
1,047 bytes, Mushroom sorted128 4,017 bytes, and the favorable prototype
case 911 bytes. Metadata provisioning and private PIR overhead remain unknown.

Mushroom's sorted layout reduces variable row work by about 54.52% on these
eight queries. But the half schedule, B=32, certifies only **5/8**. The smallest
tested budget that certifies all eight is B=63, paying 8,064 row distances plus
63 summary distances and more record bytes than acquiring the raw cache once.
This does not show that 63 is the mathematically minimum safe budget; budgets
33 through 62 were deliberately not searched or tuned after observing results.

The favorable synthetic case demonstrates a **real geometry effect**: one
16-row group suffices for each of the 16 center queries. With a public B=1,
it pays 16 row plus 16 summary distances. This is a known low-radius condition,
and the queries were deliberately centers. It gives **no all-query correctness
or availability guarantee** for arbitrary queries. Choosing a budget based on
that observation would not establish private exact search. The complementary
pair universe contains a query requiring all 256 rows, despite exact centers,
radii and IDs; its full schedule has 128 group headers, making record packets
3.22 times the raw cache body. One can stop correctly on some easier queries,
but cannot infer a universal small budget from them.

## What padding and trust do not solve

Equal slot/operation counts are checked; no private address selection is
implemented. Callback addresses, Python branches, elapsed time and parsing
behavior remain observable. An eventual PIR scheme must pay all request,
server scan, preprocessing/hint, integrity proof, ciphertext, RTT and release
costs. Those costs are marked **unknown**, not zero. If client success/failure
or retries reach the server, an incomplete fixed schedule can still leak.
No privacy equivalence or pre-decryption gate follows from this count model.

The exactly-B counts apply to **well-formed callback transcripts**. Malformed,
missing or stale packets raise immediately at `_open_packet`, so rejection
can abort before B slots finish. Failure-transcript padding, dummy completion
after a rejection and hiding callback exceptions are **not implemented**.
The rejection tests establish refusal to release an incorrect result against
the pin, not equal traffic or timing for malicious-server failures. A private
service would need to specify and charge that failure policy separately.

Full G-slot padding often destroys the useful variable-work effect. Uneven
prototype groups require every private slot to accommodate the largest group:
Mushroom's capacity is 1,286, giving 20,576 paid row distances and a reply-body
model 2.58 times the raw cache body. Sorted blocks mitigate capacity inflation
but still download essentially the full corpus when the schedule must cover
the hard observed query. Repeated full schedules reacquire records already
available to a permitted retained cache.

The mutable plaintext cache correctly applies a delete and an insert per case
with two logical mutations. The literal summary control rebuilds after that
batch: N centroid bit visits per coordinate, N radius distances, plus N times
the seed count for prototype assignment. For Mushroom prototype16 this is
127,936 assignment distances, 1,007,496 centroid bit visits and 7,996 radius
distances. These are actual logical counts, **not wall-clock update bounds**.
No compressed cache, authenticated incremental update scheme, resident memory
measurement, asynchronous update or multiple-device service is implemented
here. Those stronger controls could further favor caching.

## Return to the plan

Q29's bounded contract/count discriminator is complete for this literal known
control. It passes bounded exactness and rejects stale or missing data against
trusted metadata; it **stops as a candidate original main mechanism**. Do not
start a large PIR service on the strength of favorable variable visits.

A subsequent Route C attempt needs a genuinely distinct joint summary, block
and coverage representation, a specified useful query domain or safe all-query
schedule, and a measured frontier against raw/compressed mutable owner caches.
It must charge private retrieval and malicious outer-HE release before secret
use. Standard bounds plus PANTHER/SANNS-style retrieval are already covered by
the [closest-work comparison](closest-work-roadmap-refresh-20261002.md#6-closest-work-for-owner-summary-assisted-exact-retrieval).
Keep Route C lower priority while Routes A/B face their stronger controls.

```bash
.venv/bin/python -m pytest -q experiments/bfv_search_lab/test_owner_summary_oracle.py
.venv/bin/python benchmarks/owner_summary_lab.py \
  --cache ../research-data/uci-20260927 \
  --connect4 ../research-data/uci-connect4-20260930/connect-4.data \
  --receipt ../research-data/owner-summary-20261003/preregistration-receipt.json \
  --json-out /tmp/e103-owner-summary-new-run.json
```

The final 11-test run and explicit Ruff check of these three excluded research
files pass. The first Ruff invocation followed repository exclusions and
checked no files; it is **not** counted as validation. Explicit checking found
two loop-closure warnings in tests; default bindings fixed them, then the
tests and complete exact/count run were repeated with final source hashes.
No preregistered scope or decision threshold changed.
