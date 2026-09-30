# E58/E60: permitted authenticated cache acquisition and remote cost screen

2026-09-30. The user clarified that the online client queries its own data and
may retain any of it. Full local caching is therefore allowed. No artificial
memory or retention restriction is imposed. This strengthens P00/P01/P06's
mandatory download-once comparison; these are known baseline ingredients.

`experiments/bfv_search_lab/cache_snapshot.py` uses standard AES256-GCM via
PyCryptodome, a random12-byte nonce, a16-byte tag and an authenticated header
with dimensions/count/compression flag/random epoch. The client needs an
owner-approved key and **current pinned manifest** through a trusted channel.
It authenticates before any parser/decompressor sees decrypted bytes, bounds
packet and decompressed lengths and validates unique uint64 IDs/binary widths.
The [library API](https://www.pycryptodome.org/src/cipher/modern) specifies
nonce uniqueness per key and tag verification; this experiment creates a new
key for each snapshot. It does not supply a remote authorization channel,
durable freshness/nonce management, erasure or HE. Compressed length is
additional declared leakage. Tampering, wrong key, stale manifests, truncation,
duplicate IDs, noncanonical padding and authenticated expansion are tested.

After acquisition, raw mode retains parsed rows/IDs; compressed-retained mode
decompresses/parses again for each exact local query. Body counts exclude
Python object/RSS and transient duplicate allocations. Every mode returns
every exact score and stable `(distance, ID)` top3.

## Actual acquisition measurements

Two rotating repetitions, eight held-out queries per mode, split seed3001.
The first level9 run retains18 cases/144 exact queries; the compression-effort
follow-up retains54 cases/432 exact queries across levels1/3/6/9. Fixture loading
is reported separately as common input acquisition. Owner serialization,
compression, encryption and client authentication/decompression are charged
in acquisition. This is a warm-process cache cold start, **not process-start,
measured network, RTT or mobile-device latency**. First-use AES initialization
is visible in the first raw Semeion case and is retained.

| Enrolled fixture / d | Raw AEAD packet | zlib1 packet | zlib9 packet | zlib1 owner+client acquisition | zlib9 owner+client acquisition |
|---|---:|---:|---:|---:|---:|
| Semeion1465 /256 | 58,692 B | 32,954 B | 30,268 B | ~1.98 ms | ~13.54 ms |
| Mushroom7996 /126 | 191,996 B | 63,064 B | 49,901 B | ~6.09 ms | ~62.36 ms |
| Connect-467429 /126 | 1,618,388 B | 627,155 B | 506,956 B | ~56.57 ms | ~817.58 ms |

The table uses compressed packet → raw-retained mode pair means. Local exact
query means are about0.15/0.75/5.78 ms at level1 for the three fixtures.
Keeping only compressed bodies instead costs about0.80/3.49/28.96 ms per query
at that level. Compression level is a known cost/size choice: maximum effort
does not necessarily minimize cold-session latency.

The larger real fixture is [UCI Connect-4](https://archive.ics.uci.edu/dataset/26/connect%2B4),
Tromp1995, DOI10.24432/C59P43, CC BY4.0. Its67,557 records encode42 categorical
board cells plus an ignored outcome label. Three indicator bits per cell yield
d126 and Hamming distance exactly twice the number of mismatched cells.
The existing128-row holdout leaves67,429 enrolled records, with no duplication
to inflate count. This is game-position similarity, not text retrieval or
evidence of customer update frequencies. `connect4_fixture.py` pins archive,
compressed member and decompressed hashes; the old two-fixture catalog is
unchanged. This tranche measures full-corpus caching, not HE at67,429 rows.

Source hashes and full commands are retained in:

- `publication-cache-snapshot-20260930.json`
- `publication-cache-compression-levels-20260930.json`
- `benchmarks/cache_snapshot_lab.py`

## Ready-remote comparison, explicitly a model

E60 reads these retained measurements and the strongest global BGV/original
EMVP full-gated CPU controls. Raw source/count/dimension hashes match; every
cache/EMVP held-out score hash matches. Remote uses the **fastest non-warmup
gated sample**, with setup, private-state/token provision, framing and RTT
omitted. This intentionally favors remote evaluation. Independent run timing,
three BGV timed queries and eight EMVP/cache queries do not establish a latency
distribution. Different unreviewed parameters/entropy/protocols also prevent
an equal-assured-security dominance claim.

For empirical constants C(acquisition), L(local query), U(remote query), packet
sizes P and B, nominal link rate v and session count q, the screen computes:

```text
cache:          C + q*L + 8*P/v
ready remote:       q*U + q*8*B/v
```

The ready-remote expression is a lower cost **within this specified model**
because prepaid costs are omitted; it is not a runtime lower bound. Session
counts1/2/4/8 and nominal1/10/100/1000/10000 Mbps are modeled cells, not socket
measurements. Candidate choices include raw/each measured compression effort
and raw/compressed retention, and all eligible ready-remote profiles.

Cold owner+client caching is cheaper in37/40 cells. The three other cells are
Semeion single-query sessions: own BGV at1/10 Mbps and original EMVP at10000
Mbps. Separate owner-ready-cache accounting removes prepaid owner preparation
as well; it wins38/40 cells, leaving the two slow-link single-query BGV cells.
For example at10 Mbps, one modeled query costs about23.24 ms ready BGV versus
25.10 ms owner-ready compressed cache; two queries already favor caching.
These narrow remote-favorable cells motivate cold-session experiments. They
**do not prove outsourcing is beneficial** after currently omitted remote
provisioning, real device/link costs and lifetime are included.

The initial cold-owner screen and the expanded owner-ready screen are both
retained, with distinct source versions:

- `publication-cache-remote-cost-screen-20260930.json`
- `publication-cache-remote-ready-screen-20260930.json`
- `benchmarks/cache_remote_cost_lab.py`

Return to the plan: prefer an authenticated local cache for the measured reuse
profiles. Keep HE/code-based outsourcing as explicit alternatives for a measured
resource or cold-session frontier. P00's usefulness, P06's practical-effect
gate and paper originality are still open; this is not a new crypto mechanism.
