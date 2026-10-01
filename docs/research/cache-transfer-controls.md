# E67: actual loopback acquisition of the permitted full cache

2026-09-30. Executed R2 control of the
[research plan](publication-research-plan.md); a pilot, not a matched remote
HE service comparison. The owner is allowed to retain and provision all rows.

[Transport harness](../../experiments/bfv_search_lab/loopback_transfer.py),
[tests](../../experiments/bfv_search_lab/test_loopback_transfer.py),
[runner](../../benchmarks/cache_transfer_lab.py) and
[raw](../../benchmarks/results/publication-cache-loopback-controls-20260930.json)
at source HEAD `e9c91f8`. The existing authenticated
[snapshot control](cache-acquisition-results.md) is reused.

## What was actually transferred

The owner begins with parsed rows and stable IDs. It creates a fresh 32-byte
key, serializes/compresses and AES-GCM-authenticates a snapshot, then uploads
the actual packet over TCP. The bytes received by that enrollment endpoint
are subsequently served by the storage endpoint. An isolated trusted owner
endpoint supplies the key plus pinned 64-byte manifest header: **96 private
bytes**, never placed on the public-storage catalog. The client authenticates
before parsing, and returns every exact score with stable top-3 ID ordering.

All sockets bind to 127.0.0.1 on ephemeral ports. The harness measures actual
reads/writes, connection establishment and payloads; it handles partial reads,
truncation and pinned length bounds. Download framing is 8+8 bytes and upload
framing is 16+8 bytes. Acquisition includes both private and storage download
framing. Cold acquisition additionally charges upload and its framing.

This is **not confidential private provisioning over a network**: the separate
trusted endpoint is a measurement boundary, not a deployed secure channel.
TLS, WAN, TCP/IP headers/retransmissions, thread/server startup, service queues,
durability and native/Python peak RSS are excluded. Retained bytes are a
serialized-body model, not process memory. Common fixture ingestion is timed
separately; the cold stage sum starts with parsed owner-held rows. It does not
represent cold representation discovery for an HE system.

## Measured pilot

Pinned split seed 3001; index-prefix cap 32,768; four held-out queries per case.
Three repetitions of five transport/retention choices on each dataset give
**45 acquisition cases / 180 exact local searches**. Raw, zlib1 and zlib9 can
all retain parsed raw rows. Two more modes retain only the compressed body and
charge decompression/parsing on every query. Every score, ID and stable top-3
is checked against a separate full plaintext calculation.

Below, acquisition bytes include the 96-byte private channel and 32 framing
bytes. Times are medians of three stage sums and twelve returning queries per
row; they are pilot diagnostics, not p95 or confidence intervals.

| Dataset / uploaded encoding; raw retained | Storage packet | New-client acquisition bytes | Cold stage sum | New-client stage sum | Returning query |
|---|---:|---:|---:|---:|---:|
| Mushroom, raw | 191,996 B | 192,124 B | 5.327 ms | 2.990 ms | 0.705 ms |
| Mushroom, zlib1 | 63,064 B | 63,192 B | 6.539 ms | 3.088 ms | 0.707 ms |
| Mushroom, zlib9 | 49,901 B | 50,029 B | 62.716 ms | 3.102 ms | 0.718 ms |
| Semeion, raw | 58,692 B | 58,820 B | 1.660 ms | 0.978 ms | 0.146 ms |
| Semeion, zlib1 | 32,954 B | 33,082 B | 2.409 ms | 1.092 ms | 0.152 ms |
| Semeion, zlib9 | 30,268 B | 30,396 B | 14.233 ms | 0.993 ms | 0.140 ms |
| Connect-4, raw | 786,524 B | 786,652 B | 21.970 ms | 12.147 ms | 2.689 ms |
| Connect-4, zlib1 | 305,261 B | 305,389 B | 28.415 ms | 12.768 ms | 2.701 ms |
| Connect-4, zlib9 | 247,388 B | 247,516 B | 399.982 ms | 12.388 ms | 2.691 ms |

The rows are respectively 7,996x126, 1,465x256 and 32,768x126. Connect-4 rows
are distinct. Raw retained body models are 191,904 / 58,600 / 786,432 bytes.
Retaining zlib1 instead reduces that body to 62,972 / 32,862 / 305,169 bytes,
but returning-query medians become 3.485 / 0.794 / 14.442 ms. The zlib9 retained
mode has similar query cost and more owner compression work; the raw keeps
all observations rather than selecting only favorable cases.

## Return to the plan

The actual packet sizes reproduce the earlier serialization controls with
private acquisition and framing now charged. Owner zlib9 cost is substantial
and differs sharply from an already-enrolled client's acquisition. No modeled
WAN crossover has been promoted to a measurement, and no new HE speed ratio
is inferred by combining this pilot with old HE timings.

R2 remains open for matched HE provisioning/RPC, client working memory,
controlled link/RTT experiments, relevant GPU residency and a justified
deployment frontier. Choose a bounded matched returning/new-client panel next;
give every HE token, mapping and hidden gate input its actual transport cost.
The cache is an executable competing action, not an excluded fallback.

```bash
.venv/bin/python benchmarks/cache_transfer_lab.py \
  --cache ../research-data/uci-20260927 \
  --connect4 ../research-data/uci-connect4-20260930/connect-4.data \
  --repeats 3 --queries 4 --json-out /tmp/e67-cache-new-run.json
```

Local TCP permission is required by the sandbox. No external service or
customer data was used.
