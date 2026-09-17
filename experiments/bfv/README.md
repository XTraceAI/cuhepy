# BFV packed Hamming experiment

This prototype moves exact Hamming-distance arithmetic and result packing to a
server that has no secret key. It returns up to **8,192 encrypted distances per
ciphertext**. The client decrypts those distances and selects top-k.

It is an offline research experiment using synthetic binary vectors. It does
not implement encrypted server-side top-k or connect to the XTrace API. The
Paillier implementations, `ExecutionContext`, `Retriever`, production dependencies,
and server wire format are unchanged. This directory is outside the SDK wheel.

The [research report](../../docs/research/bfv-packed-hamming.md) explains the
existing repository, the BFV design, measured tradeoffs, and integration work.

## Run

From the repository root, using the existing SDK virtual environment:

```bash
uv pip install --python .venv/bin/python -r experiments/bfv/requirements.txt
.venv/bin/python -m pytest experiments/bfv -q
.venv/bin/python experiments/bfv/benchmark.py --num-vectors 8192 --paillier-ref main
```

The benchmark reads a **local** Git revision, exports its `src/` into a temporary
directory, and starts a subprocess that imports that exact Paillier implementation.
It does not fetch, check out, or modify `main`. Use `--paillier-ref c8fc683` to
compare the starting GPU branch's **CPU** path. It does not benchmark a GPU.

```bash
# Save every measured phase and byte count; this appends a JSONL record.
.venv/bin/python experiments/bfv/benchmark.py \
  --num-vectors 2048 --repeats 3 --paillier-ref main \
  --output /tmp/xtrace-bfv-measurements.jsonl

# Reproduce the smaller ring's noise-budget failure, with security still TC128.
.venv/bin/python experiments/bfv/noise_probe.py --degree 4096
.venv/bin/python experiments/bfv/noise_probe.py --degree 8192
```

The benchmark checks **every** distance and top-k against a plaintext oracle. It
records encryption, server evaluation, client decryption/selection, setup keys,
index storage, query upload, response download, and byte-only amortization. The
JSONL includes the baseline commit and hashes of the experiment source.

## Minimal client/server example

Run this Python code from the repository root:

```python
from experiments.bfv.packed_hamming import BfvClient, BfvServer

client = BfvClient(dimension=4)
server = BfvServer(client.server_bundle())  # public/evaluation-key bytes only

index = client.encrypt_index(
    [[1, 0, 1, 0], [0, 1, 0, 1], [1, 0, 0, 0]],
    ids=[101, 102, 103],
)
query = client.encrypt_query([1, 0, 1, 0])
response = server.search(index, query)
assert client.top_k(response, k=2) == [(101, 0), (103, 1)]
```

`index`, `query`, `response`, and `server_bundle()` are MessagePack `bytes`.
The tests also run the server in a separate process supplied only these public
or encrypted inputs. Secret keys are never serialized by this prototype.
Keys live in the client instance; creating another client creates a different
key and requires a corresponding index.

`decrypt_distances()` returns `(ID, distance)` in original index order. `top_k()`
orders by distance, breaking ties with the smaller ID. Empty indexes return empty
results; `k=0` returns none and oversized `k` returns all candidates. Dimensions
1 through 4,096 are accepted and padded to a power of two. IDs are unique unsigned
64-bit integers. Embedding floats must be binarized before calling these APIs.

## Parameters and serialization

The protocol fixes BFV degree `N=8192`, plaintext modulus `t=65537`, and SEAL's
`BFVDefault(N, TC128)` coefficient moduli. The tested binding yields key-level
prime bit sizes `[43, 43, 44, 44, 44]`; input ciphertexts use four of those primes.
The server drops to one prime after completing the arithmetic and packing.
`server.search(..., compact=False)` retains all four for comparison.

These are exact integer computations, with one ciphertext multiplication per
input tile. No bootstrapping or approximate arithmetic is used. The client
checks remaining noise budget and the decoded distance range; those checks do
not authenticate server output. `noise_budgets()` is a local diagnostic only.

TenSEAL 0.3.16 exposes the required SEAL batching, rotations, and modulus switching
through `sealapi`. Its low-level save/load binding takes filenames, so `_save`
and `_load` use temporary files for **ciphertexts and public/evaluation keys**.
Measured serialization time includes that file I/O. No plaintexts or secret keys
pass through these helpers. A service implementation should use memory-based
serialization in a maintained binding or C++.

**Backend limitation:** Microsoft currently recommends SEAL **4.4.0 or later**
for security fixes involving untrusted inputs and native memory safety. The pinned
TenSEAL wheel used for this experiment is not evidence of a patched backend. Use
this experiment with locally generated inputs; update and verify the native
backend before accepting service traffic. [Microsoft's SEAL notice](https://github.com/microsoft/SEAL)

## What remains for a service

Existing Paillier ciphertexts need a client-side migration/reindexing step before
this evaluator can use them. Keep both indexes to offer an operational fallback.
The current SDK cannot send a BFV query to an existing Paillier knowledge base.

This prototype assumes one key owner and an honest evaluator. IDs, dimension,
and candidate count are visible. Messages have schema and identity checks but
no authentication, query nonce, replay protection, or proof of correct evaluation.
The client must retain decrypted values, errors, and noise diagnostics locally.
SEAL documents these distinctions between encryption, authenticity, and decryption
feedback in its [security guidance](https://github.com/microsoft/SEAL/blob/main/SECURITY.md).

Server-side encrypted comparison/selection, index persistence, updates,
metadata/range filtering, key lifecycle management, and an actual transport are
future work. The [research report](../../docs/research/bfv-packed-hamming.md)
sets out the proposed boundaries for those changes.
