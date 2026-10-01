# E72: one-registration verification of encrypted queries

2026-10-01. Executed R3-B1/B2's
[preregistration](query-verification-preregistration-20261001.md). Homemade
[gate](../../experiments/bfv_search_lab/encrypted_query_gate.py),
[tests](../../experiments/bfv_search_lab/test_encrypted_query_gate.py),
[runner](../../benchmarks/encrypted_query_gate_lab.py), immutable
[raw](../../benchmarks/results/publication-encrypted-query-gate-control-20261001.json).
The [E71 reference](encrypted-query-certificate-control.md) is unchanged.

## Relation and exact evidence

The public encrypted index maps the actual encrypted query's **two full-Q
components** linearly to three response components. Compile a private uniform
field fingerprint once. Check selected C0 and full C1/C2 before computing
selected phases with the inner secret. Pin the original query and owner-approved
layout, epoch, key, IDs and private plan identity. No fresh encrypted owner
answers, private point hints, quotient upload or extra challenge RTT is needed.
This is a known linear-check control, **not a new cryptographic construction**.

For challenge `(w0,w1,w2)`, index column `(a0,a1)` and query `(b0,b1)`:

```
z0 = adj(a0) w0 + adj(a1) w1
z1 = adj(a0) w1 + adj(a1) w2
check: z0·b0 + z1·b1 = w0·C0 + w1·C1 + w2·C2   mod Q
```

Sum over columns/replies. The adjoint is convolution by `a(X^-1)` in the
negacyclic ring; omitted C0 challenge entries are zero. Center selected Q phases
before reduction to t; never ordinary-decrypt a zero-padded ciphertext.

All **112 queries** across seven mixed/empty/multi-reply layouts pass, with
every score and stable top-three ID matching plaintext and independent full
decryption. Literal signed matrices check each compiled component. The signed
transpose test caught and fixed normalization before GMP packing. All **18
scoped tests pass**: wrong transmitted C0/C1/C2, malformed body, substituted
encrypted input, context, replay and shared cross-epoch lifetime controls.
Selected rejects reach no private decoder. Tests are not parameter assurance.

## Feedback boundary

In the ideal uniform-field model, a fixed nonzero **projected output error**
passes k independent rows with probability Q^-k. With one aggregate decision,
the all-reject path fixes the next error; first false acceptance is at most
B/Q^k over B attempts. Correct outputs always satisfy the equation and reveal
no checker predicate in this model. Exhausting 81 q=3/two-row/two-coordinate
checkers yields 17 first wrong acceptances over two attempts, at most 2/9.

Unlike E71's true-output/bad-quotient control, there is no independently supplied
proof-round field. This is **not** a proof covering private timing, leaked hints,
rollback or arbitrary application feedback. Hints/challenges must stay private,
and a future receiver needs durable lifetime state. This code is local,
volatile and variable time; HE privacy/parameter assumptions remain open.

## Costs and return to the plan

Toy N=32/t=17/eta=1/4-round cases send **924-byte query packets** and
288–1,048-byte projected reply bodies. Compiled hints occupy 4,096 B;
one-reply challenge bodies are 1,152–1,536 B, three-reply challenges 4,192 B.
These canonical bodies exclude Python overhead, pending public queries, IDs,
envelopes and provisioning. Separate traced Python allocations are not RSS.

One registration serves all sixteen queries. Small-fixture medians:
0.350–0.383 ms query encryption, 0.396–1.042 ms GMP server multiplication,
0.237–0.446 ms verification/selected decrypt/decode. These are toy CPU stages,
not native/GPU service results or equal-security latency ratios.

Eight separate **correctness/count models** use E71's larger depth-one Q and
the exact 1,024-attempt/128-bit algebraic row count. Selected Mushroom/Semeion
compiled private hints alone occupy **22.5 / 16.17 MiB**; raw Connect-4 needs
**10.83 MiB**. Full-output public-body upper bounds are
3,226,624 / 2,396,896 / 1,963,968 B. These Q values require new keys/index
encryption and are unapproved. C0 support can reduce reply/challenge bodies,
but does not reduce compiled input hints.

**R6 decision: retain the executable control; stop the literal variant as a
paper candidate.** Trusted per-query index preparation is removable, but
large state/upload merely relocates its cost. Authorized caches and original
direct-fresh HE remain mandatory controls. Next R3-B0 packs the query and
prices the whole verification boundary; unchecked server expansion is not
acceptable. A survivor needs an original step and a useful complete margin.

```bash
.venv/bin/python benchmarks/encrypted_query_gate_lab.py \
  --json-out /tmp/e72-new-run.json
```
