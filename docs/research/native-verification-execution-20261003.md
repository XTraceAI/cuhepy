# Complete native verification: execution record

This execution follows Q56–Q61 in
[the system blueprint](system-research-blueprint-20261003.md). Parent checkpoint
is `dfdd6bd298dec2da93b9d5a9dd1acad1d1889734`, on a new
`experiment/native-verification-system-20261003` branch. Previous company code,
raw measurements and delivered native binaries remain the baseline. New evidence
is exclusively in `../research-data/native-verification-system-20261003/`.

## Q56: complete native control

The new files are `experiments/bfv_search_lab/native_complete_checked_bgv.py`
and `_native/complete_continuation.h`, with separately guarded bindings and a
`make complete` target. The new module is `_bgv_complete`; it uses our existing
C++/GMP/RNS arithmetic and does not import SEAL. The earlier tiny Python
controller and existing CPU/CUDA/checker binaries remain available.

Enrollment binds the ordered encrypted index, all evaluation keys, IDs, source
layout, terminal modulus and epoch. Original four-field seeded and five-field
rounded query formats are expanded from their exact enrolled context. Entire
immutable product-block coverage, all canonical RNS coefficients and claimed
response grammar are checked before any private check weights are sampled.
Each block receives fresh three-round checks per prime with locally recomputed
C2. Only after every block passes does native trusted arithmetic apply the
initial shift, every butterfly rotation, canonical full-Q digit decomposition,
and GMP terminal conversion. Every final coefficient is serialized and checked,
including unused score coordinates. A supplied response must equal those exact
authoritative bytes. Prepared full native replay is a separate control and never
an expected-answer oracle inside admission.

The controller has no HE secret, private decoder, receipt signer or enclave. Its
optional release sentinel is public test instrumentation. One-use, process and
copy guards are local: durable rollback/global attempt assurance, protected
check-coin side channels, attestation, private-client arithmetic, parameter
assurance and a deployed malicious-server protocol remain separate obligations.

Conditional arithmetic soundness for a false product in a fixed immutable
snapshot is at most `B / min(p0,p1)^3` per full attempt, where B is the number
of blocks. This relies on the actual prime fields, correct arithmetic, fixed
bytes before independent uniform private coins, and no coin leakage. It is a
union bound over blocks; probabilities for an honest second limb are not
multiplied into the bad-limb bound. Across J attempts, the corresponding union
bound requires a real globally enforced J. These assumptions and the trusted
suffix boundary do not establish the complete privacy/deployment reduction.

The frozen eight-query cohort independently matches every packet byte against
the schoolbook oracle in both prepared replay and checked-product continuation.
Its native resource body is 1,280 bytes, two response groups, five trusted
rotation nodes and 32 terminal coordinates. The standalone native worker also
retains 35 canonical algebra geometry checks and 28 parser negatives, plus an
N16384 algebra-only suffix comparison. These are correctness observations, not
valid-HE claims for those arbitrary algebra fixtures or performance results.

The integrated native test module passes 116 cases. They cover every
tiny product tile/component/limb, every final and unused coordinate, context and
snapshot substitutions, all-block validation before entropy, later entropy
failure, concurrent duplicate and independent requests, original query grammar,
invalid terminal profiles, no replay/producer admission oracle, and
semantically equal alternate MessagePack bytes, the 64-group limit, and the
bounded public seed expansion. An initial 88-pass/1-failure
development run contained the old tiny controller's obsolete geometry restriction;
the new controller correctly permits broader bounded layouts. The final test
uses genuinely incomplete coverage instead. This failed development observation
is retained separately from the final scope.

The source-sized valid-HE cohort is separately preregistered: one fresh owner
key, N16384/Q120/t1031/D512, 8,192 rows of 512 bits, P25, and three original
seeded queries. It completed once with 24,576 correct distances and stable top3.
All three complete packets match the older public CPU backend, new prepared
replay and checked-product continuation. This checks 98,304 terminal coordinates
across three queries; six outside-owner diagnostic decryptions do not double the
unique distance count. Source native implementations share low-level RNS routines,
so this large comparison is supplemented by independent plaintext Hamming truth;
it is not a wholly independent schoolbook implementation at N16384.

Each query actually carries 134,217,728 bytes (128 MiB) of product output to
the checker, executes 511 trusted rotations, and returns 102,488 framed client
bytes (102,400 packed coefficient bytes). This confirms the old product-body
model on real valid-HE inputs. It is a correctness cohort with no latency winner
or independent timing uncertainty claim. Product/checker traffic is about 1,310
times the framed client reply; that does not mean a 1,310x latency penalty.
The actual link, local C2 computation, parsing/copying and protected suffix need
separate complete measurement for a deployment claim.

## Q57 and the next gate

The operator discriminator compares normalized source maps to the strongest
equally specialized generic affine/adjoint control. Non-additive choices alone
do not establish originality: the generic control is allowed the same sharing,
canonical cuts, index specialization and basis normalization. A literal atomic
dictionary's modeled allocation is separate from required or measured resident
state. Q58 proceeds only if a distinct feasible rule survives this comparison.

New prior work [KeyMemRT](https://arxiv.org/abs/2601.18445) is pinned as the 102nd
source record, with PDF/text hashes and a targeted read of typed rotation keys,
key lifetime merging, hoisting, CSE and prefetching. It is a concrete known
memory-scheduling control, not an artifact reproduction or an equivalence proof
for our complete verification relation. Its relevant PDF pages were visually
checked using the PDF skill.

Q59 completed the bounded static identity after H1 stopped, giving the generic
control the same degree-one factorization. Its 144 public fixed-coins comparisons
and 24 large static support cards match that control. Fixed diagnostic coins
validate algebra; they do not approve adaptive reuse. Fresh private coins
require rebuilding the relevant adjoints, with that work charged. Both literal
originality gates therefore stop; Q58/Q60 are skipped under their prerequisites.
The [Q61 decision](native-verification-selection-20261003.md) retains these known
engineering controls and records the unimplemented live-update/service assurance.

## Evidence and reproducibility

`baseline-inventory.json` records all tracked source and delivered extension
hashes before edits. The native build receipts retain the first failed make
attempt, the corrected build and unchanged historical binaries. New test/cohort
receipts are scoped individually and must not be added to overlapping old test
counts. The public frozen fixture remains at its old hash; new source fixtures
contain public encrypted material, not the HE secret or encryption randomness.

Run the new frozen cohort with the repository interpreter:

```sh
.venv/bin/python -m benchmarks.native_complete_bgv_lab \
  --backend ../research-data/native-verification-system-20261003/native/_bgv_complete.cpython-312-x86_64-linux-gnu.so \
  --output /tmp/new-q56-frozen-receipt.json
```

The ledger reports exact logical body sizes and explicit resident buffer classes.
It does not call their sum measured peak memory, nor omit duplicated public
snapshot, prepared replay and checker buffers from the complete-state account.

After the source run and independent review, four new Python files received
formatting cleanup and the local conversion lambda became a named function.
All 20 exact executed input files were archived first in `source-cohort-inputs/`
with a manifest matching the source preregistration. `readability-receipt.json`
checks AST preservation after the declared lambda-to-function normalization;
no native binary changed. Final scoped tests and lint validate the readable
version. The original cohort/review hashes identify the executed version, not
a claim that current source text still has its pre-format hash.
