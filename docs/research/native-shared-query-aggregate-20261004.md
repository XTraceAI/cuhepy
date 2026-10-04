# Q76.4b exact aggregate control return

The registered public gate passes: **16 retained small and six saved large
cases** match all three pre-relinearization tensor components and the complete
compact frames. There are 394,944 aggregate coefficient comparisons, including
393,216 at source scale. Each complete frame is publicly authorized before a
durable, single public-only callback claim.

No HE key, encryption, decryption, randomized challenge, GPU run or timing
panel was added. One ephemeral standard Ed25519 context supports the cohort;
unit-test contexts are separate. No secret was serialized. This is a **known
exact control**, not a new primitive, performance result, approved parameter
set or deployed attestation result.

## Shared implementation and independent reference

`_shared_query/shared_query_aggregate.cpp` is a separate translation unit. It
retains full-witness ABI1202 and replay ABI1, adding aggregate ABI1. The core
is factored into genuine query expansion, paired-Karatsuba aggregation and
canonical relinearization helpers shared by all three modes. Existing full
body/source ordering and replay behavior pass their regression gates on this
build. Earlier successful libraries and all delivered company files remain
byte exact.

The untrusted producer emits complete canonical whole-Q `C0,C1,C2` arrays per
group and its proposed compact frame. The protected checker validates every
claim coordinate before prefix NTTs, expands the signed original query, and
compares all three vectors in both actual-prime NTTs against the equally
optimized three-product aggregate. This is the direct coefficient form of the
known exact three-point interpolation identity. It uses no sampled coordinate,
hidden scalar or free peer-expanded query. These protected products are paid.

After equality, the protected suffix derives genuine common-Q radix30 C2
digits, performs delayed relinearization and the shared exact Q-to-P codec.
Terminal bytes are written only after every group passes, and authorization
requires the entire frame to match. `aggregate_shared_query.py` binds the
trusted factory-selected exact mode/library/code and original signed context.
The existing local lifecycle consumes failures and rechecks snapshots; its
trusted nonrollback storage assumption remains explicit.

The small reference independently expands the original query with signed
schoolbook permutations/convolution and uses four literal tensor products. Its
N>64 guard remains. Large recovery uses the preserved, independently GMP-
validated trace: saved C2 is genuine, and saved final components are
`C0+switch(C2)[0]`, `C1+switch(C2)[1]`. Subtract an independent whole-Q GMP key
switch to recover C0/C1. No HE secret or thousands of feature products are
needed. Historical signatures, file hashes and the earlier GMP-body hash are
checked before using this provenance. It is not a fresh independent large
encryption experiment. Public reconstruction receipts preserve current mode
enrollments without duplicating the large original inputs.

```bash
make -C experiments/bfv_search_lab/_shared_query \
  SOURCE=shared_query_aggregate.cpp TARGET=/tmp/cuhepy-aggregate/libshared_query_aggregate.so
```

Adapter/reference/tests live alongside the experimental implementations;
`benchmarks/aggregate_shared_query_lab.py` reproduces the gate with explicit
fixture/library/baseline/preflight paths and a new output directory. Source,
binary, flags, versions and signatures are preserved in
`/home/pete/yavor-projects/xtrace-work/research-data/q76-aggregate-20261004`.

## Tests and measured byte counts

The final normal invocation passes **360 cases**, including 309 existing and
51 new aggregate cases. UBSan passes the overlapping 160-case native/replay/
aggregate subset. The first 50-case invocation also passes; these invocations
are not added as independent experiments. Four normal and three UBSan warnings
come from deliberate fork-after-thread rejection tests.

All 1,728 small aggregate coordinates are mutated in each of three families:
ordinary error and errors preserving either actual prime. **All 5,184 faults
reject.** A registered test-only follow-up adds 384 faults, each isolated to
one physical NTT frequency of one actual prime; all reject. Independent
odd-root evaluation verifies that each fault really isolates that frequency.
The total is 5,568 fault mutations, with the two families counted separately.
Further cases cover single-point component cancellation, late
noncanonical syntax, full tails/headers/context/mode, exact C ABI lengths/nulls
and unchanged terminal sentinels, forbidden private/reference/producer entry
points, closed/copied/forked/threaded ownership and consumed/restart/stale/
foreign-policy lifecycle. Tests do not establish formal native assurance,
parameter security or private side-channel safety.

The initial 359-case/159-case runs and the 22-case cohort used the first
411-file source snapshot. The isolated-frequency follow-up changes only the
aggregate test file. A second 411-file archive pins the final 360-case/160-case
regressions; native code, adapters and both binaries are unchanged. The cohort
is retained rather than repeated, and overlapping invocations are not summed.

| Records | Full-trace body | Aggregate body | Compact frame | Dedicated final-Q buffer |
| ---: | ---: | ---: | ---: | ---: |
| 8,224 | 126,320,640 B | 737,280 B | 102,488 B | 491,520 B |
| 16,384 | 126,320,640 B | 737,280 B | 102,488 B | 491,520 B |
| 32,768 | 127,057,920 B | 1,474,560 B | 204,895 B | 983,040 B |

The first two columns are internal server-to-verifier bodies before envelopes.
The compact client frame is unchanged. Expansion-source witness bytes are
absent, while aggregate bytes, claim transforms, prefix, suffix and **three
protected products per feature** remain paid. Full protected replay needs
zero aggregate-witness bytes and no untrusted producer. Byte reduction does
not establish that delegation beats replay or improves latency.

The whole runner high-water mark was 2,882,494,464 B, including historical
packet reads, Python/GMP work, authentication and native preparation/computation.
It is neither a native-stage peak nor a comparison with the different replay
runner. The final-Q column excludes other scratch and retained state.

Q76.4b is complete in its registered local/public scope. The
[machine return](native-shared-query-aggregate-return-20261004.json) returns the
[execution plan](system-contribution-execution-plan-20261004.md) to **Q76.4c,
the permitted authenticated cache**, then Q76.5's independent certificate/
resource/client-context handoff. Complete-cost evaluation, actual deployment/
security and the external originality decision remain unfinished. Randomized
admission is unimplemented; this exact gate approves no challenge reuse or
adaptive probabilistic budget.
