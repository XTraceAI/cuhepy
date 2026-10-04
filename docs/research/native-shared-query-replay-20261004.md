# Q76.4a matched native prepared replay return

The bounded public correctness gate passes: 16 retained N16/N32 cases and six
saved N16384/D512 cases at 8224, 16384 and 32768 records. Both complete compact
ciphertext components, all coordinates, headers, groups and tails match the
reference frames. Historical signatures and input hashes were verified before
the large inputs were re-signed under the new trusted control policy.
No HE key, ciphertext or decryption was generated for this gate. One ephemeral
standard Ed25519 context supports the cohort; test-fixture signature contexts
are separate. No signing or HE secret was serialized.

This is a **known-method comparison control**, not a new algorithm, speedup,
attestation result, security parameter approval or accepted original main result.
The previous source checkpoint supplied independently GMP-validated large
frames and post-authorization private diagnostics; those diagnostics were not
rerun here. The small fixture schoolbook/GMP provenance is retained.

## Implementation and execution

- `_shared_query/shared_query_replay.cpp` exports replay ABI1 alongside the
  unchanged public ABI1202. It includes the existing core in one translation
  unit and calls its shared producer/codec with source-witness writes disabled.
- The core's optional internal mode omits only witness serialization. Original
  query expansion, whole-Q CRT/radix30 formation, both actual-prime NTTs,
  paired Karatsuba, genuine key switching and exact Q-to-P conversion remain.
  Original exported calls retain their full-witness behavior.
- `replay_shared_query.py` pins a distinct trusted factory policy and the
  explicit library/adapter/source. A received packet cannot select a graph,
  executable or admission mode. PID/lock/handle ownership remains shared with
  the existing native adapter.
- `ReplayRequest.checked_frame` recomputes every coefficient of a proposed
  server frame. `PreparedReplayAuthorizer.execute` is the stronger matched
  protected-execution control: receive only the signed original request,
  compute the complete frame once, and authorize it. It requires neither an
  untrusted producer nor a server frame/source witness. Both use the same
  durable local authorization/claim semantics.
- The only Python change to the existing authenticated path is a trusted
  request-factory seam, including query cleanup if construction fails.
  Policy hashing intentionally changes when this code changes. Saved
  historical envelopes are verified in their original context before the
  current control's separately signed enrollment is constructed.

All code is isolated in `experiments/bfv_search_lab`; the reproducible runner
is `benchmarks/replay_shared_query_lab.py`. The delivered company source and
libraries, original native builds, main/staging and prior evidence remain
unchanged. No production interface migration follows from this gate.

```bash
make -C experiments/bfv_search_lab/_shared_query \
  SOURCE=shared_query_replay.cpp TARGET=/tmp/cuhepy-replay/libshared_query_replay.so
```

Use explicit fixture/library paths for tests and the pinned baseline,
preflight and source report for the runner. The
[registration](native-shared-query-replay-registration-20261004.json) and
[machine return](native-shared-query-replay-return-20261004.json) record the
bounded scope. Outer evidence is
`/home/pete/yavor-projects/xtrace-work/research-data/q76-replay-20261004`.

## Counts and resources

The final normal invocation passes **309 cases**, including 258 existing
cases and 51 new replay cases. UBSan passes the overlapping 109-case native
and replay subset. These invocations are not added as independent experiments.
Three normal and two UBSan warnings are from deliberate fork-after-thread
ownership rejection tests. The first 51-case invocation had one test-helper
instrumentation failure: it monkeypatched a nonexistent module-level GMP
producer instead of `GMPPublicContext.produce`. That log and the corrected
source revision are preserved; arithmetic/build sources did not change.

| Records | Reference full-witness body | Replay source-witness bytes | Compact frame | Replay dedicated final-Q buffer |
| ---: | ---: | ---: | ---: | ---: |
| 8,224 | 126,320,640 B | 0 B | 102,488 B | 491,520 B |
| 16,384 | 126,320,640 B | 0 B | 102,488 B | 491,520 B |
| 32,768 | 127,057,920 B | 0 B | 204,895 B | 983,040 B |

These are different buffers/links. Replay does **not** further reduce the
existing compact client ciphertext frame. It removes the unused internal
source witness for protected full execution. This is not a measured latency
improvement. The dedicated final-Q buffer is not total scratch or peak memory.
Index/key preparation and expanded-query working state are still paid. The
cohort's whole-process high-water mark was 2,862,178,304 B, including Python,
historical packet reads, current authentication/preparation and native work;
it is neither a native-stage peak nor a timing result.

Large current enrollment envelopes are preserved by small public reconstruction
receipts: authenticate the pinned original payload, replace only its policy
field5, and use the saved current Ed25519 signature. Their complete original
inputs reside in the preceding source checkpoint. The runner checks exact
reconstruction and the current signature. No duplicated large index or secret
is required to reconstruct the envelopes.

## Return to the publication plan

Q76.4a is complete in its registered local/public scope. Q76 remains partial.
Next is Q76.4b: canonical aggregate-only tensor output, genuine protected query
prefix, exact whole-vector aggregate checks and protected suffix, with the same
compatible arithmetic and lifecycle. Then complete the permitted cache control
and independent certificate/resource/client-context handoff before Q77's frozen
full-cost evaluation.

Three tensor components can be checked at three distinct points exactly, or
computed directly with paired Karatsuba using the same three products. That
known fact supplies a strong control; it does not itself establish a useful
delegation speedup. The randomized alternative remains unimplemented, with
its separate adaptive-budget/hidden-challenge obligations. Actual attestation,
rollback-resistant authority and private side-channel/parameter assurance
remain Q78 work. The potential contribution remains an independently assured
complete system and a prior-separated execution-cost finding.
