# Owner custody and complete private finish component

The additive owner adapter is
[`complete_cost_owner.py`](../../experiments/bfv_search_lab/complete_cost_owner.py),
with its public control tests in
[`test_complete_cost_owner.py`](../../experiments/bfv_search_lab/test_complete_cost_owner.py).
The [component registration](native-shared-query-owner-component-registration-20261004.json)
was committed at `f36f9e389d4a984e6fdeacc0505247f6488219af` before either
new source file existed. The [return receipt](native-shared-query-owner-component-return-20261004.json)
records the exact scope, source versions, both invocations and retained failures.

## Implemented path

`OwnerKeyCustody` binds the owner's supplied homemade BGV key metadata to one
frozen geometry. It reconstructs the public fingerprint, checks complete
canonical public coefficients and matching ternary secret metadata, and
keeps a process-bound, noncopyable handle. The honest owner-generated key-pair
relation remains a premise: matching fingerprints and key IDs do not prove
the mathematical public/secret relation. The caller can retain its original
Python secret-key copies; closing the holder cannot securely erase them.

`OwnerClient` binds the independently trusted descriptor and all three verifier
anchors to that custody. `OwnerAttempt.finish` offers no caller-selected private
callback. It delegates public admission to the existing `ResultClient`, which
authenticates the complete receipt/frame, binds the original request and current
descriptor, checks public coefficient grammar and consumes the attempt before
invoking the fixed private finish. A rejected response cannot initialize the
private backend through this API. Process-local consumption is not durable
nonrollback authority or hardware attestation.

The admitted packed coefficients feed the existing homemade
[`private_bgv.PrivateDecoder`](../../experiments/bfv_search_lab/private_bgv.py).
Its native handle is created lazily, checked against the selected terminal
modulus and reused for the registered owner-key lifetime. Packed bytes avoid
rebuilding GMP ciphertext rows. A per-block client close leaves key custody
alive; decode and key close share a lock. Initial private preparation and its
lifetime must be charged in the exact execution addendum. The existing private
extension was pinned and copied; it was neither rebuilt nor actually executed
by the public unit gate.

Every decoded physical coefficient is checked: canonical plaintext residues,
complete group coverage, zero unused tails, occupied signed-score range and
Hamming parity. The output contains all exact distances and the first three
matches ordered by `(distance, row ordinal)`, with IDs treated as bound labels.
Any private-finish exception disables the entire key context, attempts native
cleanup, and returns through the existing coarse consumed-attempt error path.
There is no private fallback or fresh-context retry. This control rule does not
establish constant-time Python handling or guarantee erasure after native cleanup
failure.

## Bounded evidence

The final combined invocation passed **236 distinct tests: 78 new owner cases
and 158 existing public role/transport cases**. The owner cases use public
grammar-only key metadata and a public plaintext decoder stub, not a valid HE
key pair. Guards observed zero actual HE key generation, encryption, decryption,
native private preparation or native private decoding attempts. The native
private path is implemented but its HE correctness is still unexecuted here.

The first invocation passed 77 of 78 cases. Its stale-pin fixture advanced the
epoch without changing the logical revision; the fixture was corrected and
both source archives/results were retained. Counts from both invocations are
not added as distinct experiments. Three intentional fork-negative tests
produce Python deprecation warnings; they check rejection before inherited
locks, not real worker isolation. Actual public workers must be independently
spawned without an HE secret in their parent.

The compatibility suite retains six small public native case/mode paths and
two bad native-result rejects. Its copied public role files record six delivered
and two rejected local journal attempts. This is public/native control evidence,
not independent HE-key or private arithmetic evidence.

All 425 preceding runtime files, 66 company preservation files and six isolated
public/control libraries remain unchanged; the two additive files bring the
runtime inventory to 427. This return adds no HE key, CUDA/native build, large
timing, Lean proof, parameter approval, deployed TEE or originality verdict.

## Next dependency

The [build plan](paper-system-build-plan-after-roles-20261004.md) moves to R2:
complete the owner coordinator, independent public-process launch and the exact
execution freeze. Register sources, custody, private preparation/lifetimes,
setup/acquisition/update DAG, link overlap, initial state, deadlines and query
budgets before generating either actual HE key or executing private arithmetic.
The selected one-profile/two-key/three-size cap remains 18 blocks and 144
observations per implementation, split 48 calibration and 96 held-out. Resolve
the 540 standalone plus up to 180 prefetch remote-component encryptions explicitly.
Actual owner HE finish and process custody remain R2/R3 obligations; Q78
deployment/security and Q79 originality/paper are open.
