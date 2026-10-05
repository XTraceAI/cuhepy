# Q76.5 completed bounded certificate and public client handoff

The [registration](native-shared-query-certificate-registration-20261004.json)
preceded the frozen [reference/toolchain](native-shared-query-certificate-preparation-return-20261004.json).
The [return](native-shared-query-certificate-return-20261004.json) and
[validation](native-shared-query-certificate-validation-20261004.json) now record
the completed bounded static handoff. This completes Q76's selected local
prototype/control package. Q77 is eligible for a separate registration;
complete-cost timings, real deployment/security and originality remain open.

## Implementation and result

- `experiments/bfv_search_lab/shared_query_certificate.py` independently
  reconstructs all selected geometry, prime/common-integer, graph/coverage,
  phase/terminal, placement, authority-premise and resource declarations. It
  imports no optimizer, HE arithmetic, native adapter or noise oracle. Strict
  bounded canonical JSON and full content comparison prevent a matching old
  digest from approving changed trusted context or a weaker statement.
- `experiments/bfv_search_lab/shared_query_client_context.py` authenticates a
  fixed canonical MessagePack descriptor and compares its exact separately
  trusted owner pin before payload parsing. It binds every original ordered ID,
  the logical revision, all three HE modes and the independent cache context.
  It reconstructs expected certificate digests locally and retains no full
  certificate, encrypted index or evaluation key. Its process-owned adapter
  prevents late acquisition from republishing an invalidated pin and rejects
  copy/pickle, closed use and fork use before acquiring an inherited lock.
- `proofs/shared_query/Model.lean` supplies twelve scoped kernel-checked
  theorems using the pinned official Lean 4.34.1 core/Std distribution.
  They cover closed selected guards, canonical digit reconstruction, score
  arithmetic and conditional representation/frame/state lemmas. CRT/NTT
  validity and trusted nonrollback execution remain explicit premises.
- `benchmarks/certificate_shared_query_lab.py` checks saved public declarations
  and component accounting. It imports/executes no HE/native evaluator and
  does not measure latency. It bridges 16 small and six source-scale cases
  to their three separate authenticated mode snapshots and the cache view.

The standalone final suite passes **252 tests** with **247 distinct bounded
metadata/context/ownership faults**, below the registered 256 cap. The retained
cohort passes **66 static case/mode combinations**. One fresh standard Ed25519
cohort signing object and two public unit-only signing contexts are used;
unit fixture bytes are reused between attempts. No new HE key, encryption,
decryption, native build/evaluation, symmetric key, CUDA run or timing panel
occurs. Earlier HE correctness and fault counts are referenced rather than
rerun or added to this metadata result.

At 32,768 rows the complete signed descriptor is **263,206 bytes**, including
262,144 bytes of ordered UInt64 IDs. At 16,384 it is 132,134 bytes, and at
8,224 it is 66,854 bytes. The complete HE enrollment is not imposed on the
online client. The [resource ledger](native-shared-query-resource-ledger-20261004.md)
separates owner setup, each link, resident preparation, scratch and live copies,
client provisioning and permitted cache acquisition/updates.

## Preserved failures and proof boundary

The first 250-case unit run had two failures caused by an overreaching test
premise: an opaque cache key/snapshot label with a newly trusted initial owner
pin need not be publicly related to an HE ciphertext. That relationship is an
honest-owner premise. The final tests check malformed labels and specific
original-pin rejection, and explicitly confirm valid independently provisioned
labels. The implementation did not acquire an invented public plaintext-
equivalence property to satisfy the test. The failed source, receipt, XML and
stdout remain preserved; overlapping invocations are not added.

The four actual Lean invocations include a failed CLI source-root attempt and
a failed finite-guard decidability attempt. The latter's diagnostic `sorryAx`
output is retained as a failed build. The accepted development/final source
uses no user axiom, admission or `native_decide`; the final twelve `#print axioms`
lines expose use of standard `propext`, `Quot.sound` and `Classical.choice` where
applicable. The closed selected guards and terminal value have no axioms.

One freeze preflight also detected duplicate fault IDs before test/cohort
execution. Its failed helper copy/receipt is preserved. Correcting catalogue
identifiers changed no scheme or guard. Execution freezes preserve the original
and final test versions; only the retained-cohort runner later gained an
explicit trusted standard-signing argument, allowing one in-memory context
without secret serialization. That first cohort attempt passed.

The [security/prior card](native-shared-query-security-feasibility-20261004.md)
separates all remaining premises. This is not a mechanized BGV-model validity
proof, C++/NTT refinement, RLWE/KDM reduction, private timing guarantee, secure
owner channel or deployed attestation. Public static validation conveys no
private release capability. No original main result is accepted from these
supporting engineering/proof results.

## Recorded execution and reproduction

The outer evidence directory is
`/home/pete/yavor-projects/xtrace-work/research-data/q76-certificate-20261004`.
It contains the frozen source copies, all four model attempts, both unit
attempts, the complete fault catalogue, 66 certificates, 22 compact descriptors
and owner pins, resource cross-checks and helper/command receipts. Original
company sources/libraries, the 415 preceding runtime files, six isolated native
libraries, main/staging refs and 120-record literature registry are unchanged.

The recorded standalone unit command, from the research checkout, was:

```bash
.venv/bin/python -m pytest -q -ra \
  experiments/bfv_search_lab/test_shared_query_certificate.py \
  experiments/bfv_search_lab/test_shared_query_client_context.py \
  --junitxml=/path/to/new-evidence/tests.xml
```

The model command used the exact copied source inside each recorded invocation
directory, with that directory as cwd, and explicit `.olean` output. This
avoids the Lean CLI source-root error. Use the pinned workspace executable
`../research-tools/lean-4.34.1-linux/bin/lean`, not an unpinned global version.

The retained metadata runner's arguments are `--workspace`, `--output` and
`--freeze`; recorded execution uses `execution-freeze-3.json`. It refuses to
overwrite output and checks its absolute input/source pins before processing.
Reproduction must preserve the old outputs and identify its own cohort/paths.
A fresh standard signer reproduces semantics and sizes, not the original
signature bytes or an archived HE/cache private key. The registered run is
complete and is not silently extended by a reproduction command.

## Return to the finite plan

Register Q77's complete-cost local prototype cohort next: exact source/method/
key budgets, paid setup/device/update/arrival trace, six calibration blocks,
frozen compatible policies and twelve held-out blocks. Include strongest
prepared replay and allowed mutable cache/prefetch, and record the unknown
randomized prior adapter as unknown. Expose stage peaks and private/native
assurance limitations. Real attestation/private release/parameter assurance
remain Q78; the specific operating-region originality and paper decision remain
Q79. There is no new unbounded preliminary experiment queue.
