# Validation and preservation of the Q71 component return

The combined current research suite passes **186 tests** using the retained
homemade propagated-gadget backend and the new isolated wire kernel. Ruff check
and format check pass for all ten new Python files. These are scoped regression
results; overlapping development runs are not added to the count and this is
not a new performance measurement or independent encrypted cohort.

The exact commands, environment overrides, logs, binary hashes and 54 pinned
source files are retained in
`../research-data/gadget-cut-fusion-20261004/validation/`. The final source
archive agrees with its start receipt and the sources stayed unchanged during
validation. The [results](gadget-cut-fusion-results-20261004.md) distinguish
the repeated retained-fixture adapters, large structural models, two fresh toy
RNS key contexts and reused wire-parser cohort.

Both new native libraries built with
`-O3 -std=c++17 -Wall -Wextra -Werror -fPIC -shared` and GMP. They use the
repository's own NTT headers and link no SEAL. Post-build receipts in `native/`
and `native-wire/` pin their different executed source archives, headers,
compiler-version capture, logs, binary sizes/hashes and linkage. The first
48,280-byte library is preserved; the second is 61,632 bytes. This records
tracked compilation inputs, not a complete compiler/system-header/runtime
closure or a claim that both versions were rebuilt from the final wrapper.

The final preservation audit establishes:

- All 54 earlier `src/` files and all 12 delivered shared libraries are byte
  exact. No production implementation or earlier experimental source changed.
- Of 1,469 earlier tracked files, 1,465 are unchanged. The only four changes
  prepend current pointers to historical plan/progress documents; every earlier
  body remains byte exact.
- All 471 previous evidence files and the previous checkpoint manifest remain
  byte exact. All ten executed-source archives match their own start receipts,
  including the failed controls reader. Source versions differ across runs and
  are compared to those receipts, not silently substituted with current code.
- All 784 recorded input-file receipts and 98 native public-context/trace/frame/
  body output receipts match their recorded sizes and hashes. The separately
  pinned current validation sources and both backend binaries also match.
- Main remains `0f8522e449d00622e10f4111ac8eb89d52ca577b`; staging remains
  `eb96aa1f79a92d6b6f0c1f6389d3daadff5546be`.

The first controls reader failed before any completed output on an old ledger
field name. Its source/start/log/failure are retained with the registered retry.
The retry corrects `index-sum` update dependencies in a separate addendum to
448 old resource graphs. Every other resource field remains exact and old raw
screens are untouched. Development test/lint corrections are not independent
success cohorts: a test's canonical-plan fixture was corrected, unused imports
were removed, and kernel ownership regressions were added before final scoped
validation. No company algorithm changed.

These checks support reproducibility and the public experimental arithmetic
component. They do not certify production parameters, private side channels,
attestation, complete protected admission, an end-to-end benefit or originality.
The [conditional argument](gadget-cut-native-kernel-assurance-20261004.md) and
[next construction gate](gadget-cut-native-controller-plan-20261004.md) state
those remaining obligations explicitly.
