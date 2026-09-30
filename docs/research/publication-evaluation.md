# P11 execution artifact: scoped pilots, not the final paper evaluation

2026-09-30. The [progress log](publication-progress.md),
[work packages](publication-work-packages.json),
[claims ledger](paper-claims.md) and [plan](publication-research-plan.md)
govern interpretation and next execution. All company/deliverable code remains
homemade; pinned author artifacts/estimator are reference baselines/tools.

## Retention and identity

The protected E01–E40 commit is `02e06c0` and the initial plan `00a6362`.
Executed research is retained in `e52df4b`, `d2c198d`, `7f2962b`, `f8a8290`,
`cf88c1b`, `4cff0ed`, `7058a47` and `f19af00`. Company/production `src/` has no
diff from the protected checkpoint. These experiments are on
`experiment/creative-search-algebra`, not main or staging.

[The machine-readable execution manifest](publication-execution-manifest.json)
retains **29 completed raw runs** and **64 exact source versions**. Verification
finds no mismatches. A recorded run HEAD can predate then-uncommitted source;
the source SHA is matched to a historical committed blob rather than silently
assuming HEAD reproduces it. Two native binaries and one generated external
Cargo lock are explicitly workspace-cache dependencies, not Git-bundle content.
Their bytes are additionally archived beside the final checkpoint bundle.

Ignored `.partial.json` files, preliminary codec-scope runs not selected for
retention, fixture caches and external checkouts are not claimed to be final
results. Retained historical runs remain immutable even when a later scope
correction supersedes their headline. In particular, four-edit lifetime runs
excluded affine discovery; the complete eight-edit run includes it.

Run identity verification from the research checkout:

```bash
.venv/bin/python benchmarks/publication_artifact_manifest.py \
  --verify docs/research/publication-execution-manifest.json
```

Public UCI fixtures are pinned by raw/source hashes in the reports; caches are
in `../research-data/uci-20260927`. Author clones are separate:
`secure-vector-search` at `519148cf3fddc11277a111774ca8cb92d891e0e3`,
`lattice-estimator` at `53da5982597709ba0fdf94ea37a84d822310fd84` under
`../research-data/reference-artifacts-20260930`. Rust 1.98.1 overrides the
author-requested 1.95.0; source/lock/binary metadata records this distinction.
SDK Python is 3.12, Sage 10.9 uses Python 3.14; the latter needs `/opt/sage/bin/python`
in this environment. The external matrix artifact's 78 CPU tests passed.

## Reproduction entry points

| Subcomponent | Entry point / required inputs | Interpretation |
|---|---|---|
| Exact finite static oracle/DP | `benchmarks/representation_oracle_lab.py` | Complete tiny grammar/counts and arithmetic references |
| External exact EMVP/BNTM modes | `benchmarks/run_secure_vector_reference.py`; pinned clone + adapter/Cargo locks + exact fixture inputs | Partial author-mode reproduction, full-score adaptation costs distinct |
| Frozen-map lifecycle | `benchmarks/representation_lifecycle_lab.py`; `--help` selects rows/rank/pool/updates/consumption | Complete enrollment/discovery/pool/update/all-token CPU stage sums |
| Public-component recipe | `benchmarks/component_recipe_lab.py`; public cache/dataset | Measured work/state/body tradeoff; bandwidth crossover is a model |
| Factory comparison | `benchmarks/ciphertext_factory_lab.py --dataset synthetic128 --vectorized-control` | Fresh vectorized plaintext beats encrypted rerandomization in strongest pilot |
| Compact local caches | `benchmarks/coordinate_cache_lab.py`; public cache/dataset or synthetic128 | Every score/ID/tie exact; compressed/state bodies are not RSS |
| Full-ring/layout/global controls | `benchmarks/score_layout_lab.py`; public cache/dataset, `--representations global_raw global_affine --vectorized-owner` | Native/GMP/full-phase/gate checks; research-only parameters |
| Lifetime catalog DP | `benchmarks/lifetime_planner_lab.py` | Hindsight count model/exhaustive agreement, not calibrated runtime gain |
| Parameter screen | `benchmarks/bgv_parameter_estimation.py`; Sage + pinned estimator | Heuristic costs; missing/time-limited attacks retained, no assurance |

These scripts accept `--json-out` paths; use new filenames to preserve old
observations. Reconstruct/build isolated native research extensions using their
retained Makefiles and the matching SDK Python. Exact binary hashes are an
environment receipt, not a promise that another compiler emits identical bytes.

## Verification and limits

The related **156 tests pass**: finite static/lifetime oracles and planners,
backend/carry/partial-subring oracles, frozen-map repair, component recipes,
factory/cache controls, all-row capacities, native/GMP encryption, full-vector
checks, noise certificates and seed-composition negatives. New Python modules
pass the repository lint rules when explicitly included. Manifest verification
passes separately. These are scoped research checks, not whole-repository CI,
hardware attestation, a security proof or GPU/private-backend certification.

Publication-size repetitions, confidence intervals/p95, realistic service RTT,
CPU contention/RSS/energy, strongest recursive/low-state baselines, held-out
update policies, insertion/deletion and durable anti-rollback remain outside
this tranche. No new GPU kernel or measurement is implied by CPU results.
Use source/parameter/metric/trust labels from each report; do not combine
server-only, modeled network, changed-output or proof-disabled numbers into
an end-to-end claim. Gates A–D and full work-package acceptance remain open.
