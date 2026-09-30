# P11 execution artifact: scoped pilots, not the final paper evaluation

2026-09-30. The [progress log](publication-progress.md),
[work packages](publication-work-packages.json),
[claims ledger](paper-claims.md) and [plan](publication-research-plan.md)
govern interpretation and next execution. All company/deliverable code remains
homemade; pinned author artifacts/estimator are reference baselines/tools.

## Retention and identity

The protected E01–E40 commit is `02e06c0` and the initial plan `00a6362`.
Initial executed research is retained in `e52df4b`, `d2c198d`, `7f2962b`, `f8a8290`,
`cf88c1b`, `4cff0ed`, `7058a47` and `f19af00`. Company/production `src/` has no
diff from the protected checkpoint. These experiments are on
`experiment/creative-search-algebra`, not main or staging.
The prior immutable `checkpoint/publication-execution-2026-09-30` at `20d00c6`
retains its original29-run manifest. The current execution adds E54–E65,
original-author controls, explicit permitted-cache baselines and negative
discriminators through `f1e8afc`. A new checkpoint is separate; old tags/raws
are not replaced.

[The machine-readable execution manifest](publication-execution-manifest.json)
retains **59 completed raw runs** and **181 exact source versions**. Verification
finds no mismatches. A recorded run HEAD can predate then-uncommitted source;
the source SHA is matched to a historical committed blob rather than silently
assuming HEAD reproduces it. There are118 historical Git blobs and63 explicitly
separate workspace-cache dependencies: native binaries, original-author source/
libraries and two adapter binary versions, plus the external generated Cargo
lock. These dependencies are archived beside the new checkpoint bundle; they
are not misrepresented as SDK Git content.

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

Public UCI fixtures are pinned by raw/source hashes in the reports; earlier
caches are in `../research-data/uci-20260927`, with Connect-4 in
`../research-data/uci-connect4-20260930`. Author clones are separate:
`secure-vector-search` at `519148cf3fddc11277a111774ca8cb92d891e0e3`,
`lattice-estimator` at `53da5982597709ba0fdf94ea37a84d822310fd84` under
`../research-data/reference-artifacts-20260930`. Rust 1.98.1 overrides the
author-requested 1.95.0; source/lock/binary metadata records this distinction.
SDK Python is 3.12, Sage 10.9 uses Python 3.14; the latter needs `/opt/sage/bin/python`
in this environment. The external matrix artifact's 78 CPU tests passed.
Original EMVP uses the unchanged Go/C++ library at
`856762f5925fe873bb5cbc0401ceb5a44568efa9`, an isolated Go1.23.12 toolchain,
NTL/GMP/OpenSSL and an OS-thread-pinned adapter. Three own adapter tests and
three selected upstream tests passed; an upstream commented score assertion
and the retained unpinned failure limit what those tests alone establish.

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
| Exact base-revision frontier | `benchmarks/overlay_lifetime_lab.py` | Finite hindsight exceptions/rebase model |
| Original EMVP | `benchmarks/emvp_author_lab.py`; pinned original clone, Go/C++ build/cache and public fixtures | Original cached/key-only modes plus separate private gate; entropy/parameter scope distinct |
| Private delta and selective tile lifecycle | `benchmarks/client_delta_lifecycle_lab.py`; complete configured pool/updates and `--methods` | Known controls; localized/dispersed and vectorized fresh costs retained |
| Calibrated causal policy | `benchmarks/lifetime_price_lab.py`, `benchmarks/client_delta_lifecycle_lab.py --price-file … --methods … priced_policy` | Calibration plus unseen synthetic edits; all16 decisions keep deltas, no useful policy result |
| Authenticated full cache | `benchmarks/cache_snapshot_lab.py`; public fixture/cache/compression efforts | Owner/client cold acquisition and exact local queries, no sockets/RSS |
| Private mutable rows | `benchmarks/client_buffer_lifecycle_lab.py` | Edits/inserts/deletes compared with permitted mutable cache; no encrypted-base migration |
| Cold/ready model | `benchmarks/cache_remote_cost_lab.py` | Separate modeled bandwidth panels; favorable ready-remote omissions explicit |
| Larger real control | `benchmarks/score_layout_lab.py --dataset connect4 --max-index-rows 32768 --cache-control`; pinned fixture path | Distinct real prefix, matched HE/cache scores and known global-affine effect |
| Conditional soundness oracle | `benchmarks/soundness_lifetime_lab.py` | Exact684 toy rejection paths/reset negative, not a full protocol proof |
| Single-leaf selected decoding | `benchmarks/decryption_projection_lab.py` | Actual public-fixture bodies, separate projected gate and dedicated decoder |
| Split/legacy support | `benchmarks/decryption_support_lab.py`, `benchmarks/supported_decoder_lab.py` | Complete tiny decoder matrices and112 exact native encrypted queries |
| Static support planner | `benchmarks/support_planner_lab.py --random-cases 32 --seed 67501` | Exhaustive static allocations; simple one-row-refined controls match every tested frontier |
| Parameter screen | `benchmarks/bgv_parameter_estimation.py`; Sage + pinned estimator | Heuristic costs; missing/time-limited attacks retained, no assurance |

These scripts accept `--json-out` paths; use new filenames to preserve old
observations. Reconstruct/build isolated native research extensions using their
retained Makefiles and the matching SDK Python. Exact binary hashes are an
environment receipt, not a promise that another compiler emits identical bytes.

## Verification and limits

The related **205 tests in30 files pass**: finite static/lifetime oracles and planners,
backend/carry/partial-subring oracles, frozen-map repair, component recipes,
factory/cache controls, all-row capacities, native/GMP encryption, full-vector
checks, noise certificates and seed-composition negatives, plus cache AEAD,
arbitrary private buffers, global attempt accounting, supported decoders and
support-allocation/refinement negatives. Explicit lint passes on46 Python paths
changed since the earlier execution checkpoint. Manifest verification
passes separately. The [validation receipt](publication-validation-20260930.json)
retains the exact selected test command and changed-source hashes.
These are scoped research checks, not whole-repository CI,
hardware attestation, a security proof or GPU/private-backend certification.

Publication-size repetitions, confidence intervals/p95, realistic service RTT,
CPU contention/RSS/energy, strongest recursive/low-state baselines, held-out
useful held-out update policies, general encrypted-base insertion/deletion/
migration and durable anti-rollback remain outside
this tranche. No new GPU kernel or measurement is implied by CPU results.
Use source/parameter/metric/trust labels from each report; do not combine
server-only, modeled network, changed-output or proof-disabled numbers into
an end-to-end claim. Gates A–D and full work-package acceptance remain open.

Known private deltas/selected tiles improve some company controls, while
stronger vectorized fresh preparation reverses the earlier sparse-repair win.
Original EMVP is faster CPU with larger replies and a distinct assurance
profile. Permitted caches remain compelling after actual acquisition costs
and larger real data. The new supported decoder is exact in its stated scope;
E65's stronger simple controls reject a new static-optimizer contribution.
See [the results ledger](paper-claims.md) and [current plan](publication-research-plan.md)
before scheduling additional implementation.
