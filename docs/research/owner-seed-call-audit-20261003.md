# Q49/E124 supporting owner seed-call source audit

The proposed owner-window compression calculation remains unactivated. Its
target is the experimental **BGV OwnerClient/seeded_bgv** path, and current
source does not enforce a total honest seed-input or enrollment lifetime
budget. `A_other` is unknown; it is not zero. This is a read-only code finding,
not a measured attack or a statement about production Paillier.

The [full audit](../../../research-data/joint-root-census-20261003/owner-seed-call-audit/audit.md)
and [final baseline scope](../../../research-data/joint-root-census-20261003/owner-seed-call-audit/baseline-scope-addendum.md)
retain exact code locations and source hashes. The final
[inventory](../../../research-data/joint-root-census-20261003/owner-seed-call-audit/static-source-inventory-baseline.json)
covers534 immutable tracked source/evidence files and528 static references;
those are metadata counts, not a lifetime budget. The three mutable census
files are excluded. No repository module, HE operation, seed/key generation,
probability, test, benchmark or native build was executed by this audit.

## Exact domain and permitted call semantics

[seeded_bgv.py](../../experiments/bfv_search_lab/seeded_bgv.py) and
[owner_bgv.py](../../experiments/bfv_search_lab/owner_bgv.py) use the same
`cuhepy-lab-bgv-seeded-query-v1 || key_id32 || seed32` SHAKE frame. Both
encryption factories generate their own fresh OS seed after validating the
message shape. Fresh, independent OS entropy remains a model assumption.
Direct expansion/sampler helpers accept an existing caller-supplied seed.
Repeated expansion repeats an oracle input; it does not create a new
independent uniform mask.

Owner enrollment, queries, cached-answer encryption, rerandomizers, correction
polynomials, updates and rebases can all create inputs in this domain. Native
private multiplication uses the already sampled mask and is not another seed
draw. Key and evaluation-key setup use OS sampling rather than this frame.
[BFV QueryFactory](../../experiments/bfv_search_lab/query.py) uses a different
literal domain and must not be added to this particular collision budget.

The current frame has no role/epoch/attempt field. Local factory and attested
client limits do not establish a global total across direct helpers, new
instances, failed attempts, updates, reenrollment, restarts and rollback.
Static calls are not proof that a deployment uses every helper; excluding
helpers requires an explicit closed API/key-isolation contract.

## Index-origin mismatch remains explicit

The historical [BGV owner pipeline](../../benchmarks/bgv_owner_pipeline.py)
publicly encrypts its index while using owner-seeded online queries. The
public-key phase contains the public-key error/product terms. It cannot be
relabeled as the hypothetical fresh owner phase `M+tE`. An optional research
owner-index path exists, but the typed Q42 enrollment/lifecycle contract is
unimplemented, and drop87 still fails the existing metadata admission guards.
This audit changes no source, sampler, default guard or encrypted index.

## Next supporting engineering requirement

Before Q49 numerical GO, specify and enforce—or explicitly scope as model
assumptions—a complete owner-origin, key/framing and lifetime contract. Reserve
total polynomial budgets before seed generation; charge failures, retries,
abandoned attempts, auxiliary encryptions, updates/rebases and epochs. Cover
concurrency, fork/restart/rollback and untracked helper access. State the
honest/external oracle-address convention and the complete finite call budget.
Changing the framing requires a versioned protocol and new source review.

Concrete SHAKE, OS entropy, authentication, private arithmetic/side channels,
parameter security and actual lifecycle assurance remain separate obligations.
A source inventory supplies neither their failure terms nor a security level.
The [owner-window plan](owner-window-consequence-plan-20261003.md) remains a
known supporting control; the [research queue](publication-work-packages.json)
records only this completed source-audit component.
