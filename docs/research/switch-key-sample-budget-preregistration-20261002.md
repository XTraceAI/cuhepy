# E98 follow-up: enforce the original sample budget

2026-10-02, parent `ae79347`. This is a newly registered applicability check,
after both immutable E98 cost cohorts, before its audit/replacement runs.
Keep the original raw outputs, their 12 raw below128 flags and all sources.

Source audit of unchanged lattice-estimator revision53da598 shows
`estimator/lwe.py:13` aliases `LWE.dual_hybrid` to `matzov`. In
`estimator/lwe_dual.py:583–584`, its `cost` defaults original sample count m
to `params.n`; the calling optimizer at lines660–672 omits m. Every registered
E98 setup-only sample budget is smaller than that dimension. The printed input
`params.m` alone therefore does not establish applicability of this call.
No sample-amplification theorem with the same noise law was supplied.

## Exact applicability rule and replacement control

Audit each of the two original cohorts, retaining all outputs. For finite
MATZOV default results, reject applicability when returned original m exceeds
the available disjoint setup samples. For the existing primal calls check their
returned lattice d is at most n+m+1; for the existing ordinary dual check
returned original m<=available. This checks sample budgets in these unchanged
short-ternary/large-error contexts, which normalize without swapping secret/error.
It is not a full algorithm/cost-model audit, and nonfinite is never approval.

Then call **`estimator.lwe_dual.dual_hybrid`**, the distinct finite-sample DH
routine. Its `dual_reduce` explicitly clamps original m to `params.m`
(line88); `cost` returns that original count (line176). Use its default
opt_step8, exhaustive-search solver, fft=False and no MITM, with RC.MATZOV
classical reduction costs, same exact Xe summary, contexts, external source,
Sage, beta configuration and parent-enforced10-second budget. This is a
different named heuristic, not a patch to the author artifact or a Gaussian
replacement. Its internal reduced-error heuristic remains disclosed.

Two fresh immutable serial cohorts,44 calls each, preserve failures/timeouts.
Compare context/source/model and every overlapping finite returned cost; report
availability differences. Independently check each finite DH's original m
against the actual sample count. A finite budget mismatch is inapplicable, not
a real attack estimate for this transcript. Missing/unsupported stays open.

Reclassify the **qualified** profile minimum using only applicable original
primal/ordinary-dual calls and applicable replacement DH calls. Do not silently
erase original raw minima or claim the four original heuristics were equivalent.
Any qualified sub128 estimate stops that profile under the named models.
Others are unapproved, with distribution/structured/quantum/key-graph/protocol/
private gates unchanged. The smaller-ring512 conclusion is presently open;
large-ring512 already has sub128 applicable primal/ordinary-dual results.

Return to R6 after this tool-model prerequisite. A method exploiting gaps,
overlapping rows or the full ring transcript is not modeled by this subset.
There is no lattice reduction, key recovery, customer data or production change.
