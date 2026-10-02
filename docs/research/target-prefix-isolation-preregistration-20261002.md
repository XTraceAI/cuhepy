# E96 follow-up: hard worker isolation after the soft timer failed

2026-10-02. Keep the first E96 result and runner unchanged. Its Sage signal
timer was swallowed inside a symbolic C call: one dual-hybrid call returned
after16.64 seconds despite the nominal10-second budget, while three timed out.
This affects the declared execution cap/completeness, not the already returned
sub128-bit p512/p1024 costs. Preserve the warning and all missing results.

Use the same pinned estimator/context/secret/error/sample/model/functions in
separate forked workers, with parent-enforced10-second joins and termination
of ONLY this runner's child processes. Record timeouts, worker status and all
finite costs. No extra attack or parameter is added. Run an isolated initial/
repeat pair; compare every model/context/source and returned finite cost field,
excluding estimator execution time/UTC/command. Preserve any availability
differences; do not claim failed calls were repeated successfully. Compare
finite overlapping costs with the retained first soft-timer run.

Then run the registered E96 coupled precision screen, including the exact
public row equations and all p512/1024/2048/4096/full-N controls when supported.
Independently reproduce all1,600 old E95 degree points before expanding only
the new support/degree grid to powers2^11..2^22. This expanded grid is declared
before inspection of those new precision results. Above128 in the selected
classical estimates is not approval; unknown quantum/other attacks/structured
and key-graph/private/proof/PBS assurance remain open.
