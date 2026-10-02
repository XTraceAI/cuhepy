# Q20/E94: condition on the fixed owner index, sample fresh query errors

2026-10-02. Proposed finite follow-up before new code/results. E93 resolves
the empty original-q quarter budget and stops generic fresh-epoch composition
as a new mechanism. Its support source bound is dominated by error products.
Return to [R6](construction-selection-20261002.md) after this separate question.

For seeded owner encryption, let the fixed enrolled column phases be
`I_j=m_j+t*e_j`, with coefficient cap `F=floor(t/2)+t*eta`.
An adaptive plaintext query has centered coefficient cap `M=floor(t/2)`;
its independently sampled fresh centered-binomial errors are `E_j`.
The integer score phase is

`sum_j I_j * u_j + t*sum_j I_j * E_j`.

Condition on the entire prior history, original secret, fixed index errors
and newly pinned index/query message, before drawing the query errors. The
first term is bounded by `N*h*F*M`. Each coefficient of the second is a
linear sum of distinct fresh CBD variables with twice-variance proxy at most
`eta*t^2*N*h*F^2`. For at most K coefficient/query events and target kappa,
use the integer bound

`min(N*h*F^2, N*h*F*M + ceil_sqrt(eta*t^2*N*h*F^2*(kappa+ceil_log2(2K))))`.

This is known conditional MGF mathematics. It averages **only fresh query
errors**, not the reused index, public key, source secret, adaptive messages
or product noises. It is potentially a useful complete lifetime/source-bound
interface; no conference originality is accepted from this formula alone.

All original query/index dependencies must be pinned and authenticated.
Independent query error generation is an honest owner premise. A malicious
client that selects/reuses errors, post-error index selection, or unregistered
index updates is outside the lemma. Postselection of coefficients after the
query ciphertext is published is covered by all K permitted events. Replays
of the same original query are the same noise event, not independent trials.
Count every fresh generated query, including abandoned/retried ones.

Finite tasks:

1. State the conditional-history and accepted-release union lemma, including
   source plus target/PBS/proof failure budgets. Compare Spiral/YPIR conditional
   noise controls, the dependency-aware BGV paper and the heavy-tail critique.
   Their public-key/rescaling/heuristic settings are not silently ours.
2. Exhaust N2/t3/eta1 fixed supported index phases, all plaintext query/error
   supports, and exact CBD mass. Check direct integer ring phase versus the
   conditional decomposition. Use rational DP tails at larger N to make the
   test nontrivial. Preserve explicit revealed-error/post-error-index and
   repeated-error counterexamples; these are premise falsifiers, not attacks.
3. Implement a public integer policy/budget recomputation and a bounded
   volatile freshness ledger. It does not prove OS sampling, secret support,
   original scores, persistence, side channels or authorize decryption.
4. On all eight E93 geometries and lifetimes1/8/32/256/4096, recompute source
   bounds at original Q. Compare full support, conditional fresh-query bound
   and changed-Q controls. Include actual key/index regeneration flags,
   allocation of separate failure terms, and no claimed parameter assurance.
   Re-evaluate the strong known target-key deterministic/statistical degree
   controls with this source bound; no source-bound win is a measured PBS win.

Use kappa129 for the new source and each fresh target epoch, reporting their
sum explicitly. A single target epoch plus source costs at most 2^-128 in this
restricted arithmetic model; many target epochs need a summed or allocated
budget. Do not retroactively call E93's kappa128 a combined protocol guarantee.
Stop if ordering/provenance is invalid, the generic control already supplies
the proposed complete step, or unknown proof/security costs are being hidden.
Keep correct company controls and update the next research plan honestly.
