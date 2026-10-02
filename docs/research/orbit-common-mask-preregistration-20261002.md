# Q14/E88: original-ring orbit keys versus generic common-mask selection

2026-10-02. Recorded before its bounded oracle/count. E87's switches are known
controls; their compact authenticated-selection gap remains open. This is a
new question, not restarting a stopped fingerprint/digit shortcut.

## Hypothesis and closest difference

For coefficient phase `C0+C1*S+C2*S²`, fix the single common mask
`a = coefficients(C1)||coefficients(C2)` (omit C2 for two components).
Slot k's secret is the signed extraction row of S and S². Its body is C0[k].
This view should reproduce every original coefficient phase **without** a
packing key, rounding or extra bytes. These slot keys are related signed
orbits, not independent Matrix-LWE secrets. The inverse public view simply
restores C0/C1/C2, so standalone privacy is conditional on original encryption
and valid evaluation; it does not establish auxiliary-key or feedback security.

The downloaded [common-mask paper](https://eprint.iacr.org/2025/2112.pdf)
already defines CM formats, operations, packing and costs. Our proposed
research difference would be exploiting the **original orbit key structure**
to share authenticated nonlinear selection keys/work beyond its general CM
and standard packed controls. The view identity itself is known ring algebra.

## One finite oracle and paid return

1. Independently compare all N=2/Q=3 two/three-component phases, source keys
   and score positions; also seeded N4/8/16 cases. Round-trip every component.
   Test block start d by signed rotating common masks and reusing the same
   canonical slot-key rows. After a known packed partial-key switch, the
   public union support for width w is min(N,D+w-1), for prefix dimension D.
   Direct S² has at most min(N,2D-1) prefix support before that orbit union;
   its secret values are not automatically binary/ternary.
2. Exhaust all tiny ternary source keys and count the joint orbit law, versus
   independent per-slot secrets. Demonstrate why independent-CM parameter/
   reduction claims cannot silently be applied to that different law.
3. A compact ring operation is negacirculant and commutes with the signed
   shift T. Enumerate every binary slot diagonal for N2/4/8, test `[D,T]`,
   and compare actual `D*v` to a proposed one-ring-multiplication surrogate
   over the full admitted toy input domain. Basis density is not distance.
   Test the whole binary diagonal space, not only unit errors.
4. Test the effect of same-mask, same-secret reuse as a **negative**; our
   different orbit secrets must not be replaced by one repeated secret.
5. Use existing E72 geometries to count original common masks, orbit secret
   descriptions versus full matrices, conventional CM packing/BSK formats
   and scalar/PBS/coverage work. Pay signed/ternary gates and S² handling.
   Include the stronger ordinary *shared* PBS key across all extracted
   scalar samples, not an artificially separate key per score/block.
   Count common-mask Table 7 seeded/unseeded forms and Appendix C.1's
   compact-key/regeneration control; regeneration/residency is not free.

Stop a literal free-CM-PBS recipe if nonconstant slot diagonals leave the ring
algebra, independent-key assumptions fail or full auxiliary keys erase the
advantage. Do not claim all structured/matrix/block methods impossible.
If a new closed, cheaper *complete* authenticated relation survives, specify
the actual evaluator/proof/selector and its conditional lemmas before Q6.
Otherwise retain the exact orbit view as a control and select a different
bounded question at R6. No performance timing or production assurance here.
