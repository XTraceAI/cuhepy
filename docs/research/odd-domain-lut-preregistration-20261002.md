# Q15/E89: full odd-message domain, negacyclic LUT and switching margin

2026-10-02. Recorded before implementation/result. Known TFHE LUT arithmetic
is a control, not a claimed novel primitive. E85's full eight-point antipodal
negative does not rule out full *odd* plaintext moduli.

For ring degree M and rotation modulus 2M, a test polynomial gives values
`L[r]` at 0≤r<M and `-L[r-M]` at M≤r<2M. Message h is located near
`r_h=round(2M*k*h/t) mod 2M`, with unit-map permutation k coprime to t.
If t is odd, doubling permutes residues mod t, so folded centers are
`round(M*j/t)` for all j. For M≥t they are distinct, with minimum cyclic
spacing floor(M/t). Arbitrary values can then be assigned, accounting for
the sign of each unfolded center. The ideal full-torus noise radius is
about 1/(4t), not ordinary message decoding's 1/(2t).

Independent finite test: every small message/permutation/allowed rotation
error and arbitrary output function; compare actual multiplication by X^-r
in Z_p[X]/(X^M+1) to table evaluation. Include even-domain incompatible
antipodes, insufficient M, an over-radius error and componentwise modulus
switching accumulated rounding. No programmable bootstrap is implemented.

Count actual odd t193/257/1153 cards and degree/rank choices against ordinary
shared PBS and generic CM controls. State allowed **integer** error from
the folded center grid, not a loose real radius. Include original unit
noise, gadget-key noise and componentwise switching to 2M; a hypothetical
64-bit torus intermediate does not remove that final rounding. Use the
worst-case prefix-secret L1 control and identify when no larger Q can make
that sufficient bound pass. A failed worst-case bound is not failure of
reviewed probabilistic/bias-corrected TFHE methods.

Only then consider higher-rank/lower-degree CM shapes. Charge field/rank,
key setup/regeneration/residency, noise and full proof/ID coverage. Known
large-precision/sign evaluation and alternative LUT/PBS controls remain
explicit alternatives; no prototype timing or security parameters approved.
Return to R6: advance an exact control, stop the unpriced precision shortcut,
and select the next complete interface question before Q6.
