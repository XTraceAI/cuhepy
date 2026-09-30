# P03: backend and ciphertext-linear screening

2026-09-30. E42 and E47 are exact algebra/count screens; outer vLHE is not
implemented or certified. See the [matched author reproduction](baseline-reproduction.md).

The pinned EMVP profile uses plaintext padding 1,024, code length 1,292 and
76 response shares. BNTM uses length 1,024 and one share. Reducing private data
rank from 512 to 3 does not shrink these fixed code parameters: a single
query still costs 10,336 or 8,192 modeled bytes respectively. Four separately
encoded leaves pay that query floor four times. Response and index bytes remain
proportional to total rows under these unchanged profiles. Unsupported smaller
LPN/LSN fields or dimensions are not a valid optimization. Joint leaf encoding,
Protocol-3 recursion and preprocessing the author verifier are still open.

The E47 oracle constructs the actual signed negacyclic shifts of public
ciphertext coefficients as an F_Q matrix. For every tiny field input, matrix
evaluation equals independent integer-ring products. A negative control finds
`alpha(a+b mod t) != alpha(a)+alpha(b) mod Q`; full-Q residues cannot be replaced
with scores modulo t. Work caps precede literal matrix allocation.

For an R-reply N-degree index with F encrypted columns and W correction
coefficients, the literal operator has `2*R*N*W` entries, while the implicit
base index has `2*R*N*F`. Expansion is W/F, reaching 64 on the reproduced
Semeion profile and 32 on Mushroom. At Q32, those literal packed bodies would
be about 184 MiB and 128 MiB respectively, versus about 2.875 MiB and 4 MiB
for the base indices. The full-Q uncompressed output remains 131,072 bytes
before paying outer encryption, registration and proofs.

The outer plaintext arithmetic must return residues modulo the actual inner
Q. The reference ReinsPIRe examples' small plaintext modulus and database
norm parameters do not automatically support this matrix. Its definition also
allows registration to bind a malicious server to an admissible database;
our composition needs the **owner's approved** ciphertext matrix. Check honest
and admissible norm classes, setup, proof assumptions, full output and an
actually supported implicit operator before implementing the outer protocol.
[ReinsPIRe, Appendix A and Section 4](https://eprint.iacr.org/2026/1934).

E47 therefore remains a conditional alternate, with a substantial explicit
matrix/output obstacle. No token preparation, full inner response check or
parameter gate was removed. This is a useful early rejection of a naive
implementation, not an impossibility theorem for a structured outer protocol.
