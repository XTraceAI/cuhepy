# Symbolic signed-monomial count control

Derived before E122's scientific run; no root, orbit inventory, mass or witness
was computed for this card. This is an ordinary symmetry control, with no
originality claim. It does not alter the frozen E122 contract or its stopping
rule. A separate static mathematical review is retained in the new cache.

Let N be a power of two, and consider all integer coefficient vectors
S in {-1,0,1}^N. Multiplication by X modulo X^N+1 shifts coefficients and
negates the wrapped coefficient. Its powers form a group of order 2N,
preserve this finite sample space and its uniform law, and fix zero.

Every nonzero vector has an orbit of exactly 2N distinct integer vectors.
Indeed, Q[X]/(X^N+1) is a field because X^N+1 is the cyclotomic polynomial
Phi_(2N). If X^h S=S for 0<h<2N, then (X^h-1)S=0 in that field. The class
of X has exact multiplicative order 2N, and the class of nonzero S is
nonzero. This contradicts the absence of zero divisors. In particular, the
shift by N sends S to -S; it is not an additional independent factor.

For any fixed set T of roots of X^N+1 in a finite field, multiplication by
X^h preserves the event that S vanishes at every root: each root is nonzero,
so evaluations are multiplied by a nonzero scalar. The event therefore
contains zero and a disjoint union of free nonzero signed-monomial orbits.
Its exact number of raw ternary vectors satisfies

    C_T = 1 + 2N*k_T,  k_T a nonnegative integer.

For the registered degree16 law, any nonzero event has count at least 33,
and every count is 1 modulo 32. This is a symbolic constraint, not an observed
mass. The probability denominator stays 3^16; the zero vector is included
once. The result concerns integer ternary vectors, which also inject into
the registered odd field since q>2.

This action preserves a root set rather than moving it. It grants no new
root-set orbit reduction, arbitrary additive exponent action, root-event
independence or disjointness between different T. The signed odd-Galois
orbit partition in E122 remains a separate symmetry. Nor does count
granularity give a useful actual-prime probability bound by itself. Any
later use in a census or numerical certificate needs its own frozen scope;
known methods and equally informed generic controls receive the same fact.
