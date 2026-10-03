# Prospective exact-union refinement for the fixed toy census

This new symbolic refinement is proposed after the E122 discriminator and
before any E123 census activation. It changes no E122 source, contract or
result. There is no new root, orbit, mass or secret experiment here. The
argument uses the known determinant/nullity control and elementary counting;
no originality claim follows. Independent static review is required before
including it in E123's frozen contract.

Keep precisely the registered degree16, prime97 and uniform integer ternary
law. For nonzero S, the integral negacyclic multiplication determinant is
nonzero: Q[X]/(X^16+1) is a field and deg S<16. Each matrix column is a
signed coefficient rotation, so Hadamard gives

    0 < |det(S)| <= ||S||_2^16 <= 16^8.

The prime97 fully splits X^16+1. If k evaluation roots vanish, the matrix
modulo97 has nullity k. Its integral Smith factors therefore include at
least k multiples of97, and 97^k divides the nonzero determinant. But

    97^5 > 96^5 = 3^5 * 2^25 > 2^32 = 16^8.

Consequently every NONZERO S has k<=4. This bound excludes the zero vector,
whose determinant is zero and whose k is16. It supplies no small-defect
certificate at the actual source dimension/primes.

For all four-root subsets T let C_T be their exact raw ternary zero-event
counts. Write Z4=sum_T C_T. The ordinary factorial moment is

    E[choose(k,4)] = Z4 / 3^16.

Here every nonzero vector contributes either zero or one to Z4, because
k<=4. The zero vector contributes choose(16,4)=1820. Therefore, ONLY after
complete authenticated census coverage,

    Pr(k>=4) = (Z4-1819) / 3^16
             = (1 + sum_T (C_T-1)) / 3^16.

In the signed-Galois orbit representation, replace the last sum by
sum_orbits |orbit|*(C_representative-1). The zero vector is added once,
not once per orbit or epoch query. The signed-monomial control additionally
requires every C_T to be 1 modulo32; it does not supply root-set disjointness
by itself.

The distinction between a factorial moment and a union is retained in
general. This special equality needs the reviewed nonzero k<=4 lemma and
all classes, with exact input/provenance and integer arithmetic. A partial
census may report its partial sums but cannot claim the complete event
probability. No sampler conditioning, source-prime extrapolation, deployment
assurance or new numerical correctness budget follows. The prospective
E123 contract must freeze this refinement and its generic control explicitly;
all equally informed controls receive it.

Independent static review passed before E123 activation: external
`norm-union-symbolic-review.md`, SHA256
`e509e66d01c8c2791cf49e7a30caa6738aa9c057aaab9f9a59013a3ff72ab11e`.
The reviewed argument remains a known finite control.
