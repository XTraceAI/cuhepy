# Q13/E87: proof-carrying batched score extraction and key switching

2026-10-02. **Proposed, not implemented.** E86 supplies a correct known public
BGV unit converter. The next candidate shares extraction/key-switch arithmetic
and its authentication across a packed score batch. No novelty is asserted.

## Specify and compare before coding

For plus-sign phase `C0+C1*S+C2*S²`, coefficient k's extracted masks are signed
rotations of each polynomial Cj. Let `d_l(x)` be an exact balanced gadget
decomposition of the centered representative modulo odd Q with odd radix r,
enough levels, and `d_l(-x)=-d_l(x)`. This symmetry must be proved including
zero, endpoints and carries; ordinary truncated binary decomposition cannot
be assumed to have it.

Let `K[j,l]` be an ordinary scalar-LWE encryption, under a supported target
key u, of `r^l*S[j]`; include a separate S² family for direct C2. Use the
repository's plus-sign convention consistently. The literal key switch sums
each extracted digit against these public key ciphertexts. For each target
mask/body coordinate v, regard the j-indexed key entries as a polynomial
`K_l,v(X)`. For every k simultaneously, those sums should equal coefficient k
of `sum_l d_l(C1(X))*K_l,v(X)` in the negacyclic ring, plus the C2 family.
C0 enters only the body. This is an exact public convolution identity, not a
new encryption scheme; retain the ordinary switch's noise, dimensions, keys
and message permutation. A scalar-key polynomial must not be represented as
a normally distributed ring secret without its actual security argument.

The **candidate new step** is one complete authenticated relation for this
shared family, rather than materializing/certifying each independently. Bind
owner-approved original components/RNS limbs, actual digit decomposition,
auxiliary keys/epoch, all required score positions, and the downstream public
PBS/selector trace. The server's witness is public evaluator arithmetic; the
secret key/decoded scores are not server witnesses. Generic FFT switching or
a quotient witness alone does not pass the mechanism gate.

Closest controls to read before declaring a difference:

- [Faster Secret Keys for (T)FHE](https://eprint.iacr.org/2023/979), section 3.3:
  FFT LWE switching via inverse extraction, partial GLWE keys and extraction.
- [HERMES](https://eprint.iacr.org/2023/1244): optimized column/MLWE/ring packing
  and key-memory tradeoffs. Packing in the opposite direction must be identified.
- CHIMERA functional switching; ordinary once-packed relinearization then
  extraction; supported batched/streamed scalar switches. Pay every key scan.
- Existing E70–E72 polynomial/quotient and E76 private-M/EMVP controls for
  authentication; E83's full-error and row-access negatives.
- HasteBoots and full known key-value selection for proof/PBS/coverage; full-score
  release and authenticated raw/compressed caches for the same deployment.
- [Scheme-switching hardness](https://eprint.iacr.org/2023/988): targeted
  introduction and reduction statements were read. It concerns general
  SIMD CKKS/exact conversion and comparisons, rather than forbidding the
  known BGV/BFV unit map. State why any bounded-score improvement avoids its
  stronger/general function premises; do not promise free general comparison.

The first two papers are recorded as leads, not full proof audits or reproduced
artifacts. Download/hash and targeted-read the algorithm/noise/key-size passages
as the first action of this packet. Search for equivalent batched convolution
switches and authenticated versions; author implementations remain controls.

## One bounded oracle session

1. Independently implement exact centered odd-radix decomposition and literal
   scalar switching. Exhaust all small Q/r residues, signed extraction indices,
   two/three-component families and independently generated toy key errors.
2. Compare every output mask/body with schoolbook convolution; compare decoded
   phase against the original message plus the explicit accumulated noise.
   Include odd-radix and known binary/approximate-decomposition controls.
3. Inject omitted components/limbs/digits/indices, swapped auxiliary keys/epoch,
   noncanonical carries and corrupted output/proof. A public parser is not
   authentication. Challenge after answer/key/index binding; basis-only or
   root-only error checks are inadmissible after E83.
4. State how the client binds the public convolution/decomposition and PBS/
   selector trace before private work. If no actual verifier is supplied, record
   an arithmetic control only, not an authenticated protocol.

## One paid-count session and R6 return

Separate dense all-coefficient, sparse required-score and repeated-batch modes.
For each strongest control charge key setup/residency/transfers, exact digit
levels, transforms, pointwise work, materialization/streaming, relin/rounding/
KS/PBS noise, proof setup/prover/verifier/wire, all ID/coverage work and RTTs.
Keep public preprocessing versus secret receiver state explicit. The current
N=16384 and N=2048 cards are inputs, not security parameter sets.

Advance only if the actual new authenticated step is specified, survives the
strong controls and meets the existing complete-cost/state effect target.
If the identity merely recovers a known FFT switch, keep it as a homemade
engineering control and pivot the research mechanism. If sparse output,
key memory, proof/coverage or supported target-key constraints defeat it,
record that finite stop. Return to Q4/R6 after each subcomponent; Q6/full
backend remains conditional on the selected complete mechanism.
