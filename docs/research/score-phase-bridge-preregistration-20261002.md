# Q11/E85: discriminate the actual score-to-selection interface

2026-10-02, before the new oracle/result. This is a bounded exact-arithmetic
screen, not a TFHE implementation or a novel complete converter. The proposed
shared relation must cover original ciphertext components, integer carries and
score/ID coverage. We first determine which work an ordinary converter already
provides, and which required work the proposed shortcut silently omits.

1. Independently compare signed coefficient sample extraction against
   schoolbook negacyclic decryption, including unrelinearized C2 and the derived
   secret S². Exhaust all degree-two ciphertexts and ternary keys over F3.
2. For the actual BFV phase convention `floor(Q/t)*m + e`, switch every public
   LWE coefficient by nearest-integer `B/Q`. Exhaust bounded messages, noise,
   masks and keys. Check a rational worst-case margin including the floor
   remainder and the full extracted secret norm. Test equality/failure margins.
3. For BGV's centered phase `m + t*e`, test the same switch and the alternative
   componentwise `B/t` shortcut. Include two representations of the same phase
   with different unknown Q carries. Do not infer a broken published converter
   from a broken proposed shortcut.
4. Include C2 omission, one-limb CRT substitution, noncanonical residues and
   unsafe bounds. Arithmetic checks are not original-input authentication.
5. Check the negacyclic LUT/padding restriction for an exact threshold on the
   entire admitted integer domain. A rounded torus plaintext is not yet an
   arbitrary programmable bootstrap or a stable-ID winner certificate.
6. At retained E72 geometries count un-relinearized versus once-relinearized
   extracted dimensions, optional materialized input bodies, and the changed
   one-product correctness bound for a fully split t. Materialization is one
   implementation choice, not a communication/work lower bound. Pay setup,
   key switch/PBS, proof, padding, ID coverage and changed HE parameters.

Known strong controls include TFHE sample extraction/modulus switching,
CHIMERA's BFV/TFHE scheme switching, HElib's plaintext-ring operations and
RevoLUT's key-value counting. Advance only with a specified extra algebraic
step that improves a complete paid interface. Otherwise retain a useful
baseline adapter and return to R6; do not start a generic TFHE/CUDA port or
claim that all conversion methods are impossible.
