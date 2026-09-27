"""E15: deterministic phase bounds for the *joint* trace/packing circuit.

For D input positions, the packing butterfly is sum_i X^i Trace_D(f_i).
Trace_D(f) keeps only coefficients divisible by D and multiplies them by D.
The shifted supports are disjoint. Thus its input contribution is bounded by
D*max_i ||f_i||inf, rather than D*sum_i ||f_i||inf.

An error polynomial introduced after level j (zero based) goes through the
remaining butterfly of degree D/2**(j+1). At that level, its shifted support is
disjoint from the other nodes' supports. Uniform switch-error bound S therefore
contributes at most sum_j D/2**(j+1)*S = (D-1)*S. No independence or distributional
assumption is used: every error polynomial may be adversarially correlated.

Inputs here already include the relinearization error. The result bounds the
entire final polynomial, including unused output coefficients. It is a bound
on an integer lift of the phase; equality to the actual ciphertext is modulo Q.
Only a final lift below Q/2 permits correct centered decryption.

This opt-in research class keeps the existing native arithmetic unchanged and
does not modify the original conservative server, codecs or Nitro policy.
It supplies neither response authentication nor a lattice-security estimate.
Bounds are owner-side assumptions about honest inputs, never wire evidence.
"""

from __future__ import annotations

from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.native_bgv import NativeServer, PreparedIndex

POLICY = "cuhepy-lab-bgv-joint-support-bound-v1"


def final_bound(padded: int, input_bounds: list[int], switch_error: int) -> int:
    """Bound one nonempty joint response group with arbitrary missing tail inputs."""
    if (
        type(padded) is not int or padded < 1 or padded & (padded - 1)
        or not 1 <= len(input_bounds) <= padded
        or any(type(b) is not int or b < 0 for b in input_bounds)
        or type(switch_error) is not int or switch_error < 0
    ):
        raise ValueError("Invalid support-bound schedule")
    return padded * max(input_bounds) + (padded - 1) * switch_error


class SupportBoundServer(NativeServer):
    """Same joint C++/CUDA computation with a separately justified public bound.

    The per-tile trace backend introduces errors in a different order and is
    deliberately refused. Existing native prepared-index ownership, canonical
    ciphertext checks and terminal/codec bounds still apply. No secret key is
    passed to this class. Use only trusted local fixtures pending protocol review.
    """

    bound_policy = POLICY

    def _bounds(self, query: bgv.Ciphertext, index: PreparedIndex, joint: bool) -> list[int]:
        if joint is not True or index.owner is not self._identity:
            raise ValueError("Support bound requires this server's index and joint circuit")
        bgv._validate(query, self.pk)
        if len(query.components) != 2:
            raise ValueError("Joint support bound needs two-component inputs")
        capacity = self.pk.n // self.keys.padded
        if (
            type(index.count) is not int or index.count < 0
            or len(index.phase_bounds) != (index.count + capacity - 1) // capacity
            or any(type(b) is not int or not 0 <= 2*b < self.pk.q for b in index.phase_bounds)
        ):
            raise ValueError("Invalid support-bound index metadata")
        d, error = self.keys.padded, self.keys.switch_error_bound
        bounds = []
        for start in range(0, len(index.phase_bounds), d):
            relinearized = [
                self.pk.n * query.phase_bound * b + error
                for b in index.phase_bounds[start:start + d]
            ]
            bound = final_bound(d, relinearized, error)
            if 2 * bound >= self.pk.q:
                raise ValueError("Joint support correctness bound exceeds Q/2")
            bounds.append(bound)
        return bounds
