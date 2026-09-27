"""Optional trusted arithmetic engine; caller-supplied weights are NOT a protocol.

Use only through checked_switch_bgv.Request or checked_product_bgv.Request for
pinning, validation before
sampling, fresh CSPRNG weights and one-use lifecycle. No HE secrets, SEAL or
GPU code are used. Verifier randomness has no side-channel/erasure assurance.
"""

import importlib
import struct


class NativeCheckArithmetic:
    def __init__(self, context):
        self.context = context
        self._native = importlib.import_module('experiments.bfv_search_lab._verify._bgv_checked')
        key = b''.join(struct.pack(f'<{context.n}Q', *poly)
                       for limb in context.key for column in limb for poly in column)
        self._handle = self._native.create(context.n, key)
        if self._native.primes(self._handle) != context.primes:
            raise ValueError('Native/reference RNS prime mismatch')

    def validate(self, packet, batch, components):
        self._native.validate(self._handle, packet, batch, components)

    def check_arithmetic(self, input_packet, output_packet, weights, batch):
        return self._native.check_arithmetic(self._handle, input_packet, output_packet, weights, batch)


class NativeProductArithmetic:
    """Resident ordered public index; fresh challenges belong to the wrapper."""

    def __init__(self, context, arithmetic):
        if type(arithmetic) is not NativeCheckArithmetic or arithmetic.context is not context.context:
            raise ValueError('Wrong native switch context for product')
        self.context, self.arithmetic = context, arithmetic
        self._native = arithmetic._native
        self._handle = self._native.product_create(arithmetic._handle, context.raw_index, context.batch)

    def validate_result(self, witness, output, mode):
        from experiments.bfv_search_lab.checked_product_bgv import MODES
        self._native.product_validate(self._handle, witness, output, MODES[mode])

    def check_arithmetic(self, query, witness, output, weights, mode):
        from experiments.bfv_search_lab.checked_product_bgv import MODES
        return self._native.product_check(self._handle, query, witness, output, weights, MODES[mode])

    def evaluate(self, query, *, witness=False):
        """Deterministic native recomputation control; no verification claim."""
        if type(witness) is not bool:
            raise ValueError('Explicit bool witness policy required')
        return self._native.product_evaluate(self._handle, query, int(witness))
