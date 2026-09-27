"""Optional trusted arithmetic engine; caller-supplied weights are NOT a protocol.

Use only through checked_switch_bgv.Request for pinning, validation before
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
