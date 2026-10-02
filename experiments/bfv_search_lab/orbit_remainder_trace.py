"""E90 bounded public quotient/remainder controls, not PBS or a proof system.

All quotients stay in Z. Public inputs are owner approved by the caller;
hashes identify that context but do not authenticate upstream encrypted scores.
Toy secrets appear only in independent tests, never in server/verifier inputs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json


@dataclass(frozen=True)
class Profile:
    modulus: int
    targets: tuple[int, ...]
    context_id: str
    key_id: str
    epoch: str


def divisors(profile):
    if (type(profile) is not Profile or type(profile.modulus) is not int
            or not 4 <= profile.modulus <= 1 << 64 or profile.modulus & (profile.modulus - 1)
            or type(profile.targets) is not tuple or not 1 <= len(profile.targets) <= 4
            or any(type(s) is not str or not 1 <= len(s) <= 64
                   for s in (profile.context_id, profile.key_id, profile.epoch))):
        raise ValueError("Invalid bounded public profile")
    current, result = profile.modulus, []
    for target in profile.targets:
        if (type(target) is not int or not 2 <= target <= current // 2
                or target & (target - 1)):
            raise ValueError("Dyadic targets must leave an even remainder modulus")
        current //= target
        result.append(current)
    return tuple(result)


@dataclass(frozen=True)
class Step:
    quotient: int
    remainder: int
    half: int


def scalar_trace(value, profile):
    lengths = divisors(profile)
    if type(value) is not int or not 0 <= value < profile.modulus:
        raise ValueError("Canonical initial torus residue required")
    current, result = value, []
    for length in lengths:
        remainder = (current + length // 2) % length - length // 2
        result.append(Step((current - remainder) // length, remainder,
                           int(current % length == length // 2)))
        current = remainder
    return tuple(result)


def signed_trace(value, original, sign, profile):
    """Share a validated canonical source trace through a signed mask rotation."""
    lengths = divisors(profile)
    _trace_shape(original, profile)
    if (type(sign) is not int or sign not in (-1, 1)
            or original != scalar_trace(value, profile)):
        raise ValueError("Signed sharing requires the complete original trace")
    return _signed_trace(value, original, sign, profile, lengths)


def _signed_trace(value, original, sign, profile, lengths):
    # Internal caller has already validated/built the original once.
    if sign == 1:
        return original
    result, previous_half = [], 0
    for stage, (step, length, target) in enumerate(zip(original, lengths, profile.targets, strict=True)):
        carry = target * int(value != 0) if stage == 0 else -target * previous_half
        result.append(Step(-step.quotient + step.half + carry,
                           -step.remainder - length * step.half, step.half))
        previous_half = step.half
    return tuple(result)


@dataclass(frozen=True)
class Approved:
    profile: Profile
    components: tuple[tuple[int, ...], ...]
    blocks: tuple[tuple[int, int], ...]


def degree(approved):
    if type(approved) is not Approved:
        raise ValueError("Owner-approved public context required")
    divisors(approved.profile)
    components = approved.components
    if (type(components) is not tuple or len(components) not in (2, 3)
            or type(components[0]) is not tuple):
        raise ValueError("Body plus one or two complete mask families required")
    n = len(components[0])
    if (not 2 <= n <= 16 or n & (n - 1)
            or any(type(poly) is not tuple or len(poly) != n
                   or any(type(x) is not int or not 0 <= x < approved.profile.modulus for x in poly)
                   for poly in components)):
        raise ValueError("Invalid bounded canonical source components")
    if type(approved.blocks) is not tuple or not 1 <= len(approved.blocks) <= n:
        raise ValueError("Bounded ordered block coverage required")
    seen = set()
    for block in approved.blocks:
        if (type(block) is not tuple or len(block) != 2
                or any(type(x) is not int for x in block)):
            raise ValueError("Noncanonical block descriptor")
        start, width = block
        if not 0 <= start < n or not 1 <= width <= n - start:
            raise ValueError("Block outside the approved coefficient range")
        positions = set(range(start, start + width))
        if seen & positions:
            raise ValueError("Repeated approved score position")
        seen.update(positions)
    return n


def anchor(approved):
    degree(approved)
    body = json.dumps(asdict(approved), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"E90-public-subrelation-v1\0" + body).hexdigest()


@dataclass(frozen=True)
class BlockTrace:
    start: int
    width: int
    bodies: tuple[tuple[Step, ...], ...]
    masks: tuple[tuple[tuple[Step, ...], ...], ...]


@dataclass(frozen=True)
class Transcript:
    anchor: str
    original: tuple[tuple[tuple[Step, ...], ...], ...]
    blocks: tuple[BlockTrace, ...]


def build(approved):
    """A shared public trace. Outputs are encrypted-component arithmetic only."""
    n = degree(approved)
    lengths = divisors(approved.profile)
    original = tuple(tuple(scalar_trace(x, approved.profile) for x in poly)
                     for poly in approved.components)
    blocks = []
    for start, width in approved.blocks:
        masks = tuple(tuple(_signed_trace(poly[(j + start) % n], traces[(j + start) % n],
                                          1 if j + start < n else -1, approved.profile, lengths)
                            for j in range(n))
                      for poly, traces in zip(approved.components[1:], original[1:], strict=True))
        blocks.append(BlockTrace(start, width, original[0][start:start + width], masks))
    return Transcript(anchor(approved), original, tuple(blocks))


def _trace_shape(trace, profile):
    lengths = divisors(profile)
    if type(trace) is not tuple or len(trace) != len(lengths):
        raise ValueError("Missing or malformed public stage")
    for step, length in zip(trace, lengths, strict=True):
        if (type(step) is not Step
                or any(type(x) is not int for x in (step.quotient, step.remainder, step.half))
                or not -2 * profile.modulus <= step.quotient <= 2 * profile.modulus
                or not -length // 2 <= step.remainder < length // 2 or step.half not in (0, 1)):
            raise ValueError("Noncanonical centered integer trace")


def verify_and_release(approved, transcript, private_callback):
    """Full paid recomputation before any callback; no compact proof is implied."""
    n = degree(approved)
    if (type(transcript) is not Transcript or type(transcript.anchor) is not str
            or transcript.anchor != anchor(approved)
            or type(transcript.original) is not tuple or len(transcript.original) != len(approved.components)
            or type(transcript.blocks) is not tuple or len(transcript.blocks) != len(approved.blocks)):
        raise ValueError("Wrong public context, component or coverage framing")
    for poly in transcript.original:
        if type(poly) is not tuple or len(poly) != n:
            raise ValueError("Missing original coefficient")
        for trace in poly:
            _trace_shape(trace, approved.profile)
    for block in transcript.blocks:
        if (type(block) is not BlockTrace or type(block.start) is not int or type(block.width) is not int
                or type(block.bodies) is not tuple or not 1 <= block.width <= n
                or len(block.bodies) != block.width or type(block.masks) is not tuple
                or len(block.masks) != len(approved.components) - 1):
            raise ValueError("Noncanonical output block")
        for trace in block.bodies:
            _trace_shape(trace, approved.profile)
        for family in block.masks:
            if type(family) is not tuple or len(family) != n:
                raise ValueError("Missing output mask coefficient")
            for trace in family:
                _trace_shape(trace, approved.profile)
    if transcript != build(approved):
        raise ValueError("False public quotient, remainder, half bit or signed output")
    return private_callback(transcript)


def rounded_grid(value, q, b):
    if (any(type(x) is not int for x in (value, q, b)) or not 3 <= q < 1 << 64 or q % 2 == 0
            or not 4 <= b <= 1 << 64 or b & (b - 1) or not 0 <= value < q):
        raise ValueError("Canonical odd-source/dyadic-target grid required")
    return ((2 * b * value + q) // (2 * q)) % b


def grid_tie_count(q, b, cumulative_target):
    rounded_grid(0, q, b)
    if (type(cumulative_target) is not int or not 2 <= cumulative_target <= b // 2
            or cumulative_target & (cumulative_target - 1)):
        raise ValueError("Cumulative target must leave an even remainder modulus")
    length = b // cumulative_target
    # Bijection with odd y, |y|<Q/L. No randomness/crypto assumption here.
    return 2 * ((q + length) // (2 * length))
