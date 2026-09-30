"""E41 exact finite grammar for private affine maps and final reply geometry.

Fixed index-only median trees offer raw/affine nodes or both children. Final
CRT geometry is independent of that discovery tree. The finite layout grammar
assigns contiguous elementary slots to canonical distinct maps and enumerates
every positive allocation. It is deliberately restricted, not an arbitrary
partition or layout optimum. Every candidate preserves all rows and stable IDs.

An important control targets the RESPONSE occupancy of E29, rather than the
input-product tile count optimized by the inherited E27/E35 allocator.
Equal private basis rows may share coordinate IDs; arbitrary equal values in
one query never justify that sharing. No encryption library is imported.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import itertools
import math

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import reduction_oracles as reductions
from experiments.bfv_search_lab.representation_contract import Profile, Resources, Workload


@dataclass(frozen=True)
class Node:
    path: str
    positions: tuple[int, ...]
    children: tuple[Node, ...] = ()


@dataclass(frozen=True)
class Piece:
    source_path: str
    positions: tuple[int, ...]
    mapping: affine.Plan
    mode: str


@dataclass(frozen=True)
class Choice:
    pieces: tuple[Piece, ...]

    @property
    def name(self) -> str:
        return "+".join(f"{p.source_path or 'root'}:{p.mode}" for p in self.pieces)


@dataclass(frozen=True)
class Compiled:
    workload: Workload
    profile: Profile
    choice: Choice
    allocation: tuple[int, ...]
    candidate: partition.Candidate
    maps: tuple[affine.Plan, ...]
    query_space: space.Space
    groups: tuple[tuple[tuple[int, ...], ...], ...]
    resources: Resources
    equal_forms: bool

    @property
    def dimension(self) -> int:
        return self.workload.dimension

    @property
    def ids(self) -> tuple[int, ...]:
        return self.workload.ids

    @property
    def binding(self) -> str:
        # Owner-local audit identity. Publishing an unsalted digest of private
        # rows/maps enables dictionary tests; use authenticated RANDOM epoch
        # handles and commitments to randomized public ciphertexts remotely.
        body = (bytes.fromhex(self.workload.digest) + self.query_space.binding
                + repr((self.profile, self.choice, self.allocation, self.equal_forms)).encode())
        return hashlib.sha256(b"cuhepy/research/exact-representation/plan/v1\0" + body).hexdigest()

    def client_view(self) -> ClientView:
        """Detach the enrolled plaintext rows from the online client."""
        return ClientView(self.dimension, self.ids, self.profile, self.candidate,
                          self.maps, self.query_space, self.binding)


@dataclass(frozen=True)
class ClientView:
    dimension: int
    ids: tuple[int, ...]
    profile: Profile
    candidate: partition.Candidate
    maps: tuple[affine.Plan, ...]
    query_space: space.Space
    binding: str


def median_tree(workload: Workload, depth: int = 2) -> Node:
    workload.validate()
    if type(depth) is not int or not 0 <= depth <= 6:
        raise ValueError("Invalid bounded fixed discovery tree depth")

    def build(path: str, positions: tuple[int, ...], left: int) -> Node:
        if not left or len(positions) == 1:
            return Node(path, positions)
        middle = len(positions) // 2
        return Node(path, positions, (build(path + "0", positions[:middle], left - 1),
                                     build(path + "1", positions[middle:], left - 1)))

    return build("", tuple(range(len(workload.rows))), depth)


def validate_tree(workload: Workload, root: Node) -> None:
    workload.validate()

    def visit(node: Node, expected_path: str, expected: tuple[int, ...]) -> None:
        if (node.path != expected_path or node.positions != expected or not expected
                or len(node.path) > 6 or len(node.children) not in (0, 2)):
            raise ValueError("Invalid fixed discovery tree or row coverage")
        if node.children:
            left, right = node.children
            if (not left.positions or not right.positions
                    or left.positions + right.positions != expected):
                raise ValueError("Discovery children omit or reorder enrolled rows")
            visit(left, expected_path + "0", left.positions)
            visit(right, expected_path + "1", right.positions)

    visit(root, "", tuple(range(len(workload.rows))))


def raw_map(dimension: int, prime: int) -> affine.Plan:
    result = affine.Plan(dimension, prime, 0, tuple(range(dimension)),
                         tuple(tuple(int(i == j) for j in range(dimension)) for i in range(dimension)))
    affine.validate(result)
    return result


def choices(workload: Workload, root: Node, prime: int, *, limit: int = 4096) -> tuple[Choice, ...]:
    """Independent exhaustive grammar reference, with a hard work cap."""
    validate_tree(workload, root)
    affine._field(workload.dimension, prime)
    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("Invalid exhaustive grammar work limit")
    raw = raw_map(workload.dimension, prime)

    def enumerate_node(node: Node) -> tuple[Choice, ...]:
        mapping = affine.prepare([workload.rows[i] for i in node.positions], workload.dimension, prime)
        result = [Choice((Piece(node.path, node.positions, raw, "raw"),)),
                  Choice((Piece(node.path, node.positions, mapping, "affine"),))]
        if node.children:
            left, right = map(enumerate_node, node.children)
            if len(left) * len(right) + 2 > limit:
                raise ValueError("Exhaustive representation grammar exceeds work limit")
            result.extend(Choice(a.pieces + b.pieces) for a in left for b in right)
        return tuple(result)

    return enumerate_node(root)


def allocations(total: int, groups: int, *, limit: int = 100000) -> tuple[tuple[int, ...], ...]:
    """Every positive composition, independently of a greedy tile allocator."""
    if (type(total) is not int or not 1 <= total <= 64 or total & (total - 1)
            or type(groups) is not int or not 1 <= groups <= total
            or type(limit) is not int or not 1 <= limit <= 1000000):
        raise ValueError("Invalid bounded final slot allocation")
    if math.comb(total - 1, groups - 1) > limit:
        raise ValueError("Exhaustive final allocation exceeds work limit")
    return tuple(tuple(b - a for a, b in zip((0,) + cuts, cuts + (total,), strict=True))
                 for cuts in itertools.combinations(range(1, total), groups - 1))


def grouped(choice: Choice, workload: Workload, prime: int) -> tuple[tuple[affine.Plan, ...], tuple[tuple[int, ...], ...]]:
    if not choice.pieces or len(choice.pieces) > 64:
        raise ValueError("Invalid finite representation choice")
    positions = tuple(i for p in choice.pieces for i in p.positions)
    if positions != tuple(range(len(workload.rows))):
        raise ValueError("Representation omits, duplicates or reorders a row")
    groups: dict[affine.Plan, list[int]] = {}
    for piece in choice.pieces:
        affine.validate(piece.mapping)
        if (not piece.positions or piece.mode not in ("raw", "affine")
                or (piece.mapping.dimension, piece.mapping.prime) != (workload.dimension, prime)):
            raise ValueError("Invalid private map or chosen field")
        affine.index_features(piece.mapping, [workload.rows[i] for i in piece.positions])
        groups.setdefault(piece.mapping, []).extend(piece.positions)
    return tuple(groups), tuple(tuple(indices) for indices in groups.values())


def _cover(allocation: tuple[int, ...]) -> tuple[tuple[str, int], ...]:
    labels = tuple(i for i, count in enumerate(allocation) for _ in range(count))
    result = []

    def visit(path: str, start: int, stop: int) -> None:
        if all(label == labels[start] for label in labels[start:stop]):
            result.append((path, labels[start]))
            return
        middle = (start + stop) // 2
        visit(path + "0", start, middle)
        visit(path + "1", middle, stop)

    visit("", 0, len(labels))
    return tuple(result)


def compile_choice(workload: Workload, choice: Choice, profile: Profile,
                   allocation: tuple[int, ...], *, equal_forms: bool = True) -> Compiled:
    workload.validate()
    profile.validate(workload.dimension)
    maps, positions = grouped(choice, workload, profile.prime)
    if (type(equal_forms) is not bool or type(allocation) is not tuple
            or len(allocation) != len(maps) or any(type(x) is not int or x < 1 for x in allocation)):
        raise ValueError("Invalid distinct-map allocation")
    slots = sum(allocation)
    if slots > fields.max_slots(profile.prime) or slots > 64 or slots & (slots - 1):
        raise ValueError("Final CRT geometry lacks valid dyadic slots")
    cover = _cover(allocation)
    ctx = tree.context(profile.n, tuple(path for path, _ in cover), profile.prime)
    # Unlike E35's input-product tiles, every component coefficient can carry
    # an E29 response score. Allocate all rows against this exact reply capacity.
    replies = max((len(group) + count * (profile.n // slots) - 1) // (count * (profile.n // slots))
                  for group, count in zip(positions, allocation, strict=True))
    offsets = [0] * len(maps)
    blocks = []
    for (path, group), leaf in zip(cover, ctx.leaves, strict=True):
        count = min(len(positions[group]) - offsets[group], replies * leaf.degree)
        piece = positions[group][offsets[group]:offsets[group] + count]
        offsets[group] += count
        blocks.append(partition.Block(path, piece, maps[group]))
    if offsets != list(map(len, positions)):
        raise AssertionError("Reply allocation lost enrolled rows")
    layout = tree.layout(ctx, tuple(b.mapping.features for b in blocks), tuple(len(b.positions) for b in blocks))
    candidate = partition.Candidate(layout, tuple(blocks), (), partition.epoch_digest(list(workload.rows), workload.dimension),
                                    workload.dimension, partition.map_body_bytes(tuple(blocks)), None)
    partition.validate_epoch(candidate, list(workload.rows))
    if layout.cost.response_ciphertexts != replies:
        raise AssertionError("Exact reply capacity disagrees with layout")
    coordinate_ids = ()
    if equal_forms:
        seen: dict[tuple[int, ...], int] = {}
        coordinate_ids = tuple(tuple(seen.setdefault(row, len(seen)) for row in
                                    (p.basis or ((0,) * workload.dimension,))) for p in maps)
    s = space.space(layout, tuple(maps.index(b.mapping) for b in blocks), coordinate_ids=coordinate_ids)
    rounds = fields.rounds(profile.q, budget=profile.attempt_budget, integrity_bits=profile.check_bits)
    cost = space.cost(s, q_bits=profile.q.bit_length(), eta=profile.eta, rounds=rounds)
    if 2 * cost["worst_case_phase_bound"] >= profile.q:
        raise ValueError("Representation exceeds deterministic honest phase bound")
    response = (2 * replies * profile.n * profile.q.bit_length() + 7) // 8
    width = (profile.q.bit_length() + 7) // 8
    ids_permutation = 12 * len(workload.rows)  # uint64 stable IDs + uint32 restore positions.
    checker = rounds * (32 + sum(s.column_degrees) * width)
    groups = tuple(tuple(tuple(row) for row in affine.index_features(b.mapping, [workload.rows[i] for i in b.positions]))
                   for b in blocks)
    resources = Resources(s.dimension, s.columns, sum(s.column_degrees), replies,
                          cost["online_query_body_bytes"], response, s.columns * response,
                          cost["native_ntt_index_word_bytes"], candidate.map_bytes, ids_permutation,
                          checker, candidate.map_bytes + ids_permutation + checker,
                          cost["offline_seeded_answer_body_bytes_per_token"],
                          sum(len(g) * f for g, f in zip(groups, layout.features, strict=True))
                          * ((profile.prime.bit_length() + 7) // 8),
                          cost["worst_case_phase_bound"], rounds,
                          cost["checker_online_scalar_products"], cost["native_online_pointwise_scalar_products"])
    return Compiled(workload, profile, choice, allocation, candidate, maps, s, groups, resources, equal_forms)


def query(plan: Compiled | ClientView, word: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if type(word) is not int or not 0 <= word < 1 << plan.dimension:
        raise ValueError("Query outside the binary dimension")
    values = [affine.query_features(p, word) for p in plan.maps]
    if plan.query_space.coordinate_ids:
        weights: list[int | None] = [None] * plan.query_space.dimension
        for (terms, _), ids in zip(values, plan.query_space.coordinate_ids, strict=True):
            for value, identifier in zip(terms, ids, strict=True):
                if weights[identifier] is not None and weights[identifier] != value:
                    raise AssertionError("Equal basis forms produced unequal query values")
                weights[identifier] = value
        if any(x is None for x in weights):
            raise AssertionError("Missing masked coordinate")
        transformed = tuple(int(x) for x in weights)
    else:
        transformed = tuple(x for terms, _ in values for x in terms)
    return transformed, tuple(offset for _, offset in values)


def decode(plan: Compiled | ClientView, plaintexts: list[list[int]], offsets: tuple[int, ...]) -> tuple[int, ...]:
    if len(offsets) != len(plan.maps):
        raise ValueError("Incorrect private anchor offsets")
    decoded = tree.unpack(plan.candidate.layout, plaintexts)
    restored: list[int | None] = [None] * len(plan.ids)
    for block, dots, group in zip(plan.candidate.blocks, decoded, plan.query_space.map_ids, strict=True):
        for position, value in zip(block.positions, affine.decode(plan.maps[group], dots, offsets[group]), strict=True):
            if restored[position] is not None:
                raise AssertionError("Duplicate output position")
            restored[position] = value
    if any(x is None for x in restored):
        raise AssertionError("Missing output position")
    return tuple(int(x) for x in restored)


def exact_scores(plan: Compiled, word: int) -> tuple[int, ...]:
    """Independent integer negacyclic products, not the encrypted evaluator."""
    values, offsets = query(plan, word)
    columns = space.columns(plan.query_space, [[list(row) for row in g] for g in plan.groups])
    corrections = space.corrections(plan.query_space, values)
    products = [[reductions.ring_product(columns[j][r], space.expand(plan.query_space, corrections[j]))
                 for j in range(plan.query_space.columns)] for r in range(plan.resources.replies)]
    result = [[sum(poly[i] for poly in group) % plan.profile.prime for i in range(plan.profile.n)] for group in products]
    return decode(plan, result, offsets)


def enumerate_plans(workload: Workload, root: Node, profiles: tuple[Profile, ...],
                    slots: tuple[int, ...] = (1, 2, 4, 8), *, limit: int = 100000,
                    equal_forms: bool = True) -> tuple[tuple[Compiled, ...], tuple[tuple[str, str], ...]]:
    """Exhaustive complete-plan reference; retain every rejected construction."""
    if type(limit) is not int or not 1 <= limit <= 1000000 or not profiles:
        raise ValueError("Invalid complete grammar budget")
    plans, rejected, attempted = [], [], 0
    for profile in profiles:
        profile.validate(workload.dimension)
        for choice in choices(workload, root, profile.prime):
            maps, _ = grouped(choice, workload, profile.prime)
            for count in slots:
                if type(count) is not int or not 1 <= count <= 64 or count & (count - 1):
                    raise ValueError("Invalid final slot catalog")
                if count < len(maps):
                    continue
                if attempted == limit:
                    raise ValueError("Complete grammar exceeds work limit")
                for allocation in allocations(count, len(maps), limit=limit - attempted):
                    attempted += 1
                    if attempted > limit:
                        raise ValueError("Complete grammar exceeds work limit")
                    name = f"{profile}:{choice.name}:{allocation}"
                    try:
                        plans.append(compile_choice(workload, choice, profile, allocation, equal_forms=equal_forms))
                    except ValueError as error:
                        rejected.append((name, str(error)))
    return tuple(plans), tuple(rejected)
