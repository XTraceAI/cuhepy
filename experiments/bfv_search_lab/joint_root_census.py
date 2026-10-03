"""E123 exact-once continuation of a frozen public root-count inventory.

The evaluator and authenticated original records supply exact masses. This
controller does not establish their law, choose roots, or rebuild an inventory.
Synthetic controller tests are not extra field-distribution experiments.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, fields
import hashlib
import json

from experiments.bfv_search_lab import joint_root as old


def _integer(value):
    if type(value) is not int:
        raise ValueError("Expected an exact integer, without numeric aliases")
    return value


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError("Missing, extra, or malformed serialized fields")
    return value


def _array(value):
    if type(value) is not list:
        raise ValueError("Expected a serialized array")
    return value


def _integers(value):
    return tuple(_integer(item) for item in _array(value))


def _digest(value):
    if (type(value) is not str or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)):
        raise ValueError("Expected a lowercase SHA256 digest")
    return value


def strict_json(text):
    """Reject duplicate object keys and noninteger numbers before conversion."""
    if type(text) is not str:
        raise ValueError("Expected exact JSON text")

    def object_pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    def reject_number(_value):
        raise ValueError("Noninteger or nonfinite JSON number")

    return json.loads(text, object_pairs_hook=object_pairs,
                      parse_float=reject_number, parse_constant=reject_number)


def parse_context(value):
    _fields(value, ("n", "q", "root"))
    return old.Context(*(_integer(value[name]) for name in ("n", "q", "root"))).validate()


def parse_inventory(value):
    _fields(value, ("context", "root_count", "orbits", "assignments"))
    ctx, root_count = parse_context(value["context"]), _integer(value["root_count"])
    orbits = []
    for item in _array(value["orbits"]):
        _fields(item, ("representative", "members", "stabilizer"))
        orbits.append(old.Orbit(_integers(item["representative"]),
                                tuple(_integers(member) for member in _array(item["members"])),
                                _integers(item["stabilizer"])))
    assignments = []
    for item in _array(value["assignments"]):
        _array(item)
        if len(item) != 3:
            raise ValueError("Malformed serialized transporter")
        assignments.append((_integers(item[0]), _integers(item[1]), _integer(item[2])))
    return old.Inventory(ctx, root_count, tuple(orbits), tuple(assignments)).validate()


def parse_count(value):
    names = tuple(field.name for field in fields(old.Count))
    _fields(value, names)
    parsed = {}
    for name in names:
        if name == "roots":
            parsed[name] = _integers(value[name])
        elif name == "witness":
            parsed[name] = None if value[name] is None else _integers(value[name])
        else:
            parsed[name] = _integer(value[name])
    return old.Count(**parsed).validate()


def validate_count(ctx, root_count, count, *, verify_witness=True):
    """Grammar and optional literal witness checks do not recompute a mass."""
    if type(ctx) is not old.Context or type(count) is not old.Count:
        raise ValueError("Expected exact frozen context/count objects")
    ctx.validate()
    _integer(root_count)
    if type(verify_witness) is not bool:
        raise ValueError("Expected an exact witness-validation flag")
    count.validate()
    if count.n != ctx.n or len(count.roots) != root_count:
        raise ValueError("Count disagrees with context or prescribed arity")
    if old.is_quartic_packet(ctx, count.roots) and count.total_count != 1:
        raise ValueError("Structured packet contradicts the known zero-only control")
    if count.total_count % (2 * ctx.n) != 1:
        raise ValueError("Count contradicts free signed-monomial action")
    if verify_witness and count.witness is not None:
        old.verify_witness(ctx, count.roots, count.witness)
    return count


def count_digest(count):
    if type(count) is not old.Count:
        raise ValueError("Expected an exact count")
    count.validate()
    text = json.dumps(asdict(count), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def validate_zero_accounting(included_per_count, added_again):
    """The original count field is INTEGER one, not a truth-value alias."""
    if _integer(included_per_count) != 1 or type(added_again) is not bool or added_again:
        raise ValueError("Expected zero included once per count, without another addition")
    return True


@dataclass(frozen=True)
class Entry:
    index: int
    origin: str
    original_record_sha256: str
    orbit_size: int
    structured_quartic: bool
    count: old.Count

    def validate(self, inventory):
        if type(inventory) is not old.Inventory:
            raise ValueError("Expected a frozen inventory")
        _integer(self.index)
        _integer(self.orbit_size)
        _digest(self.original_record_sha256)
        if (type(self.origin) is not str or self.origin not in ("reused_E122", "fresh_E123")
                or type(self.structured_quartic) is not bool
                or not 1 <= self.index <= len(inventory.orbits)):
            raise ValueError("Malformed census ledger entry")
        orbit = inventory.orbits[self.index - 1]
        validate_count(inventory.context, inventory.root_count, self.count, verify_witness=False)
        if (self.count.roots != orbit.representative or self.orbit_size != len(orbit.members)
                or self.structured_quartic != old.is_quartic_packet(inventory.context, self.count.roots)):
            raise ValueError("Entry disagrees with its frozen representative")
        if self.origin == "fresh_E123" and self.original_record_sha256 != count_digest(self.count):
            raise ValueError("Fresh count digest mismatch")
        return self


def entry(inventory, index, count, *, origin, record_sha256=None):
    _integer(index)
    if type(inventory) is not old.Inventory or not 1 <= index <= len(inventory.orbits):
        raise ValueError("Unknown census representative index")
    digest = count_digest(count) if record_sha256 is None else _digest(record_sha256)
    return Entry(index, origin, digest, len(inventory.orbits[index - 1].members),
                 old.is_quartic_packet(inventory.context, count.roots), count).validate(inventory)


def validate_entries(inventory, entries, *, reused_count):
    if type(inventory) is not old.Inventory:
        raise ValueError("Expected a frozen inventory")
    _integer(reused_count)
    if (type(entries) is not tuple or not 0 <= reused_count <= len(entries)
            or len(entries) > len(inventory.orbits)):
        raise ValueError("Malformed census coverage")
    for index, item in enumerate(entries, 1):
        if type(item) is not Entry:
            raise ValueError("Expected an exact ledger entry")
        item.validate(inventory)
        if (item.index != index
                or item.origin != ("reused_E122" if index <= reused_count else "fresh_E123")):
            raise ValueError("Reordered, missing, duplicate, or mislabeled ledger entry")
    return entries


def reuse_prefix(inventory, raw_counts, lines):
    """Authenticate each exact JSONL record against the raw's ordered counts.

    The runner separately pins original bytes/checkpoint/status/receipts.
    This function checks semantics without evaluating any reused mass.
    """
    if type(inventory) is not old.Inventory or type(lines) is not tuple:
        raise ValueError("Expected a frozen inventory and exact JSONL lines")
    inventory.validate()
    parsed_counts = tuple(parse_count(item) for item in _array(raw_counts))
    if not lines or len(lines) != len(parsed_counts) or len(lines) > len(inventory.orbits):
        raise ValueError("Prefix/raw coverage mismatch")
    records = []
    for index, (text, original_count) in enumerate(zip(lines, parsed_counts, strict=True), 1):
        if type(text) is not str or not text.endswith("\n") or text.count("\n") != 1:
            raise ValueError("Expected a complete original JSONL line")
        item = strict_json(text)
        _fields(item, ("index", "count", "structured_quartic"))
        if (_integer(item["index"]) != index or type(item["structured_quartic"]) is not bool):
            raise ValueError("Malformed prefix ordinal or packet label")
        count = parse_count(item["count"])
        validate_count(inventory.context, inventory.root_count, count)
        if (count != original_count or item["structured_quartic"]
                != old.is_quartic_packet(inventory.context, count.roots)):
            raise ValueError("Original prefix/raw count mismatch")
        records.append(entry(inventory, index, count, origin="reused_E122",
                             record_sha256=hashlib.sha256(text.encode()).hexdigest()))
    return validate_entries(inventory, tuple(records), reused_count=len(records))


@dataclass(frozen=True)
class Result:
    status: str
    reused_count: int
    entries: tuple[Entry, ...]
    interrupted_mass_work_unknown: bool

    def validate(self, inventory):
        validate_entries(inventory, self.entries, reused_count=self.reused_count)
        if (type(self.status) is not str or self.status not in
                ("completed", "resource_bounded_inconclusive")
                or type(self.interrupted_mass_work_unknown) is not bool
                or self.interrupted_mass_work_unknown != (self.status == "resource_bounded_inconclusive")
                or (self.status == "completed" and len(self.entries) != len(inventory.orbits))):
            raise ValueError("Invalid completion or resource-stop status")
        return self


def continue_census(inventory, reused, evaluate, *, on_complete=None):
    """Visit the frozen remaining list once; never stop at a positive mass.

    The trusted evaluator validates fresh witnesses and supplies exact counts.
    The callback must finish its durable append before a count is completed.
    Resource exceptions preserve only already completed records.
    """
    if type(inventory) is not old.Inventory:
        raise ValueError("Expected the frozen inventory")
    inventory.validate()
    validate_entries(inventory, reused, reused_count=len(reused))
    records = list(reused)
    try:
        for index in range(len(reused) + 1, len(inventory.orbits) + 1):
            roots = inventory.orbits[index - 1].representative
            count = evaluate(roots)
            item = entry(inventory, index, count, origin="fresh_E123")
            if on_complete is not None:
                on_complete(item)
            records.append(item)
    except (TimeoutError, MemoryError):
        return Result("resource_bounded_inconclusive", len(reused), tuple(records), True).validate(inventory)
    return Result("completed", len(reused), tuple(records), False).validate(inventory)


@dataclass(frozen=True)
class NormBridge:
    """Public known determinant bound, not a new full secret enumeration."""

    context: old.Context
    root_count: int

    def validate(self):
        if type(self.context) is not old.Context:
            raise ValueError("Expected a bounded prime split context")
        ctx = self.context.validate()
        _integer(self.root_count)
        if (not 1 <= self.root_count <= min(4, ctx.n)
                or ctx.n ** (ctx.n // 2) >= ctx.q ** (self.root_count + 1)):
            raise ValueError("Norm bound does not imply the registered defect cap")
        return self


def complete_summary(inventory, result, *, norm_bridge=None):
    """Only a full authenticated ledger admits maxima or weighted moments.

    General weighted moments are distinct from a union. The optional known
    norm bridge permits the special zero-corrected union conversion.
    """
    if type(inventory) is not old.Inventory or type(result) is not Result:
        raise ValueError("Expected exact inventory/result objects")
    inventory.validate()
    result.validate(inventory)
    if result.status != "completed":
        raise ValueError("Global observables require complete mass coverage")
    entries = result.entries
    weighted_subsets = sum(item.orbit_size for item in entries)
    if weighted_subsets != len(inventory.assignments):
        raise ValueError("Incomplete weighted subset coverage")
    maximum = max(item.count.total_count for item in entries)
    histogram = Counter((item.count.total_count, item.orbit_size, item.structured_quartic)
                        for item in entries)
    numerator = sum(item.orbit_size * item.count.total_count for item in entries)
    denominator = 3 ** inventory.context.n
    summary = {"complete_mass_inventory": True, "weighted_root_subsets": weighted_subsets,
               "maximum_count": maximum, "raw_denominator": denominator,
               "maximizing_orbits": [item.index for item in entries if item.count.total_count == maximum],
               "nonstructured_violating_orbits": [item.index for item in entries
                                                  if not item.structured_quartic and item.count.total_count > 1],
               "histogram": [{"count": key[0], "orbit_size": key[1], "structured_quartic": key[2],
                              "representatives": number, "root_subsets": number * key[1]}
                             for key, number in sorted(histogram.items())],
               "factorial_moment": {"numerator": numerator, "denominator": denominator},
               "union_event": None}
    if norm_bridge is not None:
        if (type(norm_bridge) is not NormBridge or norm_bridge.validate().context != inventory.context
                or norm_bridge.root_count != inventory.root_count):
            raise ValueError("Norm bridge disagrees with the complete census")
        nonzero = sum(item.orbit_size * (item.count.total_count - 1) for item in entries)
        union = numerator - (weighted_subsets - 1)
        if union != 1 + nonzero or not 1 <= union <= denominator:
            raise ValueError("Invalid once-only zero correction")
        summary["union_event"] = {"numerator": union, "denominator": denominator,
                                  "nonzero_event_count": nonzero,
                                  "conditional_nonzero_denominator": denominator - 1,
                                  "zero_added_once": True,
                                  "nonzero_defect_cap": inventory.root_count,
                                  "norm_bound": inventory.context.n ** (inventory.context.n // 2),
                                  "prime_power_comparison": inventory.context.q ** (inventory.root_count + 1)}
    return summary


def work_counters(result):
    if type(result) is not Result:
        raise ValueError("Expected an exact census result")
    counters = {}
    for origin in ("reused_E122", "fresh_E123"):
        counts = tuple(item.count for item in result.entries if item.origin == origin)
        counters[origin] = {"representatives": len(counts),
                            "half_visits": sum(count.half_visits for count in counts),
                            "left_bucket_join_visits": sum(count.left_keys for count in counts),
                            "vector_updates": sum(count.vector_updates for count in counts),
                            "extraction_visits": sum(count.extraction_visits for count in counts),
                            "extraction_vector_updates": sum(count.extraction_vector_updates for count in counts)}
    return {"recorded": counters, "counter_scope": "completed_mass_records_only",
            "interrupted_mass_work_unknown": result.interrupted_mass_work_unknown,
            "total_mass_work_counter_complete": not result.interrupted_mass_work_unknown,
            "other_work_excluded": "input validation, histogram/sample checks, tuple coordinates, Horner, output and source hashing"}
