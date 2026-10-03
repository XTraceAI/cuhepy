"""Sixteen bounded E123 parser/controller cases; no scientific N16 fixture.

Synthetic positive counts test trusted-controller behavior, not actual tiny
field probabilities. Historical E122 tests are retained rather than rerun here.
"""

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json

import pytest

from experiments.bfv_search_lab import joint_root as old
from experiments.bfv_search_lab import joint_root_census as lab


def inventory():
    return old.orbit_inventory(old.Context(4, 17, 2), 2)


def zero_count(ctx, roots):
    leaves = 3 ** (ctx.n // 2)
    return old.Count(roots, 1, 3 ** ctx.n, ctx.n, 2 * leaves, leaves, leaves,
                     2 * (leaves - 1), 0, 0, None).validate()


def serialized_prefix(inv, number=1):
    counts = json.loads(json.dumps([asdict(zero_count(inv.context, orbit.representative))
                                   for orbit in inv.orbits[:number]]))
    lines = tuple(json.dumps({"index": index, "count": count, "structured_quartic": False}) + "\n"
                  for index, count in enumerate(counts, 1))
    return counts, lines


def test_duplicate_json_keys_are_rejected_before_array_conversion():
    for text in ('{"n":4,"n":4}', '{"count":{"roots":[1],"roots":[1]}}',
                 '{"entries":[{"index":1,"index":1}]}'):
        with pytest.raises(ValueError, match="Duplicate"):
            lab.strict_json(text)
    assert lab.strict_json('{"a":[1,null,true]}') == {"a": [1, None, True]}


def test_noninteger_json_numbers_are_rejected_without_python_equality_aliases():
    for value in ("1.0", "1e0", "NaN", "Infinity", "-Infinity"):
        with pytest.raises(ValueError, match="Noninteger"):
            lab.strict_json('{"nested":[' + value + ']}')
    with pytest.raises(ValueError):
        lab.strict_json(b'{"n":4}')


def test_context_parser_rejects_aliases_missing_fields_and_unknown_fields():
    original = asdict(old.Context(4, 17, 2))
    assert lab.parse_context(original) == old.Context(4, 17, 2)
    for name in original:
        for alias in (True, float(original[name]), str(original[name])):
            malformed = dict(original, **{name: alias})
            with pytest.raises(ValueError):
                lab.parse_context(malformed)
    for malformed in ({"n": 4, "q": 17}, dict(original, unused=0), list(original)):
        with pytest.raises(ValueError):
            lab.parse_context(malformed)


def test_inventory_roundtrip_checks_all_coverage_transporter_and_nested_alias_fields():
    inv = inventory()
    original = json.loads(json.dumps(asdict(inv)))
    assert lab.parse_inventory(original) == inv
    variants = []
    for key in ("orbits", "assignments"):
        malformed = deepcopy(original)
        malformed[key].pop()
        variants.append(malformed)
    for path in (("root_count",), ("orbits", 0, "representative", 0),
                 ("orbits", 0, "stabilizer", 0), ("assignments", 0, 2)):
        malformed = deepcopy(original)
        cursor = malformed
        for key in path[:-1]:
            cursor = cursor[key]
        cursor[path[-1]] = float(cursor[path[-1]])
        variants.append(malformed)
    malformed = deepcopy(original)
    malformed["assignments"][0][2] = 0
    variants.append(malformed)
    malformed = deepcopy(original)
    malformed["orbits"][0]["unused"] = 0
    variants.append(malformed)
    for malformed in variants:
        with pytest.raises(ValueError):
            lab.parse_inventory(malformed)


def test_count_parser_rejects_all_integer_alias_coordinates_and_incomplete_schema():
    inv = inventory()
    count = zero_count(inv.context, inv.orbits[0].representative)
    original = json.loads(json.dumps(asdict(count)))
    assert lab.parse_count(original) == count
    for name, value in original.items():
        if type(value) is int:
            for alias in (float(value), True):
                with pytest.raises(ValueError):
                    lab.parse_count(dict(original, **{name: alias}))
    for alias in (True, 1.0):
        malformed = deepcopy(original)
        malformed["roots"][0] = alias
        with pytest.raises(ValueError):
            lab.parse_count(malformed)
    for malformed in (dict(original, extra=0), {k: v for k, v in original.items() if k != "witness"}):
        with pytest.raises(ValueError):
            lab.parse_count(malformed)


def test_reused_prefix_preserves_original_line_hash_without_evaluating_a_mass():
    inv = inventory()
    counts, lines = serialized_prefix(inv)
    entries = lab.reuse_prefix(inv, counts, lines)
    assert entries[0].origin == "reused_E122"
    assert entries[0].original_record_sha256 == hashlib.sha256(lines[0].encode()).hexdigest()
    assert entries[0].count == lab.parse_count(counts[0])
    assert entries[0].orbit_size == len(inv.orbits[0].members)


def test_reuse_rejects_missing_duplicate_reordered_unknown_and_raw_mismatched_records():
    inv = inventory()
    counts, lines = serialized_prefix(inv, len(inv.orbits))
    variants = ((counts, lines[:-1]), (counts, (lines[0],) + lines),
                (counts, tuple(reversed(lines))))
    for raw_counts, serialized in variants:
        with pytest.raises(ValueError):
            lab.reuse_prefix(inv, raw_counts, serialized)
    item = json.loads(lines[0])
    item["count"]["roots"] = [1, 7]
    with pytest.raises(ValueError):
        lab.reuse_prefix(inv, counts[:1], (json.dumps(item) + "\n",))
    mismatch = deepcopy(counts[:1])
    mismatch[0]["left_keys"] -= 1
    with pytest.raises(ValueError, match="mismatch"):
        lab.reuse_prefix(inv, mismatch, lines[:1])


def test_prefix_ordinal_packet_label_and_line_framing_are_strict():
    inv = inventory()
    counts, lines = serialized_prefix(inv)
    item = json.loads(lines[0])
    for malformed in (dict(item, index=True), dict(item, index=1.0),
                      dict(item, structured_quartic=0), dict(item, extra=0)):
        with pytest.raises(ValueError):
            lab.reuse_prefix(inv, counts, (json.dumps(malformed) + "\n",))
    for malformed in (lines[0].rstrip(), lines[0] + "\n", lines[0].encode()):
        with pytest.raises(ValueError):
            lab.reuse_prefix(inv, counts, (malformed,))
    assert lab.validate_zero_accounting(1, False) is True
    for included, added in ((True, False), (1.0, False), (0, False), (1, 0), (1, True)):
        with pytest.raises(ValueError):
            lab.validate_zero_accounting(included, added)


def test_entry_origin_hash_index_size_and_metadata_types_are_strict():
    inv = inventory()
    value = lab.entry(inv, 1, zero_count(inv.context, inv.orbits[0].representative), origin="fresh_E123")
    for malformed in (replace(value, index=True), replace(value, index=1.0),
                      replace(value, orbit_size=float(value.orbit_size)),
                      replace(value, orbit_size=value.orbit_size + 1),
                      replace(value, structured_quartic=0), replace(value, origin="reused"),
                      replace(value, original_record_sha256="0" * 64),
                      replace(value, original_record_sha256="G" * 64)):
        with pytest.raises(ValueError):
            malformed.validate(inv)


def test_continuation_evaluates_only_remaining_representatives_exactly_once_ascending():
    inv = inventory()
    counts, lines = serialized_prefix(inv)
    reused = lab.reuse_prefix(inv, counts, lines)
    visits, flushed = [], []

    def evaluate(roots):
        visits.append(roots)
        return zero_count(inv.context, roots)

    result = lab.continue_census(inv, reused, evaluate, on_complete=flushed.append)
    assert result.status == "completed"
    assert visits == [orbit.representative for orbit in inv.orbits[1:]]
    assert [item.index for item in flushed] == list(range(2, len(inv.orbits) + 1))
    assert result.entries[:1] == reused
    assert all(item.origin == "fresh_E123" for item in result.entries[1:])


def test_all_reused_complete_coverage_never_calls_the_evaluator():
    inv = inventory()
    counts, lines = serialized_prefix(inv, len(inv.orbits))
    reused = lab.reuse_prefix(inv, counts, lines)

    def forbidden(_roots):
        raise AssertionError("A reused mass was reevaluated")

    result = lab.continue_census(inv, reused, forbidden)
    assert result.status == "completed" and result.entries == reused


def test_positive_synthetic_record_does_not_restore_the_e122_first_counterexample_stop():
    inv = inventory()
    visits = []

    def synthetic(roots):
        visits.append(roots)
        count = zero_count(inv.context, roots)
        if roots == inv.orbits[0].representative:
            #Trusted controller seam only: this is NOT a field probability.
            count = replace(count, total_count=9, witness=(1, 1, 1, 1), extraction_visits=1)
        return count

    result = lab.continue_census(inv, (), synthetic)
    assert result.status == "completed" and len(visits) == len(inv.orbits)
    assert result.entries[0].count.total_count == 9


def test_resource_stop_keeps_only_completed_records_including_durable_callback_boundary():
    inv = inventory()
    counts, lines = serialized_prefix(inv)
    reused = lab.reuse_prefix(inv, counts, lines)
    for error in (TimeoutError, MemoryError):
        calls = []

        def evaluate(roots, calls=calls, error=error):
            calls.append(roots)
            if len(calls) == 2:
                raise error("synthetic registered resource stop")
            return zero_count(inv.context, roots)

        result = lab.continue_census(inv, reused, evaluate)
        assert result.status == "resource_bounded_inconclusive"
        assert len(result.entries) == 2 and result.interrupted_mass_work_unknown

    def interrupted_append(_item):
        raise TimeoutError("Incomplete durable append")

    result = lab.continue_census(inv, reused, lambda roots: zero_count(inv.context, roots),
                                 on_complete=interrupted_append)
    assert result.entries == reused


def test_mismatched_evaluator_or_reordered_reuse_fails_instead_of_silent_continuation():
    inv = inventory()
    counts, lines = serialized_prefix(inv, len(inv.orbits))
    reused = lab.reuse_prefix(inv, counts, lines)
    with pytest.raises(ValueError):
        lab.continue_census(inv, tuple(reversed(reused)), lambda roots: zero_count(inv.context, roots))
    wrong = zero_count(inv.context, inv.orbits[-1].representative)
    with pytest.raises(ValueError):
        lab.continue_census(inv, (), lambda _roots: wrong)
    with pytest.raises(ValueError):
        lab.continue_census(inv, (), lambda _roots: None)


def test_complete_weighted_moment_is_not_union_without_explicit_valid_norm_bridge():
    inv = inventory()
    result = lab.continue_census(inv, (), lambda roots: zero_count(inv.context, roots))
    general = lab.complete_summary(inv, result)
    assert general["factorial_moment"]["numerator"] == len(inv.assignments)
    assert general["union_event"] is None
    bridge = lab.NormBridge(inv.context, inv.root_count)
    exact = lab.complete_summary(inv, result, norm_bridge=bridge)
    assert exact["union_event"]["numerator"] == 1
    assert exact["union_event"]["nonzero_event_count"] == 0
    assert exact["union_event"]["zero_added_once"] is True
    partial = lab.Result("resource_bounded_inconclusive", 0, result.entries[:1], True)
    with pytest.raises(ValueError, match="complete"):
        lab.complete_summary(inv, partial, norm_bridge=bridge)
    with pytest.raises(ValueError):
        lab.complete_summary(inv, result, norm_bridge=lab.NormBridge(old.Context(4, 41, 3), 2))
    with pytest.raises(ValueError):
        lab.NormBridge(inv.context, True).validate()


def test_work_counters_separate_historical_and_fresh_work_and_reject_false_completion():
    inv = inventory()
    counts, lines = serialized_prefix(inv)
    reused = lab.reuse_prefix(inv, counts, lines)
    result = lab.continue_census(inv, reused, lambda roots: zero_count(inv.context, roots))
    counters = lab.work_counters(result)
    assert counters["recorded"]["reused_E122"]["representatives"] == 1
    assert counters["recorded"]["fresh_E123"]["representatives"] == len(inv.orbits) - 1
    assert counters["recorded"]["fresh_E123"]["left_bucket_join_visits"] == 9 * (len(inv.orbits) - 1)
    assert counters["total_mass_work_counter_complete"] is True
    for malformed in (replace(result, entries=result.entries[:-1]),
                      replace(result, reused_count=True),
                      replace(result, interrupted_mass_work_unknown=0)):
        with pytest.raises(ValueError):
            malformed.validate(inv)
