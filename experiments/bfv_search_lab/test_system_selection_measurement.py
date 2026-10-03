"""SB01 scheduler/recording tests; no HE, CUDA imports, fixtures or timing claims."""

import ast
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks import system_selection_measurement as lab  # noqa: E402


@pytest.mark.parametrize("mode,count,repeats,update", [("main", 32768, 5, 32), ("intrinsic", 16, 1, 16)])
def test_exact_registered_modes(mode, count, repeats, update):
    assert lab.Plan(mode, count, measured_queries=repeats, update_count=update).validate().mode == mode


@pytest.mark.parametrize("change", [
    {"count": True}, {"count": 32768.0}, {"count": 8192}, {"dimension": 511},
    {"n": 8192}, {"measured_queries": 6}, {"update_count": 31}, {"mode": "pilot"},
])
def test_no_unregistered_scale_or_type_alias(change):
    args = dict(mode="main", count=32768)
    args.update(change)
    with pytest.raises(ValueError):
        lab.Plan(**args).validate()


def test_query_schedule_contains_named_boundaries_and_no_crypto_randomness():
    warmup = [int(j % 3 == 0) for j in range(512)]
    words = lab.queries(lab.Plan("main", 32768), warmup)
    assert len(words) == 6 and words[0] == warmup
    assert words[1] == [0] * 512 and words[2] == [1] * 512
    assert words[3] == [j % 2 for j in range(512)]
    assert words == lab.queries(lab.Plan("main", 32768), warmup)
    assert "gmpy2" not in lab.__dict__ and "BFVClient" not in lab.__dict__


def test_every_round_has_every_variant_once():
    schedule = lab.orders(6)
    assert schedule == lab.orders(6)
    assert all(len(x) == 5 and set(x) == set(lab.VARIANTS) for x in schedule)
    assert len({tuple(x) for x in schedule}) > 1


def test_warmup_excluded_and_elapsed_kept_separate_from_stage_medians():
    samples = [{"warmup": True, "timings": {"local_total_s": 1000, "server_total_s": 1000}},
               {"warmup": False, "timings": {"local_total_s": 10, "server_total_s": 1}},
               {"warmup": False, "timings": {"local_total_s": 20, "server_total_s": 5}}]
    result = lab.summarize(samples)
    assert result["local_total_s"] == {"median": 15, "minimum": 10, "maximum": 20}
    assert result["server_total_s"]["median"] == 3
    with pytest.raises(ValueError):
        lab.summarize(samples[:1])


def test_inconsistent_phase_boundaries_cannot_be_summarized():
    with pytest.raises(ValueError):
        lab.summarize([{"warmup": False, "timings": {"local_total_s": 1}},
                       {"warmup": False, "timings": {"server_total_s": 1}}])


def test_stable_top3_with_ties():
    distances, top = lab.scores([[0, 0], [0, 0], [1, 1], [0, 0]], [0, 0])
    assert distances == [0, 0, 2, 0] and top == [0, 1, 3]


def test_recorder_never_serializes_returned_private_objects_and_retains_failure(tmp_path):
    rec = lab.Recorder(tmp_path / "events.jsonl")
    returned = object()
    _, value = rec.phase("fixture", "opaque", lambda: returned)
    assert value is returned

    def fail():
        raise ValueError("local fixture fails")

    with pytest.raises(ValueError):
        rec.phase("fixture", "deliberate_failure", fail)
    rec.close()
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert [x["kind"] for x in events] == ["phase_begin", "phase_end", "phase_begin", "phase_failed"]
    assert all(set(x) <= {"kind", "monotonic", "utc", "target", "phase", "elapsed_s"} for x in events)
    with pytest.raises(FileExistsError):
        lab.Recorder(tmp_path / "events.jsonl")


def complete_report():
    results = []
    for variant in lab.VARIANTS:
        samples = [{"repeat": i, "warmup": i == 0, "all_scores_and_top3_correct": True,
                    "query_bytes": 10, "response_bytes": 20,
                    "query_plaintext_sha256": str(i), "scores_sha256": str(i),
                    "timings": {x: 1 for x in lab.PHASES}} for i in range(2)]
        results.append({"variant": variant, "setup_timings": {"prepare_s": 1}, "samples": samples})
    return {"results": results, "updates": [
        {"variant": v, "replacement_rows": 16, "all_scores_and_top3_correct": True,
         "delta_packet_bytes": 10} for v in lab.VARIANTS]}


def test_partial_duplicate_or_unmatched_cohort_cannot_be_complete():
    plan = lab.Plan("intrinsic", 16, measured_queries=1, update_count=16)
    assert lab.validate_complete(plan, complete_report())
    for change in ("missing_variant", "missing_sample", "duplicate_variant", "unmatched_query",
                   "false_correctness", "unpaid_setup", "missing_update"):
        report = complete_report()
        if change == "missing_variant":
            report["results"].pop()
        elif change == "missing_sample":
            report["results"][0]["samples"].pop()
        elif change == "duplicate_variant":
            report["results"][0]["variant"] = lab.VARIANTS[1]
        elif change == "unmatched_query":
            report["results"][0]["samples"][1]["query_plaintext_sha256"] = "other"
        elif change == "false_correctness":
            report["results"][0]["samples"][1]["all_scores_and_top3_correct"] = False
        elif change == "unpaid_setup":
            report["results"][0]["setup_timings"] = {}
        else:
            report["updates"].pop()
        with pytest.raises(ValueError):
            lab.validate_complete(plan, report)


def test_aligned_replacement_preserves_ids_and_covers_exact_existing_tiles():
    for plan in (lab.Plan("main", 32768), lab.Plan("intrinsic", 16, measured_queries=1, update_count=16)):
        for variant in lab.VARIANTS:
            ids, ciphertexts = lab.replacement_geometry(plan, variant)
            assert ids == tuple(range(plan.update_count))
            if variant in lab.VARIANTS[:2]:
                assert ciphertexts == 1 and max(ids) // 32 == 0
            elif variant in lab.VARIANTS[2:4]:
                assert ciphertexts == plan.update_count
            else:
                assert ciphertexts is None


def test_resource_cap_cannot_be_missing_widened_or_boolean_alias():
    assert lab.validate_resource_caps(dict(lab.RESOURCE_CAPS))
    for key in lab.RESOURCE_CAPS:
        for value in (None, True, 0, -1, lab.RESOURCE_CAPS[key] + 1):
            changed = dict(lab.RESOURCE_CAPS, **{key: value})
            with pytest.raises(ValueError):
                lab.validate_resource_caps(changed)
        missing = dict(lab.RESOURCE_CAPS)
        del missing[key]
        with pytest.raises(ValueError):
            lab.validate_resource_caps(missing)


def test_public_coefficient_context_closes_existing_decoder_state_contract():
    # Parse the inherited decoder's attribute contract without importing its HE
    # modules or constructing a key. This catches the observed missing-pk glue.
    tree = ast.parse((lab.ROOT / "benchmarks/coefficient_search_lab.py").read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Case")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "unpack")
    adapter = object.__new__(lab.BGVAdapter)
    adapter.pk = SimpleNamespace(n=16384, t=1031, q=65537, key_id="00" * 32, fresh_bound=123)
    context = adapter.coeff_context()
    paths = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.Attribute):
            continue
        path, value = [], node
        while isinstance(value, ast.Attribute):
            path.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name) and value.id == "self":
            paths.add(tuple(reversed(path)))
    assert ("pk", "fresh_bound") in paths
    for path in paths:
        value = context
        for attribute in path:
            value = getattr(value, attribute)
    assert context.pk is adapter.pk and not hasattr(context, "sk")
