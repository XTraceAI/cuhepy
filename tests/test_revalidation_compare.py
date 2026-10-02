"""Offline analyzer contracts; no crypto or benchmark workload is started."""

import hashlib
import json

import pytest

from benchmarks import revalidation_compare as compare


def block(identity, baseline, candidate, **extra):
    return {"block_id": identity, "baseline": baseline, "candidate": candidate,
            "unit": "s", "statistic": "median", "scope": "elapsed_online_request", **extra}


def test_bootstrap_preserves_pairing_under_process_scale_variation():
    rows = [block("a", 1, .5), block("b", 1000, 500), block("c", .01, .005)]
    result = compare.paired_ratio_report(rows, draws=200)
    assert result["geometric_mean_candidate_over_baseline"] == pytest.approx(.5)
    assert result["block_bootstrap_95_interval"] == pytest.approx([.5, .5])
    assert result["independent_process_blocks"] == 3
    assert result["small_sample_inference_provisional"]


def test_one_process_does_not_get_query_level_uncertainty():
    result = compare.paired_ratio_report([block("one-process-many-queries", 10, 9)], draws=100)
    assert result["block_bootstrap_95_interval"] is None
    assert result["margin_sensitivity_not_universal_acceptance_thresholds"]["0"] == "insufficient_independent_blocks"


@pytest.mark.parametrize("replacement", [{"unit": "ms"}, {"statistic": "mean"}, {"scope": "whole_process"}])
def test_bootstrap_refuses_incompatible_measurement_boundaries(replacement):
    with pytest.raises(ValueError, match="compatible"):
        compare.paired_ratio_report([block("a", 1, .9), block("b", 1, .9, **replacement)], draws=100)


def test_bootstrap_refuses_aliases_and_nonpositive_measurements():
    with pytest.raises(ValueError):
        compare.paired_ratio_report([block("same", 1, .9), block("same", 1, .9)], draws=100)
    with pytest.raises(ValueError):
        compare.paired_ratio_report([block("a", 0, .9)], draws=100)


def test_generic_timings_keep_paths_units_estimators_and_process_scope():
    raw = {"summary": {"full/cpu": {"local_total_s": {"mean": 2, "median": 1.8}}},
           "samples": [{"answer_ms": 5, "response_bytes": 99}], "controller_wall_s": 12}
    values = compare.flatten_timings(raw)
    assert values["/summary/full~1cpu/local_total_s/mean"].statistic == "mean"
    assert values["/summary/full~1cpu/local_total_s/median"].statistic == "median"
    assert values["/samples/0/answer_ms"].unit == "ms"
    assert values["/controller_wall_s"].scope == "whole_process_or_controller"
    assert "/samples/0/response_bytes" not in values


def test_reported_interval_endpoints_are_not_point_mean_estimates():
    raw = {"query_wall_s": {"mean": 1, "process_bootstrap_mean_95_interval": [.8, 1.2]}}
    values = compare.flatten_timings(raw)
    assert values["/query_wall_s/mean"].statistic == "mean"
    assert values["/query_wall_s/process_bootstrap_mean_95_interval/0"].statistic == "reported_interval_bound"


def test_identity_matched_path_still_refuses_different_units():
    a = compare.Timing("/same", "s", "median", "online", 1)
    b = compare.Timing("/same", "ms", "median", "online", 1000)
    result = compare.compare_timings({a.path: a}, {b.path: b})
    assert not result["matched"] and result["incompatible"] == ["/same"]


def test_changed_process_sample_count_refuses_index_based_trial_join():
    old = {"trials": [{"answer_ms": 1}, {"answer_ms": 2}], "summary": {"answer_ms": 1.5}}
    new = {"trials": [{"answer_ms": 1}], "summary": {"answer_ms": 1}}
    issues = compare.sequence_alignment_issues(old, new)
    assert issues == [{"path": "/trials", "reason": "sequence_length_changed",
                       "historical_length": 2, "repeat_length": 1}]
    values = compare.aligned_paths(compare.flatten_timings(new), issues)
    assert set(values) == {"/summary/answer_ms"}


def test_reordered_variant_rows_do_not_compare_different_methods_at_same_index():
    old = [{"method": "full", "answer_ms": 1}, {"method": "delta", "answer_ms": .9}]
    new = list(reversed(old))
    issues = compare.sequence_alignment_issues(old, new)
    assert len(issues) == 2
    assert not compare.aligned_paths(compare.flatten_timings(new), issues)


def test_ciphertext_randomness_does_not_make_fixed_summary_rows_unaligned():
    old = [{"method": "full", "ciphertext": [1, 2], "answer_ms": 1}]
    new = [{"method": "full", "ciphertext": [4, 5], "answer_ms": 2}]
    assert not compare.sequence_alignment_issues(old, new)


def test_random_ciphertexts_and_private_phase_are_not_exact_counts():
    a = {"n": 32, "ciphertext": [123, 456], "maximum_unreduced_integer_phase": 234,
         "all_scores_exact": True, "response_body_bytes": 128}
    b = {**a, "ciphertext": [987, 654], "maximum_unreduced_integer_phase": 999}
    result = compare.compare_semantics(compare.semantic_observations(a), compare.semantic_observations(b))
    assert not result["labeled_count_observations"]["changed"]
    assert result["labeled_count_observations"]["matched_paths"] == 1
    assert result["serialized_payload_size_observations"]["matched_paths"] == 1
    assert not result["reported_exact_checks"]["changed"]


def test_changed_exact_assertion_is_reported_independently_of_timing():
    a = compare.semantic_observations({"all_scores_exact": True, "answer_ms": 1})
    b = compare.semantic_observations({"all_scores_exact": False, "answer_ms": .1})
    assert compare.compare_semantics(a, b)["reported_exact_checks"]["changed"] == [
        {"metric_path": "/all_scores_exact", "historical": True, "repeat": False}]


def test_serialized_payload_variation_is_separate_from_exact_geometry():
    a = compare.semantic_observations({"count": 8, "response_bytes": 4226945,
                                       "warm_median_bytes": {"response_bytes": 4226945.5},
                                       "public_keys_bytes": 4354, "resident_index_bytes": 123})
    b = compare.semantic_observations({"count": 8, "response_bytes": 4226941,
                                       "warm_median_bytes": {"response_bytes": 4226941.5},
                                       "public_keys_bytes": 4353, "resident_index_bytes": 456})
    result = compare.compare_semantics(a, b)
    assert not result["labeled_count_observations"]["changed"]
    assert len(result["serialized_payload_size_observations"]["changed"]) == 3
    assert "/resident_index_bytes" not in a["serialized_payload_size_observations"]


def test_serialized_body_sizes_do_not_imply_random_ciphertext_count_changes():
    a = compare.semantic_observations({"request_body_bytes": 20801, "query_body_bytes_model": 1024})
    b = compare.semantic_observations({"request_body_bytes": 20803, "query_body_bytes_model": 1024})
    result = compare.compare_semantics(a, b)
    assert not result["labeled_count_observations"]["changed"]
    assert result["serialized_payload_size_observations"]["changed"] == [
        {"metric_path": "/request_body_bytes", "historical": 20801, "repeat": 20803}]


def test_lifecycle_implementation_and_trace_length_are_not_process_replications():
    contrast = {"contrast": "E43/full_reencrypt->sparse_delta/full_lifetime_stage_sum_s", "geometry": {}}
    raw = {"kind": "pending_mask_complete_lifecycle", "rank": 128,
           "owner_arithmetic": "python", "update_count": 4}
    signatures = {compare.contrast_signature(raw, contrast),
                  compare.contrast_signature({**raw, "owner_arithmetic": "numpy"}, contrast),
                  compare.contrast_signature({**raw, "update_count": 8}, contrast)}
    assert len(signatures) == 3


def test_factory_vectorized_control_flag_is_a_distinct_workload_signature():
    contrast = {"contrast": "E49/plaintext->encrypted_index/offline_production_and_check_s", "geometry": {}}
    raw = {"kind": "encrypted_index_trusted_factory", "vectorized_plaintext_control": False}
    assert compare.contrast_signature(raw, contrast) != compare.contrast_signature(
        {**raw, "vectorized_plaintext_control": True}, contrast)


def test_e26_full_and_crt_masks_extract_cpu_cuda_separately():
    raw = {"result": {"summary": {label: {"evaluate_s": {"median": v}, "local_total_s": {"median": v + 1}}
                                   for label, v in [("full/cpu", 100), ("crt_masks/cpu", 50),
                                                    ("full/cuda", 2), ("crt_masks/cuda", 1.9)]}}}
    rows = {r["contrast"]: r for r in compare.measured_contrasts(raw)}
    assert rows["full->crt_masks/cpu/evaluate_s"]["candidate"] == 50
    assert rows["full->crt_masks/cuda/local_total_s"]["baseline"] == 3
    assert len(rows) == 4


def test_unrelated_list_summary_is_not_a_variant_dictionary():
    assert compare.measured_contrasts({"kind": "E79", "summary": [{"dataset": "fixture", "metrics": {}}]}) == []
    assert compare.measured_contrasts({"result": [{"count": 1}], "summary": []}) == []


def test_e77_charges_factory_and_keeps_geometries_separate():
    raw = {"kind": "public_seed_conditioned_affine_query_gate_known_control", "cases": [
        {"n": 32, "q": 97, "t": 3, "eta": 1, "paths": [""], "counts": [8],
         "samples": [{"baseline_client_stage_sum_ms": 2,
                      "affine_client_plus_trusted_factory_stage_sum_ms": 2.2}]}]}
    row, = compare.measured_contrasts(raw)
    assert row["candidate"] == 2.2 and row["unit"] == "ms"
    assert row["geometry"]["counts"] == [8]
    assert row["scope"] == "stage_sum_model"


def test_e27_allocation_comparison_is_distinct_from_fullscan():
    raw = {"result": {"summary": {label: {"evaluate_s": {"median": v}, "local_total_s": {"median": v + .01}}
                                   for label, v in [("repair32/cpu", 1), ("allocated/cpu", .9)]}}}
    rows = compare.measured_contrasts(raw)
    assert {r["contrast"] for r in rows} == {
        "repair32->allocated/cpu/evaluate_s", "repair32->allocated/cpu/local_total_s"}
    assert rows[0]["candidate"] == .9


def test_e43_single_update_and_lifetime_are_distinct_stage_models():
    raw = {"summary": {method: {metric: {"median": value} for metric in (
        "total_update_stage_sum_s", "full_lifetime_stage_sum_s")}
        for method, value in [("full_reencrypt", 10), ("sparse_delta", 8)]}}
    rows = compare.measured_contrasts(raw)
    assert len(rows) == 2
    assert all(r["candidate"] / r["baseline"] == .8 for r in rows)
    assert {r["scope"] for r in rows} == {"stage_sum_model"}


def test_e49_stronger_numpy_control_and_offline_online_costs_are_separate():
    raw = {"kind": "encrypted_index_trusted_factory", "summary": {
        variant: {"offline_production_and_check_s": {"median": v},
                  "complete_local_online_elapsed_s": {"median": .05}}
        for variant, v in [("plaintext", .18), ("numpy_plaintext", .038), ("encrypted_index", .054)]}}
    rows = compare.measured_contrasts(raw)
    assert len(rows) == 4
    row = next(r for r in rows if r["contrast"] == "E49/numpy_plaintext->encrypted_index/offline_production_and_check_s")
    assert row["candidate"] / row["baseline"] > 1
    assert row["scope"] == "offline_stage_sum"


def test_current_source_label_remains_even_when_hashes_match():
    raw = {"source_sha256": {"runner.py": "abc"}, "git_head": "old"}
    identity = compare.source_identity(raw, raw, {"execution_mode": "current_source_confirmation"})
    assert identity["same_recorded_hash_map"]
    assert not identity["historical_source_replication_certified"]


def test_declared_metadata_adaptation_is_visible_and_requires_both_hashes():
    old = {"source_sha256": {"benchmarks/helper.py": "before", "arithmetic.py": "old-math"}}
    new = {"source_sha256": {"benchmarks/helper.py": "after", "arithmetic.py": "new-math"}}
    adaptations = {"source_copy": "/copy", "changes": [{"path": "/copy/benchmarks/helper.py",
        "reason": "relative metadata paths", "before_sha256": "before", "after_sha256": "after"}]}
    identity = compare.source_identity(old, new, {"execution_mode": "current_source_confirmation"}, adaptations)
    assert identity["changed_paths"] == ["arithmetic.py", "benchmarks/helper.py"]
    assert identity["changed_paths_without_exact_declared_before_after_match"] == ["arithmetic.py"]
    assert not identity["historical_source_replication_certified"]


def test_analyzer_detects_immutable_raw_mismatch(tmp_path):
    original = tmp_path / "original.json"
    original.write_text('{"n":32}')
    fresh = tmp_path / "fresh.json"
    fresh.write_text('{"n":32}')
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"entries": [{"original_raw": "original.json", "original_raw_sha256": "wrong"}]}))
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "receipt.json").write_text(json.dumps({"job": {"id": "one", "new_raw": str(fresh),
        "original_raws": ["original.json"]}, "returncode": 0,
        "new_raw_sha256": hashlib.sha256(fresh.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="historical raw"):
        compare.analyze(tmp_path, [inventory], runs, draws=100)


def test_analyzer_deduplicates_output_aliases_and_reports_resource_subset(tmp_path):
    raw = {"kind": "component_test", "source_sha256": {"runner.py": "old"},
           "result": {"dataset": "fixture", "count": 8, "dimension": 16, "summary": {
               label: {"evaluate_s": {"median": value}, "local_total_s": {"median": value + 1}}
               for label, value in [("full/cpu", 10), ("crt_masks/cpu", 5)]}}}
    originals = []
    for name in ("original.json", "alias.json"):
        path = tmp_path / name
        path.write_text(json.dumps(raw))
        originals.append({"original_raw": name, "original_raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"entries": originals}))
    runs = tmp_path / "runs"
    for index in range(2):
        folder = runs / str(index)
        folder.mkdir(parents=True)
        fresh = folder / "fresh.json"
        fresh.write_text(json.dumps({**raw, "source_sha256": {"runner.py": "changed"}}))
        (folder / "receipt.json").write_text(json.dumps({"job": {"id": str(index), "new_raw": str(fresh),
            "original_raws": ["original.json", "alias.json"]}, "returncode": 0,
            "new_raw_sha256": hashlib.sha256(fresh.read_bytes()).hexdigest(),
            "execution_mode": "current_source_confirmation", "driver_sha256": f"controller{index}",
            "resource_conditions": {"qualified_by_conditions": index == 1}}))
    report = compare.analyze(tmp_path, [inventory], runs, draws=100)
    assert len(report["comparisons"]) == 4
    assert len(report["paired_contrasts"]) == 2
    for contrast in report["paired_contrasts"]:
        assert contrast["all_recorded_blocks"]["independent_process_blocks"] == 2
        assert contrast["designated_low_load_blocks"]["independent_process_blocks"] == 1
        assert contrast["designated_low_load_blocks"]["block_bootstrap_95_interval"] is None
        assert len(contrast["controller_version_subsets"]) == 2
        assert all(s["paired_ratio_report"]["independent_process_blocks"] == 1
                   for s in contrast["controller_version_subsets"])
    assert report["comparisons"][0]["source_identity"]["changed_paths"] == ["runner.py"]
    assert not report["comparisons"][0]["source_identity"]["historical_source_replication_certified"]
