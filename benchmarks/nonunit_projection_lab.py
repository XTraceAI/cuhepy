#!/usr/bin/env python3
"""E118 frozen finite public algebra cohort and one exact correctness model."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab import nonunit_projection as lab  # noqa: E402

WORK = REPO.parent / "research-data/nonunit-projection-20261003"
RAW = REPO / "benchmarks/results/publication-nonunit-projection-20261003.json"
PREREG = "docs/research/nonunit-projection-preregistration-20261003.md"
FROZEN_SHA = "479ad6d8c90de7127fe5b96a9c7aacd40b6ddea32285ce41073904589bfeca7d"
SOURCES = [PREREG, "experiments/bfv_search_lab/nonunit_projection.py",
           "experiments/bfv_search_lab/test_nonunit_projection.py",
           "benchmarks/nonunit_projection_lab.py",
           "experiments/bfv_search_lab/one_prime_bounds.py",
           "experiments/bfv_search_lab/query_quantizer_law.py",
           "experiments/bfv_search_lab/compressed_query_bgv.py",
           "experiments/bfv_search_lab/support_bounds_bgv.py",
           "src/cuhepy/bfv/scheme.py", "experiments/bfv_search_lab/shallow_bgv.py",
           "benchmarks/results/publication-one-prime-20261003.json",
           "benchmarks/results/publication-query-quantizer-law-20261003.json",
           "docs/research/query-secret-law-card-20261003.md"]
E115 = REPO.parent / "research-data/seeded-correctness-20261003/secret-law/one-drop23-exact-card.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(value):
    if type(value) is Fraction:
        return {"numerator_hex": hex(value.numerator), "denominator_hex": hex(value.denominator)}
    if is_dataclass(value):
        return encode(asdict(value))
    if type(value) is dict:
        return {str(key): encode(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [encode(item) for item in value]
    return value


def write_json(path, value):
    path.write_text(json.dumps(encode(value), indent=2) + "\n")


def require(condition, name, evidence):
    if not condition:
        write_json(WORK / "main-failure.json", {"check": name, "evidence": evidence})
        raise AssertionError(name)


def schoolbook(left, right):
    """Independent literal integer product, not the signed Toeplitz formula."""
    n = len(left)
    output = [0] * n
    for i in range(n):
        for j in range(n):
            position = i + j
            term = left[i] * right[j]
            if position >= n:
                position -= n
                term = -term
            output[position] += term
    return tuple(output)


def schoolbook_matrix(secret):
    columns = [schoolbook(secret, tuple(int(i == j) for i in range(len(secret))))
               for j in range(len(secret))]
    return tuple(tuple(column[i] for column in columns) for i in range(len(secret)))


def bareiss(matrix):
    """Independent fraction-free determinant with exact divisibility checks."""
    rows = [list(row) for row in matrix]
    sign, previous = 1, 1
    for column in range(len(rows) - 1):
        pivot = next((i for i in range(column, len(rows)) if rows[i][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            rows[column], rows[pivot] = rows[pivot], rows[column]
            sign *= -1
        current = rows[column][column]
        for i in range(column + 1, len(rows)):
            for j in range(column + 1, len(rows)):
                numerator = rows[i][j] * current - rows[i][column] * rows[column][j]
                if numerator % previous:
                    raise ArithmeticError("Bareiss division is not exact")
                rows[i][j] = numerator // previous
            rows[i][column] = 0
        previous = current
    return sign * rows[-1][-1]


def gaussian_rank(matrix, q):
    """Independent row echelon, avoiding the implementation's normalization."""
    rows = [[value % q for value in row] for row in matrix]
    rank = 0
    for column in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(rank + 1, len(rows)):
            # A division-free row update modulo the prime field.
            lead, factor = rows[rank][column], rows[i][column]
            if factor:
                rows[i] = [(lead * a - factor * b) % q
                           for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
        if rank == len(rows):
            break
    return rank


def ternary_panel():
    ctx = lab.Context(8, 17, 3).validate()
    certificate = lab.norm_certificate(8, 17, 8)
    roots = tuple(pow(3, 2*j + 1, 17) for j in range(8))
    counts, records, determinant_values = Counter(), [], Counter()
    for secret in product((-1, 0, 1), repeat=8):
        matrix = schoolbook_matrix(secret)
        require(matrix == lab.multiplication_matrix(secret), "integer_matrix", secret)
        determinant = bareiss(matrix)
        rank = gaussian_rank(matrix, 17)
        require(rank == lab.rank_mod(matrix, 17), "modular_rank", secret)
        zeros = tuple(alpha for alpha in roots
                      if sum(value * pow(alpha, j, 17) for j, value in enumerate(secret)) % 17 == 0)
        require(zeros == lab.zero_roots(secret, ctx), "literal_roots", secret)
        require(8 - rank == len(zeros), "split_rank_vs_roots", secret)
        prefix_rank = gaussian_rank(matrix[:certificate.prefix_length], 17)
        require(prefix_rank == lab.projection_rank(secret, 17, tuple(range(certificate.prefix_length))),
                "prefix_rank_independence", secret)
        norm2 = sum(value * value for value in secret)
        nullity = 8 - rank
        if norm2:
            require(determinant != 0, "nonzero_integer_determinant", secret)
            require(determinant % (17 ** nullity) == 0, "prime_power_divisibility", secret)
            require(abs(determinant) <= norm2 ** 4 <= 8 ** 4, "parseval_norm_bound", secret)
            require(nullity <= certificate.nullity_cap, "public_nullity_cap", secret)
            require(prefix_rank == certificate.prefix_length, "fixed_prefix_surjectivity", secret)
            counts["unit_nonzero" if nullity == 0 else "nonunit_nonzero"] += 1
        else:
            require(determinant == 0 and rank == prefix_rank == 0, "zero_exception", secret)
            counts["zero_exception"] += 1
        counts[f"nullity_{nullity}"] += 1
        determinant_values[determinant] += 1
        records.append({"secret": secret, "determinant": determinant,
                        "norm2": norm2, "modular_nullity": nullity,
                        "zero_roots": zeros, "prefix_rank": prefix_rank})
    path = WORK / "all-6561-public-ternary-records.json"
    write_json(path, {"context": ctx, "norm_certificate": certificate, "records": records})
    return {"public_context": ctx, "norm_certificate": certificate,
            "distinct_ternary_states": len(records), "counts": dict(sorted(counts.items())),
            "matrix_coefficient_comparisons": len(records) * 64,
            "root_zero_membership_comparisons": len(records) * 8,
            "determinant_distinct_values": len(determinant_values),
            "all_nonzero_norm_divisibility_rank_prefix_checks_passed": True,
            "zero_excluded_from_nonzero_claim": True,
            "tiny_distribution_not_large_unit_probability": True,
            "records_path": str(path), "records_sha256": sha(path)}


def mask_panel(secret, name):
    ctx = lab.Context(4, 17, 2).validate()
    norm2 = sum(value * value for value in secret)
    certificate = lab.norm_certificate(4, 17, norm2)
    matrix = schoolbook_matrix(secret)
    require(matrix == lab.multiplication_matrix(secret), "mask_matrix", secret)
    rank = gaussian_rank(matrix, 17)
    zeros = lab.zero_roots(secret, ctx)
    require(4 - rank == len(zeros), "mask_rank_roots", secret)
    prefix, translated_prefix, image, translated_image, arbitrary = (Counter() for _ in range(5))
    translation = (1, 2, 3, 4)
    mask_count = 0
    for mask in product(range(17), repeat=4):
        literal = tuple(value % 17 for value in schoolbook(secret, mask))
        require(literal == lab.apply_matrix(matrix, mask, 17), "full_mask_product", mask)
        shifted = tuple((b - value) % 17 for b, value in zip(translation, literal, strict=True))
        prefix[literal[:certificate.prefix_length]] += 1
        translated_prefix[shifted[:certificate.prefix_length]] += 1
        image[literal] += 1
        translated_image[shifted] += 1
        if name == "X2_minus_4":
            arbitrary[(literal[0], literal[2])] += 1
            require(literal[2] == 4 * literal[0] % 17, "arbitrary_subset_dependency", mask)
        mask_count += 1
    expected_prefix = 17 ** certificate.prefix_length
    expected_mass = 17 ** (4 - certificate.prefix_length)
    require(len(prefix) == len(translated_prefix) == expected_prefix,
            "full_prefix_support", name)
    require(set(prefix.values()) == set(translated_prefix.values()) == {expected_mass},
            "exact_prefix_uniformity", name)
    require(len(image) == len(translated_image) == 17 ** rank,
            "affine_image_cardinality", name)
    require(set(image.values()) == set(translated_image.values()) == {17 ** (4 - rank)},
            "uniform_image_fibers", name)
    for vector in image:
        require(all(sum(value * pow(alpha, i, 17) for i, value in enumerate(vector)) % 17 == 0
                    for alpha in zeros), "image_parity_checks", vector)
    for vector in translated_image:
        require(all(sum((value - translation[i]) * pow(alpha, i, 17)
                        for i, value in enumerate(vector)) % 17 == 0 for alpha in zeros),
                "translated_coset_checks", vector)
    if arbitrary:
        require(len(arbitrary) == 17 and set(arbitrary.values()) == {17 ** 3},
                "arbitrary_subset_not_uniform_2D", name)
    hist = WORK / f"{name}-exact-full-histograms.json"
    write_json(hist, {"context": ctx, "public_nonternary_secret": secret,
                     "fixed_translation": translation,
                     **{label: [{"vector": vector, "mass": mass} for vector, mass in sorted(count.items())]
                        for label, count in (("prefix", prefix), ("translated_prefix", translated_prefix),
                                             ("image", image), ("translated_image", translated_image),
                                             ("arbitrary_0_2", arbitrary))}})
    return {"context": ctx, "public_nonternary_secret": secret,
            "not_actual_ternary_secret_law": True, "norm_certificate": certificate,
            "actual_nullity": 4 - rank, "actual_zero_roots": zeros,
            "full_masks_enumerated": mask_count, "mask_component_comparisons": mask_count * 4,
            "fixed_translation": translation, "uniform_prefix_support": len(prefix),
            "uniform_prefix_mass_each": expected_mass,
            "full_image_support": len(image), "full_image_fibers_each": 17 ** (4 - rank),
            "full_vector_not_uniform_over_complete_ring": len(image) < 17 ** 4,
            "arbitrary_subset_0_2_rank": lab.projection_rank(secret, 17, (0, 2)) if arbitrary else None,
            "arbitrary_subset_0_2_support": len(arbitrary) if arbitrary else None,
            "arbitrary_subset_0_2_mass_each": 17 ** 3 if arbitrary else None,
            "all_prefix_image_coset_checks_passed": True,
            "histogram_path": str(hist), "histogram_sha256": sha(hist)}


def large_card():
    model = lab.Model(16384, 512, 8192, 1152921504606748673, 4294953991, 1031, 21, 15, 23)
    result = lab.correctness_model(model)
    reference = json.loads(E115.read_text())
    comparisons = {}
    for key, value in result.items():
        if key not in reference:
            continue
        expected = reference[key]
        if type(value) is Fraction:
            expected = Fraction(int(expected["numerator"]), int(expected["denominator"]))
        require(value == expected, "E115_independent_literal_model_" + key, {"actual": value, "expected": expected})
        comparisons[key] = True
    require(len(comparisons) >= 25, "complete_reference_comparison_scope", len(comparisons))
    require(result["generic_given_derived_lemma_ratio"] == reference["ordinary_same_control_ratio"] == 1,
            "generic_given_lemma_equality", {})
    return {"model": model, "result": result, "E115_reference_path": str(E115),
            "E115_reference_sha256": sha(E115), "exact_equal_common_fields": comparisons,
            "comparison_field_count": len(comparisons),
            "conditional_ideal_only": True,
            "precise_consequence_originality_or_prior_containment": "unconfirmed; generic given lemma equality is not prior-work evidence"}


def main():
    sys.set_int_max_str_digits(0)  # Trusted pinned E115 decimal exact rationals.
    WORK.mkdir(parents=True, exist_ok=True)
    prereg = json.loads((WORK / "preregistration-receipt.json").read_text())
    if sha(REPO / PREREG) != FROZEN_SHA or prereg["sha256"] != FROZEN_SHA:
        raise ValueError("Frozen specification changed")
    freeze = json.loads((WORK / "source-argv-freeze.json").read_text())
    for path, digest in freeze["source_sha256"].items():
        if sha(Path(path)) != digest:
            raise ValueError("Frozen source/input changed: " + path)
    if RAW.exists():
        raise ValueError("Do not overwrite completed finite cohort")
    snapshot = WORK / "before-main-sources"
    snapshot.mkdir(exist_ok=False)
    for source in SOURCES:
        target = snapshot / source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / source, target)
    shutil.copyfile(E115, snapshot / "E115-independent-one-drop23-exact-card.json")
    ternary = ternary_panel()
    masks = [mask_panel((-2, 1, 0, 0), "X_minus_2"), mask_panel((-4, 0, 1, 0), "X2_minus_4")]
    large = large_card()
    summary = {"ternary_states": ternary["distinct_ternary_states"],
               "nonzero_ternary_states": ternary["counts"]["unit_nonzero"] + ternary["counts"]["nonunit_nonzero"],
               "zero_exceptions": ternary["counts"]["zero_exception"],
               "full_mask_contexts": len(masks), "full_masks_each": [card["full_masks_enumerated"] for card in masks],
               "full_masks_total": sum(card["full_masks_enumerated"] for card in masks),
               "large_literal_cards": 1, "large_missing_root_cap": large["result"]["nullity_cap"],
               "large_uniform_prefix_m": large["result"]["prefix_uniform_coordinates"],
               "large_nonzero_ideal_lifetime_dyadic_bits": large["result"]["floor_retained_log_exponent_lower"] - 47,
               "large_single_setup_ideal_lifetime_dyadic_bits": large["result"]["single_setup_plus_lifetime_dyadic_bits"],
               "generic_given_derived_lemma_ratio": 1,
               "outcome": "bounded_public_oracle_pass; conditional_consequence_retained; originality_and_actual_transfer_open"}
    output = {"kind": "E118_bounded_nonunit_projection_public_math_assurance",
              "utc": datetime.now(UTC).isoformat(),
              "repo_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "preregistration_sha256": FROZEN_SHA,
              "source_argv_freeze_sha256": sha(WORK / "source-argv-freeze.json"),
              "source_sha256": {source: sha(REPO / source) for source in SOURCES},
              "summary": summary, "all_ternary_panel": ternary,
              "exactly_two_nonternary_full_mask_panels": masks, "one_large_literal_card": large,
              "scope": {"public_math_only": True, "fixed_consecutive_projection_only": True,
                        "every_arbitrary_subset_false": True, "zero_exception_budget_once_per_setup": True,
                        "large_actual_secret_examined_or_sampled": False, "actual_sampler_or_keygen_modified": False,
                        "new_HE_or_release_protocol_implemented": False, "large_API_guard_bypassed": False,
                        "native_GPU_build_key_setup_timing_or_proof_executed": False,
                        "actual_SHAKE_ROM_or_cryptographic_parameter_approval": False,
                        "new_novelty_or_published_containment_established": False},
              "development_failures": [],
              "development_corrections": ["peer review: root count describes zero-membership comparisons, not equality of all numeric evaluations; corrected before finite cohort"]}
    RAW.parent.mkdir(parents=True, exist_ok=True)
    write_json(RAW, output)
    print(json.dumps(summary, indent=2))
    print("tiny_ternary_counts", json.dumps(ternary["counts"], sort_keys=True))
    print("raw_sha256", sha(RAW))


if __name__ == "__main__":
    main()
