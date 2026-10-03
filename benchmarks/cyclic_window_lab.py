#!/usr/bin/env python3
"""One frozen E121 public exact-law cohort, not a runtime benchmark."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab import cyclic_window as lab  # noqa: E402

WORK = REPO.parent / "research-data/cyclic-window-20261003"
RAW = REPO / "benchmarks/results/publication-cyclic-window-20261003.json"
PREREG = "docs/research/cyclic-window-preregistration-20261003.md"
PREREG_SHA = "506e1a5a1f3f1d374dab6371c45069b517dc265422b3a0ace79c17019509553a"
OWNED = ("experiments/bfv_search_lab/cyclic_window.py",
         "experiments/bfv_search_lab/test_cyclic_window.py", "benchmarks/cyclic_window_lab.py")


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


def schoolbook_matrix(secret):
    """Literal monomial products, independent of the Toeplitz helper."""
    n = len(secret)
    columns = []
    for column in range(n):
        output = [0] * n
        for i, coefficient in enumerate(secret):
            position = i + column
            output[position % n] += coefficient * (-1 if position >= n else 1)
        columns.append(tuple(output))
    return tuple(tuple(column[i] for column in columns) for i in range(n))


def control_rank(matrix, q):
    """Division-free field echelon, independent of normalized elimination."""
    rows = [[x % q for x in row] for row in matrix]
    rank = 0
    for j in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][j]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(rank + 1, len(rows)):
            lead, factor = rows[rank][j], rows[i][j]
            if factor:
                rows[i] = [(lead * a - factor * b) % q
                           for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
        if rank == len(rows):
            break
    return rank


def independent_basis(matrix, q):
    #Reverse public column order differentiates the two greedy bases.
    columns, indices = [], []
    for j in reversed(range(len(matrix))):
        candidate = columns + [tuple(row[j] for row in matrix)]
        rows = tuple(tuple(column[i] for column in candidate) for i in range(len(matrix)))
        if control_rank(rows, q) > len(columns):
            columns, indices = candidate, indices + [j]
    return tuple(indices), tuple(tuple(column[i] for column in columns) for i in range(len(matrix)))


def rank_panel(ctx):
    matrix = schoolbook_matrix(ctx.secret)
    require(matrix == ctx.matrix, "schoolbook_matrix", ctx)
    implementation = lab.window_ranks(ctx)
    independent = tuple(control_rank(tuple(matrix[i] for i in window), ctx.q)
                        for window in ctx.windows)
    require(implementation == independent == (ctx.window_length,) * ctx.n,
            "all_literal_cyclic_window_ranks", ctx)
    return {"context": ctx, "literal_windows": ctx.windows, "ranks": implementation,
            "independent_ranks": independent, "window_rank_checks": ctx.n,
            "matrix_coefficient_comparisons": ctx.n * ctx.n}


def independent_factored(ctx, weights, law):
    #No geometric-MGF helper: count each scalar codec coefficient explicitly,
    #then combine the three exact CBD outcomes within an admitted window.
    radix = 1 << law.drop
    center = ((radix - 1) // law.t) // 2
    scalar_pmf = {}
    for coefficient in range(ctx.q):
        delta = center - (coefficient % radix) // law.t
        scalar_pmf[delta] = scalar_pmf.get(delta, 0) + 1
    scalars = {}
    for weight in set(weights):
        scalars[weight] = sum((Fraction(mass * cbd_mass, ctx.q * 4)
                              * Fraction(2) ** (ctx.n * weight * (delta + error))
                              for delta, mass in scalar_pmf.items()
                              for error, cbd_mass in ((-1, 1), (0, 2), (1, 1))), Fraction())
    windows = tuple(product_fraction(scalars[weights[i]] for i in window)
                    for window in ctx.windows)
    return windows, tuple(sorted(scalar_pmf.items()))


def product_fraction(values):
    result = Fraction(1)
    for value in values:
        result *= value
    return result


def image_panel(ctx, expected_rank, expected_image, expected_fibre):
    ranks = rank_panel(ctx)
    matrix = schoolbook_matrix(ctx.secret)
    control_indices, control_basis = independent_basis(matrix, ctx.q)
    image = lab.enumerate_image(ctx)
    require(control_rank(matrix, ctx.q) == len(control_indices) == image.rank == expected_rank,
            "independent_image_basis_rank", ctx)
    combined = tuple(control_basis[i] + tuple(matrix[i][j] for j in image.basis_indices)
                     for i in range(ctx.n))
    require(control_rank(combined, ctx.q) == image.rank,
            "both_column_bases_span_same_image", ctx)
    require(len(image.points) == len(set(image.points)) == expected_image
            and ctx.q ** ctx.n // len(image.points) == expected_fibre,
            "unique_complete_image_constant_fibres", ctx)
    image_path = WORK / f"image-{expected_rank}.json"
    write_json(image_path, {"context": ctx, "basis_indices": image.basis_indices,
                            "points": image.points})
    histograms = []
    message = (1, -1, 0, 0)
    for error in ((0, 0, 0, 0), (1, 0, 0, 0)):
        hist = lab.translated_histograms(image, message, error, 3)
        for window, histogram in zip(ctx.windows, hist, strict=True):
            require(len(histogram) == ctx.q ** ctx.window_length
                    and {count for _, count in histogram}
                    == {len(image.points) // (ctx.q ** ctx.window_length)},
                    "translated_window_histogram_uniform", (ctx, error, window))
        histograms.append({"error": error, "windows": hist})
    histogram_path = WORK / f"window-histograms-{expected_rank}.json"
    write_json(histogram_path, {"message": message, "contexts": histograms})
    law = lab.QuantizerLaw(17, 3, 2)
    weights = (1, -2, 0, 1)
    joint = lab.joint_law(image, message, weights, law)
    comparison = joint.compare()
    factored = lab.factored_window_moments(ctx, weights, law)
    independent, pmf = independent_factored(ctx, weights, law)
    require(comparison["window_moments"] == factored == independent,
            "literal_joint_vs_both_factored_window_controls", ctx)
    require(comparison["rhs"] == product_fraction(independent)
            and comparison["holder_holds"] and comparison["ordinary_control_ratio"] == 1,
            "known_regular_cover_comparison", ctx)
    require(joint.error_vectors == 81 and joint.tuple_visits == 81 * expected_image
            and sum(mass for _, mass in lab.cbd_one_states(4)) == 4 ** 4,
            "literal_CBD_joint_counts", ctx)
    exponent_path = WORK / f"joint-exponent-laws-{expected_rank}.json"
    write_json(exponent_path, joint)
    record = {"rank_panel": ranks, "rank": image.rank,
              "basis_indices": image.basis_indices, "independent_basis_indices": control_indices,
              "image_count": len(image.points), "image_enumerations": 1,
              "full_mask_enumerations": 0, "constant_fibre": expected_fibre,
              "image_cache": str(image_path), "image_sha256": sha(image_path),
              "histogram_panels": 8, "histogram_cache": str(histogram_path),
              "histogram_sha256": sha(histogram_path), "message": message, "weights": weights,
              "scalar_codec_pmf": pmf, "scalar_codec_mean": law.mean_units(),
              "joint_law_denominator": joint.denominator, "CBD_vectors": joint.error_vectors,
              "joint_tuple_visits": joint.tuple_visits, "scalar_lookups": joint.scalar_lookups,
              "window_sums": joint.window_sums, "scalar_cache_entries": joint.scalar_cache_entries,
              "joint_law_cache": str(exponent_path), "joint_law_sha256": sha(exponent_path),
              "comparison": comparison, "factored_window_control": factored,
              "independent_factored_window_control": independent}
    return image, record


def main():
    #Resource ceilings, not performance phase measurements.
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    signal.alarm(60)
    WORK.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((WORK / "root-freeze-receipt.json").read_text())
    require(sha(REPO / PREREG) == PREREG_SHA == receipt["frozen_sha256"], "prereg_pin", {})
    freeze = json.loads((WORK / "source-argv-freeze.json").read_text())
    require(freeze["argv"] == [sys.executable, *sys.argv], "argv_pin", {})
    for name, digest in freeze["source_sha256"].items():
        require(sha(Path(name)) == digest, "source_pin", name)
    require(not RAW.exists() and not (WORK / "before-main-sources").exists(), "one_main_only", {})
    snapshot = WORK / "before-main-sources"
    snapshot.mkdir()
    for name in (*OWNED, PREREG):
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    n8 = rank_panel(lab.Context(8, 17, 3, (-1, 0, -1, 1, 0, 0, 0, 0), 7))
    _, first = image_panel(lab.Context(4, 17, 2, (-2, 1, 0, 0), 3), 3, 4913, 17)
    second_image, second = image_panel(lab.Context(4, 17, 2, (-4, 0, 1, 0), 2), 2, 289, 289)
    indicator = lab.indicator_control(second_image, (0, 2))
    require(all(point[2] == 4 * point[0] % 17 for point in second_image.points),
            "untranslated_arbitrary_subset_relation", {})
    require(indicator["direct_moment"] == Fraction(20, 17)
            and indicator["fake_iid_moment"] == Fraction(18, 17) ** 2
            and indicator["direct_moment"] != indicator["fake_iid_moment"]
            and indicator["ordinary_holder_equality"], "unscaled_indicator_false_IID", indicator)
    for name, digest in freeze["source_sha256"].items():
        require(sha(Path(name)) == digest, "post_main_source_pin", name)
    result = {"packet": "Q47/E121", "created_utc": datetime.now(UTC).isoformat(),
              "parent_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO,
                                                       text=True).strip(),
              "scope": "tiny public conditional laws; ordinary known Holder control",
              "prereg_sha256": PREREG_SHA, "source_argv_freeze_sha256": sha(WORK / "source-argv-freeze.json"),
              "source_sha256": freeze["source_sha256"], "N8_rank_only": n8,
              "N4_joint_laws": [first, second], "untranslated_indicator": indicator,
              "total_joint_tuple_visits": first["joint_tuple_visits"] + second["joint_tuple_visits"],
              "total_scalar_lookups": first["scalar_lookups"] + second["scalar_lookups"],
              "total_window_sums": first["window_sums"] + second["window_sums"],
              "image_enumerations": 2, "full_mask_enumerations": 0, "histogram_panels": 16,
              "large_profile_calculations": 0, "HE_operations": 0, "timing_claims": False,
              "ordinary_control_ratio": 1,
              "decision": "retain exact assurance control; concentration mechanism known/unselected as paper main"}
    write_json(RAW, result)
    print(json.dumps({"packet": result["packet"], "raw_sha256": sha(RAW),
                      "total_joint_tuple_visits": result["total_joint_tuple_visits"],
                      "ordinary_control_ratio": 1, "decision": result["decision"]}))


if __name__ == "__main__":
    main()
