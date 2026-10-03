#!/usr/bin/env python3
"""E119 one frozen public squarefree-CRT/codec cohort; no HE or timing."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
from itertools import product
import json
from math import prod
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab import squarefree_projection as lab  # noqa: E402
from experiments.bfv_search_lab.query_quantizer_law import QuantizerLaw  # noqa: E402

WORK = REPO.parent / "research-data/squarefree-projection-20261003"
RAW = REPO / "benchmarks/results/publication-squarefree-projection-20261003.json"
PREREG = "docs/research/squarefree-projection-preregistration-20261003.md"
AMENDMENT = "docs/research/squarefree-projection-codec-amendment-20261003.md"
PREREG_SHA = "3073a0c49f88886598a45bbda41bf10bc8ad56f3cd32968d706cc7662d80bcee"
AMENDMENT_SHA = "1bbd04cf061a34483c9229cbb3a033efee01c3b357814c435bdba9705c5f7083"
SOURCES = [PREREG, AMENDMENT,
           "experiments/bfv_search_lab/squarefree_projection.py",
           "experiments/bfv_search_lab/test_squarefree_projection.py",
           "benchmarks/squarefree_projection_lab.py",
           "experiments/bfv_search_lab/one_prime_bounds.py",
           "experiments/bfv_search_lab/query_quantizer_law.py",
           "experiments/bfv_search_lab/compressed_query_bgv.py",
           "experiments/bfv_search_lab/nonunit_projection.py",
           "experiments/bfv_search_lab/test_nonunit_projection.py"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(value):
    if type(value) is Fraction:
        return {"numerator": value.numerator, "denominator": value.denominator}
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
    """Independent literal integer negacyclic polynomial multiplication."""
    output = [0] * len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            position = i + j
            term = a * b
            if position >= len(left):
                position -= len(left)
                term = -term
            output[position] += term
    return tuple(output)


def schoolbook_matrix(secret):
    columns = [schoolbook(secret, tuple(int(i == j) for i in range(len(secret))))
               for j in range(len(secret))]
    return tuple(tuple(column[i] for column in columns) for i in range(len(secret)))


def bareiss(matrix):
    """Independent fraction-free determinant with checked exact divisions."""
    rows = [list(row) for row in matrix]
    sign, previous = 1, 1
    for column in range(len(rows)-1):
        pivot = next((i for i in range(column, len(rows)) if rows[i][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            rows[column], rows[pivot] = rows[pivot], rows[column]
            sign *= -1
        current = rows[column][column]
        for i in range(column+1, len(rows)):
            for j in range(column+1, len(rows)):
                numerator = rows[i][j]*current - rows[i][column]*rows[column][j]
                if numerator % previous:
                    raise ArithmeticError("Bareiss division is not exact")
                rows[i][j] = numerator // previous
            rows[i][column] = 0
        previous = current
    return sign * rows[-1][-1]


def field_rank(matrix, prime):
    """Independent division-free field echelon; no composite elimination."""
    if not matrix:
        return 0
    rows = [[x % prime for x in row] for row in matrix]
    rank = 0
    for column in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(rank+1, len(rows)):
            lead, factor = rows[rank][column], rows[i][column]
            if factor:
                rows[i] = [(lead*a-factor*b) % prime
                           for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
        if rank == len(rows):
            break
    return rank


def literal_zero_roots(secret, ctx):
    return tuple(tuple(alpha for alpha in
                       (pow(root, 2*j+1, prime) for j in range(ctx.n))
                       if sum(a*pow(alpha, j, prime) for j, a in enumerate(secret)) % prime == 0)
                 for prime, root in zip(ctx.primes, ctx.primitive_roots, strict=True))


def literal_crt_table(ctx):
    """Independent full coefficient inventory; no modular-inverse formula."""
    table = {tuple(c % p for p in ctx.primes): c for c in range(ctx.q)}
    if len(table) != ctx.q:
        raise AssertionError("CRT coefficient inventory is not bijective")
    return table


def norm_cap_using_product_as_if_prime(n, q, norm2):
    """Deliberately INVALID composite shortcut, retained only as a negative."""
    bound, k = norm2 ** (n//2), 0
    while k < n and q ** (k+1) <= bound:
        k += 1
    return k


def witness_panel():
    ctx = lab.Context(8, (17, 97), (3, 8)).validate()
    secret = (-1, 0, -1, 1, 0, 0, 0, 0)
    matrix = schoolbook_matrix(secret)
    require(matrix == lab.multiplication_matrix(secret), "N8_schoolbook_matrix", secret)
    determinant = bareiss(matrix)
    require(determinant == lab.determinant(matrix), "N8_independent_determinant", determinant)
    nullities = tuple(ctx.n-field_rank(matrix, p) for p in ctx.primes)
    require(nullities == tuple(ctx.n-lab.rank_mod(matrix, p) for p in ctx.primes),
            "N8_independent_prime_ranks", nullities)
    roots = literal_zero_roots(secret, ctx)
    require(roots == lab.zero_roots(secret, ctx) == ((3,), ()), "N8_zero_root_membership", roots)
    require(nullities == tuple(map(len, roots)) == (1, 0), "N8_limb_defects", nullities)
    norm2 = sum(x*x for x in secret)
    norm = lab.norm_certificate(ctx.n, ctx.primes, norm2)
    require(norm.limb_nullity_caps == (1, 0) and norm.prefix_length == 7,
            "N8_common_norm_prefix7", norm)
    prefix_ranks = tuple(field_rank(matrix[:norm.prefix_length], p) for p in ctx.primes)
    require(prefix_ranks == lab.projection_ranks(secret, ctx, tuple(range(7))) == (7, 7),
            "N8_common_prefix_surjectivity", prefix_ranks)
    divisor = lab.weighted_divisor(ctx, nullities)
    require(determinant != 0 and determinant % divisor == 0 and abs(determinant) <= norm2**4 == 81,
            "N8_weighted_divisibility_norm", determinant)
    require(divisor == 17 and determinant % ctx.q != 0,
            "N8_wholeQ_divisibility_shortcut_false", determinant)
    invalid_k = norm_cap_using_product_as_if_prime(8, ctx.q, norm2)
    require(invalid_k == 0 and max(nullities) > invalid_k,
            "N8_false_fullvector_uniformity_prediction", invalid_k)
    ternary_norm = lab.norm_certificate(8, ctx.primes, 8)
    require(ternary_norm.limb_nullity_caps == (2, 1) and ternary_norm.prefix_length == 6,
            "N8_allternary_norm_not_fitted_witness", ternary_norm)
    require(lab.projection_ranks(secret, ctx, tuple(range(6))) == (6, 6),
            "N8_conservative_prefix6", {})
    return {"context": ctx, "public_ternary_polynomial": secret, "norm2": norm2,
            "integer_determinant": determinant, "prime_limb_nullities": nullities,
            "zero_roots": roots, "weighted_divisor": divisor,
            "norm_certificate_actual_public_polynomial": norm,
            "common_prefix_ranks": prefix_ranks,
            "all_ternary_public_norm_envelope_certificate": ternary_norm,
            "all_ternary_domain_enumerated": False,
            "invalid_wholeQ_nullity_cap": invalid_k,
            "Q_power_max_nullity_divisibility_false": True,
            "full8_uniformity_shortcut_false": True,
            "matrix_coefficient_comparisons": 64, "root_zero_membership_comparisons": 16,
            "N8_masks_enumerated": 0, "actual_key_or_secret_draw": False}


def mask_panel(secret, name, expected_nullities):
    ctx = lab.Context(2, (5, 13), (2, 5)).validate()
    q, matrix = ctx.q, schoolbook_matrix(secret)
    require(matrix == lab.multiplication_matrix(secret), "N2_schoolbook_matrix", name)
    determinant = bareiss(matrix)
    require(determinant == lab.determinant(matrix), "N2_independent_determinant", name)
    nullities = tuple(ctx.n-field_rank(matrix, p) for p in ctx.primes)
    require(nullities == expected_nullities
            == tuple(ctx.n-lab.rank_mod(matrix, p) for p in ctx.primes),
            "N2_actual_prime_ranks", name)
    roots = literal_zero_roots(secret, ctx)
    require(roots == lab.zero_roots(secret, ctx) and tuple(map(len, roots)) == nullities,
            "N2_rank_root_membership", name)
    norm2 = sum(x*x for x in secret)
    norm = lab.norm_certificate(ctx.n, ctx.primes, norm2)
    actual_prefix_length = ctx.n-max(nullities)
    ranks = tuple(field_rank(matrix[:actual_prefix_length], p) for p in ctx.primes)
    require(ranks == lab.projection_ranks(secret, ctx, tuple(range(actual_prefix_length))) == (1, 1),
            "N2_actual_rank_prefix", name)
    divisor = lab.weighted_divisor(ctx, nullities)
    require(determinant != 0 and determinant % divisor == 0 and abs(determinant) <= norm2,
            "N2_weighted_divisibility_norm", name)
    if name == "X_minus_5":
        require(norm.limb_nullity_caps == (2, 1) and norm.prefix_length == 0,
                "X_minus_5_norm_only_vacuous_not_actual_rank", norm)
    else:
        require(norm.limb_nullity_caps == (1, 0) and norm.prefix_length == 1,
                "X_minus_2_norm_prefix", norm)
    table = literal_crt_table(ctx)
    translation = (1, 2)
    prefix, translated_prefix, image, translated_image = (Counter() for _ in range(4))
    mask_count = 0
    for mask in product(range(q), repeat=ctx.n):
        output = tuple(c % q for c in schoolbook(secret, mask))
        limb_outputs = tuple(tuple(c % p for c in schoolbook(secret, tuple(x % p for x in mask)))
                             for p in ctx.primes)
        crt_output = tuple(table[tuple(v[i] for v in limb_outputs)] for i in range(ctx.n))
        require(output == crt_output == lab.multiply_via_crt(secret, mask, ctx),
                "complete_schoolbook_limb_CRT_product", {"name": name, "mask": mask})
        shifted = tuple((c+u) % q for c, u in zip(output, translation, strict=True))
        prefix[output[:actual_prefix_length]] += 1
        translated_prefix[shifted[:actual_prefix_length]] += 1
        image[output] += 1
        translated_image[shifted] += 1
        mask_count += 1
    expected_image = prod(p ** (ctx.n-k) for p, k in zip(ctx.primes, nullities, strict=True))
    require(mask_count == q**ctx.n == 4225 and len(image) == len(translated_image) == expected_image,
            "N2_fullimage_support", name)
    require(set(image.values()) == set(translated_image.values()) == {divisor},
            "N2_exact_fullimage_fibres", name)
    require(len(prefix) == len(translated_prefix) == q**actual_prefix_length == 65
            and set(prefix.values()) == set(translated_prefix.values()) == {65},
            "N2_actual_rank_prefix_uniform", name)
    for values, shift in ((image, (0, 0)), (translated_image, translation)):
        for vector in values:
            require(all(sum((c-shift[j])*pow(alpha, j, p) for j, c in enumerate(vector)) % p == 0
                        for p, zeros in zip(ctx.primes, roots, strict=True) for alpha in zeros),
                    "N2_image_or_affine_coset_parity", {"name": name, "vector": vector})
    hist = WORK / f"{name}-complete-public-histograms.json"
    write_json(hist, {"context": ctx, "public_nonternary_polynomial": secret,
                     "fixed_translation": translation,
                     **{key: [{"vector": vector, "mass": mass} for vector, mass in sorted(count.items())]
                        for key, count in (("actual_rank_prefix", prefix),
                                           ("translated_actual_rank_prefix", translated_prefix),
                                           ("image", image), ("translated_image", translated_image))}})
    return {"context": ctx, "public_nonternary_polynomial": secret,
            "not_an_actual_ternary_secret_law": True,
            "norm2": norm2, "integer_determinant": determinant,
            "actual_prime_limb_nullities": nullities, "actual_zero_roots": roots,
            "norm_only_certificate": norm, "actual_public_rank_prefix_length": actual_prefix_length,
            "actual_public_rank_prefix_ranks": ranks,
            "prefix_histogram_justification": "independently checked actual public rank; not substituted for conservative norm-only cap",
            "full_masks_enumerated": mask_count, "schoolbook_vs_CRT_coefficient_comparisons": mask_count*ctx.n,
            "full_image_support": len(image), "full_image_fibre_each": divisor,
            "full_vector_not_uniform_over_allQ_vectors": len(image) != q**ctx.n,
            "actual_rank_prefix_bins": len(prefix), "actual_rank_prefix_mass_each": 65,
            "fixed_translation": translation, "all_fullimage_coset_prefix_checks_pass": True,
            "histogram_path": str(hist), "histogram_sha256": sha(hist)}


def formal_coefficient_formula(c, q, t, drop):
    """Literal FORMULA only: no codec admission, cryptographic guard or HE API.

    In particular the q5 diagnostic below is unadmitted by QuantizerLaw. The
    independently evaluated algebraic map is useful to reject blind CRT
    substitution, not to bypass the existing added-error/domain guards.
    """
    if (any(type(x) is not int for x in (c, q, t, drop)) or not 0 <= c < q
            or q < 3 or not q & 1 or not 3 <= t < q or not t & 1
            or not 1 <= drop < q.bit_length()):
        raise ValueError("Invalid literal public coefficient formula")
    r = 2**drop
    h0 = ((r-1)//t)//2
    high, low = c//r, c % r
    word = high*t + low % t
    reconstructed = (high*r + low % t + t*h0) % q
    return word, reconstructed, t*(h0-low//t)


def codec_panel():
    law = QuantizerLaw(65, 3, 2)
    records, masses = [], Counter()
    for c in range(65):
        word, reconstructed, delta = formal_coefficient_formula(c, 65, 3, 2)
        require((word, reconstructed) == law.literal_map(c)
                and delta == law.added_error(c) and reconstructed == (c+delta) % 65,
                "wholeQ_literal_word_reconstruction", c)
        masses[delta//3] += 1
        records.append({"coefficient": c, "word": word,
                        "reconstructed": reconstructed, "signed_added_error": delta})
    require(dict(masses) == dict(law.pmf()) == {0: 49, -1: 16}
            and sum(masses.values()) == 65 and law.mean_units() == Fraction(-16, 65),
            "wholeQ_exact_signed_partial_cycle_PMF", dict(masses))
    q5_law_refused = False
    try:
        QuantizerLaw(5, 3, 2)
    except ValueError:
        q5_law_refused = True
    require(q5_law_refused, "formal_Q5_formula_not_admitted_law", {})
    ctx = lab.Context(2, (5, 13), (2, 5))
    whole = formal_coefficient_formula(8, 65, 3, 2)[1]
    limbs = tuple(formal_coefficient_formula(8 % p, p, 3, 2)[1] for p in ctx.primes)
    combined = literal_crt_table(ctx)[limbs]
    require(combined == lab.crt_lift(limbs, ctx) == 60 and limbs == (0, 8) and whole == 8,
            "formal_unadmitted_limb_substitution_negative", {"whole": whole, "limbs": limbs})
    path = WORK / "wholeQ65-t3-drop2-all65-coefficients.json"
    write_json(path, {"literal_scalar_records": records, "signed_units_masses": dict(masses)})
    return {"wholeQ": 65, "t": 3, "drop": 2, "canonical_coefficients_enumerated": 65,
            "scalar_QuantizerLaw_admitted": True, "actual_HE_codec_domain_or_ciphertext_admitted": False,
            "signed_added_error_units_masses": dict(masses), "mean_signed_units": law.mean_units(),
            "partial_cycle_coefficient64": records[-1],
            "literal_formula_limb_negative": {"original_coefficient": 8,
                "wholeQ_reconstructed": whole, "formal_limb_reconstructions": limbs,
                "formal_limb_CRT_lift": combined, "Q5_QuantizerLaw_guard_refuses": q5_law_refused,
                "formal_limb_map_not_admitted_codec": True},
            "inventory_path": str(path), "inventory_sha256": sha(path)}


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    prereg = json.loads((WORK / "preregistration-receipt.json").read_text())
    if sha(REPO / PREREG) != PREREG_SHA or prereg["sha256"] != PREREG_SHA:
        raise ValueError("Frozen specification changed")
    if sha(REPO / AMENDMENT) != AMENDMENT_SHA:
        raise ValueError("Frozen codec clarification changed")
    freeze = json.loads((WORK / "source-argv-freeze.json").read_text())
    if freeze["argv"] != [sys.executable, *sys.argv]:
        raise ValueError("Frozen main argv changed")
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
    witness = witness_panel()
    masks = [mask_panel((-2, 1), "X_minus_2", (1, 0)),
             mask_panel((-5, 1), "X_minus_5", (0, 1))]
    codec = codec_panel()
    summary = {"N8_public_ternary_witnesses": 1, "N8_masks_enumerated": 0,
               "N8_actual_norm_common_prefix": witness["norm_certificate_actual_public_polynomial"].prefix_length,
               "N8_false_wholeQ_fullvector_bound_rejected": True,
               "full_mask_contexts": 2, "full_masks_each": [card["full_masks_enumerated"] for card in masks],
               "full_masks_total": sum(card["full_masks_enumerated"] for card in masks),
               "N2_norm_only_prefixes": [card["norm_only_certificate"].prefix_length for card in masks],
               "N2_actual_public_rank_prefixes": [card["actual_public_rank_prefix_length"] for card in masks],
               "wholeQ_scalar_panels": 1, "scalar_coefficients_enumerated": 65,
               "formal_unadmitted_limb_substitution_rejected": True,
               "equally_informed_generic_control_ratio": 1,
               "outcome": "bounded_CRT_prerequisite_pass; wholeQ_large_implication_and_originality_unapproved"}
    output = {"kind": "E119_squarefree_CRT_public_mathematical_discriminator",
              "utc": datetime.now(UTC).isoformat(),
              "repo_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "preregistration_sha256": PREREG_SHA, "codec_amendment_sha256": AMENDMENT_SHA,
              "source_argv_freeze_sha256": sha(WORK / "source-argv-freeze.json"),
              "source_sha256": {source: sha(REPO / source) for source in SOURCES},
              "summary": summary, "one_N8_public_ternary_witness": witness,
              "exactly_two_N2_full_mask_panels": masks, "one_wholeQ_scalar_codec_panel": codec,
              "scope": {"known_weighted_norm_CRT_Vandermonde_controls": True,
                        "public_tiny_math_only": True, "squarefree_fully_split_only": True,
                        "common_fixed_consecutive_prefix_only": True,
                        "norm_only_and_public_rank_certificates_separate": True,
                        "no_field_elimination_modulo_composite": True,
                        "formal_limb_map_does_not_bypass_admission": True,
                        "large_model_or_profile_grid_executed": False,
                        "actual_secret_sampler_key_HE_or_release_executed": False,
                        "native_GPU_proof_timing_estimator_service_executed": False,
                        "actual_SHAKE_ROM_parameter_security_or_novelty_approved": False},
              "development_failures": [],
              "precohort_clarifications": ["Q5 formal limb formula is unadmitted; existing QuantizerLaw guard is independently asserted to refuse it"]}
    RAW.parent.mkdir(parents=True, exist_ok=True)
    write_json(RAW, output)
    print(json.dumps(summary, indent=2))
    print("raw_sha256", sha(RAW))


if __name__ == "__main__":
    main()
