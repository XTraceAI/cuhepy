"""Q76.5 static metadata faults, with no HE operations or native evaluations."""

import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from experiments.bfv_search_lab import shared_query_certificate as cert


def token(label):
    return hashlib.sha256(label.encode("ascii")).digest()


def plan(number=0, mode=cert.MODES[0]):
    p = cert.geometry(number)
    # All these shapes are present in the retained correctness cohort.
    count = (17, 33, 32768)[number]
    return cert.TrustedPlan(
        p,
        count,
        token("HE-key"),
        token("ordered-IDs"),
        token("snapshot"),
        token("policy"),
        token("code"),
        mode,
    )


@pytest.mark.parametrize("number", range(3))
@pytest.mark.parametrize("mode", cert.MODES)
def test_selected_profiles_and_complete_modes(number, mode):
    selected = plan(number, mode)
    packet = cert.make_certificate(selected)
    result = cert.check_certificate(
        packet, selected, expected_digest=cert.certificate_digest(packet)
    )
    assert result.plan == selected and result.certificate == packet
    assert result.terminal_support < selected.geometry.p // 2
    assert not hasattr(result, "decrypt") and not hasattr(result, "authorize")


def test_closed_large_numbers_agree_with_saved_native_accounting():
    selected = replace(plan(2), count=16384)
    fresh, _, _, _, _, terminal = cert.support_bounds(selected.geometry)
    assert fresh == 22166 and terminal == 8450122
    values = cert.counted_resources(selected)
    # Constants from the preserved Q76.3b source cohort, independently of this
    # checker. This tests the accounting boundary rather than copying formulas.
    assert values["full_witness_body_bytes"] == 126320640
    assert values["source_polynomials"] == 512
    assert values["public_RNS_rows"] == 1616
    assert values["resident_RNS_row_component_bytes"] == 423624704
    assert values["resident_map_shift_component_bytes"] == 3538944
    assert values["setup_forward_prime_NTTs"] == 2226
    assert values["client_coefficient_body_bytes"] == 102400
    assert values["aggregate_claim_body_bytes"] == 737280
    assert cert.counted_resources(plan(2))["cache_complete_acquisition_bytes"] == 2359635
    assert (
        cert.counted_resources(replace(selected, mode=cert.MODES[1]))[
            "mode_internal_claim_body_bytes"
        ]
        == 0
    )


GEOMETRY_FAULTS = (
    ("n", True),
    ("n", 64),
    ("dimension", 4),
    ("t", 9),
    ("eta", 2),
    ("q", cert.RETAINED_PROFILES[0][4] - 1),
    ("p", 33554269),
    ("primes", tuple(reversed(cert.RETAINED_PROFILES[0][-1]))),
    ("primes", (cert.RETAINED_PROFILES[0][-1][0],) * 2),
    ("primes", list(cert.RETAINED_PROFILES[0][-1])),
)


@pytest.mark.parametrize("name,value", GEOMETRY_FAULTS)
def test_no_peer_parameter_or_basis_substitution(name, value):
    with pytest.raises(ValueError):
        replace(cert.geometry(0), **{name: value})


PLAN_FAULTS = (
    ("count", True),
    ("count", 0),
    ("count", 33),
    ("key_id", bytearray(32)),
    ("ordered_ids_digest", b"short"),
    ("snapshot_id", "a" * 32),
    ("policy_digest", b""),
    ("code_digest", bytes(31)),
    ("mode", "randomized"),
)


@pytest.mark.parametrize("name,value", PLAN_FAULTS)
def test_trusted_metadata_has_strict_types_and_registered_caps(name, value):
    with pytest.raises(ValueError):
        replace(plan(), **{name: value})


# One explicit mutation per static obligation, with selected interior/boundary
# schedule coordinates. This is bounded metadata testing, not a polynomial or
# freshly encrypted-case grid. The cohort reuses these registered fault IDs.
SECTIONS = {
    "context": "N dimension padded t eta Q P count groups key_id ordered_ids_digest snapshot_id policy_digest code_digest mode",
    "origin": "status index_origin policy query_encoding index_encoding unused_feature_and_record_plaintext secret_absolute_support independent_error_absolute_support sampler seed_basis evaluation_key_targets",
    "representation": "lift minimum exclusive_maximum word_bytes radix_bits digits digit_minimum digit_exclusive_maximum digit_lowering actual_prime_count NTT frequencies_per_prime expanded_query CRT",
    "key_schedule": "columns ciphertext_components relinearization_keys",
    "expansion": "original_query_pairs",
    "contraction": "unused_record_plaintext_positions unused_feature_positions relinearizations final_Q_polynomials",
    "phase": "fresh switch contracted output terminal full_guard terminal_guard",
    "terminal": "codec input_interval components_per_group coefficients_per_component coefficient_bits physical_padding unused_record_ciphertext frame score IDs",
    "placement": "mode random_challenge replay_source_witness aggregate_arithmetic_savings code_selection",
    "authority": "certificate owner_currentness response_predicate binding attempt native_refinement attestation HE_secret_custody CPU_signer",
    "resources": "common_polynomial_bytes evaluation_key_common_bytes index_common_bytes original_query_common_bytes source_polynomials full_witness_body_bytes aggregate_claim_body_bytes mode_internal_claim_body_bytes client_coefficient_body_bytes public_RNS_rows resident_RNS_row_component_bytes resident_map_shift_component_bytes setup_forward_prime_NTTs complete_ordered_ID_bytes cache_vector_bytes cache_body_with_ID_bytes cache_complete_acquisition_bytes counts_scope RSS_policy",
}
FAULT_PATHS = [("version",)] + [
    (section, name) for section, names in SECTIONS.items() for name in names.split()
]
FAULT_PATHS += [
    ("context", "ordered_primes", 0),
    ("context", "ordered_primes", 1),
    ("key_schedule", "rotation_exponents", 0),
    ("key_schedule", "rotation_exponents", 1),
    ("expansion", "levels", 0, "level"),
    ("expansion", "levels", 0, "automorphism"),
    ("expansion", "levels", 1, "minus_monomial_exponent"),
    ("expansion", "levels", 1, "branches", 1, 0),
    ("expansion", "levels", 1, "branches", 1, 1),
    ("expansion", "levels", 1, "branches", 1, 2),
    ("expansion", "levels", 1, "branches", 1, 3),
    ("expansion", "final_feature_positions", 3),
    ("expansion", "signed_branches", 1),
    ("contraction", "terms", 0),
    ("contraction", "terms", 1),
    ("contraction", "terms", 2),
    ("contraction", "feature_group_coverage", 3, 0),
    ("contraction", "feature_group_coverage", 3, 1),
    ("contraction", "feature_group_coverage", 3, 2),
    ("contraction", "occupied_records", 1),
    ("contraction", "C2_sources", 1),
    ("phase", "each_expansion_level", 0),
    ("phase", "each_expansion_level", 1),
    ("phase", "each_expansion_level", 2),
    ("terminal", "tie_key", 1),
    ("placement", "protected_work", 0),
    ("resources", "paid_lifetimes", 0),
    ("resources", "paid_lifetimes", 7),
    ("resources", "unclosed_components", 0),
    ("resources", "unclosed_components", 3),
]
FAULT_PATHS = tuple(FAULT_PATHS)


def changed(packet, path):
    value = json.loads(packet)
    node = value
    for item in path[:-1]:
        node = node[item]
    old = node[path[-1]]
    node[path[-1]] = old + 1 if type(old) is int else old + " changed"
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


@pytest.mark.parametrize("path", FAULT_PATHS, ids=lambda x: ".".join(map(str, x)))
def test_each_obligation_rejects_even_a_recomputed_digest(path):
    selected = plan()
    packet = changed(cert.make_certificate(selected), path)
    with pytest.raises(ValueError, match="reconstructed reference"):
        cert.check_certificate(packet, selected, expected_digest=cert.certificate_digest(packet))


@pytest.mark.parametrize(
    "field,value",
    [
        ("count", 16),
        ("mode", cert.MODES[1]),
        ("key_id", token("different-key")),
        ("snapshot_id", token("new-snapshot")),
    ],
)
def test_valid_old_digest_cannot_authorize_changed_trusted_context(field, value):
    selected = plan()
    packet = cert.make_certificate(selected)
    with pytest.raises(ValueError, match="reconstructed reference"):
        cert.check_certificate(
            packet,
            replace(selected, **{field: value}),
            expected_digest=cert.certificate_digest(packet),
        )


GRAMMAR_FAULTS = (
    b'{"version":1,"version":1}',
    b'{"a":1.0}',
    b'{"a":NaN}',
    b'{"a":null}',
    b'{"a":true}',
    b'{"a":' + b"1" * 65 + b"}",
    b"[" * 17 + b"0" + b"]" * 17,
    b'{"a":[' + b"0," * 1024 + b"0]}",
    b'{"a":"' + b"x" * 257 + b'"}',
    b'{"a":"\\u00e9"}',
    b"{}{}",
    b"\xff",
    bytearray(b"{}"),
    b"x" * (cert.MAX_CERTIFICATE_BYTES + 1),
)


@pytest.mark.parametrize("packet", GRAMMAR_FAULTS, ids=range(len(GRAMMAR_FAULTS)))
def test_bounded_grammar_rejects_before_validated_metadata(packet):
    with pytest.raises(ValueError):
        cert.check_certificate(packet, plan())


def test_semantically_valid_noncanonical_encoding_rejected():
    selected = plan()
    packet = cert.make_certificate(selected)
    with pytest.raises(ValueError, match="Noncanonical"):
        cert.check_certificate(b" " + packet, selected)


@pytest.mark.parametrize("fault", ["unknown-field", "missing-expanded-edge", "missing-group"])
def test_unknown_or_incomplete_reference_statement_rejected(fault):
    selected = plan()
    statement = json.loads(cert.make_certificate(selected))
    if fault == "unknown-field":
        statement["extra"] = 1
    elif fault == "missing-expanded-edge":
        statement["expansion"]["levels"][1]["branches"].pop()
    else:
        statement["contraction"]["occupied_records"].pop()
    packet = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(ValueError, match="reconstructed reference"):
        cert.check_certificate(packet, selected, expected_digest=cert.certificate_digest(packet))


def test_checker_has_no_HE_optimizer_native_or_authentication_import():
    tree = ast.parse(Path(cert.__file__).read_text())
    modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    modules |= {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert modules == {"__future__", "dataclasses", "hashlib", "json", "math", "gmpy2"}
