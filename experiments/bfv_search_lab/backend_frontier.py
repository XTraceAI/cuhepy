"""E42 count frontier under ACTUAL pinned author code-dimension floors.

No reduced-rank LPN/LSN security parameters are invented. These models price
unchanged author configurations, not measured network traffic. Integrity and
state contracts are exposed separately; raw corpus caching is a control.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CodeProfile:
    name: str
    plaintext_dimension: int
    code_dimension: int
    response_shares: int
    field_bytes: int = 8
    quantization: int = 1 << 20


EMVP = CodeProfile("emvp_author_sec128_heuristic", 1024, 1292, 76)
BNTM = CodeProfile("bntm_author_sec128_unestimated_lpn", 1024, 1024, 1)


def code_cost(profile: CodeProfile, row_counts: tuple[int, ...], feature_counts: tuple[int, ...],
              *, query_bound: int = 1, verified: bool = False) -> dict:
    if (profile not in (EMVP, BNTM) or type(verified) is not bool
            or not row_counts or len(row_counts) != len(feature_counts)
            or any(type(m) is not int or not 1 <= m <= 32768 for m in row_counts)
            or sum(row_counts) > 32768
            or any(type(f) is not int or not 1 <= f <= profile.plaintext_dimension for f in feature_counts)
            or type(query_bound) is not int or not 1 <= query_bound <= 65536):
        raise ValueError("Invalid exact author-code comparison")
    if verified and profile == EMVP:
        raise ValueError("Pinned EMVP author scorer has no verification mode")
    m, groups = sum(row_counts), len(row_counts)
    qbody = groups * profile.code_dimension * profile.field_bytes
    response = m * profile.response_shares * profile.field_bytes
    index = m * profile.code_dimension * profile.field_bytes
    field = (1 << 61) - 1
    bound = max(feature_counts) * query_bound  # enrolled affine pivot differences are <=1.
    return {"backend": profile.name, "independent_query_encodings": groups,
            "private_features": sum(feature_counts), "security_padding_floor": profile.plaintext_dimension,
            "query_body_bytes_model": qbody, "response_body_bytes_model": response,
            "online_body_bytes_model": qbody + response, "server_index_word_bytes": index,
            "server_field_products_model": m * profile.code_dimension,
            "integer_dot_absolute_bound": bound,
            "quantized_dot_no_field_wrap": 2 * bound * profile.quantization**2 < field,
            "integer_score_exact_in_float_api": bound <= 1 << 24,
            "integrity": "full per-response author Freivalds with retained encrypted index" if verified else "none",
            "verification_field_products_lower_bound_model": 3 * m * profile.code_dimension if verified else 0,
            "client_verified_index_word_bytes_lower_bound": index if verified else 0,
            "client_bntm_decode_dense_state_word_bytes_lower_bound": m * (1024 + 2 * 128) * 8 if profile == BNTM else 0,
            "client_emvp_private_d_word_bytes": 1024 * 1292 * 8 if profile == EMVP else 0,
            "parameter_security_is_reviewed": False,
            "scope": "Body/work/lower-state models; excludes sparse state, IDs, framing, outer authentication and RSS."}
