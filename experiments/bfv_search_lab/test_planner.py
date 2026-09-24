"""Network arithmetic and capability constraints of the measurement planner."""

import pytest

from experiments.bfv_search_lab.planner import rank


def fixture_report():
    # Fastest local variant has a large upload; slower bandwidth reverses it.
    return {
        "kind": "local_encrypted_benchmark_no_network_or_attestation",
        "all_distances_and_top3_correct": True,
        "results": [
            {
                "variant": name,
                "partials": partials,
                "samples": [
                    {
                        "online_total_s": seconds,
                        "total_with_refill_s": seconds + refill,
                        "query_bytes": upload,
                        "response_bytes": 1000,
                    }
                ],
            }
            for name, partials, seconds, refill, upload in (
                ("public", 1, 0.01, 0, 100000),
                ("seeded", 1, 0.02, 0, 10000),
                ("partial-2-seeded-pool", 2, 0.005, 0.1, 10000),
            )
        ],
    }


def test_bandwidth_reverses_ranking_and_adds_one_rtt():
    data = fixture_report()
    fast = rank(data, upload_mbps=1000, download_mbps=1000, rtt_ms=10, allow_symmetric=True)
    slow = rank(data, upload_mbps=1, download_mbps=1000, rtt_ms=10, allow_symmetric=True)
    assert fast[0].variant == "public"
    assert fast[0].estimated_ms == pytest.approx(20.808)
    assert slow[0].variant == "seeded"
    assert slow[0].estimated_ms == pytest.approx(110.008)


def test_capabilities_exclude_variants_and_refill_changes_cost():
    data = fixture_report()
    settings = dict(upload_mbps=100, download_mbps=100)
    assert [x.variant for x in rank(data, **settings)] == ["public"]
    eligible = dict(allow_partial_scores=True, allow_symmetric=True, allow_precompute=True)
    assert rank(data, **settings, **eligible)[0].variant == "partial-2-seeded-pool"
    assert (
        rank(data, **settings, **eligible, include_refill=True)[-1].variant
        == "partial-2-seeded-pool"
    )
    for capability in eligible:
        changed = eligible | {capability: False}
        assert all(x.variant != "partial-2-seeded-pool" for x in rank(data, **settings, **changed))


@pytest.mark.parametrize(
    "upload,download,rtt",
    [(0, 1, 0), (1, -1, 0), (1, 1, -1), (float("inf"), 1, 0), (1, 1, float("nan"))],
)
def test_invalid_network_values_rejected(upload, download, rtt):
    with pytest.raises(ValueError):
        rank(fixture_report(), upload_mbps=upload, download_mbps=download, rtt_ms=rtt)


def test_unverified_or_missing_measurement_rejected():
    data = fixture_report()
    data["all_distances_and_top3_correct"] = False
    with pytest.raises(ValueError):
        rank(data, upload_mbps=100, download_mbps=100)
    data = fixture_report()
    data["results"][0]["samples"] = []
    with pytest.raises(ValueError):
        rank(data, upload_mbps=100, download_mbps=100)
