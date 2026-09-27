"""Independent serial-cost examples and malformed measurement rejection."""

from copy import deepcopy
from dataclasses import replace

import pytest

from experiments.bfv_search_lab import radix_planner as planner
from experiments.bfv_search_lab.radix_bgv import Layout


def report():
    cases, samples, methods, variants = {}, {}, {}, {}
    for label, group, seconds, query, response in (("g1", 1, .1, 100, 200), ("distance2", 2, .04, 500, 80)):
        layout = Layout(3, group)
        plan = dict(terminal_bits=25, query_drop=5, response_drop=4, query_bytes=query, response_bytes=response)
        q, r = (layout.packet_size(v, 8, k) for v, k in ((query, "query"), (response, "response")))
        setup = dict.fromkeys(planner.SETUP_FIELDS, .1)
        setup.update(full_index_coefficient_bytes=1000, full_key_coefficient_bytes=200)
        name = label+"-p0"
        cases[name] = dict(layout=vars(layout), layout_name=label, selected=plan, pareto_frontier=[plan.copy()],
                           query_bytes=q, response_bytes=r, setup=setup, n=8, t=1031)
        samples[name+"/local"] = [dict(total_s=seconds, query_bytes=q, response_bytes=r)]*3
        samples[name+"/test"] = [dict(total_s=seconds+1)]*2
        methods[name] = "native" if group == 1 else "numpy"
        variants[name] = name
    return dict(kind="bgv_radix", all_precision=True, packed_radix=True, vectorized_radix=True,
                num_vectors=8, dimension=3, repeats=3, transport_repeats=2,
                links_upload_mbps_download_mbps_rtt_ms={"test": (1, 1, 10)},
                results={"owner": dict(cases=cases, samples=samples, plaintext_decoders=methods, variants=variants,
                                       all_distances_and_stable_top3_correct=True)})


def test_only_explicit_radix_and_measured_precision_choices():
    assert [r.layout for r in planner.rank(report())] == ["g1"]
    rows = planner.rank(report(), allow_radix=True, resident_layouts=tuple(planner.LAYOUTS))
    assert [r.layout for r in rows] == ["distance2", "g1"]
    assert rows[0].amortized_ms_floor == 40


def test_setup_reencryption_transfer_floor_and_epoch_amortization():
    d = report()
    rows = planner.rank(d, allow_radix=True, upload_mbps=1, download_mbps=2, rtt_ms=10,
                        epoch_queries=20, resident_layouts=("g1",))
    by = {r.layout: r for r in rows}
    for name, row in by.items():
        expected = row.local_ms+10+8*(row.query_bytes+4)/1000+8*(row.response_bytes+4)/2000
        assert row.steady_ms == expected
        setup = 0 if name == "g1" else 1000+8*1200/1000
        assert row.setup_ms_floor == pytest.approx(setup)
        assert row.amortized_ms_floor == pytest.approx(expected+setup/20)
    threshold = planner.break_even_queries(by["distance2"], by["g1"])
    assert threshold > 1
    for horizon, faster in ((threshold-1, False), (threshold, True)):
        a, b = by["distance2"], by["g1"]
        assert (a.steady_ms+a.setup_ms_floor/horizon <= b.steady_ms) is faster


def test_break_even_has_no_persistent_threshold_for_slower_steady_state():
    e = planner.rank(report())[0]
    assert planner.break_even_queries(replace(e, steady_ms=e.steady_ms+1, setup_ms_floor=0), e) is None
    assert planner.break_even_queries(e, e) == 1
    assert planner.break_even_queries(replace(e, setup_ms_floor=e.setup_ms_floor+1), e) is None


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(all_precision=False),
    lambda d: d['results']['owner'].update(all_distances_and_stable_top3_correct=False),
    lambda d: d['results']['owner']['samples']['g1-p0/local'][0].update(total_s=float('nan')),
    lambda d: d['results']['owner']['cases']['g1-p0'].update(query_bytes=3),
    lambda d: d['results']['owner']['cases']['g1-p0']['selected'].update(terminal_bits=24),
    lambda d: d['results']['owner']['cases']['g1-p0']['setup'].update(full_key_coefficient_bytes=0),
])
def test_invalid_or_unmeasured_points_are_rejected(mutation):
    d = deepcopy(report())
    mutation(d)
    with pytest.raises(ValueError):
        planner.rank(d)


@pytest.mark.parametrize("settings", [dict(upload_mbps=1), dict(upload_mbps=0, download_mbps=1),
    dict(epoch_queries=True), dict(resident_layouts=("unknown",)), dict(rtt_ms=1)])
def test_invalid_model_settings(settings):
    with pytest.raises(ValueError):
        planner.rank(report(), **settings)


def test_transport_predictions_use_local_samples_then_score_other_samples():
    result = planner.transport_validation(report())["test"]
    assert result['predicted']['layout'] == "distance2"
    assert result['measured_best'] == "distance2-p0"
    assert result['measured_regret_ms'] == 0


def test_fresh_layout_costs_terminal_preparation_despite_later_cache_hit():
    d = report()
    r = d['results']['owner']
    r['cases']['g1-p1'] = deepcopy(r['cases']['g1-p0'])
    r['cases']['g1-p1']['setup']['terminal_prepare_s'] = 0
    r['samples']['g1-p1/local'] = deepcopy(r['samples']['g1-p0/local'])
    r['variants']['g1-p1'] = 'g1-p1'
    r['plaintext_decoders']['g1-p1'] = 'native'
    rows = planner.rank(d)
    assert rows[0].setup_compute_ms == pytest.approx(1000)
    assert rows[1].setup_compute_ms == rows[0].setup_compute_ms
