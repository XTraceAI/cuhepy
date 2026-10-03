"""E103 complete small-universe exactness, owner coverage and paid slot checks."""

from dataclasses import replace
from itertools import product

import pytest

from experiments.bfv_search_lab import owner_summary_oracle as lab

EPOCH = bytes(range(32))


def reference(records, query):
    # Independent complete sorting control; duplicates with distinct IDs survive.
    return tuple(sorted(((row ^ query).bit_count(), stable_id, row) for stable_id, row in records)[:3])


def exhaustive_cases():
    for count in range(4):
        for words in product(range(8), repeat=count):
            records = tuple((2 * (count - i) + 1, word) for i, word in enumerate(words))
            layouts = ((records,), (records[:1], (), records[1:]))
            for groups in layouts:
                owner = lab.enroll(records, groups, 3, EPOCH)
                for query in range(8):
                    yield records, owner, query


def test_exhaust_ordered_small_binary_universe_with_duplicates_and_uneven_empty_groups():
    checked = 0
    for records, owner, query in exhaustive_cases():
        expected = reference(records, query)
        for budget in (None, len(owner.blocks)):
            result = lab.search(owner.manifest, query, owner.fetch, budget=budget)
            assert result.certified and result.top3 == expected
            if budget is not None:
                assert result.paid_slots == budget
                assert result.record_distance_evaluations == budget * owner.manifest.capacity
        checked += 1
    assert checked == 2 * 8 * sum(8 ** count for count in range(4)) == 9360


def test_all_queries_ties_far_words_short_live_sets_and_deletions():
    records = ((99, 0), (2, 1), (7, 1), (3, 2), (100, 15), (8, 8))
    cache = lab.MutableCache(records, 4)
    for deleted in ((), (99,), (2, 7, 3, 100)):
        for stable_id in deleted:
            cache.delete(stable_id)
        live = tuple(cache.rows.items())
        owner = lab.enroll(live, (live[:1], (), live[1:4], live[4:]), 4,
                           bytes([cache.mutations]) * 32)
        for query in range(16):
            expected = reference(live, query)
            assert cache.query(query) == expected
            assert lab.search(owner.manifest, query, owner.fetch).top3 == expected
            assert lab.search(owner.manifest, query, owner.fetch, budget=4).top3 == expected
    assert len(cache.rows) == 1
    cache.put(50, 15)
    cache.put(8, 0)
    assert cache.query(15) == reference(tuple(cache.rows.items()), 15)
    assert cache.mutations == 7


def test_owner_enrollment_rejects_omitted_changed_or_duplicate_live_coverage():
    records = ((99, 0), (2, 1), (7, 1), (3, 15))
    for groups in ((records[:-1],), (records, records[:1]), ((records[0], (2, 0)), records[2:])):
        with pytest.raises(ValueError, match="coverage|stable IDs"):
            lab.enroll(records, groups, 4, EPOCH)
    owner = lab.enroll(records, (records[:2], records[2:]), 4, EPOCH)
    for candidate in (
            replace(owner.manifest, groups=owner.manifest.groups[:-1]),
            replace(owner.manifest, count=2, groups=owner.manifest.groups[:-1]),
            replace(owner.manifest, epoch=bytes(32)),
            replace(owner.manifest, groups=(replace(owner.manifest.groups[0], radius=0), owner.manifest.groups[1])),
            replace(owner.manifest, groups=(replace(owner.manifest.groups[0], minimum_id=99), owner.manifest.groups[1]))):
        with pytest.raises(ValueError, match="counts|owner pin"):
            lab.pin_candidate(candidate, owner.manifest)
    assert lab.pin_candidate(owner.manifest, owner.manifest) is owner.manifest


def test_malicious_block_omission_substitution_duplicate_reply_and_stale_revision_reject():
    records = ((9, 0), (7, 1), (2, 1), (3, 15))
    owner = lab.enroll(records, (records[:2], records[2:]), 4, EPOCH)
    # Force full public slots. Every real block is needed or has its pinned digest
    # checked if fetched; a server may not substitute one block for another.
    for transform in (
            lambda packet: replace(packet, records=packet.records[:-1]),
            lambda packet: replace(packet, records=((packet.records[0][0], 8), *packet.records[1:])),
            lambda packet: replace(packet, epoch=bytes(32)),
            lambda packet: owner.fetch(1 - packet.index, EPOCH)):
        with pytest.raises(ValueError, match="block"):
            lab.search(owner.manifest, 0, lambda j, epoch, transform=transform: transform(owner.fetch(j, epoch)), budget=2)
    cache = lab.MutableCache(records, 4)
    cache.delete(7)
    live = tuple(cache.rows.items())
    revised = lab.enroll(live, (live[:1], live[1:]), 4, bytes([42]) * 32)
    with pytest.raises(ValueError, match="owner pin"):
        lab.pin_candidate(owner.manifest, revised.manifest)
    with pytest.raises(ValueError, match="Stale"):
        lab.search(revised.manifest, 0, lambda j, epoch: owner.fetch(j, EPOCH), budget=2)


def test_every_fixed_budget_has_identical_paid_counts_and_no_query_dependent_retry():
    records = tuple((i, i) for i in range(16))
    owner = lab.enroll(records, tuple(records[j:j + 4] for j in range(0, 16, 4)), 4, EPOCH)
    for budget in (1, 2, 4):
        for query in range(16):
            calls = []

            def fetch(index, epoch, calls=calls):
                calls.append(index)
                return owner.fetch(index, epoch)

            result = lab.search(owner.manifest, query, fetch, budget=budget)
            assert len(calls) == result.paid_slots == budget
            assert result.record_distance_evaluations == budget * 4
            assert result.downloaded_record_packet_bytes_model == budget * lab.padded_packet_bytes(owner.manifest)
            assert result.summary_distance_evaluations == 4
            if result.certified:
                assert result.top3 == reference(records, query)
            else:
                assert result.top3 is None  # No hidden retry or approximate answer.


def test_favorable_singletons_still_pay_dummy_records_after_logical_completion():
    records = ((1, 0), (2, 0), (3, 0), (4, 15), (5, 15))
    owner = lab.enroll(records, tuple((record,) for record in records), 4, EPOCH)
    result = lab.search(owner.manifest, 0, owner.fetch, budget=5)
    assert result.certified and len(result.fetched_groups) == 3 and result.dummy_slots == 2
    assert result.record_distance_evaluations == 5
    assert result.top3 == reference(records, 0)


def test_complementary_pair_geometry_has_a_full_scan_worst_case():
    records = tuple((i, i) for i in range(256))
    groups = tuple((records[i], records[i ^ 255]) for i in range(128))
    owner = lab.enroll(records, groups, 8, EPOCH)
    # Every coordinate is tied, so all centers are zero. At query zero every
    # group lower distance is zero; the worst-case corpus scan is unavoidable.
    assert all(group.centroid == 0 for group in owner.manifest.groups)
    all_rows = []
    for query in range(256):
        result = lab.search(owner.manifest, query, owner.fetch)
        assert result.top3 == reference(records, query)
        all_rows.append(result.fetched_records)
    # ID pruning can sometimes save groups even when all distance lower bounds
    # are zero. There still exists a query requiring the full corpus.
    assert max(all_rows) == len(records)
    assert not lab.search(owner.manifest, 0, owner.fetch, budget=32).certified


@pytest.mark.parametrize("dimension", (True, 0, 513))
def test_invalid_binary_dimension_rejects(dimension):
    with pytest.raises(ValueError):
        lab.enroll((), ((),), dimension, EPOCH)


def test_noncanonical_ids_rows_epochs_budgets_and_dummy_payloads_reject():
    for records in (((True, 0),), ((1, True),), ((1, 16),), ((1 << 64, 0),), ((1, 0), (1, 1))):
        with pytest.raises(ValueError):
            lab.enroll(records, (records,), 4, EPOCH)
    with pytest.raises(ValueError):
        lab.enroll((), ((),), 4, b"old")
    owner = lab.enroll((), ((),), 4, EPOCH)
    for budget in (0, True, 2):
        with pytest.raises(ValueError):
            lab.search(owner.manifest, 0, owner.fetch, budget=budget)
    with pytest.raises(ValueError, match="Dummy"):
        lab.search(owner.manifest, 0, lambda j, e: lab.Packet(e, None, ((1, 0),)), budget=1)
