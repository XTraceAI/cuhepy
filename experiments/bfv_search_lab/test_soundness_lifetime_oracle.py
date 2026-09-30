"""Known ideal bound versus invalid conditional and reset shortcuts."""

from fractions import Fraction

from experiments.bfv_search_lab import soundness_lifetime_oracle as oracle


def test_all_bounded_rejection_path_policies_and_exact_event_probabilities():
    for attempts, expected in enumerate((Fraction(1, 9), Fraction(17, 81), Fraction(25, 81)), start=1):
        result = oracle.enumerate_first_failure(budget=attempts)
        assert result["maximum_first_failure_probability"] == expected
        assert result["policies_checked"] == 4 ** attempts
    assert oracle.enumerate_first_failure(q=5, rounds=2, budget=3)["maximum_first_failure_probability"] <= Fraction(3, 25)


def test_epoch_resets_exceed_claimed_budget_and_conditional_rate_increases():
    result = oracle.conditional_and_reset_counterexamples()
    assert result["third_conditional_probability_after_two_rejections"] == Fraction(1, 8)
    assert result["two_independent_epochs_with_three_attempts_each_first_failure"] == Fraction(3425, 6561)
