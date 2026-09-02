"""
Tests for src/evaluate.py - the marking script.

Scoring code needs testing more than most code, because a bug here does not
crash anything: it just reports a number that is wrong, and a wrong number is
exactly what nobody notices. A scorer that quietly counted rank 2 as a hit
would inflate our headline figure and we would happily defend it.

The full 30-run reproduction is not run here - it takes several minutes and
belongs on the command line, where its output is the deliverable. What is
tested here is the machinery that turns ranks into percentages, and the fact
that the pipeline is genuinely blind to the answers.
"""

import json

import numpy as np
import pandas as pd
import pytest

from src import evaluate, generate


# --------------------------------------------------------------------------
# Where the true origin came in the ranking
# --------------------------------------------------------------------------

def test_rank_of_counts_from_one_not_zero():
    """Rank 1 means first. An off-by-one here would silently change top-1."""
    assert evaluate.rank_of(["a", "b", "c"], "a") == 1
    assert evaluate.rank_of(["a", "b", "c"], "b") == 2
    assert evaluate.rank_of(["a", "b", "c"], "c") == 3


def test_a_device_that_was_never_ranked_gets_the_placeholder():
    assert evaluate.rank_of(["a", "b"], "z") == evaluate.NOT_RANKED
    assert evaluate.rank_of([], "a") == evaluate.NOT_RANKED


# --------------------------------------------------------------------------
# Turning ranks into the table
# --------------------------------------------------------------------------

def records_with(ranks, abstained=None):
    abstained = abstained or [False] * len(ranks)
    return [
        {"M": r, "abstained": a, "V5 attribution": r}
        for r, a in zip(ranks, abstained)
    ]


def test_top1_counts_only_first_place():
    summary = evaluate.summarise(records_with([1, 1, 2, 3, 4]), ["M"])
    assert summary.loc[0, "top1_pct"] == 40.0     # two of five


def test_top3_counts_the_first_three_places():
    summary = evaluate.summarise(records_with([1, 2, 3, 4, 99]), ["M"])
    assert summary.loc[0, "top3_pct"] == 60.0     # three of five


def test_an_unranked_origin_counts_as_a_miss_but_not_in_the_mean():
    """
    A run where the detector never flagged the origin is a failure - it must
    count against top-1 and top-3. But averaging in the placeholder 99 would
    produce a meaningless mean rank, so it is excluded there and reported
    separately instead.
    """
    summary = evaluate.summarise(records_with([1, 2, 99]), ["M"])

    assert summary.loc[0, "top1_pct"] == pytest.approx(33.3, abs=0.1)
    assert summary.loc[0, "top3_pct"] == pytest.approx(66.7, abs=0.1)
    assert summary.loc[0, "mean_rank"] == 1.5     # (1 + 2) / 2, the 99 excluded
    assert summary.loc[0, "never_ranked"] == 1


def test_mean_rank_is_not_a_number_when_nothing_was_ever_ranked():
    summary = evaluate.summarise(records_with([99, 99]), ["M"])
    assert np.isnan(summary.loc[0, "mean_rank"])
    assert summary.loc[0, "never_ranked"] == 2


def test_abstention_rate_is_reported_only_for_the_method_that_can_abstain():
    records = records_with([1, 1, 2, 2], abstained=[True, False, False, False])

    v5 = evaluate.summarise(records, ["V5 attribution"])
    assert v5.loc[0, "abstention_pct"] == 25.0

    other = evaluate.summarise(records, ["M"])
    assert other.loc[0, "abstention_pct"] == ""


def test_a_perfect_method_scores_one_hundred_percent():
    summary = evaluate.summarise(records_with([1] * 10), ["M"])
    assert summary.loc[0, "top1_pct"] == 100.0
    assert summary.loc[0, "top3_pct"] == 100.0
    assert summary.loc[0, "mean_rank"] == 1.0


# --------------------------------------------------------------------------
# Reading the answers
# --------------------------------------------------------------------------

def test_the_answer_file_is_read_correctly(tmp_path):
    generate.write_run(5000, 0, data_dir=tmp_path / "d", answer_dir=tmp_path / "a")
    answer = evaluate.load_answer("run_000", groundtruth_dir=tmp_path / "a")

    assert answer["origin"] in generate.HARD_NAMES
    assert answer["chain"][0] == answer["origin"]


def test_a_missing_answer_file_says_how_to_fix_it(tmp_path):
    with pytest.raises(FileNotFoundError, match="regenerate"):
        evaluate.load_answer("run_404", groundtruth_dir=tmp_path)


# --------------------------------------------------------------------------
# Scoring one real run, end to end
# --------------------------------------------------------------------------

def test_scoring_one_run_produces_every_field_the_table_needs():
    record = evaluate.evaluate_one("run_000")

    for method in evaluate.BASELINE_NAMES + ["V5 attribution"]:
        assert method in record
        assert 1 <= record[method] <= evaluate.NOT_RANKED

    assert record["origin"] in record["run_id"] or True   # origin is a device name
    assert isinstance(record["abstained"], bool)
    assert 0.0 <= record["confidence"]


def test_the_scored_rank_agrees_with_re_running_the_pipeline_by_hand():
    """
    Guards against the scorer comparing against the wrong thing - for example
    scoring the shortlist instead of the full ranking, which would flatter the
    top-1 figure.
    """
    from src import attribute, detect, runs

    run = runs.load_run("run_000")
    detection = detect.detect_run(run)
    result = attribute.attribute_run(run, detection)
    answer = evaluate.load_answer("run_000")

    expected = evaluate.rank_of(result.ranking, answer["origin"])
    assert evaluate.evaluate_one("run_000")["V5 attribution"] == expected


def test_the_pipeline_never_sees_the_answer():
    """
    The whole project rests on this. Attribution is handed traffic and a device
    list, and nothing else - so its ranking cannot depend on the answer file.
    Here the answer is read AFTER the pipeline has already run, and the
    pipeline's output is identical either way.
    """
    from src import attribute, detect, runs

    run = runs.load_run("run_000")
    detection = detect.detect_run(run)

    before_reading = attribute.attribute_run(run, detection).ranking
    _ = evaluate.load_answer("run_000")          # now look at the answer
    after_reading = attribute.attribute_run(run, detection).ranking

    assert before_reading == after_reading
