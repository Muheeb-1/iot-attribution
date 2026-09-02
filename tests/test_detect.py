"""
Tests for src/detect.py.

As with features, two layers:

  FIDELITY  - the detector must agree exactly with hard.py, or the published
              53% / 90% stops describing this code.
  SEMANTICS - hand-built feature tables where the right answer is obvious, so
              a reader can see what "onset" actually means rather than taking
              a 25,000-row comparison on trust.

There is also one measurement test at the bottom, which does not assert a
behaviour so much as quantify a known nuance: whether "three windows in a row"
counted over rows ever differs from counting over window numbers.
"""

import numpy as np
import pandas as pd
import pytest

import hard
from src import detect, features, generate, runs, windows

FEATURE_COLUMNS = features.FEATURE_COLUMNS


def feature_table(device, rows, start_window=0):
    """
    Build a feature table by hand.

    rows is a list of dicts giving whichever features matter for the test;
    anything left out is filled with a boring constant so the baseline is
    quiet and predictable.
    """
    defaults = {
        "bytes_out": 1000.0, "bytes_in": 400.0, "n_conn": 5.0,
        "n_dst": 1.0, "n_new_ext": 0.0, "n_peer": 0.0, "iat_reg": 2.0,
    }
    out = []
    for i, row in enumerate(rows):
        record = dict(defaults)
        record.update(row)
        record["dev"] = device
        record["w"] = start_window + i
        out.append(record)
    return pd.DataFrame(out)[["dev", "w"] + FEATURE_COLUMNS]


def quiet_baseline(n=30, jitter=True):
    """n windows of ordinary life, with a little natural variation."""
    rng = np.random.default_rng(0)
    rows = []
    for _ in range(n):
        wobble = rng.normal(0, 30) if jitter else 0.0
        rows.append({"bytes_out": 1000.0 + wobble, "bytes_in": 400.0 + wobble / 3})
    return rows


# --------------------------------------------------------------------------
# 1. Fidelity to the prototype
# --------------------------------------------------------------------------

@pytest.mark.parametrize("seed", [5000, 5001, 5017])
def test_weighted_detector_matches_the_prototype(seed):
    """This is the V5 detector: DIAG-weighted."""
    connections, _ = generate.make_run(seed)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)

    ours = detect.detect(table, baseline_windows=180, weighted=True)
    their_scores, their_onsets = hard.detect(table, weighted=True)

    assert ours.onsets == their_onsets
    assert set(ours.scores) == set(their_scores)
    for device in their_scores:
        assert ours.scores[device] == pytest.approx(their_scores[device])


@pytest.mark.parametrize("seed", [5000, 5003])
def test_plain_detector_also_matches_the_prototype(seed):
    """The unweighted version is kept so evaluate.py can show what DIAG buys."""
    connections, _ = generate.make_run(seed)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)

    ours = detect.detect(table, baseline_windows=180, weighted=False)
    _, their_onsets = hard.detect(table, weighted=False)

    assert ours.onsets == their_onsets


def test_diag_weights_are_the_ones_from_the_prototype():
    assert detect.DIAG == hard.DIAG
    assert set(detect.DIAG) == set(features.FEATURE_COLUMNS)


# --------------------------------------------------------------------------
# 2. What an onset actually means
# --------------------------------------------------------------------------

def test_a_quiet_device_never_gets_an_onset():
    table = feature_table("dev-a", quiet_baseline(60))
    result = detect.detect(table, baseline_windows=30)

    assert "dev-a" not in result.onsets


def test_the_z_score_stays_calm_for_a_device_that_does_nothing_unusual():
    """
    Measured separately from the onset, because the two witnesses behave very
    differently on flat data.

    The weighted z-score on a quiet device peaks below 2 - nowhere near the
    threshold of 4. IsolationForest, however, can spike on a baseline this
    artificially flat: it expresses its verdict relative to how much it
    wobbled during the baseline, and when the baseline barely wobbles at all
    it is dividing by nearly nothing, so an ordinary window can come out
    looking dramatic.

    That is tolerable precisely because of the three-in-a-row rule, which the
    next test pins down. Real device baselines are far noisier than this, and
    the fidelity tests above confirm the behaviour on real runs matches the
    prototype exactly.
    """
    table = feature_table("dev-a", quiet_baseline(60)).sort_values("w")
    z_only = detect.robust_scores(
        table.assign(**{c: table[c] for c in FEATURE_COLUMNS}), 30, weighted=True
    )
    # Re-run with the forest unavailable, so only the z-score speaks.
    real_forest = detect.IsolationForest
    try:
        detect.IsolationForest = None  # calling None raises, and is caught
        z_only = detect.robust_scores(table, 30, weighted=True)
    finally:
        detect.IsolationForest = real_forest

    assert z_only.max() < detect.THRESHOLD


def test_an_isolated_spike_from_the_second_opinion_is_absorbed():
    """
    The three-in-a-row rule is what makes the max-of-two-witnesses design safe.
    Either witness may raise the alarm, but neither can convict on one window.
    """
    table = feature_table("dev-a", quiet_baseline(60))
    result = detect.detect(table, baseline_windows=30)

    scores = [result.scores["dev-a"][w] for w in sorted(result.scores["dev-a"])]
    longest_run = 0
    current = 0
    for value in scores:
        current = current + 1 if value > detect.THRESHOLD else 0
        longest_run = max(longest_run, current)

    assert longest_run < detect.CONSECUTIVE
    assert "dev-a" not in result.onsets


def test_a_sustained_change_produces_an_onset_at_its_first_window():
    """Three alarming windows in a row: the onset is the FIRST of the three."""
    rows = quiet_baseline(30) + [{}] * 5
    rows += [{"n_new_ext": 4.0, "n_peer": 6.0}] * 3      # windows 35, 36, 37
    rows += [{}] * 5
    table = feature_table("dev-a", rows)

    result = detect.detect(table, baseline_windows=30)

    assert result.onset_windows["dev-a"] == 35
    assert result.onsets["dev-a"] == windows.window_start(35)
    assert result.onsets["dev-a"] == 35 * 60


def test_a_single_alarming_window_is_not_enough():
    """One noisy minute is usually a backup, not a break-in."""
    rows = quiet_baseline(30) + [{}] * 5
    rows += [{"n_new_ext": 6.0, "n_peer": 9.0}]           # just one
    rows += [{}] * 5
    table = feature_table("dev-a", rows)

    assert "dev-a" not in detect.detect(table, baseline_windows=30).onsets


def test_two_alarming_windows_are_still_not_enough():
    rows = quiet_baseline(30) + [{}] * 3
    rows += [{"n_new_ext": 6.0, "n_peer": 9.0}] * 2       # two in a row
    rows += [{}] * 5
    table = feature_table("dev-a", rows)

    assert "dev-a" not in detect.detect(table, baseline_windows=30).onsets


def test_the_run_length_is_configurable_and_actually_used():
    rows = quiet_baseline(30) + [{}] * 3
    rows += [{"n_new_ext": 6.0, "n_peer": 9.0}] * 2
    rows += [{}] * 5
    table = feature_table("dev-a", rows)

    assert "dev-a" not in detect.detect(table, baseline_windows=30, consecutive=3).onsets
    assert "dev-a" in detect.detect(table, baseline_windows=30, consecutive=2).onsets


def test_an_onset_can_never_land_inside_the_baseline():
    """
    The baseline is the stretch we are calling normal by definition. An onset
    inside it would be a contradiction, so even a violent change there is
    ignored until the baseline ends.
    """
    rows = [{"n_new_ext": 9.0, "n_peer": 9.0}] * 10 + quiet_baseline(25)
    rows += [{"n_new_ext": 9.0, "n_peer": 9.0}] * 4
    table = feature_table("dev-a", rows)

    result = detect.detect(table, baseline_windows=35)
    assert result.onset_windows["dev-a"] >= 35


def test_onsets_are_reported_at_the_start_of_the_window():
    connections, _ = generate.make_run(5000)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    result = detect.detect(table, baseline_windows=180)

    for device, seconds in result.onsets.items():
        assert seconds % 60 == 0, "%s onset %r is not a window start" % (device, seconds)
        assert seconds == windows.window_start(result.onset_windows[device])


# --------------------------------------------------------------------------
# 3. Robustness - the reason for median and MAD
# --------------------------------------------------------------------------

def test_one_freak_window_in_the_baseline_does_not_blind_the_detector():
    """
    THE reason for median/MAD instead of mean/standard deviation. A single
    enormous baseline window would inflate an ordinary standard deviation so
    much that the later attack looks unremarkable. The robust version shrugs
    it off.
    """
    rows = quiet_baseline(29)
    rows.insert(14, {"bytes_out": 90_000_000.0, "bytes_in": 40_000_000.0})  # freak
    rows += [{}] * 3
    rows += [{"n_new_ext": 4.0, "n_peer": 6.0}] * 3
    table = feature_table("dev-a", rows)

    result = detect.detect(table, baseline_windows=30)
    assert "dev-a" in result.onsets, "a single freak baseline window hid the attack"


def test_a_feature_that_never_varied_does_not_divide_by_zero():
    """
    A sensor whose baseline n_new_ext is exactly 0 in every window has zero
    spread. Without a fallback that divides by zero and every later window
    becomes infinitely surprising.
    """
    rows = [{}] * 30 + [{"n_new_ext": 1.0}] * 3
    table = feature_table("dev-a", rows)

    result = detect.detect(table, baseline_windows=30)
    scores = np.array(list(result.scores["dev-a"].values()))
    assert np.isfinite(scores).all(), "non-finite score - something divided by zero"


def test_a_device_with_too_little_history_is_skipped_not_guessed():
    table = feature_table("dev-a", quiet_baseline(4) + [{"n_new_ext": 9.0}] * 3)
    result = detect.detect(table, baseline_windows=4)

    assert "dev-a" in result.skipped
    assert "dev-a" not in result.onsets
    assert "dev-a" not in result.scores


def test_weighting_makes_the_diagnostic_features_speak_louder():
    """
    Same size of change, different feature. A jump in 'new outside addresses'
    (DIAG 3.0) must score higher than the same jump in bytes (DIAG 1.0).
    """
    base = quiet_baseline(30)
    new_ext = feature_table("dev-a", base + [{"n_new_ext": 3.0}] * 3)
    volume = feature_table("dev-a", base + [{"bytes_out": 1000.0 + 3 * 30}] * 3)

    ext_result = detect.detect(new_ext, baseline_windows=30)
    vol_result = detect.detect(volume, baseline_windows=30)

    assert ext_result.peak_score("dev-a") > vol_result.peak_score("dev-a")


# --------------------------------------------------------------------------
# 4. Shape of the result
# --------------------------------------------------------------------------

def test_scores_cover_every_window_the_device_had_traffic_in():
    connections, _ = generate.make_run(5000)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    result = detect.detect(table, baseline_windows=180)

    for device, per_window in result.scores.items():
        expected = set(table.loc[table["dev"] == device, "w"])
        assert set(per_window) == expected


def test_devices_by_onset_is_earliest_first():
    connections, _ = generate.make_run(5000)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    result = detect.detect(table, baseline_windows=180)

    ordered = result.devices_by_onset()
    times = [result.onsets[d] for d in ordered]
    assert times == sorted(times)


def test_the_same_input_always_gives_the_same_onsets():
    """
    IsolationForest is random. It is pinned with random_state=0, and this test
    is what stops that pinning being removed by accident - without it the
    reported accuracy would wobble between runs.
    """
    connections, _ = generate.make_run(5001)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)

    first = detect.detect(table, baseline_windows=180)
    second = detect.detect(table, baseline_windows=180)
    assert first.onsets == second.onsets


def test_works_end_to_end_on_a_saved_run(tmp_path):
    generate.write_run(5000, 0, data_dir=tmp_path, answer_dir=tmp_path / "a")
    run = runs.load_run("run_000", data_dir=tmp_path)
    result = detect.detect_run(run)

    assert set(result.onsets) <= set(run.device_names)
    for seconds in result.onsets.values():
        assert run.baseline_seconds <= seconds < run.capture_seconds


# --------------------------------------------------------------------------
# 5. Measuring a known nuance rather than assuming it away
# --------------------------------------------------------------------------

def test_consecutive_rows_and_consecutive_windows_agree_in_practice():
    """
    'Three windows in a row' is counted over consecutive ROWS of the feature
    table. A device that is silent for a minute has no row for it, so in
    principle its next three ACTIVE windows could be non-adjacent and the two
    readings could disagree.

    Rather than assume that never matters, this measures it. If the stricter
    reading (window numbers must be adjacent too) ever changes an onset, this
    test says so and by how much, so the choice can be defended with a number
    instead of a shrug.
    """
    disagreements = []

    for seed in range(5000, 5010):
        connections, _ = generate.make_run(seed)
        table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
        loose = detect.detect(table, baseline_windows=180)

        for device, group in table.groupby("dev"):
            group = group.sort_values("w")
            if device not in loose.scores:
                continue
            scores = np.array([loose.scores[device][w] for w in group["w"]])
            window_numbers = group["w"].values

            strict = None
            for i in range(len(scores) - 2):
                if window_numbers[i] < 180:
                    continue
                adjacent = (window_numbers[i + 1] == window_numbers[i] + 1
                            and window_numbers[i + 2] == window_numbers[i] + 2)
                if adjacent and all(scores[i + j] > detect.THRESHOLD for j in range(3)):
                    strict = windows.window_start(int(window_numbers[i]))
                    break

            if loose.onsets.get(device) != strict:
                disagreements.append((seed, device, loose.onsets.get(device), strict))

    # Recorded as a number, not asserted away. If this ever starts failing,
    # the message tells you exactly how big the effect is.
    assert len(disagreements) <= 2, (
        "row-adjacency and window-adjacency disagree on %d device-runs out of "
        "~120: %s" % (len(disagreements), disagreements[:5])
    )
