"""
Tests for src/features.py.

Two kinds of test here, and both matter for different reasons.

1. FIDELITY. The published benchmark numbers were measured with hard.py's
   feature calculation. If ours differs anywhere - a different definition of
   "new", population vs sample standard deviation, distinct peers instead of
   peer connections - the accuracy figures stop describing this code. So we
   compute the features both ways on a full 25,000-connection run and demand
   they match exactly.

2. SEMANTICS. The fidelity test would happily pass if both implementations
   were wrong in the same way, and it tells a reader nothing about what the
   numbers MEAN. So each feature is also tested on a handful of hand-written
   connections where the right answer can be worked out on paper.
"""

import numpy as np
import pandas as pd
import pytest

import hard
from src import features, generate, runs, windows

LAB = ["dev-a", "dev-b", "dev-c"]


def make_connections(records):
    """Tiny helper: build a traffic table from (t, src, dst, out, in) tuples."""
    return pd.DataFrame(
        [(t, s, d, o, i, 1) for t, s, d, o, i in records],
        columns=["t", "src", "dst", "bytes_out", "bytes_in", "pkts"],
    )


def one_row(table, dev, w):
    rows = table[(table["dev"] == dev) & (table["w"] == w)]
    assert len(rows) == 1, "expected exactly one row for %s in window %d, got %d" % (
        dev, w, len(rows)
    )
    return rows.iloc[0]


# --------------------------------------------------------------------------
# 1. Fidelity to the prototype
# --------------------------------------------------------------------------

@pytest.mark.parametrize("seed", [5000, 5001, 5017])
def test_features_match_the_prototype_exactly(seed):
    connections, _ = generate.make_run(seed)

    ours = features.build_features(
        connections, generate.HARD_NAMES, baseline_seconds=3 * 3600, window_seconds=60
    )
    theirs = hard.features(connections)

    ours = ours.sort_values(["dev", "w"]).reset_index(drop=True)
    theirs = theirs.sort_values(["dev", "w"]).reset_index(drop=True)

    assert list(ours.columns) == list(theirs.columns)
    pd.testing.assert_frame_equal(ours, theirs, check_dtype=False)


def test_feature_columns_are_the_seven_we_specified():
    assert features.FEATURE_COLUMNS == [
        "bytes_out", "bytes_in", "n_conn", "n_dst", "n_new_ext", "n_peer", "iat_reg"
    ]
    assert set(features.FEATURE_LABELS) == set(features.FEATURE_COLUMNS)


# --------------------------------------------------------------------------
# 2. What each number actually means
# --------------------------------------------------------------------------

def test_bytes_and_counts_are_summed_within_a_window():
    connections = make_connections([
        (10.0, "dev-a", "cloud", 100, 10),
        (20.0, "dev-a", "cloud", 200, 20),
        (30.0, "dev-a", "other", 300, 30),
    ])
    table = features.build_features(connections, LAB, baseline_seconds=60)
    row = one_row(table, "dev-a", 0)

    assert row["bytes_out"] == 600
    assert row["bytes_in"] == 60
    assert row["n_conn"] == 3
    assert row["n_dst"] == 2          # "cloud" and "other"


def test_window_boundary_is_half_open_here_too():
    """
    A connection at exactly 60.0 belongs to window 1, not window 0. This is
    the same rule as src/windows.py, and it is checked again here because
    features.py is where a stray reimplementation would do the damage.
    """
    connections = make_connections([
        (59.999, "dev-a", "cloud", 1, 1),
        (60.000, "dev-a", "cloud", 1, 1),
    ])
    table = features.build_features(connections, LAB, baseline_seconds=120)

    assert one_row(table, "dev-a", 0)["n_conn"] == 1
    assert one_row(table, "dev-a", 1)["n_conn"] == 1


def test_window_numbers_agree_with_the_shared_helper():
    connections, _ = generate.make_run(5000)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)

    for _, row in table.head(50).iterrows():
        matching = connections[
            (connections["src"] == row["dev"])
            & (windows.window_of(connections["t"]) == row["w"])
        ]
        assert len(matching) == row["n_conn"]


def test_n_peer_counts_connections_not_distinct_devices():
    """
    Ten connections to one laptop is a data transfer; one connection each to
    ten devices is a scan. Counting connections catches both; counting
    distinct devices would hide the transfer.
    """
    connections = make_connections(
        [(float(i), "dev-a", "dev-b", 10, 0) for i in range(10)]
        + [(50.0, "dev-a", "cloud", 10, 0)]
    )
    table = features.build_features(connections, LAB, baseline_seconds=60)
    row = one_row(table, "dev-a", 0)

    assert row["n_peer"] == 10        # ten connections, not one device
    assert row["n_dst"] == 2          # dev-b and cloud


def test_new_external_ignores_addresses_already_seen_in_the_baseline():
    connections = make_connections([
        # baseline: window 0
        (10.0, "dev-a", "cloud", 10, 0),
        # after baseline: window 1, same address as before
        (70.0, "dev-a", "cloud", 10, 0),
        # ...and one genuinely new outside address
        (80.0, "dev-a", "somewhere-new", 10, 0),
    ])
    table = features.build_features(connections, LAB, baseline_seconds=60)

    assert one_row(table, "dev-a", 0)["n_new_ext"] == 0   # baseline defines normal
    assert one_row(table, "dev-a", 1)["n_new_ext"] == 1   # only the new one counts


def test_new_external_ignores_lab_devices():
    """
    Talking to one of our own machines for the first time is suspicious in a
    different way, and n_peer already covers it. n_new_ext is about the
    outside world only.
    """
    connections = make_connections([
        (10.0, "dev-a", "cloud", 10, 0),          # baseline
        (70.0, "dev-a", "dev-b", 10, 0),          # new, but ours
        (80.0, "dev-a", "outside-host", 10, 0),   # new, and not ours
    ])
    table = features.build_features(connections, LAB, baseline_seconds=60)
    row = one_row(table, "dev-a", 1)

    assert row["n_new_ext"] == 1      # only "outside-host"
    assert row["n_peer"] == 1         # dev-b shows up here instead


def test_a_repeated_beacon_keeps_counting_as_new():
    """
    'New' is measured against the BASELINE, not against the previous window.
    So a device beaconing to the same outside address every minute keeps
    scoring n_new_ext = 1, minute after minute. If we had compared each window
    to everything before it, the beacon would have vanished after its first
    minute - exactly when we most want to see it.
    """
    records = [(10.0, "dev-a", "cloud", 10, 0)]                  # baseline
    records += [(60.0 + i * 30.0, "dev-a", "ext-c2", 10, 0) for i in range(6)]
    table = features.build_features(make_connections(records), LAB, baseline_seconds=60)

    later = table[(table["dev"] == "dev-a") & (table["w"] >= 1)]
    assert len(later) >= 3
    assert (later["n_new_ext"] == 1).all()


def test_regular_timing_scores_higher_than_bursty_timing():
    """
    iat_reg is the 'does this look like a machine on a timer' number.
    Higher = more regular.
    """
    regular = make_connections([(float(i) * 5.0, "dev-a", "cloud", 10, 0) for i in range(11)])
    bursty = make_connections(
        [(float(i) * 0.1, "dev-a", "cloud", 10, 0) for i in range(8)]
        + [(50.0, "dev-a", "cloud", 10, 0), (55.0, "dev-a", "cloud", 10, 0),
           (58.0, "dev-a", "cloud", 10, 0)]
    )

    regular_score = one_row(features.build_features(regular, LAB, 60), "dev-a", 0)["iat_reg"]
    bursty_score = one_row(features.build_features(bursty, LAB, 60), "dev-a", 0)["iat_reg"]

    assert regular_score > bursty_score
    assert regular_score == pytest.approx(1.0 / 0.05)   # perfectly even ticking


def test_too_few_connections_to_judge_timing_gets_a_neutral_score():
    """
    With four or fewer gaps there is not enough evidence to call the timing
    regular or irregular, so it gets a fixed middling value rather than a
    wild one computed from two numbers.
    """
    connections = make_connections([(float(i), "dev-a", "cloud", 10, 0) for i in range(3)])
    row = one_row(features.build_features(connections, LAB, 60), "dev-a", 0)
    assert row["iat_reg"] == pytest.approx(1.0 / 1.05)


# --------------------------------------------------------------------------
# Shape of the output
# --------------------------------------------------------------------------

def test_only_lab_devices_get_rows():
    """
    The broker relays the attacker's hop, but it is infrastructure. We are not
    trying to attribute an intrusion to a message queue.
    """
    connections = make_connections([
        (10.0, "dev-a", "cloud", 10, 0),
        (20.0, "broker", "dev-b", 10, 0),
        (30.0, "some-outside-host", "dev-c", 10, 0),
    ])
    table = features.build_features(connections, LAB, baseline_seconds=60)
    assert set(table["dev"]) == {"dev-a"}


def test_silent_windows_do_not_appear_at_all():
    """
    A window with no traffic is absent, not zero-filled. A row of zeros is
    indistinguishable from 'genuinely silent' and would drag the device's
    idea of normal downwards.
    """
    connections = make_connections([
        (10.0, "dev-a", "cloud", 10, 0),
        (610.0, "dev-a", "cloud", 10, 0),     # window 10, nothing in between
    ])
    table = features.build_features(connections, LAB, baseline_seconds=60)
    assert sorted(table["w"]) == [0, 10]


def test_empty_traffic_gives_an_empty_table_with_the_right_columns():
    empty = make_connections([]).astype({"t": float})
    table = features.build_features(empty, LAB, baseline_seconds=60)
    assert len(table) == 0
    assert list(table.columns) == ["dev", "w"] + features.FEATURE_COLUMNS


def test_the_same_traffic_always_gives_the_same_numbers():
    connections, _ = generate.make_run(5002)
    first = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    second = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    pd.testing.assert_frame_equal(first, second)


# --------------------------------------------------------------------------
# Splitting off the baseline
# --------------------------------------------------------------------------

def test_split_baseline_uses_a_half_open_cut():
    table = pd.DataFrame({
        "dev": ["dev-a"] * 4,
        "w": [178, 179, 180, 181],
        **{c: [0, 0, 0, 0] for c in features.FEATURE_COLUMNS},
    })
    baseline, later = features.split_baseline(table, 180)

    assert list(baseline["w"]) == [178, 179]   # 179 is the last baseline window
    assert list(later["w"]) == [180, 181]      # 180 starts at the 3-hour mark


# --------------------------------------------------------------------------
# Works on a real saved run, for both scenarios
# --------------------------------------------------------------------------

@pytest.mark.parametrize("easy,expected_devices", [(False, 12), (True, 7)])
def test_works_on_a_saved_run_of_either_difficulty(tmp_path, easy, expected_devices):
    seed = 1000 if easy else 5000
    generate.write_run(seed, 0, easy=easy, data_dir=tmp_path, answer_dir=tmp_path / "a")
    run_id = "easy_000" if easy else "run_000"

    run = runs.load_run(run_id, data_dir=tmp_path)
    table = features.features_for_run(run)

    assert len(run.device_names) == expected_devices
    assert set(table["dev"]) <= set(run.device_names)
    assert table["w"].min() >= 0
    assert table["w"].max() < run.capture_seconds / run.window_seconds
    assert not table[features.FEATURE_COLUMNS].isna().any().any()


def test_loader_complains_clearly_about_a_missing_run(tmp_path):
    with pytest.raises(FileNotFoundError, match="no traffic file"):
        runs.load_run("run_999", data_dir=tmp_path)
