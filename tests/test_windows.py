"""
Tests for src/windows.py - the single shared time-window helper.

WHY THIS FILE EXISTS, AND WHY IT WAS WRITTEN BEFORE THE CODE
------------------------------------------------------------
Every number this project produces depends on chopping the timeline into
60-second windows. If that chopping is off by one window then:

  * a device's "normal" gets learned from a window that actually contains
    attack traffic, so the attack starts to look normal; and
  * onset times shift by 60 seconds, which changes which device looks
    earliest, which changes which device gets blamed.

Nothing would crash. The results would just be quietly wrong. That is the
worst kind of bug in a measurement project, so the rules are pinned down
here before a single line of the helper exists.

THE RULE: windows are HALF-OPEN, [start, start + width).
Window w covers every timestamp t where  w*width <= t < (w+1)*width.
A timestamp landing exactly on a boundary belongs to the LATER window.
"""

import math

import numpy as np
import pandas as pd
import pytest

from src import windows as W


# --------------------------------------------------------------------------
# The basics
# --------------------------------------------------------------------------

def test_default_window_is_60_seconds():
    """The whole project is specified in 60-second windows."""
    assert W.WINDOW_SECONDS == 60


def test_time_zero_is_window_zero():
    assert W.window_of(0) == 0
    assert W.window_of(0.0) == 0


def test_timestamp_inside_the_first_window():
    assert W.window_of(1) == 0
    assert W.window_of(30.5) == 0
    assert W.window_of(59) == 0


# --------------------------------------------------------------------------
# The off-by-one that would silently ruin every result
# --------------------------------------------------------------------------

def test_boundary_belongs_to_the_later_window():
    """[t, t+w) means 60.0 opens window 1 - it does NOT close window 0."""
    assert W.window_of(60.0) == 1
    assert W.window_of(120.0) == 2
    assert W.window_of(3600.0) == 60


def test_just_below_a_boundary_stays_in_the_earlier_window():
    assert W.window_of(59.999) == 0
    assert W.window_of(119.999) == 1


def test_windows_tile_the_timeline_with_no_gaps_and_no_overlaps():
    """
    Walk a long stretch of time in small steps. The window number must never
    skip a value and never go backwards - i.e. the windows fit together edge
    to edge, covering every instant exactly once.
    """
    previous = W.window_of(0)
    t = 0.0
    while t < 3600:
        current = W.window_of(t)
        assert current in (previous, previous + 1), "window jumped at t=%r" % t
        previous = current
        t += 0.25
    assert previous == 59  # 3599.75s is still inside window 59


def test_every_timestamp_falls_inside_its_own_window_bounds():
    """The round trip must be self-consistent: start <= t < end."""
    for t in [0, 0.001, 59.9, 60, 61, 599.5, 3599.9, 3600, 12345.678]:
        w = W.window_of(t)
        start, end = W.window_bounds(w)
        assert start <= t < end, "t=%r escaped window %r" % (t, w)


# --------------------------------------------------------------------------
# Converting the other way
# --------------------------------------------------------------------------

def test_window_start_is_the_first_instant_of_the_window():
    assert W.window_start(0) == 0.0
    assert W.window_start(1) == 60.0
    assert W.window_start(180) == 10800.0


def test_window_bounds_are_start_and_start_plus_width():
    assert W.window_bounds(0) == (0.0, 60.0)
    assert W.window_bounds(7) == (420.0, 480.0)


def test_window_start_round_trips_back_to_the_same_window():
    for w in [0, 1, 5, 180, 359]:
        assert W.window_of(W.window_start(w)) == w


# --------------------------------------------------------------------------
# Baseline helper - used by detect.py to decide "learn normal from here"
# --------------------------------------------------------------------------

def test_baseline_window_count_for_three_hours():
    """3 hours of baseline = 180 windows, numbered 0..179."""
    assert W.baseline_window_count(3 * 3600) == 180


def test_last_baseline_window_is_in_and_first_post_window_is_out():
    """
    The baseline test is 'window number < baseline_window_count'. Window 179
    ends at 10800s, the exact 3-hour mark, so it is the last baseline window.
    Window 180 starts at 10800s and is NOT baseline.
    """
    n = W.baseline_window_count(3 * 3600)
    assert W.window_of(10799.999) == n - 1
    assert W.window_of(10800.0) == n


def test_baseline_window_count_rejects_a_partial_window():
    """A baseline that is not a whole number of windows is a spec error."""
    with pytest.raises(ValueError):
        W.baseline_window_count(90)  # 1.5 windows


# --------------------------------------------------------------------------
# Whole columns at once - features.py converts an entire traffic table
# --------------------------------------------------------------------------

def test_works_on_a_numpy_array_and_matches_the_scalar_answer():
    ts = np.array([0.0, 59.9, 60.0, 60.1, 3600.0])
    got = W.window_of(ts)
    assert isinstance(got, np.ndarray)
    assert got.tolist() == [0, 0, 1, 1, 60]
    assert got.tolist() == [W.window_of(float(t)) for t in ts]


def test_works_on_a_pandas_series_and_keeps_the_index():
    s = pd.Series([0.0, 60.0, 130.0], index=[10, 11, 12])
    got = W.window_of(s)
    assert isinstance(got, pd.Series)
    assert got.index.tolist() == [10, 11, 12]
    assert got.tolist() == [0, 1, 2]


def test_result_is_a_whole_number_type_not_a_float():
    """Window numbers are used as groupby keys, so they must be integers."""
    assert isinstance(W.window_of(90.0), int)
    assert np.issubdtype(W.window_of(np.array([90.0])).dtype, np.integer)


def test_empty_input_is_allowed_and_gives_an_empty_result():
    got = W.window_of(np.array([]))
    assert len(got) == 0


# --------------------------------------------------------------------------
# A different window width still obeys the same rule
# --------------------------------------------------------------------------

def test_custom_window_width():
    assert W.window_of(0, 10) == 0
    assert W.window_of(9.99, 10) == 0
    assert W.window_of(10.0, 10) == 1
    assert W.window_bounds(3, 10) == (30.0, 40.0)
    assert W.baseline_window_count(100, 10) == 10


# --------------------------------------------------------------------------
# Refusing nonsense loudly, instead of returning a wrong number quietly
# --------------------------------------------------------------------------

def test_negative_time_is_rejected():
    """t is 'seconds since the capture started', so it can never be negative."""
    with pytest.raises(ValueError):
        W.window_of(-1)
    with pytest.raises(ValueError):
        W.window_of(np.array([5.0, -0.001]))


def test_not_a_number_is_rejected():
    with pytest.raises(ValueError):
        W.window_of(float("nan"))
    with pytest.raises(ValueError):
        W.window_of(float("inf"))
    with pytest.raises(ValueError):
        W.window_of(np.array([1.0, np.nan]))


def test_zero_or_negative_window_width_is_rejected():
    for bad in (0, -60):
        with pytest.raises(ValueError):
            W.window_of(100, bad)
        with pytest.raises(ValueError):
            W.window_start(1, bad)


def test_negative_window_number_is_rejected():
    with pytest.raises(ValueError):
        W.window_start(-1)
    with pytest.raises(ValueError):
        W.window_bounds(-1)


def test_text_is_rejected():
    with pytest.raises((TypeError, ValueError)):
        W.window_of("60")


# --------------------------------------------------------------------------
# Guard against a "clever" reimplementation drifting from the spec
# --------------------------------------------------------------------------

def test_matches_plain_floor_division_over_a_wide_range():
    rng = np.random.default_rng(0)
    for t in rng.uniform(0, 24 * 3600, size=2000):
        assert W.window_of(float(t)) == math.floor(t / 60.0)
