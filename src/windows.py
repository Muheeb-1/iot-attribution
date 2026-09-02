"""
The ONE place in this project that turns a timestamp into a window number.

Every other file must call these functions rather than doing the arithmetic
itself. That is the entire point of the file: if the maths lives in five
places it will eventually disagree with itself, and the disagreement will not
crash anything - it will just make the results wrong in a way nobody notices.

THE DEFINITION
--------------
Time is measured in seconds since the capture started (t = 0.0 is the first
instant of the capture; there is no such thing as a negative timestamp).

The timeline is cut into fixed-width windows, and every window is HALF-OPEN:

    window w covers  [ w*width , (w+1)*width )

so the left edge is INSIDE the window and the right edge is OUTSIDE it.
With the default 60-second width:

    t = 0.0    -> window 0        t = 59.999 -> window 0
    t = 60.0   -> window 1        (the boundary opens the next window)
    t = 3600.0 -> window 60

Half-open is the right choice because it means the windows tile the timeline
perfectly: every instant belongs to exactly one window, with no gaps and no
double counting. If both edges were included, traffic landing exactly on a
boundary would be counted twice and would inflate two windows at once.

WHY THE FUNCTIONS ARE FUSSY
---------------------------
They raise an error on negative times, NaN, infinity, text, and non-positive
widths. Those inputs have no sensible answer, and silently returning a number
anyway is how a measurement project ends up defending results it cannot
justify. Failing loudly is cheaper than being quietly wrong.
"""

from __future__ import annotations

import math
import numbers

import numpy as np
import pandas as pd

# The window width the whole project is specified in. One minute is short
# enough to pin an attack's start down usefully, and long enough that a
# normally-quiet sensor still has some traffic in most windows.
WINDOW_SECONDS = 60


# --------------------------------------------------------------------------
# Internal checks
# --------------------------------------------------------------------------

def _check_width(window_seconds) -> float:
    """A window must have a real, positive length."""
    if isinstance(window_seconds, (str, bytes)) or not isinstance(
        window_seconds, numbers.Real
    ):
        raise TypeError(
            "window_seconds must be a number, got %r" % type(window_seconds).__name__
        )
    width = float(window_seconds)
    if not math.isfinite(width) or width <= 0:
        raise ValueError("window_seconds must be finite and > 0, got %r" % window_seconds)
    return width


def _check_scalar_time(t) -> float:
    """One timestamp: must be a real, finite, non-negative number."""
    if isinstance(t, (str, bytes)):
        raise TypeError("timestamp must be a number, not text: %r" % (t,))
    if not isinstance(t, numbers.Real):
        raise TypeError("timestamp must be a number, got %r" % type(t).__name__)
    value = float(t)
    if not math.isfinite(value):
        raise ValueError("timestamp must be a finite number, got %r" % (t,))
    if value < 0:
        raise ValueError(
            "timestamp must be >= 0 (seconds since capture start), got %r" % (t,)
        )
    return value


def _check_time_array(values: np.ndarray) -> np.ndarray:
    """A whole column of timestamps, checked in one go."""
    values = np.asarray(values, dtype=float)
    if values.size == 0:
        return values
    if not np.isfinite(values).all():
        raise ValueError("timestamps contain NaN or infinity")
    if (values < 0).any():
        raise ValueError("timestamps must be >= 0 (seconds since capture start)")
    return values


# --------------------------------------------------------------------------
# The public helpers
# --------------------------------------------------------------------------

def window_of(t, window_seconds=WINDOW_SECONDS):
    """
    Which window does this moment belong to?

    Accepts a single timestamp, or a whole column of them (a list, a numpy
    array, or a pandas Series - the Series keeps its index, so the answer can
    be assigned straight back onto a traffic table).

    Returns whole numbers, because window numbers are used as grouping keys.

        >>> window_of(59.9)
        0
        >>> window_of(60.0)
        1
    """
    width = _check_width(window_seconds)

    if isinstance(t, pd.Series):
        values = _check_time_array(t.to_numpy())
        numbers_out = np.floor(values / width).astype(np.int64)
        return pd.Series(numbers_out, index=t.index, name=t.name)

    if isinstance(t, (np.ndarray, list, tuple, pd.Index)):
        values = _check_time_array(np.asarray(t))
        return np.floor(values / width).astype(np.int64)

    return int(math.floor(_check_scalar_time(t) / width))


def window_start(w, window_seconds=WINDOW_SECONDS) -> float:
    """
    The first instant of window `w`, in seconds. This is the inverse of
    window_of: window_of(window_start(w)) == w, always.

    Used whenever a window number has to be reported back to a human, or
    compared against a raw packet timestamp.
    """
    width = _check_width(window_seconds)
    if isinstance(w, (str, bytes)) or not isinstance(w, numbers.Integral):
        raise TypeError("window number must be a whole number, got %r" % (w,))
    if w < 0:
        raise ValueError("window numbers start at 0, got %r" % (w,))
    return float(int(w) * width)


def window_bounds(w, window_seconds=WINDOW_SECONDS) -> tuple[float, float]:
    """
    The half-open span of window `w` as (start, end), meaning start <= t < end.

    Returned as a pair so that any code needing "all traffic in this window"
    filters with  t >= start  and  t < end  - never  t <= end,  which would
    steal the first packet of the following window.
    """
    width = _check_width(window_seconds)
    start = window_start(w, width)
    return start, start + width


def baseline_window_count(baseline_seconds, window_seconds=WINDOW_SECONDS) -> int:
    """
    How many windows make up the baseline ("learn what normal looks like")
    period, given its length in seconds.

    The baseline is then simply the windows numbered  0 .. count-1,  and the
    test for "is this window part of the baseline" is  w < count.  Because
    windows are half-open, the window numbered `count` starts exactly at the
    end of the baseline, so it is correctly excluded - no off-by-one.

    A baseline that is not a whole number of windows is refused: it would mean
    part of a window is "normal" and part is not, which nothing downstream
    could act on sensibly.
    """
    width = _check_width(window_seconds)
    if isinstance(baseline_seconds, (str, bytes)) or not isinstance(
        baseline_seconds, numbers.Real
    ):
        raise TypeError(
            "baseline_seconds must be a number, got %r" % type(baseline_seconds).__name__
        )
    seconds = float(baseline_seconds)
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("baseline_seconds must be finite and >= 0, got %r" % (baseline_seconds,))

    exact = seconds / width
    rounded = round(exact)
    if not math.isclose(exact, rounded, rel_tol=0, abs_tol=1e-9):
        raise ValueError(
            "baseline of %rs is not a whole number of %rs windows (%.4f windows)"
            % (baseline_seconds, window_seconds, exact)
        )
    return int(rounded)
