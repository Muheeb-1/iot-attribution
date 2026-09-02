"""
DETECTION - learning what each device's normal looks like, then finding the
minute it stopped being normal.

THE IDEA IN ONE PARAGRAPH
-------------------------
There is no such thing as "normal traffic" in general. A camera streams 240 KB
every five seconds; a temperature sensor sends 200 bytes a minute. Judging
both against one global standard would flag the camera constantly and never
notice the sensor. So every device is judged ONLY against its own past: we
watch it for the first three hours (the baseline), work out what it usually
does, and then ask of every later minute "how far from your own usual is
this?" The answer is a single number per device per window, called the score.

WHY MEDIAN AND MAD, NOT MEAN AND STANDARD DEVIATION
---------------------------------------------------
The obvious way to measure "how unusual" is the ordinary z-score: how many
standard deviations from the mean. It has a nasty flaw here. The mean and the
standard deviation are both dragged around by extreme values, so a single
enormous window in the baseline inflates the standard deviation, which shrinks
every later score, which hides the attack. The very thing we are looking for
is the thing that blinds the measurement.

So we use the ROBUST version:
    median            instead of the mean      (middle value, ignores extremes)
    MAD               instead of the std       (median absolute deviation)

MAD is the median of "how far is each value from the median". One freak value
barely moves it. The 1.4826 multiplier is a standard constant that rescales
MAD so that, for well-behaved data, it means the same thing as a standard
deviation - so a score of 4 still means roughly "four sigma", and the
threshold stays interpretable.

WHY THE FEATURES ARE WEIGHTED (DIAG)
------------------------------------
Being unusual is not the same as being compromised. A device that sends twice
its normal data is unusual - and is very often just doing a backup. A device
that contacts an outside address it has never contacted in three hours is
unusual in a way that has far fewer innocent explanations.

DIAG says how DIAGNOSTIC each feature is of an actual compromise, and the
scores are weighted by it before we take the largest. This is what separates
the V5 detector from the plain one, and it is measurable: in the prototype's
comparison it is a large part of why V2 onwards beat V1.

    n_new_ext  3.0   contacting somewhere new and outside - hardest to explain
    n_peer     2.5   talking to our own other machines - lateral movement
    iat_reg    2.0   machine-like regularity - beacons tick, humans do not
    n_dst      1.5   suddenly talking to many places
    n_conn     1.2   lots of connections - could be a scan, could be a sync
    bytes_out  1.0   volume alone is weak evidence: backups look identical
    bytes_in   1.0   likewise

Everything is then divided by 1.6 so that raising the weights does not quietly
lower the threshold. The threshold of 4.0 keeps meaning what it meant before.

WHY A SECOND OPINION (ISOLATION FOREST)
---------------------------------------
The weighted z-score looks at each feature on its own, so it misses
combinations: a device whose byte count is normal AND whose destination count
is normal, but which has never had both at once. IsolationForest is a
machine-learning method that learns the SHAPE of normal across all seven
features together, and flags points that fall outside it.

We train it only on the baseline, score every window, and take whichever of
the two methods is more alarmed. Taking the maximum means either witness can
raise the alarm. That is deliberate: missing the origin entirely is far worse
for us than a false alarm, because a device with no onset cannot be ranked at
all, and the true origin then has no chance of being named.

WHY THREE WINDOWS IN A ROW
--------------------------
A single alarming minute is usually noise - one big download, one burst of
retries. A compromise persists: the beacon keeps beaconing. So the onset is
the first window that crosses the threshold AND stays crossed for three
consecutive windows. This trades a little sensitivity for a lot of precision,
and it is why the reported onset is the START of the sustained period rather
than its noisiest point.

WHAT COMES OUT
--------------
    scores  every device, every window, its anomaly score
    onsets  every device that ever went sustainedly abnormal, and WHEN

The onsets are the input to attribution in step 5. A device with no onset is
not a suspect - which is also this file's biggest way of failing: if the true
origin never crosses the threshold, no amount of clever reasoning downstream
can recover it. That failure is counted and reported by evaluate.py.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src import features, runs, windows

# How diagnostic each feature is of an actual compromise, rather than merely
# of an unusual day. See the docstring above for the reasoning.
DIAG = {
    "bytes_out": 1.0,
    "bytes_in": 1.0,
    "n_conn": 1.2,
    "n_dst": 1.5,
    "n_new_ext": 3.0,
    "n_peer": 2.5,
    "iat_reg": 2.0,
}

# Divides the weighted score back down so that raising the weights does not
# secretly lower the threshold.
WEIGHT_SCALE = 1.6

# Defaults, matching the prototype the benchmark numbers were measured with.
THRESHOLD = 4.0            # how far from normal counts as alarming
CONSECUTIVE = 3            # ...and for how many windows in a row
MIN_BASELINE_WINDOWS = 8   # too little history to judge a device at all
ISO_TREES = 50
ISO_WEIGHT = 1.5           # how loudly the second opinion is allowed to speak


@dataclass
class Detection:
    """What the detector concluded about one run."""

    scores: dict = field(default_factory=dict)         # dev -> {window: score}
    onsets: dict = field(default_factory=dict)         # dev -> seconds
    onset_windows: dict = field(default_factory=dict)  # dev -> window number
    skipped: list = field(default_factory=list)        # devices with too little history
    threshold: float = THRESHOLD
    consecutive: int = CONSECUTIVE
    window_seconds: int = windows.WINDOW_SECONDS

    def peak_score(self, device: str) -> float:
        """The loudest this device ever got. Used by the anomaly baseline."""
        per_window = self.scores.get(device)
        return max(per_window.values()) if per_window else 0.0

    def devices_by_onset(self) -> list:
        """Everything that went abnormal, earliest first."""
        return sorted(self.onsets, key=lambda d: self.onsets[d])

    def __repr__(self) -> str:
        return "Detection(%d devices scored, %d with an onset)" % (
            len(self.scores), len(self.onsets)
        )


def robust_scores(
    device_table: pd.DataFrame,
    baseline_windows: int,
    weighted: bool = True,
) -> np.ndarray:
    """
    Score every window for ONE device against its own baseline.

    device_table must be sorted by window and contain the seven feature
    columns. Returns one score per row, in the same order.
    """
    baseline = device_table[device_table["w"] < baseline_windows]
    columns = features.FEATURE_COLUMNS

    # What this device usually does.
    middle = baseline[columns].median()

    # How much it usually varies, measured robustly.
    spread = (baseline[columns] - middle).abs().median() * 1.4826

    # A feature that never varied at all in the baseline has spread 0, which
    # would divide by zero and make every later value infinitely surprising.
    # Fall back to the ordinary standard deviation, and failing that to 1.
    spread = (
        spread.replace(0, np.nan)
        .fillna(baseline[columns].std().replace(0, 1))
        .clip(lower=1e-6)
    )

    # How many "robust standard deviations" from usual, per feature.
    distance = (device_table[columns] - middle).abs() / spread

    if weighted:
        # Weight by how diagnostic each feature is, then take the loudest
        # single feature. Taking the max rather than the sum matters: one
        # unmistakable sign should be enough, and should not be diluted by
        # six features behaving perfectly normally.
        score = (distance * pd.Series(DIAG)).max(axis=1).values / WEIGHT_SCALE
    else:
        score = distance.max(axis=1).values

    # The second opinion: learn the shape of normal across all seven features
    # at once, and see which windows fall outside it.
    try:
        forest = IsolationForest(n_estimators=ISO_TREES, random_state=0)
        forest.fit(baseline[columns])
        outlier = -forest.score_samples(device_table[columns])
        # Put it on the same footing as the z-score by expressing it relative
        # to how it behaved during the baseline.
        n = len(baseline)
        outlier = (outlier - outlier[:n].mean()) / (outlier[:n].std() + 1e-9)
        score = np.maximum(score, outlier * ISO_WEIGHT)
    except Exception:
        # If the forest cannot be fitted (too few or degenerate baseline rows)
        # we simply keep the z-score. Losing the second opinion is survivable;
        # crashing the whole run is not.
        pass

    return score


def find_onset(
    window_numbers: np.ndarray,
    scores: np.ndarray,
    baseline_windows: int,
    threshold: float = THRESHOLD,
    consecutive: int = CONSECUTIVE,
    window_seconds: int = windows.WINDOW_SECONDS,
):
    """
    The first window that crosses the threshold and STAYS crossed.

    Returns (seconds, window_number), or (None, None) if it never does.

    Two rules are enforced here:
      * the run of crossings must start after the baseline - the baseline is
        by definition the period we are calling normal, so an "onset" inside
        it is a contradiction; and
      * it must last `consecutive` windows, so one noisy minute is not enough.

    A note on what "in a row" means. The run is counted over consecutive ROWS,
    and a device with no traffic at all in some minute has no row for it. So
    for a device that goes quiet mid-attack, "three in a row" means its next
    three ACTIVE windows. This matches the prototype the benchmark numbers
    were measured with, and in practice the two readings almost never differ
    (see tests/test_detect.py, which measures how often).
    """
    for i in range(len(scores) - consecutive + 1):
        if window_numbers[i] < baseline_windows:
            continue
        if all(scores[i + j] > threshold for j in range(consecutive)):
            w = int(window_numbers[i])
            return windows.window_start(w, window_seconds), w
    return None, None


def detect(
    feature_table: pd.DataFrame,
    baseline_windows: int,
    weighted: bool = True,
    threshold: float = THRESHOLD,
    consecutive: int = CONSECUTIVE,
    window_seconds: int = windows.WINDOW_SECONDS,
    min_baseline_windows: int = MIN_BASELINE_WINDOWS,
) -> Detection:
    """
    Score every device against its own baseline and find when each went bad.

    weighted=True is the V5 detector (features weighted by DIAG).
    weighted=False is the plain version, kept so evaluate.py can show what the
    weighting is worth rather than merely asserting it.
    """
    result = Detection(
        threshold=threshold, consecutive=consecutive, window_seconds=window_seconds
    )

    for device, group in feature_table.groupby("dev"):
        group = group.sort_values("w")
        baseline = group[group["w"] < baseline_windows]

        if len(baseline) < min_baseline_windows:
            # We have not watched this device long enough to know what normal
            # is. Saying nothing is honest; guessing would not be.
            result.skipped.append(device)
            continue

        scores = robust_scores(group, baseline_windows, weighted=weighted)
        window_numbers = group["w"].values

        result.scores[device] = dict(
            zip(window_numbers.tolist(), scores.tolist())
        )

        seconds, window = find_onset(
            window_numbers, scores, baseline_windows,
            threshold=threshold, consecutive=consecutive,
            window_seconds=window_seconds,
        )
        if seconds is not None:
            result.onsets[device] = seconds
            result.onset_windows[device] = window

    return result


def detect_run(run: runs.Run, weighted: bool = True, **kwargs) -> Detection:
    """Convenience: features and detection in one call, for a loaded run."""
    table = features.features_for_run(run)
    return detect(
        table,
        baseline_windows=run.baseline_windows,
        weighted=weighted,
        window_seconds=run.window_seconds,
        **kwargs,
    )


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Find when each device stopped behaving normally."
    )
    parser.add_argument("run_id", help="e.g. run_000")
    parser.add_argument("--threshold", type=float, default=THRESHOLD)
    parser.add_argument("--consecutive", type=int, default=CONSECUTIVE)
    parser.add_argument("--plain", action="store_true",
                        help="turn OFF the DIAG feature weighting")
    args = parser.parse_args(argv)

    run = runs.load_run(args.run_id)
    result = detect_run(
        run, weighted=not args.plain,
        threshold=args.threshold, consecutive=args.consecutive,
    )

    print("\n  %s - %s scenario, %d devices, baseline = first %d windows"
          % (run.run_id, run.scenario, len(run.device_names), run.baseline_windows))
    print("  detector: %s, threshold %.1f, %d windows in a row"
          % ("plain" if args.plain else "DIAG-weighted",
             args.threshold, args.consecutive))

    print("\n  %-12s %14s %10s %12s" % ("device", "onset", "window", "peak score"))
    print("  " + "-" * 52)

    ordered = result.devices_by_onset() + [
        d for d in sorted(result.scores) if d not in result.onsets
    ]
    for device in ordered:
        if device in result.onsets:
            seconds = result.onsets[device]
            clock = "%02d:%02d:00" % (int(seconds) // 3600, (int(seconds) % 3600) // 60)
            print("  %-12s %14s %10d %12.1f"
                  % (device, clock, result.onset_windows[device],
                     result.peak_score(device)))
        else:
            print("  %-12s %14s %10s %12.1f"
                  % (device, "-", "-", result.peak_score(device)))

    if result.skipped:
        print("\n  not enough baseline history to judge: %s" % ", ".join(result.skipped))
    print("\n  %d of %d devices flagged\n" % (len(result.onsets), len(run.device_names)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
