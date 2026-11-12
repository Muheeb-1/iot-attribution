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
from src.capture import BROADCAST_NAME

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

# STEP 18, CHANGE C3 - a minute in which a device (re)joined the network is not
# "normal" for it.
#
# What happened in rehearsal_01: 11 minutes into the baseline esp32-02 dropped
# off the Wi-Fi and came back (ARP retries, a DHCP broadcast at +695 s, a new
# MQTT session). That one baseline minute had 6 connections instead of the
# usual 2-3, which widened the board's idea of how much it normally varies -
# and the attack minutes (3 connections, one of them to port 4444) then scored
# only 2.4 against a line of 4.0. The attack was missed because one odd minute
# was allowed to define normal.
#
# The rule: a baseline minute in which a device sent a DHCP broadcast (to
# "broadcast", destination port 67 - the "I need an address" message every
# device sends when it joins or rejoins the network) is left out of THAT
# device's baseline. The minute is still scored and drawn; it just does not
# teach the detector what normal is. Nothing else is left out, and the
# baseline that remains must still hold MIN_BASELINE_WINDOWS minutes, or the
# device is skipped as before. DHCP RENEWALS go straight to the router, not
# to broadcast, so a device that merely renews its lease is not affected.
#
# A switch, default ON; set False (or evaluate.py --rules old) for the old rule.
# Simulated runs contain no "broadcast" destination, so they are unaffected.
SKIP_REJOIN_MINUTES = True
DHCP_SERVER_PORT = 67


@dataclass
class Detection:
    """What the detector concluded about one run."""

    scores: dict = field(default_factory=dict)         # dev -> {window: score}
    onsets: dict = field(default_factory=dict)         # dev -> seconds
    onset_windows: dict = field(default_factory=dict)  # dev -> window number
    skipped: list = field(default_factory=list)        # devices with too little history
    # dev -> {window: seconds of its first DHCP broadcast in that window}:
    # the baseline minutes left out of that device's normal (Step 18, C3).
    rejoins: dict = field(default_factory=dict)
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


def rejoin_minutes(
    connections: pd.DataFrame,
    device_names,
    baseline_windows: int,
    window_seconds: int = windows.WINDOW_SECONDS,
) -> dict:
    """
    The baseline minutes in which each device (re)joined the network.

    Returns dev -> {window: seconds}, where seconds is the time of the device's
    first DHCP broadcast (dst "broadcast", dport 67) in that window. Only
    baseline windows are listed and only devices in device_names. A device
    that never sent one is absent. Read from the flow table - the same one
    features.py reads - so it needs no extra input and works the same on a
    saved run, a live session and a simulated run (which has none).
    """
    needed = {"t", "src", "dst", "dport"}
    if connections is None or len(connections) == 0 or not needed <= set(connections.columns):
        return {}
    lab = set(device_names)
    asks = connections[
        (connections["dst"] == BROADCAST_NAME)
        & (connections["dport"] == DHCP_SERVER_PORT)
        & (connections["src"].isin(lab))
    ]
    if asks.empty:
        return {}
    asks = asks.assign(w=windows.window_of(asks["t"], window_seconds))
    asks = asks[asks["w"] < baseline_windows]
    out: dict = {}
    for (dev, w), group in asks.groupby(["src", "w"], sort=True):
        out.setdefault(dev, {})[int(w)] = float(group["t"].min())
    return out


def rejoins_for_run(run: runs.Run, enabled: bool | None = None) -> dict:
    """
    rejoin_minutes for a loaded run, if the Step 18 switch is ON (read at call
    time, so evaluate.py can score the old rule by turning it off); {} if OFF.
    """
    if enabled is None:
        enabled = SKIP_REJOIN_MINUTES
    if not enabled:
        return {}
    return rejoin_minutes(run.connections, run.device_names, run.baseline_windows,
                          run.window_seconds)


def robust_scores(
    device_table: pd.DataFrame,
    baseline_windows: int,
    weighted: bool = True,
    left_out=(),
) -> np.ndarray:
    """
    Score every window for ONE device against its own baseline.

    device_table must be sorted by window and contain the seven feature
    columns. Returns one score per row, in the same order. left_out lists
    baseline windows that must not count as normal (Step 18, C3): they are
    still scored, but are not used to learn the median, the spread or the
    forest.
    """
    in_baseline = (device_table["w"] < baseline_windows).values
    if len(left_out):
        in_baseline = in_baseline & ~device_table["w"].isin(list(left_out)).values
    baseline = device_table[in_baseline]
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
        # to how it behaved during the baseline. (The baseline rows are picked
        # by the same mask as above; with nothing left out they are simply the
        # first rows of the sorted table, exactly as before Step 18.)
        learned = outlier[in_baseline]
        outlier = (outlier - learned.mean()) / (learned.std() + 1e-9)
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
    rejoins: dict | None = None,
) -> Detection:
    """
    Score every device against its own baseline and find when each went bad.

    weighted=True is the V5 detector (features weighted by DIAG).
    weighted=False is the plain version, kept so evaluate.py can show what the
    weighting is worth rather than merely asserting it.

    rejoins (from rejoin_minutes) names, per device, the baseline minutes to
    leave out of its normal. None or {} leaves nothing out - the old rule.
    detect_run fills it in from the run when SKIP_REJOIN_MINUTES is ON.
    """
    rejoins = {dev: dict(ws) for dev, ws in (rejoins or {}).items()}
    result = Detection(
        threshold=threshold, consecutive=consecutive, window_seconds=window_seconds,
        rejoins=rejoins,
    )

    for device, group in feature_table.groupby("dev"):
        group = group.sort_values("w")
        left_out = sorted(rejoins.get(device, {}))
        baseline = group[(group["w"] < baseline_windows) & ~group["w"].isin(left_out)]

        if len(baseline) < min_baseline_windows:
            # We have not watched this device long enough to know what normal
            # is. Saying nothing is honest; guessing would not be. (Minutes
            # left out because the device was rejoining do not count.)
            result.skipped.append(device)
            continue

        scores = robust_scores(group, baseline_windows, weighted=weighted,
                               left_out=left_out)
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
    """
    Convenience: features and detection in one call, for a loaded run. The
    rejoin minutes are worked out from the run's own traffic when the Step 18
    switch is ON (pass rejoins=... to override).
    """
    table = features.features_for_run(run)
    if "rejoins" not in kwargs:
        kwargs["rejoins"] = rejoins_for_run(run)
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
