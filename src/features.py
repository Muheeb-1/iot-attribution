"""
FEATURES - turning raw connections into a small number of meaningful numbers.

WHAT THIS FILE DOES
-------------------
The traffic file is a list of tens of thousands of individual connections.
Nothing can reason about that directly. So we chop the capture into 60-second
windows and, for every device in every window, write down seven numbers that
between them describe "what this device was doing during that minute".

    one device, one minute  ->  seven numbers

Those seven numbers are the only thing the detector in step 4 ever sees. If a
sign of compromise is not visible in them, the rest of the pipeline cannot
find it - so the choice of which seven is the most consequential decision in
this file.

THE SEVEN, AND WHY EACH ONE IS THERE
------------------------------------
  bytes_out   how much it SENT. Data theft looks like this. On its own it is
              a poor witness, because innocent backups look identical.
  bytes_in    how much it RECEIVED. A device being fed a payload looks like
              this.
  n_conn      how many connections it made. A scan is many tiny connections.
  n_dst       how many DIFFERENT places it talked to. A device that normally
              talks to one server and suddenly talks to nine has changed
              behaviour even if the byte count barely moved.
  n_new_ext   how many of those places are OUTSIDE the lab and were never
              contacted during the quiet baseline period. This is the closest
              thing to a smoking gun: a compromised device phones somewhere
              new, and that somewhere is not one of our own machines.
  n_peer      how many connections went to OTHER LAB DEVICES. Attackers spread
              sideways; a thermostat has no business connecting to a laptop.
              This is the feature that makes lateral movement visible.
  iat_reg     how REGULAR the gaps between connections were. Humans and normal
              software are bursty and irregular. Automated malware beacons on
              a timer, so it is unnaturally regular. Higher = more machine-like.

TWO DEFINITIONS WORTH DEFENDING
-------------------------------
1. "Never seen before" means "not seen during the baseline period", not "not
   seen in any earlier window". Using the baseline as the reference point is
   the honest version: the baseline is the stretch we are entitled to call
   normal. If we instead compared each window to everything before it, then
   once an attacker contacted an address a second time it would stop counting
   as new, and a steady beacon would quietly fade from view.

2. "Outside the lab" is decided from the ASSET INVENTORY (the meta file), not
   from the answer sheet. Knowing which machines you own is something every
   real security team already has written down. Knowing which address belongs
   to the attacker is not, and this file never learns it.

A NOTE ON MISSING WINDOWS
-------------------------
If a device made no connections at all during a window, that window simply
does not appear in the table. It is not filled in with zeros. That matches
the prototype exactly, and it is also the safer choice: a row of zeros is
indistinguishable from "genuinely silent" and would drag every device's idea
of normal downwards.
"""

from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd

from src import runs, windows
from src.capture import BROADCAST_NAME

# STEP 18, CHANGE C2 - timing regularity is measured on the device's own
# conversations only, not on what it sends to "broadcast".
#
# Why: iat_reg asks "does this device tick like a timer?". laptop-i3 runs a
# connect/disconnect loop to the broker every ~2 s, which is perfectly regular.
# In minutes where it ALSO sent some broadcast or multicast chatter (Windows
# name lookups, DHCP, SSDP), those extra connections land at random moments
# between the ticks and the minute reads as irregular (iat_reg ~2-5). In
# minutes with no such chatter, the same loop reads as a metronome (iat_reg
# ~19). So the laptop's normal behaviour flip-flopped between two values for a
# reason that had nothing to do with an attack, and three "regular" minutes in a
# row were enough to flag it (rehearsal_01). Leaving broadcast connections out
# of THIS ONE measurement makes the laptop read ~19 every minute.
#
# Only iat_reg changes. The other six numbers still count broadcast traffic -
# leaving it out of all of them was tried on 11 Nov and the boards then had too
# little baseline traffic to be judged at all (docs/LIVE_PLAN.md section 7).
#
# A switch, default ON; set False (or evaluate.py --rules old) for the old rule.
# Simulated runs contain no "broadcast" destination, so they are unaffected.
IAT_IGNORES_BROADCAST = True

# The seven numbers, in a fixed order. Everything downstream refers to this
# list rather than writing the names out again, so they can never drift apart.
FEATURE_COLUMNS = [
    "bytes_out",
    "bytes_in",
    "n_conn",
    "n_dst",
    "n_new_ext",
    "n_peer",
    "iat_reg",
]

# Plain-English labels, for the dashboard and the incident brief.
FEATURE_LABELS = {
    "bytes_out": "bytes sent",
    "bytes_in": "bytes received",
    "n_conn": "connections made",
    "n_dst": "distinct destinations",
    "n_new_ext": "new outside addresses",
    "n_peer": "connections to lab devices",
    "iat_reg": "timing regularity",
}


def build_features(
    connections: pd.DataFrame,
    device_names,
    baseline_seconds: float,
    window_seconds: int = windows.WINDOW_SECONDS,
    ignore_broadcast: bool | None = None,
) -> pd.DataFrame:
    """
    Summarise traffic into one row per device per window.

    connections     the traffic table: t, src, dst, bytes_out, bytes_in, ...
    device_names    the lab's own devices, from the asset inventory
    baseline_seconds how long the quiet "this is normal" period lasts
    window_seconds  width of a window (default 60)
    ignore_broadcast leave "broadcast" connections out of iat_reg (Step 18,
                    C2); None means "whatever IAT_IGNORES_BROADCAST says now"

    Returns a table with columns: dev, w, then the seven feature columns.
    Only devices in device_names get rows - traffic from the broker or any
    other infrastructure is ignored, because we are not trying to attribute
    the attack to a message queue.
    """
    if ignore_broadcast is None:
        ignore_broadcast = IAT_IGNORES_BROADCAST
    device_names = list(device_names)
    lab = set(device_names)

    df = connections.copy()

    # The ONE place a timestamp becomes a window number, via the shared helper.
    df["w"] = windows.window_of(df["t"], window_seconds)

    baseline_windows = windows.baseline_window_count(baseline_seconds, window_seconds)

    # What each device talked to during the quiet period. This is the
    # reference for "new". Computed once, from the baseline only.
    seen_in_baseline = {
        dev: set(df.loc[(df["src"] == dev) & (df["w"] < baseline_windows), "dst"].unique())
        for dev in device_names
    }

    rows = []
    for (dev, w), group in df.groupby(["src", "w"], sort=True):
        if dev not in lab:
            continue  # not one of our devices - not a suspect

        destinations = set(group["dst"].unique())

        # How regular were the gaps between this device's connections?
        # cv is the "coefficient of variation": the spread of the gaps divided
        # by their average. Perfectly even ticking gives cv = 0. Bursty human
        # activity gives cv well above 1. We invert it so that HIGHER means
        # MORE regular, and add 0.05 so a perfectly regular device scores a
        # large finite number instead of dividing by zero.
        #
        # With the Step 18 switch ON the gaps are measured only between the
        # device's own conversations, leaving out what it sent to "broadcast"
        # (see IAT_IGNORES_BROADCAST for why).
        timed = group
        if ignore_broadcast:
            timed = group[group["dst"] != BROADCAST_NAME]
        times = np.sort(timed["t"].values)
        gaps = np.diff(times)
        if len(gaps) > 3 and gaps.mean() > 0:
            cv = gaps.std() / gaps.mean()
        else:
            cv = 1.0  # too few connections to judge - assume unremarkable

        # New AND outside the lab. Both halves matter: talking to a lab device
        # for the first time is suspicious in a different way (that is n_peer),
        # and an outside address we already used in the baseline is routine.
        new_external = {
            d for d in destinations - seen_in_baseline[dev] if d not in lab
        }

        rows.append({
            "dev": dev,
            "w": int(w),
            "bytes_out": group["bytes_out"].sum(),
            "bytes_in": group["bytes_in"].sum(),
            "n_conn": len(group),
            "n_dst": len(destinations),
            "n_new_ext": len(new_external),
            # Note: connections, not distinct devices. Ten connections to one
            # laptop is a transfer; one connection each to ten devices is a
            # scan. Both are worth seeing, and the count catches both.
            "n_peer": int(group["dst"].isin(lab).sum()),
            "iat_reg": 1.0 / (cv + 0.05),
        })

    if not rows:
        return pd.DataFrame(columns=["dev", "w"] + FEATURE_COLUMNS)

    return pd.DataFrame(rows)


def features_for_run(run: runs.Run) -> pd.DataFrame:
    """Convenience wrapper: summarise a run loaded by src/runs.py."""
    return build_features(
        run.connections,
        run.device_names,
        baseline_seconds=run.baseline_seconds,
        window_seconds=run.window_seconds,
    )


def split_baseline(table: pd.DataFrame, baseline_windows: int):
    """
    Cut the feature table into (baseline, everything after).

    The test is  w < baseline_windows.  Because windows are half-open, the
    window numbered baseline_windows begins exactly at the end of the baseline
    period, so it correctly falls on the "after" side. No off-by-one.
    """
    return (
        table[table["w"] < baseline_windows].copy(),
        table[table["w"] >= baseline_windows].copy(),
    )


# --------------------------------------------------------------------------
# Command line - look at the numbers for one device
# --------------------------------------------------------------------------

def _print_table(title: str, table: pd.DataFrame, window_seconds: int, limit: int) -> None:
    print("\n  %s" % title)
    print("  " + "-" * 104)
    print("  %6s %10s %12s %12s %8s %7s %9s %7s %9s"
          % ("window", "clock", "bytes_out", "bytes_in", "n_conn",
             "n_dst", "n_new_ext", "n_peer", "iat_reg"))
    shown = table.head(limit)
    for _, r in shown.iterrows():
        seconds = windows.window_start(int(r["w"]), window_seconds)
        clock = "%02d:%02d:00" % (int(seconds) // 3600, (int(seconds) % 3600) // 60)
        print("  %6d %10s %12d %12d %8d %7d %9d %7d %9.2f"
              % (r["w"], clock, r["bytes_out"], r["bytes_in"], r["n_conn"],
                 r["n_dst"], r["n_new_ext"], r["n_peer"], r["iat_reg"]))
    if len(table) > limit:
        print("  ... and %d more windows" % (len(table) - limit))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Show the per-window feature table for one device."
    )
    parser.add_argument("run_id", help="e.g. run_000")
    parser.add_argument("--device", required=True, help="which device to show")
    parser.add_argument("--rows", type=int, default=8, help="how many windows to print")
    parser.add_argument("--after", type=float, default=None,
                        help="only show windows at or after this many seconds")
    args = parser.parse_args(argv)

    run = runs.load_run(args.run_id)
    if args.device not in run.device_names:
        parser.error("%r is not a device in %s. Devices: %s"
                     % (args.device, run.run_id, ", ".join(run.device_names)))

    table = features_for_run(run)
    mine = table[table["dev"] == args.device].sort_values("w")
    baseline, later = split_baseline(mine, run.baseline_windows)

    print("\n  %s - device %s (%s scenario, baseline = first %d windows)"
          % (run.run_id, args.device, run.scenario, run.baseline_windows))

    if args.after is None:
        _print_table("BASELINE (normal behaviour)", baseline, run.window_seconds, args.rows)
        _print_table("AFTER THE BASELINE", later, run.window_seconds, args.rows)
    else:
        cutoff = windows.window_of(args.after, run.window_seconds)
        _print_table("FROM WINDOW %d ONWARDS" % cutoff,
                     mine[mine["w"] >= cutoff], run.window_seconds, args.rows)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
