"""
EVALUATION - marking our own homework, honestly.

THIS IS THE ONLY FILE IN src/ ALLOWED TO READ THE ANSWERS.

Everything else in the pipeline works blind: it sees traffic and an asset
inventory, and never learns which device actually started the attack. This
file opens groundtruth/run_NNN.json, compares what the pipeline said against
what really happened, and produces the table the whole project is judged on.
That separation is enforced by tests/test_no_groundtruth_leak.py, which fails
the build if any other file in src/ so much as mentions the folder.

WHAT IT MEASURES
----------------
  top-1        how often the true origin is ranked FIRST. The headline.
  top-3        how often it is in the top three. This matters because the
               method hands a human a shortlist when it is unsure, and a
               shortlist containing the answer is still useful.
  mean rank    where the true origin lands on average. A method that is
               wrong but close is better than one that is wrong and wild.
  abstention   how often the method refuses to name one device. Not a
               failure - a method that knows when to stay quiet is worth
               more than one that always guesses.

WHAT IT COMPARES AGAINST
------------------------
Four standard approaches, which are what a reasonable person would try first:

  B1 total bytes        blame whoever sent the most data
  B2 anomaly score      blame whoever looked strangest
  B3 connection count   blame whoever made the most connections
  B4 earliest onset     blame whoever went abnormal first

These are not strawmen. B4 in particular is the sensible answer, and it is
the one most people reach for. Beating it is the point of the project.

A NOTE ON HOW THE BASELINES ARE FED
-----------------------------------
In the prototype the four baselines are computed from the PLAIN detector
while V5 uses the DIAG-weighted one. That is what produced the published
numbers, so it is reproduced exactly here.

But it invites a fair objection: are the baselines being handicapped by a
worse detector? So this file also runs them a second time on the weighted
detector and reports both. If the baselines improved a lot under the better
detector, our advantage would be partly an artefact of the comparison rather
than of the method, and we would want to know that before a viva does.

RANKING CONVENTION
------------------
A device that never appears in a ranking - because the detector never flagged
it - is recorded as rank 99. Those runs still count against top-1 and top-3
(we got it wrong), but they are excluded from the mean rank, because averaging
in a placeholder number would be meaningless. The count of such runs is
reported separately as "origin never flagged", since it is a detector failure
rather than an attribution failure and the fix would be in a different file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from src import attribute, capture, detect, features, runs

ROOT = Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------
# The Step 18 rules, scored both ways
# --------------------------------------------------------------------------
# Step 18 added three measured changes, each behind its own module switch, and
# Step 18b narrowed the third:
#   C1  capture.MULTICAST_AS_BROADCAST  multicast / 255.255.255.255 -> "broadcast"
#   C2  features.IAT_IGNORES_BROADCAST  iat_reg ignores "broadcast" connections
#   C3  detect.SKIP_REJOIN_MINUTES      a baseline minute with a DHCP broadcast
#                                       from a device is not normal for it
#   C3b detect.REJOIN_NEEDS_UNASSIGNED  ...only if it was sent from 0.0.0.0, i.e.
#                                       a real (re)join, not a Windows INFORM
# "new" is all four ON (the default everywhere); "step18" is C1-C3 ON and C3b
# OFF, the rule Step 18 was measured with; "old" is all OFF, exactly the
# pipeline the published tables up to Step 17 were made with. C1 acts when
# packets are turned into flows, and C3b needs the src_unassigned column that
# only a fresh conversion has, so both only show with --pcap-dir.
RULE_SWITCHES = [
    (capture, "MULTICAST_AS_BROADCAST"),
    (features, "IAT_IGNORES_BROADCAST"),
    (detect, "SKIP_REJOIN_MINUTES"),
    (detect, "REJOIN_NEEDS_UNASSIGNED"),
]
RULES = {
    "new": (True, True, True, True),
    "step18": (True, True, True, False),
    "old": (False, False, False, False),
}


def set_rules(rules: str) -> None:
    """Set the switches to one of RULES: "new", "step18" or "old"."""
    if rules not in RULES:
        raise ValueError("rules must be one of %s, not %r" % (", ".join(RULES), rules))
    for (module, name), value in zip(RULE_SWITCHES, RULES[rules]):
        setattr(module, name, value)


def current_rules() -> str:
    """'new', 'step18', 'old', or 'mixed' if someone has set the switches by hand."""
    values = tuple(bool(getattr(module, name)) for module, name in RULE_SWITCHES)
    for name, wanted in RULES.items():
        if values == wanted:
            return name
    return "mixed"


def load_for_scoring(run_id: str, data_dir=None, pcap_dir=None, tshark=None) -> runs.Run:
    """
    The run to score. Normally data/<run_id>.parquet as saved. With pcap_dir,
    the traffic is instead re-converted from <pcap_dir>/<run_id>.pcapng under
    the naming rule in force now (C1), and only the inventory and timings are
    taken from the saved meta file - so both rules can be scored from the raw
    captures, and the saved runs are never overwritten.
    """
    run = runs.load_run(run_id) if data_dir is None else runs.load_run(run_id, data_dir)
    if pcap_dir is None:
        return run
    pcap = Path(pcap_dir) / ("%s.pcapng" % run_id)
    if not pcap.exists():
        raise FileNotFoundError("no capture file for %s at %s" % (run_id, pcap))
    binary = capture.find_tshark(tshark)
    run.connections = capture.build_flows(capture.read_packets(pcap, binary))
    return run
GROUNDTRUTH_DIR = ROOT / "groundtruth"
RESULTS_DIR = ROOT / "results"

NOT_RANKED = 99

BASELINE_NAMES = [
    "B1 total bytes",
    "B2 anomaly score",
    "B3 connection count",
    "B4 earliest onset",
]

# The two indicator-ordering rules, scored side by side so the effect of the
# fix is measured rather than asserted. See attribute.REQUIRE_ONSET_ORDER.
V5_FIXED = "V5 attribution"
V5_PROTOTYPE = "V5 (prototype indicator rule)"
V5_METHODS = [V5_PROTOTYPE, V5_FIXED]

# Which per-run field records the abstention for each method.
ABSTAIN_FIELD = {V5_FIXED: "abstained", V5_PROTOTYPE: "abstained_prototype"}

# What the prototype measured, for comparison. If we land far from these,
# one of the two is broken and we need to know which.
EXPECTED_HARD_TOP1 = {
    "B1 total bytes": 0,
    "B2 anomaly score": 10,
    "B3 connection count": 3,
    "B4 earliest onset": 17,
    V5_PROTOTYPE: 53,
}
EXPECTED_HARD_TOP3 = {V5_PROTOTYPE: 90}


def load_answer(run_id: str, groundtruth_dir: Path = GROUNDTRUTH_DIR) -> dict:
    """
    Open the answer sheet for one run.

    This is the one function in the whole of src/ that does this, and it is
    called only from the scoring code below - never from anything that makes
    a decision about the traffic.
    """
    path = Path(groundtruth_dir) / ("%s.json" % run_id)
    if not path.exists():
        raise FileNotFoundError(
            "no answer file for run %r at %s - regenerate with:\n"
            "    python -m src.generate --runs 30" % (run_id, path)
        )
    return json.loads(path.read_text(encoding="utf-8"))


def load_answer_for_run(run: runs.Run, groundtruth_dir: Path = GROUNDTRUTH_DIR) -> dict:
    """
    The answer for a loaded run. A run re-converted by src/reconvert.py
    (lab_batch_05, say) is the same capture as the run it replaces
    (live_batch_05), so it has the same answer: its own file is used if one
    exists, otherwise the replaced run's. One answer file per attack, never a
    copy that could drift out of step with it.
    """
    own = Path(groundtruth_dir) / ("%s.json" % run.run_id)
    if own.exists() or not run.replaces:
        return load_answer(run.run_id, groundtruth_dir)
    return load_answer(run.replaces, groundtruth_dir)


# --------------------------------------------------------------------------
# Live sessions: how fast, and was it contained (Step 20)
# --------------------------------------------------------------------------
# The live engine writes what it did into the run's meta file at STOP
# ("live": first_alert, containment). It cannot know when the attack really
# started - that is in the answer file - so "time to detect" is worked out
# here, the one place allowed to read both.

# What went differently in a session, written down by the operator - shown
# beside the session in every scored table, so a result is never quoted
# without its conditions. A note never removes a session: it is scored like
# any other, and `--exclude` gives the "without it" figures side by side.
# Add a line here for any session that did not run as planned.
SESSION_NOTES = {
    # 13 Nov: the operator's Enter key did not register, so laptop-i3's
    # 2-second connect/disconnect loop never started - 22 laptop flows in the
    # session against 614 in live_session_01. The attack and the containment
    # ran as planned; only the noisy innocent device was missing.
    "live_session_02": "laptop loop off",
}


def session_note(run_id: str) -> str:
    """The operator's note for a session ("" if it ran as planned)."""
    return SESSION_NOTES.get(run_id, "")


def _clock(epoch) -> str:
    """Wall-clock time on this machine (the lab laptop runs on IST)."""
    from datetime import datetime
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S") if epoch else ""


def live_timing(run_id: str, data_dir=None, groundtruth_dir=GROUNDTRUTH_DIR):
    """
    One row of timings for a session recorded by the live engine, or None
    for a run that was not (no "live" block in its meta file).

    detect_seconds        trigger sent -> alert raised (the operator's view)
    window_closed_seconds trigger sent -> the third abnormal minute closed
                          (what the detector could do with zero file delay)
    acted_within_seconds  alert raised -> the attacker's last connection: how
                          long the operator took to contain, at most
    contained_seconds     alert raised -> CONTAINED shown (that, plus the 90 s
                          of silence the check waits for)
    """
    meta_file = runs.meta_path(run_id) if data_dir is None else runs.meta_path(run_id, data_dir)
    meta = json.loads(Path(meta_file).read_text(encoding="utf-8"))
    live = meta.get("live")
    if not live:
        return None
    answer_id = run_id
    if not (Path(groundtruth_dir) / ("%s.json" % run_id)).exists() and meta.get("replaces"):
        answer_id = meta["replaces"]
    answer = load_answer(answer_id, groundtruth_dir)
    origin = answer["origin"]
    trigger = answer.get("start_epoch") or answer.get("true_onset_epoch", {}).get(origin)

    alert = live.get("first_alert") or {}
    contain = live.get("containment") or {}
    raised = alert.get("raised_epoch")
    contained_at = contain.get("contained_epoch") if contain.get("contained") else None
    last_seen = contain.get("last_seen_epoch")

    def gap(later, earlier):
        return round(later - earlier, 1) if later and earlier else None

    return {
        "run_id": run_id,
        "origin": origin,
        "trigger_clock": _clock(trigger),
        "alert_device": alert.get("device", ""),
        "alert_right": bool(alert) and alert.get("device") == origin,
        "alert_clock": _clock(raised),
        "detect_seconds": gap(raised, trigger),
        "window_closed_seconds": gap(alert.get("closed_epoch"), trigger),
        "alert_found_at_stop": bool(alert.get("found_at_stop", False)),
        "last_attack_clock": _clock(last_seen),
        "acted_within_seconds": gap(last_seen, raised) if contained_at else None,
        "contained": bool(contained_at),
        "contained_clock": _clock(contained_at),
        "contained_seconds": gap(contained_at, raised),
        "contained_device": contain.get("device", "") if contained_at else "",
        "note": session_note(run_id),
    }


def print_timing(rows: list) -> None:
    def mmss(seconds):
        if seconds is None:
            return "-"
        return "%d min %02d s" % divmod(int(round(seconds)), 60)

    print("\n  LIVE SESSIONS - what the live engine did, timed against the trigger")
    print("  %-17s %-9s %-9s %-10s %-9s %13s %10s %13s"
          % ("session", "origin", "trigger", "alert on", "at", "to detect",
             "contained", "after alert"))
    print("  " + "-" * 98)
    for r in rows:
        print("  %-17s %-9s %-9s %-10s %-9s %13s %10s %13s"
              % (r["run_id"], r["origin"], r["trigger_clock"],
                 (r["alert_device"] or "none") + ("" if r["alert_right"] else " (X)"),
                 r["alert_clock"] or "-", mmss(r["detect_seconds"]),
                 r["contained_clock"] or "no", mmss(r["contained_seconds"]))
              + ("   [%s]" % r["note"] if r.get("note") else ""))


def rank_of(ranking, device) -> int:
    """Where the device came in the ranking, or 99 if it is not in it at all."""
    return ranking.index(device) + 1 if device in ranking else NOT_RANKED


def evaluate_one(run_id: str, data_dir=None, groundtruth_dir=GROUNDTRUTH_DIR,
                 pcap_dir=None) -> dict:
    """
    Run the whole pipeline on one saved incident and score it.

    Returns a dictionary of ranks: one per baseline, one for V5, plus the
    supporting detail (confidence, whether it abstained, whether the detector
    ever flagged the true origin at all).
    """
    run = load_for_scoring(run_id, data_dir=data_dir, pcap_dir=pcap_dir)
    table = features.features_for_run(run)
    # Step 18, C3: empty when the switch is OFF, so the old rule is unchanged.
    rejoins = detect.rejoins_for_run(run)

    # The weighted detector - what V5 uses.
    weighted = detect.detect(
        table, baseline_windows=run.baseline_windows,
        weighted=True, window_seconds=run.window_seconds, rejoins=rejoins,
    )
    # The plain detector - what the prototype fed to the four baselines.
    plain = detect.detect(
        table, baseline_windows=run.baseline_windows,
        weighted=False, window_seconds=run.window_seconds, rejoins=rejoins,
    )

    # Both indicator-ordering rules, on identical detections, so any
    # difference between them is the rule and nothing else.
    fixed = attribute.attribute(
        run.connections, weighted.onsets, run.device_names,
        baseline_seconds=run.baseline_seconds, require_onset_order=False,
    )
    prototype = attribute.attribute(
        run.connections, weighted.onsets, run.device_names,
        baseline_seconds=run.baseline_seconds, require_onset_order=True,
    )

    # ---- the answer sheet is opened here, and nowhere else ----
    answer = load_answer_for_run(run, groundtruth_dir)
    origin = answer["origin"]

    plain_baselines = attribute.baseline_rankings(run.connections, plain, run.device_names)
    fair_baselines = attribute.baseline_rankings(run.connections, weighted, run.device_names)

    record = {
        "run_id": run_id,
        "scenario": run.scenario,
        "origin": origin,
        "via_broker": bool(answer.get("via_broker", False)),
        V5_FIXED: rank_of(fixed.ranking, origin),
        V5_PROTOTYPE: rank_of(prototype.ranking, origin),
        "confidence": fixed.confidence,
        "abstained": fixed.abstained,
        "abstained_prototype": prototype.abstained,
        "indicator_edges": sum(
            1 for _, _, d in fixed.graph.edges(data=True) if d.get("kind") == "indicator"
        ),
        "indicator_edges_prototype": sum(
            1 for _, _, d in prototype.graph.edges(data=True) if d.get("kind") == "indicator"
        ),
        "origin_flagged": origin in weighted.onsets,
        "origin_flagged_plain": origin in plain.onsets,
        "n_flagged": len(weighted.onsets),
        # Which devices were flagged, and which baseline minutes were left out
        # (Step 18) - so "laptop-i3 flagged in 0 of 12" is read off the file.
        "flagged": " ".join(sorted(weighted.onsets)),
        "rejoin_minutes": " ".join("%s@%d" % (dev, w) for dev in sorted(rejoins)
                                   for w in sorted(rejoins[dev])),
        "rules": current_rules(),
    }
    for name in BASELINE_NAMES:
        record[name] = rank_of(plain_baselines[name], origin)
        record["fair " + name] = rank_of(fair_baselines[name], origin)

    return record


def summarise(records: list, methods: list) -> pd.DataFrame:
    """Turn per-run ranks into the accuracy table."""
    rows = []
    n = len(records)
    for method in methods:
        ranks = np.array([r[method] for r in records])
        found = ranks[ranks < NOT_RANKED]
        field = ABSTAIN_FIELD.get(method)
        abstentions = sum(1 for r in records if r[field]) if field else None
        rows.append({
            "method": method,
            "runs": n,
            "top1_pct": round(float((ranks == 1).mean() * 100), 1),
            "top3_pct": round(float((ranks <= 3).mean() * 100), 1),
            "mean_rank": round(float(found.mean()), 2) if len(found) else float("nan"),
            "never_ranked": int((ranks == NOT_RANKED).sum()),
            "abstention_pct": (round(abstentions / n * 100, 1)
                               if abstentions is not None else ""),
        })
    return pd.DataFrame(rows)


def evaluate_scenario(prefix: str, limit: int | None = None,
                      groundtruth_dir=GROUNDTRUTH_DIR, verbose: bool = False,
                      pcap_dir=None, exclude=()) -> tuple:
    """
    Score every saved run with the given file prefix ('run' or 'easy').

    `exclude` leaves the named runs out AFTER the first `limit` are taken, so
    "--runs 2 --exclude live_session_02" is the same two sessions minus that
    one - the "without it" figure beside the full one, never a different set.
    """
    run_ids = runs.list_runs(prefix=prefix)
    if limit is not None:
        run_ids = run_ids[:limit]
    run_ids = [r for r in run_ids if r not in set(exclude)]
    if not run_ids:
        raise FileNotFoundError(
            "no %s_* runs found in data/. Generate them with:\n"
            "    python -m src.generate --runs 30%s"
            % (prefix, " --easy" if prefix == "easy" else "")
        )

    records = []
    for i, run_id in enumerate(run_ids, 1):
        record = evaluate_one(run_id, groundtruth_dir=groundtruth_dir, pcap_dir=pcap_dir)
        # The operator's note rides along only when the set has one, so the
        # per-run files of every earlier table are unchanged.
        if session_note(run_id):
            record["note"] = session_note(run_id)
        records.append(record)
        if verbose:
            print("    %-10s origin %-11s V5 rank %-3s conf %3.0f%%  %s"
                  % (run_id, record["origin"],
                     record["V5 attribution"] if record["V5 attribution"] < NOT_RANKED else "-",
                     record["confidence"] * 100,
                     "ABSTAIN" if record["abstained"] else ""))
        else:
            print("    scored %d/%d ..." % (i, len(run_ids)), end="\r", flush=True)
    if not verbose:
        print(" " * 40, end="\r")

    methods = BASELINE_NAMES + V5_METHODS
    summary = summarise(records, methods)
    fair = summarise(records, ["fair " + b for b in BASELINE_NAMES])
    return records, summary, fair


# --------------------------------------------------------------------------
# False alarms on attack-free captures
# --------------------------------------------------------------------------

def false_alarm_sessions(pcaps, session_seconds: int = 1500, baseline_seconds: int = 720,
                         tshark=None) -> list:
    """
    Cut attack-free captures into back-to-back sessions and count the alarms.

    Each capture is read once; its packets are cut into consecutive slices of
    session_seconds, measured from the capture's first packet (the same t = 0
    rule as build_flows). A slice shorter than a full session at the end is
    dropped. Each slice is then treated exactly like a live session: its own
    flows, its own first baseline_seconds as normal, the unchanged detector.
    Nothing was attacked in these recordings, so ANY device with an onset is a
    false alarm. No answer file is needed or read.
    """
    binary = capture.find_tshark(tshark)
    records = []
    for pcap in pcaps:
        pcap = Path(pcap)
        packets = capture.read_packets(pcap, binary)
        start, newest = None, None
        slices: dict = {}
        for packet in packets:
            try:
                when = float(packet["frame.time_epoch"])
            except (TypeError, ValueError):
                continue
            if start is None:
                start = when
            newest = when if newest is None else max(newest, when)
            slices.setdefault(int((when - start) // session_seconds), []).append(packet)
        # Only whole sessions: the capture must run to the end of the slice.
        whole = int((newest - start) // session_seconds) if start is not None else 0
        for k in range(whole):
            chunk = slices.get(k, [])
            if not chunk:
                continue
            flows = capture.build_flows(chunk)
            run = runs.Run(
                run_id="%s_%02d" % (pcap.stem, k), scenario="capture", connections=flows,
                device_names=list(capture.DEVICE_KINDS),
                devices=[{"name": n, "kind": t} for n, t in capture.DEVICE_KINDS.items()],
                window_seconds=60, capture_seconds=int(round(float(flows["t"].max()))),
                baseline_seconds=int(baseline_seconds),
                baseline_windows=int(baseline_seconds // 60),
            )
            detection = detect.detect_run(run)
            rejoins = detection.rejoins
            records.append({
                "pcap": pcap.name,
                "session": k,
                "start_seconds": k * session_seconds,
                "devices_seen": " ".join(sorted(set(flows["src"]) & set(run.device_names))),
                "false_alarm": bool(detection.onsets),
                "flagged": " ".join(sorted(detection.onsets)),
                # A device skipped for too little baseline was not judged at
                # all - "quiet" must not be read as "judged normal" for it.
                "skipped": " ".join(sorted(set(detection.skipped)
                                           & (set(flows["src"]) & set(run.device_names)))),
                "rejoin_minutes": " ".join("%s@%d" % (d, w) for d in sorted(rejoins)
                                           for w in sorted(rejoins[d])),
                "rules": current_rules(),
            })
    return records


# --------------------------------------------------------------------------
# Printing
# --------------------------------------------------------------------------

def print_table(title: str, summary: pd.DataFrame, expected_top1=None,
                expected_top3=None) -> None:
    print("\n  %s" % title)
    print("  %-22s %8s %8s %11s %10s %12s"
          % ("method", "top-1", "top-3", "mean rank", "unranked", "abstained"))
    print("  " + "-" * 78)
    for _, row in summary.iterrows():
        mean_rank = "%.2f" % row["mean_rank"] if row["mean_rank"] == row["mean_rank"] else "n/a"
        print("  %-22s %7.0f%% %7.0f%% %11s %10d %12s"
              % (row["method"], row["top1_pct"], row["top3_pct"], mean_rank,
                 row["never_ranked"],
                 "%s%%" % row["abstention_pct"] if row["abstention_pct"] != "" else "-"))

    if expected_top1:
        print("\n  against the prototype's published numbers:")
        print("  %-22s %10s %10s %10s" % ("method", "expected", "measured", "difference"))
        print("  " + "-" * 56)
        for _, row in summary.iterrows():
            method = row["method"]
            if method not in expected_top1:
                continue
            want = expected_top1[method]
            got = row["top1_pct"]
            flag = "  <-- CHECK" if abs(got - want) > 12 else ""
            print("  %-22s %9d%% %9.0f%% %+9.0f%s" % (method + " (top-1)", want, got, got - want, flag))
            if expected_top3 and method in expected_top3:
                want3 = expected_top3[method]
                got3 = row["top3_pct"]
                flag3 = "  <-- CHECK" if abs(got3 - want3) > 12 else ""
                print("  %-22s %9d%% %9.0f%% %+9.0f%s"
                      % (method + " (top-3)", want3, got3, got3 - want3, flag3))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Score the attribution pipeline against the answers."
    )
    parser.add_argument("--runs", type=int, default=30,
                        help="how many runs of each scenario to score")
    parser.add_argument("--hard-only", action="store_true")
    parser.add_argument("--easy-only", action="store_true")
    parser.add_argument("--prefix", default=None,
                        help="score runs with this file prefix instead of the "
                             "simulated hard/easy sets - e.g. --prefix live_batch "
                             "for captured runs")
    parser.add_argument("--label", default=None,
                        help="what to call that set in the scenario column "
                             "(defaults to --prefix)")
    parser.add_argument("--verbose", action="store_true", help="print a line for every run")
    parser.add_argument("--out", default=str(RESULTS_DIR / "table1.csv"))
    parser.add_argument("--rules", choices=list(RULES), default="new",
                        help="new = the Step 18 changes with the Step 18b rejoin rule "
                             "(default); step18 = as measured in Step 18 (any DHCP "
                             "broadcast is a rejoin); old = as up to Step 17")
    parser.add_argument("--pcap-dir", default=None,
                        help="re-convert each run from <dir>/<run_id>.pcapng under the chosen "
                             "rules instead of reading the saved data/<run_id>.parquet - "
                             "needed to score the multicast naming change (C1)")
    parser.add_argument("--false-alarms", nargs="+", default=None, metavar="PCAP",
                        help="instead of scoring attacks: cut these attack-free captures into "
                             "sessions and count the sessions in which anything was flagged")
    parser.add_argument("--session-minutes", type=int, default=25,
                        help="session length for --false-alarms (default 25)")
    parser.add_argument("--baseline", type=int, default=720,
                        help="baseline seconds for --false-alarms (default 720)")
    parser.add_argument("--exclude", nargs="+", default=(), metavar="RUN",
                        help="leave these runs out of the scored set (after --runs is "
                             "applied) - to report a set with and without a session that "
                             "ran differently, e.g. --exclude live_session_02")
    args = parser.parse_args(argv)

    set_rules(args.rules)
    print("\n  rules: %s%s" % (args.rules, {
        "new": " (Step 18 changes ON, Step 18b rejoin rule)",
        "step18": " (Step 18 changes ON, any DHCP broadcast is a rejoin)",
        "old": " (as up to Step 17)"}[args.rules]))

    if args.false_alarms:
        records = false_alarm_sessions(args.false_alarms,
                                       session_seconds=args.session_minutes * 60,
                                       baseline_seconds=args.baseline)
        alarms = [r for r in records if r["false_alarm"]]
        print("\n  FALSE ALARMS - %d attack-free sessions of %d minutes, %d-minute baseline"
              % (len(records), args.session_minutes, args.baseline // 60))
        for r in records:
            print("    %-18s session %2d  %-38s %s%s"
                  % (r["pcap"], r["session"], r["devices_seen"],
                     "FALSE ALARM: %s" % r["flagged"] if r["false_alarm"] else "quiet",
                     "  (left out: %s)" % r["rejoin_minutes"] if r["rejoin_minutes"] else ""))
        print("\n  %d false alarm(s) in %d sessions" % (len(alarms), len(records)))
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(records).to_csv(out_path, index=False)
        print("  saved: %s\n" % out_path)
        return 0

    all_rows = []
    all_records = []
    timing_rows = []

    scenarios = []
    if args.prefix:
        # An explicit prefix scores one arbitrary set - captured runs, say.
        # No expected numbers are passed: EXPECTED_HARD_* are the prototype's
        # figures for 30 SIMULATED hard runs, and holding a different set of
        # runs against them would print a "CHECK" flag that means nothing.
        scenarios.append((args.label or args.prefix, args.prefix, None, None))
    else:
        if not args.easy_only:
            scenarios.append(("hard", "run", EXPECTED_HARD_TOP1, EXPECTED_HARD_TOP3))
        if not args.hard_only:
            scenarios.append(("easy", "easy", None, None))

    for label, prefix, expected1, expected3 in scenarios:
        print("\n  scoring %s runs..." % label)
        records, summary, fair = evaluate_scenario(
            prefix, limit=args.runs, verbose=args.verbose, pcap_dir=args.pcap_dir,
            exclude=args.exclude,
        )
        if args.exclude:
            print("  left out: %s" % " ".join(args.exclude))
        noted = [r for r in records if r.get("note")]
        for r in noted:
            print("  note: %s - %s" % (r["run_id"], r["note"]))

        n = len(records)
        relayed = sum(1 for r in records if r["via_broker"])
        missed = sum(1 for r in records if not r["origin_flagged"])

        print_table(
            "%s BENCHMARK - %d runs, %d relayed through the broker"
            % (label.upper(), n, relayed),
            summary, expected1, expected3,
        )
        print("\n  detector never flagged the true origin: %d of %d runs" % (missed, n))

        before = next(r for _, r in summary.iterrows() if r["method"] == V5_PROTOTYPE)
        after = next(r for _, r in summary.iterrows() if r["method"] == V5_FIXED)
        moved = [r for r in records if r[V5_FIXED] != r[V5_PROTOTYPE]]
        better = [r for r in moved if r[V5_FIXED] < r[V5_PROTOTYPE]]
        worse = [r for r in moved if r[V5_FIXED] > r[V5_PROTOTYPE]]
        extra_edges = sum(r["indicator_edges"] - r["indicator_edges_prototype"]
                          for r in records)

        print("\n  EFFECT OF THE INDICATOR-ORDERING FIX")
        print("  %-12s %8s %8s %11s %12s"
              % ("rule", "top-1", "top-3", "mean rank", "abstained"))
        print("  " + "-" * 56)
        for rule, row in (("prototype", before), ("fixed", after)):
            print("  %-12s %7.0f%% %7.0f%% %11.2f %11s%%"
                  % (rule, row["top1_pct"], row["top3_pct"], row["mean_rank"],
                     row["abstention_pct"]))
        print("  %-12s %+7.0f  %+7.0f  %+11.2f"
              % ("difference", after["top1_pct"] - before["top1_pct"],
                 after["top3_pct"] - before["top3_pct"],
                 after["mean_rank"] - before["mean_rank"]))
        print("\n  indicator links recovered: %d across %d runs" % (extra_edges, n))
        print("  runs where the true origin moved: %d better, %d worse"
              % (len(better), len(worse)))
        for record in better[:6]:
            print("      %-10s rank %d -> %d"
                  % (record["run_id"], record[V5_PROTOTYPE], record[V5_FIXED]))
        for record in worse[:6]:
            print("      %-10s rank %d -> %d   WORSE"
                  % (record["run_id"], record[V5_PROTOTYPE], record[V5_FIXED]))

        print_table(
            "FAIRNESS CHECK - the same baselines given the better (weighted) detector",
            fair,
        )

        for _, row in summary.iterrows():
            all_rows.append({"scenario": label, "detector": "as prototype", **row.to_dict()})
        for _, row in fair.iterrows():
            all_rows.append({
                "scenario": label, "detector": "weighted (fairness check)",
                **{**row.to_dict(), "method": row["method"].replace("fair ", "")},
            })
        all_records.extend(records)

        # Only runs saved by the live engine have timings; for every other set
        # this is empty and no timing file is written, so no existing output
        # changes.
        timed = [t for t in (live_timing(r["run_id"]) for r in records) if t]
        if timed:
            print_timing(timed)
            timing_rows.extend(timed)

    table = pd.DataFrame(all_rows)[
        ["scenario", "detector", "method", "runs", "top1_pct", "top3_pct",
         "mean_rank", "never_ranked", "abstention_pct"]
    ]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(out_path, index=False)

    # Named after the summary table it belongs to. A fixed "per_run.csv" meant
    # that scoring any other set of runs - captured ones, say - silently
    # overwrote the simulated set's rows, because --out changed but this did not.
    per_run_path = out_path.with_name("%s_per_run.csv" % out_path.stem)
    pd.DataFrame(all_records).to_csv(per_run_path, index=False)

    print("\n  saved: %s" % out_path)
    print("  saved: %s  (one row per run, for checking individual cases)" % per_run_path)
    if timing_rows:
        timing_path = out_path.with_name("%s_timing.csv" % out_path.stem)
        pd.DataFrame(timing_rows).to_csv(timing_path, index=False)
        print("  saved: %s  (live engine timings)" % timing_path)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
