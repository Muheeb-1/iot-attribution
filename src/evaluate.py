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

from src import attribute, detect, features, runs

ROOT = Path(__file__).resolve().parents[1]
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


def rank_of(ranking, device) -> int:
    """Where the device came in the ranking, or 99 if it is not in it at all."""
    return ranking.index(device) + 1 if device in ranking else NOT_RANKED


def evaluate_one(run_id: str, data_dir=None, groundtruth_dir=GROUNDTRUTH_DIR) -> dict:
    """
    Run the whole pipeline on one saved incident and score it.

    Returns a dictionary of ranks: one per baseline, one for V5, plus the
    supporting detail (confidence, whether it abstained, whether the detector
    ever flagged the true origin at all).
    """
    run = runs.load_run(run_id) if data_dir is None else runs.load_run(run_id, data_dir)
    table = features.features_for_run(run)

    # The weighted detector - what V5 uses.
    weighted = detect.detect(
        table, baseline_windows=run.baseline_windows,
        weighted=True, window_seconds=run.window_seconds,
    )
    # The plain detector - what the prototype fed to the four baselines.
    plain = detect.detect(
        table, baseline_windows=run.baseline_windows,
        weighted=False, window_seconds=run.window_seconds,
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
    answer = load_answer(run_id, groundtruth_dir)
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
                      groundtruth_dir=GROUNDTRUTH_DIR, verbose: bool = False) -> tuple:
    """Score every saved run with the given file prefix ('run' or 'easy')."""
    run_ids = runs.list_runs(prefix=prefix)
    if limit is not None:
        run_ids = run_ids[:limit]
    if not run_ids:
        raise FileNotFoundError(
            "no %s_* runs found in data/. Generate them with:\n"
            "    python -m src.generate --runs 30%s"
            % (prefix, " --easy" if prefix == "easy" else "")
        )

    records = []
    for i, run_id in enumerate(run_ids, 1):
        record = evaluate_one(run_id, groundtruth_dir=groundtruth_dir)
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
    args = parser.parse_args(argv)

    all_rows = []
    all_records = []

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
            prefix, limit=args.runs, verbose=args.verbose
        )

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
    print("  saved: %s  (one row per run, for checking individual cases)\n" % per_run_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
