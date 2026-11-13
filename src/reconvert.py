"""
RECONVERT - give the replay page fresh copies of the real captures.

THE PROBLEM (measured 13 Nov)
-----------------------------
The replay page is the last rung of the fallback ladder: if the live page
fails during the demo, we open a saved capture there. But the twelve
live_batch runs and rehearsal_01 in data/ were converted BEFORE Step 18, with
the old naming rule (multicast addresses counted as ordinary destinations, no
src_unassigned column). The page analyses every run with TODAY's rules, so it
was mixing an old-rule table with new-rule maths. Result: the right board in
only 4 of the 12 batch runs (7 abstained, live_batch_05 blamed laptop-i3), and
laptop-i3 for rehearsal_01.

WHY NOT JUST OVERWRITE THEM
---------------------------
Because `python -m src.evaluate --rules old --prefix live_batch ...` rebuilds
the published results/table_live.csv from exactly those saved files, byte for
byte. Overwriting them would quietly change a published number's source.

WHAT THIS DOES INSTEAD
----------------------
Each raw capture is converted again, under today's rules, into a NEW run id:

    pcap/segments/live_batch_NN.pcapng   ->  data/lab_batch_NN
    pcap/live/rehearsal_01.pcapng        ->  data/lab_rehearsal_01

The new run takes its inventory, window and baseline length (and the
capture's clock start, if recorded) from the old run's meta file, so it is
the same analysis `evaluate.py --pcap-dir` already scores - just saved. Its
meta file says "replaces": "<old id>". The replay page then lists the new run
and hides the old one (runs.replay_runs); the old files are not touched.

The new prefix is deliberately NOT live_batch_ or rehearsal_: evaluate.py
picks runs by prefix, and lab_batch_01 sorting in among live_batch_01..12
would change which twelve runs `--runs 12` scores.

The old run's "live" block (rehearsal_01 has one: what the live engine said
on the day, under the old rule) is NOT copied - it describes that session,
not this conversion.

USAGE
-----
    python -m src.reconvert            # converts all 13, skips any already done
    python -m src.reconvert --force    # convert again, replacing the lab_* runs
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from src import capture, runs

ROOT = Path(__file__).resolve().parents[1]

# (old run id, new run id, the raw capture it came from)
RECONVERSIONS = [
    ("live_batch_%02d" % n, "lab_batch_%02d" % n,
     ROOT / "pcap" / "segments" / ("live_batch_%02d.pcapng" % n))
    for n in range(1, 13)
] + [
    ("rehearsal_01", "lab_rehearsal_01", ROOT / "pcap" / "live" / "rehearsal_01.pcapng"),
]

# Copied from the old meta file when present. Everything else is rebuilt.
CARRIED_OVER = ("capture_start_epoch",)


def reconvert(old_id: str, new_id: str, pcap_path, tshark=None,
              data_dir: Path = runs.DATA_DIR, force: bool = False) -> dict:
    """
    Convert one capture again under the rules in force now, as new_id.

    Uses exactly the functions everything else uses (capture.read_packets,
    capture.build_flows, capture.save_run) - there is no second converter.
    Returns the new run's meta dict.
    """
    data_dir = Path(data_dir)
    old_meta = json.loads(runs.meta_path(old_id, data_dir).read_text(encoding="utf-8"))
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError("no capture file for %s at %s" % (old_id, pcap_path))

    binary = capture.find_tshark(tshark)
    frame = capture.build_flows(capture.read_packets(pcap_path, binary))
    _, meta_file, meta = capture.save_run(
        frame, new_id, pcap_path,
        baseline_seconds=old_meta["baseline_seconds"],
        window_seconds=old_meta["window_seconds"],
        data_dir=data_dir, force=force,
    )
    # Same pattern as src/live.py: save_run writes the standard pair, and the
    # extra facts are added to the meta afterwards.
    for key in CARRIED_OVER:
        if key in old_meta:
            meta[key] = old_meta[key]
    meta["replaces"] = old_id
    meta["reconverted"] = {
        "why": "the old run was saved under the pre-Step-18 rules; the replay "
               "page analyses with today's rules",
        "from_pcap": str(pcap_path.relative_to(ROOT)) if pcap_path.is_relative_to(ROOT)
                     else str(pcap_path),
        "src_unassigned_column": capture.SRC_UNASSIGNED in frame.columns,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Re-convert the real captures under today's rules into new lab_* runs.")
    parser.add_argument("--force", action="store_true",
                        help="replace lab_* runs that already exist")
    parser.add_argument("--tshark", default=None)
    args = parser.parse_args(argv)

    if not capture.MULTICAST_AS_BROADCAST:
        print("\n  capture.MULTICAST_AS_BROADCAST is off - refusing: these copies "
              "must be made under today's rules.\n", file=sys.stderr)
        return 1

    made, skipped, failed = 0, 0, 0
    print()
    for old_id, new_id, pcap in RECONVERSIONS:
        if runs.data_path(new_id).exists() and not args.force:
            print("  %-13s already there (replaces %s) - skipped" % (new_id, old_id))
            skipped += 1
            continue
        try:
            meta = reconvert(old_id, new_id, pcap, tshark=args.tshark, force=args.force)
        except (FileNotFoundError, FileExistsError, RuntimeError, KeyError) as exc:
            print("  %-13s FAILED: %s" % (new_id, exc), file=sys.stderr)
            failed += 1
            continue
        print("  %-13s <- %-40s %4d connections (replaces %s)"
              % (new_id, meta["reconverted"]["from_pcap"], meta["n_connections"], old_id))
        made += 1
    print("\n  %d converted, %d already there, %d failed" % (made, skipped, failed))
    print("  The replay page now lists the lab_* runs and hides the runs they replace.\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
