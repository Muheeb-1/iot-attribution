"""
THE SCENARIO GENERATOR - invents network traffic with a hidden attack in it.

WHY WE SIMULATE INSTEAD OF USING REAL TRAFFIC
---------------------------------------------
To measure whether the attribution method is any good, we need traffic where
somebody already knows the right answer. Real captured traffic does not come
with a label saying "the attack started on the camera at 14:32". Simulated
traffic does. So we invent the incident, hide it inside realistic-looking
normal traffic, and then see whether the rest of the pipeline can find it
again without being told.

WHAT MAKES THE HARD SCENARIO HARD
---------------------------------
A generator that made the attack obvious would flatter our results. This one
is deliberately built to defeat the naive answers:

  * 12 devices, not 7 - more suspects to choose between.
  * Noisy schedules. Devices do not tick like clockwork, so "irregular
    timing" on its own is not evidence of anything.
  * DECOY SPIKES. Roughly a third of innocent devices have a big legitimate
    traffic burst (think a firmware download or a backup). This is why
    "blame whoever sent the most data" scores 0%.
  * LEGITIMATE DEVICE-TO-DEVICE CHATTER. Innocent devices sometimes talk to
    each other, which creates false trails for a causal method to follow.
  * A STEALTHY ATTACKER. The command-and-control beacon is slow (every ~90s)
    and tiny (~140 bytes), and it scans only 5 neighbours, not all of them.
  * RELAYED HOPS. In 40% of runs the jump from the first victim to the second
    goes THROUGH the shared message broker, so there is no direct connection
    between them at all. Any method that only follows direct connections is
    blind in those runs. This is the single biggest reason V5 exists.

WHAT COMES OUT
--------------
For each run, three files:

  data/run_NNN.parquet      the connection records - the "traffic"
  data/run_NNN.meta.json    the lab's own asset inventory + capture settings
  groundtruth/run_NNN.json  THE ANSWER - who really started it

The split between the second and third file is the important one.

  * The META file holds things the lab genuinely knows about itself: which
    devices it owns, how long the capture is, how long the quiet baseline
    period is. Any real security team has this. The detection code is
    allowed to read it.

  * The ANSWER file holds the origin device, the true chain, the true onset
    times and the attacker's command-and-control address. NOTHING except
    src/evaluate.py may read it, ever.

This file WRITES the answer file. It never reads it back. That is enforced by
tests/test_no_groundtruth_leak.py, which parses this file and fails if it
contains any file-reading operation at all.

FAITHFULNESS TO THE PROTOTYPES
------------------------------
The random draws happen in exactly the same order as in hard.py (and, for
--easy, sim.py). That matters more than it looks: change the order and the
same seed produces different traffic, and the published benchmark numbers
stop being reproducible. tests/test_generate.py checks row-for-row that this
file and the prototypes produce identical traffic for the same seed.

USAGE
-----
    python -m src.generate --runs 30              # 30 hard runs  (seeds 5000+)
    python -m src.generate --runs 30 --easy       # 30 easy runs  (seeds 1000+)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src import windows

# --------------------------------------------------------------------------
# Where things live
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
ANSWER_DIR = ROOT / "groundtruth"

# --------------------------------------------------------------------------
# HARD scenario - the real benchmark (ported from hard.py)
# --------------------------------------------------------------------------

WINDOW_SECONDS = windows.WINDOW_SECONDS  # 60 - from the one shared helper

BASELINE_HOURS = 3   # how long we watch before anything bad happens
TOTAL_HOURS = 6      # total length of the capture

BROKER = "broker"    # a shared message server every sensor talks to
C2 = "ext_c2"        # the attacker's outside address. NOT known to detection.

# The lab's 12 devices, as (name, kind). "kind" decides how it behaves when
# nothing is wrong: a sensor chirps every 10s, a camera streams constantly,
# a smart plug reports once a minute, a laptop browses in bursts.
HARD_DEVICES = [
    ("esp32-01", "sensor"), ("esp32-02", "sensor"),
    ("esp32-03", "sensor"), ("esp32-04", "sensor"),
    ("camera", "cam"), ("cam2", "cam"),
    ("plug", "plug"), ("bulb", "plug"),
    ("laptop-c", "lap"), ("laptop-d", "lap"),
    ("phone", "lap"), ("tablet", "lap"),
]
HARD_NAMES = [name for name, _ in HARD_DEVICES]

# Where each kind of device normally sends its data.
HARD_CLOUD = {
    "cam": "cloud_cam",
    "plug": "cloud_plug",
    "lap": "cloud_web",
    "sensor": BROKER,
}

# How often each kind of device normally talks (seconds between connections),
# and the typical size of what it sends, as (mean, spread).
HARD_PERIOD = {"sensor": 10, "cam": 5, "plug": 60, "lap": 30}
HARD_SIZE = {
    "sensor": (214, 18),
    "cam": (240000, 20000),
    "plug": (1200, 200),
    "lap": (9000, 6000),
}

# --------------------------------------------------------------------------
# EASY scenario - the gentler benchmark (ported from sim.py)
# --------------------------------------------------------------------------

EASY_SERVER = "server"
EASY_DEVICES = [
    ("esp32-01", "sensor"), ("esp32-02", "sensor"), ("esp32-03", "sensor"),
    ("camera", "cam"), ("plug", "plug"),
    ("laptop-c", "lap"), ("laptop-d", "lap"),
]
EASY_NAMES = [name for name, _ in EASY_DEVICES]
EASY_CLOUD = {"cam": "cloud_cam", "plug": "cloud_plug", "lap": "cloud_web"}

# Default starting seeds. These match the prototypes, so that "run 0 of the
# hard benchmark" means the same incident here as it did in hard.py.
HARD_SEED_BASE = 5000
EASY_SEED_BASE = 1000

# The columns of a connection record.
COLUMNS = ["t", "src", "dst", "bytes_out", "bytes_in", "pkts"]


# --------------------------------------------------------------------------
# Normal traffic
# --------------------------------------------------------------------------

def _hard_normal(rng):
    """
    Six hours of ordinary life on a 12-device network.

    Four things happen per device, and the last two are what make this
    benchmark hard rather than easy.
    """
    rows = []
    total = TOTAL_HOURS * 3600

    for dev, kind in HARD_DEVICES:
        period = HARD_PERIOD[kind]
        size = HARD_SIZE[kind]

        # 1. The device's routine: report to its own cloud service, over and
        #    over. The interval is multiplied by a random 0.45-1.9, so the
        #    schedule is genuinely ragged. A tidy schedule would make the
        #    attacker's steady beacon stand out far too easily.
        t = rng.uniform(0, period)
        while t < total:
            n = int(rng.integers(1, 5)) if kind == "lap" else 1
            for _ in range(n):
                rows.append((
                    t, dev, HARD_CLOUD[kind],
                    int(abs(rng.normal(*size)) + 50),
                    int(abs(rng.normal(size[0] * 0.3, size[1])) + 20),
                    4,
                ))
            t += period * rng.uniform(0.45, 1.9)

        # 2. Update / telemetry servers it has never used before. 6-20 of
        #    them, drawn from 120 possible addresses. This is the honest
        #    version of "contacted a brand new outside address", and it is
        #    why that feature alone cannot convict anybody.
        for _ in range(int(rng.integers(6, 20))):
            rows.append((
                rng.uniform(0, total), dev, f"upd_{rng.integers(0, 120)}",
                int(abs(rng.normal(4000, 3000)) + 200),
                int(abs(rng.normal(9000, 7000)) + 500),
                6,
            ))

        # 3. Legitimate device-to-device chatter, about a third of the time.
        #    A phone talking to a camera is normal. It also lays down a
        #    perfectly innocent trail that a causal method can mistake for
        #    an attacker hopping between machines.
        if rng.random() < 0.35:
            peer = HARD_NAMES[int(rng.integers(0, len(HARD_NAMES)))]
            if peer != dev:
                t = rng.uniform(0, total)
                for _ in range(int(rng.integers(5, 40))):
                    rows.append((
                        t, dev, peer,
                        int(abs(rng.normal(800, 300)) + 50), 300, 3,
                    ))
                    t += rng.uniform(1, 25)

        # 4. THE DECOY. About 30% of devices get a large, entirely innocent
        #    traffic burst after the baseline period - 400 connections of
        #    ~300KB each. On a graph this dwarfs the actual attack. It is the
        #    reason ranking by traffic volume gets 0% on this benchmark.
        if rng.random() < 0.30:
            t = rng.uniform(BASELINE_HOURS * 3600, total - 600)
            for step in range(400):
                rows.append((
                    t + step * 0.5, dev, HARD_CLOUD[kind],
                    int(rng.normal(300000, 50000)), 1500, 200,
                ))

    return rows


def _easy_normal(rng):
    """The simpler world from sim.py: 7 devices, tidy schedules, no decoys."""
    rows = []
    total = TOTAL_HOURS * 3600

    for dev, kind in EASY_DEVICES:
        if kind == "sensor":
            t = rng.uniform(0, 10)
            while t < total:
                rows.append((
                    t, dev, EASY_SERVER,
                    int(rng.normal(214, 18)), int(rng.normal(60, 8)), 2,
                ))
                t += 10 * rng.uniform(0.96, 1.04)

        elif kind == "cam":
            t = rng.uniform(0, 5)
            while t < total:
                rows.append((
                    t, dev, EASY_CLOUD["cam"],
                    int(rng.normal(240000, 20000)), int(rng.normal(4500, 600)), 40,
                ))
                t += 5.0 * rng.uniform(0.9, 1.1)

        elif kind == "plug":
            t = rng.uniform(0, 60)
            while t < total:
                rows.append((
                    t, dev, EASY_CLOUD["plug"],
                    int(rng.normal(1200, 200)), int(rng.normal(400, 60)), 4,
                ))
                t += 60 * rng.uniform(0.9, 1.1)

        else:  # laptop
            t = rng.uniform(0, 30)
            while t < total:
                for _ in range(int(rng.integers(1, 6))):
                    rows.append((
                        t, dev, EASY_CLOUD["lap"],
                        int(abs(rng.normal(9000, 6000)) + 500),
                        int(abs(rng.normal(40000, 30000)) + 1000),
                        12,
                    ))
                t += 30 * rng.uniform(0.5, 2.0)

        for _ in range(int(rng.integers(3, 9))):
            rows.append((
                rng.uniform(0, total), dev, f"upd_{rng.integers(0, 40)}",
                int(abs(rng.normal(3000, 1500)) + 200),
                int(abs(rng.normal(8000, 4000)) + 500),
                6,
            ))

    return rows


# --------------------------------------------------------------------------
# The attack
# --------------------------------------------------------------------------

def _hard_attack(rows, rng):
    """
    Hide an intrusion inside the normal traffic.

    The story, in order:
      1. One device - CHOSEN AT RANDOM, so we cannot accidentally tune the
         detector to a favourite - starts quietly phoning home to an outside
         address (the beacon).
      2. It scans 5 neighbours, looking for somewhere to go next.
      3. It moves to a second device. In 40% of runs this hop is RELAYED
         through the shared broker, leaving no direct trace between them.
      4. The second device starts its own beacon, then exfiltrates a large
         amount of data. This makes the SECOND device the loudest one on the
         network - the classic trap.
      5. The second device moves on to a third.

    Returns the rows plus the answer sheet.
    """
    total = TOTAL_HOURS * 3600

    origin = HARD_NAMES[int(rng.integers(0, len(HARD_NAMES)))]
    rest = [d for d in HARD_NAMES if d != origin]
    rng.shuffle(rest)
    victim2, victim3 = rest[0], rest[1]

    # When it starts: after the baseline has been established, with enough
    # time left for the whole story to play out.
    t0 = rng.uniform(BASELINE_HOURS * 3600 + 900, total - 2400)
    via_broker = rng.random() < 0.40

    # 1. The beacon. Slow and small on purpose - about 140 bytes every 90
    #    seconds. It is a rhythm, not a flood, so volume-based methods miss it.
    t = t0
    while t < total:
        rows.append((
            t, origin, C2,
            int(rng.normal(140, 15)), int(rng.normal(90, 12)), 2,
        ))
        t += 90 * rng.uniform(0.8, 1.2)

    # 2. A quiet scan: two probes each at just 5 neighbours.
    t_scan = t0 + 120
    for peer in rng.choice([d for d in HARD_NAMES if d != origin], 5, replace=False):
        for step in range(2):
            rows.append((t_scan + step * 0.5, origin, str(peer), 60, 0, 1))

    # 3. The hop to the second device.
    t_hop = t0 + 300
    if via_broker:
        # RELAYED: origin -> broker, then broker -> victim2. There is no
        # origin -> victim2 record anywhere in the data.
        for step in range(120):
            rows.append((t_hop + step * 0.5, origin, BROKER,
                         int(rng.normal(500, 60)), 200, 3))
        for step in range(120):
            rows.append((t_hop + 8 + step * 0.5, BROKER, victim2,
                         int(rng.normal(500, 60)), 200, 3))
    else:
        for step in range(160):
            rows.append((t_hop + step * 0.4, origin, victim2,
                         int(rng.normal(420, 40)), 300, 3))

    # 4. Victim 2 starts its own beacon...
    t2 = t0 + 480
    t = t2
    while t < total:
        rows.append((
            t, victim2, C2,
            int(rng.normal(140, 15)), int(rng.normal(90, 12)), 2,
        ))
        t += 90 * rng.uniform(0.8, 1.2)

    # ...and then steals data: 600 connections of ~420KB. This is the single
    # loudest thing in the whole capture, and it belongs to a VICTIM.
    t_exfil = t2 + 60
    for step in range(600):
        rows.append((t_exfil + step * 0.4, victim2, C2,
                     int(rng.normal(420000, 40000)), 1200, 300))

    # 5. On to a third device.
    t3 = t0 + 780
    for step in range(700):
        rows.append((t3 + step * 0.2, victim2, victim3,
                     int(rng.normal(700, 80)), 2500, 5))

    answer = {
        "origin": origin,
        "chain": [origin, victim2, victim3],
        "via_broker": bool(via_broker),
        "c2_host": C2,
        "true_onset_seconds": {origin: float(t0), victim2: float(t2), victim3: float(t3)},
        "events": {
            "beacon_start": float(t0),
            "scan": float(t_scan),
            "lateral_hop": float(t_hop),
            "victim2_beacon": float(t2),
            "exfiltration": float(t_exfil),
            "second_hop": float(t3),
        },
    }
    return rows, answer


def _easy_attack(rows, rng):
    """The gentler intrusion from sim.py: louder beacon, full scan, direct hop."""
    total = TOTAL_HOURS * 3600

    candidates = list(EASY_NAMES)
    origin = candidates[int(rng.integers(0, len(candidates)))]
    rest = [d for d in candidates if d != origin]
    rng.shuffle(rest)
    victim2, victim3 = rest[0], rest[1]

    t0 = rng.uniform(BASELINE_HOURS * 3600 + 1800, total - 3600)

    t = t0
    while t < total:
        rows.append((t, origin, C2,
                     int(rng.normal(200, 20)), int(rng.normal(120, 15)), 2))
        t += 30 * rng.uniform(0.87, 1.13)

    t_scan = t0 + 90
    for peer in candidates:
        if peer == origin:
            continue
        for step in range(4):
            rows.append((t_scan + step * 0.4 + rng.uniform(0, .2), origin, peer, 60, 0, 1))

    t_hop = t0 + 180
    for step in range(340):
        rows.append((t_hop + step * 0.26, origin, victim2,
                     int(rng.normal(420, 40)), int(rng.normal(300, 40)), 3))

    t2 = t0 + 270
    t = t2
    while t < total:
        rows.append((t, victim2, C2,
                     int(rng.normal(200, 20)), int(rng.normal(120, 15)), 2))
        t += 30 * rng.uniform(0.87, 1.13)

    t_exfil = t2 + 30
    for step in range(700):
        rows.append((t_exfil + step * 0.35, victim2, C2,
                     int(rng.normal(480000, 40000)), 1200, 340))

    t3 = t0 + 420
    for step in range(900):
        rows.append((t3 + step * 0.13, victim2, victim3,
                     int(rng.normal(700, 80)), int(rng.normal(2500, 400)), 5))

    answer = {
        "origin": origin,
        "chain": [origin, victim2, victim3],
        "via_broker": False,
        "c2_host": C2,
        "true_onset_seconds": {origin: float(t0), victim2: float(t2), victim3: float(t3)},
        "events": {
            "beacon_start": float(t0),
            "scan": float(t_scan),
            "lateral_hop": float(t_hop),
            "victim2_beacon": float(t2),
            "exfiltration": float(t_exfil),
            "second_hop": float(t3),
        },
    }
    return rows, answer


# --------------------------------------------------------------------------
# Destination ports
# --------------------------------------------------------------------------

def _port_for(destination: str, device_names: list[str]) -> int:
    """
    Give every connection a realistic destination port.

    This is worked out from the destination by a fixed lookup - no randomness
    is involved, so adding it cannot disturb the random draws above and cannot
    change the benchmark numbers by so much as a row. It exists because the
    incident brief in step 7 has to quote real ports, and a brief that says
    "port 8443" when no such port appears in the evidence is exactly the kind
    of invention we must be able to catch.
    """
    if destination == BROKER:
        return 1883      # MQTT, the usual message-broker port
    if destination == EASY_SERVER:
        return 1883
    if destination == "cloud_cam":
        return 554       # RTSP video streaming
    if destination in ("cloud_plug", "cloud_web"):
        return 443       # ordinary HTTPS
    if destination.startswith("upd_"):
        return 443       # update servers over HTTPS
    if destination in device_names:
        return 445       # device-to-device file sharing
    return 8443          # anything else, including the attacker's address


# --------------------------------------------------------------------------
# Putting one run together
# --------------------------------------------------------------------------

def make_run(seed: int, easy: bool = False):
    """
    Build one complete incident.

    Returns (connections, answer) where connections is a table sorted by time
    and answer is the dictionary that will become the answer file.
    """
    rng = np.random.default_rng(seed)

    if easy:
        rows = _easy_normal(rng)
        rows, answer = _easy_attack(rows, rng)
        device_names = list(EASY_NAMES)
        devices = EASY_DEVICES
    else:
        rows = _hard_normal(rng)
        rows, answer = _hard_attack(rows, rng)
        device_names = list(HARD_NAMES)
        devices = HARD_DEVICES

    df = pd.DataFrame(rows, columns=COLUMNS).sort_values("t").reset_index(drop=True)

    # A stable label for every single connection. The incident brief cites
    # these as evidence ids, and step 7 checks that every id it quotes really
    # exists. Assigned after sorting, so C000001 is always the earliest
    # connection in the file.
    df.insert(0, "conn_id", ["C%06d" % i for i in range(len(df))])
    df["dport"] = [_port_for(d, device_names) for d in df["dst"]]

    df = df[["conn_id", "t", "src", "dst", "dport", "bytes_out", "bytes_in", "pkts"]]
    df["bytes_out"] = df["bytes_out"].astype("int64")
    df["bytes_in"] = df["bytes_in"].astype("int64")
    df["pkts"] = df["pkts"].astype("int32")
    df["dport"] = df["dport"].astype("int32")

    # Record the true onsets as window numbers too, using the one shared
    # helper - so the answer file and the detector are speaking the same
    # language when evaluate.py compares them later.
    answer["true_onset_windows"] = {
        dev: int(windows.window_of(t))
        for dev, t in answer["true_onset_seconds"].items()
    }
    answer["scenario"] = "easy" if easy else "hard"
    answer["seed"] = int(seed)
    answer["devices"] = [name for name, _ in devices]

    return df, answer


def _meta_for(df: pd.DataFrame, seed: int, easy: bool, run_id: str) -> dict:
    """
    The lab's own record of itself. Deliberately contains NOTHING about the
    attack: no origin, no chain, no onset times, no attacker address. Every
    field here is something a real security team would already have written
    down before any incident happened.
    """
    devices = EASY_DEVICES if easy else HARD_DEVICES
    baseline_seconds = BASELINE_HOURS * 3600
    return {
        "run_id": run_id,
        "scenario": "easy" if easy else "hard",
        "seed": int(seed),
        "devices": [{"name": n, "kind": k} for n, k in devices],
        "device_names": [n for n, _ in devices],
        "window_seconds": WINDOW_SECONDS,
        "capture_seconds": TOTAL_HOURS * 3600,
        "baseline_seconds": baseline_seconds,
        "baseline_windows": windows.baseline_window_count(baseline_seconds, WINDOW_SECONDS),
        "n_connections": int(len(df)),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def write_run(seed: int, index: int, easy: bool = False,
              data_dir: Path = DATA_DIR, answer_dir: Path = ANSWER_DIR,
              prefix: str | None = None) -> dict:
    """
    Build one run and save it to disk. Returns a small summary dictionary
    (used by the command line to print the table at the end).
    """
    if prefix is None:
        prefix = "easy" if easy else "run"
    run_id = "%s_%03d" % (prefix, index)

    df, answer = make_run(seed, easy=easy)
    answer["run_id"] = run_id

    data_dir.mkdir(parents=True, exist_ok=True)
    answer_dir.mkdir(parents=True, exist_ok=True)

    data_path = data_dir / ("%s.parquet" % run_id)
    meta_path = data_dir / ("%s.meta.json" % run_id)
    answer_path = answer_dir / ("%s.json" % run_id)

    df.to_parquet(data_path, index=False)
    meta = _meta_for(df, seed, easy, run_id)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    answer_path.write_text(json.dumps(answer, indent=2), encoding="utf-8")

    return {
        "run_id": run_id,
        "scenario": answer["scenario"],
        "seed": seed,
        "rows": int(len(df)),
        "origin": answer["origin"],
        "chain": answer["chain"],
        "via_broker": answer["via_broker"],
        "data_path": data_path,
    }


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate simulated IoT incidents with a known answer."
    )
    parser.add_argument("--runs", type=int, default=30,
                        help="how many runs to generate (default: 30)")
    parser.add_argument("--easy", action="store_true",
                        help="generate the simpler sim.py scenario instead of the hard one")
    parser.add_argument("--start", type=int, default=0,
                        help="first run number, used in the file name (default: 0)")
    parser.add_argument("--seed-base", type=int, default=None,
                        help="first random seed (default: 5000 hard, 1000 easy)")
    parser.add_argument("--prefix", default=None,
                        help="file name prefix (default: 'run' hard, 'easy' easy)")
    parser.add_argument("--quiet", action="store_true", help="print nothing")
    args = parser.parse_args(argv)

    if args.runs <= 0:
        parser.error("--runs must be at least 1")

    seed_base = args.seed_base
    if seed_base is None:
        seed_base = EASY_SEED_BASE if args.easy else HARD_SEED_BASE

    summaries = []
    for offset in range(args.runs):
        index = args.start + offset
        summaries.append(
            write_run(seed_base + index, index, easy=args.easy, prefix=args.prefix)
        )

    if not args.quiet:
        label = "EASY" if args.easy else "HARD"
        print("\n  %s scenario - %d run(s) written" % (label, len(summaries)))
        print("  %-10s %8s %9s %-11s %-8s %s"
              % ("run", "seed", "rows", "origin", "relayed", "true chain"))
        print("  " + "-" * 76)
        for s in summaries:
            print("  %-10s %8d %9d %-11s %-8s %s"
                  % (s["run_id"], s["seed"], s["rows"], s["origin"],
                     "yes" if s["via_broker"] else "no", " -> ".join(s["chain"])))
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
