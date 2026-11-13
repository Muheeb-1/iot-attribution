"""
The front door: finding a saved run on disk and loading it.

A "run" is one simulated incident, saved as two files by src/generate.py:

    data/run_000.parquet     the connection records
    data/run_000.meta.json   the lab's own asset inventory and capture settings

This module loads exactly those two, and nothing else. It has no idea the
answer sheet exists, and neither does anything that imports it.

Why the loading lives here rather than inside features.py: features.py should
be a plain function - traffic in, table out - so it can be tested with a
handful of hand-written rows and no files anywhere. Mixing "find the file" in
with "do the maths" makes both harder to test and harder to explain.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


@dataclass
class Run:
    """One loaded incident, with everything the pipeline is allowed to know."""

    run_id: str
    scenario: str                      # "hard" or "easy"
    connections: pd.DataFrame          # the traffic
    device_names: list[str]            # the lab's own devices (the inventory)
    devices: list[dict] = field(default_factory=list)   # name + kind
    window_seconds: int = 60
    capture_seconds: int = 6 * 3600
    baseline_seconds: int = 3 * 3600
    baseline_windows: int = 180
    # The run this one is a fresh conversion of (same capture, newer rules),
    # or None. Written by src/reconvert.py; see replay_runs() below.
    replaces: str | None = None

    def __len__(self) -> int:
        return len(self.connections)

    def __repr__(self) -> str:
        return "Run(%s, %s, %d connections, %d devices)" % (
            self.run_id, self.scenario, len(self.connections), len(self.device_names)
        )


def data_path(run_id: str, data_dir: Path = DATA_DIR) -> Path:
    return Path(data_dir) / ("%s.parquet" % run_id)


def meta_path(run_id: str, data_dir: Path = DATA_DIR) -> Path:
    return Path(data_dir) / ("%s.meta.json" % run_id)


def list_runs(prefix: str | None = None, data_dir: Path = DATA_DIR) -> list[str]:
    """
    Every run saved in the data folder, in name order.

    prefix="run" gives the hard runs, prefix="easy" gives the easy ones.
    """
    pattern = "%s_*.parquet" % prefix if prefix else "*.parquet"
    return sorted(p.stem for p in Path(data_dir).glob(pattern))


def replaced_by(data_dir: Path = DATA_DIR) -> dict:
    """
    {old run id: new run id} for every run that has been re-converted.

    Why this exists (13 Nov, fallback rung 3): the twelve live_batch runs and
    rehearsal_01 were saved before Step 18, under the old naming rule. The
    replay page analyses every run under today's rules, and on those old
    tables it named the right board in only 4 of 12 batch runs (and blamed
    laptop-i3 for rehearsal_01). They cannot simply be re-written in place:
    `evaluate.py --rules old` reproduces the published table_live.csv from
    exactly those saved files. So src/reconvert.py converts each capture
    again into a NEW run id and writes "replaces": "<old id>" into the new
    run's meta file. The old files stay byte-for-byte as they were.
    """
    links = {}
    for meta_file in sorted(Path(data_dir).glob("*.meta.json")):
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        old = meta.get("replaces")
        if old:
            links[old] = meta.get("run_id", meta_file.name[:-len(".meta.json")])
    return links


def replay_runs(data_dir: Path = DATA_DIR) -> list[str]:
    """
    The runs the replay page offers: every run, minus the ones that have been
    replaced by a fresh conversion. A replaced run is still on disk and still
    scored by evaluate.py; it is only kept out of the demo list, because the
    page would analyse an old-rule table with today's rules and could show a
    wrong board.
    """
    hidden = set(replaced_by(data_dir))
    return [r for r in list_runs(data_dir=data_dir) if r not in hidden]


def load_run(run_id: str, data_dir: Path = DATA_DIR) -> Run:
    """Load one saved incident. Raises a clear error if either file is missing."""
    connections_file = data_path(run_id, data_dir)
    inventory_file = meta_path(run_id, data_dir)

    if not connections_file.exists():
        raise FileNotFoundError(
            "no traffic file for run %r at %s - generate it first with:\n"
            "    python -m src.generate --runs 1" % (run_id, connections_file)
        )
    if not inventory_file.exists():
        raise FileNotFoundError(
            "run %r has traffic but no inventory file at %s" % (run_id, inventory_file)
        )

    connections = pd.read_parquet(connections_file)
    meta = json.loads(inventory_file.read_text(encoding="utf-8"))

    return Run(
        run_id=meta["run_id"],
        scenario=meta["scenario"],
        connections=connections,
        device_names=list(meta["device_names"]),
        devices=list(meta.get("devices", [])),
        window_seconds=int(meta["window_seconds"]),
        capture_seconds=int(meta["capture_seconds"]),
        baseline_seconds=int(meta["baseline_seconds"]),
        baseline_windows=int(meta["baseline_windows"]),
        replaces=meta.get("replaces"),
    )
