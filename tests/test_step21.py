"""
Step 21 - the live sessions scored, an aborted session left out, and the
documents the demo is run from.

Three kinds of test:

1. Aborted sessions (plain unit tests, no data needed). live_session_06 was
   stopped during its baseline and no attack was sent, so it has no answer
   file. evaluate.py must leave it out of every scored set automatically -
   "--runs 7" over sessions 01..07 scores six - and must never try to score
   it (it would crash on the missing answer, or worse, count as a miss).

2. The sessions as measured on 13 Nov (skip when data/ or the answer files
   are absent, e.g. on a fresh clone). These pin the figures quoted in
   README.md and docs/LIVE_DEMO.md, so the documents cannot drift from the
   data without a test failing.

3. The documents themselves. Every "python -m src.<module> --flag" written in
   README.md or docs/LIVE_DEMO.md must name a module that exists and flags
   that module really accepts. A typo in the demo script would otherwise be
   found in front of the judges.
"""

import json
import re
from pathlib import Path

import pytest

from src import evaluate, runs

ROOT = Path(__file__).resolve().parent.parent
ANSWERS = ROOT / "groundtruth"


# --------------------------------------------------------------------------
# 1. Aborted sessions
# --------------------------------------------------------------------------

def _fake_record(run_id, **_):
    methods = (evaluate.BASELINE_NAMES + evaluate.V5_METHODS
               + ["fair " + b for b in evaluate.BASELINE_NAMES])
    return {"run_id": run_id, **{m: 1 for m in methods},
            "abstained": False, "abstained_prototype": False}


def test_live_session_06_is_recorded_as_aborted():
    assert "live_session_06" in evaluate.ABORTED_SESSIONS
    assert evaluate.session_note("live_session_06").startswith("aborted")


def test_an_aborted_session_is_never_scored(monkeypatch, capsys):
    ids = ["live_session_%02d" % n for n in range(1, 8)]
    monkeypatch.setattr(evaluate.runs, "list_runs", lambda prefix=None: ids)
    scored = []

    def fake(run_id, **kw):
        scored.append(run_id)
        return _fake_record(run_id, **kw)

    monkeypatch.setattr(evaluate, "evaluate_one", fake)
    records, summary, _ = evaluate.evaluate_scenario("live_session", limit=7)
    assert "live_session_06" not in scored
    assert [r["run_id"] for r in records] == [i for i in ids if i != "live_session_06"]
    assert int(summary["runs"].iloc[0]) == 6
    # ...and it says so on screen, so the left-out session is never silent.
    assert "left out (not scored): live_session_06" in capsys.readouterr().out


def test_aborted_and_excluded_together(monkeypatch):
    ids = ["live_session_%02d" % n for n in range(1, 8)]
    monkeypatch.setattr(evaluate.runs, "list_runs", lambda prefix=None: ids)
    monkeypatch.setattr(evaluate, "evaluate_one", _fake_record)
    records, _, _ = evaluate.evaluate_scenario("live_session", limit=7,
                                               exclude=["live_session_02"])
    assert [r["run_id"] for r in records] == [
        "live_session_01", "live_session_03", "live_session_04",
        "live_session_05", "live_session_07"]


def test_session_05_carries_its_note():
    assert evaluate.session_note("live_session_05") == "board back on before STOP"
    for clean in ("live_session_01", "live_session_03", "live_session_04", "live_session_07"):
        assert evaluate.session_note(clean) == ""


# --------------------------------------------------------------------------
# 2. The sessions as measured on 13 Nov
# --------------------------------------------------------------------------

def _have(*run_ids, answers=True):
    return all(runs.meta_path(r).exists() and (not answers or (ANSWERS / ("%s.json" % r)).exists())
               for r in run_ids)


# session: origin, seconds trigger -> alert, seconds alert -> CONTAINED, beacons
MEASURED = {
    "live_session_03": ("esp32-02", 234.3, 95.9, 8),
    "live_session_04": ("esp32-03", 203.1, 97.0, 7),
    "live_session_05": ("esp32-02", 227.1, 103.0, 8),
    "live_session_07": ("esp32-03", 218.8, 81.3, 7),
}


@pytest.mark.skipif(not _have(*MEASURED), reason="needs data/live_session_03..07 and answers")
@pytest.mark.parametrize("run_id", sorted(MEASURED))
def test_session_as_scored_on_13_nov(run_id):
    origin, detect_s, contained_s, n_beacons = MEASURED[run_id]
    row = evaluate.live_timing(run_id)
    assert row["origin"] == origin and row["alert_right"]
    assert row["detect_seconds"] == pytest.approx(detect_s, abs=0.2)
    assert row["contained"] and row["contained_device"] == origin
    assert row["contained_seconds"] == pytest.approx(contained_s, abs=0.2)
    assert evaluate.evaluate_one(run_id)[evaluate.V5_FIXED] == 1
    flows = runs.load_run(run_id).connections
    beacons = flows[flows.dport == 4444]
    assert set(beacons.src) == {origin} and len(beacons) == n_beacons
    assert set(beacons.bytes_out) == {496}
    assert beacons.t.diff().dropna().round().eq(30).all()
    # laptop-i3's loop was ON (session 01: 614 laptop flows; 02, loop off: 22).
    assert (flows.src == "laptop-i3").sum() > 500


@pytest.mark.skipif(not _have("live_session_05"), reason="needs data/live_session_05")
def test_session_05_board_rejoined_before_contained():
    """The operator's note, checked from the traffic: esp32-02 asked for an
    address from 0.0.0.0 after its last beacon and before CONTAINED - and no
    beacon followed, so CONTAINED is genuine."""
    meta = json.loads(runs.meta_path("live_session_05").read_text(encoding="utf-8"))
    contain = meta["live"]["containment"]
    start = meta["capture_start_epoch"]
    flows = runs.load_run("live_session_05").connections
    last_beacon = contain["last_seen_epoch"] - start
    rejoin = flows[(flows.src == "esp32-02") & (flows.dport == 67) & flows.src_unassigned]
    assert len(rejoin) == 1
    assert last_beacon < rejoin.t.iloc[0] < contain["contained_epoch"] - start
    assert not ((flows.dport == 4444) & (flows.t > last_beacon)).any()


@pytest.mark.skipif(not _have("live_session_06", answers=False), reason="needs data/live_session_06")
def test_session_06_really_had_no_attack():
    assert not (ANSWERS / "live_session_06.json").exists()
    meta = json.loads(runs.meta_path("live_session_06").read_text(encoding="utf-8"))
    assert meta["capture_seconds"] < meta["baseline_seconds"]       # stopped during baseline
    assert meta["live"]["first_alert"] is None
    flows = runs.load_run("live_session_06").connections
    assert not (flows.dport == 4444).any()


# --------------------------------------------------------------------------
# 3. The documents
# --------------------------------------------------------------------------

DOCS = [ROOT / "README.md", ROOT / "docs" / "LIVE_DEMO.md"]
COMMAND = re.compile(r"python -m src\.(\w+)([^\n`|]*)")


def _commands():
    found = []
    for doc in DOCS:
        for module, rest in COMMAND.findall(doc.read_text(encoding="utf-8")):
            found.append((doc.name, module, re.findall(r"(?<![\w-])--[a-z][a-z-]*", rest)))
    return found


def test_both_documents_exist_and_cover_the_demo():
    for doc in DOCS:
        assert doc.exists(), doc
    demo = (ROOT / "docs" / "LIVE_DEMO.md").read_text(encoding="utf-8").lower()
    for must in ("fallback", "why about four minutes", "anomaly detection",
                 "quiet", "cannot see", "stop the capture before plugging"):
        assert must in demo, must


def test_every_documented_command_exists_with_its_flags():
    commands = _commands()
    assert len(commands) > 10
    for doc, module, flags in commands:
        source = ROOT / "src" / ("%s.py" % module)
        assert source.exists(), "%s names src.%s, which does not exist" % (doc, module)
        text = source.read_text(encoding="utf-8")
        for flag in flags:
            assert '"%s"' % flag in text, "%s: src.%s has no %s option" % (doc, module, flag)
