"""
THE POLISH INVARIANT - the polish phase (docs/POLISH_PLAN.md, P1-P6) changes
what is seen and heard, never what is concluded.

After every polish step, two real hardware sessions are replayed through the
live path (src.live.replay, exactly what `python -m src.live --replay` does)
and must give the same verdict as the session that was saved on the day:

  live_session_07  esp32-03 attacked, board unplugged -> CONTAINED
  live_session_03  esp32-02 attacked, board unplugged -> CONTAINED

WHAT IS COMPARED, AND WITH WHAT
-------------------------------
data/<session>.meta.json records the live engine's own first alert (device,
onset, the moment the third abnormal minute closed, the moment it was raised)
and its CONTAINED check. It does not record the named device or the
confidence; those come from the offline pipeline over the saved
data/<session>.parquet - the same capture, analysed whole at STOP.

  named device, confidence, every onset   == offline pipeline on the saved run
  first-alert device and onset             == meta
  earliest-possible alert (closed second)  == meta, exactly
  alert second (raised)                    == meta, to the whole second
  CONTAINED second                         == meta, exactly

Why the raised alert is compared to the second and not exactly: the live
engine reads a file only once the next one exists, so the alert is raised at
the newest packet of the file that completed the third minute. The live
capture cut its ring files where dumpcap cut them; a replay cuts the merged
capture every 10 s with editcap, so the last file can end a fraction of a
second differently. Measured before any polish change (14 Nov 2026):
live_session_07 968.856 s both ways; live_session_03 969.544 s replayed vs
970.240 s live - both second 970 when rounded. The closed second (965 s) and
everything else agree exactly.

The scoring half of the invariant - `git diff --exit-code results/` after
re-running the scoring commands - is run by hand at the end of each step and
reported in the commit message; it re-converts captures and takes minutes.

Skips cleanly when the gitignored captures, saved runs or tshark are absent.
"""

import json
from pathlib import Path

import pytest

from src import attribute, capture, detect, live, runs

ROOT = Path(__file__).resolve().parents[1]
LIVE_PCAPS = ROOT / "pcap" / "live"
SESSIONS = ["live_session_07", "live_session_03"]


def _tshark():
    try:
        return capture.find_tshark()
    except FileNotFoundError:
        return None


def _have(session):
    return ((LIVE_PCAPS / ("%s.pcapng" % session)).exists()
            and runs.meta_path(session).exists() and runs.data_path(session).exists()
            and _tshark() is not None)


@pytest.fixture(scope="module", params=SESSIONS)
def replayed(request, tmp_path_factory):
    session = request.param
    if not _have(session):
        pytest.skip("needs pcap/live/%s.pcapng, data/%s.* and tshark" % (session, session))
    tmp = tmp_path_factory.mktemp(session)
    engine = live.replay(LIVE_PCAPS / ("%s.pcapng" % session), "invariant_" + session,
                         folder=tmp / session, data_dir=tmp / "data", speed=0,
                         save=False, quiet=True)
    meta = json.loads(runs.meta_path(session).read_text(encoding="utf-8"))
    run = runs.load_run(session)
    detection = detect.detect_run(run)
    offline = attribute.attribute_run(run, detection)
    return session, engine, meta, detection, offline


def test_same_device_and_confidence_as_the_saved_session(replayed):
    session, engine, meta, detection, offline = replayed
    assert engine.result.named == offline.named
    assert engine.result.confidence_percent == offline.confidence_percent
    assert engine.result.named == meta["live"]["first_alert"]["device"]
    # what was published for these two sessions (results/table_live_sessions.csv)
    expected = {"live_session_07": "esp32-03", "live_session_03": "esp32-02"}[session]
    assert engine.result.named == expected and engine.result.confidence_percent == 100


def test_same_onsets_as_the_saved_session(replayed):
    session, engine, meta, detection, offline = replayed
    assert engine.detection.onsets == detection.onsets
    assert engine.first_alert["onset_seconds"] == meta["live"]["first_alert"]["onset_seconds"]


def test_same_alert_second_as_the_saved_session(replayed):
    session, engine, meta, detection, offline = replayed
    saved = meta["live"]["first_alert"]
    assert engine.first_alert["device"] == saved["device"]
    assert engine.first_alert["closed_seconds"] == saved["closed_seconds"]
    assert round(engine.first_alert["raised_seconds"]) == round(saved["raised_seconds"])
    assert engine.capture_start_epoch == meta["capture_start_epoch"]


def test_same_contained_second_as_the_saved_session(replayed):
    session, engine, meta, detection, offline = replayed
    saved = meta["live"]["containment"]
    assert engine.containment["contained"] is True and saved["contained"] is True
    assert engine.containment["device"] == saved["device"]
    assert engine.containment["contained_seconds"] == pytest.approx(saved["contained_seconds"],
                                                                    abs=1e-6)
