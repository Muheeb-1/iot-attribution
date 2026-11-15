"""
Step P6 - the two dress rehearsals on hardware (live_session_08 and _09,
15 Nov 2026), and the one display fix found during them.

Three kinds of test:

1. The stray "›" on the live page (plain unit tests, no data needed). It was
   not a character in our HTML: it was Streamlit's own "open the sidebar"
   button, a chevron fixed to the window's top-left corner. The page scrolls
   underneath it (inside Streamlit's main panel), so it was drawn on the "o"
   of the title and, scrolled, just left of "Severity rule" and of "Attack
   techniques seen". The button must stay - the sidebar holds the "Alert
   sound" switch the demo script tells the operator to click - so the theme
   gives it its own left margin. Checked in Edge (1366 x 768) at the top of
   the page and scrolled: the button ends at x = 42 px, the page content
   starts at x = 57 px; clicking it still opens the sidebar.

2. The two sessions as measured (skip when data/ or the answer files are
   absent, e.g. on a fresh clone). These pin the figures quoted in README.md,
   docs/HOW_IT_WORKS.md and docs/LIVE_DEMO.md.

3. Why session 08's alert came sooner (2 min 37 s; every other session
   3 min 16 s - 3 min 54 s), checked from the engine's own record. The
   alert needs three minutes in a row over 4.0. A minute holding just ONE
   beacon scored 3.19-3.25 (under the line) in sessions 01, 03, 05 and 09, so
   the count started a minute later. In 08 that minute scored 106: esp32-02's
   learned normal had no incoming bytes at all (its connection to the broker
   never appears in the capture - in the other sessions it appears in the first
   learning minute, about 9 kB in), so the spread fell back to 1 byte and the
   beacon's 170 bytes back were far over the line. The detector is unchanged;
   this is what that session's baseline looked like.

And the published tables: sessions 01-07's rows are exactly as committed at
tag core-locked; 08 and 09 are new rows only.
"""

import json
import re
import subprocess
from pathlib import Path

import pandas as pd
import pytest

from dashboard import theme
from src import evaluate, runs

ROOT = Path(__file__).resolve().parent.parent
ANSWERS = ROOT / "groundtruth"
LIVE = ROOT / "pcap" / "live"
REM = 16.0          # px per rem (Streamlit's root font size)
BUTTON_PX = 36      # width of Streamlit's collapsed-sidebar control, measured in Edge


# --------------------------------------------------------------------------
# 1. The sidebar arrow has its own margin
# --------------------------------------------------------------------------

def _rule(selector_start: str) -> str:
    m = re.search(re.escape(selector_start) + r"[^{]*\{([^}]*)\}", theme.CSS)
    assert m, selector_start
    return m.group(1)


def _rem(value: str) -> float:
    assert value.endswith("rem"), value
    return float(value[:-3]) * REM


def test_the_sidebar_arrow_is_placed_by_the_theme():
    rule = _rule('[data-testid="stSidebarCollapsedControl"]')
    assert re.search(r"left:\s*0\.5rem", rule) and re.search(r"top:\s*0\.75rem", rule)
    assert "display: none" not in rule      # it must stay: it opens the Alert sound switch


def test_page_content_starts_right_of_the_arrow():
    arrow = _rule('[data-testid="stSidebarCollapsedControl"]')
    left = _rem(re.search(r"left:\s*([\d.]+rem)", arrow).group(1))
    padding = re.search(r"padding:\s*([^;]+);", _rule('[data-testid="stMainBlockContainer"]'))
    parts = padding.group(1).split()
    assert len(parts) == 4, "the left padding must be stated on its own"
    content_left = _rem(parts[3])
    assert content_left >= left + BUTTON_PX + 8, "the arrow would touch the page content"


def test_no_chevron_character_in_the_report_cards():
    facts = {"incident_id": "INC-20261115-08", "severity": "high",
             "severity_rule": "Critical: more than one device flagged.",
             "keys": [("esp32-02", "origin")], "device": "esp32-02", "confidence": 100,
             "summary": "s", "source": "Template wording.",
             "techniques": [{"id": "T1571", "name": "Non-Standard Port", "evidence": "e"}]}
    for html in (theme.report_summary_card(facts), theme.techniques_card(facts), theme.CSS):
        assert not re.search("[‹›»❯]", html)


# --------------------------------------------------------------------------
# 2. The sessions as measured on 15 Nov
# --------------------------------------------------------------------------

def _have(*run_ids):
    return all(runs.meta_path(r).exists() and (ANSWERS / ("%s.json" % r)).exists()
               for r in run_ids)


# session: origin, trigger -> alert, alert -> CONTAINED, alert -> acknowledged, beacons
MEASURED = {
    "live_session_08": ("esp32-02", 156.7, 113.4, 10.7, 6),
    "live_session_09": ("esp32-03", 218.4, 81.7, 16.2, 7),
}


@pytest.mark.skipif(not _have(*MEASURED), reason="needs data/live_session_08..09 and answers")
@pytest.mark.parametrize("run_id", sorted(MEASURED))
def test_session_as_scored_on_15_nov(run_id):
    origin, detect_s, contained_s, ack_s, n_beacons = MEASURED[run_id]
    row = evaluate.live_timing(run_id)
    assert row["origin"] == origin and row["alert_right"]
    assert row["detect_seconds"] == pytest.approx(detect_s, abs=0.2)
    assert row["contained"] and row["contained_device"] == origin
    assert row["contained_seconds"] == pytest.approx(contained_s, abs=0.2)
    assert evaluate.session_note(run_id) == ""          # nothing went off-plan
    meta = json.loads(runs.meta_path(run_id).read_text(encoding="utf-8"))["live"]
    assert meta["acknowledged"]["after_alert_seconds"] == pytest.approx(ack_s, abs=0.1)
    assert meta["analyst"]["status"] == "ok"
    record = evaluate.evaluate_one(run_id)
    assert record[evaluate.V5_FIXED] == 1 and record["flagged"] == origin
    flows = runs.load_run(run_id).connections
    beacons = flows[flows.dport == 4444]
    assert set(beacons.src) == {origin} and len(beacons) == n_beacons
    assert set(beacons.bytes_out) == {496}
    assert beacons.t.diff().dropna().round().eq(30).all()
    assert (flows.src == "laptop-i3").sum() > 500         # laptop loop ON


# --------------------------------------------------------------------------
# 3. Why session 08 was faster
# --------------------------------------------------------------------------

def _origin_scores(run_id):
    state = json.loads((LIVE / run_id / "state.json").read_text(encoding="utf-8"))
    origin = json.loads((ANSWERS / ("%s.json" % run_id)).read_text(encoding="utf-8"))["origin"]
    flows = runs.load_run(run_id).connections
    first_beacon = flows[(flows.dport == 4444) & (flows.src == origin)].t.min()
    minute = int(first_beacon // 60)
    return state, origin, flows, first_beacon, minute


SINGLE_BEACON = ["live_session_01", "live_session_03", "live_session_05",
                 "live_session_08", "live_session_09"]


@pytest.mark.skipif(not all((LIVE / r / "state.json").exists() for r in SINGLE_BEACON)
                    or not _have(*SINGLE_BEACON), reason="needs the sessions' state.json")
def test_one_beacon_minute_is_over_the_line_only_in_session_08():
    for run_id in SINGLE_BEACON:
        state, origin, flows, first_beacon, minute = _origin_scores(run_id)
        # the first beacon came late in its minute, alone (the next is 30 s later)
        assert (minute + 1) * 60 - first_beacon < 15, run_id
        score = state["devices"][origin]["scores_by_window"][str(minute)]
        if run_id == "live_session_08":
            assert score == pytest.approx(106.25, abs=0.01)
            assert state["devices"][origin]["onset"] == minute * 60
        else:
            assert 3.0 < score < 4.0, (run_id, score)
            assert state["devices"][origin]["onset"] == (minute + 1) * 60


@pytest.mark.skipif(not _have("live_session_08", "live_session_09"), reason="needs data/")
def test_session_08_baseline_had_no_incoming_bytes():
    for run_id, flat in (("live_session_08", True), ("live_session_09", False)):
        _, origin, flows, _, _ = _origin_scores(run_id)
        baseline = flows[(flows.src == origin) & (flows.t < 720)]
        assert bool(baseline.bytes_in.max() == 0) == flat
        assert bool((baseline.dst == "broker").any()) == (not flat)


# --------------------------------------------------------------------------
# The published tables: new rows only
# --------------------------------------------------------------------------

def _at_core_locked(path: str):
    try:
        text = subprocess.run(["git", "show", "core-locked:" + path], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("needs git and the core-locked tag")
    return text.splitlines()


@pytest.mark.parametrize("name", ["table_live_sessions_per_run", "table_live_sessions_timing",
                                  "table_live_sessions_loop_on_per_run",
                                  "table_live_sessions_loop_on_timing"])
def test_published_rows_kept_and_two_sessions_added(name):
    path = "results/%s.csv" % name
    before = _at_core_locked(path)
    now = (ROOT / path).read_text(encoding="utf-8").splitlines()
    assert now[:len(before)] == before
    added = [line.split(",")[0] for line in now[len(before):]]
    assert added == ["live_session_08", "live_session_09"]


def test_summary_tables_count_all_scored_sessions():
    all_ = pd.read_csv(ROOT / "results" / "table_live_sessions.csv")
    loop_on = pd.read_csv(ROOT / "results" / "table_live_sessions_loop_on.csv")
    assert set(all_.runs) == {8} and set(loop_on.runs) == {7}
    for table in (all_, loop_on):
        v5 = table[table.method == "V5 attribution"].iloc[0]
        assert v5.top1_pct == 100.0 and v5.abstention_pct == 0.0
