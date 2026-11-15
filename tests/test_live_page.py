"""
Tests for dashboard/live_page.py and the dashboard changes of Step 17
(rebuilt as the console in Step P1 of docs/POLISH_PLAN.md).

The fixtures in tests/fixtures/live_states/ are real state.json files: one per
phase, recorded by replaying pcap/segments/live_batch_01.pcapng through the
live engine (session renamed to fixture_session). They are committed, so the
page tests run on a fresh clone without any capture. Re-recorded in Step 19
(they now carry the incident report); contained.json comes from
pcap/live/rehearsal_02.pcapng with esp32-03's packets removed 275 s after the
trigger, as if its power had been pulled.

Three kinds of test:
- plain functions: the clock, session finding, the notes under the band (the
  band, lanes and cards themselves are dashboard/theme.py, tested in
  tests/test_theme.py since Step P1);
- faithfulness: the objects the page rebuilds from state.json draw exactly
  what the engine's own objects draw (needs pcap/segments/, skips without);
- rendering: Streamlit's AppTest draws every phase (and a stale engine) with
  zero exceptions, and the band says what the theme says it should.
"""

import copy
import html
import json
import os
import re
import time
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard import app, live_page, theme
from src import live

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "live_states"
SEGMENTS = ROOT / "pcap" / "segments"
PHASE_FILES = ["waiting", "learning", "monitoring", "incident", "incident_later", "contained",
               "stopped"]


def fixture(name):
    return json.loads((FIXTURES / ("%s.json" % name)).read_text(encoding="utf-8"))


def fresh(state):
    """A copy that looks just written, so it is not stale."""
    state = copy.deepcopy(state)
    state["updated_epoch"] = time.time()
    return state


def place(live_dir, state, session=None):
    session = session or state["session"]
    folder = Path(live_dir) / session
    folder.mkdir(parents=True, exist_ok=True)
    live.write_state(folder / live.STATE_FILE, state)
    return folder


# --------------------------------------------------------------------------
# The fixtures themselves
# --------------------------------------------------------------------------

def test_there_is_a_fixture_for_every_phase_a_session_passes_through():
    phases = {fixture(n)["phase"] for n in PHASE_FILES}
    assert phases == set(live.PHASES)


def test_fixtures_carry_what_the_page_needs_to_rebuild_the_ranking():
    state = fixture("incident")
    for key in ("scores", "story_ranking", "indicator_bonus", "explanations",
                "onset_windows", "confidence"):
        assert key in state, key
    assert state["named"] == "esp32-02"


# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------

def test_capture_seconds_are_shown_as_wall_clock():
    state = {"capture_start_epoch": 1_800_000_000.0}
    assert live_page.wall_at(state, 960) == live_page.wall(1_800_000_960.0)
    assert live_page.capture_clock_to_wall(state, "00:16:00") == live_page.wall(1_800_000_960.0)
    assert live_page.capture_clock_to_wall(state, "soon") == "soon"
    assert live_page.wall(None) == "-" and live_page.wall_at({}, 5) == "-"


@pytest.mark.parametrize("seconds,text", [(None, "-"), (0, "0 s"), (59.6, "1 min 00 s"),
                                          (45, "45 s"), (230, "3 min 50 s"), (-3, "0 s")])
def test_durations_read_naturally(seconds, text):
    assert live_page.duration_text(seconds) == text


def test_a_running_session_goes_stale_and_a_stopped_one_never_does():
    state = {"phase": live.MONITORING, "updated_epoch": 1000.0}
    assert not live_page.is_stale(state, now=1000.0 + live_page.STALE_SECONDS - 1)
    assert live_page.is_stale(state, now=1000.0 + live_page.STALE_SECONDS + 1)
    assert not live_page.is_stale({"phase": live.STOPPED, "updated_epoch": 0.0}, now=1e9)


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------

def test_sessions_are_listed_newest_first_and_need_a_state_file(tmp_path):
    place(tmp_path, fresh(fixture("learning")), "older")
    time.sleep(0.05)
    place(tmp_path, fresh(fixture("learning")), "newer")
    (tmp_path / "no_state").mkdir()
    os.utime(tmp_path / "older" / live.STATE_FILE, (time.time() - 100, time.time() - 100))
    assert live_page.list_sessions(tmp_path) == ["newer", "older"]
    assert live_page.list_sessions(tmp_path / "missing") == []


def test_an_unreadable_state_is_none_not_a_crash(tmp_path):
    assert live_page.read_state(tmp_path, "nothing") is None
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / live.STATE_FILE).write_text("{not json")
    assert live_page.read_state(tmp_path, "bad") is None


def test_the_suggested_session_name_is_unused(tmp_path):
    live_dir, data_dir = tmp_path / "live", tmp_path / "data"
    assert live_page.next_session_name(live_dir, data_dir) == "live_session_01"
    (live_dir / "live_session_01").mkdir(parents=True)
    data_dir.mkdir()
    (data_dir / "live_session_02.parquet").write_bytes(b"")
    assert live_page.next_session_name(live_dir, data_dir) == "live_session_03"


# --------------------------------------------------------------------------
# The baseline countdown and the notes under the band
# --------------------------------------------------------------------------

def test_the_baseline_progress_counts_minutes_and_says_when_it_ends():
    state = fixture("learning")
    p = live_page.baseline_progress(state)
    assert p["total"] == 12 and 0 < p["done"] < 12
    assert p["ends_at"] == theme.wall(theme.baseline_end_epoch(state))
    assert p["ends_at"] in theme.band_content(state)["sub"]


def test_a_stale_engine_gets_a_note_and_a_stopped_session_says_where_it_was_saved():
    state = fixture("monitoring")
    state["updated_epoch"] = time.time() - 120
    notes = live_page.notes_under_band(state)
    assert notes[0][1] == "bad" and "has not updated" in notes[0][0]
    stopped = dict(fixture("stopped"), saved_run="live_session_99")
    saved = [text for text, _ in live_page.notes_under_band(stopped)]
    assert any("data/live_session_99.parquet" in t for t in saved)


def test_the_notes_escape_what_comes_from_data():
    state = fixture("monitoring")
    state.update(session="<b>x</b>", updated_epoch=time.time() - 120)
    text = live_page.notes_under_band(state)[0][0]
    assert "<b>x</b>" not in text and "&lt;b&gt;x&lt;/b&gt;" in text


# --------------------------------------------------------------------------
# Verdict changes
# --------------------------------------------------------------------------

def test_a_change_of_verdict_is_announced_with_its_time():
    state = fixture("incident")
    first = dict(state["verdict_changes"][0])
    later = dict(first, epoch=first["epoch"] + 60, confidence_percent=40,
                 onsets=dict(first["onsets"], **{"laptop-i3": 900.0}))
    state["verdict_changes"] = [first, later]
    lines = live_page.verdict_change_lines(state)
    assert len(lines) == 1
    assert lines[0].startswith("updated %s" % live_page.wall(later["epoch"]))
    assert "100% -> 40%" in lines[0] and "laptop-i3 also went abnormal" in lines[0]
    assert live_page.verdict_change_lines(fixture("incident")) == []


# --------------------------------------------------------------------------
# The rebuilt objects and the figures
# --------------------------------------------------------------------------

def test_the_rebuilt_objects_hold_exactly_what_the_engine_wrote():
    state = fixture("incident")
    run, detection, result = live_page.objects_from_state(state)
    assert result.ranking == state["ranking"] and result.named == state["named"]
    assert result.confidence_percent == state["confidence_percent"]
    assert result.edge_evidence() == state["edges"]
    assert {d: result.explain_rank(d) for d in result.ranking} == state["explanations"]
    assert detection.onsets == state["onsets"]
    assert run.device_names == list(state["devices"])


def test_the_replay_page_drawings_accept_the_rebuilt_objects():
    state = fixture("incident")
    run, detection, result = live_page.objects_from_state(state)
    clock = lambda s: live_page.wall_at(state, s)  # noqa: E731
    rows = app.ranking_rows(result, detection, clock=clock)
    assert [r["device"] for r in rows] == state["ranking"]
    assert rows[0]["onset"] == live_page.wall(state["devices"]["esp32-02"]["onset_epoch"])
    figure = app.network_figure(run, detection, result, clock=clock)
    drawn = set()
    for trace in figure.data:
        if trace.mode and "markers" in trace.mode and trace.text:
            drawn.update(trace.text)
    assert drawn == set(state["devices"])


def test_the_replay_page_still_shows_capture_time_by_default():
    state = fixture("incident")
    _, detection, result = live_page.objects_from_state(state)
    rows = app.ranking_rows(result, detection)
    assert rows[0]["onset"] == "00:13:00"


needs_segments = pytest.mark.skipif(not (SEGMENTS / "live_batch_01.pcapng").exists(),
                                    reason="needs pcap/segments/ (gitignored raw captures)")


@needs_segments
def test_the_page_draws_exactly_what_the_engine_concluded(tmp_path):
    """At every cycle of a real replay with a verdict, the rebuilt objects give
    the same suspect rows and the same network picture as the engine's own."""
    checked = []

    def on_cycle(session, state):
        if not state["ranking"]:
            return
        state = json.loads(json.dumps(live.json_safe(state)))
        run, detection, result = live_page.objects_from_state(state)
        want = app.ranking_rows(session.result, session.detection)
        assert app.ranking_rows(result, detection) == want
        mine = app.network_figure(run, detection, result).to_dict()["data"]
        theirs = app.network_figure(session.run, session.detection, session.result)
        assert mine == theirs.to_dict()["data"]
        checked.append(state["phase"])

    live.replay(SEGMENTS / "live_batch_01.pcapng", "faithful", folder=tmp_path / "f",
                speed=0, data_dir=tmp_path / "data", save=False, quiet=True,
                on_cycle=on_cycle)
    assert live.INCIDENT in checked and live.STOPPED in checked


# --------------------------------------------------------------------------
# The reveal tick
# --------------------------------------------------------------------------

def test_the_answer_is_not_read_before_the_session_has_stopped(monkeypatch):
    def must_not_read(run_id):
        raise AssertionError("the answer file was read during a running session")

    monkeypatch.setattr(app, "load_answer_for_display", must_not_read)
    live_page.draw_reveal(fixture("incident"))          # no error = not read
    with pytest.raises(AssertionError):
        live_page.draw_reveal(fixture("stopped"))


# --------------------------------------------------------------------------
# Rendering: every phase, zero exceptions
# --------------------------------------------------------------------------

def _page(live_dir, session):
    from dashboard import live_page as page
    page.render_page(live_dir=live_dir, session=session)


def render(live_dir, session=None):
    at = AppTest.from_function(_page, kwargs={"live_dir": str(live_dir), "session": session},
                               default_timeout=30)
    at.run()
    return at


def html_parts(at):
    """The st.html blocks the page drew (the top bar, band, lanes, cards)."""
    return [e.proto.body for e in at.get("html")]


def _words(fragment):
    return html.unescape(re.sub(r"<[^>]+>", " ", fragment))


def texts(at):
    """Everything a person can read on the page, st.html included (tags removed),
    with runs of white space folded to one space."""
    parts = []
    for kind in ("error", "warning", "info", "success", "markdown", "caption", "title",
                 "subheader"):
        parts += [str(e.value) for e in getattr(at, kind)]
    parts += [_words(body) for body in html_parts(at)]
    return re.sub(r"\s+", " ", "\n".join(parts))


def band_words(state):
    """(headline, state word) that theme.band_content gives this state, as plain words."""
    b = theme.band_content(state)
    return re.sub(r"\s+", " ", _words(b["headline"])).strip(), b["state"]


@pytest.mark.parametrize("name", PHASE_FILES)
def test_every_phase_renders_without_an_exception(tmp_path, name):
    state = fresh(fixture(name))
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    shown = texts(at)
    headline, word = band_words(state)
    assert headline in shown and word in shown
    assert "has not updated" not in shown
    # the CSS is on the page, and the lab check is tucked away at the bottom
    assert any("--alert: #FF5D6C" in body for body in html_parts(at))
    assert "Lab validation" in [e.label for e in at.expander]


def test_the_incident_page_shows_the_verdict_network_suspects_and_brief(tmp_path):
    state = fresh(fixture("incident"))
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    shown = texts(at)
    assert "The attack started on esp32-02" in shown
    assert "How it was found" in shown and "Every device, minute by minute" in shown
    assert "Attack origin" in shown
    assert "Suspects" in [s.value for s in at.subheader]
    # Step 19: the complete incident report replaces the short brief.
    assert "Incident report" in [s.value for s in at.subheader]
    assert "nothing is done automatically" in shown
    assert "spread" not in shown


def test_a_state_without_the_report_still_shows_the_brief(tmp_path):
    """A state.json from before Step 19 (or a failed report) falls back to the brief."""
    state = fresh(fixture("incident"))
    state.pop("incident")
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception
    assert "Incident brief" in [s.value for s in at.subheader]


def test_an_abstaining_incident_renders(tmp_path):
    state = fresh(fixture("incident"))
    state.update(abstained=True, named=None, shortlist=state["ranking"][:3])
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception
    assert "not certain" in texts(at)


def test_a_silent_engine_is_pointed_out(tmp_path):
    state = fixture("monitoring")
    state["updated_epoch"] = time.time() - 120
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception
    assert "has not updated" in texts(at)
    assert "Engine not updating" in texts(at)


def test_a_session_whose_state_is_not_written_yet_says_it_is_starting(tmp_path):
    (tmp_path / "brand_new").mkdir()
    at = render(tmp_path, session="brand_new")
    assert not at.exception
    assert "Starting session brand_new" in texts(at)


def test_with_no_session_at_all_the_page_shows_how_to_start_one(tmp_path):
    at = render(tmp_path / "empty")
    assert not at.exception
    assert "Waiting for a session" in texts(at)
    # The exact NN is whichever live_session_ is free in the real data/ folder
    # (once live_session_01 has been recorded it is live_session_02, and so on);
    # next_session_name's numbering is pinned hermetically in its own test above.
    # Here we only check that the admin capture command is shown, naming a session.
    assert "python -m src.live_capture --session live_session_" in at.code[0].value


def test_following_the_newest_session_picks_it_up(tmp_path):
    place(tmp_path, fresh(fixture("learning")), "old_one")
    time.sleep(0.05)
    place(tmp_path, fresh(fixture("monitoring")), "new_one")
    os.utime(tmp_path / "old_one" / live.STATE_FILE, (time.time() - 100, time.time() - 100))
    at = render(tmp_path)
    assert not at.exception
    assert "Monitoring 3 devices" in texts(at)            # new_one, not old_one (learning)
    assert "Learning normal behaviour" not in texts(at)


def test_a_replay_session_is_labelled_as_a_replay(tmp_path):
    state = fresh(fixture("incident"))
    folder = place(tmp_path, state)
    (folder / live.REPLAY_SOURCE).mkdir()
    at = render(tmp_path, session=state["session"])
    assert "Replay of a recorded capture" in texts(at)


def test_the_whole_dashboard_opens_on_the_live_monitor(tmp_path, monkeypatch):
    """app.py opens on the Live monitor (Step P1b; it opened on Past sessions
    in P1), in the console's theme. With no session it shows how to start one."""
    monkeypatch.setenv("IOT_LIVE_DIR", str(tmp_path / "empty"))
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=120)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert not [t.value for t in at.title]                 # Past sessions has a title; live has none
    bodies = html_parts(at)
    assert any("--alert: #FF5D6C" in body for body in bodies)
    assert any('<a class="on" href="./"' in body for body in bodies)
    assert "Waiting for a session" in texts(at)


def test_the_past_sessions_page_still_opens_on_its_own():
    """Rung 3 of the fallback ladder: the Past sessions page, in the theme."""
    at = AppTest.from_function(_past_page, default_timeout=180)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value == "Past sessions"
    assert at.radio[0].value == "template"
    assert any('<a class="on" href="./replay"' in body for body in html_parts(at))


def _past_page():
    from dashboard import app as dashboard_app
    dashboard_app.replay_page()


def test_the_lab_check_lives_in_lab_validation_and_waits_for_stop(tmp_path, monkeypatch):
    """"Compare with the recorded answer" sits in the collapsed Lab validation
    section; ticking it during a running session does NOT open the answer file."""
    def must_not_read(run_id):
        raise AssertionError("the answer file was read during a running session")

    monkeypatch.setattr(app, "load_answer_for_display", must_not_read)
    state = fresh(fixture("incident"))
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    box = next(c for c in at.checkbox if c.label == "Compare with the recorded answer")
    box.check().run()
    assert not at.exception, [e.value for e in at.exception]
    assert "Available once the session has stopped" in texts(at)


def test_the_old_lab_wording_is_gone_from_the_live_page():
    source = (ROOT / "dashboard" / "live_page.py").read_text(encoding="utf-8")
    source += (ROOT / "dashboard" / "theme.py").read_text(encoding="utf-8")
    for old in ("safe to launch", "do not attack yet", "Reveal the true answer",
                "Replay a saved capture"):
        assert old not in source, old


def test_the_stale_model_name_is_gone_and_the_writers_are_named():
    source = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
    assert "qwen" not in source.lower()
    assert set(app.WRITERS) == {"template", "local", "cloud"}
    from src import report
    assert report.DEFAULT_MODEL["local"] in app.WRITERS["local"]
    assert report.DEFAULT_MODEL["cloud"] in app.WRITERS["cloud"]


def test_the_live_page_never_runs_the_method_itself():
    """It draws state.json; detection and attribution are the engine's job."""
    import ast
    tree = ast.parse((ROOT / "dashboard" / "live_page.py").read_text(encoding="utf-8"))
    called = {getattr(n.func, "attr", None) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    for forbidden in ("detect_run", "attribute_run", "build_features", "build_flows",
                      "read_packets", "detect", "attribute"):
        assert forbidden not in called, forbidden
