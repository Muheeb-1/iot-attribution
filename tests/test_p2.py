"""
Tests for Step P2 of docs/POLISH_PLAN.md - the alert experience.

  - the tone: a WAV made in code, two quiet 880 Hz pips per 1.6 s;
  - Acknowledge: ack.json round trip (the page writes it once, atomically);
    the time it means, live and in a replay (incident.acknowledgement);
  - the engine reads it only to add the time to state.json and the report:
    a real replay with an acknowledgement gives the same verdict, alert and
    CONTAINED second as the saved session;
  - the band: to detect / to acknowledge / to contain from fixture states,
    the ring only while unacknowledged;
  - the page (AppTest): unacknowledged incident = ring + button + tone;
    pressing the button writes ack.json and stops all three; the sound
    switch turns only the tone off.
"""

import copy
import io
import json
import re
import time
import wave
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard import live_page, theme
from src import capture, incident, live, runs

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "live_states"


def fixture(name):
    return json.loads((FIXTURES / ("%s.json" % name)).read_text(encoding="utf-8"))


def fresh(state):
    state = copy.deepcopy(state)
    state["updated_epoch"] = time.time()
    return state


def place(live_dir, state):
    folder = Path(live_dir) / state["session"]
    folder.mkdir(parents=True, exist_ok=True)
    live.write_state(folder / live.STATE_FILE, state)
    return folder


# --------------------------------------------------------------------------
# The tone
# --------------------------------------------------------------------------

def _samples(data):
    with wave.open(io.BytesIO(data)) as w:
        assert (w.getnchannels(), w.getsampwidth()) == (1, 2)
        rate = w.getframerate()
        raw = w.readframes(w.getnframes())
    values = [int.from_bytes(raw[i:i + 2], "little", signed=True) for i in range(0, len(raw), 2)]
    return rate, values


def test_the_tone_is_two_quiet_880_hz_pips_every_1_6_seconds():
    rate, values = _samples(live_page.alert_tone_wav())
    assert len(values) / rate == pytest.approx(1.6, abs=0.001)
    assert max(abs(v) for v in values) <= 0.21 * 32767          # quiet: a fifth of full scale
    # sound runs: two separate pips, each about 0.15 s long
    loud = [abs(v) > 300 for v in values]
    runs_ = []
    start = None
    for i, on in enumerate(loud + [False]):
        if on and start is None:
            start = i
        # a pip has many zero crossings; join gaps shorter than 5 ms
        if not on and start is not None and not any(loud[i:i + int(0.005 * rate)]):
            runs_.append((start / rate, i / rate))
            start = None
    assert len(runs_) == 2, runs_
    for begin, end in runs_:
        assert end - begin == pytest.approx(0.15, abs=0.02)
    # 880 Hz: zero crossings in the first pip
    first = values[int(runs_[0][0] * rate):int(runs_[0][1] * rate)]
    crossings = sum(1 for a, b in zip(first, first[1:]) if (a < 0) != (b < 0))
    assert crossings / (len(first) / rate) / 2 == pytest.approx(880, rel=0.05)


def test_the_tone_is_the_same_bytes_every_refresh():
    """Same bytes -> same media URL -> Streamlit keeps the player (it keeps playing)."""
    assert live_page.alert_tone_wav() is live_page.alert_tone_wav()


# --------------------------------------------------------------------------
# ack.json round trip
# --------------------------------------------------------------------------

def test_acknowledge_writes_ack_json_once_and_whole(tmp_path):
    assert live_page.read_ack_epoch(tmp_path, "s1") is None
    stored = live_page.write_ack(tmp_path, "s1", now=1_800_000_123.5)
    path = tmp_path / "s1" / live.ACK_FILE
    assert json.loads(path.read_text(encoding="utf-8")) == {"acknowledged_epoch": 1_800_000_123.5}
    assert stored == live_page.read_ack_epoch(tmp_path, "s1") == 1_800_000_123.5
    # a second press keeps the first time
    assert live_page.write_ack(tmp_path, "s1", now=1_800_000_999.0) == 1_800_000_123.5
    assert not list((tmp_path / "s1").glob("*.part"))


def test_an_unreadable_ack_file_is_no_acknowledgement(tmp_path):
    (tmp_path / "s1").mkdir()
    (tmp_path / "s1" / live.ACK_FILE).write_text("{half", encoding="utf-8")
    assert live_page.read_ack_epoch(tmp_path, "s1") is None


# --------------------------------------------------------------------------
# What the click means (incident.acknowledgement)
# --------------------------------------------------------------------------

ALERT = {"raised_epoch": 1_800_000_960.0, "raised_seconds": 960.0}


def test_live_the_click_time_is_the_capture_time():
    ack = incident.acknowledgement(1_800_000_974.0, ALERT, alert_wall_epoch=None,
                                   replaying=False, start_epoch=1_800_000_000.0)
    assert ack["acknowledged_epoch"] == 1_800_000_974.0
    assert ack["after_alert_seconds"] == 14.0 and ack["acknowledged_seconds"] == 974.0


def test_in_a_replay_the_real_reaction_time_lands_on_the_recordings_clock():
    """Recording from 13 Nov, replayed today: the alert appeared on screen at
    real time W; the operator clicked 14 s later on today's clock."""
    wall = 1_900_000_000.0
    ack = incident.acknowledgement(wall + 14.0, ALERT, alert_wall_epoch=wall, replaying=True,
                                   start_epoch=1_800_000_000.0)
    assert ack["acknowledged_epoch"] == ALERT["raised_epoch"] + 14.0
    assert ack["after_alert_seconds"] == 14.0
    assert ack["clicked_epoch"] == wall + 14.0


def test_no_click_or_no_alert_means_no_acknowledgement():
    assert incident.acknowledgement(None, ALERT) is None
    assert incident.acknowledgement(1_800_000_974.0, None) is None
    assert incident.acknowledgement(1_800_000_974.0, {}) is None


def test_a_click_cannot_come_before_the_alert_it_answers():
    ack = incident.acknowledgement(1_800_000_950.0, ALERT)
    assert ack["after_alert_seconds"] == 0.0


def test_the_report_gains_one_line_and_one_field():
    report = fixture("incident")["incident"]
    ack = incident.acknowledgement(ALERT["raised_epoch"] + 14, ALERT)
    with_ack = incident.with_acknowledgement(report, ack)
    assert with_ack["acknowledged"] == ack
    assert set(with_ack) - set(report) == {"acknowledged"}            # gains, changes nothing
    assert all(with_ack[k] == report[k] for k in report)
    line = incident.acknowledged_line(ack)
    assert line.endswith("14 s after the alert.")
    assert line in incident.render_text(with_ack)
    assert line in incident.render_html(with_ack)
    assert line not in incident.render_text(report)
    assert incident.with_acknowledgement(report, None) is report


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------

def _engine(tmp_path):
    folder = tmp_path / "live" / "s1"
    folder.mkdir(parents=True)
    session = live.LiveSession(folder, baseline_seconds=480, session="s1",
                               data_dir=tmp_path / "data", reader=lambda p: [])
    session.capture_start_epoch = 1_800_000_000.0
    return session


def test_the_engine_ignores_an_acknowledgement_before_any_alert(tmp_path):
    s = _engine(tmp_path)
    live_page.write_ack(tmp_path / "live", "s1", now=1_800_000_500.0)
    assert s._read_acknowledgement() is False and s.acknowledged is None


def test_the_engine_reads_the_acknowledgement_once_and_puts_it_in_the_state(tmp_path):
    s = _engine(tmp_path)
    s.first_alert = dict(ALERT)
    s.alert_wall_epoch = 1_900_000_000.0
    live_page.write_ack(tmp_path / "live", "s1", now=1_800_000_974.0)
    assert s._read_acknowledgement() is True
    assert s.acknowledged["acknowledged_epoch"] == 1_800_000_974.0
    assert s._read_acknowledgement() is False                         # once
    state = s.state()
    assert state["acknowledged"] == s.acknowledged
    assert state["first_alert_wall_epoch"] == 1_900_000_000.0 and state["replaying"] is False


def test_a_broken_ack_file_is_ignored_and_never_counted_as_a_capture_problem(tmp_path):
    s = _engine(tmp_path)
    s.first_alert = dict(ALERT)
    (s.folder / live.ACK_FILE).write_text("not json", encoding="utf-8")
    assert s._read_acknowledgement() is False
    assert s.problems == []


def test_a_reused_session_folder_loses_its_old_acknowledgement(tmp_path):
    folder = tmp_path / "s1"
    folder.mkdir()
    (folder / live.STATE_FILE).write_text("{}", encoding="utf-8")
    (folder / live.ACK_FILE).write_text('{"acknowledged_epoch": 1}', encoding="utf-8")
    live._prepare_folder(folder, force=True)
    assert not (folder / live.ACK_FILE).exists()


def _tshark():
    try:
        return capture.find_tshark()
    except FileNotFoundError:
        return None


SESSION = "live_session_07"
needs_07 = pytest.mark.skipif(
    not ((ROOT / "pcap" / "live" / ("%s.pcapng" % SESSION)).exists()
         and runs.meta_path(SESSION).exists() and _tshark()),
    reason="needs pcap/live/live_session_07.pcapng, its saved meta and tshark")


@needs_07
def test_a_replay_with_an_acknowledgement_changes_nothing_but_the_acknowledgement(tmp_path):
    """
    Replay live_session_07 through the live path and press Acknowledge (write
    ack.json) as soon as the alert is on the page. The verdict, the alert and
    the CONTAINED second are the saved session's; the time appears in
    state.json, the report and the report file.
    """
    folder = tmp_path / SESSION
    pressed = []

    def operator(session, state):
        if state["phase"] == live.INCIDENT and not pressed:
            pressed.append(live_page.write_ack(tmp_path, SESSION))

    engine = live.replay(ROOT / "pcap" / "live" / ("%s.pcapng" % SESSION), SESSION,
                         folder=folder, data_dir=tmp_path / "data", speed=0, save=False,
                         quiet=True, on_cycle=operator)
    meta = json.loads(runs.meta_path(SESSION).read_text(encoding="utf-8"))
    saved = meta["live"]
    assert pressed, "the replay never showed an incident"
    assert engine.result.named == "esp32-03" and engine.result.confidence_percent == 100
    assert engine.first_alert["closed_seconds"] == saved["first_alert"]["closed_seconds"]
    assert round(engine.first_alert["raised_seconds"]) == round(saved["first_alert"]["raised_seconds"])
    assert engine.containment["contained_seconds"] == pytest.approx(
        saved["containment"]["contained_seconds"], abs=1e-6)
    assert [p["phase"] for p in engine.phase_log] == [
        live.WAITING, live.LEARNING, live.MONITORING, live.INCIDENT, live.CONTAINED, live.STOPPED]

    ack = engine.acknowledged
    assert ack is not None and engine.replaying
    assert 0.0 <= ack["after_alert_seconds"] < 30.0      # pressed at once (speed 0: real time)
    final = json.loads((folder / live.STATE_FILE).read_text(encoding="utf-8"))
    assert final["acknowledged"]["acknowledged_epoch"] == pytest.approx(ack["acknowledged_epoch"])
    assert final["incident"]["acknowledged"]["acknowledged_epoch"] == pytest.approx(
        ack["acknowledged_epoch"])
    report_file = Path(final["report_file"])
    assert "Acknowledged by the operator at" in report_file.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The band's figures and ring
# --------------------------------------------------------------------------

def test_an_unacknowledged_incident_rings_and_shows_to_detect_only():
    state = fixture("incident")
    b = theme.band_content(state)
    detect_s = state["incident"]["when"]["time_to_detect_seconds"]
    assert b["kpis"] == [(theme.duration_text(detect_s), "to detect"),
                         ("--", "to acknowledge"), ("--", "to contain")]
    assert b["ringing"] is True and b["acked"] is None
    band = theme.status_band(state, ack_button=True)
    assert "ringing" in band and "has-ack" in band and "Acknowledged" not in band


def test_an_acknowledged_incident_stops_ringing_and_says_when():
    state = fixture("incident")
    raised = state["first_alert"]["raised_epoch"]
    ack = incident.acknowledgement(raised + 14, state["first_alert"])
    b = theme.band_content(state, ack)
    assert b["kpis"][1] == ("14 s", "to acknowledge")
    assert b["ringing"] is False and b["acked"] == theme.wall(raised + 14)
    band = theme.status_band(state, ack)
    assert "ringing" not in band and "Acknowledged %s" % theme.wall(raised + 14) in band
    assert ("Acknowledged" in [w for _, w, _ in theme.timeline_points(state, ack)])


def test_contained_and_stopped_show_to_contain_and_never_ring():
    contained = fixture("contained")
    c = contained["containment"]
    b = theme.band_content(contained)
    expected = theme.duration_text(c["contained_epoch"] - contained["first_alert"]["raised_epoch"])
    assert b["kpis"][2] == (expected, "to contain") and b["ringing"] is False
    stopped = theme.band_content(fixture("stopped"))
    assert [k for _, k in stopped["kpis"]] == ["to detect", "to acknowledge", "to contain"]
    assert stopped["ringing"] is False


def test_before_an_incident_the_band_keeps_devices_packets_incidents():
    b = theme.band_content(fixture("monitoring"))
    assert [k for _, k in b["kpis"]] == ["devices", "packets", "incidents"]
    assert b["ringing"] is False


# --------------------------------------------------------------------------
# The page (AppTest)
# --------------------------------------------------------------------------

def _page(live_dir, session, sound):
    import streamlit as st
    from dashboard import live_page as page
    st.session_state.setdefault("alert-sound", sound)
    page.render_page(live_dir=live_dir, session=session)


def render(live_dir, session, sound=True):
    at = AppTest.from_function(_page, kwargs={"live_dir": str(live_dir), "session": session,
                                              "sound": sound}, default_timeout=30)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    return at


def band_html(at):
    return next(e.proto.body for e in at.get("html") if 'class="iot band' in e.proto.body)


def incident_state():
    state = fresh(fixture("incident"))
    state.update(replaying=True, first_alert_wall_epoch=time.time() - 14)
    return state


def test_an_unacknowledged_incident_has_the_ring_the_button_and_the_tone(tmp_path):
    state = incident_state()
    place(tmp_path, state)
    at = render(tmp_path, state["session"])
    assert "ringing" in band_html(at)
    assert [b.label for b in at.button] == ["Acknowledge"]
    assert len(at.get("audio")) == 1


def test_pressing_acknowledge_writes_ack_json_and_stops_ring_button_and_tone(tmp_path):
    state = incident_state()
    place(tmp_path, state)
    at = render(tmp_path, state["session"])
    at.button(key="ack-button").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert (tmp_path / state["session"] / live.ACK_FILE).exists()
    band = band_html(at)
    assert "ringing" not in band and "Acknowledged " in band
    assert not [b for b in at.button if b.label == "Acknowledge"]
    assert len(at.get("audio")) == 0
    # replay: about the 14 s the operator really took, not days on the recording's clock
    seconds = re.search(r'<div class="v">([^<]+)</div><div class="k">to acknowledge', band).group(1)
    assert seconds.endswith(" s") and "min" not in seconds


def test_the_sound_switch_turns_off_only_the_tone(tmp_path):
    state = incident_state()
    place(tmp_path, state)
    at = render(tmp_path, state["session"], sound=False)
    assert len(at.get("audio")) == 0
    assert [b.label for b in at.button] == ["Acknowledge"] and "ringing" in band_html(at)
    assert "Alert sound" in [t.label for t in at.sidebar.toggle]


def test_an_acknowledgement_already_in_the_state_needs_no_button(tmp_path):
    state = incident_state()
    state["acknowledged"] = incident.acknowledgement(
        state["first_alert"]["raised_epoch"] + 20, state["first_alert"])
    place(tmp_path, state)
    at = render(tmp_path, state["session"])
    assert not at.button and not at.get("audio")
    assert "20 s" in band_html(at)


@pytest.mark.parametrize("name", ["monitoring", "contained", "stopped"])
def test_no_alarm_outside_an_unacknowledged_incident(tmp_path, name):
    state = fresh(fixture(name))
    place(tmp_path, state)
    at = render(tmp_path, state["session"])
    assert not at.button and not at.get("audio")
    assert "ringing" not in band_html(at)
