"""
Tests for dashboard/theme.py (Step P1 of docs/POLISH_PLAN.md).

theme.py turns the engine's state.json into HTML strings. These tests run its
pure functions on the committed phase fixtures (tests/fixtures/live_states/,
real state.json files - see tests/test_live_page.py) and check three things:

- the WORDS: each phase says what the plan's wording table says
  ("Learning normal behaviour. Minute 7 of 12.", "Monitoring 3 devices",
  "Watching esp32-03. 2 of 3 minutes in a row...", "The attack started on");
- the LANES: one bar per closed minute on one shared scale, at least 20 slots,
  at most the newest 40, tall bars capped with the real score in the tooltip,
  over-the-line bars in the alert colour only after the baseline;
- SAFETY: a device name full of HTML comes out escaped everywhere.

Nothing here decides anything: every value comes from the fixture.
"""

import copy
import html
import json
import re
from pathlib import Path

import pytest

from dashboard import theme
from src import live

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "live_states"


def fixture(name):
    return json.loads((FIXTURES / ("%s.json" % name)).read_text(encoding="utf-8"))


def plain(fragment: str) -> str:
    """HTML -> the words a person reads."""
    return html.unescape(re.sub(r"<[^>]+>", "", fragment))


# --------------------------------------------------------------------------
# The status band: one class, word and icon per phase
# --------------------------------------------------------------------------

def test_learning_says_minute_n_of_12_and_when_monitoring_starts():
    state = fixture("learning")
    b = theme.band_content(state)
    assert b["cls"] == "learn" and b["state"] == "Learning"
    assert b["headline"] == "Learning normal behaviour"
    done = state["closed_windows"]
    assert "Minute %d of 12" % (done + 1) in plain(b["sub"])
    assert "Monitoring starts at %s" % theme.wall(theme.baseline_end_epoch(state)) in plain(b["sub"])
    assert b["progress"] == pytest.approx(done / 12)
    assert "do not attack" not in plain(theme.status_band(state)).lower()


def test_monitoring_names_the_device_count_and_the_baseline_time():
    state = fixture("monitoring")
    b = theme.band_content(state)
    assert b["cls"] == "ok" and b["headline"] == "Monitoring 3 devices"
    assert plain(b["sub"]) == ("Baseline established at %s. No device is over the line."
                               % theme.wall(theme.baseline_end_epoch(state)))
    assert "safe to launch" not in plain(theme.status_band(state))


def test_one_device_part_way_to_an_alert_is_watched_in_amber_not_accused():
    state = fixture("monitoring")
    state["devices"]["esp32-03"]["strikes"] = 2
    b = theme.band_content(state)
    assert b["cls"] == "watch" and b["state"] == "Watching"
    assert plain(b["headline"]) == "Watching esp32-03"
    assert plain(b["sub"]) == "2 of 3 minutes in a row over the line. One more raises an incident."
    assert "attack" not in plain(theme.status_band(state)).lower()


def test_two_devices_part_way_are_both_listed_most_strikes_first():
    state = fixture("monitoring")
    state["devices"]["esp32-03"]["strikes"] = 1
    state["devices"]["laptop-i3"]["strikes"] = 2
    b = theme.band_content(state)
    assert plain(b["headline"]) == "Watching 2 devices"
    assert plain(b["sub"]).index("laptop-i3") < plain(b["sub"]).index("esp32-03")


def test_an_incident_is_the_alert_colour_and_names_the_device_with_its_times():
    state = fixture("incident")
    b = theme.band_content(state)
    assert b["cls"] == "alert" and b["icon"] == "alert" and b["state"] == "Incident"
    assert plain(b["headline"]) == "The attack started on esp32-02"
    sub = plain(b["sub"])
    assert "Confidence 100%" in sub and "No other device behaved abnormally" in sub
    assert theme.wall(state["first_alert"]["raised_epoch"]) in sub


def test_the_severity_word_appears_only_once_the_engine_reports_one():
    state = fixture("incident")
    assert theme.band_content(state)["state"] == "Incident"
    state["incident"]["severity"] = "high"                  # the field Step P3 adds
    assert theme.band_content(state)["state"] == "Incident, severity high"


def test_an_abstention_is_amber_and_names_nobody():
    state = fixture("incident")
    state.update(abstained=True, named=None, shortlist=["esp32-02", "laptop-i3", "esp32-03"])
    b = theme.band_content(state)
    assert b["cls"] == "watch" and "not certain" in b["headline"]
    assert "esp32-02, laptop-i3, esp32-03" in plain(b["sub"])
    assert "started on" not in plain(b["headline"])


def test_contained_says_when_and_which_destination_went_quiet():
    state = fixture("contained")
    b = theme.band_content(state)
    c = state["containment"]
    assert b["cls"] == "ok" and b["state"] == "Contained"
    assert b["headline"] == "Contained at %s" % theme.wall(c["contained_epoch"])
    assert plain(b["sub"]).startswith(
        "esp32-03 has made no connection to 192.168.0.200:4444 for 90 seconds.")


def test_after_stop_the_band_says_the_verdict_is_final():
    b = theme.band_content(fixture("stopped"))
    assert b["state"] == "Session closed, final verdict"
    assert "Final verdict from the whole capture" in plain(b["sub"])


def test_a_quiet_session_that_stops_says_no_incident():
    state = fixture("monitoring")
    state["phase"] = live.STOPPED
    b = theme.band_content(state)
    assert b["headline"] == "No incident" and b["cls"] == "ok"


@pytest.mark.parametrize("name", ["waiting", "learning", "monitoring", "incident",
                                  "incident_later", "contained", "stopped"])
def test_every_band_has_a_word_and_an_icon_never_colour_alone(name):
    band = theme.status_band(fixture(name))
    found = re.search(r'<div class="state ic-(\w+)">(.*?)</div>', band)
    assert found, band[:300]
    icon, state_word = found.groups()
    assert plain(state_word).strip()
    # Streamlit's st.html strips <svg> (Step P2), so the icon is a CSS mask
    assert "<svg" not in band
    assert ".iot .state.ic-%s { --ic: url(\"data:image/svg+xml," % icon in theme.CSS


def test_the_waiting_band_escapes_its_text():
    out = theme.waiting_band("Starting session <x>", "a & b")
    assert "<x>" not in out and "&lt;x&gt;" in out and "a &amp; b" in out


# --------------------------------------------------------------------------
# The device badges
# --------------------------------------------------------------------------

def test_badges_in_each_phase():
    learning = fixture("learning")
    assert theme.device_badge(learning, "esp32-02")[1] == "Learning"
    assert theme.device_badge(learning, "esp32-01")[1] == "Not seen"     # off in the real lab
    incident = fixture("incident")
    assert theme.device_badge(incident, "esp32-02")[:2] == ("alert", "Attack origin")
    assert theme.device_badge(incident, "esp32-03")[:2] == ("ok", "Normal")
    contained = fixture("contained")
    assert theme.device_badge(contained, "esp32-03")[:2] == ("off", "Offline, contained")
    lanes = {r["device"]: r for r in theme.lane_rows(contained)}
    assert lanes["esp32-03"]["origin"] and not lanes["esp32-02"]["origin"]


def test_a_watched_device_says_watching_2_of_3_and_never_attack():
    state = fixture("monitoring")
    state["devices"]["laptop-i3"].update(strikes=2, latest_score=15.0)
    cls, word, tip = theme.device_badge(state, "laptop-i3")
    assert (cls, word) == ("watch", "Watching 2 of 3")
    for name in state["devices"]:
        assert "attack" not in theme.device_badge(state, name)[1].lower()


def test_a_flagged_device_in_an_abstention_is_abnormal_not_the_origin():
    state = fixture("incident")
    state.update(abstained=True, named=None)
    assert theme.device_badge(state, "esp32-02")[:2] == ("alert", "Abnormal")


# --------------------------------------------------------------------------
# The device lanes
# --------------------------------------------------------------------------

def test_one_bar_per_closed_minute_and_never_fewer_than_20_slots():
    state = fixture("incident")
    first, total, slots = theme.lane_slots(state)
    assert (first, total, slots) == (0, state["closed_windows"], theme.MIN_SLOTS)
    rows = {r["device"]: r for r in theme.lane_rows(state)}
    assert set(rows) == {"esp32-02", "esp32-03", "laptop-i3"}       # unseen esp32-01 left out
    assert all(len(r["bars"]) == total for r in rows.values())
    lanes = theme.device_lanes(state)
    # every lane draws exactly `slots` minute slots (bars plus empty placeholders)
    for lane in re.findall(r'<div class="plot".*?</div>', lanes):
        assert len(re.findall(r'<span class="m ', lane)) == slots


def test_past_40_minutes_only_the_newest_40_are_drawn():
    state = fixture("incident")
    for d in state["devices"].values():
        if d.get("scores_by_window"):
            d["scores_by_window"] = {str(w): 1.0 for w in range(55)}
    state["closed_windows"] = 55
    assert theme.lane_slots(state) == (15, 55, theme.MAX_SLOTS)
    row = theme.lane_rows(state)[0]
    assert [b["window"] for b in row["bars"]] == list(range(15, 55))


def test_bars_over_the_line_are_alert_coloured_only_after_the_baseline():
    state = fixture("incident")
    rows = {r["device"]: r for r in theme.lane_rows(state)}
    baseline = state["baseline_windows"]
    for r in rows.values():
        for bar in r["bars"]:
            if bar["window"] < baseline:
                assert "over" not in bar["cls"] and "base" in bar["cls"]
    origin_over = [b["window"] for b in rows["esp32-02"]["bars"] if "over" in b["cls"]]
    assert len(origin_over) >= 3 and min(origin_over) >= baseline
    assert rows["esp32-02"]["origin"] and not rows["esp32-03"]["origin"]


def test_a_bar_taller_than_the_scale_is_capped_and_its_real_score_is_in_the_tooltip():
    state = fixture("incident")
    state["devices"]["laptop-i3"]["scores_by_window"]["14"] = 400.0
    bar = next(b for b in {r["device"]: r for r in theme.lane_rows(state)}["laptop-i3"]["bars"]
               if b["window"] == 14)
    assert "capped" in bar["cls"] and "over" in bar["cls"]
    assert bar["height"] == pytest.approx(100.0)
    assert "score 400.0" in bar["title"]
    assert all(b["height"] <= 100.0 for r in theme.lane_rows(state) for b in r["bars"])


def test_the_alert_line_sits_at_the_threshold_on_the_shared_scale():
    state = fixture("incident")
    lanes = theme.device_lanes(state)
    expected = state["threshold"] / theme.LANE_SCALE * 100
    assert 'class="line" style="bottom:%.0f%%"' % expected in lanes
    assert "alert line (%.1f)" % state["threshold"] in lanes


def test_the_baseline_split_and_axis_label_appear_once_monitoring_has_started():
    assert "split" not in theme.device_lanes(fixture("learning"))
    assert "baseline ends" not in theme.device_lanes(fixture("learning"))
    lanes = theme.device_lanes(fixture("incident"))
    assert lanes.count('class="split"') == 3                         # one per lane
    assert "baseline ends" in lanes


def test_lanes_before_anyone_has_sent_anything():
    assert "No device has sent anything yet" in theme.device_lanes(fixture("waiting"))


# --------------------------------------------------------------------------
# The right-hand card and the timeline
# --------------------------------------------------------------------------

def test_the_session_card_before_a_verdict():
    out = plain(theme.session_card(fixture("learning")))
    assert "6 of 12" in out and "baseline minutes" in out
    assert "Not seen in this capture" in out and "esp32-01 is in the inventory" in out
    assert "Replay of a recorded capture" in plain(theme.session_card(fixture("monitoring"),
                                                                      replaying=True))


def test_how_it_was_found_reads_the_engines_report():
    state = fixture("incident")
    pattern = state["incident"]["how"]["patterns"][0]
    out = plain(theme.how_card(state))
    assert "How it was found" in out
    assert "192.168.0.200:4444" in out                 # broker:4444 shown as its address
    assert "%d" % pattern["count"] in out and "every 30 s" in out
    assert "%s bytes" % pattern["typical_bytes_out"] in out
    assert "Do this now" in out and "Isolate esp32-02" in out


def test_how_it_was_found_after_containment_says_what_the_traffic_confirmed():
    state = fixture("contained")
    out = plain(theme.how_card(state))
    assert "Confirmed from the traffic" in out and "Do this now" not in out
    assert theme.wall(state["containment"]["last_seen_epoch"]) in out


def test_an_abstention_card_names_nobody():
    state = fixture("incident")
    state.update(abstained=True, named=None, shortlist=["esp32-02", "laptop-i3"])
    out = plain(theme.how_card(state))
    assert "Too close to call" in out and "How it was found" not in out


def test_the_timeline_grows_with_the_session():
    assert theme.timeline_points(fixture("learning")) == []
    assert [w for _, w, _ in theme.timeline_points(fixture("monitoring"))] == [
        "Baseline established"]
    assert [w for _, w, _ in theme.timeline_points(fixture("incident"))] == [
        "Baseline established", "First unusual connection", "Alert raised"]
    contained = fixture("contained")
    assert theme.timeline_points(contained)[-1] == (
        theme.wall(contained["containment"]["contained_epoch"]), "Contained", "good")


# --------------------------------------------------------------------------
# The top bar
# --------------------------------------------------------------------------

def test_the_top_bar_shows_capture_status_session_and_clock():
    state = fixture("incident")
    bar = plain(theme.top_bar(state))
    assert "Live monitor" in bar and "Past sessions" in bar
    assert "Live capture" in bar and state["session"] in bar
    assert theme.wall(state["now_epoch"]) in bar
    assert "Replay of a recorded capture" in plain(theme.top_bar(state, replaying=True))
    assert "Engine not updating" in plain(theme.top_bar(state, stale=True))
    assert "Capture stopped" in plain(theme.top_bar(fixture("stopped")))
    past = theme.top_bar(None, page="past")
    assert '<a class="on" href="./replay"' in past and "Session" not in plain(past)
    # the Live monitor is the default page, served at "/" (a link to /live is "Page not found")
    assert 'href="./"' in past and 'href="./live"' not in past


# --------------------------------------------------------------------------
# Safety: data is escaped everywhere
# --------------------------------------------------------------------------

EVIL = '<img src=x onerror="alert(1)">'


def _evil_state(name):
    """A fixture whose device names and session are HTML, renamed everywhere."""
    text = json.dumps(fixture(name))
    for device in ("esp32-02", "esp32-03"):
        text = text.replace('"%s"' % device, json.dumps(EVIL + device))
        text = text.replace('"%s:' % device, json.dumps(EVIL + device + ":")[:-1])
    state = json.loads(text)
    state["session"] = EVIL
    return state


@pytest.mark.parametrize("name", ["learning", "monitoring", "incident", "contained", "stopped"])
def test_no_data_reaches_the_page_unescaped(name):
    state = _evil_state(name)
    watch = copy.deepcopy(state)
    if state["phase"] == live.MONITORING:
        watch["devices"][EVIL + "esp32-03"]["strikes"] = 2
    pieces = [theme.top_bar(state), theme.status_band(state), theme.status_band(watch),
              theme.device_lanes(state), theme.session_card(state), theme.timeline(state)]
    if state.get("onsets"):
        pieces.append(theme.how_card(state))
        abstained = copy.deepcopy(state)
        abstained.update(abstained=True, named=None,
                         shortlist=[EVIL + "esp32-02", EVIL + "esp32-03"])
        pieces += [theme.status_band(abstained), theme.how_card(abstained)]
    for piece in pieces:
        assert "<img" not in piece, piece[:200]
    assert any("&lt;img" in piece for piece in pieces)


def test_the_plotly_template_changes_colours_never_data():
    import plotly.graph_objects as go
    figure = go.Figure(go.Bar(x=[1, 2], y=[3, 4]))
    before = figure.to_dict()["data"]
    styled = theme.styled(figure)
    assert styled.to_dict()["data"] == before
    assert styled.layout.template.layout.paper_bgcolor == "rgba(0,0,0,0)"
