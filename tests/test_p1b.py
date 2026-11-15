"""
Tests for Step P1b of docs/POLISH_PLAN.md - the fixes found when P1 was
checked by eye:

  1. the app opens on the Live monitor; Past sessions opens on the newest
     real live session, never on a simulated run_* by default;
  2. the "When each device went abnormal" chart fits the longest name;
  3. four chart colours that cannot be confused;
  4. the answer check moved to a collapsed "Lab validation" section at the
     bottom of Past sessions, worded like the live page's.

Plus 5-7 checked from the source/config: the sidebar caption is gone, the
sidebar page menu is off (the top bar is the switch), inline code is restyled.
"""

import ast
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from dashboard import app, theme
from src import attribute, runs

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# 1. Which page, and which run, the dashboard opens on
# --------------------------------------------------------------------------

def test_the_live_monitor_is_the_default_page():
    tree = ast.parse((ROOT / "dashboard" / "app.py").read_text(encoding="utf-8"))
    defaults = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "Page":
            target = node.args[0].id
            defaults[target] = any(k.arg == "default" and k.value.value is True
                                   for k in node.keywords)
    assert defaults == {"live_monitor_page": True, "replay_page": False}


def test_past_sessions_opens_on_the_newest_real_live_session():
    available = ["easy_000", "lab_batch_01", "lab_batch_12", "live_session_01",
                 "live_session_02", "live_session_10", "rehearsal_02", "run_000", "run_029"]
    assert app.default_run(available) == "live_session_10"          # by number, not by name order


def test_an_aborted_session_is_never_the_default():
    from src.evaluate import ABORTED_SESSIONS
    aborted = next(iter(ABORTED_SESSIONS))                          # live_session_06
    assert app.default_run(["live_session_05", aborted, "run_000"]) == "live_session_05"


def test_without_live_sessions_a_real_lab_capture_comes_before_simulated_runs():
    assert app.default_run(["lab_batch_02", "lab_batch_11", "run_000"]) == "lab_batch_11"
    assert app.default_run(["rehearsal_01", "rehearsal_02", "run_000"]) == "rehearsal_02"
    assert app.default_run(["easy_000", "run_000"]) == "easy_000"
    assert app.default_run(["run_000", "run_001"]) == "run_000"     # only simulated: first one
    assert app.default_run([]) is None


needs_live_07 = pytest.mark.skipif(
    not runs.data_path("live_session_07").exists(),
    reason="needs data/live_session_07 (gitignored)")


def _past_page():
    from dashboard import app as dashboard_app
    dashboard_app.replay_page()


@needs_live_07
def test_the_past_sessions_picker_starts_on_the_newest_live_session():
    at = AppTest.from_function(_past_page, default_timeout=180)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.selectbox[0].value == app.default_run(runs.replay_runs())
    assert at.selectbox[0].value.startswith("live_session_")


# --------------------------------------------------------------------------
# 2 and 3. The timeline chart: names fit, colours differ
# --------------------------------------------------------------------------

def _fake(names_and_roles):
    """Just enough of a run / detection / result for timeline_figure."""
    onsets = {name: 3600.0 + 60 * i for i, (name, _) in enumerate(names_and_roles)}
    detection = SimpleNamespace(onsets=onsets,
                                devices_by_onset=lambda: sorted(onsets, key=onsets.get))
    named = next((n for n, r in names_and_roles if r == "origin"), None)
    result = SimpleNamespace(abstained=named is None, named=named,
                             shortlist=[n for n, r in names_and_roles if r in ("origin", "shortlist")])
    run = SimpleNamespace(baseline_seconds=3600.0, capture_seconds=7200.0)
    return run, detection, result


def test_the_left_margin_fits_the_longest_device_name():
    long_name = "very-long-device-name-07"
    run, detection, result = _fake([(long_name, "origin"), ("cam", "flagged")])
    figure = app.timeline_figure(run, detection, result)
    assert figure.layout.margin.l >= 8 * len(long_name)
    assert figure.layout.yaxis.automargin is True
    short = app.timeline_figure(*_fake([("cam", "origin")]))
    assert short.layout.margin.l < figure.layout.margin.l
    # the hour ticks, axis title and legend have room underneath
    assert figure.layout.margin.b >= 80


def test_the_four_roles_have_the_agreed_colours():
    assert app.ROLE_COLOUR == {"origin": theme.ALERT, "shortlist": theme.WATCH,
                               "flagged": "#B79CFF", "clean": "#5C6F92"}
    assert len(set(app.ROLE_COLOUR.values())) == 4


def test_shortlist_and_went_abnormal_are_drawn_in_different_colours():
    run, detection, result = _fake([("tablet", "shortlist"), ("esp32-02", "shortlist"),
                                    ("cam2", "flagged")])
    figure = app.timeline_figure(run, detection, result)
    colours = {trace.name: trace.marker.color for trace in figure.data}
    assert colours["on the shortlist"] == theme.WATCH
    assert colours["went abnormal"] == "#B79CFF"


# --------------------------------------------------------------------------
# 4. Lab validation on Past sessions
# --------------------------------------------------------------------------

def _result(ranking, abstained=False):
    result = attribute.Attribution()
    result.ranking, result.abstained = ranking, abstained
    result.named = None if abstained else (ranking[0] if ranking else None)
    return result


def test_the_answer_verdict_says_right_or_wrong():
    answer = {"origin": "esp32-03", "chain": ["esp32-03"]}
    kind, text = app.answer_verdict(answer, _result(["esp32-03", "laptop-i3"]))
    assert kind == "success" and text.startswith("Correct.")
    kind, _ = app.answer_verdict(answer, _result(["laptop-i3", "esp32-03"]))
    assert kind == "warning"
    kind, _ = app.answer_verdict(answer, _result(["a", "b", "c", "esp32-03"]))
    assert kind == "error"
    kind, text = app.answer_verdict(answer, _result(["laptop-i3"]))
    assert kind == "error" and "never flagged" in text
    assert app.answer_verdict(None, _result(["x"]))[0] == "info"
    # an abstention is never "Correct", even with the origin ranked first
    assert app.answer_verdict(answer, _result(["esp32-03", "x"], abstained=True))[0] == "warning"


def test_the_reveal_switch_left_the_sidebar():
    import re
    source = (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
    assert not re.search(r'checkbox\(\s*"Reveal', source)          # no widget with the old label
    assert 'st.expander("Lab validation")' in source
    assert '"Compare with the recorded answer"' in source


@needs_live_07
def test_past_sessions_compares_with_the_answer_only_when_ticked(monkeypatch):
    at = AppTest.from_function(_past_page, default_timeout=180)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert "Lab validation" in [e.label for e in at.expander]
    assert not [c for c in at.sidebar.checkbox]                     # nothing left in the sidebar
    assert not [s for s in at.success if s.value.startswith("Correct")]
    box = next(c for c in at.checkbox if c.label == "Compare with the recorded answer")
    box.check().run()
    assert not at.exception, [e.value for e in at.exception]
    verdicts = [s.value for s in at.success] + [w.value for w in at.warning] + \
               [e.value for e in at.error] + [i.value for i in at.info]
    assert any(v.startswith("Correct.") or "No answer file" in v for v in verdicts)


# --------------------------------------------------------------------------
# 5-7. Caption, page menu, inline code
# --------------------------------------------------------------------------

def test_the_streamlit_only_caption_is_gone():
    assert "no build step." not in (ROOT / "dashboard" / "app.py").read_text(encoding="utf-8") \
        .split('"""', 2)[2]                                         # the docstring may keep it


def test_the_top_bar_is_the_only_page_switch():
    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert config["client"]["showSidebarNavigation"] is False


def test_inline_code_is_soft_on_raised_not_green():
    css = theme.CSS
    rule = css[css.index(":not(pre) > code"):]
    rule = rule[:rule.index("}")]
    assert "var(--soft)" in rule and "var(--raised)" in rule
