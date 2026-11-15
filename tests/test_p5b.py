"""
Step P5b - the interpreting prompt tightened and measured the way a real
session calls (docs/POLISH_PLAN.md, "P5b as built").

  - PROMPT_P5 asks for at most 4 sentences, ~600 and never more than 650
    characters, one hedge word at a time
  - stacked hedges ("may likely", "usually consistent with") are rejected
  - after "HTTP 429" the one retry waits 5 s, and the wait counts inside the
    retry's own 25 s (and inside the STOP budget); other refusals do not wait
  - which prompt is live follows the measurement in
    tests/fixtures/analyst_p5b_trial.json (6 calls, one a minute)
"""

import json
from pathlib import Path

import pytest

from src import analyst, capture

ROOT = Path(__file__).resolve().parents[1]
NAMES = list(capture.DEVICE_KINDS)
TRIAL = json.loads((ROOT / "tests" / "fixtures" / "analyst_p5b_trial.json").read_text(encoding="utf-8"))
FACTS = TRIAL["facts"]["live_session_07"]
GOOD = ("From 19:30:19 esp32-03 connected to 192.168.0.200:4444 every 30 seconds, sending 496 "
        "bytes each time. This is usually the sign of a compromised device checking in.")


def test_the_p5_prompt_is_tightened():
    p = analyst.PROMPT_P5
    assert "AT MOST 4 short, plain sentences" in p and "never more than 650" in p
    assert "one at a time" in p and "may likely" in p           # named as the thing not to do
    assert (analyst.P5_MAX_SENTENCES, analyst.P5_MAX_CHARACTERS) == (4, 650)


@pytest.mark.parametrize("hedge", ["may likely", "could likely", "usually consistent with",
                                   "likely consistent with"])
def test_stacked_hedges_are_rejected(hedge):
    text = ("From 19:30:19 esp32-03 connected to 192.168.0.200:4444 every 30 seconds. "
            "This is %s a compromised device." % hedge)
    assert any("stacks two hedges" in p for p in analyst.check_summary(text, FACTS, NAMES))


def test_one_hedge_at_a_time_passes():
    for one in ("usually", "likely", "consistent with"):
        text = ("From 19:30:19 esp32-03 connected to 192.168.0.200:4444 every 30 seconds. "
                "This is %s a compromised device." % one)
        assert not any("hedge" in p for p in analyst.check_summary(text, FACTS, NAMES)), one


def _transport(*answers):
    calls = []

    def transport(model, system, user, timeout):
        calls.append(timeout)
        a = answers[len(calls) - 1]
        if isinstance(a, Exception):
            raise a
        return a
    transport.calls = calls
    return transport


def test_a_429_waits_5_s_inside_the_retrys_25_s():
    slept = []
    t = _transport(RuntimeError("HTTP 429"), GOOD)
    r = analyst.ask(FACTS, NAMES, transport=t, sleep=slept.append)
    assert slept == [analyst.RATE_LIMIT_WAIT] == [5.0]
    assert t.calls == [25.0, 20.0]                   # wait + retry stay inside 25 s
    assert r["status"] == analyst.OK and r["attempts"] == 2
    assert r["problems"] == ["attempt 1: no answer (RuntimeError, HTTP 429)"]


def test_other_refusals_and_timeouts_do_not_wait():
    for first in (RuntimeError("HTTP 500"), TimeoutError()):
        slept = []
        t = _transport(first, GOOD)
        r = analyst.ask(FACTS, NAMES, transport=t, sleep=slept.append)
        assert slept == [] and t.calls == [25.0, 25.0] and r["status"] == analyst.OK


def test_no_wait_and_no_retry_when_the_stop_budget_cannot_hold_it():
    ticks = iter([0.0, 0.0, 21.0, 21.0, 21.0])     # 4 s of the 25 s budget left after the 429
    slept = []
    t = _transport(RuntimeError("HTTP 429"), GOOD)
    r = analyst.ask(FACTS, NAMES, transport=t, budget=25.0, clock=lambda: next(ticks),
                    sleep=slept.append)
    assert slept == [] and len(t.calls) == 1 and r["status"] == analyst.UNREACHABLE


def test_a_429_on_the_last_attempt_does_not_wait():
    slept = []
    analyst.ask(FACTS, NAMES, transport=_transport(RuntimeError("HTTP 429")), attempts=1,
                sleep=slept.append)
    assert slept == []


def test_the_measurement_was_six_calls_one_a_minute_with_codes_recorded():
    calls = TRIAL["calls"]
    assert len(calls) == 6
    assert [c["session"] for c in calls] == ["live_session_07", "live_session_03"] * 3
    for c in calls:
        if c["status"] != "ok":
            assert any("HTTP" in p or "Error" in p for p in c["problems"]), c
    assert "x-goog" not in json.dumps(TRIAL) and "AIza" not in json.dumps(TRIAL)


# --------------------------------------------------------------------------
# The decision, and the engine
# --------------------------------------------------------------------------

def test_all_six_came_back_and_passed_so_p5_is_live():
    calls = TRIAL["calls"]
    assert all(c["status"] == "ok" for c in calls)
    assert analyst.SYSTEM_PROMPT is analyst.PROMPT_P5
    assert (analyst.MAX_SENTENCES, analyst.MAX_CHARACTERS) == (4, 650)
    for c in calls:                                   # and they pass today's live check
        assert analyst.check_summary(c["summary"], TRIAL["facts"][c["session"]], NAMES) == []
        assert len(c["summary"]) <= 650


def _report(flagged):
    return {"status": "incident", "flagged": list(flagged), "addresses": {},
            "where": {"named": "esp32-03"},
            "when": {"first_unusual_epoch": None, "first_unusual_seconds": 600.0},
            "how": {"patterns": [{"label": "broker:4444", "dport": 4444, "first_id": "C000001",
                                  "typical_gap_seconds": 30.0, "gap_cv": 0.01,
                                  "typical_bytes_out": 496, "typical_bytes_in": 170}]}}


def test_the_engine_asks_again_only_if_another_device_is_flagged(tmp_path):
    from src import live
    asked = []

    def transport(model, system, user, timeout):
        asked.append(json.loads(user.split("\n", 1)[1].split("\n\nWrite")[0]))
        return "unused"                          # rejected; only the asking is tested here
    engine = live.LiveSession(tmp_path / "s", reader=lambda p: [], data_dir=tmp_path / "data",
                              llm="cloud", analyst_transport=transport)
    engine.first_alert = {"raised_seconds": 900.0}
    engine.incident = _report(["esp32-03"])
    engine._tend_analyst()
    engine.analyst.join(10)
    for _ in range(3):                           # same facts: no new question
        engine.incident = _report(["esp32-03"])
        engine._tend_analyst()
    engine.analyst.join(10)
    assert [a["other_devices_abnormal"] for a in asked] == ["none", "none"]   # ask + its retry
    engine.incident = _report(["esp32-03", "esp32-02"])                       # it spread
    engine._tend_analyst()
    engine.analyst.join(10)
    engine.incident = _report(["esp32-03", "esp32-02"])
    engine._tend_analyst()
    engine.analyst.join(10)
    assert [a["other_devices_abnormal"] for a in asked][2:] == [["esp32-02"], ["esp32-02"]]
