"""
Step P4 - the AI analyst (cloud) (docs/POLISH_PLAN.md).

  - the model is given only facts that do not change minute to minute
  - its answer is shown only if it passes report.validate_brief plus the P4
    rules (no running counts, no other device, 2-3 sentences)
  - one retry, a time limit, and the template wording when it fails
  - the key is never printed, logged or written
  - the engine's state is identical whether the analyst passes, is rejected,
    times out or has no key - except the wording field ("analyst")
  - page and report: "Analyst summary" with where its wording came from
  - Past sessions: the cloud writer is the default when a key is present

No test here contacts the internet: every transport is a fake.
"""

import copy
import json
import time
from pathlib import Path

import pytest

from src import analyst, capture, incident, live, report

ROOT = Path(__file__).resolve().parents[1]
NAMES = list(capture.DEVICE_KINDS)
FIXTURES = ROOT / "tests" / "fixtures" / "live_states"
GOOD = ("At 19:30:19 the device esp32-03 began connecting to 192.168.0.200:4444 every 30 seconds. "
        "Each time it sent 496 bytes and received 170 bytes back.")


def contained_state():
    return json.loads((FIXTURES / "contained.json").read_text(encoding="utf-8"))


FACTS = {"device": "esp32-03", "device_address": "192.168.0.203",
         "first_unusual_connection": "19:30:19", "first_connection_id": "C000450",
         "destination": "192.168.0.200:4444", "port": 4444, "interval_seconds": 30,
         "bytes_sent_each_time": 496, "bytes_received_each_time": 170,
         "new_destination": "never used while its normal behaviour was learned"}


# --------------------------------------------------------------------------
# The facts
# --------------------------------------------------------------------------

def test_the_model_gets_only_facts_that_do_not_change_minute_to_minute():
    state = contained_state()
    facts = analyst.analyst_facts(state["incident"], state["addresses"])
    assert set(facts) <= {"device", "device_address", "first_unusual_connection",
                          "first_connection_id", "destination", "port", "interval_seconds",
                          "bytes_sent_each_time", "bytes_received_each_time", "new_destination",
                          # P5: whether the timer is regular, and who else was flagged
                          "timing", "other_devices_abnormal"}
    assert facts["device"] == "esp32-03" and facts["destination"] == "192.168.0.200:4444"
    assert facts["interval_seconds"] == 30 and facts["bytes_sent_each_time"] == 496
    text = json.dumps(facts)
    for moving in ("count", "confidence", "score", "laptop-i3", "esp32-02", "broker"):
        assert moving not in text, moving


def test_no_named_device_or_no_new_destination_means_no_question():
    state = contained_state()
    r = copy.deepcopy(state["incident"])
    r["where"]["named"] = None
    assert analyst.analyst_facts(r) is None
    r = copy.deepcopy(state["incident"])
    r["how"]["patterns"] = []
    assert analyst.analyst_facts(r) is None
    assert analyst.analyst_facts({"status": "no incident"}) is None


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------

def test_a_faithful_summary_passes():
    assert analyst.check_summary(GOOD, FACTS, NAMES) == []


@pytest.mark.parametrize("bad,why", [
    (GOOD.replace("every 30 seconds", "every 30 seconds, 7 connections so far"), "running count"),
    (GOOD.replace("19:30:19", "19:31:00"), "time"),
    (GOOD.replace("496 bytes", "4,096 bytes"), "figure"),
    (GOOD.replace("192.168.0.200:4444", "192.168.0.200:5555"), "5555"),
    (GOOD + " esp32-02 looks fine.", "another device"),
    (GOOD.replace("esp32-03", "the board"), "does not name"),
    (GOOD + " Then evil-c2-box9 took over.", "not a real device"),
    ("", "empty"),
    ("One. Two. Three. Four. Five esp32-03.", "longer"),     # P5b: at most 4
])
def test_an_unfaithful_summary_is_rejected(bad, why):
    problems = analyst.check_summary(bad, FACTS, NAMES)
    assert any(why in p for p in problems), problems


# --------------------------------------------------------------------------
# Asking: pass, reject, timeout, no key
# --------------------------------------------------------------------------

def fake(*answers):
    """A transport that gives these answers in turn (an Exception is raised)."""
    calls = []

    def transport(model, system, user, timeout):
        calls.append({"user": user, "timeout": timeout})
        answer = answers[min(len(calls), len(answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer
    transport.calls = calls
    return transport


def test_a_passing_answer_is_kept():
    t = fake(GOOD)
    r = analyst.ask(FACTS, NAMES, transport=t)
    assert r["status"] == analyst.OK and r["summary"] == GOOD and r["attempts"] == 1
    assert r["model"] == report.CLOUD_MODEL and len(t.calls) == 1
    assert t.calls[0]["timeout"] == analyst.LIMIT_SECONDS == 25.0


def test_one_retry_with_the_objections_then_it_passes():
    t = fake(GOOD + " 7 connections so far.", GOOD)
    r = analyst.ask(FACTS, NAMES, transport=t)
    assert r["status"] == analyst.OK and r["attempts"] == 2
    assert "PREVIOUS SUMMARY WAS REJECTED" in t.calls[1]["user"]
    assert "running count" in t.calls[1]["user"]


def test_rejected_twice_means_template_wording():
    t = fake(GOOD.replace("19:30:19", "19:31:00"))
    r = analyst.ask(FACTS, NAMES, transport=t)
    assert r["status"] == analyst.REJECTED and r["summary"] is None and len(t.calls) == 2


def test_a_timeout_is_unreachable_after_one_retry():
    t = fake(TimeoutError("read timed out"))
    r = analyst.ask(FACTS, NAMES, transport=t)
    assert r["status"] == analyst.UNREACHABLE and len(t.calls) == 2 and r["summary"] is None


def test_no_key_means_no_call_at_all(monkeypatch):
    monkeypatch.setattr(analyst, "key_available", lambda: False)
    monkeypatch.setattr(analyst, "cloud_transport",
                        lambda *a, **k: pytest.fail("must not be called"))
    r = analyst.ask(FACTS, NAMES)
    assert r["status"] == analyst.NO_KEY


def test_the_stop_budget_caps_the_whole_ask():
    ticks = iter([0.0, 0.0, 24.8, 24.8])       # the first attempt used 24.8 s of 25
    t = fake(TimeoutError())
    r = analyst.ask(FACTS, NAMES, transport=t, budget=25.0, clock=lambda: next(ticks))
    assert len(t.calls) == 1 and r["status"] == analyst.UNREACHABLE


def test_the_key_is_never_printed_logged_or_written(tmp_path, monkeypatch, capsys):
    secret = "AIzaTESTSECRET-0123456789"
    monkeypatch.delenv("IOT_NO_CLOUD")                 # a (fake) key is present here...
    monkeypatch.setattr(report, "_gemini_key", lambda: secret)   # ...and the network is faked below

    class Reply:
        status_code = 403
        text = "API key %s not valid" % secret          # even if the server echoed it

    import requests
    seen = {}

    def post(url, headers=None, json=None, timeout=None):
        seen.update(url=url, headers=headers)
        return Reply()
    monkeypatch.setattr(requests, "post", post)
    a = analyst.Analyst(tmp_path, NAMES)
    a.ask_in_background(FACTS)
    a.join(10)
    record = a.current()
    assert record["status"] == analyst.UNREACHABLE
    assert secret in seen["headers"]["x-goog-api-key"] and secret not in seen["url"]
    out = capsys.readouterr()
    for text in (json.dumps(record), (tmp_path / analyst.ANALYST_FILE).read_text(encoding="utf-8"),
                 out.out, out.err):
        assert secret not in text


def test_the_background_ask_returns_at_once_and_is_cached(tmp_path):
    def slow(model, system, user, timeout):
        time.sleep(0.5)
        return GOOD
    a = analyst.Analyst(tmp_path, NAMES, transport=slow)
    started = time.perf_counter()
    assert a.ask_in_background(FACTS) is True
    assert time.perf_counter() - started < 0.2              # never blocks the engine
    assert a.current()["status"] == analyst.ASKING
    assert a.ask_in_background(FACTS) is False              # one at a time
    a.join(10)
    assert a.current()["status"] == analyst.OK
    cached = json.loads((tmp_path / analyst.ANALYST_FILE).read_text(encoding="utf-8"))
    assert cached["summary"] == GOOD


def test_at_stop_a_failed_ask_keeps_the_alerts_answer_for_the_same_facts(tmp_path):
    answers = iter([GOOD, TimeoutError(), TimeoutError()])

    def transport(model, system, user, timeout):
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        return a
    a = analyst.Analyst(tmp_path, NAMES, transport=transport)
    a.ask_in_background(FACTS)
    final = a.ask_at_stop(FACTS)
    assert final["status"] == analyst.OK and final["stop_attempt"] == analyst.UNREACHABLE
    assert [(c["stage"], c["status"]) for c in a.calls] == [("alert", "ok"),
                                                           ("stop", "unreachable")]


# --------------------------------------------------------------------------
# Page and report wording
# --------------------------------------------------------------------------

def with_analyst(record):
    state = contained_state()
    state["incident"] = incident.with_analyst(state["incident"], record)
    return state


def test_the_report_says_who_wrote_the_summary():
    ok = with_analyst({"status": "ok", "model": "gemini-3.6-flash", "summary": GOOD})
    page = incident.render_html(ok["incident"], ok["addresses"])
    assert "Analyst summary" in page and GOOD in page
    assert ("Written by the AI analyst (gemini-3.6-flash). Every fact checked against the "
            "evidence.") in page
    down = with_analyst({"status": "unreachable", "model": "gemini-3.6-flash", "summary": None})
    page = incident.render_html(down["incident"], down["addresses"])
    assert "Template wording - the AI analyst was not reachable." in page and GOOD not in page
    plain = contained_state()
    assert "Template wording, built from the measurements." in incident.render_html(plain["incident"])


def test_a_summary_that_failed_the_check_is_never_shown_even_if_present():
    bad = with_analyst({"status": "rejected", "model": "m", "summary": "invented"})
    facts = incident.design_facts(bad["incident"])
    assert facts["summary"] != "invented" and not facts["by_ai"]


def test_with_analyst_adds_one_field_and_changes_nothing_else():
    state = contained_state()
    r = state["incident"]
    out = incident.with_analyst(r, {"status": "ok", "summary": GOOD})
    assert set(out) - set(r) == {"analyst"} and all(out[k] == r[k] for k in r)
    assert incident.with_analyst(r, None) is r


@pytest.mark.parametrize("record,line", [
    ({"status": "ok", "model": "gemini-3.6-flash", "summary": GOOD},
     "Written by the AI analyst (gemini-3.6-flash). Every fact checked against the evidence."),
    ({"status": "unreachable", "model": "gemini-3.6-flash"},
     "Template wording - the AI analyst was not reachable."),
])
def test_the_live_page_shows_the_analyst_summary_and_its_source(tmp_path, record, line):
    from tests.test_live_page import fresh, place, render, texts
    state = fresh(with_analyst(record))
    state["analyst"] = record
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    shown = texts(at)
    assert "Analyst summary" in shown and line in shown
    assert (GOOD in shown) == (record["status"] == "ok")


def test_past_sessions_defaults_to_the_cloud_writer_when_a_key_is_present(monkeypatch):
    from dashboard import app
    monkeypatch.setattr(app, "cloud_key_present", lambda: True)
    assert app.default_writer() == "cloud"
    monkeypatch.setattr(app, "cloud_key_present", lambda: False)
    assert app.default_writer() == "template"


def test_the_tests_never_reach_the_real_cloud():
    from dashboard import app
    assert not app.cloud_key_present() and not analyst.key_available()
    assert live.WRITE_PDF is False


def test_the_guards_are_already_on_inside_a_module_scoped_fixture(module_guard_probe):
    # Found while writing P4: a function-scoped guard came too late for a
    # module-scoped fixture, and the "no key" replay really called the model.
    assert module_guard_probe == {"cloud": False, "pdf": False}


@pytest.fixture(scope="module")
def module_guard_probe():
    return {"cloud": analyst.key_available(), "pdf": live.WRITE_PDF}


# --------------------------------------------------------------------------
# The engine: identical state in all four cases, apart from the wording
# --------------------------------------------------------------------------

PCAP = ROOT / "pcap" / "live" / "live_session_07.pcapng"


def _tools():
    try:
        capture.find_tshark()
        return PCAP.exists()
    except FileNotFoundError:
        return False


VOLATILE = {"updated_epoch", "analysis_seconds", "first_alert_wall_epoch", "analyst",
            "analyst_calls", "report_file", "pdf_file"}


def _comparable(state):
    s = {k: v for k, v in state.items() if k not in VOLATILE}
    if isinstance(s.get("incident"), dict):
        s["incident"] = {k: v for k, v in s["incident"].items() if k != "analyst"}
    return json.loads(json.dumps(live.json_safe(s)))


@pytest.fixture(scope="module")
def four_runs(tmp_path_factory):
    if not _tools():
        pytest.skip("needs pcap/live/live_session_07.pcapng and tshark")
    tmp = tmp_path_factory.mktemp("p4")
    cache = {}
    real = capture.read_packets

    def cached(path, binary):                  # tshark once per file, not once per run
        key = (Path(path).name, Path(path).stat().st_size)
        if key not in cache:
            cache[key] = real(path, binary)
        return copy.deepcopy(cache[key])

    def passing(model, system, user, timeout):
        """A faithful summary written from the facts it is sent."""
        facts = json.loads(user.split("\n", 1)[1].split("\n\nWrite")[0])
        return ("At %s the device esp32-03 began connecting to %s every %d seconds. "
                "Each time it sent %d bytes."
                % (facts["first_unusual_connection"], facts["destination"],
                   facts["interval_seconds"], facts["bytes_sent_each_time"]))

    transports = {
        "pass": passing,
        "reject": fake("esp32-03 made 7 connections so far."),
        "timeout": fake(TimeoutError("timed out")),
        "no key": None,                    # IOT_NO_CLOUD (conftest): no key, no call
    }
    out = {}
    mp = pytest.MonkeyPatch()
    mp.setattr(capture, "read_packets", cached)
    try:
        for name, transport in transports.items():
            states = []
            engine = live.replay(PCAP, "p4run", folder=tmp / "p4run",
                                 data_dir=tmp / name.replace(" ", "_") / "data",
                                 speed=0, save=False, quiet=True, force=True, llm="cloud",
                                 analyst_transport=transport,
                                 on_cycle=lambda sess, st: states.append(
                                     json.loads(json.dumps(live.json_safe(st)))))
            out[name] = (engine, states)
    finally:
        mp.undo()
    return out


def test_the_engine_state_is_identical_in_all_four_cases_but_the_wording(four_runs):
    base_engine, base = four_runs["pass"]
    assert base_engine.result.named == "esp32-03"
    for name in ("reject", "timeout", "no key"):
        engine, states = four_runs[name]
        assert len(states) == len(base), name
        for a, b in zip(base, states):
            assert _comparable(a) == _comparable(b), name


def test_only_a_passing_answer_reaches_the_final_report(four_runs):
    statuses = {name: four_runs[name][0].state()["analyst"]["status"] for name in four_runs}
    assert statuses == {"pass": "ok", "reject": "rejected", "timeout": "unreachable",
                        "no key": "no key"}
    final = four_runs["pass"][0].state()["incident"]
    assert final["analyst"]["summary"].startswith("At 19:30:19 the device esp32-03")
    html_text = Path(four_runs["pass"][0].report_file).read_text(encoding="utf-8")
    assert "Written by the AI analyst" in html_text
    for name in ("reject", "timeout", "no key"):
        r = four_runs[name][0].state()["incident"]
        assert not incident.design_facts(r)["by_ai"]
