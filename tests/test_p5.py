"""
Step P5 - documents, the interpreting prompt (measured, not adopted), the saved
reports in the new design, and test outputs kept out of git.

  - the analyst's facts now say whether the timing is machine-regular and which
    other devices were flagged ("none" is a fact)
  - claims the measurements cannot show (passwords, stolen data, a named
    attacker or malware) are rejected; a device that WAS flagged may be named
  - PROMPT_P4 stays live: PROMPT_P5 passed 7 of 10 real calls (rule: 8 of 10).
    The 7 real answers are kept as a fixture and still pass the check with
    PROMPT_P5's limits - the 3 failures were refused requests, not answers
  - a refused request now records its HTTP status code (never the key)
  - a saved live session's report carries the engine's CONTAINED check,
    evidence and addresses (how reports/live_session_0X were re-created)
  - .gitignore keeps demo_* / test_* outputs out of git
  - docs/HOW_IT_WORKS.md and docs/LIVE_DEMO.md cover what the plan asks, and
    every command they name exists with its flags
"""

import json
import re
from pathlib import Path

import pytest

from src import analyst, capture, incident, runs

ROOT = Path(__file__).resolve().parents[1]
NAMES = list(capture.DEVICE_KINDS)
TRIAL = json.loads((ROOT / "tests" / "fixtures" / "analyst_p5_trial.json").read_text(encoding="utf-8"))
FACTS = TRIAL["facts"]["live_session_07"]


# --------------------------------------------------------------------------
# The facts and the check
# --------------------------------------------------------------------------

def _report(flagged=("esp32-03",), gap_cv=0.01):
    return {"status": "incident", "flagged": list(flagged), "addresses": {},
            "where": {"named": "esp32-03"},
            "when": {"first_unusual_epoch": None, "first_unusual_seconds": 600.0},
            "how": {"patterns": [{"label": "broker:4444", "dport": 4444, "first_id": "C000001",
                                  "typical_gap_seconds": 30.0, "gap_cv": gap_cv,
                                  "typical_bytes_out": 496, "typical_bytes_in": 170}]}}


def test_facts_say_whether_the_timing_is_regular_and_who_else_changed():
    f = analyst.analyst_facts(_report())
    assert f["timing"] == "fixed timer (machine-regular)" and f["other_devices_abnormal"] == "none"
    assert "timing" not in analyst.analyst_facts(_report(gap_cv=0.5))
    assert "timing" not in analyst.analyst_facts(_report(gap_cv=None))      # a pre-P3 report
    spread = analyst.analyst_facts(_report(flagged=("esp32-03", "esp32-02")))
    assert spread["other_devices_abnormal"] == ["esp32-02"]


@pytest.mark.parametrize("claim", [
    "It is likely sending stolen passwords.", "This looks like a botnet.",
    "The credentials on it are at risk.", "A nation-state group is behind it.",
])
def test_claims_the_measurements_cannot_show_are_rejected(claim):
    text = "From 19:30:19 esp32-03 connected to 192.168.0.200:4444 every 30 seconds. " + claim
    assert any("cannot show" in p for p in analyst.check_summary(text, FACTS, NAMES))


def test_a_device_that_was_flagged_may_be_named_and_one_that_was_not_may_not():
    text = ("From 19:30:19 esp32-03 connected to 192.168.0.200:4444 every 30 seconds. "
            "esp32-02 also changed its behaviour.")
    assert any("another device" in p for p in analyst.check_summary(text, FACTS, NAMES))
    spread = dict(FACTS, other_devices_abnormal=["esp32-02"])
    assert not any("another device" in p for p in analyst.check_summary(text, spread, NAMES))


def test_the_p4_prompt_stays_live_because_p5_passed_7_of_10():
    calls = TRIAL["calls"]
    assert len(calls) == 10 and sum(c["status"] == "ok" for c in calls) == 7
    assert analyst.SYSTEM_PROMPT is analyst.PROMPT_P4
    assert analyst.MAX_SENTENCES == 3
    for rule in ("Do not guess what the messages contain", "usually", "ONE thing to check next",
                 "other device"):
        assert rule in analyst.PROMPT_P5


def test_every_real_p5_answer_passes_the_check_with_p5_limits(monkeypatch):
    monkeypatch.setattr(analyst, "MAX_SENTENCES", 5)
    monkeypatch.setattr(analyst, "MAX_CHARACTERS", 900)
    answered = [c for c in TRIAL["calls"] if c["summary"]]
    assert len(answered) == 7
    for c in answered:
        assert analyst.check_summary(c["summary"], TRIAL["facts"][c["session"]], NAMES) == [], c
    # the three failures never produced an answer: refused within a second
    failed = [c for c in TRIAL["calls"] if c["status"] != "ok"]
    assert all(c["status"] == "unreachable" and c["seconds"] < 1.0 for c in failed)


def test_a_refused_request_records_its_status_code_and_nothing_else():
    def refused(model, system, user, timeout):
        raise RuntimeError("HTTP 429")
    r = analyst.ask(FACTS, NAMES, transport=refused, attempts=1)
    assert r["problems"] == ["attempt 1: no answer (RuntimeError, HTTP 429)"]

    def other(model, system, user, timeout):
        raise RuntimeError("something with a long message that is not kept")
    r = analyst.ask(FACTS, NAMES, transport=other, attempts=1)
    assert r["problems"] == ["attempt 1: no answer (RuntimeError)"]


# --------------------------------------------------------------------------
# The saved reports
# --------------------------------------------------------------------------

needs_07 = pytest.mark.skipif(
    not (runs.meta_path("live_session_07").exists()
         and (ROOT / "pcap" / "live" / "live_session_07" / "state.json").exists()),
    reason="needs data/live_session_07 and its live state.json")


@needs_07
def test_a_saved_live_session_report_matches_the_engines_own_record():
    new = incident.report_for_run("live_session_07")
    engine = json.loads((ROOT / "pcap" / "live" / "live_session_07" / "state.json")
                        .read_text(encoding="utf-8"))["incident"]
    for key in ("named", "confidence_percent"):
        assert new["where"][key] == engine["where"][key]
    for key in ("onset_seconds", "first_unusual_seconds", "alert_seconds", "time_to_detect_seconds"):
        assert new["when"][key] == engine["when"][key], key
    assert new["containment"]["contained_epoch"] == engine["containment"]["contained_epoch"]
    assert new["status"] == "contained" and new["flagged"] == engine["flagged"]
    assert new["addresses"]["esp32-03"] == "192.168.0.203"
    assert new["evidence"]["sha256"] and new["session_folder"]
    assert "analyst" not in new and new["wording"]["source"] == "deterministic"
    page = incident.render_html(new)
    assert "Contained" in page and "192.168.0.203" in page and "broker:4444" not in page


# --------------------------------------------------------------------------
# Test outputs stay out of git
# --------------------------------------------------------------------------

def test_test_outputs_are_ignored():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for line in ("data/demo_*", "data/test_*", "pcap/live/demo_*", "pcap/live/test_*",
                 "reports/demo_*", "reports/test_*"):
        assert re.search(r"^%s$" % re.escape(line), text, re.M), line
    assert not re.search(r"^!data/demo_", text, re.M)       # the old exception is gone


# --------------------------------------------------------------------------
# The documents
# --------------------------------------------------------------------------

HOW = ROOT / "docs" / "HOW_IT_WORKS.md"
DEMO = ROOT / "docs" / "LIVE_DEMO.md"


def test_how_it_works_covers_what_the_viva_needs():
    text = HOW.read_text(encoding="utf-8")
    lowered = text.lower()
    for must in ("the flow", "what each terminal command starts", "each file in one line",
                 "cannot know the answer", "what the ai does", "24x7", "production would need",
                 "detection and attribution"):
        assert must in lowered, must
    for path in sorted((ROOT / "src").glob("*.py")) + sorted((ROOT / "dashboard").glob("*.py")):
        if path.name != "__init__.py":
            assert "%s/%s" % (path.parent.name, path.name) in text, path.name


def test_the_demo_script_covers_the_final_build():
    text = DEMO.read_text(encoding="utf-8")
    for must in ("--llm cloud", "Alert sound", "Acknowledge", "Create PDF", "Download PDF",
                 "Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned",
                 r'.\mosquitto -c "E:\T Softwares\Mosquitto\lab.config" -v', "lab\\mosquitto_lab.conf",
                 "Rung 1", "Rung 2", "Rung 3", "Rung 4", "Template wording"):
        assert must in text, must


def test_every_command_in_how_it_works_exists_with_its_flags():
    commands = re.findall(r"python -m src\.(\w+)([^\n`|]*)", HOW.read_text(encoding="utf-8"))
    assert len(commands) >= 6
    for module, rest in commands:
        source = ROOT / "src" / ("%s.py" % module)
        assert source.exists(), module
        body = source.read_text(encoding="utf-8")
        for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", rest):
            assert '"%s"' % flag in body, (module, flag)
