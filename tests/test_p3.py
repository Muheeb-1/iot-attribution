"""
Step P3 - the designed report and the PDF (docs/POLISH_PLAN.md).

  - the new report fields are rules, not a model: incident id, severity,
    ATT&CK techniques - checked on live_session_07 (high, all three, id
    INC-20261113-07) and on hand-made reports for each rule's edge
  - destinations are SHOWN as addresses (192.168.0.200:4444), never as
    "broker:4444", on the live page and in the designed report; capture.py's
    names and the report's "label" fields are unchanged
  - the "not contained yet" line is in sentence case
  - render_html escapes every piece of data and loads nothing from outside
  - html_to_pdf returns None cleanly when there is no browser, and makes a real
    PDF when Edge/Chrome is there (skipped otherwise)
  - the engine prints the PDF at STOP; the page offers Create PDF / Download PDF
    and keeps the eight sections under "Full technical detail"
"""

import copy
import json
from pathlib import Path

import pytest

from src import capture, incident, live, runs
from tests.test_live_page import fixture, fresh, place, render, texts

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# The fields: incident id, severity, techniques
# --------------------------------------------------------------------------

def _pattern(**kw):
    p = {"dst": "broker", "dport": 4444, "label": "broker:4444", "count": 7,
         "typical_gap_seconds": 30.0, "gap_cv": 0.01, "typical_bytes_out": 496,
         "typical_bytes_in": 170}
    p.update(kw)
    return p


def _report(flagged=("esp32-03",), patterns=None, session="live_session_07",
            start=1_794_483_624.0):
    return {"status": "incident", "session": session, "capture_start_epoch": start,
            "flagged": list(flagged), "how": {"patterns": [_pattern()] if patterns is None
                                              else patterns},
            "when": {"alert_epoch": None if start is None else start + 963.0,
                     "alert_seconds": 963.0}}


def test_incident_id_uses_the_capture_date_and_the_session_number():
    r = _report()
    date = __import__("datetime").datetime.fromtimestamp(r["capture_start_epoch"]).strftime("%Y%m%d")
    assert incident.incident_id(r) == "INC-%s-07" % date
    # no digits in the name: the alert's HHMM instead
    named = _report(session="demo")
    hhmm = __import__("datetime").datetime.fromtimestamp(named["when"]["alert_epoch"]).strftime("%H%M")
    assert incident.incident_id(named) == "INC-%s-%s" % (date, hhmm)
    # a simulated run has no clock: no date part
    assert incident.incident_id(_report(start=None)) == "INC-07"


@pytest.mark.parametrize("flagged,patterns,severity", [
    (["a", "b"], [_pattern()], "critical"),       # more than one device flagged
    (["a"], [_pattern()], "high"),                # one device, a new repeating destination
    (["a"], [], "medium"),                        # one device, no new repeating destination
])
def test_severity_follows_the_stated_rule(flagged, patterns, severity):
    assert incident.severity_of(_report(flagged, patterns)) == severity
    assert "Critical" in incident.SEVERITY_RULE and "Medium" in incident.SEVERITY_RULE


def test_each_technique_needs_its_own_measurement():
    ids = lambda **kw: [t["id"] for t in incident.techniques_for(_report(patterns=[_pattern(**kw)]))]  # noqa: E731
    assert ids() == ["T1571", "T1029", "T1041"]
    assert "T1571" not in ids(dport=1883, label="broker:1883")     # a known service port
    assert "T1029" not in ids(gap_cv=0.35)                          # not regular enough
    assert "T1029" not in ids(count=3)                              # too few to call a rhythm
    assert "T1029" not in ids(gap_cv=None)                          # a report from before P3
    assert "T1041" not in ids(typical_bytes_out=100, typical_bytes_in=900)   # more came back
    assert incident.techniques_for(_report(patterns=[])) == []


def test_the_technique_names_are_the_attack_mitre_org_names():
    assert {k: v["name"] for k, v in incident.TECHNIQUES.items()} == {
        "T1571": "Non-Standard Port", "T1029": "Scheduled Transfer",
        "T1041": "Exfiltration Over C2 Channel"}


needs_07 = pytest.mark.skipif(not (runs.meta_path("live_session_07").exists()
                                   and runs.data_path("live_session_07").exists()),
                              reason="needs data/live_session_07.*")


@needs_07
def test_live_session_07_is_high_with_all_three_techniques():
    r = incident.report_for_run("live_session_07")
    assert r["incident_id"] == "INC-20261113-07"
    assert r["severity"] == "high"
    assert [t["id"] for t in r["techniques"]] == ["T1571", "T1029", "T1041"]
    assert "every 30 seconds" in r["techniques"][1]["evidence"]
    assert "496 bytes out for 170 back" in r["techniques"][2]["evidence"]
    # the new fields are additions: the label still says what capture.py named it
    assert r["how"]["patterns"][0]["label"] == "broker:4444"
    json.dumps(r)


# --------------------------------------------------------------------------
# Addresses, not "broker"
# --------------------------------------------------------------------------

def test_labels_are_shown_as_addresses_but_names_are_unchanged():
    assert incident.address_label("broker:4444") == "192.168.0.200:4444"      # fixed table
    assert incident.address_label("broker:4444", {"broker": "10.0.0.9"}) == "10.0.0.9:4444"
    assert incident.address_label("broker (no port)") == "192.168.0.200 (no port)"
    assert incident.address_label("esp32-03:1883", {"esp32-03": "192.168.0.203"}) == \
        "192.168.0.203:1883"
    assert incident.address_label("8.8.8.8:53") == "8.8.8.8:53"
    assert incident.address_label("unknown-thing:80") == "unknown-thing:80"
    assert capture.IP_TO_NAME["192.168.0.200"] == "broker"                     # untouched
    assert incident.endpoint_label("broker", 4444) == "broker:4444"           # untouched


def test_display_text_replaces_only_the_reports_own_labels():
    r = {"how": {"patterns": [{"label": "broker:4444"}]}}
    assert incident.display_text("8 connections to broker:4444 every ~30 s", r) == \
        "8 connections to 192.168.0.200:4444 every ~30 s"
    assert incident.display_text("the broker credentials", r) == "the broker credentials"
    assert incident.display_text("broker:44445", r) == "broker:44445"


def test_the_not_contained_line_is_sentence_case_with_the_address():
    c = {"available": True, "device": "esp32-02", "watching": ["broker:4444"],
         "quiet_needed_seconds": 90.0, "last_seen_seconds": 100.0, "quiet_seconds": 39.0,
         "contained": False}
    line = incident.containment_line(c, 1_789_379_977.0)
    clock = incident.clock_text(100.0, 1_789_379_977.0)
    assert line == ("Not contained yet. Last connection to 192.168.0.200:4444 at %s, 39 s ago. "
                    "Containment is confirmed after 90 s with none." % clock)
    assert "NOT YET" not in line and "broker" not in line
    done = dict(c, contained=True, contained_seconds=190.0, last_seen_id="C1")
    assert incident.containment_line(done).startswith("Contained at 00:03:10: esp32-02 has made "
                                                      "no connection to 192.168.0.200:4444")


@pytest.mark.parametrize("name", ["incident", "incident_later", "contained", "stopped"])
def test_the_live_page_never_shows_broker_4444(tmp_path, name):
    state = fresh(fixture(name))
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    shown = texts(at)
    assert "broker:4444" not in shown
    assert "192.168.0.200:4444" in shown
    for frame in at.dataframe:
        assert "broker:4444" not in frame.value.to_string()


def test_the_strip_under_an_incident_band_reads_in_sentence_case(tmp_path):
    state = fresh(fixture("incident"))
    place(tmp_path, state)
    shown = texts(render(tmp_path, session=state["session"]))
    assert "Not contained yet. Last connection to 192.168.0.200:4444 at " in shown
    assert "Containment is confirmed after 90 s with none." in shown
    assert "NOT YET CONTAINED" not in shown


# --------------------------------------------------------------------------
# The designed report
# --------------------------------------------------------------------------

def test_the_designed_report_has_the_mockups_parts_and_no_broker():
    state = fixture("contained")
    page = incident.render_html(state["incident"], state["addresses"])
    for part in ("Attack started on", "to detect", "to acknowledge", "to contain",
                 "What happened", "Timeline", "How it was found", "Why we believe it",
                 "Attack techniques seen (MITRE ATT&amp;CK)", "What to do",
                 "Evidence and limits", "Severity high", "Contained", "@page { size: A4"):
        assert part in page, part
    assert "broker:4444" not in page and "192.168.0.200:4444" in page
    assert "<script" not in page.lower()
    body = page.split("</style>")[1]
    assert "http" not in body and "<link" not in page and "@import" not in page


def test_render_escapes_everything_that_comes_from_data():
    state = copy.deepcopy(fixture("incident"))
    r = state["incident"]
    evil = "<img src=x onerror=alert(1)>"
    r["session"] = evil
    r["where"]["named"] = evil
    r["how"]["patterns"][0]["label"] = evil + ":4444"
    r["what_happened"]["sentence"] = evil
    r["why"]["evidence_ids"] = [evil]
    r["flagged"] = [evil]
    page = incident.render_html(r, {evil: evil})
    assert "<img" not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page


def test_a_report_with_no_incident_renders_a_short_page():
    page = incident.render_html({"status": "no incident", "session": "q",
                                 "what_happened": {"sentence": "No incident: nothing."}})
    assert "No incident" in page and "What to do" not in page


def test_an_acknowledged_report_shows_the_time_to_acknowledge():
    state = fixture("incident")
    alert = state["first_alert"]
    ack = incident.acknowledgement(alert["raised_epoch"] + 14, alert)
    facts = incident.design_facts(incident.with_acknowledgement(state["incident"], ack))
    assert ("14 s", "to acknowledge") in facts["keys"]
    assert any(w == "Acknowledged by operator" for _, w, _ in facts["timeline"])


def test_baseline_minutes_are_never_drawn_as_alerts():
    r = copy.deepcopy(fixture("contained")["incident"])
    r["why"]["series"] = [{"window": 0, "score": 5.0, "baseline": True, "over": True},
                          {"window": 13, "score": 5.2, "baseline": False, "over": True}]
    bars = incident.design_facts(r)["bars"]
    assert [b["over"] for b in bars] == [False, True]


# --------------------------------------------------------------------------
# The PDF
# --------------------------------------------------------------------------

def test_no_browser_means_no_pdf_and_no_error(tmp_path, monkeypatch):
    page = tmp_path / "r.html"
    page.write_text("<!DOCTYPE html><p>x</p>", encoding="utf-8")
    monkeypatch.setattr(incident, "find_browser", lambda: None)
    assert incident.html_to_pdf(page) is None
    assert not (tmp_path / "r.pdf").exists()
    assert incident.html_to_pdf(tmp_path / "missing.html") is None
    # a "browser" that runs but writes nothing
    assert incident.html_to_pdf(page, browser=str(tmp_path / "not-a-browser.exe")) is None


@pytest.mark.skipif(incident.find_browser() is None, reason="needs Edge or Chrome")
def test_edge_prints_the_designed_report_to_a_pdf(tmp_path):
    state = fixture("contained")
    html_file = incident.write_html(state["incident"], tmp_path)
    pdf = incident.html_to_pdf(html_file)
    assert pdf is not None and pdf.read_bytes()[:5] == b"%PDF-"
    pages = pdf.read_bytes().count(b"/Type /Page") - pdf.read_bytes().count(b"/Type /Pages")
    assert 1 <= pages <= 2                       # two pages at most


def test_the_engine_prints_the_pdf_at_stop(tmp_path, monkeypatch):
    engine = live.LiveSession(tmp_path / "s", reader=lambda path: [], data_dir=tmp_path / "data")
    engine.report_file = tmp_path / "reports" / "s.html"
    made = []
    monkeypatch.setattr(incident, "html_to_pdf",
                        lambda path: made.append(path) or Path(str(path).replace(".html", ".pdf")))
    monkeypatch.setattr(live, "WRITE_PDF", True)
    engine._write_pdf()
    assert made == [engine.report_file]
    assert engine.state()["pdf_file"].endswith("s.pdf")
    # switched off (the tests' default): no browser is started
    monkeypatch.setattr(live, "WRITE_PDF", False)
    engine.pdf_file = None
    engine._write_pdf()
    assert len(made) == 1 and engine.state()["pdf_file"] is None


# --------------------------------------------------------------------------
# The live page's report area
# --------------------------------------------------------------------------

def test_the_report_area_follows_the_report_design(tmp_path):
    state = fresh(fixture("contained"))
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    shown = texts(at)
    for part in ("Incident report", "INC-", "Severity rule: Critical", "Timeline",
                 "Attack techniques seen (MITRE ATT&CK)", "T1571", "What to do",
                 "Template wording, built from the measurements."):
        assert part in shown, part
    labels = [e.label for e in at.expander]
    assert "Full technical detail (all eight sections)" in labels
    assert "8. What we are not sure about" in shown          # inside the collapsed section
    buttons = [b.label for b in at.button]
    assert "Create PDF" in buttons                            # no engine PDF for this fixture
    assert [d.proto.label for d in at.get("download_button")] == ["Download HTML"]


def test_a_stopped_session_offers_the_engines_pdf(tmp_path):
    state = fresh(fixture("stopped"))
    pdf = tmp_path / "fixture.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")
    state["pdf_file"] = str(pdf)
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    assert [d.proto.label for d in at.get("download_button")] == ["Download PDF", "Download HTML"]
    assert "Create PDF" not in [b.label for b in at.button]
