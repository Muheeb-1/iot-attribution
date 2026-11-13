"""
Tests for Step 19: the incident report (src/incident.py), the CONTAINED check
in the live engine, the "spread" wording fix in report.template_brief, and
the report on the live page.

Unit tests run anywhere. The acceptance tests use the gitignored captures
(pcap/live/rehearsal_02.pcapng, pcap/segments/) and skip cleanly without them.
The CONTAINED acceptance test replays rehearsal_02 through the live path with
esp32-03's packets removed 275 s after the trigger - what the capture would
have seen had its power been pulled then - because none of the recordings
contains a real containment yet (that is the next hardware run).
"""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from src import attribute, capture, detect, incident, live, report, runs

ROOT = Path(__file__).resolve().parents[1]
ANSWERS = ROOT / "groundtruth"
REHEARSAL_02 = ROOT / "pcap" / "live" / "rehearsal_02.pcapng"
SEGMENTS = ROOT / "pcap" / "segments"
ESP32_03_MAC = "30:76:f5:e5:e5:ac"
SECTIONS = ["what_happened", "when", "where", "how", "why", "impact", "playbook", "unsure"]


def flows(records):
    """[(t, src, dst, dport, bytes_out)] -> a flow table."""
    df = pd.DataFrame(records, columns=["t", "src", "dst", "dport", "bytes_out"])
    df.insert(0, "conn_id", ["C%06d" % i for i in range(len(df))])
    df["bytes_in"] = 170
    df["pkts"] = 8
    df["src_unassigned"] = False
    return df


def beacon_table():
    """dev-a: MQTT every 20 s all along; from 800 s a beacon to broker:4444 every 30 s."""
    records = [(20.0 * k, "dev-a", "broker", 1883, 300) for k in range(60)]
    records += [(800.0 + 30 * k, "dev-a", "broker", 4444, 496) for k in range(6)]
    records += [(810.0, "dev-a", "router", 53, 80), (900.0, "dev-a", "router", 53, 80)]  # 2x: too few
    records += [(820.0 + 10 * k, "dev-a", "broker", 0, 60) for k in range(5)]           # ARP: no port
    return flows(sorted(records))


# --------------------------------------------------------------------------
# Section 4 - the new behaviour, measured
# --------------------------------------------------------------------------

def test_new_patterns_are_new_repeated_destination_ports():
    found = incident.new_patterns(beacon_table(), "dev-a", baseline_seconds=720)
    assert [p["label"] for p in found] == ["broker:4444"]
    p = found[0]
    assert p["count"] == 6 and p["first_seconds"] == 800.0 and p["last_seconds"] == 950.0
    assert p["typical_gap_seconds"] == 30.0
    assert p["typical_bytes_out"] == 496 and p["typical_bytes_in"] == 170
    assert len(p["conn_ids"]) == 5
    assert incident.pattern_sentence("dev-a", p).startswith(
        "dev-a made 6 connections to broker:4444 every ~30 s, ~496 bytes each")


def test_a_pair_used_during_the_baseline_is_not_new():
    table = beacon_table()
    table.loc[len(table)] = ["C999999", 100.0, "dev-a", "broker", 4444, 496, 170, 8, False]
    assert incident.new_patterns(table, "dev-a", 720) == []


def test_labels_and_durations_read_naturally():
    assert incident.endpoint_label("broker", 4444) == "broker:4444"
    assert incident.endpoint_label("broadcast", 0) == "broadcast (no port)"
    assert incident.duration_text(184) == "3 min 04 s" and incident.duration_text(42) == "42 s"
    assert incident.clock_text(3725) == "01:02:05"


# --------------------------------------------------------------------------
# Sections 4 and 6 count the same endpoint the same way
# --------------------------------------------------------------------------

def _single_board_report(onset_seconds):
    """
    A one-board attack: normal MQTT all along, then a broker:4444 beacon from
    800 s every 30 s (14 of them). The onset is passed in, so it can be placed
    AFTER the first beacon - which is what happens on the real captures, where
    three-in-a-row is only confirmed a couple of windows into the attack.
    """
    recs = [(20.0 * k, "dev-a", "broker", 1883, 300) for k in range(72)]
    recs += [(800.0 + 30 * k, "dev-a", "broker", 4444, 496) for k in range(14)]
    run = runs.Run(run_id="syn", scenario="capture", connections=flows(sorted(recs)),
                   device_names=["dev-a"], baseline_seconds=720, baseline_windows=12,
                   capture_seconds=1260, window_seconds=60)
    onset_w = int(onset_seconds // 60)
    scores = {"dev-a": {w: (6.0 if w >= onset_w else 0.5) for w in range(21)}}
    det = detect.Detection(scores=scores, onsets={"dev-a": onset_seconds},
                           onset_windows={"dev-a": onset_w}, threshold=4.0,
                           consecutive=3, window_seconds=60)
    res = attribute.Attribution(named="dev-a", ranking=["dev-a"], shortlist=["dev-a"],
                                confidence=1.0, abstained=False, story_ranking=["dev-a"])
    return incident.build_incident(run, det, res)


def test_impact_counts_the_attack_endpoint_the_same_as_the_how_section():
    # The onset (900 s) is well after the first beacon (800 s). Counting the
    # impact from the onset used to drop those early beacons, so section 4 said
    # 14 and section 6 said 10 for the same broker:4444. They must agree now.
    report = _single_board_report(onset_seconds=900.0)
    s4 = {p["label"]: p["count"] for p in report["how"]["patterns"]}
    s6 = {r["label"]: r["count"] for r in report["impact"]["reach"]["dev-a"]}
    assert s4["broker:4444"] == 14
    assert s6["broker:4444"] == 14                 # was 10 before the fix
    # In general: every endpoint shown in both sections has one shared count.
    for label, count in s4.items():
        assert s6.get(label) == count, label
    assert "x14" in incident.render_text(report)    # the rendered impact line too


# --------------------------------------------------------------------------
# The CONTAINED check
# --------------------------------------------------------------------------

PATTERN = [{"dst": "broker", "dport": 4444, "label": "broker:4444"}]


@pytest.mark.parametrize("now,alert,contained", [
    (1000.0, 930.0, False),     # 50 s since the last beacon at 950
    (1039.9, 930.0, False),     # 89.9 s
    (1040.0, 930.0, True),      # 90 s
    (1040.0, None, False),      # no alert yet: nothing to contain
])
def test_contained_after_90_quiet_seconds_and_only_after_an_alert(now, alert, contained):
    c = incident.containment_status(beacon_table(), "dev-a", PATTERN, now, alert_seconds=alert)
    assert c["available"] and c["last_seen_seconds"] == 950.0
    assert c["contained"] is contained
    if contained:
        assert c["contained_seconds"] == 1040.0
        assert incident.containment_line(c).startswith("CONTAINED at 00:17:20")


def test_without_a_named_device_or_pattern_there_is_no_containment_check():
    assert not incident.containment_status(beacon_table(), None, PATTERN, 2000.0, alert_seconds=1)["available"]
    c = incident.containment_status(beacon_table(), "dev-a", [], 2000.0, alert_seconds=1)
    assert not c["available"] and not c["contained"]
    assert "none have been identified" in incident.containment_line(c)


def test_checksums_list_every_file(tmp_path):
    for name in ("ring_1.pcapng", "ring_2.pcapng"):
        (tmp_path / name).write_bytes(name.encode())
    ev = incident.write_checksums(tmp_path, ["ring_1.pcapng", "ring_2.pcapng", "gone.pcapng"])
    lines = (tmp_path / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    assert ev["files"] == 2 and len(lines) == 2 and len(ev["sha256"]) == 64
    assert lines[0] == "%s  ring_1.pcapng" % incident.sha256_of(tmp_path / "ring_1.pcapng")


def test_addresses_come_from_the_packets_and_skip_0_0_0_0():
    pk = lambda mac, ip: {"eth.src": mac, "ip.src": ip}  # noqa: E731
    found = capture.addresses_from_packets([pk(ESP32_03_MAC, "0.0.0.0"),
                                            pk(ESP32_03_MAC, "192.168.0.203"),
                                            pk("aa:bb:cc:dd:ee:ff", "10.0.0.9")])
    assert found == {"esp32-03": "192.168.0.203"}


# --------------------------------------------------------------------------
# The "spread" wording - report.template_brief and the report itself
# --------------------------------------------------------------------------

def _evidence(flagged):
    names = ["esp32-01", "esp32-02", "esp32-03"]
    return {"named_device": flagged[0], "verdict": "named", "shortlist": flagged[:3],
            "confidence_percent": 100, "confidence_label": "high",
            "devices": [{"device": n, "flagged": n in flagged,
                         "onset": "00:13:00" if n in flagged else None} for n in names],
            "connections": [{"id": "C000001", "from": flagged[0]}]}


def _run():
    return runs.Run(run_id="t", scenario="capture", connections=pd.DataFrame(),
                    device_names=["esp32-01", "esp32-02", "esp32-03"])


def test_one_flagged_device_is_not_called_a_spread():
    brief = report.template_brief(_evidence(["esp32-03"]), _run(), None)
    text = json.dumps(brief.model_dump()).lower()
    assert "spread" not in text
    assert "check the other devices" not in text
    assert "no other device behaved abnormally" in brief.headline.lower()


def test_several_flagged_devices_still_are():
    brief = report.template_brief(_evidence(["esp32-02", "esp32-03"]), _run(), None)
    assert "spread to other devices" in brief.headline
    assert brief.actions[1].action == "Check the other devices listed as affected."


# --------------------------------------------------------------------------
# The whole report, on saved runs
# --------------------------------------------------------------------------

def _analysed(run_id):
    run = runs.load_run(run_id)
    det = detect.detect_run(run)
    return run, det, attribute.attribute_run(run, det)


LIVE_01 = SEGMENTS / "live_batch_01.pcapng"


def _tshark():
    try:
        return capture.find_tshark()
    except FileNotFoundError:
        return None


# The saved data/live_batch_01 was converted under the OLD naming rule (before
# Step 18's C1), so it is re-converted from the raw capture, as in test_step18.
needs_live_01 = pytest.mark.skipif(
    not (runs.meta_path("live_batch_01").exists() and LIVE_01.exists() and _tshark()),
    reason="needs pcap/segments/live_batch_01.pcapng, its run meta, and tshark")


def _live_01():
    run = runs.load_run("live_batch_01")
    run.connections = capture.build_flows(capture.read_packets(LIVE_01, _tshark()))
    det = detect.detect_run(run)
    return run, det, attribute.attribute_run(run, det)
needs_simulated = pytest.mark.skipif(not runs.data_path("run_000").exists(),
                                     reason="needs the simulated runs (python -m src.generate)")


@needs_live_01
def test_a_real_attack_report_is_complete_without_any_language_model(monkeypatch):
    # Any attempt to reach a model would fail loudly.
    monkeypatch.setattr(report, "TRANSPORTS", {})
    run, det, res = _live_01()
    r = incident.build_incident(run, det, res)
    assert r["status"] == "incident" and r["wording"]["source"] == "deterministic"
    for key in SECTIONS:
        assert r.get(key), key
    assert r["how"]["sentences"][0].startswith(
        "esp32-02 made 10 connections to broker:4444 every ~30 s, ~496 bytes each")
    assert "spread" not in r["what_happened"]["sentence"]
    assert r["where"]["named"] == "esp32-02" and "laptop-i3" in r["where"]["cleared"]
    assert [s["step"] for s in r["playbook"]] == ["contain", "preserve", "eradicate",
                                                  "recover", "verify"]
    assert "30:76:f5:e4:eb:60" in r["playbook"][0]["do"][0]
    assert r["when"]["time_to_detect_seconds"] > 0
    json.dumps(r)                                    # plain data
    page = incident.render_html(r)
    for n in range(1, 9):
        assert "<h2>%d. " % n in page
    assert "<script" not in page and "http" not in page.split("</style>")[1]


@needs_simulated
def test_a_simulated_spread_says_spread_and_a_quiet_run_says_no_incident():
    said = None
    for run_id in runs.list_runs("run")[:30]:
        run, det, res = _analysed(run_id)
        if len(det.onsets) > 1 and not res.abstained:
            said = incident.build_incident(run, det, res)["what_happened"]
            break
    assert said is not None and said["spread"] and "spread to" in said["sentence"]
    quiet = runs.Run(run_id="q", scenario="capture", connections=beacon_table().iloc[:5],
                     device_names=["dev-a"], baseline_seconds=60, baseline_windows=1)
    r = incident.build_incident(quiet, detect.Detection(), attribute.Attribution())
    assert r["status"] == "no incident" and "No incident" in incident.render_text(r)
    assert "<h2>2." not in incident.render_html(r)


def test_a_validated_model_headline_is_added_and_anything_else_is_not():
    base = {"status": "incident", "what_happened": {"sentence": "x"}}
    ok = SimpleNamespace(source="llm", brief=SimpleNamespace(headline="Board 3 was hacked."))
    assert incident.wording_from_brief(base, ok)["wording"]["headline"] == "Board 3 was hacked."
    bad = SimpleNamespace(source="LLM_FALLBACK", brief=SimpleNamespace(headline="invented"))
    assert incident.wording_from_brief(base, bad)["wording"]["source"] == "deterministic"
    assert incident.wording_from_brief(base, None)["wording"]["source"] == "deterministic"


def test_incident_module_never_reads_the_answers():
    text = (ROOT / "src" / "incident.py").read_text(encoding="utf-8").lower()
    assert "groundtruth" not in text and "evaluate" not in text.replace("evaluate.py", "")


# --------------------------------------------------------------------------
# Acceptance: rehearsal_02 through the live path
# --------------------------------------------------------------------------

have_r2 = REHEARSAL_02.exists() and (ANSWERS / "rehearsal_02.json").exists() \
    and runs.meta_path("rehearsal_02").exists() and _tshark() is not None
needs_r2 = pytest.mark.skipif(not have_r2, reason="needs pcap/live/rehearsal_02.pcapng, its "
                              "run meta and answer file, and tshark")


def _answer():
    return json.loads((ANSWERS / "rehearsal_02.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def r2_live(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("r2")
    seen = []
    s = live.replay(REHEARSAL_02, "r2", folder=tmp / "r2", data_dir=tmp / "data", speed=0,
                    save=True, quiet=True,
                    on_cycle=lambda sess, st: seen.append(json.loads(json.dumps(
                        live.json_safe(st)))))
    return s, seen, tmp


@needs_r2
def test_rehearsal_02_live_report_at_the_alert(r2_live):
    s, seen, _ = r2_live
    first = next(st for st in seen if st["phase"] == live.INCIDENT)
    r = first["incident"]
    assert r["where"]["named"] == "esp32-03"
    how = r["how"]["sentences"][0]
    assert how.startswith("esp32-03 made ") and \
        " connections to broker:4444 every ~30 s, ~496 bytes each" in how
    assert r["how"]["patterns"][0]["count"] >= 3
    # time to detect: from the first beacon to the moment the engine raised it
    assert r["when"]["alert_kind"] == "raised by the live engine"
    assert 170 <= r["when"]["time_to_detect_seconds"] <= 190
    assert first["containment"]["contained"] is False
    assert "spread" not in r["what_happened"]["sentence"]


@needs_r2
def test_rehearsal_02_live_final_report_equals_the_offline_one(r2_live):
    s, seen, tmp = r2_live
    final = seen[-1]["incident"]
    run = runs.load_run("r2", tmp / "data")
    det = detect.detect_run(run)
    offline = incident.build_incident(run, det, attribute.attribute_run(run, det),
                                      capture_start_epoch=s.capture_start_epoch)
    for key in ("what_happened", "where", "how", "impact"):
        assert final[key] == json.loads(json.dumps(offline[key])), key
    assert final["how"]["patterns"][0]["count"] == 12
    # Section 6 counts broker:4444 the same as section 4 (one count at STOP).
    reach = {r["label"]: r["count"] for r in final["impact"]["reach"]["esp32-03"]}
    assert reach["broker:4444"] == 12
    assert (tmp / "reports" / "r2.html").exists()
    assert (s.folder / "SHA256SUMS.txt").exists()
    assert s.evidence["files"] == len(s.files_read)


@needs_r2
def test_pulling_the_power_gives_contained_90_s_after_the_last_beacon(tmp_path):
    cut = _answer()["start_epoch"] + 275          # after the alert (~+230 s)
    pcap = tmp_path / "cut.pcapng"
    subprocess.run([_tshark(), "-r", str(REHEARSAL_02), "-Y",
                    "!(eth.addr==%s && frame.time_epoch > %.3f)" % (ESP32_03_MAC, cut),
                    "-w", str(pcap), "-F", "pcapng"], check=True, capture_output=True)
    seen = []
    s = live.replay(pcap, "cut", folder=tmp_path / "cut", data_dir=tmp_path / "data",
                    speed=0, save=False, quiet=True,
                    on_cycle=lambda sess, st: seen.append(json.loads(json.dumps(
                        live.json_safe(st)))))
    phases = [p["phase"] for p in s.phase_log]
    assert phases == [live.WAITING, live.LEARNING, live.MONITORING, live.INCIDENT,
                      live.CONTAINED, live.STOPPED]
    c = s.containment
    assert c["contained"] and c["device"] == "esp32-03" and c["watching"] == ["broker:4444"]
    last_beacon = c["last_seen_epoch"]
    assert last_beacon <= cut
    assert c["contained_epoch"] == pytest.approx(last_beacon + 90.0)
    contained_state = next(st for st in seen if st["phase"] == live.CONTAINED)
    assert contained_state["contained_epoch"] == pytest.approx(last_beacon + 90.0)
    assert contained_state["incident"]["status"] == "contained"
    # The verdict does not change because the board went quiet.
    assert s.result.named == "esp32-03"
    html_text = (tmp_path / "reports" / "cut.html").read_text(encoding="utf-8")
    assert "CONTAINED at" in html_text


# --------------------------------------------------------------------------
# The live page
# --------------------------------------------------------------------------

def test_the_page_shows_the_report_and_the_contained_banner(tmp_path):
    from tests.test_live_page import fixture, fresh, place, render, texts
    from dashboard import live_page
    state = fresh(fixture("contained"))
    banner = live_page.headline(state)
    assert banner["kind"] == "success" and banner["title"].startswith("Contained at ")
    rows = {r["device"]: r for r in live_page.device_rows(state)}
    assert rows["esp32-03"]["status"] == "contained"
    assert rows["esp32-03"]["label"].startswith("offline / contained since")
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    shown = texts(at)
    assert "Incident report" in [s.value for s in at.subheader]
    assert "8. What we are not sure about" in shown
    assert "connections to broker:4444 every ~30 s" in shown
    assert len(at.get("download_button")) == 1
