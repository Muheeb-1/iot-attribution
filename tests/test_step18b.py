"""
Tests for Step 18b: a rejoin minute is one with a DHCP broadcast sent from
0.0.0.0 - a device that has no address yet - and not a Windows DHCP INFORM,
which laptop-i3 sends from the address it already has.

Also here: src/scenario.py refuses to overwrite an existing answer file
unless --force, and refuses BEFORE it sends the trigger (the 12 Nov mistake:
rehearsal_02 started with --run rehearsal_01).

Unit tests run anywhere; the acceptance tests use the gitignored captures and
skip cleanly without them. The numbers pinned here are the ones recorded in
docs/LIVE_PLAN.md section 7, "Step 18b".
"""

import json
from functools import lru_cache
from pathlib import Path

import pandas as pd
import pytest

from src import attribute, capture, detect, evaluate, live, runs, scenario

ROOT = Path(__file__).resolve().parents[1]
ANSWERS = ROOT / "groundtruth"
SEGMENTS = ROOT / "pcap" / "segments"
REHEARSALS = {"rehearsal_01": ROOT / "pcap" / "live" / "rehearsal_01.pcapng",
              "rehearsal_02": ROOT / "pcap" / "live" / "rehearsal_02.pcapng"}
BASELINES = [ROOT / "pcap" / "baseline.pcapng", ROOT / "pcap" / "baseline2.pcapng"]
LAB = ["dev-a", "dev-b"]
LAPTOP = "2c:6d:c1:3e:7a:9c"
ESP32_02 = "30:76:f5:e4:eb:60"
ROUTER = "c0:3a:55:43:f3:18"


@pytest.fixture
def rules(monkeypatch):
    def use(which):
        for (module, name), value in zip(evaluate.RULE_SWITCHES, evaluate.RULES[which]):
            monkeypatch.setattr(module, name, value)
    return use


def dhcp(t, mac, src_ip, sport=68, dport=67, dst_mac="ff:ff:ff:ff:ff:ff",
         dst_ip="255.255.255.255"):
    return {"frame.time_epoch": str(t), "frame.len": "342",
            "eth.src": mac, "eth.dst": dst_mac, "ip.src": src_ip, "ip.dst": dst_ip,
            "ipv6.src": "", "ipv6.dst": "", "ip.proto": "17",
            "tcp.srcport": "", "tcp.dstport": "", "tcp.flags.syn": "", "tcp.flags.ack": "",
            "udp.srcport": str(sport), "udp.dstport": str(dport), "arp.opcode": ""}


# --------------------------------------------------------------------------
# The flow table carries "sent from 0.0.0.0"
# --------------------------------------------------------------------------

def test_a_join_from_0_0_0_0_is_marked_and_an_inform_is_not():
    frame = capture.build_flows([
        dhcp(1000.0, ESP32_02, "0.0.0.0"),            # DISCOVER: no address yet
        dhcp(1000.5, ESP32_02, "0.0.0.0"),            # REQUEST
        dhcp(1200.0, LAPTOP, "192.168.0.218"),        # INFORM: from its own address
    ])
    marks = dict(zip(frame["src"], frame[capture.SRC_UNASSIGNED]))
    assert marks == {"esp32-02": True, "laptop-i3": False}
    assert list(frame.columns) == capture.FLOW_COLUMNS
    assert frame[capture.SRC_UNASSIGNED].dtype == bool


def test_only_the_initiator_s_packets_count():
    # The router answering a flow from 0.0.0.0 does not make it the router's
    # join, and a reply sent TO 0.0.0.0 does not mark a flow the board began.
    frame = capture.build_flows([
        dhcp(1000.0, ESP32_02, "192.168.0.160", sport=5000, dport=53,
             dst_mac=ROUTER, dst_ip="192.168.0.254"),
        dhcp(1000.1, ROUTER, "0.0.0.0", sport=53, dport=5000,
             dst_mac=ESP32_02, dst_ip="192.168.0.160"),
    ])
    assert len(frame) == 1 and not frame[capture.SRC_UNASSIGNED].iloc[0]


def test_the_eight_original_columns_are_unchanged():
    assert capture.COLUMNS == ["conn_id", "t", "src", "dst", "dport",
                               "bytes_out", "bytes_in", "pkts"]
    assert capture.FLOW_COLUMNS == capture.COLUMNS + ["src_unassigned"]
    assert list(capture.build_flows([]).columns) == capture.FLOW_COLUMNS


# --------------------------------------------------------------------------
# The rejoin rule reads it
# --------------------------------------------------------------------------

def table(records):
    """[(t, src, dst, dport, unassigned)] -> a flow table with the new column."""
    df = pd.DataFrame(records, columns=["t", "src", "dst", "dport", "src_unassigned"])
    df.insert(0, "conn_id", ["C%06d" % i for i in range(len(df))])
    df["bytes_out"], df["bytes_in"], df["pkts"] = 342, 0, 1
    return df


CASES = table([
    (695.3, "dev-a", "broadcast", 67, True),     # a real rejoin
    (130.0, "dev-b", "broadcast", 67, False),    # an INFORM
    (400.0, "dev-b", "broadcast", 67, False),    # another INFORM
])


def test_an_inform_is_not_a_rejoin_and_a_join_is():
    assert detect.rejoin_minutes(CASES, LAB, 12) == {"dev-a": {11: 695.3}}


def test_step_18_rule_still_available_and_still_catches_both():
    assert detect.rejoin_minutes(CASES, LAB, 12, needs_unassigned=False) == \
        {"dev-a": {11: 695.3}, "dev-b": {2: 130.0, 6: 400.0}}


def test_the_switch_is_read_when_called(monkeypatch):
    monkeypatch.setattr(detect, "REJOIN_NEEDS_UNASSIGNED", False)
    assert "dev-b" in detect.rejoin_minutes(CASES, LAB, 12)
    monkeypatch.setattr(detect, "REJOIN_NEEDS_UNASSIGNED", True)
    assert "dev-b" not in detect.rejoin_minutes(CASES, LAB, 12)


def test_a_table_without_the_column_has_no_rejoins():
    """Runs saved before Step 18b and simulated runs: the fact was never
    recorded, so nothing is left out (and nothing crashes)."""
    old = CASES.drop(columns=["src_unassigned"])
    assert detect.rejoin_minutes(old, LAB, 12) == {}
    assert detect.rejoin_minutes(old, LAB, 12, needs_unassigned=False) == \
        {"dev-a": {11: 695.3}, "dev-b": {2: 130.0, 6: 400.0}}


needs_simulated = pytest.mark.skipif(not runs.data_path("run_000").exists(),
                                     reason="needs data/run_000 (python -m src.generate)")


@needs_simulated
def test_a_simulated_run_scores_the_same_under_step18_and_new(rules):
    run = runs.load_run("run_000")
    rules("step18")
    a = detect.detect_run(run)
    rules("new")
    b = detect.detect_run(run)
    assert a.scores == b.scores and a.onsets == b.onsets and b.rejoins == {}


# --------------------------------------------------------------------------
# scenario.py: never overwrite an answer file by accident
# --------------------------------------------------------------------------

def _answer(run_id="r"):
    from datetime import datetime, timezone
    return scenario.build_answer("esp32-02", run_id, datetime.now(timezone.utc),
                                 "192.168.0.200", 1883, "192.168.0.200", 4444)


def test_write_answer_refuses_an_existing_file_unless_forced(tmp_path):
    path = scenario.write_answer(_answer(), tmp_path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        scenario.write_answer(_answer(), tmp_path)
    assert path.read_bytes() == before
    scenario.write_answer(_answer(), tmp_path, force=True)
    assert json.loads(path.read_text(encoding="utf-8"))["run_id"] == "r"


def test_main_refuses_before_sending_the_trigger(tmp_path, monkeypatch, capsys):
    sent = []
    monkeypatch.setattr(scenario, "ANSWER_DIR", tmp_path)
    monkeypatch.setattr(scenario, "publish_trigger", lambda *a, **k: sent.append(a))
    (tmp_path / "taken.json").write_text("{}", encoding="utf-8")

    assert scenario.main(["--run", "taken", "--origin", "esp32-03"]) == 1
    assert sent == []                                        # nothing was attacked
    assert (tmp_path / "taken.json").read_text(encoding="utf-8") == "{}"
    assert "REFUSED" in capsys.readouterr().err

    assert scenario.main(["--run", "fresh", "--origin", "esp32-03"]) == 0
    assert len(sent) == 1 and (tmp_path / "fresh.json").exists()

    assert scenario.main(["--run", "taken", "--origin", "esp32-03", "--force"]) == 0
    assert len(sent) == 2
    assert json.loads((tmp_path / "taken.json").read_text(encoding="utf-8"))["origin"] \
        == "esp32-03"


def test_dry_run_warns_but_touches_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(scenario, "ANSWER_DIR", tmp_path)
    monkeypatch.setattr(scenario, "publish_trigger", lambda *a, **k: pytest.fail("sent"))
    (tmp_path / "taken.json").write_text("{}", encoding="utf-8")
    assert scenario.main(["--run", "taken", "--dry-run"]) == 0
    assert "WOULD BE REFUSED" in capsys.readouterr().out
    assert (tmp_path / "taken.json").read_text(encoding="utf-8") == "{}"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["taken.json"]


# --------------------------------------------------------------------------
# Acceptance on the real captures (skip cleanly when they are absent)
# --------------------------------------------------------------------------

def _tshark():
    try:
        return capture.find_tshark()
    except FileNotFoundError:
        return None


@lru_cache(maxsize=None)
def _packets(path: str):
    return tuple(capture.read_packets(Path(path), _tshark()))


def _origin(run_id):
    return json.loads((ANSWERS / ("%s.json" % run_id)).read_text(encoding="utf-8"))["origin"]


SEGMENT_FILES = sorted(SEGMENTS.glob("live_batch_*.pcapng")) if SEGMENTS.is_dir() else []
ALL_14 = [(p.stem, p) for p in SEGMENT_FILES] + list(REHEARSALS.items())
have_all = (len(SEGMENT_FILES) == 12 and all(p.exists() for p in REHEARSALS.values())
            and all(runs.meta_path(r).exists() for r, _ in ALL_14)
            and all((ANSWERS / ("%s.json" % r)).exists() for r, _ in ALL_14)
            and _tshark() is not None)
needs_all = pytest.mark.skipif(not have_all, reason="needs the 12 segments, both rehearsal "
                               "captures, their run metas and answer files, and tshark")
needs_baselines = pytest.mark.skipif(not all(p.exists() for p in BASELINES) or _tshark() is None,
                                     reason="needs pcap/baseline*.pcapng and tshark")


def _scored(run_id, pcap):
    run = runs.load_run(run_id)
    run.connections = capture.build_flows(list(_packets(str(pcap))))
    detection = detect.detect_run(run)
    return run, detection, attribute.attribute_run(run, detection)


@needs_all
def test_fourteen_of_fourteen_and_rejoins_only_for_esp32_02_in_rehearsal_01(rules):
    rules("new")
    correct, rejoins = 0, {}
    for run_id, pcap in ALL_14:
        run, det, result = _scored(run_id, pcap)
        correct += result.named == _origin(run_id)
        assert "laptop-i3" not in det.onsets, run_id
        assert "laptop-i3" not in det.skipped, run_id
        rejoins.update({"%s/%s" % (run_id, d): sorted(w) for d, w in det.rejoins.items()})
    assert correct == 14
    assert rejoins == {"rehearsal_01/esp32-02": [11]}


@needs_all
def test_rehearsal_02_is_right_under_every_rule(rules):
    """The first session the Step 18 rules never saw: esp32-03, both ways."""
    for which in ("old", "step18", "new"):
        rules(which)
        _, det, result = _scored("rehearsal_02", REHEARSALS["rehearsal_02"])
        assert result.named == "esp32-03" == _origin("rehearsal_02"), which
        assert sorted(det.onsets) == ["esp32-03"], which


@needs_all
def test_rehearsal_02_live_laptop_never_crosses_the_line_in_a_whole_minute(tmp_path):
    session = live.replay(REHEARSALS["rehearsal_02"], "r2", folder=tmp_path / "r2",
                          data_dir=tmp_path / "data", speed=0, save=False, quiet=True)
    answer = json.loads((ANSWERS / "rehearsal_02.json").read_text(encoding="utf-8"))
    assert session.first_alert["device"] == "esp32-03"
    assert 224.0 <= session.first_alert["closed_epoch"] - answer["start_epoch"] <= 226.0
    assert session.result.named == "esp32-03" and session.result.confidence_percent == 100
    run = session.run
    whole = int(run.capture_seconds // run.window_seconds)    # the last minute is a stub
    laptop = session.detection.scores["laptop-i3"]
    over = [w for w, v in laptop.items()
            if run.baseline_windows <= w < whole and v > detect.THRESHOLD]
    assert over == []
    assert session.detection.rejoins == {}


@needs_baselines
def test_attack_free_laptop_is_judged_in_8_of_10_sessions_was_3(rules):
    seen = {}
    for which in ("step18", "new"):
        rules(which)
        records = evaluate.false_alarm_sessions(BASELINES, session_seconds=1500,
                                                baseline_seconds=720)
        assert not any(r["false_alarm"] for r in records)
        with_laptop = [r for r in records if "laptop-i3" in r["devices_seen"]]
        assert len(with_laptop) == 10
        seen[which] = sorted(r["session"] for r in with_laptop if "laptop-i3" in r["skipped"])
        if which == "new":
            assert not any(r["rejoin_minutes"] for r in records)
    assert seen == {"step18": [0, 1, 3, 4, 5, 6, 9], "new": [3, 5]}
