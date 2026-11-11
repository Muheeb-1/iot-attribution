"""
The live engine (src/live.py) - Step 15.

Two kinds of test live here.

PLAIN TESTS use a fake file reader and hand-written packets, so they need no
tshark and no capture files. They pin the engine's own rules: the newest file
is never read while the capture runs, only closed minutes are scored, a bad
file is reported rather than fatal, and state.json is always valid JSON.

ACCEPTANCE TESTS play each of the twelve real attack captures in
pcap/segments/ through the live path - cut into 10-second files, dropped into
a watched folder one by one - and check the result against the offline
pipeline run on the same capture. They skip cleanly when pcap/segments/ is
absent (a fresh clone has no raw captures: they are gitignored).

The acceptance tests read the answer files in groundtruth/ to know when each
attack was triggered. That is allowed here: tests mark the homework, the rule
is only that nothing in src/ except evaluate.py may read the answers.
"""

import ast
import json
import math
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src import attribute, capture, detect, live, runs

ROOT = Path(__file__).resolve().parents[1]
SEGMENTS = ROOT / "pcap" / "segments"
ANSWERS = ROOT / "groundtruth"

ESP32_02 = "30:76:f5:e4:eb:60"
BROKER = "cc:28:aa:75:4e:bd"
T0 = 1_800_000_000.0          # an arbitrary capture start, in epoch seconds


# --------------------------------------------------------------------------
# Hand-written packets and a fake reader
# --------------------------------------------------------------------------

def packet(t, src_mac=ESP32_02, dst_mac=BROKER, src_ip="192.168.0.160",
           dst_ip="192.168.0.200", dport=1883, sport=50000):
    """One TCP SYN, shaped exactly like a row from capture.read_packets."""
    p = {field: "" for field in capture.TSHARK_FIELDS}
    p.update({
        "frame.time_epoch": "%.6f" % (T0 + t), "frame.len": "74",
        "eth.src": src_mac, "eth.dst": dst_mac, "ip.src": src_ip, "ip.dst": dst_ip,
        "ip.proto": "6", "tcp.srcport": str(sport), "tcp.dstport": str(dport),
        "tcp.flags.syn": "1", "tcp.flags.ack": "0",
    })
    return p


def steady_file(k, seconds=10):
    """File k of a perfectly steady device: one connection every 10 s."""
    return [packet(10.0 * k + i * 10.0, sport=50000 + k) for i in range(seconds // 10)]


def write_fake(folder, k, packets):
    """A 'capture file' holding JSON, named like a dumpcap ring file."""
    path = Path(folder) / ("ring_%05d_20261111120000.pcapng" % k)
    path.write_text(json.dumps(packets), encoding="utf-8")
    return path


def fake_reader(path):
    text = Path(path).read_text(encoding="utf-8")
    if text.startswith("BROKEN"):
        raise RuntimeError("tshark failed reading %s:\nsomething went wrong" % path)
    return json.loads(text)


def session(tmp_path, baseline=480, **kwargs):
    folder = tmp_path / "live" / "s1"
    folder.mkdir(parents=True)
    return live.LiveSession(folder, baseline_seconds=baseline, session="s1",
                            data_dir=tmp_path / "data", reader=fake_reader, **kwargs)


def read_state(live_session):
    return json.loads((live_session.folder / live.STATE_FILE).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Plain tests: the engine's own rules
# --------------------------------------------------------------------------

@pytest.mark.parametrize("now,expected", [
    (None, 0), (0.0, 0), (64.9, 0), (65.0, 1), (124.99, 1), (125.0, 2), (725.0, 12),
])
def test_a_minute_closes_five_seconds_after_it_ends(now, expected):
    assert live.closed_window_count(now) == expected


def test_ring_files_are_oldest_first_and_only_capture_files(tmp_path):
    for name in ["ring_00002_x.pcapng", "ring_00001_x.pcapng", "ring_00010_x.pcap",
                 "state.json", "STOP", "ring_00011_x.pcapng.part", ".hidden.pcapng"]:
        (tmp_path / name).write_text("x")
    assert [p.name for p in live.ring_files(tmp_path)] == [
        "ring_00001_x.pcapng", "ring_00002_x.pcapng", "ring_00010_x.pcap"]
    assert live.ring_files(tmp_path / "missing") == []


def test_json_safe_removes_everything_json_would_choke_on():
    value = {1: np.float64("nan"), "b": [np.int64(3), float("inf"), np.bool_(True)],
             "c": Path("x"), "d": (1.5, -math.inf)}
    out = live.json_safe(value)
    assert out == {"1": None, "b": [3, None, True], "c": "x", "d": [1.5, None]}
    json.dumps(out, allow_nan=False)


def test_state_file_is_written_atomically_and_is_valid_json(tmp_path):
    path = tmp_path / "state.json"
    live.write_state(path, {"score": float("nan"), "w": {12: np.float32(4.5)}})
    assert json.loads(path.read_text()) == {"score": None, "w": {"12": 4.5}}
    assert not (tmp_path / "state.json.tmp").exists()


@pytest.mark.parametrize("baseline", [450, 420, 0])
def test_baseline_must_be_whole_minutes_and_at_least_eight(tmp_path, baseline):
    with pytest.raises(ValueError):
        live.LiveSession(tmp_path, baseline_seconds=baseline, reader=fake_reader)


def test_waiting_before_any_file_and_the_state_says_so(tmp_path):
    s = session(tmp_path)
    state = s.update()
    assert state["phase"] == live.WAITING
    assert read_state(s)["phase"] == live.WAITING
    assert state["packets"] == 0 and state["now_seconds"] is None


def test_the_newest_file_is_skipped_until_a_newer_one_exists(tmp_path):
    s = session(tmp_path)
    write_fake(s.folder, 0, steady_file(0))
    s.update()
    assert s.files_read == [] and s.phase == live.WAITING, \
        "the only file is the newest one: the capture may still be writing it"

    write_fake(s.folder, 1, steady_file(1))
    s.update()
    assert s.files_read == ["ring_00000_20261111120000.pcapng"]
    assert s.phase == live.LEARNING

    state = s.finish(save=False)
    assert s.files_read == ["ring_00000_20261111120000.pcapng",
                            "ring_00001_20261111120000.pcapng"], "STOP reads the newest too"
    assert state["phase"] == live.STOPPED
    assert read_state(s)["phase"] == live.STOPPED


def test_bad_files_are_reported_not_crashed_on(tmp_path):
    s = session(tmp_path)
    write_fake(s.folder, 0, steady_file(0))
    (s.folder / "ring_00001_20261111120000.pcapng").write_bytes(b"")          # empty
    (s.folder / "ring_00002_20261111120000.pcapng").write_text("BROKEN")      # unreadable
    write_fake(s.folder, 3, [{"frame.time_epoch": str(T0 + 30)}])             # no ethernet
    write_fake(s.folder, 4, steady_file(4))
    write_fake(s.folder, 5, steady_file(5))                                    # newest

    state = s.update()
    problems = {p["file"][:10]: p["problem"] for p in state["problems"]}
    assert problems["ring_00001"].startswith("empty file")
    assert problems["ring_00002"].startswith("unreadable")
    assert problems["ring_00003"] == "no readable packets"
    assert len(s.files_read) == 2 and state["packets"] == 2
    assert read_state(s)["problems"] == state["problems"]

    # A bad file is reported once, not on every cycle.
    s.update()
    assert len(s.problems) == 3
    s.finish(save=False)
    assert len(s.problems) == 3 and len(s.files_read) == 3


def test_a_file_from_the_past_is_reported_and_skipped(tmp_path):
    s = session(tmp_path)
    write_fake(s.folder, 0, steady_file(5))
    write_fake(s.folder, 1, steady_file(0))     # 50 s earlier than what was just read
    write_fake(s.folder, 2, steady_file(6))
    s.update()
    assert [p["file"][:10] for p in s.problems] == ["ring_00001"]
    assert "back in time" in s.problems[0]["problem"]


def test_phases_and_state_on_a_steady_capture(tmp_path):
    """
    Twelve minutes of a perfectly regular device, baseline eight minutes.
    LEARNING lasts until the eighth minute has CLOSED (480 s + 5 s grace),
    then MONITORING - nothing changes, so nothing is abnormal. Every cycle
    leaves a state.json that parses, and STOP saves an ordinary run.
    """
    s = session(tmp_path, baseline=480)
    phases = []
    for k in range(73):                       # 0 .. 730 s
        write_fake(s.folder, k, steady_file(k))
        state = s.update()
        assert read_state(s)["phase"] == state["phase"]
        phases.append((state["now_seconds"], state["phase"]))

    learning = [now for now, ph in phases if ph == live.LEARNING]
    monitoring = [now for now, ph in phases if ph == live.MONITORING]
    assert max(learning) < 485 <= min(monitoring)
    assert all(ph != live.INCIDENT for _, ph in phases)

    state = s.update()
    assert state["devices"]["esp32-02"]["seen"] is True
    assert state["devices"]["esp32-02"]["strikes"] == 0
    assert state["devices"]["esp32-01"]["seen"] is False
    assert state["devices"]["esp32-02"]["latest_score"] is not None
    assert state["baseline_remaining_seconds"] == 0.0

    final = s.finish()
    assert final["phase"] == live.STOPPED and final["saved_run"] == "s1"
    run = runs.load_run("s1", tmp_path / "data")
    assert run.baseline_seconds == 480 and len(run.connections) == 73
    meta = json.loads(runs.meta_path("s1", tmp_path / "data").read_text())
    assert meta["capture_start_epoch"] == pytest.approx(T0)
    assert meta["live"]["files_read"] == 73


SECTION_6_FIELDS = (
    "session phase updated_epoch capture_start_epoch now_seconds baseline_seconds "
    "baseline_remaining_seconds packets flows devices threshold onsets ranking named "
    "abstained confidence_percent path edges report first_alert_epoch contained_epoch "
    "verdict_changes").split()


def test_state_has_every_field_the_plan_promises(tmp_path):
    s = session(tmp_path)
    state = s.update()
    missing = [f for f in SECTION_6_FIELDS if f not in state]
    assert not missing
    for name in capture.DEVICE_KINDS:
        assert set(state["devices"][name]) >= {"latest_score", "strikes", "onset",
                                                "scores_by_window"}


def test_live_uses_the_pipeline_and_never_the_attack_or_marking_code():
    """
    Live mode must reuse the existing functions, and must not import the
    scenario driver (which knows the answer) or the marking script (which
    reads it).
    """
    tree = ast.parse((ROOT / "src" / "live.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported |= {node.module or ""} | {a.name for a in node.names}
        elif isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
    assert not {"scenario", "evaluate", "src.scenario", "src.evaluate",
                "generate", "src.generate"} & imported
    source = (ROOT / "src" / "live.py").read_text(encoding="utf-8")
    for call in ("capture.read_packets", "capture.build_flows", "detect.detect_run",
                 "attribute.attribute_run", "report.build_evidence",
                 "report.template_brief", "capture.save_run"):
        assert call in source, "live.py must reuse %s" % call


# --------------------------------------------------------------------------
# Real captures
# --------------------------------------------------------------------------

def _tools_ready():
    try:
        capture.find_tshark()
    except FileNotFoundError:
        return False
    return True


SEGMENT_FILES = sorted(SEGMENTS.glob("live_batch_*.pcapng")) if SEGMENTS.is_dir() else []
needs_segments = pytest.mark.skipif(
    not SEGMENT_FILES or not _tools_ready(),
    reason="pcap/segments/live_batch_*.pcapng (or tshark) not available on this machine")
RUN_IDS = [p.stem for p in SEGMENT_FILES] or ["live_batch_01"]


@needs_segments
def test_ten_second_files_hold_exactly_the_packets_of_the_original(tmp_path):
    """
    Reading a capture as 10-second files must give the same packets as reading
    it whole - with editcap, and with the tshark fallback used when editcap is
    missing. Checked on the first minute of a real capture.
    """
    tshark = capture.find_tshark()
    small = tmp_path / "first_minute.pcapng"
    import subprocess
    subprocess.run([tshark, "-r", str(SEGMENT_FILES[0]), "-Y", "frame.time_relative < 60",
                    "-F", "pcapng", "-w", str(small)], check=True, capture_output=True)
    whole = capture.read_packets(small, tshark)
    assert len(whole) > 100

    by_editcap = live.split_capture(small, tmp_path / "e")
    by_tshark = live.split_capture(small, tmp_path / "t", editcap=str(tmp_path / "no-editcap"))
    for files in (by_editcap, by_tshark):
        assert 6 <= len(files) <= 7
        pieces = [p for f in files for p in capture.read_packets(f, tshark)]
        assert pieces == whole


@pytest.fixture(scope="module")
def replays(tmp_path_factory):
    """
    Every real attack capture, once through the live path and once offline.
    Run in parallel: each replay is ~100 tshark reads, which is most of the
    time, and those run as separate processes.
    """
    if not SEGMENT_FILES or not _tools_ready():
        pytest.skip("no segments")
    base = tmp_path_factory.mktemp("replays")
    data_dir = base / "data"

    def one(segment):
        run_id = segment.stem
        invalid = []

        def check(session, state):
            try:
                text = (session.folder / live.STATE_FILE).read_text(encoding="utf-8")
                parsed = json.loads(text)
                assert parsed["phase"] in live.PHASES
            except Exception as exc:          # recorded, asserted in the test
                invalid.append(repr(exc))

        session = live.replay(segment, run_id, folder=base / "live" / run_id,
                              data_dir=data_dir, speed=0, on_cycle=check, quiet=True)

        offline_id = run_id + "_offline"
        capture.capture_to_run(segment, run_id=offline_id, baseline_seconds=720,
                               data_dir=data_dir)
        run = runs.load_run(offline_id, data_dir)
        detection = detect.detect_run(run)
        result = attribute.attribute_run(run, detection)
        return run_id, {"live": session, "invalid": invalid, "run": run,
                        "detection": detection, "result": result, "data_dir": data_dir}

    with ThreadPoolExecutor(max_workers=6) as pool:
        return dict(pool.map(one, SEGMENT_FILES))


@needs_segments
@pytest.mark.parametrize("run_id", RUN_IDS)
def test_live_final_verdict_equals_the_offline_pipeline(replays, run_id):
    r = replays[run_id]
    s, offline = r["live"], r["result"]
    assert s.phase == live.STOPPED and not s.problems

    assert s.detection.onsets == r["detection"].onsets
    assert s.result.ranking == offline.ranking
    assert s.result.named == offline.named
    assert s.result.abstained == offline.abstained
    assert s.result.confidence == pytest.approx(offline.confidence)
    assert s.result.path == offline.path

    # The saved live session is the same flow table as the offline conversion,
    # and as the run the published table was scored from, when it is on disk.
    saved = runs.load_run(run_id, r["data_dir"])
    pd.testing.assert_frame_equal(saved.connections, r["run"].connections)
    assert saved.baseline_seconds == 720
    published = runs.data_path(run_id)
    if published.exists():
        pd.testing.assert_frame_equal(saved.connections, pd.read_parquet(published))


@needs_segments
@pytest.mark.parametrize("run_id", RUN_IDS)
def test_first_incident_is_raised_when_the_third_abnormal_minute_closes(replays, run_id):
    s = replays[run_id]["live"]
    answer = json.loads((ANSWERS / ("%s.json" % run_id)).read_text(encoding="utf-8"))
    trigger = answer["start_epoch"]
    alert = s.first_alert
    assert alert is not None and not alert["found_at_stop"]

    # The closing moment is the end of the device's third abnormal scored
    # minute, plus the grace.
    det = s.detection
    w0 = det.onset_windows[alert["device"]]
    third = sorted(w for w in det.scores[alert["device"]] if w >= w0)[2]
    assert alert["closed_seconds"] == (third + 1) * 60 + live.GRACE_SECONDS

    # Raised at the first cycle that had read that far - not before, not later.
    first = next(i for i, (_, ph) in enumerate(s.cycles) if ph == live.INCIDENT)
    assert s.cycles[first][0] >= alert["closed_seconds"]
    assert s.cycles[first - 1][0] < alert["closed_seconds"]
    assert all(ph != live.INCIDENT for _, ph in s.cycles[:first])

    # Never before the attack was triggered.
    assert alert["closed_epoch"] > trigger
    assert alert["raised_epoch"] > trigger

    # Where the attacked board is the first to trip, 229-230 s after the trigger.
    if alert["device"] == answer["origin"]:
        assert 229.0 <= alert["closed_epoch"] - trigger <= 231.0


@needs_segments
@pytest.mark.parametrize("run_id", RUN_IDS)
def test_state_json_was_valid_at_every_cycle(replays, run_id):
    r = replays[run_id]
    assert r["invalid"] == []
    assert len(r["live"].cycles) > 100
