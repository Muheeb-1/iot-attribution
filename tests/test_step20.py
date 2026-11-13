"""
Step 20a (13 Nov): scoring the first live session, and fallback rung 3.

Two things are checked here.

1. evaluate.live_timing - "time to detect" and "contained" for a session the
   live engine recorded. It needs the trigger time from the answer file, so it
   lives in evaluate.py; these tests pin down the arithmetic.

2. The replay page's run list. The saved live_batch_* runs and rehearsal_01
   were converted under the pre-Step-18 rules, and the page (which analyses
   with today's rules) named the right board in only 4 of those 12 batch runs.
   src/reconvert.py converts each capture again into a new lab_* run marked
   "replaces"; runs.replay_runs hides the old ones. The acceptance test below
   opens every real capture the page offers, analyses it the way the page
   does, and checks the board against the answer file.
"""

import json
from pathlib import Path

import pandas as pd
import pytest

from src import attribute, capture, detect, evaluate, reconvert, runs

ROOT = Path(__file__).resolve().parents[1]
ANSWERS = ROOT / "groundtruth"
RESULTS = ROOT / "results"


def _meta(run_id, **extra):
    meta = {"run_id": run_id, "scenario": "capture", "device_names": ["a", "b"],
            "devices": [], "window_seconds": 60, "capture_seconds": 600,
            "baseline_seconds": 300, "baseline_windows": 5, "n_connections": 1}
    meta.update(extra)
    return meta


def _save(data_dir: Path, run_id, **extra):
    pd.DataFrame({"t": [1.0], "src": ["a"], "dst": ["b"], "dport": [80],
                  "bytes_out": [1], "bytes_in": [1], "pkts": [1],
                  "conn_id": ["C1"]}).to_parquet(runs.data_path(run_id, data_dir))
    runs.meta_path(run_id, data_dir).write_text(json.dumps(_meta(run_id, **extra)))


# --------------------------------------------------------------------------
# The replay list
# --------------------------------------------------------------------------

def test_a_replaced_run_is_hidden_from_the_replay_list_but_still_on_disk(tmp_path):
    _save(tmp_path, "live_batch_01")
    _save(tmp_path, "lab_batch_01", replaces="live_batch_01")
    _save(tmp_path, "run_000")
    assert runs.replaced_by(tmp_path) == {"live_batch_01": "lab_batch_01"}
    assert runs.replay_runs(tmp_path) == ["lab_batch_01", "run_000"]
    assert runs.list_runs(data_dir=tmp_path) == ["lab_batch_01", "live_batch_01", "run_000"]


def test_with_nothing_replaced_the_replay_list_is_every_run(tmp_path):
    _save(tmp_path, "run_000")
    _save(tmp_path, "easy_000")
    assert runs.replay_runs(tmp_path) == runs.list_runs(data_dir=tmp_path)


def test_a_broken_meta_file_does_not_break_the_list(tmp_path):
    _save(tmp_path, "run_000")
    (tmp_path / "junk.meta.json").write_text("{not json")
    assert runs.replay_runs(tmp_path) == ["run_000"]


def test_the_replaces_link_is_loaded_with_the_run(tmp_path):
    _save(tmp_path, "lab_batch_01", replaces="live_batch_01")
    _save(tmp_path, "run_000")
    assert runs.load_run("lab_batch_01", tmp_path).replaces == "live_batch_01"
    assert runs.load_run("run_000", tmp_path).replaces is None


def test_the_new_prefix_cannot_be_picked_up_by_the_old_sets():
    """--prefix live_batch / rehearsal must keep scoring exactly the old runs."""
    for old, new, _ in reconvert.RECONVERSIONS:
        for prefix in ("live_batch", "rehearsal", "live_session", "run", "easy"):
            assert not new.startswith(prefix + "_"), new
    assert len(reconvert.RECONVERSIONS) == 13


def test_reconvert_keeps_the_old_settings_and_never_touches_the_old_files(tmp_path, monkeypatch):
    _save(tmp_path, "live_batch_01", capture_start_epoch=1000.5, baseline_seconds=420,
          baseline_windows=7, live={"first_alert": {"device": "x"}})
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    pcap = tmp_path / "seg.pcapng"
    pcap.write_bytes(b"")
    monkeypatch.setattr(capture, "find_tshark", lambda explicit=None: "tshark")
    packet = {"frame.time_epoch": "1000.0", "frame.len": "100", "eth.src": "aa:aa:aa:aa:aa:aa",
              "eth.dst": "bb:bb:bb:bb:bb:bb", "ip.src": "192.168.0.160", "ip.dst": "192.168.0.200",
              "ipv6.src": "", "ipv6.dst": "", "ip.proto": "6", "tcp.srcport": "50000",
              "tcp.dstport": "4444", "tcp.flags.syn": "1", "tcp.flags.ack": "0",
              "udp.srcport": "", "udp.dstport": "", "arp.opcode": ""}
    monkeypatch.setattr(capture, "read_packets", lambda path, binary: [packet])

    meta = reconvert.reconvert("live_batch_01", "lab_batch_01", pcap, data_dir=tmp_path)

    assert meta["replaces"] == "live_batch_01"
    assert meta["baseline_seconds"] == 420 and meta["baseline_windows"] == 7
    assert meta["capture_start_epoch"] == 1000.5
    assert "live" not in meta                      # that described the old session
    assert meta["reconverted"]["src_unassigned_column"] is True
    saved = json.loads(runs.meta_path("lab_batch_01", tmp_path).read_text())
    assert saved == meta
    assert capture.SRC_UNASSIGNED in pd.read_parquet(runs.data_path("lab_batch_01", tmp_path))
    for name, content in before.items():
        assert (tmp_path / name).read_bytes() == content, name


def test_reconvert_refuses_to_overwrite_without_force(tmp_path, monkeypatch):
    _save(tmp_path, "live_batch_01")
    _save(tmp_path, "lab_batch_01", replaces="live_batch_01")
    pcap = tmp_path / "seg.pcapng"
    pcap.write_bytes(b"")
    monkeypatch.setattr(capture, "find_tshark", lambda explicit=None: "tshark")
    monkeypatch.setattr(capture, "read_packets", lambda path, binary: [])
    with pytest.raises(FileExistsError):
        reconvert.reconvert("live_batch_01", "lab_batch_01", pcap, data_dir=tmp_path)


# --------------------------------------------------------------------------
# Answers for a re-converted run, and live timings
# --------------------------------------------------------------------------

def _answer(folder: Path, run_id, origin="esp32-02", start=1000.0):
    folder.mkdir(exist_ok=True)
    (folder / ("%s.json" % run_id)).write_text(json.dumps(
        {"run_id": run_id, "origin": origin, "chain": [origin], "start_epoch": start,
         "true_onset_epoch": {origin: start}}))


def test_a_reconverted_run_is_scored_against_the_answer_of_the_run_it_replaces(tmp_path):
    _answer(tmp_path, "live_batch_05", origin="esp32-02")
    run = runs.Run("lab_batch_05", "capture", pd.DataFrame(), ["a"], replaces="live_batch_05")
    assert evaluate.load_answer_for_run(run, tmp_path)["origin"] == "esp32-02"
    # Its own answer file, if there is one, wins.
    _answer(tmp_path, "lab_batch_05", origin="esp32-03")
    assert evaluate.load_answer_for_run(run, tmp_path)["origin"] == "esp32-03"


def test_an_ordinary_run_without_an_answer_still_says_how_to_fix_it(tmp_path):
    run = runs.Run("run_123", "hard", pd.DataFrame(), ["a"])
    with pytest.raises(FileNotFoundError, match="no answer file"):
        evaluate.load_answer_for_run(run, tmp_path)


def test_live_timing_arithmetic(tmp_path):
    data, answers = tmp_path / "data", tmp_path / "gt"
    data.mkdir()
    _save(data, "live_session_09", live={
        "first_alert": {"device": "esp32-02", "closed_epoch": 1215.0,
                        "raised_epoch": 1220.3, "found_at_stop": False},
        "containment": {"device": "esp32-02", "contained": True,
                        "last_seen_epoch": 1240.0, "contained_epoch": 1330.0}})
    _answer(answers, "live_session_09", start=1000.0)
    row = evaluate.live_timing("live_session_09", data_dir=data, groundtruth_dir=answers)
    assert row["alert_right"] is True
    assert row["detect_seconds"] == 220.3
    assert row["window_closed_seconds"] == 215.0
    assert row["acted_within_seconds"] == 19.7
    assert row["contained"] is True and row["contained_seconds"] == 109.7
    assert row["contained_device"] == "esp32-02"


def test_live_timing_wrong_device_and_never_contained(tmp_path):
    data, answers = tmp_path / "data", tmp_path / "gt"
    data.mkdir()
    _save(data, "s", live={"first_alert": {"device": "laptop-i3", "raised_epoch": 1600.0},
                           "containment": {"contained": False, "last_seen_epoch": 1700.0}})
    _answer(answers, "s", start=1000.0)
    row = evaluate.live_timing("s", data_dir=data, groundtruth_dir=answers)
    assert row["alert_right"] is False and row["detect_seconds"] == 600.0
    assert row["contained"] is False
    assert row["contained_seconds"] is None and row["acted_within_seconds"] is None


def test_a_run_not_recorded_live_has_no_timing(tmp_path):
    _save(tmp_path, "live_batch_01")
    assert evaluate.live_timing("live_batch_01", data_dir=tmp_path,
                                groundtruth_dir=tmp_path) is None


# --------------------------------------------------------------------------
# Acceptance on the real data (skipped when it is not on this machine)
# --------------------------------------------------------------------------

def _has_answer(run_id):
    run = runs.load_run(run_id)
    return (ANSWERS / ("%s.json" % run_id)).exists() or (
        run.replaces and (ANSWERS / ("%s.json" % run.replaces)).exists())


REAL = [r for r in runs.replay_runs() if not r.startswith(("run_", "easy_"))] \
    if runs.DATA_DIR.is_dir() else []
have_lab = all(runs.data_path(new).exists() for _, new, _ in reconvert.RECONVERSIONS)
needs_lab = pytest.mark.skipif(not have_lab or not ANSWERS.is_dir(),
                               reason="needs the lab_* runs (python -m src.reconvert) "
                                      "and the answer files")


@needs_lab
def test_every_real_capture_the_replay_page_offers_names_the_right_board():
    """The point of rung 3: whatever real capture is picked in a demo, it is right."""
    checked = []
    for run_id in REAL:
        if not _has_answer(run_id):
            continue
        run = runs.load_run(run_id)
        detection = detect.detect_run(run)          # exactly what app.analyse does
        result = attribute.attribute_run(run, detection)
        origin = evaluate.load_answer_for_run(run)["origin"]
        assert not result.abstained and result.named == origin, (run_id, result.named)
        checked.append(run_id)
    assert len(checked) >= 13, checked


@needs_lab
def test_the_old_rule_runs_are_hidden_and_kept_unchanged():
    listed = set(runs.replay_runs())
    for old, new, _ in reconvert.RECONVERSIONS:
        assert old not in listed and new in listed
        old_meta = json.loads(runs.meta_path(old).read_text(encoding="utf-8"))
        assert "replaces" not in old_meta
        assert "multicast_as_broadcast" not in old_meta     # still the pre-Step-18 table


@needs_lab
def test_the_saved_lab_runs_give_the_published_new_rule_table():
    """
    lab_batch_NN saved = live_batch_NN re-converted on the fly by
    `evaluate --pcap-dir`; so their per-run scores must equal
    results/table_live_fixed_per_run.csv (the Step 18b table).
    """
    published = pd.read_csv(RESULTS / "table_live_fixed_per_run.csv").set_index("run_id")
    for n in range(1, 13):
        record = evaluate.evaluate_one("lab_batch_%02d" % n)
        row = published.loc["live_batch_%02d" % n]
        for column in ("origin", evaluate.V5_FIXED, "confidence", "abstained", "flagged",
                       "B4 earliest onset"):
            assert record[column] == row[column] or (
                pd.isna(row[column]) and record[column] == ""), (n, column)


@pytest.mark.skipif(not runs.meta_path("live_session_01").exists()
                    or not (ANSWERS / "live_session_01.json").exists(),
                    reason="needs data/live_session_01 and its answer file")
def test_live_session_01_as_scored_on_13_nov():
    row = evaluate.live_timing("live_session_01")
    assert row["origin"] == "esp32-02" and row["alert_right"]
    assert row["detect_seconds"] == pytest.approx(220.3, abs=0.1)
    assert row["contained"] and row["contained_device"] == "esp32-02"
    assert row["contained_seconds"] == pytest.approx(109.8, abs=0.1)
    assert evaluate.evaluate_one("live_session_01")[evaluate.V5_FIXED] == 1
