"""
Tests for src/live_capture.py - Step 16b.

The real recorder (dumpcap through Npcap) only works in an Administrator
terminal on the lab laptop, so it cannot run inside the test suite. What CAN
be tested is everything around it, and that is where the demo-breaking
mistakes would be:

- refusing, with instructions, in a terminal that would make dumpcap hang;
- picking the right adapter, or refusing to guess;
- never recording into a folder that holds another session's files;
- writing STOP only when something was recorded, and removing the
  CAPTURING marker whatever happens;
- the engine joining a capture that is already recording instead of
  deleting its files.

The recording loop itself is exercised with a stand-in recorder: a small
Python script that writes ring-style files into the folder and exits, or
runs until it is stopped. The one test that needs the real captures (the
merged file holds exactly the original packets) skips cleanly without them.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from src import capture, live, live_capture

ROOT = Path(__file__).resolve().parents[1]
SEGMENTS = ROOT / "pcap" / "segments"

DUMPCAP_LIST = """\
1. \\Device\\NPF_{D913DCC8-4269-4A52-9617-38FEDDBB418A} (Ethernet)
2. \\Device\\NPF_{11111111-2222-3333-4444-555555555555} (Wi-Fi)
3. \\Device\\NPF_{66666666-7777-8888-9999-000000000000} (Local Area Connection* 10)
4. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)
5. etwdump (Event Tracing for Windows (ETW) reader)
6. randpkt
"""


# --------------------------------------------------------------------------
# The adapter list
# --------------------------------------------------------------------------

def test_dumpcap_list_is_parsed_into_numbers_names_and_descriptions():
    rows = live_capture.parse_interfaces(DUMPCAP_LIST)
    assert [r["number"] for r in rows] == [1, 2, 3, 4, 5, 6]
    assert rows[0]["device"] == live_capture.LAB_INTERFACE
    assert rows[0]["description"] == "Ethernet"
    assert rows[4]["description"] == "Event Tracing for Windows (ETW) reader"
    assert rows[5] == {"number": 6, "device": "randpkt", "description": ""}


def test_noise_lines_are_ignored():
    assert live_capture.parse_interfaces("Capturing on...\n\n  \n") == []


@pytest.fixture
def interfaces():
    return live_capture.parse_interfaces(DUMPCAP_LIST)


def test_with_no_choice_the_lab_adapter_is_used(interfaces):
    assert live_capture.choose_interface(interfaces) == live_capture.LAB_INTERFACE


def test_with_no_choice_and_no_lab_adapter_it_refuses_and_shows_the_list(interfaces):
    others = [r for r in interfaces if r["number"] != 1]
    with pytest.raises(ValueError) as err:
        live_capture.choose_interface(others)
    assert "Wi-Fi" in str(err.value) and "--interface" in str(err.value)


@pytest.mark.parametrize("wanted,expected", [
    ("2", r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"),
    (live_capture.LAB_INTERFACE.lower(), live_capture.LAB_INTERFACE),
    ("ethernet", live_capture.LAB_INTERFACE),
    ("wi-fi", r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"),
    ("loopback", r"\Device\NPF_Loopback"),
])
def test_an_adapter_can_be_picked_by_number_name_or_description(interfaces, wanted, expected):
    assert live_capture.choose_interface(interfaces, wanted) == expected


@pytest.mark.parametrize("wanted", ["9", "bluetooth", "Device"])
def test_a_missing_or_ambiguous_adapter_is_refused_not_guessed(interfaces, wanted):
    with pytest.raises(ValueError):
        live_capture.choose_interface(interfaces, wanted)


# --------------------------------------------------------------------------
# Elevation: refuse before dumpcap can hang
# --------------------------------------------------------------------------

@pytest.mark.parametrize("elevated,admin_only,blocked", [
    (False, True, True),      # the lab laptop in an ordinary terminal
    (False, None, True),      # cannot read Npcap's setting: assume the worst
    (False, False, False),    # Npcap open to everyone
    (True, True, False),      # Administrator terminal
    (None, True, False),      # cannot tell: do not block
])
def test_capture_is_refused_only_where_dumpcap_would_hang(elevated, admin_only, blocked):
    assert live_capture.must_elevate(elevated, admin_only) is blocked


def test_the_elevation_message_says_exactly_what_to_do():
    text = live_capture.elevation_message("live_session_07")
    assert "Run as administrator" in text
    assert "python -m src.live_capture --session live_session_07" in text
    assert "Wireshark" in text and "10 seconds" in text
    assert "python -m src.live_capture --list" in live_capture.elevation_message(None, listing=True)


def test_the_checks_answer_without_raising():
    assert live_capture.is_elevated() in (True, False, None)
    assert live_capture.npcap_admin_only() in (True, False, None)


def test_an_unelevated_terminal_never_starts_dumpcap(monkeypatch, capsys):
    monkeypatch.setattr(live_capture, "is_elevated", lambda: False)
    monkeypatch.setattr(live_capture, "npcap_admin_only", lambda: True)

    def must_not_run(*args, **kwargs):
        raise AssertionError("dumpcap was looked for after the elevation check failed")

    monkeypatch.setattr(live_capture, "find_dumpcap", must_not_run)
    assert live_capture.main(["--session", "s1"]) == 2
    assert "NOT running as Administrator" in capsys.readouterr().err


def test_the_session_name_is_required_unless_listing():
    with pytest.raises(SystemExit):
        live_capture.main([])


# --------------------------------------------------------------------------
# The command and the folder
# --------------------------------------------------------------------------

def test_the_command_starts_a_new_file_every_ten_seconds(tmp_path):
    cmd = live_capture.capture_command("dumpcap", "IFACE", tmp_path)
    assert cmd[:3] == ["dumpcap", "-i", "IFACE"]
    assert "duration:%d" % live.SEGMENT_SECONDS in cmd
    assert cmd[cmd.index("-w") + 1] == str(tmp_path / "ring.pcapng")
    assert "-a" not in cmd
    timed = live_capture.capture_command("dumpcap", "IFACE", tmp_path, duration=60)
    assert timed[-2:] == ["-a", "duration:60"]


def test_files_written_with_that_name_are_what_the_engine_reads(tmp_path):
    """dumpcap turns -w ring.pcapng into ring_00001_<time>.pcapng."""
    (tmp_path / "ring_00001_20261112135857.pcapng").write_bytes(b"x")
    (tmp_path / live.CAPTURE_MARKER).write_text("{}")
    assert [p.name for p in live.ring_files(tmp_path)] == ["ring_00001_20261112135857.pcapng"]


def test_a_folder_with_old_capture_files_is_refused(tmp_path):
    (tmp_path / "ring_00001_x.pcapng").write_bytes(b"x")
    with pytest.raises(FileExistsError):
        live_capture.prepare_capture_folder(tmp_path)
    assert (tmp_path / "ring_00001_x.pcapng").exists()


def test_a_folder_another_capture_is_recording_into_is_refused(tmp_path):
    (tmp_path / live.CAPTURE_MARKER).write_text("{}")
    with pytest.raises(FileExistsError):
        live_capture.prepare_capture_folder(tmp_path)


def test_a_waiting_engine_state_is_kept_and_force_clears_old_files(tmp_path):
    (tmp_path / live.STATE_FILE).write_text("{}")
    live_capture.prepare_capture_folder(tmp_path)          # engine started first: fine
    assert (tmp_path / live.STATE_FILE).exists()

    for name in ("ring_00001_x.pcapng", live.STOP_FILE, live.CAPTURE_MARKER):
        (tmp_path / name).write_text("x")
    live_capture.prepare_capture_folder(tmp_path, force=True)
    assert live.ring_files(tmp_path) == []
    assert not (tmp_path / live.STOP_FILE).exists()
    assert not (tmp_path / live.CAPTURE_MARKER).exists()
    assert (tmp_path / live.STATE_FILE).exists()


def test_stop_is_written_only_when_something_was_recorded(tmp_path):
    (tmp_path / live.CAPTURE_MARKER).write_text("{}")
    assert live_capture.finish_capture(tmp_path, "test") is False
    assert not (tmp_path / live.STOP_FILE).exists()
    assert not (tmp_path / live.CAPTURE_MARKER).exists()

    (tmp_path / live.CAPTURE_MARKER).write_text("{}")
    (tmp_path / "ring_00001_x.pcapng").write_bytes(b"x")
    assert live_capture.finish_capture(tmp_path, "Ctrl+C") is True
    assert "Ctrl+C" in (tmp_path / live.STOP_FILE).read_text()
    assert not (tmp_path / live.CAPTURE_MARKER).exists()


# --------------------------------------------------------------------------
# The recording loop, with a stand-in recorder
# --------------------------------------------------------------------------

FAKE_RECORDER = '''
import shutil, sys, time
from pathlib import Path
folder, count, gap = Path(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
sources = sorted(Path(sys.argv[4]).glob("*.pcapng")) if len(sys.argv) > 4 else []
k = 0
while count < 0 or k < count:
    k += 1
    out = folder / ("ring_%05d_20261112120000.pcapng" % k)
    if sources:
        if k > len(sources):
            break
        shutil.copyfile(sources[k - 1], out)
    else:
        out.write_bytes(b"x" * 100)
    time.sleep(gap)
'''


@pytest.fixture
def recorder(tmp_path):
    script = tmp_path / "fake_recorder.py"
    script.write_text(FAKE_RECORDER, encoding="utf-8")

    def command(folder, count, gap=0.05, sources=None):
        cmd = [sys.executable, str(script), str(folder), str(count), str(gap)]
        return cmd + ([str(sources)] if sources else [])
    return command


def test_a_recording_that_ends_by_itself_leaves_stop_and_no_marker(tmp_path, recorder):
    folder = tmp_path / "live" / "s1"
    live_capture.prepare_capture_folder(folder)
    seen_marker = []

    outcome = live_capture.record(folder, recorder(folder, 3), "IFACE", merge=False,
                                  poll=0.02, progress_every=1e9)
    seen_marker.append((folder / live.CAPTURE_MARKER).exists())

    assert outcome["files"] == 3 and outcome["exit_code"] == 0
    assert outcome["stop_written"] is True
    assert (folder / live.STOP_FILE).exists()
    assert seen_marker == [False]


def test_the_marker_is_there_while_recording(tmp_path, recorder):
    folder = tmp_path / "s1"
    live_capture.prepare_capture_folder(folder)
    process = subprocess.Popen(recorder(folder, -1, gap=0.05))
    try:
        live_capture.write_marker(folder, "IFACE", process.pid)
        assert live.capture_is_recording(folder)
        marker = json.loads((folder / live.CAPTURE_MARKER).read_text())
        assert marker["pid"] == process.pid and marker["interface"] == "IFACE"
    finally:
        live_capture.stop_process(process, grace=0.2)
    live_capture.finish_capture(folder, "test")
    assert not live.capture_is_recording(folder)


def test_a_recorder_that_ignores_the_stop_is_ended_after_the_grace(tmp_path, recorder):
    process = subprocess.Popen(recorder(tmp_path, -1, gap=0.05))
    started = time.monotonic()
    code = live_capture.stop_process(process, grace=0.3)
    assert process.poll() is not None
    assert code is not None
    assert time.monotonic() - started < 10


def test_a_recorder_that_writes_nothing_leaves_no_stop(tmp_path, recorder):
    folder = tmp_path / "s1"
    live_capture.prepare_capture_folder(folder)
    outcome = live_capture.record(folder, recorder(folder, 0), "IFACE", merge=False,
                                  poll=0.02, startup_warning=1e9)
    assert outcome["files"] == 0 and outcome["stop_written"] is False
    assert not (folder / live.STOP_FILE).exists()
    assert not (folder / live.CAPTURE_MARKER).exists()


# --------------------------------------------------------------------------
# The engine and the capture together
# --------------------------------------------------------------------------

def test_the_engine_joins_a_capture_that_is_already_recording(tmp_path):
    """
    Engine started second, or restarted mid-session: it must keep every file -
    even with --force - and read them all from the first.
    """
    folder = tmp_path / "s1"
    folder.mkdir()
    (folder / "ring_00001_x.pcapng").write_bytes(b"x")
    (folder / live.STATE_FILE).write_text("{}")
    (folder / live.CAPTURE_MARKER).write_text("{}")

    assert live._prepare_folder(folder, force=False, join=True) is True
    assert live._prepare_folder(folder, force=True, join=True) is True
    assert (folder / "ring_00001_x.pcapng").exists()


def test_a_finished_or_unmarked_folder_is_not_joined(tmp_path):
    folder = tmp_path / "s1"
    folder.mkdir()
    (folder / "ring_00001_x.pcapng").write_bytes(b"x")
    with pytest.raises(FileExistsError) as err:
        live._prepare_folder(folder, force=False, join=True)
    assert "--replay" in str(err.value)

    (folder / live.CAPTURE_MARKER).write_text("{}")
    (folder / live.STOP_FILE).write_text("stopped")          # capture is over
    with pytest.raises(FileExistsError):
        live._prepare_folder(folder, force=False, join=True)


def test_replay_never_joins(tmp_path):
    """--replay builds its own folder; a marker there must not stop it clearing."""
    folder = tmp_path / "s1"
    folder.mkdir()
    (folder / "ring_00001_x.pcapng").write_bytes(b"x")
    (folder / live.CAPTURE_MARKER).write_text("{}")
    assert live._prepare_folder(folder, force=True) is False
    assert live.ring_files(folder) == []


def test_live_capture_does_not_touch_the_method_or_the_attack():
    """It records; it must not analyse, attack, or mark anything."""
    import ast
    tree = ast.parse((ROOT / "src" / "live_capture.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(a.name for a in node.names)
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    for forbidden in ("scenario", "evaluate", "detect", "attribute", "features"):
        assert not any(forbidden in name for name in imported), forbidden


# --------------------------------------------------------------------------
# With a real capture: recorded files -> engine, and the merged copy
# --------------------------------------------------------------------------

needs_segments = pytest.mark.skipif(
    not (SEGMENTS / "live_batch_01.pcapng").exists() or live_capture.find_mergecap() is None,
    reason="needs pcap/segments/ (gitignored raw captures) and mergecap")


@needs_segments
def test_a_recorded_session_is_read_by_the_engine_and_merged_losslessly(tmp_path, recorder):
    """
    A real capture, cut into 10-second files, "recorded" into a session folder
    by the stand-in: the engine reads every packet of it, and the merged copy
    holds exactly the original packets.
    """
    original = SEGMENTS / "live_batch_01.pcapng"
    sources = tmp_path / "slices"
    live.split_capture(original, sources)
    folder = tmp_path / "live" / "rec_01"
    live_capture.prepare_capture_folder(folder)

    outcome = live_capture.record(folder, recorder(folder, 10_000, gap=0.0, sources=sources),
                                  "IFACE", poll=0.02, progress_every=1e9)
    assert outcome["stop_written"] and outcome["merged"] is not None
    assert outcome["merged"] == tmp_path / "live" / "rec_01.pcapng"
    assert live.ring_files(folder)                      # ring files kept

    tshark = capture.find_tshark()
    want = capture.read_packets(original, tshark)
    assert capture.read_packets(outcome["merged"], tshark) == want

    session = live.LiveSession(folder, baseline_seconds=720, data_dir=tmp_path / "data")
    session.finish(save=False)
    assert len(session.packets) == len(want)
    assert session.problems == []
