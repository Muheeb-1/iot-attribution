"""
Step 22 (prepared 13 Nov, not yet flashed): the realistic beacon payload.

Two things are checked without any hardware:

1. src/listener.py turns a beacon into a readable "attacker received:" block
   and keeps a per-board profile. These tests pin the parsing and the
   formatting, including the old test-firmware beacon and non-JSON junk.

2. The firmware's three rotating beacon parts, as plain strings here, are
   valid JSON, fit in 200 bytes even at their largest, never contain the
   Wi-Fi password macro, and together carry the fields the task asked for.
   (The .ino is not compiled here; this guards the SHAPE of what it sends.)

Why detection is unaffected is argued in the module docstring and checked on
a real capture in test_step22_detection.py-style form at the bottom: the
feature builder reads addresses, counts, sizes and timing, never payload
bytes, so changing the payload cannot move a feature.
"""

import json
import re
from pathlib import Path

import pytest

from src import capture, features, listener, runs

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "firmware" / "sensor" / "sensor.ino"


# --------------------------------------------------------------------------
# The listener
# --------------------------------------------------------------------------

def _pad(obj: dict, size: int = 200) -> bytes:
    """A beacon as the board sends it: compact JSON, padded with spaces to size."""
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    assert len(raw) <= size
    return raw + b" " * (size - len(raw))


def test_a_padded_json_beacon_is_parsed():
    body = {"dev": "esp32-02", "part": "1/3", "ip": "192.168.0.160"}
    assert listener.parse_beacon(_pad(body)) == body


def test_non_json_is_not_parsed_but_is_still_shown():
    assert listener.parse_beacon(b"\x00\xffnope") is None
    block = listener.format_beacon(b"\x00\xffnope", "1.2.3.4:5", "12:00:00")
    assert "not JSON" in block and "attacker received" in block


def test_the_block_labels_fields_and_hides_nothing_sensitive():
    body = {"dev": "esp32-02", "part": "1/3", "mac": "24:6F:28:AB:CD:EF",
            "ip": "192.168.0.160", "ssid": "lab-net", "rssi": -58}
    block = listener.format_beacon(_pad(body), "192.168.0.160:5000", "12:00:00")
    assert "MAC address" in block and "24:6F:28:AB:CD:EF" in block
    assert "Wi-Fi network name" in block and "lab-net" in block
    assert "192.168.0.160" in block


def test_readings_are_shown_as_temperature_and_humidity():
    body = {"dev": "esp32-02", "part": "3/3", "readings": [[120, 2413, 5120]]}
    block = listener.format_beacon(_pad(body), "192.168.0.160:5000", "12:00:00")
    # temp/hum are sent as hundredths and shown as real units (fix, 13 Nov:
    # live_session_02's listener printed "2452 C, 5387 %").
    assert "recent readings" in block and "#120" in block
    assert "#120: 24.13 C, 51.20 %" in block
    assert "2413 C" not in block


def test_readings_hundredths_edge_values():
    body = {"dev": "esp32-02", "part": "3/3",
            "readings": [[1, 2452, 5387], [2, -5, 7], [3, -1250, 10000]]}
    block = listener.format_beacon(_pad(body), "192.168.0.160:5000", "12:00:00")
    assert "#1: 24.52 C, 53.87 %" in block
    assert "#2: -0.05 C, 0.07 %" in block
    assert "#3: -12.50 C, 100.00 %" in block


def test_the_old_test_firmware_beacon_still_reads():
    old = b'{"id":"esp32-02","beacon":7,"t":900,"pad":"' + b"x" * 150 + b'"}'
    block = listener.format_beacon(old, "192.168.0.160:5000", "12:00:00")
    assert "device id" in block and "esp32-02" in block
    assert "filler" in block                       # the pad is summarised, not dumped


def test_a_profile_accumulates_across_the_three_parts(monkeypatch):
    monkeypatch.setattr(listener, "PROFILES", {})
    listener.remember({"dev": "esp32-02", "part": "1/3", "mac": "AA", "n": 1})
    listener.remember({"dev": "esp32-02", "part": "2/3", "broker": "b:1883", "n": 2})
    profile = listener.remember({"dev": "esp32-02", "part": "3/3",
                                 "readings": [[1, 2, 3]], "n": 3})
    assert profile["mac"] == "AA" and profile["broker"] == "b:1883"
    assert "readings" in profile
    assert "part" not in profile and "n" not in profile   # bookkeeping is dropped
    assert "esp32-02" in listener.summary()


def test_say_never_raises_on_an_unprintable_character(capsys):
    listener.say("café \U0001f600 \ud800")        # lone surrogate etc.
    # no exception is the test; something is printed
    assert capsys.readouterr().out


# --------------------------------------------------------------------------
# The firmware's beacon parts, as strings (no compiler needed)
# --------------------------------------------------------------------------

# The three parts the firmware builds, with every %-field at a plausible
# maximum, so "fits in 200 bytes" is tested against the worst case.
MAX = {
    "dev": "esp32-02", "n": 4294967295, "up": 4294967295,
    "mac": "24:6F:28:AB:CD:EF", "ip": "192.168.137.200", "gw": "192.168.137.1",
    "ssid": "X" * 32,                              # SSIDs are at most 32 chars
    "rssi": -100, "broker": "192.168.0.200:1883", "client": "esp32-02",
    "heap": 4294967295,
}
PARTS = [
    {"dev": MAX["dev"], "part": "1/3", "n": MAX["n"], "up": MAX["up"],
     "mac": MAX["mac"], "ip": MAX["ip"], "gw": MAX["gw"], "ssid": MAX["ssid"],
     "rssi": MAX["rssi"]},
    {"dev": MAX["dev"], "part": "2/3", "n": MAX["n"], "up": MAX["up"],
     "broker": MAX["broker"], "client": MAX["client"],
     "sub": ["ctrl/esp32-02"], "pub": "iot/esp32-02", "heap": MAX["heap"]},
    {"dev": MAX["dev"], "part": "3/3", "n": MAX["n"], "up": MAX["up"],
     "readings": [[MAX["n"], -9999, 9999]] * 4},
]


@pytest.mark.parametrize("part", PARTS, ids=["1/3", "2/3", "3/3"])
def test_each_beacon_part_is_valid_json_and_fits_in_200_bytes(part):
    raw = json.dumps(part, separators=(",", ":"))
    assert json.loads(raw) == part
    assert len(raw.encode("utf-8")) <= listener_beacon_bytes()


def test_the_three_parts_cover_everything_the_task_asked_for():
    keys = set().union(*PARTS)
    for wanted in ("dev", "mac", "ip", "ssid", "broker", "sub", "pub",
                   "up", "readings"):
        assert wanted in keys, wanted


def listener_beacon_bytes() -> int:
    """BEACON_BYTES from the firmware, so the test tracks the real limit."""
    text = FIRMWARE.read_text(encoding="utf-8", errors="replace")
    return int(re.search(r"#define\s+BEACON_BYTES\s+(\d+)", text).group(1))


def test_the_firmware_never_sends_the_wifi_password():
    """
    The beacon builder must not format WIFI_PASS into anything. We read only
    the beacon code (buildBeaconPart / sendBeacon), so the normal Wi-Fi join
    using WIFI_PASS is not a false positive.
    """
    text = FIRMWARE.read_text(encoding="utf-8", errors="replace")
    start = text.index("int buildBeaconPart")
    end = text.index("void loop()")
    beacon_code = text[start:end]
    assert "WIFI_PASS" not in beacon_code
    assert "WiFi.SSID()" in beacon_code            # the NAME is sent, deliberately
    assert "psk" not in beacon_code.lower()


def test_the_firmware_still_beacons_once_per_30s_one_connection():
    """
    Detection depends on the rhythm, so guard it: one beacon per interval, and
    the part only ROTATES (no extra connections). If this changes, the
    'detection unaffected' claim must be re-measured.
    """
    text = FIRMWARE.read_text(encoding="utf-8", errors="replace")
    assert "#define BEACON_EVERY_MS    30000UL" in text
    assert "beaconPart = (beaconPart + 1) % 3" in text
    # exactly one connect() in the beacon path
    assert text.count("beacon.connect(") == 1


# --------------------------------------------------------------------------
# Why detection is unaffected: features never read payload bytes
# --------------------------------------------------------------------------

def test_capture_asks_tshark_for_no_payload_field():
    """The detector's whole input comes from these fields - none is payload."""
    assert not any("payload" in f or "data" in f for f in capture.TSHARK_FIELDS)


def test_the_flow_table_has_no_column_for_what_a_beacon_says():
    """
    Confirmed on a replay: the flow table (what the whole pipeline analyses) is
    only ids, time, addresses, port, byte counts, packet count and the join
    flag. The beacon's contents have nowhere to live, so Step 22 cannot move
    any number. Checked both on the schema and on a real saved capture.
    """
    payloadish = [c for c in capture.FLOW_COLUMNS
                  if any(w in c.lower() for w in ("payload", "data", "content", "body"))]
    assert payloadish == []
    if runs.data_path("live_session_01").exists():
        columns = list(runs.load_run("live_session_01").connections.columns)
        assert columns == capture.FLOW_COLUMNS


def test_features_are_computed_from_counts_sizes_and_timing_only():
    """
    The seven features are addresses, counts, byte totals and timing. Changing
    what a beacon SAYS (same size, same cadence) cannot move any of them.
    """
    import pandas as pd
    # Two beacons 30 s apart - the Step 22 cadence. The payload column below is
    # never named in FEATURE_COLUMNS, so build_features cannot read it.
    base = dict(src="esp32-02", dst="broker", dport=4444,
                bytes_out=200, bytes_in=170, pkts=8, src_unassigned=False)
    conns = pd.DataFrame([{**base, "t": 100.0, "conn_id": "C1", "payload": "part 1/3"},
                          {**base, "t": 130.0, "conn_id": "C2", "payload": "part 2/3"}])
    table = features.build_features(conns, ["esp32-02"], baseline_seconds=0,
                                    window_seconds=60)
    assert set(features.FEATURE_COLUMNS) <= set(table.columns)
    assert "payload" not in table.columns
    # The feature list is addresses/counts/sizes/timing - nothing payload-shaped.
    assert not any("payload" in c or "content" in c for c in features.FEATURE_COLUMNS)


# --------------------------------------------------------------------------
# Step 22 measured (13 Nov): live_session_02, the first session on the new
# firmware - and the operator's note that its laptop loop was off.
# --------------------------------------------------------------------------

from src import evaluate, runs  # noqa: E402

_GT = Path(__file__).resolve().parent.parent / "groundtruth"


def test_live_session_02_carries_its_note_and_nothing_else_does():
    assert evaluate.session_note("live_session_02") == "laptop loop off"
    assert evaluate.session_note("live_session_01") == ""
    assert evaluate.session_note("live_batch_05") == ""


def _fake_record(run_id, **_):
    methods = (evaluate.BASELINE_NAMES + evaluate.V5_METHODS
               + ["fair " + b for b in evaluate.BASELINE_NAMES])
    return {"run_id": run_id, **{m: 1 for m in methods},
            "abstained": False, "abstained_prototype": False}


def test_exclude_leaves_a_session_out_of_the_same_set(monkeypatch):
    monkeypatch.setattr(evaluate.runs, "list_runs",
                        lambda prefix=None: ["s_01", "s_02", "s_03"])
    monkeypatch.setattr(evaluate, "evaluate_one", _fake_record)
    records, summary, _ = evaluate.evaluate_scenario("s", limit=2, exclude=["s_02"])
    # --runs is applied first, then the exclusion: s_01 alone, never s_03.
    assert [r["run_id"] for r in records] == ["s_01"]
    assert int(summary["runs"].iloc[0]) == 1
    records, _, _ = evaluate.evaluate_scenario("s", limit=2)
    assert [r["run_id"] for r in records] == ["s_01", "s_02"]


def test_a_note_rides_along_only_on_the_noted_run(monkeypatch):
    monkeypatch.setattr(evaluate.runs, "list_runs",
                        lambda prefix=None: ["live_session_01", "live_session_02"])
    monkeypatch.setattr(evaluate, "evaluate_one", _fake_record)
    records, _, _ = evaluate.evaluate_scenario("live_session", limit=2)
    assert "note" not in records[0]
    assert records[1]["note"] == "laptop loop off"


@pytest.mark.skipif(not runs.meta_path("live_session_02").exists()
                    or not (_GT / "live_session_02.json").exists(),
                    reason="needs data/live_session_02 and its answer file")
def test_live_session_02_as_scored_on_13_nov():
    row = evaluate.live_timing("live_session_02")
    assert row["origin"] == "esp32-03" and row["alert_right"]
    assert row["detect_seconds"] == pytest.approx(196.5, abs=0.2)     # 3 min 16 s
    assert row["contained"] and row["contained_device"] == "esp32-03"
    assert row["contained_clock"] and row["note"] == "laptop loop off"
    assert evaluate.evaluate_one("live_session_02")[evaluate.V5_FIXED] == 1
    # The new firmware's beacons look exactly like the old ones on the wire:
    # one 496-byte connection every 30 s, as in live_session_01.
    flows = runs.load_run("live_session_02").connections
    beacons = flows[flows.dport == 4444]
    assert set(beacons.src) == {"esp32-03"} and len(beacons) == 8
    assert set(beacons.bytes_out) == {496}
    assert beacons.t.diff().dropna().round().eq(30).all()
    # ...and the laptop's loop really was off: 22 flows (614 in session 01).
    assert (flows.src == "laptop-i3").sum() == 22
