"""
Tests for Step 18: the three measured fixes that came out of rehearsal_01.

    C1  capture.MULTICAST_AS_BROADCAST  multicast and 255.255.255.255 are "broadcast"
    C2  features.IAT_IGNORES_BROADCAST  timing regularity ignores "broadcast" connections
    C3  detect.SKIP_REJOIN_MINUTES      a baseline minute in which a device sent a
                                        DHCP broadcast is not normal for that device

Each is a module switch, default ON, so the old rule can still be scored
(evaluate.py --rules old). Two kinds of test:

- unit tests on hand-made packets, flows and feature tables - they run anywhere;
- acceptance tests on the real captures (pcap/live/rehearsal_01.pcapng,
  pcap/segments/live_batch_*.pcapng, pcap/baseline*.pcapng). Those files are
  gitignored, so these skip cleanly on a fresh clone. They pin the measured
  before/after recorded in docs/LIVE_PLAN.md section 7. Like test_live.py they
  read the answer files to know which device was really attacked - tests may;
  src/ (except evaluate.py) may not.
"""

import json
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from dashboard import live_page
from src import attribute, capture, detect, evaluate, features, live, runs

ROOT = Path(__file__).resolve().parents[1]
SEGMENTS = ROOT / "pcap" / "segments"
REHEARSAL = ROOT / "pcap" / "live" / "rehearsal_01.pcapng"
BASELINES = [ROOT / "pcap" / "baseline.pcapng", ROOT / "pcap" / "baseline2.pcapng"]
ANSWERS = ROOT / "groundtruth"
LAB = ["dev-a", "dev-b"]


@pytest.fixture
def rules(monkeypatch):
    """Set the three switches for one test; monkeypatch puts them back after."""
    def use(which):
        for module, name in evaluate.RULE_SWITCHES:
            monkeypatch.setattr(module, name, which == "new")
    return use


def test_all_three_switches_are_on_by_default():
    assert capture.MULTICAST_AS_BROADCAST is True
    assert features.IAT_IGNORES_BROADCAST is True
    assert detect.SKIP_REJOIN_MINUTES is True
    assert evaluate.current_rules() == "new"


def test_rules_can_be_set_old_and_new_and_nothing_else(rules):
    rules("old")
    assert evaluate.current_rules() == "old"
    evaluate.set_rules("new")
    assert evaluate.current_rules() == "new"
    with pytest.raises(ValueError):
        evaluate.set_rules("both")


# --------------------------------------------------------------------------
# C1 - naming multicast "broadcast"
# --------------------------------------------------------------------------

@pytest.mark.parametrize("mac,ip", [
    ("01:00:5e:00:00:fc", "224.0.0.252"),       # LLMNR, IPv4 - laptop-i3's lookups
    ("01:00:5e:00:00:fb", "224.0.0.251"),       # mDNS
    ("01:00:5e:7f:ff:fa", "239.255.255.250"),   # SSDP
    ("33:33:00:01:00:03", "ff02::1:3"),          # LLMNR, IPv6
    ("33:33:00:00:00:fb", "ff02::fb"),           # mDNS, IPv6
    ("aa:bb:cc:dd:ee:ff", "255.255.255.255"),    # all-ones, whatever the MAC
])
def test_multicast_and_all_ones_are_named_broadcast(mac, ip):
    assert capture.endpoint_name(mac, ip) == capture.BROADCAST_NAME


@pytest.mark.parametrize("mac,ip", [
    ("01:00:5e:00:00:fc", "224.0.0.252"),
    ("33:33:00:01:00:03", "ff02::1:3"),
])
def test_with_the_switch_off_multicast_stays_a_raw_address_as_before(mac, ip):
    assert capture.endpoint_name(mac, ip, multicast_as_broadcast=False) == ip


def test_the_switch_is_read_when_called_not_when_defined(monkeypatch):
    monkeypatch.setattr(capture, "MULTICAST_AS_BROADCAST", False)
    assert capture.endpoint_name("01:00:5e:00:00:fc", "224.0.0.252") == "224.0.0.252"
    monkeypatch.setattr(capture, "MULTICAST_AS_BROADCAST", True)
    assert capture.endpoint_name("01:00:5e:00:00:fc", "224.0.0.252") == "broadcast"


def test_ordinary_addresses_are_untouched():
    # A stranger stays visibly a stranger; lab devices keep their names.
    assert capture.endpoint_name("12:34:56:78:9a:bc", "142.250.183.14") == "142.250.183.14"
    assert capture.endpoint_name("", "192.168.0.99") == "192.168.0.99"
    assert capture.endpoint_name("30:76:f5:e4:eb:60", "192.168.0.160") == "esp32-02"
    assert capture.endpoint_name("", "192.168.0.200") == "broker"
    assert capture.endpoint_name("ff:ff:ff:ff:ff:ff", "192.168.0.255") == "broadcast"
    # A non-IP multicast frame was already "broadcast" before Step 18.
    assert capture.endpoint_name("01:00:5e:00:00:01", "", multicast_as_broadcast=False) \
        == "broadcast"


@pytest.mark.parametrize("ip,expected", [
    ("224.0.0.252", True), ("239.255.255.250", True), ("ff02::1:3", True),
    ("255.255.255.255", True), ("192.168.0.255", False), ("192.168.0.200", False),
    ("fe80::1", False), ("", False), ("not-an-ip", False),
])
def test_group_addresses_are_recognised(ip, expected):
    assert capture.is_group_address(ip) is expected


def _packet(t, src_mac, dst_mac, src_ip, dst_ip, sport, dport, length=100):
    return {"frame.time_epoch": str(t), "frame.len": str(length),
            "eth.src": src_mac, "eth.dst": dst_mac, "ip.src": src_ip, "ip.dst": dst_ip,
            "ipv6.src": "", "ipv6.dst": "", "ip.proto": "17",
            "tcp.srcport": "", "tcp.dstport": "", "tcp.flags.syn": "", "tcp.flags.ack": "",
            "udp.srcport": str(sport), "udp.dstport": str(dport), "arp.opcode": ""}


def test_flows_to_multicast_have_broadcast_as_destination(monkeypatch):
    laptop = "2c:6d:c1:3e:7a:9c"
    packets = [_packet(1000.0, laptop, "01:00:5e:00:00:fc", "192.168.0.218", "224.0.0.252",
                       50000, 5355)]
    assert capture.build_flows(packets)["dst"].tolist() == ["broadcast"]
    monkeypatch.setattr(capture, "MULTICAST_AS_BROADCAST", False)
    assert capture.build_flows(packets)["dst"].tolist() == ["224.0.0.252"]


def test_a_saved_run_records_which_naming_rule_built_it(tmp_path):
    frame = capture.build_flows([_packet(1000.0, "2c:6d:c1:3e:7a:9c", "ff:ff:ff:ff:ff:ff",
                                         "192.168.0.218", "255.255.255.255", 68, 67)])
    _, _, meta = capture.save_run(frame, "r", tmp_path / "x.pcapng", baseline_seconds=60,
                                  data_dir=tmp_path)
    assert meta["multicast_as_broadcast"] is True


# --------------------------------------------------------------------------
# C2 - timing regularity ignores broadcast connections
# --------------------------------------------------------------------------

def flows(records):
    """[(t, src, dst, dport)] -> a flow table."""
    df = pd.DataFrame(records, columns=["t", "src", "dst", "dport"])
    df.insert(0, "conn_id", ["C%06d" % i for i in range(len(df))])
    df["bytes_out"] = 100
    df["bytes_in"] = 50
    df["pkts"] = 2
    return df


def laptop_minute(with_chatter: bool):
    """dev-a ticking to the broker every 2 s for a minute, plus (maybe) a
    few broadcast lookups at irregular moments - laptop-i3's two kinds of minute."""
    records = [(2.0 * k + 0.5, "dev-a", "broker", 1883) for k in range(30)]
    if with_chatter:
        records += [(t, "dev-a", "broadcast", 5355) for t in (3.1, 3.4, 17.9, 18.2, 41.0)]
    return flows(records)


def one(table, dev="dev-a", w=0):
    return table[(table["dev"] == dev) & (table["w"] == w)].iloc[0]


def test_broadcast_chatter_no_longer_hides_a_regular_tick():
    quiet = one(features.build_features(laptop_minute(False), LAB, 60))
    chatty = one(features.build_features(laptop_minute(True), LAB, 60))
    chatty_old = one(features.build_features(laptop_minute(True), LAB, 60,
                                             ignore_broadcast=False))
    # Before: the two kinds of minute read very differently (the flip-flop).
    assert chatty_old["iat_reg"] < quiet["iat_reg"] / 3
    # After: identical timing regularity.
    assert chatty["iat_reg"] == pytest.approx(quiet["iat_reg"])


def test_only_iat_reg_changes_the_other_six_still_count_broadcast():
    new = one(features.build_features(laptop_minute(True), LAB, 60))
    old = one(features.build_features(laptop_minute(True), LAB, 60, ignore_broadcast=False))
    for column in features.FEATURE_COLUMNS:
        if column != "iat_reg":
            assert new[column] == old[column], column
    assert new["n_conn"] == 35 and new["n_dst"] == 2


def test_a_device_that_only_broadcasts_scores_unremarkable_timing():
    table = features.build_features(
        flows([(t, "dev-a", "broadcast", 67) for t in (1, 2, 3, 4, 5, 6)]), LAB, 60)
    assert one(table)["iat_reg"] == pytest.approx(1 / 1.05)     # cv = 1.0: "too few to judge"


def test_without_broadcast_traffic_c2_changes_nothing():
    records = [(t, "dev-a", "broker", 1883) for t in np.cumsum(np.full(40, 3.3))]
    records += [(t, "dev-b", "router", 53) for t in np.cumsum(np.full(25, 4.1))]
    table = flows(records)
    pd.testing.assert_frame_equal(
        features.build_features(table, LAB, 60),
        features.build_features(table, LAB, 60, ignore_broadcast=False))


# --------------------------------------------------------------------------
# C3 - a rejoin minute is not normal
# --------------------------------------------------------------------------

def test_rejoin_minutes_are_dhcp_broadcasts_in_the_baseline_by_lab_devices():
    table = flows([
        (695.3, "dev-a", "broadcast", 67),     # rejoin in minute 11: counted
        (697.6, "dev-a", "broadcast", 67),     # same minute, first time kept
        (130.0, "dev-a", "router", 67),        # unicast renewal: not a rejoin
        (200.0, "dev-a", "broadcast", 5355),   # a lookup, not DHCP
        (300.0, "dev-b", "broadcast", 68),     # wrong port
        (900.0, "dev-b", "broadcast", 67),     # after the baseline: not listed
        (10.0, "router", "broadcast", 67),     # not a lab device
        (20.0, "dev-b", "broadcast", 67),      # minute 0: counted
    ])
    found = detect.rejoin_minutes(table, LAB, baseline_windows=12)
    assert found == {"dev-a": {11: 695.3}, "dev-b": {0: 20.0}}


def test_no_traffic_or_no_rejoin_means_nothing_left_out():
    assert detect.rejoin_minutes(pd.DataFrame(), LAB, 12) == {}
    assert detect.rejoin_minutes(flows([(5, "dev-a", "broker", 1883)]), LAB, 12) == {}


def board_table(odd_minute: int | None = 11):
    """
    A board's feature table shaped like esp32-02 in rehearsal_01: 2-3 quiet
    connections a minute, one odd baseline minute with 6, then an "attack" of
    3 connections a minute with a new destination port.
    """
    rows = []
    for w in range(26):
        n_conn = [2, 3][w % 2]
        if w == odd_minute:
            n_conn = 6
        if w >= 13:
            n_conn = 3
        rows.append({"dev": "dev-a", "w": w, "bytes_out": 400 * n_conn, "bytes_in": 300 * n_conn,
                     "n_conn": n_conn, "n_dst": 2 if w == odd_minute else 1,
                     "n_new_ext": 0, "n_peer": 0, "iat_reg": 1.0})
    return pd.DataFrame(rows)


def test_leaving_the_rejoin_minute_out_restores_the_board_s_normal(monkeypatch):
    monkeypatch.setattr(detect, "IsolationForest", None)    # z-score only, deterministic
    table = board_table()
    kept = detect.detect(table, baseline_windows=12)
    left_out = detect.detect(table, baseline_windows=12, rejoins={"dev-a": {11: 695.3}})
    # The odd minute widens the spread of n_dst; leaving it out narrows it, so
    # the attack minutes score higher.
    assert left_out.scores["dev-a"][13] > kept.scores["dev-a"][13]
    # The left-out minute is still scored (and drawn), and recorded.
    assert 11 in left_out.scores["dev-a"]
    assert left_out.rejoins == {"dev-a": {11: 695.3}}


def test_left_out_minutes_are_not_learned_by_the_forest_either():
    table = board_table().sort_values("w")
    plain = detect.robust_scores(table, 12)
    without = detect.robust_scores(table, 12, left_out=[11])
    never_had_it = table[table["w"] != 11]
    clean = detect.robust_scores(never_had_it, 12)
    assert not np.allclose(plain, without)
    # Leaving the odd minute out == the minute never having been in the table,
    # for every other minute - z-score and forest alike.
    assert np.allclose(np.delete(without, 11), clean)


def test_nothing_left_out_is_exactly_the_old_rule():
    table = board_table().sort_values("w")
    assert np.array_equal(detect.robust_scores(table, 12),
                          detect.robust_scores(table, 12, left_out=()))
    a = detect.detect(table, baseline_windows=12)
    b = detect.detect(table, baseline_windows=12, rejoins={})
    assert a.scores == b.scores and a.onsets == b.onsets


def test_the_minimum_baseline_counts_only_the_minutes_actually_used():
    table = board_table()
    # 12 baseline minutes; leave 5 out -> 7 used, below MIN_BASELINE_WINDOWS (8).
    five = {"dev-a": {w: w * 60.0 for w in (0, 2, 4, 6, 8)}}
    result = detect.detect(table, baseline_windows=12, rejoins=five)
    assert result.skipped == ["dev-a"] and "dev-a" not in result.scores
    four = {"dev-a": {w: w * 60.0 for w in (0, 2, 4, 6)}}
    assert "dev-a" in detect.detect(table, baseline_windows=12, rejoins=four).scores
    assert detect.MIN_BASELINE_WINDOWS == 8


def _run(connections, baseline_seconds=720):
    return runs.Run(run_id="t", scenario="capture", connections=connections,
                    device_names=LAB, window_seconds=60, capture_seconds=1500,
                    baseline_seconds=baseline_seconds,
                    baseline_windows=baseline_seconds // 60)


def test_detect_run_finds_the_rejoins_itself_and_obeys_the_switch(monkeypatch):
    records = [(60.0 * w + 5, dev, "broker", 1883) for w in range(20) for dev in LAB]
    records.append((695.3, "dev-a", "broadcast", 67))
    run = _run(flows(records))
    assert detect.detect_run(run).rejoins == {"dev-a": {11: 695.3}}
    monkeypatch.setattr(detect, "SKIP_REJOIN_MINUTES", False)
    assert detect.detect_run(run).rejoins == {}


# --------------------------------------------------------------------------
# Simulated runs: no broadcast destination, so nothing may move
# --------------------------------------------------------------------------

needs_simulated = pytest.mark.skipif(not runs.data_path("run_000").exists(),
                                     reason="needs data/run_000 (python -m src.generate)")


@needs_simulated
@pytest.mark.parametrize("run_id", ["run_000", "run_007", "easy_003"])
def test_simulated_runs_score_identically_under_both_rules(rules, run_id):
    if not runs.data_path(run_id).exists():
        pytest.skip("no %s" % run_id)
    run = runs.load_run(run_id)
    assert not (run.connections["dst"] == capture.BROADCAST_NAME).any()
    rules("new")
    new = detect.detect_run(run)
    rules("old")
    old = detect.detect_run(run)
    assert new.scores == old.scores and new.onsets == old.onsets and new.rejoins == {}


# --------------------------------------------------------------------------
# The live engine and the live page
# --------------------------------------------------------------------------

def test_state_json_lists_the_rejoin_minutes_with_wall_clock_times(tmp_path):
    """
    Fake ring files: esp32-02 connecting to the broker every 10 s, and one
    DHCP broadcast at +395 s (minute 6 of an 8-minute baseline). The state
    must say so already while LEARNING, and still after the baseline - then
    straight from the detector's own list.
    """
    from tests.test_live import T0, packet, session, steady_file, write_fake

    dhcp = packet(395.0, dst_mac="ff:ff:ff:ff:ff:ff", src_ip="0.0.0.0",
                  dst_ip="255.255.255.255", dport=0)
    dhcp.update({"ip.proto": "17", "tcp.srcport": "", "tcp.dstport": "",
                 "tcp.flags.syn": "", "tcp.flags.ack": "",
                 "udp.srcport": "68", "udp.dstport": "67"})
    s = session(tmp_path, baseline=480)
    learning_rejoins, later_rejoins = None, None
    for k in range(60):                               # 0 .. 600 s
        packets = steady_file(k) + ([dhcp] if k == 39 else [])
        write_fake(s.folder, k, packets)
        state = json.loads(json.dumps(live.json_safe(s.update())))
        if state["phase"] == live.LEARNING and state["rejoins"]:
            learning_rejoins = state["rejoins"]
        if state["phase"] == live.MONITORING:
            later_rejoins = state["rejoins"]
    want = {"esp32-02": [{"window": 6, "seconds": 395.0, "epoch": T0 + 395.0}]}
    assert learning_rejoins == want
    assert later_rejoins == want
    assert s.detection.rejoins == {"esp32-02": {6: 395.0}}


def test_the_page_says_which_minute_was_left_out_and_why():
    state = {"capture_start_epoch": 1_800_000_000.0,
             "rejoins": {"esp32-02": [{"window": 11, "seconds": 695.3,
                                       "epoch": 1_800_000_695.3}]}}
    lines = live_page.rejoin_lines(state)
    assert lines == ["esp32-02 rejoined the network at %s; that minute is not used as normal"
                     % live_page.wall(1_800_000_695.3)]
    assert live_page.rejoin_lines({}) == []


def test_a_state_with_rejoins_renders(tmp_path):
    from tests.test_live_page import fixture, fresh, place, render, texts
    state = fresh(fixture("incident"))
    start = state["capture_start_epoch"]
    state["rejoins"] = {"esp32-02": [{"window": 11, "seconds": 695.3, "epoch": start + 695.3}]}
    place(tmp_path, state)
    at = render(tmp_path, session=state["session"])
    assert not at.exception, [e.value for e in at.exception]
    assert "esp32-02 rejoined the network at %s" % live_page.wall(start + 695.3) in texts(at)


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


def _scored(run_id: str, pcap: Path):
    """Offline pipeline on a capture re-converted under the rules in force."""
    run = runs.load_run(run_id)
    run.connections = capture.build_flows(list(_packets(str(pcap))))
    detection = detect.detect_run(run)
    return run, detection, attribute.attribute_run(run, detection)


def _answer(run_id):
    return json.loads((ANSWERS / ("%s.json" % run_id)).read_text(encoding="utf-8"))


have_rehearsal = REHEARSAL.exists() and runs.meta_path("rehearsal_01").exists() \
    and (ANSWERS / "rehearsal_01.json").exists() and _tshark() is not None
needs_rehearsal = pytest.mark.skipif(not have_rehearsal,
                                     reason="needs pcap/live/rehearsal_01.pcapng, its run "
                                            "meta and answer file, and tshark")
SEGMENT_FILES = sorted(SEGMENTS.glob("live_batch_*.pcapng")) if SEGMENTS.is_dir() else []
needs_segments = pytest.mark.skipif(not SEGMENT_FILES or _tshark() is None,
                                    reason="needs pcap/segments/live_batch_*.pcapng and tshark")
needs_baselines = pytest.mark.skipif(not all(p.exists() for p in BASELINES) or _tshark() is None,
                                     reason="needs pcap/baseline.pcapng, baseline2.pcapng, tshark")


@needs_rehearsal
def test_rehearsal_01_old_rule_blamed_the_laptop_and_new_rule_names_the_board(rules):
    rules("old")
    _, det_old, old = _scored("rehearsal_01", REHEARSAL)
    assert old.named == "laptop-i3" and "esp32-02" not in det_old.onsets   # the failure

    rules("new")
    _, det, new = _scored("rehearsal_01", REHEARSAL)
    assert new.named == "esp32-02" == _answer("rehearsal_01")["origin"]
    assert new.confidence_percent == 100
    assert sorted(det.onsets) == ["esp32-02"]
    assert 11 in det.rejoins["esp32-02"]                  # the +695 s rejoin
    assert det.rejoins["esp32-02"][11] == pytest.approx(695.27, abs=0.05)


@needs_rehearsal
def test_rehearsal_01_replayed_live_alerts_185_s_after_the_attack(tmp_path):
    session = live.replay(REHEARSAL, "reh", folder=tmp_path / "reh", data_dir=tmp_path / "data",
                          speed=0, save=False, quiet=True)
    answer = _answer("rehearsal_01")
    alert = session.first_alert
    assert alert["device"] == "esp32-02" and not alert["found_at_stop"]
    assert 184.0 <= alert["closed_epoch"] - answer["start_epoch"] <= 186.0
    assert alert["raised_epoch"] - alert["closed_epoch"] <= live.SEGMENT_SECONDS
    assert session.result.named == "esp32-02" and session.result.confidence_percent == 100

    # Live final verdict == offline on the same packets.
    _, det, offline = _scored("rehearsal_01", REHEARSAL)
    assert session.detection.onsets == det.onsets
    assert session.result.ranking == offline.ranking

    # The page is told which minute was left out, with its clock time.
    state = json.loads((tmp_path / "reh" / live.STATE_FILE).read_text(encoding="utf-8"))
    rejoin = [m for m in state["rejoins"]["esp32-02"] if m["window"] == 11][0]
    assert rejoin["epoch"] == pytest.approx(session.capture_start_epoch + 695.27, abs=0.05)


@needs_segments
@pytest.mark.parametrize("pcap", SEGMENT_FILES or [SEGMENTS / "live_batch_01.pcapng"],
                         ids=lambda p: p.stem)
def test_every_real_attack_names_the_board_and_never_flags_the_laptop(rules, pcap):
    rules("new")
    _, det, result = _scored(pcap.stem, pcap)
    assert result.named == _answer(pcap.stem)["origin"]
    assert "laptop-i3" not in det.onsets
    assert "laptop-i3" not in det.skipped


@needs_segments
@pytest.mark.parametrize("pcap", SEGMENT_FILES or [SEGMENTS / "live_batch_01.pcapng"],
                         ids=lambda p: p.stem)
def test_under_the_old_rule_the_published_runs_reproduce_exactly(rules, pcap):
    """results/table_live.csv stays the old rule: re-converting the capture with
    the switches OFF must give exactly the saved run it was scored from."""
    published = runs.data_path(pcap.stem)
    if not published.exists():
        pytest.skip("no data/%s.parquet" % pcap.stem)
    rules("old")
    frame = capture.build_flows(list(_packets(str(pcap))))
    pd.testing.assert_frame_equal(frame, pd.read_parquet(published))


@needs_segments
def test_the_live_batch_is_11_of_12_old_and_12_of_12_new(rules):
    if len(SEGMENT_FILES) != 12:
        pytest.skip("expects all 12 segments")
    counts = {}
    for which in ("old", "new"):
        rules(which)
        counts[which] = sum(_scored(p.stem, p)[2].named == _answer(p.stem)["origin"]
                            for p in SEGMENT_FILES)
    assert counts == {"old": 11, "new": 12}


@needs_baselines
def test_attack_free_sessions_one_false_alarm_old_none_new(rules):
    rules("old")
    old = evaluate.false_alarm_sessions(BASELINES, session_seconds=1500, baseline_seconds=720)
    rules("new")
    new = evaluate.false_alarm_sessions(BASELINES, session_seconds=1500, baseline_seconds=720)
    assert len(old) == len(new) == 24
    assert [(r["pcap"], r["session"], r["flagged"]) for r in old if r["false_alarm"]] == \
        [("baseline2.pcapng", 7, "laptop-i3")]
    assert not any(r["false_alarm"] for r in new)
    # That session's laptop was really judged under the new rule, not skipped.
    session_7 = [r for r in new if r["pcap"] == "baseline2.pcapng" and r["session"] == 7][0]
    assert "laptop-i3" not in session_7["skipped"]
