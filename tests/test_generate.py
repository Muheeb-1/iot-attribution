"""
Tests for src/generate.py - the scenario generator.

THE MOST IMPORTANT TEST IN THIS FILE is the fidelity check. The published
benchmark numbers (V5: 53% top-1, 90% top-3) were measured on traffic produced
by hard.py. If this rewrite produces even slightly different traffic for the
same seed, those numbers no longer describe this project and cannot be
defended. So we generate a run both ways and demand they match row for row.

That is a stricter test than it first appears. numpy's random generator hands
out numbers in a fixed sequence, so if the port shuffled the order of even one
random draw - one extra call, one call moved earlier - every subsequent number
would differ and the traffic would diverge. Matching row for row proves the
port is faithful, not merely similar.
"""

import json

import pandas as pd
import pytest

import hard          # the prototype: hard benchmark
import sim           # the prototype: easy benchmark
from src import generate, windows

SHARED_COLUMNS = ["t", "src", "dst", "bytes_out", "bytes_in", "pkts"]


# --------------------------------------------------------------------------
# Fidelity to the prototypes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("seed", [5000, 5001, 5017])
def test_hard_traffic_matches_the_prototype_row_for_row(seed):
    ours, _ = generate.make_run(seed, easy=False)
    theirs, _ = hard.make(seed)

    assert len(ours) == len(theirs), "different number of connections"
    pd.testing.assert_frame_equal(
        ours[SHARED_COLUMNS].reset_index(drop=True),
        theirs[SHARED_COLUMNS].reset_index(drop=True),
        check_dtype=False,
    )


@pytest.mark.parametrize("seed", [1000, 1001, 1013])
def test_easy_traffic_matches_the_prototype_row_for_row(seed):
    ours, _ = generate.make_run(seed, easy=True)
    theirs, _ = sim.make_run(seed)

    assert len(ours) == len(theirs)
    pd.testing.assert_frame_equal(
        ours[SHARED_COLUMNS].reset_index(drop=True),
        theirs[SHARED_COLUMNS].reset_index(drop=True),
        check_dtype=False,
    )


@pytest.mark.parametrize("seed", [5000, 5003, 5011])
def test_hard_answer_matches_the_prototype(seed):
    _, ours = generate.make_run(seed, easy=False)
    _, theirs = hard.make(seed)

    assert ours["origin"] == theirs["origin"]
    assert ours["chain"] == theirs["chain"]
    assert ours["via_broker"] == theirs["via_broker"]


# --------------------------------------------------------------------------
# The origin really is picked at random
# --------------------------------------------------------------------------

def test_the_origin_changes_from_run_to_run():
    """
    If the origin were fixed, or nearly fixed, we could accidentally tune the
    detector to one device and report a meaningless accuracy.
    """
    origins = [generate.make_run(5000 + i)[1]["origin"] for i in range(30)]
    assert len(set(origins)) >= 6, "origin is barely varying: %s" % sorted(set(origins))


def test_the_origin_is_always_a_real_lab_device():
    for i in range(10):
        _, answer = generate.make_run(5000 + i)
        assert answer["origin"] in generate.HARD_NAMES
        assert len(set(answer["chain"])) == 3, "the chain must be three different devices"


# --------------------------------------------------------------------------
# The relayed hop - the thing that defeats direct-connection methods
# --------------------------------------------------------------------------

def test_relayed_runs_happen_roughly_40_percent_of_the_time():
    flags = [generate.make_run(5000 + i)[1]["via_broker"] for i in range(60)]
    share = sum(flags) / len(flags)
    assert 0.20 <= share <= 0.60, "relayed share was %.2f, expected about 0.40" % share


def test_a_relayed_run_carries_the_hop_through_the_broker_not_directly():
    """
    This is the whole point of the broker relay, so it is worth proving rather
    than assuming.

    Careful with what is actually claimed here. In a relayed run the origin may
    STILL have a couple of direct connections to the second victim, because the
    scan step probes 5 random neighbours and the victim is sometimes one of
    them. Those probes are 60 bytes with no reply - a knock on the door, not a
    delivery. What must never exist in a relayed run is a direct TRANSFER: the
    120 connections carrying the hop go origin -> broker -> victim, and the
    direct route is empty of anything substantial.

    (That leftover scan probe matters later. It is a real direct connection
    inside the onset window, so a graph that only asks "did u ever connect to
    v" will still draw an edge in some relayed runs. V5 cannot rely on that
    happening, which is exactly why it also links devices by shared indicator.)
    """
    checked = 0
    for i in range(40):
        df, answer = generate.make_run(5000 + i)
        if not answer["via_broker"]:
            continue
        checked += 1
        origin, victim2 = answer["chain"][0], answer["chain"][1]

        direct = df[(df.src == origin) & (df.dst == victim2)]
        assert len(direct) <= 10, (
            "run seed %d is relayed but has %d direct connections from %s to %s"
            % (5000 + i, len(direct), origin, victim2)
        )
        if not direct.empty:
            assert direct["bytes_out"].max() <= 60, (
                "run seed %d is relayed but the direct route carries real data"
                % (5000 + i)
            )
            assert (direct["bytes_in"] == 0).all()

        # ...and the broker really is carrying the hop instead.
        assert len(df[(df.src == origin) & (df.dst == generate.BROKER)]) >= 120
        assert len(df[(df.src == generate.BROKER) & (df.dst == victim2)]) >= 120

    assert checked > 0, "no relayed runs in the sample - the test proved nothing"


def test_a_direct_run_really_does_transfer_data_between_the_devices():
    """The mirror image: when the hop is not relayed, the transfer is right there."""
    checked = 0
    for i in range(40):
        df, answer = generate.make_run(5000 + i)
        if answer["via_broker"]:
            continue
        checked += 1
        origin, victim2 = answer["chain"][0], answer["chain"][1]
        transfer = df[(df.src == origin) & (df.dst == victim2) & (df.bytes_out > 100)]
        assert len(transfer) >= 160, (
            "run seed %d is a direct run but only has %d transfer connections"
            % (5000 + i, len(transfer))
        )
    assert checked > 0


# --------------------------------------------------------------------------
# Shape of the traffic table
# --------------------------------------------------------------------------

def test_connections_are_sorted_by_time_and_start_at_zero_or_later():
    df, _ = generate.make_run(5000)
    assert df["t"].is_monotonic_increasing
    assert (df["t"] >= 0).all()
    assert df["t"].max() <= generate.TOTAL_HOURS * 3600


def test_every_connection_has_a_unique_evidence_id_in_time_order():
    """report.py cites these ids as evidence, so they must be unique and stable."""
    df, _ = generate.make_run(5000)
    assert df["conn_id"].is_unique
    assert df["conn_id"].iloc[0] == "C000000"
    assert list(df["conn_id"]) == sorted(df["conn_id"])


def test_ports_are_present_and_sensible():
    df, _ = generate.make_run(5000)
    assert df["dport"].between(1, 65535).all()
    # the broker is the message bus, so sensor traffic goes to 1883
    broker_rows = df[df.dst == generate.BROKER]
    assert (broker_rows["dport"] == 1883).all()


def test_ports_do_not_disturb_the_random_draws():
    """
    Ports are looked up from the destination, never drawn at random. If that
    ever changed, the traffic would drift away from the prototype - which the
    fidelity tests above would catch, but this states the reason plainly.
    """
    names = generate.HARD_NAMES
    assert generate._port_for("broker", names) == generate._port_for("broker", names)
    assert generate._port_for("cloud_cam", names) == 554


def test_both_scenarios_have_the_expected_number_of_devices():
    assert len(generate.HARD_DEVICES) == 12
    assert len(generate.EASY_DEVICES) == 7


# --------------------------------------------------------------------------
# What gets written to disk
# --------------------------------------------------------------------------

def test_writing_a_run_produces_the_three_expected_files(tmp_path):
    data_dir = tmp_path / "data"
    answer_dir = tmp_path / "answers"

    summary = generate.write_run(5000, 0, easy=False,
                                 data_dir=data_dir, answer_dir=answer_dir)

    assert (data_dir / "run_000.parquet").exists()
    assert (data_dir / "run_000.meta.json").exists()
    assert (answer_dir / "run_000.json").exists()
    assert summary["run_id"] == "run_000"
    assert summary["rows"] > 0


def test_the_saved_traffic_survives_the_round_trip(tmp_path):
    data_dir = tmp_path / "data"
    generate.write_run(5000, 0, data_dir=data_dir, answer_dir=tmp_path / "a")

    saved = pd.read_parquet(data_dir / "run_000.parquet")
    fresh, _ = generate.make_run(5000)
    pd.testing.assert_frame_equal(saved, fresh, check_dtype=False)


def test_the_meta_file_gives_nothing_away(tmp_path):
    """
    The meta file is readable by the detection code, so it must not contain a
    single hint about the attack: not the origin, not the chain, not the
    onset times, not the attacker's address.
    """
    data_dir = tmp_path / "data"
    answer_dir = tmp_path / "answers"
    generate.write_run(5000, 0, data_dir=data_dir, answer_dir=answer_dir)

    meta_text = (data_dir / "run_000.meta.json").read_text(encoding="utf-8")
    meta = json.loads(meta_text)
    answer = json.loads((answer_dir / "run_000.json").read_text(encoding="utf-8"))

    for banned in ("origin", "chain", "onset", "c2", "via_broker"):
        assert banned not in meta_text.lower(), "meta file mentions %r" % banned

    assert answer["origin"] not in meta.get("chain", [])
    assert meta["device_names"] == generate.HARD_NAMES  # inventory only
    assert set(meta) == {
        "run_id", "scenario", "seed", "devices", "device_names", "window_seconds",
        "capture_seconds", "baseline_seconds", "baseline_windows",
        "n_connections", "generated_at",
    }


def test_the_answer_file_contains_the_answer(tmp_path):
    answer_dir = tmp_path / "answers"
    generate.write_run(5000, 0, data_dir=tmp_path / "d", answer_dir=answer_dir)

    answer = json.loads((answer_dir / "run_000.json").read_text(encoding="utf-8"))
    assert answer["origin"] in generate.HARD_NAMES
    assert answer["chain"][0] == answer["origin"]
    assert answer["seed"] == 5000
    assert answer["scenario"] == "hard"


# --------------------------------------------------------------------------
# Uses the shared window helper, rather than its own arithmetic
# --------------------------------------------------------------------------

def test_baseline_length_is_a_whole_number_of_windows(tmp_path):
    data_dir = tmp_path / "data"
    generate.write_run(5000, 0, data_dir=data_dir, answer_dir=tmp_path / "a")
    meta = json.loads((data_dir / "run_000.meta.json").read_text(encoding="utf-8"))

    assert meta["window_seconds"] == 60
    assert meta["baseline_seconds"] == 3 * 3600
    assert meta["baseline_windows"] == 180
    assert meta["baseline_windows"] == windows.baseline_window_count(3 * 3600, 60)


def test_true_onset_windows_agree_with_the_shared_helper():
    _, answer = generate.make_run(5000)
    for device, seconds in answer["true_onset_seconds"].items():
        assert answer["true_onset_windows"][device] == windows.window_of(seconds)


# --------------------------------------------------------------------------
# The easy scenario is genuinely easier
# --------------------------------------------------------------------------

def test_easy_scenario_is_smaller_and_never_relayed():
    df_easy, answer_easy = generate.make_run(1000, easy=True)
    assert answer_easy["scenario"] == "easy"
    assert answer_easy["via_broker"] is False
    assert answer_easy["origin"] in generate.EASY_NAMES
    assert set(df_easy["src"].unique()) - set(generate.EASY_NAMES) <= set()


def test_easy_runs_get_their_own_file_names(tmp_path):
    summary = generate.write_run(1000, 4, easy=True,
                                 data_dir=tmp_path / "d", answer_dir=tmp_path / "a")
    assert summary["run_id"] == "easy_004"
    assert (tmp_path / "d" / "easy_004.parquet").exists()
