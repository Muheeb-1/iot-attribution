"""
Tests for src/attribute.py - method V5.

THE HAND-BUILT CASE COMES FIRST, ON PURPOSE.

Most of this file checks V5 against hard.py on real 25,000-row runs, which
proves the port is faithful but explains nothing. The first test below is the
opposite: four devices, one obvious answer, few enough connections to check on
paper.

    A goes abnormal first, and connects to B
    B then connects to C
    D is innocent

The answer is obviously A. If the method cannot get this right, nothing it
says about a harder case is worth reading. It is the sanity check that would
catch a wholesale mistake - a reversed arrow, a sign error in the scoring, a
graph built backwards - which a fidelity test would happily reproduce if
hard.py had the same mistake.
"""

import networkx as nx
import numpy as np
import pandas as pd
import pytest

import hard
from src import attribute, detect, features, generate, runs

LAB = ["A", "B", "C", "D"]
BASELINE = 600.0        # the first 10 minutes are "normal"


def connections_from(records):
    """Build a traffic table from (t, src, dst, bytes_out) tuples."""
    rows = [
        ("C%06d" % i, t, s, d, 443, b, 100, 2)
        for i, (t, s, d, b) in enumerate(sorted(records, key=lambda r: r[0]))
    ]
    return pd.DataFrame(rows, columns=[
        "conn_id", "t", "src", "dst", "dport", "bytes_out", "bytes_in", "pkts"
    ])


def tiny_incident(include_d_onset=False):
    """
    The four-device case described at the top of this file.

    Timeline:
        0 - 600s    everybody chats to "cloud", which is normal for all of them
        700s        A starts calling "evil-host", which nobody has ever called
        720 - 760s  A connects to B repeatedly          <- the first hop
        800s        B starts calling "evil-host" too
        820 - 860s  B connects to C repeatedly          <- the second hop
        900s        C starts calling "evil-host" too
        throughout  D carries on talking to "cloud" and nothing else

    Onsets are supplied directly rather than run through the detector, because
    what is under test here is the attribution logic, not the detector. Using
    exact onsets keeps the expected answer something a reader can verify by
    hand.
    """
    records = []

    # Normal life for all four devices, during the baseline.
    for device in LAB:
        for i in range(30):
            records.append((float(i * 20), device, "cloud", 1000))

    # ...and D keeps doing exactly that, all the way through. D is innocent.
    for i in range(30):
        records.append((600.0 + i * 20, "D", "cloud", 1000))

    # A is compromised: it starts calling an address nobody has ever called.
    for i in range(20):
        records.append((700.0 + i * 30, "A", "evil-host", 150))

    # A hops to B.
    for i in range(60):
        records.append((720.0 + i * 0.5, "A", "B", 400))

    # B is now compromised, and calls the same address.
    for i in range(20):
        records.append((800.0 + i * 30, "B", "evil-host", 150))

    # B hops to C.
    for i in range(60):
        records.append((820.0 + i * 0.5, "B", "C", 400))

    # C is now compromised, and calls the same address.
    for i in range(20):
        records.append((900.0 + i * 30, "C", "evil-host", 150))

    onsets = {"A": 700.0, "B": 800.0, "C": 900.0}
    if include_d_onset:
        # D has an innocent burst - a backup - so the detector flags it too.
        for i in range(200):
            records.append((760.0 + i * 0.2, "D", "cloud", 900_000))
        onsets["D"] = 760.0

    return connections_from(records), onsets


# --------------------------------------------------------------------------
# THE HAND-BUILT CASE
# --------------------------------------------------------------------------

def test_the_obvious_four_device_case_names_A():
    """A -> B -> C, D innocent. The answer is A."""
    connections, onsets = tiny_incident()

    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)

    assert result.ranking[0] == "A", (
        "ranked %s, expected A first. Scores: %s" % (result.ranking, result.scores)
    )
    assert result.named == "A"
    assert not result.abstained


def test_the_obvious_case_is_not_a_close_call():
    """A should win clearly, not scrape it. A narrow win here would be luck."""
    connections, onsets = tiny_incident()
    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)

    assert result.confidence >= attribute.ABSTAIN_BELOW
    assert result.scores["A"] > result.scores["B"] > result.scores["C"]


def test_the_obvious_case_recovers_the_path_A_B_C():
    connections, onsets = tiny_incident()
    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)

    assert result.path == ["A", "B", "C"]


def test_the_obvious_case_draws_the_arrows_the_right_way_round():
    """
    A causes B causes C. Not the reverse. This is the test that catches a
    graph built backwards - the kind of mistake that still produces a
    plausible-looking ranking.
    """
    connections, onsets = tiny_incident()
    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)

    assert result.graph.has_edge("A", "B")
    assert result.graph.has_edge("B", "C")
    assert not result.graph.has_edge("B", "A")
    assert not result.graph.has_edge("C", "B")

    # A explains everybody; nothing explains A.
    assert result.graph.in_degree("A") == 0
    assert set(nx.descendants(result.graph, "A")) == {"B", "C"}


def test_the_innocent_device_is_never_named_even_when_it_is_flagged():
    """
    D does something unusual - a big innocent backup - so the detector flags
    it. It still explains nothing and nothing links it to the incident, so it
    must not be blamed. This is the decoy problem in miniature.
    """
    connections, onsets = tiny_incident(include_d_onset=True)
    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)

    assert result.ranking[0] == "A", "a decoy device outranked the real origin"
    assert result.named == "A"
    assert result.scores["A"] > result.scores["D"]


def test_the_loudest_device_is_not_the_answer():
    """
    D sends far more data than anybody. Ranking by volume would name D; V5
    must not. This is the 0%-scoring baseline, reproduced in four devices.
    """
    connections, onsets = tiny_incident(include_d_onset=True)

    by_volume = connections[connections["src"].isin(LAB)].groupby("src")["bytes_out"].sum()
    assert by_volume.idxmax() == "D", "test setup wrong - D should be loudest"

    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)
    assert result.ranking[0] == "A"


def test_a_relayed_hop_is_still_linked_by_the_shared_indicator():
    """
    The reason V5 exists. Remove every direct connection between A and B, so
    the hop leaves no trace at all - as happens in 40% of the hard runs. A and
    B still both call "evil-host", which neither ever called before, and A
    called it first. That alone must keep A above B.
    """
    connections, onsets = tiny_incident()
    relayed = connections[~((connections["src"] == "A") & (connections["dst"] == "B"))]

    result = attribute.attribute(relayed, onsets, LAB, baseline_seconds=BASELINE)

    assert result.graph.has_edge("A", "B"), "no link survived the relayed hop"
    assert result.graph["A"]["B"]["kind"] == "indicator"
    assert result.graph["A"]["B"]["w"] == attribute.WEIGHT_INDICATOR
    assert result.ranking[0] == "A"


# --------------------------------------------------------------------------
# The rules for drawing an arrow
# --------------------------------------------------------------------------

def test_no_arrow_without_a_connection_between_the_onsets():
    """
    Timing alone is circumstantial. Two devices going bad in sequence with no
    traffic between them is a coincidence, not a mechanism.
    """
    records = [(float(i * 20), d, "cloud", 1000) for i in range(30) for d in ("A", "B")]
    records += [(700.0 + i * 30, "A", "evil-a", 150) for i in range(10)]
    records += [(800.0 + i * 30, "B", "evil-b", 150) for i in range(10)]
    connections = connections_from(records)

    graph = attribute.build_causal_graph(
        connections, {"A": 700.0, "B": 800.0}, LAB
    )
    assert not graph.has_edge("A", "B")


def test_no_arrow_when_the_gap_is_too_long():
    """Beyond 30 minutes, anything could explain anything. So nothing does."""
    records = [(float(i * 20), d, "cloud", 1000) for i in range(30) for d in ("A", "B")]
    records += [(700.0 + i, "A", "B", 400) for i in range(50)]
    connections = connections_from(records)

    close = attribute.build_causal_graph(connections, {"A": 700.0, "B": 900.0}, LAB)
    assert close.has_edge("A", "B")

    far = attribute.build_causal_graph(
        connections, {"A": 700.0, "B": 700.0 + attribute.MAX_GAP_SECONDS + 1}, LAB
    )
    assert not far.has_edge("A", "B")


def test_arrows_only_point_forwards_in_time():
    connections, onsets = tiny_incident()
    graph = attribute.build_causal_graph(connections, onsets, LAB)

    for u, v in graph.edges():
        assert onsets[u] < onsets[v], "%s -> %s points backwards in time" % (u, v)


def test_more_connections_make_a_stronger_arrow():
    def graph_with(count):
        records = [(float(i * 20), d, "cloud", 1000) for i in range(30) for d in ("A", "B")]
        records += [(700.0 + i * 0.5, "A", "B", 400) for i in range(count)]
        return attribute.build_causal_graph(
            connections_from(records), {"A": 700.0, "B": 800.0}, LAB
        )

    weak = graph_with(1)["A"]["B"]["w"]
    strong = graph_with(100)["A"]["B"]["w"]
    assert strong > weak
    assert strong <= 2.0, "edge weight must stay capped"


def test_an_address_used_during_the_baseline_is_not_an_indicator():
    """
    If a device talked to it while everything was normal, it is infrastructure,
    not an indicator. Otherwise every device sharing a DNS server would be
    linked to every other.
    """
    records = [(float(i * 20), d, "shared-server", 1000) for i in range(30) for d in ("A", "B")]
    records += [(700.0 + i * 30, "A", "shared-server", 150) for i in range(10)]
    records += [(800.0 + i * 30, "B", "shared-server", 150) for i in range(10)]
    connections = connections_from(records)

    graph = attribute.add_indicator_edges(
        connections, nx.DiGraph(), {"A": 700.0, "B": 800.0}, LAB, BASELINE
    )
    assert not graph.has_edge("A", "B")


def test_an_address_only_one_device_touched_is_not_an_indicator():
    connections, onsets = tiny_incident()
    graph = attribute.add_indicator_edges(
        connections, nx.DiGraph(), {"A": 700.0}, LAB, BASELINE
    )
    assert graph.number_of_edges() == 0


# --------------------------------------------------------------------------
# Abstaining
# --------------------------------------------------------------------------

def test_it_abstains_when_the_top_two_cannot_be_separated():
    """
    Two identical, unconnected devices. There is genuinely no way to choose,
    and saying so is the correct answer.
    """
    records = []
    for device in ("A", "B"):
        records += [(float(i * 20), device, "cloud", 1000) for i in range(30)]
        records += [(700.0 + i * 30, device, "evil-%s" % device, 150) for i in range(10)]
    connections = connections_from(records)

    result = attribute.attribute(
        connections, {"A": 700.0, "B": 700.0}, LAB, baseline_seconds=BASELINE
    )

    assert result.abstained
    assert result.named is None
    assert set(result.shortlist) == {"A", "B"}


def test_abstaining_still_returns_a_shortlist_of_three():
    connections, _ = generate.make_run(5004)
    run_devices = generate.HARD_NAMES
    table = features.build_features(connections, run_devices, 3 * 3600)
    detection = detect.detect(table, baseline_windows=180)
    result = attribute.attribute(connections, detection.onsets, run_devices, 3 * 3600)

    if result.abstained:
        assert result.named is None
        assert 1 <= len(result.shortlist) <= 3
        assert result.shortlist == result.ranking[:len(result.shortlist)]


def test_no_onsets_means_no_accusation():
    connections, _ = tiny_incident()
    result = attribute.attribute(connections, {}, LAB, baseline_seconds=BASELINE)

    assert result.ranking == []
    assert result.named is None
    assert result.path == []


def test_a_single_suspect_is_named_without_hesitation():
    connections, _ = tiny_incident()
    result = attribute.attribute(connections, {"A": 700.0}, LAB, baseline_seconds=BASELINE)

    assert result.ranking == ["A"]
    assert result.named == "A"
    assert not result.abstained


# --------------------------------------------------------------------------
# Fidelity to the prototype
# --------------------------------------------------------------------------

@pytest.mark.parametrize("seed", [5000, 5001, 5007, 5017])
def test_v5_matches_the_prototype_ranking_and_confidence(seed):
    connections, _ = generate.make_run(seed)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)

    ours_detection = detect.detect(table, baseline_windows=180, weighted=True)
    _, their_onsets = hard.detect(table, weighted=True)
    assert ours_detection.onsets == their_onsets

    their_graph = hard.build_graph(connections, their_onsets, allow_broker=True)
    their_ranking, their_confidence = hard.score_v5(
        connections, their_graph, their_onsets, None
    )

    ours = attribute.attribute(
        connections, ours_detection.onsets, generate.HARD_NAMES, 3 * 3600
    )

    assert ours.ranking == their_ranking
    assert ours.confidence == pytest.approx(their_confidence)


@pytest.mark.parametrize("seed", [5000, 5001, 5007])
def test_the_causal_graph_matches_the_prototype(seed):
    connections, _ = generate.make_run(seed)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    detection = detect.detect(table, baseline_windows=180)

    ours = attribute.build_causal_graph(
        connections, detection.onsets, generate.HARD_NAMES
    )
    theirs = hard.build_graph(connections, detection.onsets, allow_broker=True)

    assert set(ours.edges()) == set(theirs.edges())
    for u, v in theirs.edges():
        assert ours[u][v]["w"] == pytest.approx(theirs[u][v]["w"])


def test_scoring_weights_add_up_to_one():
    """
    The six story ingredients are a weighted average, so they should total 1.
    If somebody tunes one weight without adjusting the others, the scale
    silently shifts and the abstain threshold stops meaning what it meant.
    """
    total = (attribute.W_COVERAGE + attribute.W_STRENGTH + attribute.W_ORPHAN
             + attribute.W_EARLY + attribute.W_NOVELTY + attribute.W_QUIET)
    assert total == pytest.approx(1.0)


# --------------------------------------------------------------------------
# End to end on a real run
# --------------------------------------------------------------------------

def test_runs_end_to_end_on_a_saved_run(tmp_path):
    generate.write_run(5000, 0, data_dir=tmp_path, answer_dir=tmp_path / "a")
    run = runs.load_run("run_000", data_dir=tmp_path)

    result = attribute.attribute_run(run)

    assert set(result.ranking) <= set(run.device_names)
    assert len(set(result.ranking)) == len(result.ranking), "a device ranked twice"
    assert 0.0 <= result.confidence
    assert result.path[0] == result.ranking[0]
    for edge in result.edge_evidence():
        assert edge["kind"] in {"direct", "relay", "indicator"}


def test_the_result_is_reproducible():
    connections, _ = generate.make_run(5002)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    detection = detect.detect(table, baseline_windows=180)

    first = attribute.attribute(connections, detection.onsets, generate.HARD_NAMES, 3 * 3600)
    second = attribute.attribute(connections, detection.onsets, generate.HARD_NAMES, 3 * 3600)

    assert first.ranking == second.ranking
    assert first.confidence == pytest.approx(second.confidence)


def test_baseline_rankings_cover_every_device():
    connections, _ = generate.make_run(5000)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    detection = detect.detect(table, baseline_windows=180)

    rankings = attribute.baseline_rankings(connections, detection, generate.HARD_NAMES)
    assert set(rankings) == {
        "B1 total bytes", "B2 anomaly score", "B3 connection count", "B4 earliest onset"
    }
    assert len(rankings["B1 total bytes"]) == len(generate.HARD_NAMES)
    assert rankings["B4 earliest onset"] == detection.devices_by_onset()


# --------------------------------------------------------------------------
# The two stages are recorded separately, so the final order can be explained
# --------------------------------------------------------------------------

def test_both_ranking_stages_are_recorded():
    """
    A reader who sees rank 1 holding a lower story score than rank 2 must be
    able to find out why. Keeping stage 1 and the indicator bonus lets the
    interface say so instead of looking broken.
    """
    connections, onsets = tiny_incident()
    result = attribute.attribute(connections, onsets, LAB, baseline_seconds=BASELINE)

    assert result.story_ranking, "stage-1 ranking was not recorded"
    assert set(result.story_ranking) == set(result.ranking)
    assert set(result.indicator_bonus) == set(result.story_ranking[:attribute.SHORTLIST])
    for device in result.ranking:
        assert result.explain_rank(device)


def test_indicator_evidence_can_overrule_the_story_score():
    """
    The whole point of the two-stage design. On this run the whole-story score
    puts the wrong device first, and the shared-indicator re-ranking corrects
    it - which is precisely why V5 beats V2 on top-1 while keeping its top-3.
    """
    connections, _ = generate.make_run(5002)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    detection = detect.detect(table, baseline_windows=180)
    result = attribute.attribute(connections, detection.onsets, generate.HARD_NAMES, 3 * 3600)

    assert result.ranking[0] != result.story_ranking[0], (
        "expected the re-ranking to change the winner on this run"
    )
    assert result.ranking[0] == "bulb"
    # ...and the device it overtook genuinely had the higher story score.
    assert result.scores[result.story_ranking[0]] > result.scores[result.ranking[0]]


def test_a_device_outside_the_shortlist_keeps_its_story_order():
    connections, _ = generate.make_run(5002)
    table = features.build_features(connections, generate.HARD_NAMES, 3 * 3600)
    detection = detect.detect(table, baseline_windows=180)
    result = attribute.attribute(connections, detection.onsets, generate.HARD_NAMES, 3 * 3600)

    tail_final = result.ranking[attribute.SHORTLIST:]
    tail_story = result.story_ranking[attribute.SHORTLIST:]
    assert tail_final == tail_story


# --------------------------------------------------------------------------
# Confidence: a ranking signal, and separately a thing shown to a person
# --------------------------------------------------------------------------

def test_the_raw_confidence_is_left_unbounded():
    """
    The second stage measures the indicator gap as (best - second) /
    (|best| + 1), which exceeds 1.0 when the runner-up scores negatively. That
    is inherited from the prototype and must NOT be changed: the abstain
    decision and every published accuracy figure are computed from it, so
    clamping it here would quietly alter the results.
    """
    result = attribute.Attribution(confidence=1.5, ranking=["a", "b"])
    assert result.confidence == 1.5


def test_the_displayed_confidence_is_clamped_to_a_sensible_percentage():
    """
    "150% confident" is not a sentence anybody should read, least of all the
    non-expert this project is written for. Display goes through here; the
    decision-making does not.
    """
    assert attribute.Attribution(confidence=1.5).confidence_percent == 100
    assert attribute.Attribution(confidence=0.67).confidence_percent == 67
    assert attribute.Attribution(confidence=0.0).confidence_percent == 0
    assert attribute.Attribution(confidence=-0.2).confidence_percent == 0


def test_clamping_does_not_disturb_the_abstain_decision():
    """The threshold is applied to the raw value, so a clamp cannot move it."""
    below = attribute.Attribution(confidence=0.10)
    above = attribute.Attribution(confidence=1.50)
    assert below.confidence < attribute.ABSTAIN_BELOW
    assert above.confidence > attribute.ABSTAIN_BELOW
    assert above.confidence_percent == 100


def test_real_runs_never_display_an_impossible_percentage():
    for run_id in runs.list_runs()[:12]:
        run = runs.load_run(run_id)
        detection = detect.detect_run(run)
        result = attribute.attribute_run(run, detection)
        assert 0 <= result.confidence_percent <= 100, (
            "%s would display %d%%" % (run_id, result.confidence_percent)
        )
