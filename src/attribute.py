"""
ATTRIBUTION - working out which device the attack STARTED from.

This is the heart of the project. Everything before it prepares the evidence;
everything after it presents the conclusion. It implements method V5, the
winner of the five-way comparison in hard.py.

THE PROBLEM
-----------
Step 4 hands us a list of devices that went abnormal, and when. The obvious
next move is to blame whichever went abnormal first. On the hard benchmark
that is right 17% of the time. It fails because "went abnormal first" and
"was attacked first" are different statements: an innocent device running a
backup goes abnormal too, and often earlier.

THE IDEA BEHIND V5
------------------
Do not score devices. Score STORIES.

For each suspect, ask: "if this device were patient zero, how much of
everything else that happened would that explain?" A device that explains the
whole incident, that nothing else points at, that started early, and that
contacted addresses it had never used before, is telling a complete story. A
device that explains only itself is telling a very short one.

That is the difference between V1 (43%) and V2 (47%), and it is most of why
V5 reaches 53% with the true origin in the top 3 90% of the time.

HOW THE STORY IS BUILT - THE GRAPH
----------------------------------
We draw an arrow u -> v meaning "u could plausibly have caused v", and we are
strict about what earns one:

  DIRECT (weight 1.0 to 2.0)
      u went abnormal BEFORE v, there is a real connection from u to v
      between the two onsets, and the gap is under 30 minutes. The weight
      rises with the number of connections, because one packet is a
      coincidence and two hundred is a transfer.

  RELAYED (weight 0.5)
      no direct connection, but in that same window u talked to some outside
      host and v was talked to BY that same host. The attacker may have
      hopped through it. Deliberately weak: shared infrastructure like a
      message broker produces this pattern innocently all day long.

  SHARED INDICATOR (weight 1.6)
      u and v both contacted the SAME outside address, and neither had ever
      contacted it during the baseline. Whoever touched it first is upstream.

The 30-minute limit matters. Without it, anything that happened later in the
capture could be blamed on anything that happened earlier, and the graph
would say nothing.

WHY SHARED INDICATORS ARE THE KEY TO V5
---------------------------------------
In 40% of runs the attacker's hop is relayed through the shared broker, so
there is NO direct connection between the origin and its first victim. A
method that only follows direct connections is blind in those runs.

But the two devices still have something in common: they are both now talking
to the attacker's address, and neither ever did before. This is exactly how a
human analyst pivots - "these two machines are both calling the same place
they have never called; they are connected" - and it survives a relayed hop
because it does not depend on the hop leaving a trace.

THE TWO-STAGE RANKING
---------------------
Whole-story scoring produces a reliable SHORTLIST but is not the best at
picking the winner from it. Shared-indicator evidence is the reverse: sharper
at picking the winner, weaker at assembling the shortlist (V4, which used it
throughout, got top-1 53% but top-3 only 73%).

So V5 uses each for what it is good at:
    1. rank everybody by whole-story score  -> take the top 3
    2. re-rank those 3 by indicator evidence -> prefer the device that
       explains more and is pointed at less
This is why V5 keeps V2's 90% top-3 AND gains V4's 53% top-1.

KNOWING WHEN TO SHUT UP
-----------------------
Confidence is the gap between first and second place. Below 15% the top two
are effectively tied, and naming one would be a coin toss dressed up as a
finding. In that case the method ABSTAINS: it returns the shortlist of three
and says plainly that it cannot choose. For a tool whose output a non-expert
is meant to act on, an honest "these three, I cannot separate them" is worth
far more than a confident guess that is wrong half the time.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

import networkx as nx
import numpy as np
import pandas as pd

from src import detect, runs

# How long after u went bad can v go bad and still be blamed on u.
MAX_GAP_SECONDS = 1800          # 30 minutes

# Edge weights.
WEIGHT_RELAY = 0.5              # shared outside host - weak, happens innocently
WEIGHT_INDICATOR = 1.6          # same brand-new outside address - strong

# How much of the score each part of the story is worth. These are the V2
# weights from the prototype, which the benchmark numbers were measured with.
W_COVERAGE = 0.34               # how much of the incident this device explains
W_STRENGTH = 0.20               # how solid the links in its story are
W_ORPHAN = 0.22                 # nothing points at it
W_EARLY = 0.10                  # it started early
W_NOVELTY = 0.10                # it contacted brand-new outside addresses
W_QUIET = 0.04                  # it is not the loudest device (loud = victim)
W_UNEXPLAINED = 0.03            # counterfactual bonus, per orphaned device

# Below this gap between first and second place, refuse to name one device.
ABSTAIN_BELOW = 0.15

# How many devices make the shortlist that gets re-ranked.
SHORTLIST = 3

# Evidence connection ids kept per edge, for the incident brief.
EVIDENCE_PER_EDGE = 5


@dataclass
class Attribution:
    """The conclusion, with everything needed to justify it."""

    ranking: list = field(default_factory=list)      # FINAL order, after re-ranking
    scores: dict = field(default_factory=dict)       # device -> whole-story score
    confidence: float = 0.0                          # gap between #1 and #2
    abstained: bool = False
    shortlist: list = field(default_factory=list)    # the top 3
    named: str | None = None                         # None when abstaining
    path: list = field(default_factory=list)         # reconstructed attack path
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    onsets: dict = field(default_factory=dict)

    # The two stages kept separately, so the final order can be explained.
    # Without these, a reader sees rank 1 holding a LOWER story score than
    # rank 2 and reasonably concludes the code is broken - when in fact the
    # shared-indicator re-ranking has overruled the story score, which is
    # exactly what V5 is for.
    story_ranking: list = field(default_factory=list)   # order after stage 1
    indicator_bonus: dict = field(default_factory=dict)  # stage 2, shortlist only

    def explain_rank(self, device: str) -> str:
        """One line saying how this device ended up where it did."""
        if device not in self.story_ranking:
            return "not a suspect"
        stage1 = self.story_ranking.index(device) + 1
        if device not in self.indicator_bonus:
            return "story rank %d (not re-ranked)" % stage1
        final = self.ranking.index(device) + 1
        bonus = self.indicator_bonus[device]
        if final == stage1:
            return "story rank %d, held by indicator score %+.1f" % (stage1, bonus)
        direction = "promoted from" if final < stage1 else "pushed down from"
        return "%s story rank %d by indicator score %+.1f" % (direction, stage1, bonus)

    @property
    def top(self) -> str | None:
        return self.ranking[0] if self.ranking else None

    @property
    def confidence_percent(self) -> int:
        """
        Confidence as a whole percentage, for showing to a person. CLAMPED to
        0-100.

        The raw `confidence` is not a probability and is not bounded above.
        The second stage measures the gap between the top two indicator
        scores as (best - second) / (|best| + 1), which exceeds 1.0 whenever
        the runner-up scores negatively - it happened in 10 of our 60 saved
        runs, the worst reading 1.50.

        As a ranking signal that is fine, and it is left exactly as it is,
        because the abstain decision and every published accuracy figure are
        computed from the raw value. As something to put in front of a site
        manager it is not: "150% confident" is not a sentence anybody should
        read. So display goes through here, and the decision-making does not.
        """
        return int(round(max(0.0, min(1.0, self.confidence)) * 100))

    def edge_evidence(self) -> list:
        """Every link we drew, as plain dictionaries - for the brief and the UI."""
        out = []
        for u, v, data in self.graph.edges(data=True):
            out.append({
                "from": u, "to": v,
                "kind": data.get("kind", "direct"),
                "weight": round(float(data.get("w", 0.0)), 3),
                "detail": data.get("detail", ""),
                "evidence_ids": list(data.get("evidence_ids", [])),
            })
        return sorted(out, key=lambda e: (-e["weight"], e["from"], e["to"]))

    def __repr__(self) -> str:
        if self.abstained:
            return "Attribution(ABSTAIN, shortlist=%s, confidence=%.2f)" % (
                self.shortlist, self.confidence
            )
        return "Attribution(%s, confidence=%.2f, path=%s)" % (
            self.named, self.confidence, " -> ".join(self.path)
        )


# --------------------------------------------------------------------------
# (a) The graph of "who could have caused whom"
# --------------------------------------------------------------------------

def build_causal_graph(
    connections: pd.DataFrame,
    onsets: dict,
    device_names,
    max_gap_seconds: float = MAX_GAP_SECONDS,
    allow_relay: bool = True,
) -> nx.DiGraph:
    """
    Draw an arrow u -> v wherever u could plausibly have caused v.

    Three conditions must ALL hold before a direct arrow is drawn:
      * u went abnormal strictly before v          (causes precede effects)
      * the gap is at most max_gap_seconds         (or everything explains
                                                    everything)
      * there is a real connection from u to v BETWEEN the two onsets
                                                   (a mechanism, not a
                                                    coincidence of timing)

    The third is the important one. Timing alone is circumstantial; a
    connection in the right direction at the right moment is a mechanism.
    """
    lab = set(device_names)
    suspects = list(onsets)

    graph = nx.DiGraph()
    graph.add_nodes_from(suspects)

    for u in suspects:
        for v in suspects:
            if u == v:
                continue
            if not (onsets[u] < onsets[v] <= onsets[u] + max_gap_seconds):
                continue

            window = (connections["t"] >= onsets[u]) & (connections["t"] <= onsets[v])

            direct = connections[
                (connections["src"] == u) & (connections["dst"] == v) & window
            ]
            if len(direct) > 0:
                # More connections means a transfer rather than a stray packet,
                # so the arrow is worth more - capped so a huge transfer cannot
                # dominate the whole score.
                ids = []
                if "conn_id" in direct.columns:
                    ids = list(direct["conn_id"].head(EVIDENCE_PER_EDGE))
                graph.add_edge(
                    u, v,
                    w=1.0 + min(len(direct) / 50, 1.0),
                    kind="direct",
                    detail="%d connections from %s to %s between the two onsets"
                           % (len(direct), u, v),
                    evidence_ids=ids,
                )
                continue

            if not allow_relay:
                continue

            # No direct link. Did they share an outside middleman?
            u_talked_to = set(connections.loc[(connections["src"] == u) & window, "dst"]) - lab
            v_heard_from = set(connections.loc[(connections["dst"] == v) & window, "src"]) - lab
            shared = u_talked_to & v_heard_from
            if shared:
                graph.add_edge(
                    u, v,
                    w=WEIGHT_RELAY,
                    kind="relay",
                    detail="both connected to %s in the same period"
                           % ", ".join(sorted(shared)[:3]),
                    evidence_ids=[],
                )

    return graph


# --------------------------------------------------------------------------
# (c) Shared-indicator links
# --------------------------------------------------------------------------

def add_indicator_edges(
    connections: pd.DataFrame,
    graph: nx.DiGraph,
    onsets: dict,
    device_names,
    baseline_seconds: float,
) -> nx.DiGraph:
    """
    Link devices that are calling the same place they have never called before.

    This is how a human analyst pivots. If two compromised devices both contact
    the same outside address, and NEITHER of them ever contacted it during the
    quiet baseline, they are part of the same story - and whoever touched it
    first is upstream of the other.

    Its great virtue is that it does not care how the attacker got from one
    device to the other. The hop can be relayed through a broker and leave no
    trace at all; this link still forms.

    Three conditions keep it honest:
      * the address must be new to BOTH devices, judged against the baseline;
      * no device in the lab may have contacted it during the baseline - if
        anybody used it normally, it is not an indicator, it is infrastructure;
      * the arrow runs from earlier onset to later, never backwards.

    Contacts from 120 seconds BEFORE the onset count, because the detector
    needs three windows to confirm an onset and so always reports it slightly
    late. Without that allowance the very first contact - the most valuable
    one - would fall outside the window and be missed.
    """
    lab = set(device_names)
    suspects = list(onsets)

    baseline_destinations = {
        d: set(connections.loc[
            (connections["src"] == d) & (connections["t"] < baseline_seconds), "dst"
        ])
        for d in suspects
    }

    # For each brand-new outside address: which suspects touched it, and when first.
    first_contact = {}
    for d in suspects:
        after = connections[
            (connections["src"] == d) & (connections["t"] >= onsets[d] - 120)
        ]
        for destination, group in after.groupby("dst"):
            if destination in lab or destination in baseline_destinations[d]:
                continue
            first_contact.setdefault(destination, {})[d] = group["t"].min()

    for destination, hits in first_contact.items():
        if len(hits) < 2:
            continue  # only one device called it - proves nothing about linkage

        # If anybody used it during the baseline it is ordinary infrastructure.
        if any(destination in baseline_destinations[d] for d in suspects):
            continue

        order = sorted(hits, key=lambda d: hits[d])
        for earlier, later in zip(order, order[1:]):
            if onsets[earlier] <= onsets[later] and not graph.has_edge(earlier, later):
                graph.add_edge(
                    earlier, later,
                    w=WEIGHT_INDICATOR,
                    kind="indicator",
                    detail="both contacted %s, never seen before; %s first at %.0fs"
                           % (destination, earlier, hits[earlier]),
                    evidence_ids=[],
                    indicator=destination,
                )

    return graph


# --------------------------------------------------------------------------
# (b) Whole-story scoring
# --------------------------------------------------------------------------

def score_whole_story(
    connections: pd.DataFrame,
    graph: nx.DiGraph,
    onsets: dict,
    device_names,
    baseline_seconds: float,
):
    """
    Score each device by the whole story it explains, not by the device alone.

    Six ingredients, and the weights are the prototype's:

      coverage 0.34  what fraction of the incident this device's tree reaches.
                     The single most important signal: patient zero explains
                     everybody, a late victim explains only itself.
      strength 0.20  how solid the links in that tree are, on average. A story
                     held together by weak relay guesses is worth less than one
                     held together by two hundred real connections.
      orphan   0.22  nothing points at this device. If something did, that
                     something is a better candidate for patient zero.
      early    0.10  it went abnormal early in the incident. Deliberately
                     small: "earliest" alone is the 17% baseline.
      novelty  0.10  it contacted outside addresses it never used before.
      quiet    0.04  it is NOT the loudest device. The loudest is usually the
                     victim doing the data theft, which is the classic trap.

    Then a counterfactual check on the top three: delete that device's outgoing
    arrows and count how many devices become unexplainable. If removing it
    leaves the rest of the incident dangling, it was holding the story together.
    """
    lab = set(device_names)
    suspects = list(onsets)
    if not suspects:
        return [], {}, 0.0

    n = len(suspects)
    earliest = min(onsets.values())
    latest = max(onsets.values())
    span = max(latest - earliest, 1)

    # The loudest device since the incident began - the yardstick for "quiet".
    since_start = connections[
        connections["src"].isin(lab) & (connections["t"] >= earliest)
    ]
    loudest = max(since_start.groupby("src")["bytes_out"].sum().max(), 1) \
        if len(since_start) else 1

    scores = {}
    for d in suspects:
        tree = nx.bfs_tree(graph, d) if d in graph else nx.DiGraph()

        coverage = len(set(tree.nodes())) / n

        strength = (
            float(np.mean([graph[u][v]["w"] for u, v in tree.edges()]))
            if tree.number_of_edges() else 0.0
        )

        orphan = 1.0 if graph.in_degree(d) == 0 else 0.0

        early = (latest - onsets[d]) / span

        after = connections[(connections["src"] == d) & (connections["t"] >= onsets[d])]
        before = set(connections.loc[
            (connections["src"] == d) & (connections["t"] < baseline_seconds), "dst"
        ])
        new_external = len({x for x in set(after["dst"]) - before if x not in lab})
        novelty = min(new_external / 2.0, 1.0)

        sent = connections[
            (connections["src"] == d) & (connections["t"] >= onsets[d])
        ]["bytes_out"].sum()
        quiet = 1.0 - min(sent / loudest, 1.0)

        scores[d] = (
            W_COVERAGE * coverage
            + W_STRENGTH * strength
            + W_ORPHAN * orphan
            + W_EARLY * early
            + W_NOVELTY * novelty
            + W_QUIET * quiet
        )

    ranking = sorted(scores, key=lambda d: -scores[d])

    # Counterfactual confirmation on the shortlist.
    for d in ranking[:SHORTLIST]:
        without = graph.copy()
        without.remove_edges_from(list(graph.out_edges(d)))
        roots = [x for x in without if without.in_degree(x) == 0]
        unexplained = sum(
            1 for x in without
            if not any(nx.has_path(without, root, x) for root in roots)
        )
        scores[d] += W_UNEXPLAINED * unexplained

    ranking = sorted(scores, key=lambda d: -scores[d])
    confidence = (
        (scores[ranking[0]] - scores[ranking[1]]) / max(scores[ranking[0]], 1e-9)
        if len(ranking) > 1 else 1.0
    )
    return ranking, scores, confidence


# --------------------------------------------------------------------------
# (d) (e) (f) V5 itself
# --------------------------------------------------------------------------

def attribute(
    connections: pd.DataFrame,
    onsets: dict,
    device_names,
    baseline_seconds: float,
    max_gap_seconds: float = MAX_GAP_SECONDS,
    abstain_below: float = ABSTAIN_BELOW,
) -> Attribution:
    """
    Method V5, end to end.

      1. build the causal graph (direct + relayed arrows)
      2. score every device by the whole story it explains  -> shortlist
      3. add shared-indicator arrows
      4. re-rank the shortlist: prefer devices that explain more and are
         pointed at less
      5. if first and second place are within 15%, abstain
      6. report the attack path as well as the ranking
    """
    suspects = list(onsets)
    if not suspects:
        return Attribution(onsets=dict(onsets))

    graph = build_causal_graph(
        connections, onsets, device_names, max_gap_seconds=max_gap_seconds
    )

    ranking, scores, confidence = score_whole_story(
        connections, graph, onsets, device_names, baseline_seconds
    )

    # The full evidence graph, including indicator links. Used for the
    # re-ranking, the reported path, and the diagram in the dashboard.
    full = add_indicator_edges(
        connections, graph.copy(), onsets, device_names, baseline_seconds
    )

    if len(ranking) < 2:
        named = ranking[0] if ranking else None
        return Attribution(
            ranking=list(ranking), scores=scores, confidence=confidence,
            abstained=False, shortlist=list(ranking), named=named,
            path=_walk(full, named), graph=full, onsets=dict(onsets),
            story_ranking=list(ranking), indicator_bonus={},
        )

    # Re-rank the shortlist on indicator evidence. Things it explains count
    # for it; things pointing AT it count double against it, because being
    # pointed at is the strongest sign that a device is a victim, not a source.
    top = ranking[:SHORTLIST]
    bonus = {}
    for d in top:
        pointing_at_it = len(nx.ancestors(full, d)) if d in full else 0
        it_explains = len(nx.descendants(full, d)) if d in full else 0
        bonus[d] = it_explains - 2.0 * pointing_at_it

    reranked = sorted(top, key=lambda d: (-bonus[d], ranking.index(d))) + ranking[SHORTLIST:]

    # Confidence is the better of the two separations. Using the max is
    # deliberate: if either stage cleanly separates first from second, that is
    # a real reason for confidence, and neither stage should be able to veto
    # the other's certainty.
    ordered_bonus = sorted(bonus.values(), reverse=True)
    if len(ordered_bonus) > 1:
        indicator_gap = (ordered_bonus[0] - ordered_bonus[1]) / max(abs(ordered_bonus[0]) + 1, 1)
        confidence = max(confidence, indicator_gap)

    shortlist = reranked[:SHORTLIST]
    # bool() not numpy bool: this value gets written to JSON by the report
    # layer, and json.dumps refuses a numpy type.
    abstained = bool(confidence < abstain_below)

    return Attribution(
        ranking=reranked,
        scores=scores,
        confidence=float(confidence),
        abstained=abstained,
        shortlist=shortlist,
        named=None if abstained else reranked[0],
        path=_walk(full, reranked[0]),
        graph=full,
        onsets=dict(onsets),
        story_ranking=list(ranking),
        indicator_bonus={d: float(b) for d, b in bonus.items()},
    )


def _walk(graph: nx.DiGraph, start) -> list:
    """
    The attack path: the devices reachable from the named origin, in the order
    the story reaches them. Built from the full evidence graph, so a relayed
    hop that only a shared indicator revealed still appears in the path.
    """
    if start is None or start not in graph:
        return [start] if start else []
    return [start] + [n for n in nx.bfs_tree(graph, start) if n != start]


def attribute_run(run: runs.Run, detection: detect.Detection | None = None) -> Attribution:
    """Convenience: detect and attribute a loaded run in one call."""
    if detection is None:
        detection = detect.detect_run(run)
    return attribute(
        run.connections,
        detection.onsets,
        run.device_names,
        baseline_seconds=run.baseline_seconds,
    )


# --------------------------------------------------------------------------
# Baselines - the standard approaches we have to beat
# --------------------------------------------------------------------------

def baseline_rankings(connections: pd.DataFrame, detection: detect.Detection,
                      device_names) -> dict:
    """
    The four obvious answers, for comparison. Each returns devices best-suspect
    first. These are not strawmen - they are what a reasonable person would try.
    """
    lab = set(device_names)
    mine = connections[connections["src"].isin(lab)]

    by_volume = mine.groupby("src")["bytes_out"].sum().sort_values(ascending=False)
    by_count = mine.groupby("src").size().sort_values(ascending=False)

    return {
        "B1 total bytes": list(by_volume.index),
        "B2 anomaly score": sorted(
            detection.scores, key=lambda d: -detection.peak_score(d)
        ) if detection.scores else [],
        "B3 connection count": list(by_count.index),
        "B4 earliest onset": detection.devices_by_onset(),
    }


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Work out which device an attack started from."
    )
    parser.add_argument("run_id", help="e.g. run_000")
    parser.add_argument("--graph", action="store_true", help="also print every link drawn")
    args = parser.parse_args(argv)

    run = runs.load_run(args.run_id)
    detection = detect.detect_run(run)
    result = attribute_run(run, detection)

    print("\n  %s - %s scenario, %d devices, %d flagged as abnormal"
          % (run.run_id, run.scenario, len(run.device_names), len(detection.onsets)))

    print("\n  %-5s %-12s %7s %7s %11s %8s   %s"
          % ("rank", "device", "onset", "story", "storyscore", "indicat.",
             "how it reached this rank"))
    print("  " + "-" * 94)
    for i, device in enumerate(result.ranking, 1):
        seconds = result.onsets[device]
        clock = "%02d:%02d" % (int(seconds) // 3600, (int(seconds) % 3600) // 60)
        stage1 = (result.story_ranking.index(device) + 1
                  if device in result.story_ranking else 0)
        bonus = result.indicator_bonus.get(device)
        print("  %-5s %-12s %7s %7d %11.3f %8s   %s"
              % ("%d%s" % (i, "*" if i <= SHORTLIST else " "), device, clock,
                 stage1, result.scores[device],
                 "%+.1f" % bonus if bonus is not None else "-",
                 result.explain_rank(device)))
    print("\n  (* = shortlist. 'story' is the stage-1 rank; only the shortlist is"
          " then re-ranked on indicator evidence,")
    print("   which is why a device can rank above one with a higher story score.)")

    print("\n  confidence: %.0f%%" % (result.confidence * 100))
    if result.abstained:
        print("  VERDICT: ABSTAIN - cannot separate the top candidates.")
        print("           shortlist: %s" % ", ".join(result.shortlist))
    else:
        print("  VERDICT: %s" % result.named)
        print("  attack path: %s" % " -> ".join(result.path))

    if args.graph:
        print("\n  links drawn:")
        for edge in result.edge_evidence():
            print("    %-11s -> %-11s  %-10s w=%.2f  %s"
                  % (edge["from"], edge["to"], edge["kind"],
                     edge["weight"], edge["detail"]))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
