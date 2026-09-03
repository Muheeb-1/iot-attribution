"""
THE DASHBOARD - one page a human actually looks at.

Streamlit only. No Node, no React, no build step: this is a Python file, and
`streamlit run` is the whole toolchain. That matters for a project that has to
be demonstrated on someone else's machine.

WHAT IS ON THE PAGE
-------------------
  1. The verdict      which device started it, and how sure we are - or an
                      honest "cannot tell, here are three" when it abstains.
  2. The network      every device as a dot, every link the analysis drew as
                      an arrow, with the attack path picked out in red.
  3. The timeline     when each device went abnormal, in clock time.
  4. The ranking      every suspect with a confidence bar.
  5. The brief        the plain-English incident report from step 7.

REPLAY MODE - WHY IT EXISTS
---------------------------
A live demo has three ways to fail: the network is down, Ollama is not
running, or the model produces something the validator rejects while an
examiner watches.

Replay mode removes all three. It reads a traffic file already saved on disk,
runs the real pipeline over it - features, detection, attribution, all of it,
nothing faked - and produces the brief from the plain template instead of
calling the model. With the machine in aeroplane mode it still shows a
complete, honest analysis. It is on by default, because a demo that cannot
fail is worth more than a demo that shows off.

The only thing replay mode skips is the language model. Every number on the
page is computed live from the traffic.

A NOTE ON THE ANSWER SHEET
--------------------------
There is a "reveal the answer" switch, off by default. It reads
groundtruth/ purely to draw a tick or a cross next to the verdict, and it
runs AFTER the analysis has completely finished. Nothing it reads can reach
the pipeline. It is here because the first question anyone asks during a
demonstration is "was it right?", and the honest way to answer that is to
show the answer being checked rather than asserted.

RUN IT
------
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

# Streamlit executes this file directly, so the project root is not on the
# import path yet. Put it there before importing anything from src/.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import plotly.graph_objects as go
import streamlit as st

from src import attribute, detect, features, report, runs

# Colours, chosen to stay legible on Streamlit's light and dark themes.
COLOUR_ORIGIN = "#d62728"      # the named origin - red
COLOUR_SHORTLIST = "#ff7f0e"   # on the shortlist - orange
COLOUR_FLAGGED = "#ffbb44"     # went abnormal, not a leading suspect - amber
COLOUR_CLEAN = "#b8c4cc"       # never flagged - grey
COLOUR_PATH = "#d62728"        # attack path edges
COLOUR_EDGE = "#95a5a6"        # every other edge

EDGE_STYLE = {
    "direct": "solid",
    "indicator": "dash",
    "relay": "dot",
}


# --------------------------------------------------------------------------
# Pure helpers - no Streamlit in here, so they can be tested normally
# --------------------------------------------------------------------------

def circle_layout(names) -> dict:
    """Place devices evenly around a circle. Stable, so the picture does not
    jump around between reruns."""
    names = list(names)
    count = max(len(names), 1)
    positions = {}
    for i, name in enumerate(names):
        angle = 2 * math.pi * i / count - math.pi / 2
        positions[name] = (math.cos(angle), math.sin(angle))
    return positions


def device_role(device: str, result: attribute.Attribution,
                detection: detect.Detection) -> str:
    """Which of the four categories a device falls into, for colouring."""
    if not result.abstained and device == result.named:
        return "origin"
    if device in result.shortlist:
        return "shortlist"
    if device in detection.onsets:
        return "flagged"
    return "clean"


ROLE_COLOUR = {
    "origin": COLOUR_ORIGIN,
    "shortlist": COLOUR_SHORTLIST,
    "flagged": COLOUR_FLAGGED,
    "clean": COLOUR_CLEAN,
}
ROLE_LABEL = {
    "origin": "named origin",
    "shortlist": "on the shortlist",
    "flagged": "went abnormal",
    "clean": "nothing unusual",
}


def path_edges(path) -> set:
    """The consecutive pairs along the reconstructed attack path."""
    return set(zip(path, path[1:]))


def network_figure(run: runs.Run, detection: detect.Detection,
                   result: attribute.Attribution) -> go.Figure:
    """
    The network as a picture: a dot per device, an arrow per link the analysis
    drew, and the attack path in red.
    """
    positions = circle_layout(run.device_names)
    on_path = path_edges(result.path)
    figure = go.Figure()

    # Edges first, so nodes sit on top of them.
    for kind in ("relay", "indicator", "direct"):
        for highlight in (False, True):
            xs, ys, labels = [], [], []
            for u, v, data in result.graph.edges(data=True):
                if data.get("kind", "direct") != kind:
                    continue
                if ((u, v) in on_path) != highlight:
                    continue
                if u not in positions or v not in positions:
                    continue
                x0, y0 = positions[u]
                x1, y1 = positions[v]
                xs += [x0, x1, None]
                ys += [y0, y1, None]
                labels.append("%s -> %s (%s)" % (u, v, kind))
            if not xs:
                continue
            figure.add_trace(go.Scatter(
                x=xs, y=ys, mode="lines",
                line=dict(
                    color=COLOUR_PATH if highlight else COLOUR_EDGE,
                    width=4 if highlight else 1.5,
                    dash=EDGE_STYLE.get(kind, "solid"),
                ),
                hoverinfo="text",
                text="<br>".join(labels),
                name="%s link%s" % (kind, " (attack path)" if highlight else ""),
                showlegend=True,
            ))

    # Nodes, one trace per role so the legend explains the colours.
    for role in ("origin", "shortlist", "flagged", "clean"):
        members = [d for d in run.device_names
                   if device_role(d, result, detection) == role]
        if not members:
            continue
        hover = []
        for device in members:
            onset = detection.onsets.get(device)
            rank = result.ranking.index(device) + 1 if device in result.ranking else None
            hover.append(
                "<b>%s</b><br>%s<br>%s" % (
                    device,
                    "went abnormal at %s" % report.clock(onset) if onset is not None
                    else "never flagged",
                    "rank %d of %d" % (rank, len(result.ranking)) if rank else "not ranked",
                )
            )
        figure.add_trace(go.Scatter(
            x=[positions[d][0] for d in members],
            y=[positions[d][1] for d in members],
            mode="markers+text",
            marker=dict(size=30 if role == "origin" else 22,
                        color=ROLE_COLOUR[role],
                        line=dict(width=2, color="white")),
            text=members,
            textposition="top center",
            textfont=dict(size=11),
            hoverinfo="text",
            hovertext=hover,
            name=ROLE_LABEL[role],
        ))

    figure.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.18, x=0),
        margin=dict(l=10, r=10, t=10, b=10),
        height=440,
        xaxis=dict(visible=False, range=[-1.45, 1.45]),
        yaxis=dict(visible=False, range=[-1.45, 1.45], scaleanchor="x"),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return figure


def timeline_figure(run: runs.Run, detection: detect.Detection,
                    result: attribute.Attribution) -> go.Figure:
    """When each device went abnormal, in clock time, earliest at the top."""
    ordered = detection.devices_by_onset()
    figure = go.Figure()

    if not ordered:
        figure.add_annotation(text="no device was flagged in this run",
                              showarrow=False)
        figure.update_layout(height=220)
        return figure

    for role in ("origin", "shortlist", "flagged"):
        members = [d for d in ordered if device_role(d, result, detection) == role]
        if not members:
            continue
        figure.add_trace(go.Scatter(
            x=[detection.onsets[d] / 3600.0 for d in members],
            y=members,
            mode="markers",
            marker=dict(size=16, color=ROLE_COLOUR[role],
                        line=dict(width=2, color="white")),
            name=ROLE_LABEL[role],
            hovertext=["%s went abnormal at %s"
                       % (d, report.clock(detection.onsets[d])) for d in members],
            hoverinfo="text",
        ))

    figure.add_vline(
        x=run.baseline_seconds / 3600.0,
        line=dict(color="#7f8c8d", width=2, dash="dash"),
        annotation_text="baseline ends",
        annotation_position="top",
    )

    figure.update_layout(
        height=max(240, 42 * len(ordered) + 90),
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(title="hours into the capture",
                   range=[0, run.capture_seconds / 3600.0]),
        yaxis=dict(categoryorder="array", categoryarray=list(reversed(ordered))),
        legend=dict(orientation="h", yanchor="bottom", y=-0.3, x=0),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return figure


def ranking_rows(result: attribute.Attribution, detection: detect.Detection) -> list:
    """
    The ranking as plain rows, with each score scaled to a 0-1 bar.

    The bar is the whole-story score relative to the leader, which is what the
    ranking is built from. It is NOT the confidence figure - confidence is a
    single number about the gap between first and second, shown separately.
    """
    if not result.ranking:
        return []
    top_score = max(result.scores.values()) or 1.0
    rows = []
    for position, device in enumerate(result.ranking, 1):
        score = result.scores[device]
        rows.append({
            "position": position,
            "device": device,
            "score": score,
            "bar": max(0.0, min(1.0, score / top_score)),
            "onset": report.clock(detection.onsets[device])
            if device in detection.onsets else "-",
            "explanation": result.explain_rank(device),
            "shortlisted": device in result.shortlist,
        })
    return rows


def load_answer_for_display(run_id: str):
    """
    Read the answer sheet, for the 'was it right?' tick only.

    This is called AFTER the analysis is complete and its result is never fed
    back into anything. It exists so a demonstration can show the answer being
    checked rather than merely asserted.
    """
    path = ROOT / "groundtruth" / ("%s.json" % run_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def ollama_is_awake(timeout: float = 1.5) -> bool:
    """Is a local model server there? Used only to tell the user, never to fail."""
    try:
        import requests
        requests.get("http://localhost:11434/api/tags", timeout=timeout)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# The analysis, cached so the page stays responsive
# --------------------------------------------------------------------------

@st.cache_data(show_spinner=False)
def analyse(run_id: str):
    """Run the whole pipeline over one saved capture."""
    run = runs.load_run(run_id)
    detection = detect.detect_run(run)
    result = attribute.attribute_run(run, detection)
    evidence = report.build_evidence(run, detection, result)
    return run, detection, result, evidence


@st.cache_data(show_spinner=False)
def make_brief(run_id: str, offline: bool, nonce: int = 0):
    """Produce the incident brief. Cached so it is not regenerated on every click."""
    run, detection, result, evidence = analyse(run_id)
    facts = report.allowed_facts_from(evidence, run)
    outcome = report.generate_brief(evidence, facts, run, result, offline=offline)
    return outcome


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="IoT Incident Attribution",
                       page_icon="🔎", layout="wide")

    st.title("IoT Incident Attribution")
    st.caption("Which device did the attack start from - and what should be "
               "done about it?")

    available = runs.list_runs()
    if not available:
        st.error("No captures found in `data/`.")
        st.code("python -m src.generate --runs 30\n"
                "python -m src.generate --runs 30 --easy", language="bash")
        st.stop()

    # ---- sidebar -------------------------------------------------------
    with st.sidebar:
        st.header("Capture")
        run_id = st.selectbox("Which incident?", available,
                              index=available.index("run_000")
                              if "run_000" in available else 0)

        st.header("Demo safety")
        replay = st.toggle(
            "Replay mode", value=True,
            help="Reads a capture already on disk and skips the language "
                 "model. The full analysis still runs. Nothing needs to be "
                 "connected.",
        )
        if replay:
            st.success("Replay mode: nothing external is contacted.")
        else:
            if ollama_is_awake():
                st.info("Live mode: the brief will be written by qwen3:4b.")
            else:
                st.warning("Live mode selected, but no model server answered "
                           "on port 11434. The brief will fall back to the "
                           "plain template.")

        if st.button("Rewrite the brief", disabled=replay,
                     help="Ask the model again. Replay mode uses the template."):
            st.session_state["nonce"] = st.session_state.get("nonce", 0) + 1

        st.header("Demonstration")
        reveal = st.checkbox(
            "Reveal the true answer", value=False,
            help="Reads the answer sheet purely to mark the verdict right or "
                 "wrong. It runs after the analysis and cannot influence it.",
        )

        st.divider()
        st.caption("Streamlit only - no Node, no React, no build step.")

    with st.spinner("Running the analysis over the capture..."):
        run, detection, result, evidence = analyse(run_id)

    # ---- the verdict ---------------------------------------------------
    left, right = st.columns([3, 2])

    with left:
        if result.abstained:
            st.warning("**Cannot say which device started it.** "
                       "The top candidates are too close to separate.")
            st.markdown("**Shortlist:** " + ", ".join(
                "`%s`" % d for d in result.shortlist))
        else:
            st.error("**The attack started on `%s`.**" % result.named)
            if len(result.path) > 1:
                st.markdown("**Spread:** " + " → ".join(
                    "`%s`" % d for d in result.path))

    with right:
        a, b, c = st.columns(3)
        a.metric("Confidence", "%d%%" % result.confidence_percent)
        b.metric("Flagged", "%d of %d" % (len(detection.onsets),
                                          len(run.device_names)))
        c.metric("Connections", "{:,}".format(len(run.connections)))

    if reveal:
        answer = load_answer_for_display(run_id)
        if answer is None:
            st.info("No answer file saved for this capture.")
        else:
            origin = answer["origin"]
            rank = result.ranking.index(origin) + 1 if origin in result.ranking else None
            if rank == 1:
                st.success("Correct. The attack really did start on `%s`. "
                           "True chain: %s" % (origin, " → ".join(answer["chain"])))
            elif rank is not None and rank <= 3:
                st.warning("Not first, but on the shortlist: `%s` was ranked "
                           "%d. True chain: %s"
                           % (origin, rank, " → ".join(answer["chain"])))
            elif rank is not None:
                st.error("Wrong. `%s` was the real origin, ranked %d. "
                         "True chain: %s" % (origin, rank, " → ".join(answer["chain"])))
            else:
                st.error("`%s` was the real origin, and the detector never "
                         "flagged it, so it could not be ranked at all." % origin)

    st.divider()

    # ---- network and ranking ------------------------------------------
    diagram, ranking = st.columns([3, 2])

    with diagram:
        st.subheader("The network")
        st.caption("Every device on the site. Arrows are links the analysis "
                   "drew between them; the attack path is picked out in red. "
                   "Solid = a real connection, dashed = the same new outside "
                   "address, dotted = a shared middleman.")
        st.plotly_chart(network_figure(run, detection, result),
                        use_container_width=True)

    with ranking:
        st.subheader("Suspects")
        st.caption("Bars show how complete a story each device explains, "
                   "relative to the leader.")
        rows = ranking_rows(result, detection)
        if not rows:
            st.info("No device was flagged, so there is nobody to rank.")
        for row in rows:
            label = "**%d. `%s`**" % (row["position"], row["device"])
            if row["position"] == 1 and not result.abstained:
                label += "  ← named"
            elif row["shortlisted"]:
                label += "  · shortlist"
            st.markdown(label)
            st.progress(row["bar"])
            st.caption("went abnormal %s · %s" % (row["onset"], row["explanation"]))

    st.divider()

    # ---- timeline ------------------------------------------------------
    st.subheader("When each device went abnormal")
    st.caption("Everything to the left of the dashed line is the quiet period "
               "used to learn what normal looks like.")
    st.plotly_chart(timeline_figure(run, detection, result),
                    use_container_width=True)

    st.divider()

    # ---- the brief -----------------------------------------------------
    st.subheader("Incident brief")

    with st.spinner("Writing the brief..."):
        outcome = make_brief(run_id, replay, st.session_state.get("nonce", 0))
    brief = outcome.brief

    if outcome.is_fallback:
        if replay:
            st.info("**Plain template** - replay mode does not call the "
                    "language model, so the brief is generated mechanically "
                    "from the evidence.")
        else:
            st.warning("**LLM_FALLBACK** - the generated brief was rejected "
                       "for containing something that is not in the evidence, "
                       "twice. Showing the verified template instead.")
            with st.expander("Why it was rejected"):
                for line in outcome.rejections:
                    st.write("- %s" % line)
    else:
        st.success("Written by the model and checked against the evidence "
                   "(passed on attempt %d)." % outcome.attempts)

    st.markdown("### %s" % brief.headline)

    one, two = st.columns([2, 3])
    with one:
        st.markdown("**Origin:** `%s`" % brief.origin.device)
        st.markdown("**Confidence:** %d%% (%s)"
                    % (brief.origin.confidence, brief.origin.label))
        st.markdown("**Affected:** " + ", ".join("`%s`" % d
                                                 for d in brief.affected_devices))
    with two:
        st.markdown("**What we are not sure about**")
        st.info(brief.uncertainty)

    st.markdown("**What happened**")
    for entry in brief.timeline:
        st.markdown("- **%s · `%s`** — %s  \n  <span style='color:#7f8c8d'>"
                    "evidence: %s</span>"
                    % (entry.time, entry.device, entry.what_happened,
                       ", ".join(entry.evidence_ids)),
                    unsafe_allow_html=True)

    st.markdown("**What to do**")
    for action in sorted(brief.actions, key=lambda a: a.order):
        st.markdown("%d. **[%s]** %s  \n   *%s*"
                    % (action.order, action.urgency.upper(), action.action,
                       action.why))

    # ---- the evidence behind it ----------------------------------------
    with st.expander("The evidence behind this verdict"):
        st.markdown("**Links the analysis drew**")
        edges = result.edge_evidence()
        if edges:
            st.dataframe(
                [{"from": e["from"], "to": e["to"], "kind": e["kind"],
                  "weight": e["weight"], "why": e["detail"]} for e in edges],
                use_container_width=True, hide_index=True,
            )
        else:
            st.write("No links could be drawn between the flagged devices. "
                     "That is usually why the analysis abstains.")

        st.markdown("**Connections cited as evidence**")
        st.dataframe(evidence["connections"], use_container_width=True,
                     hide_index=True)


if __name__ == "__main__":
    main()
