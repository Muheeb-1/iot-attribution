"""
THE DASHBOARD - the entry point, and the "Past sessions" page.

`streamlit run dashboard/app.py` opens two pages, switched in the top bar:
"Live monitor" (dashboard/live_page.py, the page it opens on) and "Past
sessions" (this file's replay_page - the last rung of the fallback ladder,
which needs nothing but the saved runs in data/; it opens on the newest real
live session). Both share dashboard/theme.py: the dark
console colours and the Plotly template (Step P1 of docs/POLISH_PLAN.md).

Streamlit only. No Node, no React, no build step: this is a Python file, and
`streamlit run` is the whole toolchain. That matters for a project that has to
be demonstrated on someone else's machine.

WHAT IS ON THE PAST SESSIONS PAGE
---------------------------------
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
At the bottom, in a collapsed "Lab validation" section, a box "Compare with
the recorded answer", off by default. It reads groundtruth/ purely to say
right or wrong, and it runs AFTER the analysis has completely finished. Nothing it reads can reach
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
import re
import sys
from pathlib import Path

# Streamlit executes this file directly, so the project root is not on the
# import path yet. Put it there before importing anything from src/.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import plotly.graph_objects as go
import streamlit as st

from dashboard import theme
from src import attribute, detect, features, incident, report, runs

# Colours, from the console theme (dashboard/theme.py) so both pages match.
# Four roles, four hues that cannot be confused (Step P1b: the old orange
# "shortlist" and amber "went abnormal" looked the same on the dark page).
COLOUR_ORIGIN = theme.ALERT     # the named origin - red
COLOUR_SHORTLIST = theme.WATCH  # on the shortlist - amber
COLOUR_FLAGGED = theme.FLAGGED  # went abnormal, not a leading suspect - violet
COLOUR_CLEAN = theme.BAR        # never flagged - grey
COLOUR_PATH = theme.ALERT       # attack path edges
COLOUR_EDGE = theme.MUTED       # every other edge

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
                   result: attribute.Attribution, clock=report.clock) -> go.Figure:
    """
    The network as a picture: a dot per device, an arrow per link the analysis
    drew, and the attack path in red.

    clock turns "seconds into the capture" into the text shown on hover. The
    replay page shows the capture's own clock (00:16:00); the live page passes
    a wall-clock version (14:32:05).
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
                    "went abnormal at %s" % clock(onset) if onset is not None
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
                        line=dict(width=2, color=theme.TEXT)),
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
                        line=dict(width=2, color=theme.TEXT)),
            name=ROLE_LABEL[role],
            hovertext=["%s went abnormal at %s"
                       % (d, report.clock(detection.onsets[d])) for d in members],
            hoverinfo="text",
        ))

    figure.add_vline(
        x=run.baseline_seconds / 3600.0,
        line=dict(color=theme.SOFT, width=2, dash="dash"),
        annotation_text="baseline ends",
        annotation_position="top",
    )

    figure.update_layout(
        height=max(280, 42 * len(ordered) + 150),
        # The left margin fits the longest device name, and the bottom one
        # the hour ticks, the axis title and the legend (Step P1b: names, ticks
        # and title were cut off or overlapping); automargin lets Plotly widen
        # either further if a font is wider than expected.
        margin=dict(l=name_margin(ordered), r=10, t=30, b=90),
        xaxis=dict(title="hours into the capture",
                   range=[0, run.capture_seconds / 3600.0], automargin=True),
        yaxis=dict(categoryorder="array", categoryarray=list(reversed(ordered)),
                   automargin=True),
        showlegend=True,
        legend=dict(orientation="h", yanchor="top", y=-0.32, x=0),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    return figure


def name_margin(names, px_per_char: float = 8.5, padding: int = 24) -> int:
    """Left margin, in pixels, wide enough for the longest name at 13 px."""
    longest = max((len(str(n)) for n in names), default=0)
    return int(round(longest * px_per_char + padding))


def default_run(available) -> str | None:
    """
    The run the Past sessions page opens on: the newest real live session
    (live_session_NN, highest number, leaving out aborted sessions that have
    no attack), else the newest real lab capture, else the first that is not
    simulated. Never a simulated run_* while a real capture exists (Step P1b).
    """
    available = list(available)
    if not available:
        return None
    try:
        from src.evaluate import ABORTED_SESSIONS
    except Exception:                      # the page must open whatever happens
        ABORTED_SESSIONS = {}

    def number(run_id):
        digits = re.findall(r"\d+", run_id)
        return int(digits[-1]) if digits else -1

    for prefix in ("live_session_", "lab_batch_", "lab_", "rehearsal_"):
        real = [r for r in available if r.startswith(prefix) and r not in ABORTED_SESSIONS]
        if real:
            return max(real, key=number)
    not_simulated = [r for r in available if not r.startswith("run_")]
    return not_simulated[0] if not_simulated else available[0]


def ranking_rows(result: attribute.Attribution, detection: detect.Detection,
                 clock=report.clock) -> list:
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
            "onset": clock(detection.onsets[device])
            if device in detection.onsets else "-",
            "explanation": result.explain_rank(device),
            "shortlisted": device in result.shortlist,
        })
    return rows


def start_epoch(run_id: str):
    """The capture's wall-clock start, if the run recorded it (live sessions do)."""
    try:
        meta = json.loads(runs.meta_path(run_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return meta.get("capture_start_epoch")


def load_answer_for_display(run_id: str):
    """
    Read the answer sheet, for the 'was it right?' tick only.

    This is called AFTER the analysis is complete and its result is never fed
    back into anything. It exists so a demonstration can show the answer being
    checked rather than merely asserted.
    """
    path = ROOT / "groundtruth" / ("%s.json" % run_id)
    if not path.exists():
        # A re-converted run (lab_batch_05) is the same capture as the run it
        # replaces (live_batch_05), so it shares that run's answer file.
        replaces = replaced_run(run_id)
        if not replaces:
            return None
        path = ROOT / "groundtruth" / ("%s.json" % replaces)
        if not path.exists():
            return None
    return json.loads(path.read_text(encoding="utf-8"))


def replaced_run(run_id: str):
    """The run this one is a fresh conversion of (src/reconvert.py), or None."""
    try:
        meta = json.loads(runs.meta_path(run_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return meta.get("replaces")


def run_label(run_id: str, came_from: dict) -> str:
    """What the run picker shows: the id, plus where a re-converted run came from."""
    old = came_from.get(run_id)
    return "%s  (= %s, today's rules)" % (run_id, old) if old else run_id


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


# Who writes the brief. "template" contacts nothing and cannot fail; the two
# models go through the evidence validator and fall back to the template.
WRITERS = {
    "template": "Plain template (nothing contacted)",
    "local": "Local model - %s via Ollama" % report.DEFAULT_MODEL["local"],
    "cloud": "Cloud model - %s" % report.DEFAULT_MODEL["cloud"],
}


def cloud_key_present() -> bool:
    """Is the cloud key file there? Checked only to warn; it is never opened here."""
    return (ROOT / report.API_KEY_FILE).exists() or Path(report.API_KEY_FILE).exists()


@st.cache_data(show_spinner=False)
def make_brief(run_id: str, writer: str = "template", nonce: int = 0):
    """Produce the incident brief. Cached so it is not regenerated on every click."""
    run, detection, result, evidence = analyse(run_id)
    facts = report.allowed_facts_from(evidence, run)
    if writer == "template":
        return report.generate_brief(evidence, facts, run, result, offline=True)
    return report.generate_brief(evidence, facts, run, result, provider=writer)


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def live_monitor_page() -> None:
    """
    The live page lives in dashboard/live_page.py. It is imported here, when
    the page is opened, not at the top of the file: if anything in it were
    broken, the Past sessions page - the last rung of the fallback ladder -
    must still open.
    """
    try:
        from dashboard import live_page
    except Exception as exc:                 # keep the Past sessions page alive whatever happens
        st.set_page_config(page_title="IoT Incident Attribution", layout="wide")
        st.error("The live page could not be loaded: %s" % exc)
        st.info("Use the Past sessions page, or run  streamlit run dashboard/live_page.py")
        return
    live_page.page_config()
    live_page.render_page()


def main() -> None:
    # No set_page_config here: Streamlit allows one per run, and each page sets
    # its own (the live page starts with the sidebar collapsed; this page keeps
    # it open, because its run picker is there).
    # The app opens on the Live monitor (Step P1b); Past sessions is one click
    # away in the top bar, and is still the last rung of the fallback ladder.
    pages = st.navigation([
        st.Page(live_monitor_page, title="Live monitor", icon="📡", url_path="live",
                default=True),
        st.Page(replay_page, title="Past sessions", icon="🔎", url_path="replay"),
    ])
    pages.run()


def replay_page() -> None:
    st.set_page_config(page_title="IoT Incident Attribution - past sessions",
                       page_icon="🔎", layout="wide", initial_sidebar_state="expanded")
    theme.inject()
    st.html(theme.top_bar(None, page="past"))
    st.title("Past sessions")
    st.caption("Which device did the attack start from - and what should be "
               "done about it? Pick a saved capture in the sidebar; the whole "
               "analysis runs again on its traffic.")

    # Runs that a fresh conversion has replaced are hidden here (they were
    # saved under the pre-Step-18 rules and this page analyses with today's);
    # they stay on disk for evaluate.py. See runs.replay_runs.
    available = runs.replay_runs()
    came_from = {new: old for old, new in runs.replaced_by().items()}
    if not available:
        st.error("No captures found in `data/`.")
        st.code("python -m src.generate --runs 30\n"
                "python -m src.generate --runs 30 --easy", language="bash")
        st.stop()

    # ---- sidebar -------------------------------------------------------
    with st.sidebar:
        st.header("Capture")
        run_id = st.selectbox("Which incident?", available,
                              index=available.index(default_run(available)),
                              format_func=lambda r: run_label(r, came_from))

        st.header("Who writes the brief")
        writer = st.radio(
            "Brief written by", list(WRITERS), format_func=WRITERS.get, index=0,
            help="The analysis is identical whichever you pick. A model only "
                 "rewords it, is checked against the evidence, and falls back "
                 "to the template if it invents anything.",
        )
        replay = writer == "template"
        if writer == "template":
            st.success("Nothing external is contacted.")
        elif writer == "local":
            if ollama_is_awake():
                st.info("The brief will be written by %s." % report.DEFAULT_MODEL["local"])
            else:
                st.warning("No model server answered on port 11434. The brief "
                           "will fall back to the plain template.")
        elif not cloud_key_present():
            st.warning("%s not found, so the cloud model cannot be called. The "
                       "brief will fall back to the plain template." % report.API_KEY_FILE)
        else:
            st.info("The brief will be written by %s (needs internet)."
                    % report.DEFAULT_MODEL["cloud"])

        if st.button("Rewrite the brief", disabled=replay,
                     help="Ask the model again. The template never changes."):
            st.session_state["nonce"] = st.session_state.get("nonce", 0) + 1


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

    st.divider()

    # ---- network and ranking ------------------------------------------
    diagram, ranking = st.columns([3, 2])

    with diagram:
        st.subheader("The network")
        st.caption("Every device on the site. Arrows are links the analysis "
                   "drew between them; the attack path is picked out in red. "
                   "Solid = a real connection, dashed = the same new outside "
                   "address, dotted = a shared middleman.")
        st.plotly_chart(theme.styled(network_figure(run, detection, result)),
                        use_container_width=True, theme=None)

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
    st.plotly_chart(theme.styled(timeline_figure(run, detection, result)),
                    use_container_width=True, theme=None)

    st.divider()

    # ---- the brief -----------------------------------------------------
    st.subheader("Incident brief")

    with st.spinner("Writing the brief..."):
        outcome = make_brief(run_id, writer, st.session_state.get("nonce", 0))
    brief = outcome.brief

    if outcome.is_fallback:
        if replay:
            st.info("**Plain template** - no language model was asked, so "
                    "the brief is generated mechanically from the evidence.")
        else:
            st.warning("**LLM_FALLBACK** - the model's brief could not be used "
                       "(it did not answer, or twice wrote something that is "
                       "not in the evidence). Showing the verified template instead.")
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
        st.markdown("- **%s · `%s`** — %s  \n  <span style='color:#8496B5'>"
                    "evidence: %s</span>"
                    % (entry.time, entry.device, entry.what_happened,
                       ", ".join(entry.evidence_ids)),
                    unsafe_allow_html=True)

    st.markdown("**What to do**")
    for action in sorted(brief.actions, key=lambda a: a.order):
        st.markdown("%d. **[%s]** %s  \n   *%s*"
                    % (action.order, action.urgency.upper(), action.action,
                       action.why))

    # ---- the complete incident report (Step 19) -------------------------
    # The same eight-section report the live page shows, built from this
    # run's own analysis - so the last rung of the fallback ladder has it too.
    # Deterministic; a model's headline is added only if it passed the
    # validator above.
    if detection.onsets and result.ranking:
        try:
            full = incident.wording_from_brief(
                incident.build_incident(run, detection, result,
                                        capture_start_epoch=start_epoch(run_id)),
                outcome if not outcome.is_fallback else None)
            with st.expander("The complete incident report (eight sections)"):
                st.download_button("Download it (HTML, print to PDF from the browser)",
                                   data=incident.render_html(full),
                                   file_name="%s.html" % run_id, mime="text/html")
                st.text(incident.render_text(full))
        except Exception as exc:          # presentation only: never break the page
            st.caption("The complete report could not be built (%s)." % exc)

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

    draw_lab_validation(run_id, result)


def answer_verdict(answer, result: attribute.Attribution):
    """
    (kind, sentence) for the lab check: the recorded answer against the
    finished analysis. kind is success / warning / error / info. Pure, so it
    is tested directly.
    """
    if answer is None:
        return "info", "No answer file saved for this capture."
    origin = answer["origin"]
    chain = " → ".join(answer.get("chain") or [origin])
    rank = result.ranking.index(origin) + 1 if origin in result.ranking else None
    if rank == 1 and not result.abstained:
        return "success", "Correct. The attack really did start on `%s`. True chain: %s" % (
            origin, chain)
    if rank is not None and rank <= 3:
        return "warning", ("Not named first, but on the shortlist: `%s` was ranked %d. "
                           "True chain: %s" % (origin, rank, chain))
    if rank is not None:
        return "error", "Wrong. `%s` was the real origin, ranked %d. True chain: %s" % (
            origin, rank, chain)
    return "error", ("`%s` was the real origin, and the detector never flagged it, so it "
                     "could not be ranked at all." % origin)


def draw_lab_validation(run_id: str, result: attribute.Attribution) -> None:
    """
    The lab-only check, collapsed at the bottom - worded and behaving like the
    live page's (Step P1b; it used to be "Reveal the true answer" in the
    sidebar). It is drawn after the whole analysis has run, and the answer
    file is opened only when the box is ticked; nothing it reads goes back
    into the analysis.
    """
    with st.expander("Lab validation"):
        compare = st.checkbox("Compare with the recorded answer", value=False,
                              key="past-compare",
                              help="Opens the answer file the attack script wrote, only to "
                                   "mark the finished verdict right or wrong.")
        if compare:
            kind, sentence = answer_verdict(load_answer_for_display(run_id), result)
            {"success": st.success, "warning": st.warning, "error": st.error,
             "info": st.info}[kind](sentence)


if __name__ == "__main__":
    main()
