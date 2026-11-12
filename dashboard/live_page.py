"""
THE LIVE PAGE - the dashboard while the capture is still running.

WHAT IT SHOWS
-------------
It reads pcap/live/<session>/state.json, which the live engine (src/live.py)
rewrites every second or so, and redraws itself every 3 seconds:

  WAITING     no capture yet: the exact commands to start one
  LEARNING    the baseline countdown - do not attack yet
  MONITORING  "safe to launch the attack"; every device's strike meter
  INCIDENT    red banner: which device it started from, how sure, since when;
              the network, the suspects, the full incident report (Step 19)
  CONTAINED   green banner on top of the report: the named device has made no
              connection to its new destinations for 90 s
  STOPPED     the final verdict (identical to the offline analysis), where the
              session was saved, and the "reveal the true answer" tick

All times on the page are wall-clock times (capture start + seconds), so they
can be compared with the clock on the wall and with the attack command.

THE PAGE DECIDES NOTHING
------------------------
Every number on it comes from state.json, which the engine produced with the
unchanged pipeline. To draw the network and the suspect list the page rebuilds
the engine's Attribution and Detection objects FROM state.json
(objects_from_state) and hands them to the same functions the replay page
uses - network_figure and ranking_rows in dashboard/app.py. Nothing is
re-detected or re-ranked here; a test checks the rebuilt objects give exactly
the rows the engine's own objects give.

THE STRIKE METER IS NOT AN ALARM
--------------------------------
One abnormal minute names nobody. In the twelve real attacks the innocent
laptop had at least one abnormal minute in nine of them; alerting on one
minute would have blamed it most of the time. The detector waits for three in
a row (docs/LIVE_PLAN.md section 7). So the meter is drawn as a plain
"watching: 2 of 3 minutes" bar, never in alarm colours; only the incident
banner, which appears after the third minute, is red.

THE ANSWER SHEET
----------------
The reveal tick reads the answer file only once the session is STOPPED, i.e.
after the analysis has completely finished, exactly like the replay page.

RUN IT
------
    streamlit run dashboard/app.py          -> "Live monitor" in the sidebar
    streamlit run dashboard/live_page.py    -> this page on its own
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard import app
from src import attribute, detect, incident, live, runs

REFRESH_SECONDS = 3

# The engine rewrites state.json about once a second while a session runs.
# Silence for this long means it has stopped or crashed.
STALE_SECONDS = 20

# The score chart: attack minutes can score in the hundreds, which would flatten
# everything else into a line on the floor. Scores above this are drawn at the
# top edge, with the real value on hover.
SCORE_CHART_CAP = 25.0

PHASE_LABEL = {
    live.WAITING: "Waiting for the capture",
    live.LEARNING: "Learning what normal looks like",
    live.MONITORING: "Monitoring",
    live.INCIDENT: "INCIDENT",
    live.CONTAINED: "Contained",
    live.STOPPED: "Capture stopped - final verdict",
}


# --------------------------------------------------------------------------
# Finding and reading sessions
# --------------------------------------------------------------------------

def live_dir_default() -> Path:
    """pcap/live, or IOT_LIVE_DIR if set (the tests point it at fixtures)."""
    override = os.environ.get("IOT_LIVE_DIR")
    return Path(override) if override else live.LIVE_DIR


def list_sessions(live_dir: Path) -> list:
    """Sessions that have a state.json, the most recently updated first."""
    live_dir = Path(live_dir)
    if not live_dir.is_dir():
        return []
    found = []
    for folder in live_dir.iterdir():
        state_file = folder / live.STATE_FILE
        if folder.is_dir() and state_file.is_file():
            found.append((state_file.stat().st_mtime, folder.name))
    return [name for _, name in sorted(found, reverse=True)]


def read_state(live_dir: Path, session: str):
    """
    The session's state, or None. The engine writes the file atomically, so a
    half-written file cannot be seen; a read can still lose a race with the
    swap on Windows, and then the page simply shows the previous moment.
    """
    path = Path(live_dir) / session / live.STATE_FILE
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def next_session_name(live_dir: Path, data_dir: Path = runs.DATA_DIR,
                      prefix: str = "live_session_") -> str:
    """The first live_session_NN not used by a session folder or a saved run."""
    used = set()
    for folder in (Path(live_dir), Path(data_dir)):
        if folder.is_dir():
            for p in folder.iterdir():
                match = re.match(r"%s(\d+)" % re.escape(prefix), p.name)
                if match:
                    used.add(int(match.group(1)))
    n = 1
    while n in used:
        n += 1
    return "%s%02d" % (prefix, n)


def is_replay(live_dir: Path, session: str) -> bool:
    """A --replay session keeps its cut-up source capture beside the ring files."""
    return (Path(live_dir) / session / live.REPLAY_SOURCE).is_dir()


# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------

def wall(epoch) -> str:
    """Local clock time, HH:MM:SS."""
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(float(epoch)).strftime("%H:%M:%S")


def wall_at(state: dict, seconds) -> str:
    """Seconds into the capture -> local clock time."""
    start = state.get("capture_start_epoch")
    if start is None or seconds is None:
        return "-"
    return wall(start + float(seconds))


def capture_clock_to_wall(state: dict, text: str) -> str:
    """'00:16:00' (seconds-from-start, as the brief writes it) -> wall clock."""
    match = re.fullmatch(r"\s*(\d+):(\d{2}):(\d{2})\s*", str(text))
    if not match:
        return str(text)
    h, m, s = (int(x) for x in match.groups())
    return wall_at(state, h * 3600 + m * 60 + s)


def duration_text(seconds) -> str:
    """3 min 45 s, for countdowns and 'time to detect'."""
    if seconds is None:
        return "-"
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return "%d s" % seconds
    return "%d min %02d s" % (seconds // 60, seconds % 60)


def seconds_since_update(state: dict, now: float | None = None) -> float | None:
    updated = state.get("updated_epoch")
    if updated is None:
        return None
    return (time.time() if now is None else now) - updated


def is_stale(state: dict, now: float | None = None) -> bool:
    """Has a running session stopped being updated? A STOPPED one never is."""
    if state.get("phase") == live.STOPPED:
        return False
    age = seconds_since_update(state, now)
    return age is not None and age > STALE_SECONDS


# --------------------------------------------------------------------------
# What each part of the page says - plain functions, tested directly
# --------------------------------------------------------------------------

def baseline_progress(state: dict) -> dict:
    """How far through the baseline, and when it will be complete."""
    total = int(state.get("baseline_windows") or 0)
    done = min(int(state.get("closed_windows") or 0), total)
    start = state.get("capture_start_epoch")
    ends_seconds = (state.get("baseline_seconds") or 0) + (state.get("grace_seconds") or 0)
    return {
        "done": done,
        "total": total,
        "fraction": (done / total) if total else 0.0,
        "remaining_seconds": state.get("baseline_remaining_seconds"),
        "ends_at": wall(start + ends_seconds) if start is not None else "-",
    }


def device_rows(state: dict) -> list:
    """
    One row per device for the watch panel: the strike count and a plain
    label. The label never says "attack" - a strike is something to watch,
    not an accusation (see the module docstring).
    """
    consecutive = int(state.get("consecutive") or detect.CONSECUTIVE)
    threshold = state.get("threshold") or detect.THRESHOLD
    learning = state.get("phase") in (live.WAITING, live.LEARNING)
    rows = []
    for name, d in (state.get("devices") or {}).items():
        strikes = int(d.get("strikes") or 0)
        score = d.get("latest_score")
        contained = (state.get("containment") or {})
        if not d.get("seen"):
            status, label = "unseen", "not seen in this capture"
        elif d.get("onset") is not None and contained.get("contained") \
                and contained.get("device") == name:
            # Unplugged or blocked: still marked abnormal by the detector (it
            # went silent), but it is not attacking any more.
            status = "contained"
            label = "offline / contained since %s (abnormal since %s)" % (
                wall(contained.get("contained_epoch")), wall(d.get("onset_epoch")))
        elif d.get("onset") is not None:
            status = "flagged"
            label = "abnormal since %s (%d of %d minutes over the line)" % (
                wall(d.get("onset_epoch")), consecutive, consecutive)
        elif d.get("skipped"):
            status, label = "skipped", "too little traffic in the baseline to judge"
        elif learning or score is None:
            status, label = "learning", "learning its normal pattern"
        elif strikes:
            status = "watching"
            label = "watching: %d of %d minutes in a row over the line" % (strikes, consecutive)
        else:
            status = "normal"
            label = "normal (last minute scored %.1f, the line is %.1f)" % (score, threshold)
        rows.append({"device": name, "kind": d.get("kind", ""), "status": status,
                     "strikes": strikes, "fraction": min(1.0, strikes / consecutive),
                     "label": label})
    return rows


def headline(state: dict) -> dict:
    """
    The banner at the top: kind (info/success/error/warning), a title and one
    sentence. Everything a person in the room needs to know at a glance.
    """
    phase = state.get("phase", live.WAITING)
    named = state.get("named")
    alert = state.get("first_alert") or {}
    confidence = state.get("confidence_percent")

    if phase == live.WAITING:
        return {"kind": "info", "title": "Waiting for the capture to start",
                "text": "No capture file has arrived yet."}
    if phase == live.LEARNING:
        p = baseline_progress(state)
        return {"kind": "info", "title": "Learning what normal looks like - do not attack yet",
                "text": "Minute %d of %d of the baseline. Complete at %s (in about %s). "
                        "Anything that happens now is learned as normal."
                        % (p["done"], p["total"], p["ends_at"],
                           duration_text(p["remaining_seconds"]))}
    if phase == live.MONITORING:
        ended = wall_at(state, (state.get("baseline_seconds") or 0)
                        + (state.get("grace_seconds") or 0))
        return {"kind": "success", "title": "Monitoring - safe to launch the attack",
                "text": "Baseline learned at %s. Every device is being watched; "
                        "nothing has been abnormal for %d minutes in a row."
                        % (ended, int(state.get("consecutive") or detect.CONSECUTIVE))}

    # INCIDENT, CONTAINED, STOPPED all carry a verdict, if there is one.
    if not state.get("onsets"):
        if phase == live.STOPPED:
            return {"kind": "success", "title": "Capture stopped - no incident",
                    "text": "No device was abnormal for %d minutes in a row."
                            % int(state.get("consecutive") or detect.CONSECUTIVE)}
        return {"kind": "info", "title": PHASE_LABEL.get(phase, phase), "text": ""}

    since = wall(alert.get("raised_epoch"))
    contained = state.get("containment") or {}
    if phase == live.CONTAINED and contained.get("contained"):
        return {"kind": "success",
                "title": "Contained at %s - %s has stopped" % (
                    wall(contained.get("contained_epoch")), contained.get("device")),
                "text": "No connection from %s to %s since %s. The incident report below "
                        "stays as the record; stop the capture when you are ready."
                        % (contained.get("device"), ", ".join(contained.get("watching") or []),
                           wall(contained.get("last_seen_epoch")))}
    prefix = "Final verdict: " if phase == live.STOPPED else ""
    if state.get("abstained"):
        return {"kind": "warning",
                "title": "%sIncident - starting device not certain" % prefix,
                "text": "Too close to call between %s (gap %s%%). Alert raised at %s."
                        % (", ".join(state.get("shortlist") or []), confidence, since)}
    return {"kind": "error" if phase == live.INCIDENT else "warning",
            "title": "%sIncident - the attack started on %s" % (prefix, named),
            "text": "Confidence %s%%. %s first abnormal at %s; alert raised at %s."
                    % (confidence, named, wall((state.get("devices") or {})
                                               .get(named, {}).get("onset_epoch")), since)}


def rejoin_lines(state: dict) -> list:
    """
    One line per baseline minute the detector left out of a device's normal
    because the device sent a DHCP broadcast then - it was joining or rejoining
    the network (Step 18, C3). Read from state.json; nothing is recomputed.
    """
    lines = []
    for device, minutes in sorted((state.get("rejoins") or {}).items()):
        for m in minutes or []:
            lines.append("%s rejoined the network at %s; that minute is not used as normal"
                         % (device, wall(m.get("epoch"))))
    return lines


def verdict_change_lines(state: dict) -> list:
    """'updated 14:32:05: ...' lines, for when a later minute changes the verdict."""
    changes = state.get("verdict_changes") or []
    lines = []
    for previous, change in zip(changes, changes[1:]):
        if change.get("abstained"):
            what = "abstains between %s" % ", ".join(change.get("ranking", [])[:3])
        else:
            what = "origin %s" % change.get("named")
        reason = []
        if change.get("named") != previous.get("named"):
            reason.append("origin changed from %s" % previous.get("named"))
        if change.get("confidence_percent") != previous.get("confidence_percent"):
            reason.append("confidence %s%% -> %s%%" % (previous.get("confidence_percent"),
                                                       change.get("confidence_percent")))
        if set(change.get("onsets", {})) != set(previous.get("onsets", {})):
            new = sorted(set(change.get("onsets", {})) - set(previous.get("onsets", {})))
            if new:
                reason.append("%s also went abnormal" % ", ".join(new))
        lines.append("updated %s: %s%s" % (wall(change.get("epoch")), what,
                                           " (%s)" % "; ".join(reason) if reason else ""))
    return lines


# --------------------------------------------------------------------------
# Rebuilding the engine's objects, so the replay page's drawings can be reused
# --------------------------------------------------------------------------

def objects_from_state(state: dict):
    """
    (run, detection, result) rebuilt from state.json - display copies of the
    engine's own objects, filled field by field from what it wrote. Nothing is
    computed: no detection, no ranking. The run carries no traffic, only the
    inventory and the timings the drawings need.
    """
    devices = state.get("devices") or {}
    scores = {}
    for name, d in devices.items():
        by_window = {int(w): float(s) for w, s in (d.get("scores_by_window") or {}).items()
                     if s is not None}
        if by_window:
            scores[name] = by_window
    detection = detect.Detection(
        scores=scores,
        onsets={k: float(v) for k, v in (state.get("onsets") or {}).items()},
        onset_windows={k: int(v) for k, v in (state.get("onset_windows") or {}).items()},
        skipped=[n for n, d in devices.items() if d.get("skipped")],
        threshold=float(state.get("threshold") or detect.THRESHOLD),
        consecutive=int(state.get("consecutive") or detect.CONSECUTIVE),
        window_seconds=int(state.get("window_seconds") or 60),
    )

    graph = nx.DiGraph()
    for e in state.get("edges") or []:
        graph.add_edge(e["from"], e["to"], kind=e.get("kind", "direct"),
                       w=e.get("weight", 0.0), detail=e.get("detail", ""),
                       evidence_ids=list(e.get("evidence_ids", [])))
    result = attribute.Attribution(
        ranking=list(state.get("ranking") or []),
        scores={k: float(v) for k, v in (state.get("scores") or {}).items()},
        confidence=float(state.get("confidence") or 0.0),
        abstained=bool(state.get("abstained")),
        shortlist=list(state.get("shortlist") or []),
        named=state.get("named"),
        path=list(state.get("path") or []),
        graph=graph,
        onsets=dict(detection.onsets),
        story_ranking=list(state.get("story_ranking") or []),
        indicator_bonus={k: float(v) for k, v in (state.get("indicator_bonus") or {}).items()},
    )
    run = runs.Run(
        run_id=state.get("session", "live"),
        scenario="capture",
        connections=pd.DataFrame(),
        device_names=list(devices),
        devices=[{"name": n, "kind": d.get("kind", "")} for n, d in devices.items()],
        window_seconds=int(state.get("window_seconds") or 60),
        capture_seconds=int(round(state.get("now_seconds") or 0)),
        baseline_seconds=int(state.get("baseline_seconds") or 0),
        baseline_windows=int(state.get("baseline_windows") or 0),
    )
    return run, detection, result


def score_figure(state: dict) -> go.Figure:
    """
    Each device's score for every finished minute, against the threshold line,
    in wall-clock time. Points are drawn in the middle of their minute.
    """
    figure = go.Figure()
    start = state.get("capture_start_epoch")
    width = int(state.get("window_seconds") or 60)
    threshold = float(state.get("threshold") or detect.THRESHOLD)
    devices = state.get("devices") or {}
    if start is None or not any(d.get("scores_by_window") for d in devices.values()):
        figure.add_annotation(text="no minute has been scored yet", showarrow=False)
        figure.update_layout(height=260, xaxis=dict(visible=False), yaxis=dict(visible=False))
        return figure

    def when(seconds):
        return datetime.fromtimestamp(start + seconds)

    for name, d in devices.items():
        windows_scored = sorted((int(w), s) for w, s in (d.get("scores_by_window") or {}).items()
                                if s is not None)
        if not windows_scored:
            continue
        xs = [when(w * width + width / 2) for w, _ in windows_scored]
        ys = [min(s, SCORE_CHART_CAP) for _, s in windows_scored]
        hover = ["%s, minute %s-%s: score %.1f" % (name, wall(start + w * width),
                                                   wall(start + (w + 1) * width), s)
                 for w, s in windows_scored]
        flagged = d.get("onset") is not None
        figure.add_trace(go.Scatter(
            x=xs, y=ys, mode="lines+markers", name=name,
            line=dict(width=3 if flagged else 1.5,
                      color=app.COLOUR_ORIGIN if name == state.get("named") else None),
            hovertext=hover, hoverinfo="text"))

    figure.add_hline(y=threshold, line=dict(color="#7f8c8d", width=2, dash="dash"),
                     annotation_text="the line (%.1f)" % threshold,
                     annotation_position="top left")
    baseline_end = when(state.get("baseline_seconds") or 0)
    figure.add_shape(type="line", x0=baseline_end, x1=baseline_end, y0=0, y1=1,
                     yref="paper", line=dict(color="#7f8c8d", width=1, dash="dot"))
    figure.add_annotation(x=baseline_end, y=1, yref="paper", text="baseline ends",
                          showarrow=False, yanchor="bottom")
    figure.update_layout(
        height=320, margin=dict(l=10, r=10, t=30, b=10),
        yaxis=dict(title="how unusual (score)", rangemode="tozero"),
        xaxis=dict(title="clock time", tickformat="%H:%M"),
        legend=dict(orientation="h", yanchor="bottom", y=-0.35, x=0),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
    return figure


def start_commands(session: str) -> str:
    return ("# 1. ordinary PowerShell, repo root - the engine\n"
            "python -m src.live --session %s\n\n"
            "# 2. ADMINISTRATOR PowerShell, repo root - the capture\n"
            "python -m src.live_capture --session %s\n\n"
            "# fallback - replay a recorded capture through the same page\n"
            "python -m src.live --session replay_01 --replay pcap\\segments\\live_batch_01.pcapng"
            % (session, session))


# --------------------------------------------------------------------------
# Drawing
# --------------------------------------------------------------------------

def _banner(kind: str, title: str, text: str) -> None:
    body = "**%s**" % title + ("  \n%s" % text if text else "")
    {"info": st.info, "success": st.success, "warning": st.warning,
     "error": st.error}.get(kind, st.info)(body)


def draw_waiting(live_dir: Path) -> None:
    st.info("**Waiting for a session.** No live session has started yet.")
    st.markdown("Start these two, in this order (the page picks the session up by itself):")
    st.code(start_commands(next_session_name(live_dir)), language="powershell")


def draw_state(state: dict, live_dir: Path, reveal: bool = False) -> None:
    """The whole page for one moment of one session."""
    session = state.get("session", "?")
    phase = state.get("phase", live.WAITING)
    replaying = is_replay(live_dir, session)

    top = st.columns([3, 1, 1, 1])
    top[0].markdown("#### Session `%s`%s" % (
        session, "  ·  replay of a recorded capture" if replaying else "  ·  live capture"))
    top[1].metric("Clock (capture)", wall(state.get("now_epoch")))
    top[2].metric("Packets", "{:,}".format(state.get("packets") or 0))
    top[3].metric("Connections", "{:,}".format(state.get("flows") or 0))

    if is_stale(state):
        st.warning("The engine has not updated this page for %s. Is "
                   "`python -m src.live --session %s` still running?"
                   % (duration_text(seconds_since_update(state)), session))

    if phase == live.WAITING:
        _banner(**headline(state))
        st.code(start_commands(session), language="powershell")
        return

    _banner(**headline(state))

    if phase == live.LEARNING:
        p = baseline_progress(state)
        st.progress(p["fraction"], text="baseline: %d of %d minutes learned"
                                        % (p["done"], p["total"]))
    if phase == live.MONITORING:
        st.markdown("Launch the attack from another terminal:")
        st.code("python -m src.scenario --run %s" % session, language="powershell")
    if phase == live.INCIDENT:
        line = containment_text(state)
        if line:
            st.warning(line)

    for line in verdict_change_lines(state):
        st.caption(line)

    alert = state.get("first_alert") or {}
    if alert:
        a, b, c = st.columns(3)
        a.metric("First abnormal minute began", wall_at(state, alert.get("onset_seconds")))
        b.metric("Third abnormal minute closed", wall(alert.get("closed_epoch")))
        c.metric("Alert raised", wall(alert.get("raised_epoch")))

    if phase == live.STOPPED:
        saved = state.get("saved_run")
        if saved:
            st.info("Saved as `data/%s.parquet` - the Replay page and evaluate.py can open it. "
                    "This verdict is the offline analysis of the whole capture." % saved)
        if reveal:
            draw_reveal(state)

    rejoined = rejoin_lines(state)
    if rejoined:
        st.info("  \n".join(rejoined))

    problems = state.get("problems") or []
    if problems:
        with st.expander("%d capture file(s) were skipped" % len(problems)):
            for p in problems:
                st.write("- %s: %s" % (p.get("file"), p.get("problem")))

    st.divider()
    st.subheader("Every device, minute by minute")
    st.caption("A device is only flagged after %d abnormal minutes IN A ROW - one odd "
               "minute names nobody." % int(state.get("consecutive") or detect.CONSECUTIVE))
    rows = device_rows(state)
    if rows:
        columns = st.columns(len(rows))
        for column, row in zip(columns, rows):
            with column:
                st.markdown("**%s**  \n<span style='color:#7f8c8d'>%s</span>"
                            % (row["device"], row["kind"]), unsafe_allow_html=True)
                st.progress(row["fraction"])
                st.caption(row["label"])
    st.plotly_chart(score_figure(state), use_container_width=True)
    st.caption("How high one minute goes matters less than how many in a row cross the "
               "dashed line: the noisy laptop often has single tall spikes and is never "
               "flagged for them; an attacked board sits just over the line minute after "
               "minute.")

    if not state.get("ranking"):
        return

    run, detection, result = objects_from_state(state)
    clock = lambda seconds: wall_at(state, seconds)  # noqa: E731

    st.divider()
    diagram, suspects = st.columns([3, 2])
    with diagram:
        st.subheader("The network")
        st.caption("Arrows are links the analysis drew; the attack path is in red.")
        st.plotly_chart(app.network_figure(run, detection, result, clock=clock),
                        use_container_width=True)
    with suspects:
        st.subheader("Suspects")
        st.caption("Bars show how complete a story each device explains, "
                   "relative to the leader.")
        for row in app.ranking_rows(result, detection, clock=clock):
            label = "**%d. `%s`**" % (row["position"], row["device"])
            if row["position"] == 1 and not result.abstained:
                label += "  ← named"
            elif row["shortlisted"]:
                label += "  · shortlist"
            st.markdown(label)
            st.progress(row["bar"])
            st.caption("went abnormal %s · %s" % (row["onset"], row["explanation"]))

    if state.get("incident") and state["incident"].get("status") not in ("failed", None):
        draw_report(state)
    else:
        if (state.get("incident") or {}).get("status") == "failed":
            st.warning("The incident report could not be built (%s); the brief is shown "
                       "instead. The verdict above stands."
                       % state["incident"].get("error", "unknown error"))
        draw_brief(state)


def containment_text(state: dict) -> str | None:
    """The CONTAINED check in one line, or None before there is an incident."""
    c = state.get("containment")
    if not c:
        return None
    return incident.containment_line(c, state.get("capture_start_epoch"))


def draw_report(state: dict) -> None:
    """
    The Step 19 incident report - every section, as the engine wrote it into
    state.json. Nothing is recomputed here; the download is the same report as
    the HTML file the engine writes to reports/<session>.html.
    """
    r = state["incident"]
    start = r.get("capture_start_epoch")
    st.divider()
    st.subheader("Incident report")
    st.download_button("Download the report (HTML, print to PDF from the browser)",
                       data=incident.render_html(r),
                       file_name="%s.html" % r.get("session", "incident"),
                       mime="text/html", key="report-download")
    if state.get("report_file"):
        st.caption("Also saved as `%s`." % state["report_file"])

    st.markdown("**1. What happened**")
    st.markdown("### %s" % r["what_happened"]["sentence"])
    if r.get("wording", {}).get("source") == "llm":
        st.caption("In other words: %s" % r["wording"]["headline"])
    if r.get("status") == "no incident":
        return

    w = r["when"]
    st.markdown("**2. When**")
    st.write(w["sentence"])
    if w["abnormal_minutes"]:
        st.caption("Abnormal minutes: " + " · ".join(
            "%s (%.1f)" % (m["text"], m["score"]) for m in w["abnormal_minutes"]))

    where = r["where"]
    st.markdown("**3. Where it started**")
    st.write(where["sentence"])
    for row in where["ranking"]:
        st.caption("%d. `%s` - abnormal from %s - %s"
                   % (row["position"], row["device"], row["onset_text"], row["explanation"]))
    if where.get("cleared"):
        st.caption("Stayed normal: %s" % ", ".join("`%s`" % d for d in where["cleared"]))
    if where.get("not_judged"):
        st.caption("Not judged (too little baseline traffic): %s" % ", ".join(where["not_judged"]))

    st.markdown("**4. How**")
    for line in r["how"]["sentences"]:
        st.write(line)
    pats = r["how"]["patterns"]
    if pats:
        st.dataframe(pd.DataFrame([{
            "destination": x["label"], "connections": x["count"],
            "first": incident.clock_text(x["first_seconds"], start),
            "typical gap": "~%d s" % round(x["typical_gap_seconds"])
            if x["typical_gap_seconds"] is not None else "-",
            "bytes sent": x["typical_bytes_out"], "bytes back": x["typical_bytes_in"],
            "first ids": ", ".join(x["conn_ids"][:3])} for x in pats]),
            hide_index=True, use_container_width=True)

    why = r["why"]
    st.markdown("**5. Why we believe it**")
    st.write(why["sentence"])
    if why["moved"]:
        st.caption("What moved: " + "; ".join(
            "%s - normally %s, during the attack %s" % (m["words"], m["normal"], m["during"])
            for m in why["moved"]))
    st.caption("Evidence connections: %s" % ", ".join(why["evidence_ids"]))

    imp = r["impact"]
    st.markdown("**6. Impact**")
    st.write(imp["sentence"])
    for dev, rows in imp["reach"].items():
        st.caption("`%s` talked to: %s" % (dev, ", ".join(
            "%s%s ×%d" % (x["label"], " (NEW)" if x["new"] else "", x["count"]) for x in rows)))

    st.markdown("**7. What to do** (recommended - the operator acts; nothing is done "
                "automatically)")
    for i, step in enumerate(r["playbook"], 1):
        st.markdown("%d. **[%s] %s**  \n%s" % (i, step["urgency"].upper(), step["title"],
                                                "  \n".join("   - %s" % d for d in step["do"])))

    st.markdown("**8. What we are not sure about**")
    st.info("  \n".join("- %s" % u for u in r["unsure"]))
    st.caption(r.get("wording", {}).get("note", ""))


def draw_brief(state: dict) -> None:
    report_part = state.get("report") or {}
    brief = report_part.get("brief")
    st.divider()
    st.subheader("Incident brief")
    if not brief:
        if report_part.get("source") == "failed":
            st.warning("The brief could not be built (%s). The verdict above stands."
                       % report_part.get("error", "unknown error"))
        return
    st.markdown("### %s" % brief["headline"])
    one, two = st.columns([2, 3])
    with one:
        origin = brief.get("origin") or {}
        st.markdown("**Origin:** `%s`" % origin.get("device"))
        st.markdown("**Confidence:** %s%% (%s)" % (origin.get("confidence"), origin.get("label")))
        st.markdown("**Affected:** " + ", ".join("`%s`" % d
                                                 for d in brief.get("affected_devices", [])))
    with two:
        st.markdown("**What we are not sure about**")
        st.info(brief.get("uncertainty", ""))
    st.markdown("**What happened**")
    for entry in brief.get("timeline", []):
        st.markdown("- **%s · `%s`** — %s  \n  <span style='color:#7f8c8d'>evidence: %s</span>"
                    % (capture_clock_to_wall(state, entry.get("time")), entry.get("device"),
                       entry.get("what_happened"), ", ".join(entry.get("evidence_ids", []))),
                    unsafe_allow_html=True)
    st.markdown("**What to do** (recommended - the operator acts; nothing is done automatically)")
    for action in sorted(brief.get("actions", []), key=lambda a: a.get("order", 0)):
        st.markdown("%d. **[%s]** %s  \n   *%s*" % (action.get("order", 0),
                                                    str(action.get("urgency", "")).upper(),
                                                    action.get("action"), action.get("why")))


def draw_reveal(state: dict) -> None:
    """The 'was it right?' tick - only ever called once the session is STOPPED."""
    if state.get("phase") != live.STOPPED:
        return
    answer = app.load_answer_for_display(state.get("session", ""))
    if answer is None:
        st.info("No answer file saved for this session.")
        return
    origin = answer.get("origin")
    ranking = state.get("ranking") or []
    rank = ranking.index(origin) + 1 if origin in ranking else None
    if rank == 1 and not state.get("abstained"):
        st.success("Correct. The attack really did start on `%s`." % origin)
    elif rank is not None and rank <= 3:
        st.warning("`%s` was the real origin, ranked %d." % (origin, rank))
    elif rank is not None:
        st.error("Wrong. `%s` was the real origin, ranked %d." % (origin, rank))
    else:
        st.error("`%s` was the real origin, and it was never flagged." % origin)


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def render_page(live_dir=None, session: str | None = None,
                refresh_seconds: float = REFRESH_SECONDS) -> None:
    """
    The live page. With no session given, the sidebar offers the sessions
    found, and by default follows the newest - so a session started after the
    page was opened appears on it without anyone touching the page.
    """
    live_dir = Path(live_dir) if live_dir else live_dir_default()

    with st.sidebar:
        st.header("Live session")
        follow = True
        chosen = session
        if session is None:
            follow = st.toggle("Follow the newest session", value=True,
                               help="Switches to a new session by itself as soon as "
                                    "its engine starts.")
            options = list_sessions(live_dir)
            if options and not follow:
                chosen = st.selectbox("Session", options)
        reveal = st.checkbox("Reveal the true answer (after stop)", value=False,
                             help="Reads the answer file only once the session has "
                                  "stopped, to mark the verdict right or wrong.")
        st.caption("Updates every %d s. Containment is recommended, never executed."
                   % refresh_seconds)

    st.title("Live monitor")

    @st.fragment(run_every=refresh_seconds)
    def body():
        name = chosen
        if name is None and follow:
            newest = list_sessions(live_dir)
            name = newest[0] if newest else None
        if name is None:
            draw_waiting(live_dir)
            return
        state = read_state(live_dir, name)
        if state is None:
            st.info("Session `%s` has no readable state yet - the engine is starting." % name)
            return
        draw_state(state, live_dir, reveal=reveal)

    body()


def main() -> None:
    st.set_page_config(page_title="IoT Incident Attribution - live",
                       page_icon="📡", layout="wide")
    render_page()


if __name__ == "__main__":
    main()
