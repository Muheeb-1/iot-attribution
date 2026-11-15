"""
THE LIVE PAGE - the console while the capture is still running.

WHAT IT SHOWS
-------------
It reads pcap/live/<session>/state.json, which the live engine (src/live.py)
rewrites every second or so, and redraws itself every 3 seconds. The look is
docs/design/console_mockup.html (Step P1 of docs/POLISH_PLAN.md); the HTML
pieces come from dashboard/theme.py.

  top bar      brand, the two pages, capture status, session, clock
  status band  the one loud thing on the page - one colour, word and icon per
               phase:
                 WAITING     no capture yet: the exact commands to start one
                 LEARNING    "Learning normal behaviour. Minute 7 of 12."
                 MONITORING  "Monitoring 3 devices" (or "Watching esp32-03"
                             when a device is part-way to an alert)
                 INCIDENT    "The attack started on esp32-03"
                 CONTAINED   "Contained at 19:34:49"
                 STOPPED     the final verdict (identical to the offline
                             analysis)
  device lanes one bar per device per minute, on one scale, with the line
  right card   "This session" before a verdict, "How it was found" after
  report area  the designed report (Step P3, docs/design/report_mockup.html):
               key facts and what happened, the timeline, the ATT&CK
               techniques, what to do, Create PDF / Download PDF; the full
               eight sections in a collapsed "Full technical detail"; the
               network and suspects in an expander
  Lab validation  collapsed, at the bottom: the test-attack command and
               "Compare with the recorded answer"

All times on the page are wall-clock times (capture start + seconds), so they
can be compared with the clock on the wall and with the attack command.

THE PAGE DECIDES NOTHING
------------------------
Every number on it comes from state.json, which the engine produced with the
unchanged pipeline. To draw the network and the suspect list the page rebuilds
the engine's Attribution and Detection objects FROM state.json
(objects_from_state) and hands them to the same functions the Past sessions
page uses - network_figure and ranking_rows in dashboard/app.py. Nothing is
re-detected or re-ranked here; a test checks the rebuilt objects give exactly
the rows the engine's own objects give.

ONE ABNORMAL MINUTE IS NOT AN ALARM
-----------------------------------
One abnormal minute names nobody. In the twelve real attacks the innocent
laptop had at least one abnormal minute in nine of them; alerting on one
minute would have blamed it most of the time. The detector waits for three in
a row (docs/LIVE_PLAN.md section 7). So a device part-way there is shown as
"Watching 2 of 3" in amber, never in the alert colour; only the incident,
which appears after the third minute, is red.

THE ALERT (Step P2)
-------------------
While an incident is not acknowledged the band rings, carries an
Acknowledge button, and a short quiet tone repeats (two 880 Hz pips every
1.6 s, made in code - alert_tone_wav). The sidebar's "Alert sound" switch
turns the tone off; the visual alert never depends on it. A browser may
refuse to play sound until someone has clicked on the page, which is why the
demo script says to flick that switch once after opening the page.

Acknowledge is an operator action, written by the page as
pcap/live/<session>/ack.json ({"acknowledged_epoch": <this laptop's clock>}).
The engine reads it only to put the time in state.json and the report
(incident.acknowledgement). Until the engine's next cycle the page places
the click on the session's clock itself, with the same function, so the
ring and the tone stop at once. The band then shows "Acknowledged HH:MM:SS"
and its three figures become to detect / to acknowledge / to contain.

THE ANSWER SHEET
----------------
"Compare with the recorded answer", in the collapsed Lab validation section,
reads the answer file only once the session is STOPPED, i.e. after the
analysis has completely finished, exactly like the Past sessions page.

RUN IT
------
    streamlit run dashboard/app.py          -> "Live monitor" in the top bar or sidebar
    streamlit run dashboard/live_page.py    -> this page on its own
"""

from __future__ import annotations

import io
import json
import math
import os
import re
import struct
import sys
import time
import wave
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import networkx as nx
import pandas as pd
import streamlit as st

from dashboard import app, theme
from dashboard.theme import duration_text, wall, wall_at  # noqa: F401  (used by tests too)
from src import attribute, detect, incident, live, runs

REFRESH_SECONDS = 3

# The engine rewrites state.json about once a second while a session runs.
# Silence for this long means it has stopped or crashed.
STALE_SECONDS = 20


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
# Time (wall, wall_at and duration_text live in dashboard/theme.py)
# --------------------------------------------------------------------------

def capture_clock_to_wall(state: dict, text: str) -> str:
    """'00:16:00' (seconds-from-start, as the brief writes it) -> wall clock."""
    match = re.fullmatch(r"\s*(\d+):(\d{2}):(\d{2})\s*", str(text))
    if not match:
        return str(text)
    h, m, s = (int(x) for x in match.groups())
    return wall_at(state, h * 3600 + m * 60 + s)


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
    return {
        "done": done,
        "total": total,
        "fraction": (done / total) if total else 0.0,
        "remaining_seconds": state.get("baseline_remaining_seconds"),
        "ends_at": wall(theme.baseline_end_epoch(state)),
    }


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
# Rebuilding the engine's objects, so the Past sessions drawings can be reused
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


def start_commands(session: str) -> str:
    return ("# 1. ordinary PowerShell, repo root - the engine\n"
            "python -m src.live --session %s\n\n"
            "# 2. ADMINISTRATOR PowerShell, repo root - the capture\n"
            "python -m src.live_capture --session %s\n\n"
            "# fallback - replay a recorded capture through the same page\n"
            "python -m src.live --session replay_01 --replay pcap\\segments\\live_batch_01.pcapng"
            % (session, session))


# --------------------------------------------------------------------------
# The alert: acknowledgement and tone (Step P2)
# --------------------------------------------------------------------------

def ack_path(live_dir: Path, session: str) -> Path:
    return Path(live_dir) / session / live.ACK_FILE


def read_ack_epoch(live_dir: Path, session: str):
    """The operator's clock time in ack.json, or None."""
    try:
        data = json.loads(ack_path(live_dir, session).read_text(encoding="utf-8"))
        return float(data["acknowledged_epoch"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def write_ack(live_dir: Path, session: str, now: float | None = None) -> float:
    """
    The Acknowledge button: write ack.json once (a second press keeps the
    first time). Written whole then renamed, so the engine never reads half
    a file. Returns the time stored.
    """
    existing = read_ack_epoch(live_dir, session)
    if existing is not None:
        return existing
    clicked = time.time() if now is None else float(now)
    path = ack_path(live_dir, session)
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    part.write_text(json.dumps({"acknowledged_epoch": clicked}), encoding="utf-8")
    os.replace(part, path)
    return clicked


def acknowledgement_for(state: dict, live_dir: Path):
    """
    The acknowledgement to show: the engine's, once it has read ack.json;
    before that, the click placed on the session's clock by the same function
    the engine uses (so both always agree).
    """
    if state.get("acknowledged"):
        return state["acknowledged"]
    session = state.get("session", "")
    replaying = state.get("replaying")
    if replaying is None:
        replaying = is_replay(live_dir, session)
    return incident.acknowledgement(read_ack_epoch(live_dir, session), state.get("first_alert"),
                                    state.get("first_alert_wall_epoch"), bool(replaying),
                                    state.get("capture_start_epoch"))


def alarm_is_on(state: dict, ack) -> bool:
    """Ring, button and tone: an incident is raised and nobody has acknowledged it."""
    return (state.get("phase") == live.INCIDENT and bool(state.get("first_alert"))
            and not ack)


TONE_RATE = 16000          # samples per second
TONE_PERIOD = 1.6          # seconds per repeat (the file loops)
TONE_PIPS = ((0.00, 0.15), (0.25, 0.40))   # two pips, start and end in seconds
TONE_HZ = 880.0
TONE_VOLUME = 0.2          # of full scale: quiet


@lru_cache(maxsize=1)
def alert_tone_wav() -> bytes:
    """
    The alert tone as a WAV file: two short 880 Hz pips, then silence, 1.6 s in
    all, played on a loop. Each pip fades in and out over 10 ms so it does not
    click. Made in code - no sound file in the repository. Cached, so the page
    hands Streamlit the same bytes on every refresh and the player is not
    re-created (it keeps playing across the 3-second refresh).
    """
    fade = int(0.010 * TONE_RATE)
    frames = bytearray()
    for i in range(int(TONE_PERIOD * TONE_RATE)):
        t = i / TONE_RATE
        value = 0.0
        for start, end in TONE_PIPS:
            if start <= t < end:
                k = i - int(start * TONE_RATE)
                left = int(end * TONE_RATE) - i
                envelope = min(1.0, k / fade, left / fade)
                value = TONE_VOLUME * envelope * math.sin(2 * math.pi * TONE_HZ * t)
        frames += struct.pack("<h", int(round(value * 32767)))
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(TONE_RATE)
        out.writeframes(bytes(frames))
    return buffer.getvalue()


def containment_text(state: dict) -> str | None:
    """The CONTAINED check in one line, or None before there is an incident."""
    c = state.get("containment")
    if not c:
        return None
    return incident.containment_line(c, state.get("capture_start_epoch"), state.get("addresses"))


# --------------------------------------------------------------------------
# Drawing
# --------------------------------------------------------------------------

def draw_waiting(live_dir: Path) -> None:
    st.html(theme.top_bar(None))
    st.html(theme.waiting_band(
        "Waiting for a session",
        "No live session has started yet. Start these two, in this order; "
        "the page picks the session up by itself."))
    st.code(start_commands(next_session_name(live_dir)), language="powershell")


def notes_under_band(state: dict) -> list:
    """(html, kind) for the quiet notes under the band; data escaped."""
    session = state.get("session", "?")
    notes = []
    if is_stale(state):
        notes.append(("<b>The engine has not updated this page for %s.</b> Is "
                      "<span class='mono'>python -m src.live --session %s</span> still running?"
                      % (theme.esc(duration_text(seconds_since_update(state))),
                         theme.esc(session)), "bad"))
    if state.get("phase") == live.INCIDENT:
        line = containment_text(state)
        if line:
            notes.append((theme.esc(line), "warn"))
    for line in verdict_change_lines(state):
        notes.append((theme.esc(line), "warn"))
    if state.get("phase") == live.STOPPED and state.get("saved_run"):
        notes.append(("Saved as <span class='mono'>data/%s.parquet</span>. The Past sessions page "
                      "and evaluate.py can open it. This verdict is the offline analysis of the "
                      "whole capture." % theme.esc(state["saved_run"]), ""))
    for line in rejoin_lines(state):
        notes.append((theme.esc(line), ""))
    return notes


def draw_band(state: dict, live_dir: Path, ack, sound: bool) -> None:
    """
    The status band. While the alarm is on, the band and its Acknowledge
    button share one keyed container (the CSS puts the button inside the
    band), and the tone plays from a hidden player.
    """
    session = state.get("session", "?")
    if not alarm_is_on(state, ack):
        st.html(theme.status_band(state, ack))
        return
    with st.container(key="alert-band"):
        st.html(theme.status_band(state, ack, ack_button=True))
        st.button("Acknowledge", key="ack-button", on_click=write_ack,
                  args=(live_dir, session),
                  help="Tells the console a person has seen the alert: the ring and the "
                       "tone stop, and the time goes into the report. It does not "
                       "contain anything.")
    if sound:
        with st.container(key="alert-tone"):
            st.audio(alert_tone_wav(), format="audio/wav", autoplay=True, loop=True)


def draw_state(state: dict, live_dir: Path, sound: bool = True) -> None:
    """The whole page for one moment of one session."""
    session = state.get("session", "?")
    phase = state.get("phase", live.WAITING)
    replaying = is_replay(live_dir, session)
    ack = acknowledgement_for(state, live_dir)

    st.html(theme.top_bar(state, replaying=replaying, stale=is_stale(state)))
    draw_band(state, live_dir, ack, sound)
    for text, kind in notes_under_band(state):
        st.html(theme.notice(text, kind))

    problems = state.get("problems") or []
    if problems:
        with st.expander("%d capture file(s) were skipped" % len(problems)):
            for p in problems:
                st.write("- %s: %s" % (p.get("file"), p.get("problem")))

    if phase == live.WAITING:
        st.code(start_commands(session), language="powershell")
        draw_lab_validation(state)
        return

    lanes, side = st.columns([1.6, 1], gap="medium")
    with lanes:
        st.html(theme.device_lanes(state))
    with side:
        if state.get("onsets") and (state.get("named") or state.get("abstained")):
            st.html(theme.how_card(state))
        else:
            st.html(theme.session_card(state, replaying=replaying))

    if state.get("ranking"):
        draw_report_area(state, ack)
    draw_lab_validation(state)


def report_for_page(state: dict, ack=None):
    """
    The engine's report as the page shows it: with the acknowledgement the
    page already knows (the engine adds it on its next cycle) - or None when
    there is no usable report.
    """
    r = state.get("incident")
    if not r or r.get("status") in ("failed", None):
        return None
    if ack and not r.get("acknowledged"):
        r = incident.with_acknowledgement(r, ack)
    if r.get("containment") and r.get("status") != "no incident":
        # the playbook's last line, re-worded from the same check (a state
        # written before P3 still says "NOT YET CONTAINED: ...")
        r = incident.with_containment(r, r["containment"])
    return r


def draw_report_area(state: dict, ack=None) -> None:
    """
    The report area, in the report's design (Step P3): key facts and what
    happened, timeline, techniques and what to do, the PDF; then the full
    eight sections collapsed; then the network and suspects.
    """
    r = report_for_page(state, ack)
    if r is not None and r.get("status") != "no incident":
        facts = incident.design_facts(r, state.get("addresses"))
        st.html(theme.report_summary_card(facts))
        line = theme.timeline(state, ack)
        if line:
            st.html(line)
        left, right = st.columns([1, 1], gap="medium")
        with left:
            st.html(theme.techniques_card(facts))
        with right:
            st.html(theme.steps_card(facts))
        draw_downloads(state, r)
        with st.expander("Full technical detail (all eight sections)"):
            draw_report(state, r)
    else:
        line = theme.timeline(state, ack)
        if line:
            st.html(line)
        if (state.get("incident") or {}).get("status") == "failed":
            st.warning("The incident report could not be built (%s); the brief is shown "
                       "instead. The verdict above stands."
                       % state["incident"].get("error", "unknown error"))
        draw_brief(state)

    run, detection, result = objects_from_state(state)
    clock = lambda seconds: wall_at(state, seconds)  # noqa: E731
    with st.expander("How the origin was chosen: the network and the suspects"):
        diagram, suspects = st.columns([3, 2])
        with diagram:
            st.subheader("The network")
            st.caption("Arrows are links the analysis drew; the attack path is in red.")
            st.plotly_chart(theme.styled(app.network_figure(run, detection, result, clock=clock)),
                            use_container_width=True, theme=None)
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


def draw_lab_validation(state: dict) -> None:
    """
    The lab-only part, collapsed at the bottom: the command that starts the
    test attack, and the check against the answer file the attack script
    wrote. The check is offered only once the session has STOPPED.
    """
    session = state.get("session", "?")
    with st.expander("Lab validation"):
        if state.get("phase") in (live.WAITING, live.LEARNING, live.MONITORING):
            st.caption("Test attack, once monitoring has started - in another terminal:")
            st.code("python -m src.scenario --run %s" % session, language="powershell")
        compare = st.checkbox("Compare with the recorded answer", value=False, key="lab-compare",
                              help="Opens the answer file the attack script wrote, only once "
                                   "the session has stopped, to mark the verdict right or wrong.")
        if compare:
            if state.get("phase") == live.STOPPED:
                draw_reveal(state)
            else:
                st.caption("Available once the session has stopped: the answer file is opened "
                           "only after the analysis has finished.")


def pdf_cache_key(state: dict, report: dict) -> tuple:
    """A page-made PDF is reused only while the report it was made from is current."""
    return (state.get("session"), report.get("status"), report.get("now_seconds"),
            bool(report.get("acknowledged")), (report.get("analyst") or {}).get("status"))


def create_pdf(html_text: str, key: tuple) -> None:
    """The Create PDF button: print the report now (Edge, ~3 s); remember the bytes."""
    import tempfile
    folder = Path(tempfile.mkdtemp(prefix="iot_report_"))
    source = folder / "report.html"
    source.write_text(html_text, encoding="utf-8")
    made = incident.html_to_pdf(source)
    st.session_state["report-pdf"] = {"key": key,
                                      "data": made.read_bytes() if made else None}


def engine_pdf_bytes(state: dict):
    """The PDF the engine printed at STOP, if it is there."""
    if state.get("phase") != live.STOPPED or not state.get("pdf_file"):
        return None
    try:
        return Path(state["pdf_file"]).read_bytes()
    except OSError:
        return None


def draw_downloads(state: dict, report: dict) -> None:
    """
    Download PDF (the engine's, printed at STOP, or one made with Create PDF)
    and the same report as HTML. If no PDF can be made on this computer, the
    HTML can be printed to PDF from the browser.
    """
    session = report.get("session", "incident")
    html_text = incident.render_html(report, state.get("addresses"))
    key = pdf_cache_key(state, report)
    made = st.session_state.get("report-pdf") or {}
    pdf = engine_pdf_bytes(state)
    if pdf is None and made.get("key") == key:
        pdf = made.get("data")
    one, two, note = st.columns([1, 1, 3])
    with one:
        if pdf:
            st.download_button("Download PDF", data=pdf, file_name="%s.pdf" % session,
                               mime="application/pdf", key="report-pdf-download", type="primary")
        else:
            st.button("Create PDF", key="report-pdf-create", on_click=create_pdf,
                      args=(html_text, key),
                      help="Prints this report to PDF with Microsoft Edge (a few seconds).")
    with two:
        st.download_button("Download HTML", data=html_text, file_name="%s.html" % session,
                           mime="text/html", key="report-download")
    with note:
        if made.get("key") == key and made.get("data") is None and not pdf:
            st.caption("No PDF could be made on this computer (Edge or Chrome is needed). "
                       "Download the HTML and print it to PDF from the browser.")
        elif state.get("report_file"):
            st.caption("Also saved as `%s`%s." % (
                state["report_file"],
                " and `%s`" % state["pdf_file"] if state.get("pdf_file") else ""))


def draw_report(state: dict, r: dict | None = None) -> None:
    """
    The Step 19 incident report - every section, as the engine wrote it into
    state.json, inside "Full technical detail". Nothing is recomputed here.
    Destinations are shown as addresses (192.168.0.200:4444), never as
    "broker:4444" (incident.display_text - display only).
    """
    r = r or state["incident"]
    start = r.get("capture_start_epoch")
    addresses = state.get("addresses")
    show = lambda text: incident.display_text(text, r, addresses)  # noqa: E731

    st.markdown("**1. What happened**")
    st.write(show(r["what_happened"]["sentence"]))
    if r.get("wording", {}).get("source") == "llm":
        st.caption("In other words: %s" % show(r["wording"]["headline"]))
    if r.get("status") == "no incident":
        return

    w = r["when"]
    st.markdown("**2. When**")
    st.write(show(w["sentence"]))
    if r.get("acknowledged"):
        st.write(incident.acknowledged_line(r["acknowledged"]))
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
        st.write(show(line))
    pats = r["how"]["patterns"]
    if pats:
        st.dataframe(pd.DataFrame([{
            "destination": incident.address_label(x["label"], addresses),
            "connections": x["count"],
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
            "%s%s ×%d" % (incident.address_label(x["label"], addresses),
                          " (NEW)" if x["new"] else "", x["count"]) for x in rows)))

    st.markdown("**7. What to do** (recommended - the operator acts; nothing is done "
                "automatically)")
    for i, step in enumerate(r["playbook"], 1):
        st.markdown("%d. **[%s] %s**  \n%s" % (i, step["urgency"].upper(), step["title"],
                                                "  \n".join("   - %s" % show(d) for d in step["do"])))

    st.markdown("**8. What we are not sure about**")
    st.info("  \n".join("- %s" % u for u in r["unsure"]))
    st.caption(r.get("wording", {}).get("note", ""))


def draw_brief(state: dict) -> None:
    report_part = state.get("report") or {}
    brief = report_part.get("brief")
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
        st.markdown("- **%s · `%s`** — %s  \n  <span style='color:#8496B5'>evidence: %s</span>"
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
    theme.inject()

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
        sound = st.toggle("Alert sound", value=True, key="alert-sound",
                          help="A short quiet tone repeats while an incident is not "
                               "acknowledged. A browser may block sound until the page has "
                               "been clicked once: switch this off and on after opening the "
                               "page.")
        st.caption("Updates every %d s. Containment is recommended, never executed."
                   % refresh_seconds)

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
            st.html(theme.top_bar(None))
            st.html(theme.waiting_band("Starting session %s" % name,
                                       "The engine is starting; its first state has not "
                                       "been written yet."))
            return
        draw_state(state, live_dir, sound=sound)

    body()


def page_config() -> None:
    """The live page's own settings: wide, sidebar collapsed (it holds the page switch)."""
    st.set_page_config(page_title="IoT Incident Attribution - live monitor",
                       page_icon="📡", layout="wide", initial_sidebar_state="collapsed")


def main() -> None:
    page_config()
    render_page()


if __name__ == "__main__":
    main()
