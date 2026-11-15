"""
THE THEME - how the console looks (docs/POLISH_PLAN.md, Step P1).

The design is docs/design/console_mockup.html. This file carries it into the
Streamlit pages in three parts:

  CSS              the mockup's colour tokens and classes, plus a few rules
                   that make Streamlit's own widgets sit quietly on the dark
                   page (inject() puts it on the page once per run);
  PLOTLY_TEMPLATE  the same colours and fonts for every Plotly chart;
  pure functions   top_bar, status_band, device_lanes, how_card,
                   session_card, timeline, notice - each takes the engine's
                   state.json (a plain dict) and returns an HTML string.

THE PAGE DECIDES NOTHING
------------------------
Every word and number here is read from state.json, which the live engine
wrote with the unchanged pipeline. These functions only choose how to SAY it:
which colour, which word, which bar is taller. Nothing is detected, scored,
ranked or counted again. Where the plan asks for something the engine does
not record yet (the severity, Step P3), the band shows it only once the
engine's report carries it.

ONE LOUD THING
--------------
The status band at the top is the only element that changes colour with the
phase. Everything else is quiet. Status is never colour alone: every state has
a word ("Normal", "Watching 2 of 3", "Attack origin", "Offline, contained")
and the band has an icon.

THE DEVICE LANES
----------------
They replace the old multi-line score chart. One row per device, one bar per
closed minute, every row on the same scale with the alert line (4.0) dashed
across it. Bars over the line in a monitored minute are drawn in the alert
colour. The scale tops out at 10: an attack minute can score in the hundreds,
which would flatten everything else, so a taller bar is capped and marked,
and its real score is in the tooltip. The plot always has at least 20 minute
slots so bars never change width as the session grows; past 40 minutes it
shows the last 40. No per-device colours: nothing depends on telling three
line colours apart.

The only motion is the newest bar growing in, and the band's ring while an
incident is unacknowledged (Step P2). prefers-reduced-motion turns both off.

THE ALERT (Step P2)
-------------------
In INCIDENT, CONTAINED and STOPPED the band's three figures are the response
times: "to detect" (first unusual connection -> alert, from the engine's
report), "to acknowledge" (alert -> the operator pressed Acknowledge) and "to
contain" (alert -> CONTAINED), each "--" until known. While an incident is
not acknowledged the band rings; afterwards it says "Acknowledged HH:MM:SS".
The Acknowledge button itself is a Streamlit button that the CSS below
places inside the band (the band is HTML and cannot hold a widget).

FONTS
-----
Only fonts Windows 11 already has: Bahnschrift (headings, numbers), Segoe UI
Variable (text), Cascadia Mono (addresses, ids). No web fonts, no CDN.

SAFETY
------
Every piece of text that comes from data - device names, addresses, the
engine's sentences - goes through html.escape (esc) before it is put into
HTML.
"""

from __future__ import annotations

import html
import urllib.parse
from datetime import datetime

import plotly.graph_objects as go

from src import detect, incident, live

# --------------------------------------------------------------------------
# Tokens (copied from docs/design/console_mockup.html)
# --------------------------------------------------------------------------

PAGE = "#0E1524"
PANEL = "#162033"
RAISED = "#1E2B44"
LINE = "#2A3A59"
TEXT = "#E8EEF9"
SOFT = "#B4C2DB"
MUTED = "#8496B5"
OK = "#35C7A0"
LEARN = "#6FA8FF"
WATCH = "#F2B544"
ALERT = "#FF5D6C"
FLAGGED = "#B79CFF"      # Past sessions charts: "went abnormal", not a suspect (P1b)
BAR = "#5C6F92"
BAR_DIM = "#33435F"

DISPLAY_FONT = '"Bahnschrift", "DIN Alternate", "Barlow Semi Condensed", "Segoe UI", sans-serif'
BODY_FONT = '"Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif'
MONO_FONT = '"Cascadia Mono", "Cascadia Code", Consolas, monospace'

# Lanes: the scale every row shares, and how many minute slots are drawn.
LANE_SCALE = 10.0          # with the line at 4.0 the line sits at 40% of the height
MIN_SLOTS = 20
MAX_SLOTS = 40

CSS = """
:root {
  --page: #0E1524;  --panel: #162033;  --raised: #1E2B44;  --line: #2A3A59;
  --text: #E8EEF9;  --soft: #B4C2DB;   --muted: #8496B5;
  --ok: #35C7A0;    --learn: #6FA8FF;  --watch: #F2B544;   --alert: #FF5D6C;
  --ok-bg: #10312F; --learn-bg: #15294A; --watch-bg: #3A2F17; --alert-bg: #3D1722;
  --bar: #5C6F92;   --bar-dim: #33435F;
  --display: "Bahnschrift", "DIN Alternate", "Barlow Semi Condensed", "Segoe UI", sans-serif;
  --body: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  --mono: "Cascadia Mono", "Cascadia Code", Consolas, monospace;
}

/* ---- Streamlit itself: dark page, no header bar, full width ---- */
.stApp, [data-testid="stAppViewContainer"] { background: var(--page); color: var(--text); }
.stApp, .stApp p, .stApp li, .stApp label, .stApp button, .stApp input,
.stMarkdown, [data-testid="stCaptionContainer"] { font-family: var(--body); }
.stApp h1, .stApp h2, .stApp h3, .stApp h4 { font-family: var(--display); font-weight: 600; letter-spacing: 0.01em; }
.stApp code, .stApp pre { font-family: var(--mono); }
/* inline code (`esp32-03`, file paths): quiet, not Streamlit's green (P1b) */
.stApp :not(pre) > code { color: var(--soft) !important; background: var(--raised) !important;
                          border-radius: 4px; padding: 0.1em 0.35em; }
header[data-testid="stHeader"] { background: transparent; height: 0; }
[data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] { display: none; }
[data-testid="stMainBlockContainer"], .block-container { max-width: 100%; padding: 0.75rem 1.5rem 3rem; }
[data-testid="stSidebar"] { background: #0B1120; border-right: 1px solid var(--line); }
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) { border-color: var(--line); }
[data-testid="stExpander"] details { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; }
[data-testid="stExpander"] summary { font-family: var(--display); font-size: 16px; }

.iot * { box-sizing: border-box; }
.iot { color: var(--text); font: 15px/1.45 var(--body); }
.iot .num { font-family: var(--display); font-variant-numeric: tabular-nums; }
.iot .mono { font-family: var(--mono); font-size: 0.92em; }

/* ---- top bar ---- */
.iot.top { display: flex; align-items: center; gap: 20px; min-height: 52px; padding: 0 4px;
           border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.iot .brand { font: 600 19px var(--display); letter-spacing: 0.01em; }
.iot .brand small { font: 400 13px var(--body); color: var(--muted); margin-left: 10px; }
.iot.top nav { display: flex; gap: 4px; margin-left: 12px; }
.iot.top nav a { color: var(--soft); text-decoration: none; padding: 6px 12px; border-radius: 6px; font-size: 14px; }
.iot.top nav a.on { background: var(--raised); color: var(--text); }
.iot.top .right { margin-left: auto; display: flex; align-items: center; gap: 18px; color: var(--soft); font-size: 14px; }
.iot .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--ok); display: inline-block; margin-right: 7px; }
.iot .dot.off { background: var(--muted); }  .iot .dot.bad { background: var(--alert); }
.iot .clock { font: 600 22px var(--display); color: var(--text); font-variant-numeric: tabular-nums; }

/* ---- status band: the one loud thing on the page ---- */
.iot.band { padding: 22px 26px; border-radius: 10px; border: 1px solid var(--line);
            display: grid; grid-template-columns: 1fr auto; gap: 24px; align-items: center;
            background: var(--panel); transition: background .4s, border-color .4s; }
.iot.band .state { font: 500 14px var(--body); display: flex; align-items: center; gap: 8px; margin-bottom: 6px; color: var(--soft); }
.iot.band .headline { font: 600 40px/1.08 var(--display); letter-spacing: -0.005em; margin: 0; }
.iot.band .headline .dev { font-family: var(--mono); font-size: 0.86em; font-weight: 600; }
.iot.band .sub { color: var(--soft); margin-top: 8px; font-size: 16px; max-width: 70ch; }
.iot.band .sub b { color: var(--text); }
.iot.band.learn { background: var(--learn-bg); border-color: #2C4E86; }  .iot.band.learn .state { color: var(--learn); }
.iot.band.ok    { background: var(--ok-bg);    border-color: #1F6B5C; }  .iot.band.ok .state { color: var(--ok); }
.iot.band.watch { background: var(--watch-bg); border-color: #7A6325; }  .iot.band.watch .state { color: var(--watch); }
.iot.band.alert { background: var(--alert-bg); border-color: var(--alert); }  .iot.band.alert .state { color: var(--alert); }
.iot.band.alert.ringing { animation: iot-ring 1.6s ease-out infinite; }
@keyframes iot-ring { 0% { box-shadow: 0 0 0 0 rgba(255,93,108,.55); } 100% { box-shadow: 0 0 0 18px rgba(255,93,108,0); } }
.iot .progress { height: 6px; border-radius: 3px; background: #223A63; margin-top: 16px; max-width: 520px; overflow: hidden; }
.iot .progress i { display: block; height: 100%; background: var(--learn); border-radius: 3px; transition: width .6s; }
.iot .side { display: flex; align-items: center; gap: 26px; }
.iot .kpis { display: flex; gap: 26px; }
.iot .kpi .v { font: 600 30px/1 var(--display); font-variant-numeric: tabular-nums; }
.iot .kpi .v.wait { color: var(--muted); }
.iot .kpi .k { color: var(--soft); font-size: 13px; margin-top: 5px; }
.iot .acked { color: var(--soft); font-size: 14px; }
.iot.band.has-ack .side { padding-right: 170px; }

/* Step P2: the Acknowledge button (a Streamlit widget) placed inside the band,
   and the alert tone's player, which is never shown */
.st-key-alert-band { position: relative; }
.st-key-alert-band [data-testid="stElementContainer"]:has([data-testid="stButton"]) {
  position: absolute; left: auto; right: 26px; top: 50%; transform: translateY(-50%);
  width: auto !important; z-index: 2; }
/* Streamlit sets the button's wrappers to the full column width; shrink them to the button */
.st-key-alert-band [data-testid="stButton"], .st-key-alert-band [data-testid="stButton"] > div,
.st-key-alert-band [data-testid="stButton"] [data-testid="stTooltipIcon"] { width: auto !important; }
.st-key-alert-band [data-testid="stButton"] button {
  background: var(--alert); color: #2A0A10; border: 0; border-radius: 8px; padding: 12px 20px; min-height: 0; }
.st-key-alert-band [data-testid="stButton"] button p { font: 600 15px var(--body); color: #2A0A10; }
.st-key-alert-band [data-testid="stButton"] button:hover { filter: brightness(1.08); }
.st-key-alert-band [data-testid="stButton"] button:focus-visible { outline: 3px solid #fff; outline-offset: 2px; }
.st-key-alert-tone { display: none; }

/* ---- cards ---- */
.iot.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 18px 20px; }
.iot .ctitle { font: 600 17px var(--display); letter-spacing: 0.01em; }
.iot .hint { color: var(--muted); font-size: 13px; margin-top: 2px; }

/* device lanes: one bar per minute, on one shared scale; the dashed line is the alert line */
.iot .lane { display: grid; grid-template-columns: 178px minmax(0, 1fr) 150px; gap: 16px; align-items: center;
             padding: 13px 0; border-top: 1px solid var(--line); }
.iot .lane.first { border-top: 0; margin-top: 8px; }
.iot .lane .name { font: 600 16px var(--mono); }
.iot .lane .role { color: var(--muted); font-size: 13px; }
.iot .lane.origin .name { color: var(--alert); }
.iot .plot { position: relative; height: 54px; display: flex; align-items: flex-end; gap: 2px; }
.iot .plot .m { flex: 1 1 0; min-width: 3px; border-radius: 3px 3px 0 0; background: var(--bar); min-height: 2px; transform-origin: bottom; }
.iot .plot .m.base { background: var(--bar-dim); }
.iot .plot .m.empty { background: none; min-height: 0; }
.iot .plot .m.over { background: var(--alert); }
.iot .plot .m.capped { box-shadow: inset 0 3px 0 var(--text); }
.iot .plot .m.fresh { animation: iot-grow .5s ease-out; }
@keyframes iot-grow { from { transform: scaleY(0); } to { transform: scaleY(1); } }
.iot .plot .split { flex: none; width: 1px; align-self: stretch; background: var(--soft); opacity: .55; margin: 0 4px; }
.iot .plot .line { position: absolute; left: 0; right: 0; border-top: 1px dashed var(--soft); opacity: .6; pointer-events: none; }
.iot .lane .status { text-align: right; }
.iot .badge { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 600; padding: 3px 10px; border-radius: 999px; }
.iot .badge.ok { color: var(--ok); background: var(--ok-bg); }       .iot .badge.learn { color: var(--learn); background: var(--learn-bg); }
.iot .badge.watch { color: var(--watch); background: var(--watch-bg); } .iot .badge.alert { color: var(--alert); background: var(--alert-bg); }
.iot .badge.off { color: var(--muted); background: var(--raised); }
.iot .strikes { display: flex; gap: 4px; justify-content: flex-end; margin-top: 7px; }
.iot .strikes i { width: 26px; height: 6px; border-radius: 3px; background: var(--raised); }
.iot .strikes i.hit { background: var(--watch); }  .iot .strikes.full i.hit { background: var(--alert); }
.iot .axis { display: grid; grid-template-columns: 178px minmax(0, 1fr) 150px; gap: 16px; color: var(--muted); font-size: 12px; margin-top: 4px; }
.iot .axis .ticks { position: relative; display: flex; justify-content: space-between; }
.iot .axis .mid { position: absolute; top: 0; transform: translateX(-50%); white-space: nowrap; }
.iot .legend { display: flex; flex-wrap: wrap; gap: 16px; color: var(--soft); font-size: 13px; margin-top: 12px; }
.iot .legend span::before { content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; background: var(--bar); }
.iot .legend .l-base::before { background: var(--bar-dim); } .iot .legend .l-over::before { background: var(--alert); }
.iot .legend .l-line::before { height: 0; border-top: 1px dashed var(--soft); width: 16px; background: none; vertical-align: 3px; border-radius: 0; }
.iot .empty-note { color: var(--muted); margin-top: 14px; }

/* right column */
.iot .facts { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 18px; margin-top: 14px; }
.iot .fact .v { font: 600 24px/1.1 var(--display); font-variant-numeric: tabular-nums; }
.iot .fact .k { color: var(--muted); font-size: 13px; }
.iot .path { display: flex; align-items: center; gap: 10px; margin: 16px 0 14px; }
.iot .node { border: 1px solid var(--line); background: var(--raised); border-radius: 8px; padding: 9px 12px; font: 600 14px var(--mono); }
.iot .node small { display: block; font: 400 12px var(--body); color: var(--muted); }
.iot .node.bad { border-color: var(--alert); color: var(--alert); }
.iot .wire { flex: 1; border-top: 2px dashed var(--alert); position: relative; min-width: 30px; }
.iot .wire::after { content: ""; position: absolute; right: -1px; top: -6px; border: 5px solid transparent; border-left-color: var(--alert); }
.iot .do { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--line); }
.iot .do .dtitle { font: 600 15px var(--display); margin-bottom: 6px; }
.iot .do p { color: var(--soft); margin: 0 0 4px; }  .iot .do b { color: var(--text); }
.iot .shortlist { list-style: none; padding: 0; margin: 12px 0 0; }
.iot .shortlist li { padding: 7px 0; border-top: 1px solid var(--line); color: var(--soft); }
.iot .shortlist li:first-child { border-top: 0; }

/* timeline */
.iot .tl { display: grid; grid-auto-columns: 1fr; grid-auto-flow: column; margin-top: 16px; }
.iot .tl > div { border-top: 2px solid var(--line); padding: 10px 8px 0 0; position: relative; }
.iot .tl > div::before { content: ""; position: absolute; top: -6px; left: 0; width: 10px; height: 10px; border-radius: 50%; background: var(--muted); }
.iot .tl .hot::before { background: var(--alert); } .iot .tl .good::before { background: var(--ok); }
.iot .tl .t { font: 600 18px var(--display); font-variant-numeric: tabular-nums; } .iot .tl .w { color: var(--soft); font-size: 13px; }

/* Step P3: the report area, drawn from incident.design_facts like the PDF */
.iot .rkeys { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 14px;
              border: 1px solid var(--line); border-radius: 8px; }
.iot .rkeys > div { padding: 11px 14px; border-left: 1px solid var(--line); min-width: 0; }
.iot .rkeys > div:first-child { border-left: 0; }
.iot .rkeys .v { font: 600 21px/1.15 var(--display); font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.iot .rkeys .v.sev-critical, .iot .rkeys .v.sev-high { color: var(--alert); }
.iot .rkeys .v.sev-medium { color: var(--watch); }
.iot .rkeys .k { color: var(--muted); font-size: 13px; margin-top: 3px; }
.iot .summary { font-size: 16px; line-height: 1.55; margin: 14px 0 0; color: var(--text); }
.iot .source { font-size: 13px; margin-top: 8px; color: var(--muted); }
.iot .source.ai { color: var(--ok); font-weight: 600; }
.iot .tech { display: grid; grid-template-columns: auto 1fr; gap: 10px 12px; align-items: baseline; margin-top: 14px; }
.iot .tech > b { font: 600 13px var(--mono); background: var(--raised); border: 1px solid var(--line);
                 border-radius: 4px; padding: 1px 7px; color: var(--soft); }
.iot .tech span { color: var(--soft); } .iot .tech span b { color: var(--text); }
.iot .steps { list-style: none; padding: 0; margin: 10px 0 0; }
.iot .steps li { display: grid; grid-template-columns: 16px 52px 1fr; gap: 10px; padding: 9px 0;
                 border-top: 1px solid var(--line); color: var(--soft); }
.iot .steps li:first-child { border-top: 0; }
.iot .steps li b { color: var(--text); }
.iot .steps .box { width: 13px; height: 13px; border: 1.5px solid var(--muted); border-radius: 3px; margin-top: 4px; }
.iot .steps .done .box { background: var(--ok); border-color: var(--ok); }
.iot .steps .when { font-weight: 600; font-size: 13px; color: var(--alert); padding-top: 1px; }
.iot .steps .when.later { color: var(--watch); }

/* quiet notes under the band */
.iot.note { border: 1px solid var(--line); border-left: 3px solid var(--muted); background: var(--panel); border-radius: 6px;
            padding: 8px 12px; color: var(--soft); font-size: 14px; }
.iot.note.warn { border-left-color: var(--watch); }  .iot.note.bad { border-left-color: var(--alert); }
.iot.note b { color: var(--text); }

@media (max-width: 980px) {
  .iot.band { grid-template-columns: 1fr; } .iot .side { flex-wrap: wrap; }
  .iot.band.has-ack .side { padding-right: 0; }
  .st-key-alert-band [data-testid="stElementContainer"]:has([data-testid="stButton"]) {
    position: static; transform: none; }
  .iot .lane, .iot .axis { grid-template-columns: 120px 1fr; } .iot .lane .status { grid-column: 1 / -1; text-align: left; }
  .iot .strikes { justify-content: flex-start; }
}
@media (prefers-reduced-motion: reduce) {
  .iot.band.alert.ringing, .iot .plot .m.fresh { animation: none; }
  .iot, .iot * { transition: none !important; }
}
"""

# The band's icons (the mockup's drawings). Streamlit's st.html removes <svg>
# elements, so they cannot be put in the HTML - found in Step P2: the P1 band
# showed no icon in the real app. Each drawing is used instead as a CSS mask
# on the state line's ::before, painted in the state colour (currentColor):
# the band's HTML only names it, <div class="state ic-alert">.
ICON_PATHS = {
    "learn": '<circle cx="10" cy="10" r="7"/><path d="M10 6v4l3 2"/>',
    "ok": '<path d="M10 2l6 3v5c0 4-2.6 6.6-6 8-3.4-1.4-6-4-6-8V5z"/><path d="M7 10l2 2 4-4"/>',
    "watch": '<path d="M1.5 10S5 4 10 4s8.5 6 8.5 6-3.5 6-8.5 6-8.5-6-8.5-6z"/>'
             '<circle cx="10" cy="10" r="2.5"/>',
    "alert": '<path d="M10 2.5l8 14H2z"/><path d="M10 8v4M10 14.5v.5"/>',
}


def _icon_url(paths: str) -> str:
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="none" '
           'stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
           '%s</svg>' % paths)
    return 'url("data:image/svg+xml,%s")' % urllib.parse.quote(svg, safe="")


ICON_CSS = (".iot .state[class*='ic-']::before { content: ''; width: 18px; height: 18px; flex: none;"
            " background: currentColor; -webkit-mask: var(--ic) center / contain no-repeat;"
            " mask: var(--ic) center / contain no-repeat; }\n"
            + "".join(".iot .state.ic-%s { --ic: %s; }\n" % (name, _icon_url(paths))
                      for name, paths in ICON_PATHS.items()))
CSS += ICON_CSS


def icon_class(name: str) -> str:
    """'state ic-alert' - the class that draws the icon (empty name: no icon)."""
    return "state ic-%s" % name if name in ICON_PATHS else "state"

# A plain dark template for every Plotly chart, in the page's colours.
PLOTLY_TEMPLATE = go.layout.Template(layout=dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family=BODY_FONT.replace('"', ""), color=SOFT, size=13),
    colorway=[LEARN, WATCH, OK, ALERT, "#B79CFF", "#7FD3E8", BAR],
    xaxis=dict(gridcolor=LINE, zerolinecolor=LINE, linecolor=LINE, tickcolor=LINE),
    yaxis=dict(gridcolor=LINE, zerolinecolor=LINE, linecolor=LINE, tickcolor=LINE),
    legend=dict(font=dict(color=SOFT), bgcolor="rgba(0,0,0,0)"),
    hoverlabel=dict(bgcolor=RAISED, bordercolor=LINE, font=dict(color=TEXT)),
    annotationdefaults=dict(font=dict(color=SOFT)),
))


def styled(figure: go.Figure) -> go.Figure:
    """The figure on the page's template (colours and fonts only, never the data)."""
    figure.update_layout(template=PLOTLY_TEMPLATE)
    return figure


def inject() -> None:
    """Put the CSS on the page. Call once per run, after set_page_config."""
    import streamlit as st
    st.html("<style>%s</style>" % CSS)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def esc(value) -> str:
    """Data -> safe HTML text."""
    return html.escape("" if value is None else str(value), quote=True)


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


def duration_text(seconds) -> str:
    """3 min 45 s, for countdowns and 'time to detect'."""
    if seconds is None:
        return "-"
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return "%d s" % seconds
    return "%d min %02d s" % (seconds // 60, seconds % 60)


def _plural(n: int, word: str) -> str:
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _consecutive(state: dict) -> int:
    return int(state.get("consecutive") or detect.CONSECUTIVE)


def _threshold(state: dict) -> float:
    return float(state.get("threshold") or detect.THRESHOLD)


def _devices(state: dict) -> dict:
    return state.get("devices") or {}


def judged_devices(state: dict) -> list:
    """Devices the detector watches: seen in the capture and not skipped."""
    return [n for n, d in _devices(state).items() if d.get("seen") and not d.get("skipped")]


def unseen_devices(state: dict) -> list:
    return [n for n, d in _devices(state).items() if not d.get("seen")]


def baseline_end_epoch(state: dict):
    """The clock time the baseline is complete (its last minute plus the grace)."""
    start = state.get("capture_start_epoch")
    if start is None:
        return None
    return start + (state.get("baseline_seconds") or 0) + (state.get("grace_seconds") or 0)


def endpoint_text(label, addresses: dict) -> str:
    """
    'broker:4444' -> '192.168.0.200:4444': the address from the packets, else
    the lab's fixed infrastructure address (incident.address_label, Step P3),
    so "broker:4444" is never shown.
    """
    return incident.address_label(label, addresses)


def _contained(state: dict) -> dict:
    c = state.get("containment") or {}
    return c if c.get("contained") else {}


def watching_devices(state: dict) -> list:
    """(device, strikes) for devices part-way to an alert, most strikes first."""
    rows = [(n, int(d.get("strikes") or 0)) for n, d in _devices(state).items()
            if d.get("seen") and d.get("onset") is None and int(d.get("strikes") or 0) > 0]
    return sorted(rows, key=lambda r: (-r[1], r[0]))


def device_badge(state: dict, name: str) -> tuple:
    """
    (css class, word, tooltip) for one device. The word never accuses a device
    that has not been flagged: one or two minutes over the line is "Watching",
    not an alarm (one odd minute names nobody).
    """
    d = _devices(state).get(name) or {}
    phase = state.get("phase")
    contained = _contained(state)
    consecutive = _consecutive(state)
    if not d.get("seen"):
        return "off", "Not seen", "sent nothing in this capture"
    if d.get("onset") is not None:
        since = "abnormal since %s" % wall(d.get("onset_epoch"))
        if contained.get("device") == name:
            return "off", "Offline, contained", "%s; contained since %s" % (
                since, wall(contained.get("contained_epoch")))
        if name == state.get("named") and not state.get("abstained"):
            return "alert", "Attack origin", since
        return "alert", "Abnormal", since
    if d.get("skipped"):
        return "off", "Not judged", "too little traffic in the baseline to judge"
    if phase in (live.WAITING, live.LEARNING) or d.get("latest_score") is None:
        return "learn", "Learning", "learning its normal pattern"
    strikes = int(d.get("strikes") or 0)
    if strikes:
        return "watch", "Watching %d of %d" % (strikes, consecutive), \
            "%d of %d minutes in a row over the line" % (strikes, consecutive)
    return "ok", "Normal", "last minute scored %.1f, the line is %.1f" % (
        float(d.get("latest_score")), _threshold(state))


# --------------------------------------------------------------------------
# The top bar
# --------------------------------------------------------------------------

def top_bar(state: dict | None, page: str = "live", replaying: bool = False,
            stale: bool = False) -> str:
    """
    Brand, the two pages, and (on the live page) capture status, session and
    clock. The top bar is the only page switch (the sidebar's is hidden,
    Step P1b). The Live monitor is the app's default page, which Streamlit
    serves at "/" - a link to "/live" would raise "Page not found".
    """
    nav = ('<nav><a class="%s" href="./" target="_self">Live monitor</a>'
           '<a class="%s" href="./replay" target="_self">Past sessions</a></nav>'
           % ("on" if page == "live" else "", "on" if page == "past" else ""))
    right = ""
    if state is not None:
        phase = state.get("phase")
        if stale:
            dot, words = "bad", "Engine not updating"
        elif phase == live.STOPPED:
            dot, words = "off", "Capture stopped"
        elif phase == live.WAITING:
            dot, words = "off", "Waiting for the capture"
        elif replaying:
            dot, words = "", "Replay of a recorded capture"
        else:
            dot, words = "", "Live capture"
        right = ('<div class="right"><span><span class="dot %s"></span>%s</span>'
                 '<span>Session <span class="mono">%s</span></span>'
                 '<span class="clock">%s</span></div>'
                 % (dot, esc(words), esc(state.get("session", "?")),
                    esc(wall(state.get("now_epoch")))))
    return ('<header class="iot top"><div class="brand">IoT Incident Attribution'
            '<small>network forensics console</small></div>%s%s</header>' % (nav, right))


# --------------------------------------------------------------------------
# The status band
# --------------------------------------------------------------------------

def response_figures(state: dict, ack: dict | None = None) -> list:
    """
    The band's three figures once there is an alert (Step P2): to detect, to
    acknowledge, to contain - each "--" until it is known. Read from the
    engine's report, its first alert, its CONTAINED check and the
    acknowledgement; nothing is measured here.
    """
    alert = state.get("first_alert") or {}
    raised = alert.get("raised_epoch")
    when = (state.get("incident") or {}).get("when") or {}
    detect_s = when.get("time_to_detect_seconds")
    if detect_s is None and raised is not None and when.get("first_unusual_epoch") is not None:
        detect_s = raised - when["first_unusual_epoch"]
    ack_s = (ack or {}).get("after_alert_seconds")
    contained = _contained(state)
    contain_s = None
    if contained.get("contained_epoch") is not None and raised is not None:
        contain_s = max(0.0, contained["contained_epoch"] - raised)

    def text(seconds):
        return "--" if seconds is None else duration_text(seconds)

    return [(text(detect_s), "to detect"), (text(ack_s), "to acknowledge"),
            (text(contain_s), "to contain")]


def band_content(state: dict, ack: dict | None = None) -> dict:
    """
    What the band says, as plain parts (tested directly): css class, icon,
    the state word, the headline and the sentence under it (both already
    HTML, data escaped), an optional progress fraction, the figures on the
    right, whether it rings, and the acknowledgement time ("HH:MM:SS" or
    None). ack is the operator's acknowledgement (incident.acknowledgement).
    """
    phase = state.get("phase", live.WAITING)
    devices = _devices(state)
    named = state.get("named")
    consecutive = _consecutive(state)
    packets = "{:,}".format(int(state.get("packets") or 0))
    judged = judged_devices(state)
    n_onsets = len(state.get("onsets") or {})
    figures = [(str(len(judged)), "devices"), (packets, "packets"),
               ("1", "incident") if n_onsets else ("0", "incidents")]

    def part(cls, icon, word, head, sub, progress=None, kpis=None):
        return {"cls": cls, "icon": icon, "state": word, "headline": head, "sub": sub,
                "progress": progress, "kpis": figures if kpis is None else kpis,
                "ringing": False, "acked": None}

    def responding(b):
        """An incident's band: response figures, the ring until acknowledged."""
        b["kpis"] = response_figures(state, ack)
        b["ringing"] = phase == live.INCIDENT and not ack
        b["acked"] = wall(ack["acknowledged_epoch"]) if ack else None
        return b

    if phase == live.WAITING:
        return part("", "learn", "Waiting", "Waiting for the capture",
                    "No capture file has arrived yet.", kpis=[])

    if phase == live.LEARNING:
        total = int(state.get("baseline_windows") or 0)
        done = min(int(state.get("closed_windows") or 0), total)
        minute = min(done + 1, total) if total else 0
        seen = len(state.get("devices_seen") or [])
        return part("learn", "learn", "Learning", "Learning normal behaviour",
                    "Minute <b>%d of %d</b>. Monitoring starts at <b>%s</b>."
                    % (minute, total, esc(wall(baseline_end_epoch(state)))),
                    progress=(done / total) if total else 0.0,
                    kpis=[(str(seen), "devices seen"), (packets, "packets")])

    if phase == live.MONITORING:
        watching = watching_devices(state)
        if watching:
            if len(watching) == 1:
                dev, strikes = watching[0]
                head = "Watching <span class='dev'>%s</span>" % esc(dev)
                sub = "<b>%d of %d</b> minutes in a row over the line." % (strikes, consecutive)
                if strikes == consecutive - 1:
                    sub += " One more raises an incident."
            else:
                head = "Watching %d devices" % len(watching)
                sub = "Minutes in a row over the line: %s." % ", ".join(
                    "<span class='mono'>%s</span> <b>%d of %d</b>" % (esc(d), s, consecutive)
                    for d, s in watching)
            return part("watch", "watch", "Watching", head, sub)
        return part("ok", "ok", "Monitoring", "Monitoring %s" % _plural(len(judged), "device"),
                    "Baseline established at <b>%s</b>. No device is over the line."
                    % esc(wall(baseline_end_epoch(state))))

    # INCIDENT, CONTAINED and STOPPED carry a verdict, if there is one.
    stopped = phase == live.STOPPED
    if not state.get("onsets"):
        if stopped:
            return part("ok", "ok", "Session closed", "No incident",
                        "No device was over the line for %d minutes in a row." % consecutive)
        return part("", "learn", esc(phase), esc(phase), "")

    alert = state.get("first_alert") or {}
    raised = esc(wall(alert.get("raised_epoch")))
    contained = _contained(state)
    if contained and not stopped:
        dest = ", ".join("<span class='mono'>%s</span>" % esc(endpoint_text(w, state.get("addresses")))
                         for w in contained.get("watching") or [])
        return responding(part("ok", "ok", "Contained",
                    "Contained at %s" % esc(wall(contained.get("contained_epoch"))),
                    "<span class='mono'>%s</span> has made no connection to %s for %d seconds. "
                    "The incident stays open as the record."
                    % (esc(contained.get("device")), dest or "its new destinations",
                       int(round(contained.get("quiet_needed_seconds") or 90)))))

    if state.get("abstained"):
        word = "Session closed, origin not certain" if stopped else "Incident, origin not certain"
        return responding(part("watch", "watch", word, "Incident: the starting device is not certain",
                    "Too close to call between %s. Alert raised at <b>%s</b>."
                    % (", ".join("<span class='mono'>%s</span>" % esc(d)
                                 for d in state.get("shortlist") or []), raised)))

    others = sorted(set(state.get("onsets") or {}) - {named})
    sub = "Confidence <b>%s%%</b>. " % esc(state.get("confidence_percent"))
    sub += ("No other device behaved abnormally." if not others else
            "Also abnormal: %s." % ", ".join("<span class='mono'>%s</span>" % esc(d) for d in others))
    head = "The attack started on <span class='dev'>%s</span>" % esc(named)
    severity = (state.get("incident") or {}).get("severity")   # from Step P3 on
    if stopped:
        if contained:
            sub += " Contained at <b>%s</b>." % esc(wall(contained.get("contained_epoch")))
        sub += " Final verdict from the whole capture."
        return responding(part("ok" if contained else "alert", "ok" if contained else "alert",
                    "Session closed, contained" if contained else "Session closed, final verdict",
                    head, sub))
    sub += " Alert raised at <b>%s</b>." % raised
    word = "Incident" + (", severity %s" % esc(severity) if severity else "")
    return responding(part("alert", "alert", word, head, sub))


def status_band(state: dict, ack: dict | None = None, ack_button: bool = False) -> str:
    """
    The band at the top of the live page, as HTML. ack_button=True leaves room
    on the right for the Acknowledge button the page puts over the band.
    """
    b = band_content(state, ack)
    progress = ""
    if b["progress"] is not None:
        progress = '<div class="progress"><i style="width:%.0f%%"></i></div>' % (
            100 * max(0.0, min(1.0, b["progress"])))
    kpis = "".join('<div class="kpi"><div class="v%s">%s</div><div class="k">%s</div></div>'
                   % (" wait" if v in ("--", "-") else "", esc(v), esc(k)) for v, k in b["kpis"])
    classes = " ".join(c for c in (b["cls"], "ringing" if b["ringing"] else "",
                                   "has-ack" if ack_button else "") if c)
    acked = ('<span class="acked">Acknowledged %s</span>' % esc(b["acked"])) if b["acked"] else ""
    return ('<section class="iot band %s" aria-live="polite"><div>'
            '<div class="%s">%s</div><div class="headline">%s</div>'
            '<div class="sub">%s</div>%s</div>'
            '<div class="side"><div class="kpis">%s</div>%s</div></section>'
            % (classes, icon_class(b["icon"]), b["state"], b["headline"], b["sub"],
               progress, kpis, acked))


def waiting_band(title: str, sentence: str) -> str:
    """The band before any session exists (or before its state can be read)."""
    return ('<section class="iot band" aria-live="polite"><div>'
            '<div class="%s">Waiting</div><div class="headline">%s</div>'
            '<div class="sub">%s</div></div><div></div></section>'
            % (icon_class("learn"), esc(title), esc(sentence)))


def notice(text_html: str, kind: str = "") -> str:
    """A quiet one-line note under the band. text_html must already be escaped."""
    return '<div class="iot note %s">%s</div>' % (kind, text_html)


# --------------------------------------------------------------------------
# The device lanes
# --------------------------------------------------------------------------

def _scores(d: dict) -> dict:
    """scores_by_window with int keys (state.json has string keys)."""
    return {int(w): float(s) for w, s in (d.get("scores_by_window") or {}).items()
            if s is not None}


def lane_slots(state: dict) -> tuple:
    """
    (first window shown, windows with data, slots drawn). At least MIN_SLOTS
    slots so bars keep one width; at most MAX_SLOTS, the newest.
    """
    total = int(state.get("closed_windows") or 0)
    for d in _devices(state).values():
        scores = _scores(d)
        if scores:
            total = max(total, max(scores) + 1)
    first = max(0, total - MAX_SLOTS)
    return first, total, max(MIN_SLOTS, total - first)


def lane_rows(state: dict) -> list:
    """
    One row per device seen in the capture: its bars (css class, height in %,
    tooltip), its badge and its strike count. Devices never seen are left to
    the session card ("not seen in this capture").
    """
    threshold = _threshold(state)
    baseline = int(state.get("baseline_windows") or 0)
    width = int(state.get("window_seconds") or 60)
    first, total, _ = lane_slots(state)
    stopped = state.get("phase") == live.STOPPED
    addresses = state.get("addresses") or {}
    rows = []
    for name, d in _devices(state).items():
        if not d.get("seen"):
            continue
        scores = _scores(d)
        bars = []
        for w in range(first, total):
            span = "%s-%s" % (wall_at(state, w * width)[:5], wall_at(state, (w + 1) * width)[:5])
            score = scores.get(w)
            classes = []
            if w < baseline:
                classes.append("base")
            if score is None:
                height = 4.0
                tip = "%s: %s" % (span, "learning, not scored yet" if w < baseline else "no score")
            else:
                if w >= baseline and score > threshold:
                    classes.append("over")
                if score > LANE_SCALE:
                    classes.append("capped")
                height = max(4.0, min(score, LANE_SCALE) / LANE_SCALE * 100)
                tip = "%s: score %.1f%s" % (span, score, " (taller than the scale)"
                                            if score > LANE_SCALE else "")
            if w == total - 1 and not stopped:
                classes.append("fresh")
            bars.append({"window": w, "cls": " ".join(classes), "height": height, "title": tip})
        cls, word, tip = device_badge(state, name)
        role = d.get("kind") or ""
        if addresses.get(name):
            role = "%s, %s" % (role, addresses[name]) if role else addresses[name]
        rows.append({"device": name, "role": role, "bars": bars,
                     "badge": (cls, word, tip), "strikes": int(d.get("strikes") or 0),
                     # the named device keeps its red name once contained (as in the mockup)
                     "origin": (d.get("onset") is not None and name == state.get("named")
                                and not state.get("abstained"))})
    return rows


def device_lanes(state: dict) -> str:
    """The 'every device, minute by minute' card, as HTML."""
    consecutive = _consecutive(state)
    threshold = _threshold(state)
    baseline = int(state.get("baseline_windows") or 0)
    width = int(state.get("window_seconds") or 60)
    first, total, slots = lane_slots(state)
    rows = lane_rows(state)
    line_at = max(0.0, min(100.0, threshold / LANE_SCALE * 100))
    monitoring = total > baseline

    head = ('<div class="ctitle">Every device, minute by minute</div>'
            '<div class="hint">One bar per minute: how unusual that minute was. A device is '
            'flagged only after %s in a row over the line.</div>'
            % ("three minutes" if consecutive == 3 else "%d minutes" % consecutive))
    if not rows:
        return ('<div class="iot card">%s<div class="empty-note">No device has sent anything '
                'yet.</div></div>' % head)

    lanes = []
    for i, row in enumerate(rows):
        bars = []
        for bar in row["bars"]:
            if bar["window"] == baseline and bar["window"] > first:
                bars.append('<span class="split"></span>')
            bars.append('<span class="m %s" style="height:%.0f%%" title="%s"></span>'
                        % (bar["cls"], bar["height"], esc(bar["title"])))
        bars += ['<span class="m empty" style="height:0"></span>'] * (slots - (total - first))
        cls, word, tip = row["badge"]
        strikes = ""
        if monitoring:
            hits = min(row["strikes"], consecutive)
            strikes = '<div class="strikes%s" title="minutes in a row over the line">%s</div>' % (
                " full" if hits >= consecutive else "",
                "".join('<i class="%s"></i>' % ("hit" if k < hits else "")
                        for k in range(consecutive)))
        lanes.append(
            '<div class="lane%s%s"><div><div class="name">%s</div><div class="role">%s</div></div>'
            '<div class="plot" role="img" aria-label="%s score per minute">%s'
            '<span class="line" style="bottom:%.0f%%"></span></div>'
            '<div class="status"><span class="badge %s" title="%s">%s</span>%s</div></div>'
            % (" first" if i == 0 else "", " origin" if row["origin"] else "",
               esc(row["device"]), esc(row["role"]), esc(row["device"]), "".join(bars),
               line_at, cls, esc(tip), esc(word), strikes))

    start = state.get("capture_start_epoch")
    left = wall_at(state, first * width)[:5] if start is not None else ""
    right = wall_at(state, (first + slots) * width)[:5] if start is not None else ""
    mid = ""
    if monitoring and first < baseline <= first + slots:
        mid = '<span class="mid" style="left:%.0f%%">baseline ends %s</span>' % (
            (baseline - first) / slots * 100, esc(wall(baseline_end_epoch(state))[:5]))
    axis = ('<div class="axis"><span></span><div class="ticks"><span>%s</span>%s<span>%s</span>'
            '</div><span></span></div>' % (esc(left), mid, esc(right)))
    legend = ('<div class="legend"><span class="l-base">learning minute</span>'
              '<span>monitored minute</span><span class="l-over">over the line</span>'
              '<span class="l-line">alert line (%.1f)</span></div>' % threshold)
    return '<div class="iot card">%s%s%s%s</div>' % (head, "".join(lanes), axis, legend)


# --------------------------------------------------------------------------
# The right-hand card
# --------------------------------------------------------------------------

def _fact(value, key) -> str:
    return '<div class="fact"><div class="v">%s</div><div class="k">%s</div></div>' % (
        esc(value), esc(key))


def how_card(state: dict) -> str:
    """
    'How it was found' - once there is a verdict. Read from the engine's
    incident report (section 4, the new repeating destination; the playbook's
    contain step) and its CONTAINED check.
    """
    report = state.get("incident") or {}
    named = state.get("named")
    consecutive = _consecutive(state)
    addresses = state.get("addresses") or {}

    if state.get("abstained") or not named:
        explanations = state.get("explanations") or {}
        items = "".join('<li><span class="mono">%s</span>: %s</li>'
                        % (esc(d), esc(explanations.get(d, ""))) for d in state.get("shortlist") or [])
        return ('<div class="iot card"><div class="ctitle">Too close to call</div>'
                '<div class="hint">These devices explain the incident almost equally well. '
                'Nobody is named; check each one.</div><ul class="shortlist">%s</ul></div>' % items)

    patterns = (report.get("how") or {}).get("patterns") or []
    parts = ['<div class="ctitle">How it was found</div>'
             '<div class="hint">Measured from the traffic, not from the contents.</div>']
    if patterns:
        p = patterns[0]
        parts.append('<div class="path"><div class="node bad">%s<small>%s</small></div>'
                     '<div class="wire"></div><div class="node">%s<small>never used in the '
                     'baseline</small></div></div>'
                     % (esc(named), esc(addresses.get(named, "")),
                        esc(endpoint_text(p.get("label", ""), addresses))))
        gap = p.get("typical_gap_seconds")
        parts.append('<div class="facts">%s%s%s%s</div>' % (
            _fact(p.get("count", 0), "new connections"),
            _fact("every %d s" % round(gap) if gap is not None else "-", "machine-regular timing"),
            _fact("%s bytes" % p.get("typical_bytes_out", "-"), "sent each time"),
            _fact("%d of %d" % (consecutive, consecutive), "minutes over the line")))
    else:
        onset = (_devices(state).get(named) or {}).get("onset_epoch")
        parts.append('<div class="facts">%s%s</div>' % (
            _fact(wall(onset), "abnormal from"),
            _fact("%d of %d" % (consecutive, consecutive), "minutes over the line")))
        parts.append('<div class="hint" style="margin-top:12px">No new repeating destination: '
                     'flagged on how its traffic changed.</div>')

    contained = _contained(state)
    if contained:
        ports = ", ".join(esc(endpoint_text(w, addresses)) for w in contained.get("watching") or [])
        parts.append('<div class="do"><div class="dtitle">Confirmed from the traffic</div>'
                     '<p>Last connection to <span class="mono">%s</span> at <b>%s</b>. None in the '
                     '%d seconds after.</p></div>'
                     % (ports, esc(wall(contained.get("last_seen_epoch"))),
                        int(round(contained.get("quiet_needed_seconds") or 90))))
    elif state.get("phase") != live.STOPPED:
        playbook = report.get("playbook") or []
        contain = next((s for s in playbook if s.get("step") == "contain"), None)
        if contain and contain.get("do"):
            parts.append('<div class="do"><div class="dtitle">Do this now</div><p>%s</p></div>'
                         % esc(contain["do"][0]))
    return '<div class="iot card">%s</div>' % "".join(parts)


def session_card(state: dict, replaying: bool = False) -> str:
    """'This session' - before there is a verdict."""
    total = int(state.get("baseline_windows") or 0)
    done = min(int(state.get("closed_windows") or 0), total)
    learning = state.get("phase") in (live.WAITING, live.LEARNING)
    judged = len(state.get("devices_seen") or []) if learning else len(judged_devices(state))
    hint = ("Replay of a recorded capture, one 10-second file at a time." if replaying else
            "Capture on the wired adapter, a new file every 10 seconds.")
    parts = ['<div class="ctitle">This session</div><div class="hint">%s</div>' % hint,
             '<div class="facts">%s%s%s%s</div>' % (
                 _fact("%d of %d" % (done, total), "baseline minutes"),
                 _fact(judged, "devices seen" if learning else "devices judged"),
                 _fact(len(state.get("problems") or []), "files unreadable"),
                 _fact("%.1f" % _threshold(state), "alert line"))]
    unseen = unseen_devices(state)
    skipped = [n for n, d in _devices(state).items() if d.get("seen") and d.get("skipped")]
    notes = []
    if unseen:
        notes.append("<p>%s %s in the inventory but %s sent nothing.</p>" % (
            ", ".join('<span class="mono">%s</span>' % esc(n) for n in unseen),
            "is" if len(unseen) == 1 else "are", "has" if len(unseen) == 1 else "have"))
    if skipped:
        notes.append("<p>%s: too little traffic in the baseline to judge.</p>"
                     % ", ".join('<span class="mono">%s</span>' % esc(n) for n in skipped))
    if notes:
        title = "Not judged in this capture" if skipped else "Not seen in this capture"
        parts.append('<div class="do"><div class="dtitle">%s</div>%s</div>'
                     % (title, "".join(notes)))
    return '<div class="iot card">%s</div>' % "".join(parts)


# --------------------------------------------------------------------------
# The timeline
# --------------------------------------------------------------------------

def timeline_points(state: dict, ack: dict | None = None) -> list:
    """(clock time, words, css class) for each moment known so far."""
    report = state.get("incident") or {}
    when = report.get("when") or {}
    alert = state.get("first_alert") or {}
    contained = _contained(state)
    points = []
    if baseline_end_epoch(state) is not None and state.get("phase") not in (live.WAITING,
                                                                             live.LEARNING):
        points.append((wall(baseline_end_epoch(state)), "Baseline established", ""))
    if when.get("first_unusual_epoch") is not None:
        points.append((wall(when["first_unusual_epoch"]), "First unusual connection", "hot"))
    if alert.get("raised_epoch") is not None:
        points.append((wall(alert["raised_epoch"]), "Alert raised", "hot"))
    if ack:
        points.append((wall(ack["acknowledged_epoch"]), "Acknowledged", ""))
    if contained:
        points.append((wall(contained.get("contained_epoch")), "Contained", "good"))
    return points


def timeline(state: dict, ack: dict | None = None) -> str:
    points = timeline_points(state, ack)
    if not points:
        return ""
    items = "".join('<div class="%s"><div class="t">%s</div><div class="w">%s</div></div>'
                    % (cls, esc(t), esc(w)) for t, w, cls in points)
    return ('<div class="iot card"><div class="ctitle">Timeline</div>'
            '<div class="tl">%s</div></div>' % items)


# --------------------------------------------------------------------------
# The report area (Step P3) - the designed report's facts, drawn dark
# --------------------------------------------------------------------------
#
# incident.design_facts collects what the report shows from the engine's
# report dict; the PDF draws it light (incident.render_html), these draw the
# same facts dark for the console, so the page and the paper never disagree.

def _mono_in(text: str, monos) -> str:
    out = esc(text)
    for m in sorted({x for x in monos or [] if x}, key=len, reverse=True):
        out = out.replace(esc(m), '<span class="mono">%s</span>' % esc(m))
    return out


def report_keys(facts: dict) -> list:
    """(value, label, css) for the page's key facts: incident, severity, origin, confidence."""
    origin = facts.get("keys", [("-", "")])[0]
    return [
        (facts.get("incident_id") or "-", "incident", ""),
        ((facts.get("severity") or "-").capitalize(), "severity",
         "sev-%s" % (facts.get("severity") or "none")),
        (origin[0], origin[1], ""),
        ("%s%%" % facts["confidence"] if facts.get("device") and facts.get("confidence")
         is not None else "Not certain", "confidence", ""),
    ]


def report_summary_card(facts: dict) -> str:
    """Key facts and 'What happened' with where its wording came from."""
    keys = "".join('<div><div class="v %s">%s</div><div class="k">%s</div></div>'
                   % (css, esc(v), esc(k)) for v, k, css in report_keys(facts))
    return ('<div class="iot card"><div class="ctitle">Incident report</div>'
            '<div class="hint">Severity rule: %s</div><div class="rkeys">%s</div>'
            '<div class="ctitle" style="margin-top:16px;font-size:15px">Analyst summary</div>'
            '<p class="summary" style="margin-top:6px">%s</p><div class="source%s">%s%s</div></div>'
            % (esc(facts.get("severity_rule", "")), keys, esc(facts.get("summary", "")),
               " ai" if facts.get("by_ai") else "", "&#10003; " if facts.get("by_ai") else "",
               esc(facts.get("source", ""))))


def techniques_card(facts: dict) -> str:
    items = "".join('<b>%s</b><span><b>%s.</b> %s</span>'
                    % (esc(t["id"]), esc(t["name"]), esc(t["evidence"]))
                    for t in facts.get("techniques") or [])
    if not items:
        items = '<span></span><span>No technique could be matched from the shape of the traffic.</span>'
    return ('<div class="iot card"><div class="ctitle">Attack techniques seen (MITRE ATT&amp;CK)'
            '</div><div class="hint">Consistent with these techniques, judged from the '
            'shape of the traffic only.</div><div class="tech">%s</div></div>' % items)


def steps_card(facts: dict) -> str:
    items = "".join('<li class="%s"><span class="box"></span><span class="when%s">%s</span>'
                    '<span><b>%s</b> %s</span></li>'
                    % ("done" if s["done"] else "", " later" if s["later"] else "", esc(s["when"]),
                       esc(s["title"]), _mono_in(s["text"], s.get("mono")))
                    for s in facts.get("steps") or [])
    return ('<div class="iot card"><div class="ctitle">What to do</div><div class="hint">'
            'Recommended - the operator acts; nothing is done automatically.</div>'
            '<ul class="steps">%s</ul></div>' % items)
