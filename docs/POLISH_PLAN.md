# Polish plan - product look, alert experience, designed report, AI analyst

Version 1, 14 Nov 2026. **Approved by Muheeb on 14 Nov 2026** - this replaces the
"no code changes after the freeze" note and the "do not start Step 23 without asking" note
in CLAUDE.md. The core is locked at git tag `core-locked` (commit 7ca51aa): 6 of 6 live
sessions correct, full suite green. Nothing in this plan may change a verdict or a score.

## 1. What this plan is for

The engine is finished. What a judge sees is not: the page reads like a lab script
("safe to launch the attack"), the alert is a quiet coloured box, the report is plain HTML,
and the title says "LLM-Assisted" while the live page uses no model. This plan fixes what
is seen and heard, and nothing else.

## 2. Rules for every step (P1-P6)

1. **Do not edit**: `src/capture.py`, `features.py`, `detect.py`, `attribute.py`,
   `windows.py`, `runs.py`, `generate.py`, the scoring in `evaluate.py`, `firmware/`.
   If a step seems to need one of them, stop and ask.
2. `state.json` and the report dict may **gain** fields. No existing field changes meaning.
3. The page stays a display: it never decides anything. The engine never reads the answer
   folder (the leak test still applies to every `src/` file).
4. **Invariant check, after every step** (add it once as `tests/test_polish_invariant.py`,
   skipping cleanly when the pcaps are absent): replaying `pcap/live/live_session_07.pcapng`
   and `live_session_03.pcapng` through `src.live` gives the same named device, confidence,
   onsets, alert second and CONTAINED second as the saved `data/<session>.meta.json`.
   And `git diff --exit-code results/` is clean after re-running the scoring commands.
5. One step = tests, full suite green, one commit, push, tag `polish-pN`. Then **stop**,
   tell Muheeb in plain English what changed and give the one command that shows it
   without hardware (`python -m src.live --session demo_pN --replay
   pcap\live\live_session_07.pcapng --speed 20`, then the dashboard).
6. No new heavy dependency. Streamlit 1.40.2 + CSS + Plotly + what is already installed.
   No web fonts and no CDN: the design uses fonts Windows 11 already has (Bahnschrift,
   Segoe UI Variable, Cascadia Mono).
7. Every piece of text that comes from data (device names, addresses, model wording) goes
   through `html.escape` before it is put into HTML.
8. Fallback ladder still works at every commit (live -> `--replay` -> Past sessions page ->
   saved report).

## 3. Design references (open them in a browser first)

- `docs/design/console_mockup.html` - the live page in five phases (buttons at the bottom:
  Learning, Monitoring, Watching, Incident, Contained). Layout, colours, type, wording and
  the one animation are all in this file. Match it.
- `docs/design/report_mockup.html` - the incident report. One light A4 design used both on
  screen and for the PDF. Two pages at most.

Design decisions that are easy to miss:
- **One loud element**: the status band at the top. Everything else is quiet.
- **Device lanes replace the multi-line chart**: one row per device, one bar per closed
  minute, all rows on one scale, dashed alert line at 4.0, bars over the line in the alert
  colour. A bar taller than the scale is capped and marked; the real score is in the
  tooltip. The plot always has at least 20 minute slots so bars never change width; past 40
  minutes it shows the last 40. No per-device colours are needed, so nothing depends on
  telling three line colours apart.
- Status is never colour alone: every state has a word ("Normal", "Watching 2 of 3",
  "Attack origin", "Offline, contained") and the band has an icon.
- The only motion: the band's ring while an incident is unacknowledged, and bars growing.
  `prefers-reduced-motion` turns both off.
- Product wording, not lab wording:

  | was | now |
  |---|---|
  | Learning what normal looks like - do not attack yet | Learning normal behaviour. Minute 7 of 12. Monitoring starts at 19:29:18. |
  | Monitoring - safe to launch the attack | Monitoring 3 devices. Baseline established at 19:29:18. No device is over the line. |
  | watching: 2 of 3 minutes in a row over the line | Watching esp32-03. 2 of 3 minutes in a row over the line. |
  | Incident - the attack started on esp32-03 | The attack started on esp32-03 (state line: "Incident, severity high") |
  | Reveal the true answer (after stop) | moved into a collapsed "Lab validation" section at the bottom: "Compare with the recorded answer" |
  | Replay a saved capture | Past sessions |

## 4. Steps

### P1 - the console (live page) and the shared theme
- `dashboard/theme.py`: the CSS (copied from the mockup's tokens), a Plotly template, and
  pure functions that return HTML strings: `status_band(state)`, `device_lanes(state)`,
  `how_card(state)`, `session_card(state)`. Pure functions are unit-tested.
- `.streamlit/config.toml`: dark base colours so Streamlit's own widgets match. Hide
  Streamlit's header bar. Use the full width. Sidebar collapsed by default; it keeps the
  page switch, "Follow the newest session", and (P2) the sound switch.
- Live page rebuilt to the mockup: top bar, status band per phase, lanes + right card,
  then the report area (existing report content for now; P3 restyles it).
- "Lab validation" expander at the bottom holds the reveal tick. Same behaviour as today:
  it reads the answer file only after STOPPED.
- Past sessions page (the replay page): same theme and Plotly template, renamed; its
  layout is not rebuilt.
- Tests: pure-function tests; AppTest renders every phase (waiting, learning, monitoring,
  watching, incident, contained, stopped, stale engine) with zero exceptions.
- Look at it: try screenshots with headless Edge
  (`msedge --headless --disable-gpu --user-data-dir=<temp folder> --window-size=1366,768
  --virtual-time-budget=10000 --screenshot=<png> http://localhost:8501/...`). If the page
  comes out blank (Streamlit draws over a websocket), say so and ask Muheeb for
  screenshots instead - do not guess what it looks like. Save what you get in
  `docs/screenshots/`.

### P2 - the alert experience
- While the phase is INCIDENT and not acknowledged: band ring animation, an **Acknowledge**
  button in the band, and a short repeating tone.
- Acknowledge writes `pcap/live/<session>/ack.json` (`{"acknowledged_epoch": ...}`) - an
  operator action, written by the page, read by the engine only to put the time in
  state.json and the report. The ring and the tone stop. The band shows "Acknowledged
  HH:MM:SS".
- Tone: a WAV generated in code (two 880 Hz pips per 1.6 s, quiet), played with
  `st.audio(..., autoplay=True, loop=True)`. Sidebar switch "Alert sound", default on.
  Verified in a headless browser on 14 Nov: the audio element survives the 3-second
  fragment refresh (it is not re-created, it keeps playing), and disappears on Acknowledge.
  **Not verified**: a real browser may refuse to play sound until the operator has clicked
  something on the page. So `docs/LIVE_DEMO.md` gets a line: click the "Alert sound"
  switch off and on once after opening the page. The visual alert never depends on sound.
- Three figures in the band: **to detect** (first unusual connection -> alert; already in
  the report), **to acknowledge** (alert -> acknowledge), **to contain** (alert ->
  CONTAINED). Shown as "--" until known.
- Tests: ack file round trip; figures from fixture states; AppTest for acknowledged and
  unacknowledged incident.

### P3 - the designed report and the PDF
- New report fields, all rule-based and deterministic (no model):
  - `incident_id`: `INC-<capture date YYYYMMDD>-<trailing digits of the session name,
    else HHMM of the alert>`.
  - `severity`: **critical** = more than one device flagged; **high** = one device with a
    new repeating destination (section 4 non-empty); **medium** = flagged, no new repeating
    destination. The report states the rule in one line.
  - `techniques` (MITRE ATT&CK, wording "consistent with"):
    T1571 Non-Standard Port - new destination port not in the known-service list;
    T1029 Scheduled Transfer - 4 or more connections with a regular gap (std / mean < 0.2);
    T1041 Exfiltration Over C2 Channel - more bytes out than back on that destination.
    Check the three names on attack.mitre.org before committing.
- `incident.render_html` rewritten to `docs/design/report_mockup.html`. The eight existing
  sections stay in the report dict and in `render_text` unchanged; the designed page shows
  the short version and the dashboard keeps "Full technical detail" in an expander.
- PDF: `incident.html_to_pdf(html_path) -> Path | None` using the Edge that Windows 11
  already has: find `msedge.exe` (both Program Files folders; Chrome as second choice), run
  `--headless --disable-gpu --no-pdf-header-footer --user-data-dir=<fresh temp folder>
  --print-to-pdf=<out.pdf> <file URI from Path.as_uri()>` with a 45 s timeout, arguments
  as a list (the repo path has a space). The fresh `--user-data-dir` matters: without it a
  running Edge swallows the command and no file appears. Return None on any failure.
  Verified 14 Nov with Chromium on Linux: the mockup prints to a 2-page A4 PDF with its
  colours. **Not verified on this laptop** - so the first thing in P3 is converting
  `reports\live_session_07.html`; if it cannot be made to work in 30 minutes, keep the
  HTML download with "print to PDF from the browser" and say so.
- Engine writes the PDF at STOP. The page has "Create PDF" -> "Download PDF".
- Tests: fields on rehearsal_02 / live_session_07 fixtures (high, three techniques,
  id format); render contains no unescaped data; `html_to_pdf` returns None cleanly when
  no browser is found.

### P4 - the AI analyst (cloud)
- Why cloud: the local model took 45+ minutes per answer on this laptop. Internet is
  assumed for the demo; the page must still be complete without it.
- First: one real call with the key in `API_KEY.env` (never print it) to confirm
  `report.CLOUD_MODEL` still answers, and time it. In September one call took 4.4 s and one
  hit the 90 s timeout. If the model name is refused, list the models, pick the current
  flash-tier one, and tell Muheeb.
- `python -m src.live --session <name> --llm cloud`: when the first alert is raised, a
  background thread asks for the analyst summary. Limit 25 s, one retry, never blocks the
  engine's tick. The answer goes through the existing validator (`report.validate_brief`
  path); only a passing answer is shown. Result cached as
  `pcap/live/<session>/analyst.json`; asked again once at STOP for the final report.
- The summary is 2-3 sentences and names only things that do not change minute to minute
  (device, time of first unusual connection, destination and port, interval, bytes) - no
  running connection counts, so it never disagrees with the cards beside it.
- On the page and in the report: "Analyst summary" with either "Written by the AI analyst
  (<model>). Every fact checked against the evidence." or "Template wording - the AI
  analyst was not reachable." The verdict, numbers and playbook never come from the model.
- What leaves the laptop: device names, MAC and IP addresses, ports, times, byte counts.
  No packet contents, no Wi-Fi password. Say so in the README.
- Past sessions page: default writer is cloud when a key is present.
- Tests: thread with a fake transport (pass, validator reject, timeout, no key) - the
  engine's state is identical in all four except the wording field.

### P5 - documents
- `docs/HOW_IT_WORKS.md`: the viva guide, written from the code - the flow, what each
  terminal command starts, each file's job in one line, how detection and attribution
  differ, how the engine cannot know the answer, real-world IDS vs this prototype.
- `docs/LIVE_DEMO.md` updated to the new screens and wording, plus: the broker started the
  way Muheeb starts it (`.\mosquitto -c "E:\T Softwares\Mosquitto\lab.config" -v` from
  `C:\Program Files\Mosquitto`, `lab\mosquitto_lab.conf` as the alternative); Administrator
  windows need `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` before
  the activate line; `--llm cloud`; the sound switch click; the attacker's listener window
  shown beside the console.
- README and CLAUDE.md brought up to date.

### P6 - two dress rehearsals on the hardware, then freeze
- `rehearsal_03` (esp32-02) and `rehearsal_04` (esp32-03), following `docs/LIVE_DEMO.md`
  word for word, with sound, Acknowledge, unplug, CONTAINED, PDF. In one of them also do
  fallback rung 2 once. Then tag `demo-ready`. After that: no code changes.

## 5. Left out on purpose

- A continuous siren, pop-up windows, automatic blocking: real operations teams avoid
  them; a wrong automatic block takes a healthy device offline.
- An "ask the analyst anything" chat box: unvalidated model text on a security console.
- A second attack type, an attack that spreads between boards, a rolling baseline for
  24x7 use: these change the core and belong after the demo.
