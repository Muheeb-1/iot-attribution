# Polish plan - product look, alert experience, designed report, AI analyst

Version 1, 14 Nov 2026. **Approved by Muheeb on 14 Nov 2026** - this replaces the
"no code changes after the freeze" note and the "do not start Step 23 without asking" note
in CLAUDE.md. The core is locked at git tag `core-locked` (commit 7ca51aa): 6 of 6 live
sessions correct, full suite green. (After P6: 8 of 8, frozen at tag `demo-ready`.) Nothing in this plan may change a verdict or a score.

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

### P1b - fixes found when P1 was checked by eye (15 Nov 2026)
1. The app opens on **Live monitor** (its `st.Page` has `default=True`). Past sessions
   opens on the newest real live session (`live_session_NN`, highest number, aborted
   sessions left out), else the newest real lab capture - never a simulated `run_*` by
   default (`app.default_run`).
2. Past sessions, "When each device went abnormal": the left margin fits the longest
   device name (`app.name_margin`, plus Plotly automargin); the bottom margin fits the
   hour ticks, the axis title and the legend, which also overlapped.
3. Past sessions chart colours: origin = `theme.ALERT`, on the shortlist = `theme.WATCH`,
   went abnormal = `#B79CFF` (`theme.FLAGGED`), nothing unusual = `#5C6F92`. The old
   orange shortlist and amber "went abnormal" looked the same.
4. Past sessions: "Reveal the true answer" left the sidebar for a collapsed "Lab
   validation" section at the bottom, "Compare with the recorded answer", like the live
   page (`app.answer_verdict` is the pure part).
5. The sidebar caption "Streamlit only - no Node, no React, no build step." is gone.
6. The page menu showed twice. Checked in a real browser (Edge driven over its DevTools
   protocol) that the top-bar links work alone, then set `showSidebarNavigation = false`.
   Found while checking: the Live monitor link pointed at `/live`, but the default page is
   served at `/`, so it raised Streamlit's "Page not found" dialog - the link is now `./`.
   (Typing `/replay` into a freshly started server can still flash that dialog once,
   with or without the sidebar menu - a Streamlit 1.40 quirk; opening `/` and clicking
   the top bar never does.)
7. Inline code (`esp32-03`, file paths) is `var(--soft)` on `var(--raised)` on both
   pages, not Streamlit's green.
8. This section. Tests: `tests/test_p1b.py`.

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

P2 as built (15 Nov 2026):
- In INCIDENT, CONTAINED and STOPPED the band's three figures are "to detect", "to
  acknowledge", "to contain" (as in the mockup), not devices / packets / incidents.
- Which clock "to acknowledge" uses: live, the click time is the capture time (the packets
  are stamped by the same laptop clock); in a replay the recording's clock runs 20 times
  fast, so the click is placed at the alert plus the operator's REAL reaction time
  (`incident.acknowledgement`; the engine records the real moment it raised the alert as
  `first_alert_wall_epoch`).
- The band icons were never drawn in the real app: Streamlit's `st.html` strips `<svg>`.
  They are now CSS masks (`theme.ICON_PATHS`), checked in Edge.
- Checked in Edge over its DevTools protocol: the button sits inside the band; the tone
  stays silent until the page has been clicked, and plays after "Alert sound" was
  switched off and on with real clicks; the same player survives the 3-second refresh
  and loops; Acknowledge writes ack.json and the ring, button and tone go.

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

P3 as built (15 Nov 2026):
- The Edge command was tried first on `reports\live_session_07.html`: it worked
  on this laptop (Edge in `C:\Program Files (x86)`, about 3 s, 2 A4 pages with the
  colours). No fallback was needed. `incident.html_to_pdf` returns None on any
  failure; the page then says to download the HTML and print it from the browser.
- Destinations are SHOWN as addresses everywhere on the live page and in the
  report (`192.168.0.200:4444`, never `broker:4444`): `incident.address_label` /
  `display_text`, display only. capture.py's names and the report's `label`
  fields are unchanged, so the containment check and every comparison still
  match on them. The address comes from the packets, else `capture.IP_TO_NAME`.
- The containment line is sentence case: "Not contained yet. Last connection to
  192.168.0.200:4444 at 19:33:19, 39 s ago. Containment is confirmed after 90 s
  with none." / "Contained at ...".
- ATT&CK names checked on attack.mitre.org (15 Nov): T1571 Non-Standard Port
  (Command and Control), T1029 Scheduled Transfer (Exfiltration), T1041
  Exfiltration Over C2 Channel (Exfiltration).
- Report gains (new fields only): `incident_id`, `severity`, `severity_rule`,
  `techniques`, `addresses`, `evidence`, `session_folder`, `why.series` (every
  scored minute, for the bars) and `gap_cv` per section-4 pattern (for T1029).
  A state saved before P3 is still drawn the new way (`designed_fields` works
  from the dict; without `gap_cv` it does not claim T1029).
- Live page report area: key facts (incident, severity, origin, confidence -
  the three response times are already in the band just above), what happened
  with its wording source, timeline, techniques, what to do, Create PDF /
  Download PDF + Download HTML, then "Full technical detail (all eight
  sections)" collapsed. The engine prints `reports/<session>.pdf` at STOP
  (`live.WRITE_PDF`; switched off for the tests in `tests/conftest.py`).
- A baseline minute over the line is drawn grey in the report's bars (learning,
  not an alert), as on the live lanes.
- Tests: `tests/test_p3.py`.

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

P4 as built (15 Nov 2026):
- First real call (key from API_KEY.env, never printed): `report.CLOUD_MODEL`
  = gemini-3.6-flash still answers - HTTP 200 in 8.0 s. No model change.
  In a speed-20 replay of live_session_07 with `--llm cloud`: 5.7 s at the
  alert, 5.0 s at STOP, both passed the check.
- `src/analyst.py`: `analyst_facts` (device, its address, first unusual
  connection time and id, destination address:port, interval, bytes sent and
  received - nothing that changes minute to minute), `check_summary`
  (report.validate_brief with exactly those facts allowed, plus: at most 3
  sentences, no running count, no other lab device, names the device), `ask`
  (25 s per attempt, one retry carrying the objections), `Analyst` (background
  thread, cached as `pcap/live/<session>/analyst.json`; at STOP one more ask
  inside one 25 s budget; if that fails, the alert's passing answer is kept
  when its facts are the same).
- Engine: `python -m src.live --session <name> [--replay ...] --llm cloud`.
  The report and state gain `analyst` (status ok / asking / rejected /
  unreachable / no key, model, summary) and the state `llm` and
  `analyst_calls` (stage, status, seconds of each ask). Nothing else depends
  on it: tests/test_p4.py replays live_session_07 four times (pass, rejected,
  timeout, no key) and every state of every cycle is identical apart from
  those fields.
- Wording on the page and in the report, under "Analyst summary": "Written by
  the AI analyst (gemini-3.6-flash). Every fact checked against the evidence."
  / "Template wording - the AI analyst was not reachable." (offline, timeout,
  no key) / "Template wording - the AI analyst's answer did not pass the
  evidence check." (rejected twice) / "Template wording, built from the
  measurements." (run without --llm). The summary is shown only with status ok.
- Offline checked for real: with HTTPS_PROXY pointed at a closed port, both
  asks fail in ~4 s and the report shows the template wording.
- Past sessions: the writer defaults to cloud when API_KEY.env is present
  (`app.default_writer`). The tests set IOT_NO_CLOUD=1 for the whole session
  (tests/conftest.py) so no test can reach the real cloud - found while writing
  P4: a function-scoped guard came too late for a module-scoped replay fixture.
- README: the AI analyst and what leaves the laptop (no packet contents, no
  Wi-Fi password).

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

P5 as built (15 Nov 2026):
- The interpreting prompt (`analyst.PROMPT_P5`): what a small, same-size message to a new
  address on a fixed timer usually means, why it matters, whether another device changed,
  one thing to check next; no contents, attacker or method may be invented. The facts gain
  `timing` (machine-regular, same rule as T1029) and `other_devices_abnormal` ("none" or
  the list). The check gains a rule against claims the measurements cannot show
  (passwords, credentials, stolen data, botnet, nation-state, ...); a flagged device may be
  named. Measured with 10 real calls, one attempt each (5 x live_session_07, 5 x _03
  facts): **7 of 10 passed**, 1.9-9.0 s each (median 4.3 s over all ten). All 7 answers that
  came back passed the check; the 3 failures came back within 0.6-0.8 s with no answer (the
  server refused the request; most likely the free tier's rate limit - the code was not
  recorded then and is now: "HTTP 429"). By the rule set beforehand (keep only if at least
  8 of 10 pass) **`PROMPT_P4` stays live**; `PROMPT_P5` is kept in the file, and the 10
  results in `tests/fixtures/analyst_p5_trial.json`. Switching needs a new measurement and
  Muheeb's approval.
- Saved reports: `reports/` was never in git (gitignored since Step 19), so the old-design
  files were copied to `reports/old_design/` (also gitignored) before
  `python -m src.incident live_session_0N --pdf` re-created 01, 02, 03, 04, 05 and 07 (06 was
  aborted and has no report) as HTML + 2-page PDF, template wording. `report_for_run` now
  carries a saved live session's own CONTAINED check, evidence list, acknowledgement and
  addresses. Checked per session against the engine's own final report
  (`pcap/live/<session>/state.json`), the saved meta and the scored tables: named device,
  confidence, flagged set, onset, first unusual connection, alert second (also = meta),
  time to detect, beacon destination and count, CONTAINED moment and status, flagged set
  and confidence = `table_live_sessions_per_run.csv`, V5 rank 1, contained clock =
  `table_live_sessions_timing.csv` - no mismatch in any of the six.
- `.gitignore`: data/, pcap/live/ and reports/ demo_* and test_* are never committed (the
  old "frozen demo run" exception for data/demo_* was removed - none was ever committed).
  Nothing was deleted.
- `docs/HOW_IT_WORKS.md` (new, for the viva) and `docs/LIVE_DEMO.md` version 2 (final build:
  Muheeb's broker command, the Administrator `Set-ExecutionPolicy` line, `--llm cloud`, the
  sound-switch click, Acknowledge, Create/Download PDF, the attacker's window beside the
  console, the ladder with the new rung 4). README and CLAUDE.md brought up to date.
- Tests: `tests/test_p5.py`.

### P5b - the interpreting prompt, tightened and measured the way a session calls

P5b as built (15 Nov 2026):
- `PROMPT_P5` tightened: at most 4 sentences, about 600 and never more than 650 characters
  (the check uses 4 / 650: `P5_MAX_SENTENCES`, `P5_MAX_CHARACTERS`); "why it matters" folded
  into the meaning sentence; ONE of "usually" / "likely" / "consistent with" at a time. The
  check rejects stacked hedges ("may likely", "usually consistent with") - six of P5's seven
  answers had one. Everything else about the prompt is unchanged.
- After "HTTP 429" the one retry waits 5 s (`RATE_LIMIT_WAIT`), and the wait counts inside the
  retry's 25 s (its own timeout drops to 20 s) and inside the 25 s STOP budget. Other refusals
  and timeouts retry at once.
- Measured the way a real session calls: 6 real calls, one every 60 s, alternating
  live_session_07 and live_session_03 facts, one attempt each, with the P5 limits:

  | call | facts | result | seconds | characters | sentences |
  |---|---|---|---|---|---|
  | 1 | live_session_07 | passed | 1.95 | 605 | 4 |
  | 2 | live_session_03 | passed | 1.88 | 487 | 4 |
  | 3 | live_session_07 | passed | 5.20 | 531 | 4 |
  | 4 | live_session_03 | passed | 1.64 | 497 | 4 |
  | 5 | live_session_07 | passed | 1.94 | 473 | 4 |
  | 6 | live_session_03 | passed | 1.78 | 539 | 4 |

  No failure, so no HTTP code to record. All 6 came back and passed -> by the rule, **PROMPT_P5
  is live** with the 4 / 650 limits (`tests/fixtures/analyst_p5b_trial.json`).
- Because the live summary now says whether any other device changed, the engine asks again
  if the set of other flagged devices changes later in the incident (`live._tend_analyst`),
  so the summary cannot disagree with the cards. A normal session still makes 2 calls.
- Docs: HOW_IT_WORKS (the AI section, the numbers, the test count; also corrected: a summary
  rejected twice is labelled "...did not pass the evidence check", not "not reachable"),
  LIVE_DEMO Q&A, README, CLAUDE.md. Tests: `tests/test_p5b.py`.

### P6 - two dress rehearsals on the hardware, then freeze
- `rehearsal_03` (esp32-02) and `rehearsal_04` (esp32-03), following `docs/LIVE_DEMO.md`
  word for word, with sound, Acknowledge, unplug, CONTAINED, PDF. In one of them also do
  fallback rung 2 once. Then tag `demo-ready`. After that: no code changes.

P6 as built (15 Nov 2026):
- The two rehearsals were recorded as ordinary live sessions, `live_session_08` (esp32-02)
  and `live_session_09` (esp32-03), not as rehearsal_03/04, so they are scored with the
  other live sessions. Final build, `--llm cloud`, LIVE_DEMO.md followed; nothing went
  off-plan (no `SESSION_NOTES` entry). Fallback rung 2 (`--replay` of live_session_07 as
  replay_demo_01, a test output, not committed) gave the same alert second.
- Measured from the engine's own records (`evaluate.py` timing table) - all clocks IST:

  | session | trigger | alert | to detect | acknowledged | CONTAINED | after alert | V5 |
  |---|---|---|---:|---|---|---:|---|
  | 08 | 14:31:26 | 14:34:03 | 2 min 37 s | 14:34:14 (+10.7 s) | 14:35:56 | 1 min 53 s | esp32-02, 100% |
  | 09 | 14:54:35 | 14:58:13 | 3 min 38 s | 14:58:29 (+16.2 s) | 14:59:35 | 1 min 22 s | esp32-03, 100% |

  Session 09's CONTAINED was 14:59:35 (reported on the day as "about 14:59:45"). Only the
  attacked board was flagged in either session. AI analyst: 4 of 4 calls passed, 2.1-4.1 s.
- Session 08's faster alert, checked: its first beacon came 1.1 s before its minute closed
  (the first monitored minute). Being in the first monitored minute is not the reason -
  session 09's first beacon also was, 2.7 s before the close. The reason is the score: a
  minute holding one beacon scored 3.19-3.25 (under 4.0) in sessions 01, 03, 05 and 09, but
  106 in 08, because esp32-02's broker connection never appears in that capture (in every
  other session it appears in the first learning minute, ~9 kB in), so its learned normal
  had zero incoming bytes and the beacon's 170 bytes back were far outside it
  (`bytes_in` spread fell back to 1). So in 08 the minute of the first beacon was minute 1
  of 3. Same detector; that session's baseline was different. The same flat baseline is
  why B2 ("strangest-looking") was right once.
- Scored the same way as 01-07 (`--runs 9`; `--runs 9 --exclude live_session_02`):
  sessions 01-07's rows in the per-run and timing files are unchanged; 08 and 09 are new
  rows. The summary tables are recomputed over the larger set (as Step 21 did): all
  sessions 8, V5 top-1 100%, B4 100%, B3 12.5% (was 16.7% of 6), B2 12.5% (was 0%), B1 0%;
  loop on 7, V5 100%, B2 14.3% (was 0%). Re-converting the raw captures (`--pcap-dir
  pcap/live`) gives the same verdict for all 8. Data files: as for 01-07, the answer files
  and `data/` runs stay gitignored; only the `results/` tables are committed.
- Replays of 08 and 09 through the live path (speed 20): same verdict, onset minute,
  closed second and CONTAINED second. The alert is raised 4.5 s later in the replay than
  live (+910.0 vs +905.5; +969.9 vs +965.5): by minute 15 the live ring files had drifted
  4.5 s from the replay's even 10-s cuts. A display-time difference only; session 07 (the
  practised rung 2) has none.
- Fix: the stray "›" left of "Severity rule" and "Attack techniques seen" was Streamlit's
  "open the sidebar" button, fixed to the window corner while the page scrolls under it
  (at the top it sat on the "o" of the title). It stays (it opens the Alert sound switch);
  `theme.CSS` gives it its own left margin. Checked in Edge at 1366 x 768, top and scrolled;
  the button still opens the sidebar. `tests/test_p6.py`.
- Real attacks named correctly under today's rules: 22 of 22 (12 batch, 2 rehearsals,
  8 live). Hardware sessions under today's rules: 9 (rehearsal_02 + 8 live), all correct.
- Tagged `demo-ready`. **The code is frozen**: no code changes unless Muheeb asks.

## 5. Left out on purpose

- A continuous siren, pop-up windows, automatic blocking: real operations teams avoid
  them; a wrong automatic block takes a healthy device offline.
- An "ask the analyst anything" chat box: unvalidated model text on a security console.
- A second attack type, an attack that spreads between boards, a rolling baseline for
  24x7 use: these change the core and belong after the demo.
