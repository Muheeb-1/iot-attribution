# Final phase: live attribution - the plan

Version 2, 11 Nov 2026. Audit done 26 Oct against commit ee805cd (Step 14); decisions taken
11 Nov. **Status: approved - build it.** Deadline: everything working and rehearsed by
**Saturday 14 Nov, end of day**. No new features on Saturday; Saturday is for rehearsal.

## 1. The goal in one paragraph

Today the pipeline runs after a capture has stopped: record in Wireshark, convert with
`src/capture.py`, pick the run in the dashboard. The final phase makes it run WHILE the
capture is running. The dashboard learns what normal looks like, watches every device,
raises an incident when a board is compromised, names the most likely origin, and shows
one complete incident report (what happened, when, where it started, how, why we believe
it, what to do) - without anyone stopping the capture. When the session ends it is saved
as an ordinary run, so the existing replay dashboard and `evaluate.py` can open and score it.

## 2. Decisions (taken 11 Nov - do not reopen without asking Muheeb)

1. **Containment is recommend-only.** The report tells the operator exactly what to do; the
   operator does it by hand (pull the board's power, or block its MAC on the router). The
   engine then CONFIRMS containment by watching the traffic. No button executes anything.
2. **The multicast fix goes in, measured and reported both ways** (Step 19).
3. **One incident report, everything in one place**, built deterministically from the
   evidence so it cannot fail in a demo; LLM wording is optional polish on top (Step 18).
4. **Fallback ladder - the demo must never depend on an untested part:**
   live capture -> if it misbehaves, the same live page driven by `--replay` of a recorded
   capture -> if the page misbehaves, the existing replay dashboard. Each rung is kept
   working at every step.
5. Wi-Fi credentials in the firmware, the academic report and slide alignment: after the
   demo. Not part of this plan.

## 3. Design

```
 dumpcap / Wireshark  -->  pcap/live/<session>/ring_00001_<time>.pcapng   (new file every 10 s)
 (Administrator)                         |
                                         v
 src/live.py   each FINISHED file -> capture.read_packets (same tshark fields as today)
               each closed 60 s window -> the UNCHANGED pipeline on everything so far:
               build_flows -> build_features (closed windows only) -> detect -> attribute
               -> incident report (deterministic; optional LLM wording in a background thread)
               writes pcap/live/<session>/state.json atomically (tmp file + os.replace)
                                         |
                                         v
 dashboard live page   st.fragment(run_every="3s") reads state.json and redraws
```

- Why packet capture and not MQTT: the attack beacon is raw TCP to port 4444 and never
  passes through the broker, so an MQTT subscriber would not see the attack at all. MQTT
  stays the lab's control channel (the attack trigger).
- Why files and not a pipe: Npcap here is AdminOnly, so capture must run elevated, but
  reading finished files needs no privileges. The engine and the dashboard run as a normal
  user, the same code path as offline conversion is used, and the session's files are the
  forensic record (merge them with `mergecap` afterwards).
- Why "re-run everything" instead of incremental maths: the live verdict equals the offline
  verdict on the same packets by construction. It is cheap: one cycle measured 0.2-0.4 s
  for a 17-minute session.
- The newest ring file is still being written and is never read. After STOP (or when no new
  file has appeared for 30 s) the last file is read and one final pass is made.
- Only CLOSED windows are scored (window end + 5 s grace), so a half-finished minute can
  never create or hide an onset.

## 4. Session lifecycle (what the operator sees)

| phase | when | page shows |
|---|---|---|
| WAITING | no ring file yet | "Start the capture" + the exact command |
| LEARNING | first 12 min (configurable, minimum 8 windows) | countdown, packets/devices seen |
| MONITORING | baseline done, no onset | green "safe to launch the attack"; per-device strike meter 0/3 |
| INCIDENT | first confirmed onset | red banner + the incident report; keeps updating |
| CONTAINED | incident, and the named device's attack connections have stopped for 90 s | green "contained at HH:MM:SS" on top of the report |
| STOPPED | capture stopped | final verdict = offline analysis; saved as data/<session>.parquet; reveal |

If another device goes abnormal later, the ranking and confidence change and the page says
so with a timestamp ("updated 14:32:05").

## 5. Steps and schedule

Each step: tests with the code, full suite green, one commit with a detailed message, push.
The days below are latest-by dates, not limits: as soon as a step is green, start the next.
If a step is not green by its day's end, stop and tell Muheeb - do not stack work on it.

### Wednesday 11 Nov

**Step 15 - `src/live.py`, the live engine (no UI, no hardware)**
- `LiveSession(folder, baseline_seconds=720, devices=capture.DEVICE_KINDS)`: ingest finished
  files, remember the first packet's epoch (wall clock for display), re-run the pipeline
  when a window closes, write `state.json` (section 6), and on stop save the session via
  `capture.save_run(..., baseline_seconds=...)` plus `capture_start_epoch` in the meta.
- CLI: `python -m src.live --session live_session_01 [--baseline 720] [--replay <pcap>]
  [--speed 20]`. `--replay` cuts a recorded pcap into 10-second files (editcap `-i 10`, or
  tshark if editcap is missing) and feeds them at the chosen speed - used by the tests and
  by rung 2 of the fallback ladder.
- Must not mention the answer folder (leak test). Must not import scenario.py.
- Acceptance tests (skip cleanly when `pcap/segments/` is absent, e.g. on a fresh clone):
  - each of the 12 `pcap/segments/live_batch_*.pcapng` through the live path gives final
    verdict, ranking and onsets identical to the offline pipeline;
  - the first INCIDENT appears exactly when the third over-threshold window closes
    (229-230 s after the trigger where the board trips first), never before the trigger;
  - the newest file is skipped until a newer one exists; STOP reads it; an empty or
    truncated file is reported, not crashed on;
  - state.json is always valid JSON.

**Step 16a - capture smoke test on the real laptop (15 minutes, do it today)**
- In an Administrator PowerShell: `dumpcap -D`, then a 60-second ring capture on the wired
  adapter into a scratch folder with `-b duration:10`. Confirm: 6-7 files appear, each
  finished file opens with tshark, and the boards' MACs are in them.
- This is the only part that could not be tested off the laptop. If it fails, say so the
  same day; the fallback is Wireshark's GUI writing the same multi-file capture.

### Thursday 12 Nov

**Step 16b - `src/live_capture.py`**
- Finds dumpcap (like `capture.find_tshark`), `--list` prints the interfaces, otherwise runs
  `dumpcap -i <iface> -b duration:10 -w pcap/live/<session>/ring.pcapng -q`. Says clearly
  when it is not elevated instead of hanging. Ctrl+C writes the STOP marker.

**Step 17 - the live dashboard page**
- New page beside the replay page (Streamlit multipage or a mode switch). Reuse
  `network_figure`, `timeline_figure`, `ranking_rows` from dashboard/app.py.
- Shows: phase banner and countdown; per-device strike meter ("2 of 3 minutes over the
  line"), labelled "watching" and never styled as an alert - see section 7 for why one
  abnormal minute must not name a device; score-per-minute chart with the threshold line; incident banner; the incident
  report; after STOP the "reveal" tick reading `groundtruth/<session>.json`.
- All times on the page are wall-clock (capture start + seconds), not seconds-from-start.
- Fix while here: stale "qwen3:4b" text; provider choice (template / local / cloud).
- Tests: plain-function tests plus a Streamlit AppTest rendering every phase from a
  fixture state.json with zero exceptions.
- End of day: first full live rehearsal on hardware (capture -> engine -> page -> attack).

### Friday 13 Nov

**Step 18 - the incident report (the centrepiece)**
One function builds a plain dict from run + detection + attribution; the page renders it
and writes `reports/<session>.html` (self-contained, print-to-PDF from the browser, plus a
download button). No new dependency. Sections:
1. **What happened** - one sentence. Wording must match the facts: say "spread" only when
   more than one device is flagged. (Today's template always says "and spread to other
   devices" and "check the other devices", which is wrong for a single-board attack - fix
   `template_brief` the same way and update its tests.)
2. **When** - first unusual connection, each abnormal minute, alert time, time-to-detect.
3. **Where it started** - named device, confidence, full ranking, and the devices that
   stayed normal (cleared).
4. **How** - the new behaviour, measured: for the named device, destination+port pairs seen
   3 or more times after the baseline and never during it, with count, first time, typical
   gap and size. On the real captures this yields exactly
   "broker:4444, 10 connections, every ~30 s, ~496 bytes" for the attacking board.
5. **Why we believe it** - per-minute score against the threshold, which measurements
   moved, and the evidence connection ids.
6. **Impact** - affected devices and what they could reach.
7. **What to do (playbook)** - contain now (exact MAC, IP, port), preserve evidence
   (session files + SHA-256), eradicate (re-flash, rotate credentials), recover (reconnect
   only after a clean baseline), verify (the CONTAINED check below).
8. **What we are not sure about** - confidence in words, what this capture point cannot see.
- CONTAINED check: after an incident, when the named device has made no connection to the
  section-4 destination(s) for 90 s, the state becomes CONTAINED with the time. A device
  that is unplugged goes silent and will still score as abnormal - that is expected; the
  page labels it "offline / contained", not "attacking".
- LLM wording is optional: if used, it goes through the existing validator and falls back
  to the deterministic text. The report must be complete with the LLM switched off.

**Step 19 - the multicast fix, measured**
- The bug: `capture.endpoint_name` means to name multicast traffic "broadcast" (see its own
  comment), but that check sits after `if ip: return ip`, so it never fires for IP packets.
  Windows name lookups from laptop-i3 (LLMNR, UDP 5355 to 224.0.0.252 / ff02::1:3) were
  therefore counted as "new outside addresses" - the cause of the one wrong verdict
  (live_batch_05) and of the confidence drop in live_batch_04.
- Add a switch (default ON) that names IPv4/IPv6 multicast and 255.255.255.255 "broadcast".
- Report both ways, never overwrite: `results/table_live.csv` stays as the original rule
  (11/12); add `results/table_live_multicast.csv` (expected 12/12), both reproducible from
  `pcap/segments/`. The README states that the fix was found by studying these captures and
  that the fresh sessions of Step 20 are its independent test.
- Simulated runs contain no multicast addresses, so table1.csv must not move - confirm it.

### Saturday 14 Nov

**Step 20 - fresh sessions on the real lab (minimum 3, target 6)**
- Alternate esp32-02 / esp32-03, laptop-i3 loop running, sleep disabled. Each: start
  capture + engine, wait for MONITORING, `python -m src.scenario --run live_session_NN`,
  wait for the alert, contain by hand, wait for CONTAINED, stop.
- Score with `python -m src.evaluate --prefix live_session --label live-sessions --runs N
  --out results/table_live_sessions.csv`. Time-to-detect needs the answer file, so that
  scoring lives in evaluate.py and nowhere else.

**Step 21 - README and `docs/LIVE_DEMO.md`**
- README brought up to date (Steps 9-21, all three result tables, live mode).
- LIVE_DEMO.md: the exact terminal order, what the page should show at each minute, what
  to do if something fails (the fallback ladder), and the measured answer to "why does the
  alert take about four minutes" (section 7).
- Two full dress rehearsals, then freeze. No code changes after the freeze.

## 6. state.json (minimum fields)

`session, phase, updated_epoch, capture_start_epoch, now_seconds, baseline_seconds,
baseline_remaining_seconds, packets, flows, devices{name: {latest_score, strikes, onset,
scores_by_window}}, threshold, onsets, ranking, named, abstained, confidence_percent, path,
edges, report{...section 5 Step 18...}, first_alert_epoch, contained_epoch,
verdict_changes[...]`

## 7. Evidence that this works (measured, not assumed)

26 Oct:
- Fresh clone: 249 passed, 6 skipped. Simulated and live tables reproduce exactly; the 12
  segments re-converted from raw pcap give identical flow tables to the saved runs (12/12).
- The 12 real attack captures replayed packet by packet as live streams through the
  unchanged pipeline, scoring only closed windows: final live verdict identical to offline
  in 12/12 (ranking and onsets too); alert 229-230 s after the trigger in 11/12; verdict at
  the moment of the alert = final verdict in 12/12.
- One cycle 0.2-0.4 s. Reading the capture as 10-second files gives exactly the same
  packets and flows as one file (6,121 packets checked).
- End-to-end prototype (ring files -> engine -> state.json -> Streamlit fragment page) on a
  real capture: incident at t = 969 s (trigger 735 s), brief passed the validator, page
  rendered with zero exceptions. Streamlit 1.40.2 has `st.fragment(run_every=...)`.

11 Nov, with the multicast fix applied on top:
- Same 12 live replays: 12/12 correct, every alert 229-230 s after the trigger, confidence
  100% at the alert and at the end, zero alerts before a trigger.
- Attack-free captures cut into 25-minute sessions: 0 false alarms in 10 sessions with
  laptop-i3 (was 1 in 10 under the original rule) and 0 in 14 without it.
- The section-4 "How" extraction gives the port-4444 pattern cleanly on all 11 runs where a
  board is named.

11 Nov, why the alert takes 3-4 minutes and why that rule stays (multicast fix applied):
- In all 12 real attacks the attacking board's minutes read `.XXXX`: the minute the attack
  starts is not abnormal (the trigger lands 15 s into it and the first beacon 30 s later),
  every later minute is. The alert comes when the third abnormal minute closes:
  45 s + 180 s + 5 s grace = 230 s. In general 3 to 4 minutes, depending on where in the
  minute the attack starts.
- The innocent laptop had at least one abnormal minute in 9 of the 12 runs, two in a row
  in 1, three in a row in none. Alerting on one minute would have pointed at the wrong
  device in most runs; `CONSECUTIVE = 3` is what prevents that. Do not lower it.
- The laptop's blips are minutes in which it sent no broadcast traffic, so its
  connect/disconnect loop looks perfectly regular (iat_reg ~19 against a baseline of ~4).
- Tested and rejected: leaving broadcast flows out of the per-minute measurements. The
  boards then have too little baseline traffic to be judged and the attack is not
  detected at all (0/12). Do not try it.

Not testable off the laptop: live capture through Npcap (Step 16a, first day).

## 8. Limits to state honestly

- About 4 minutes from attack to confirmed alert, by design (3 one-minute windows).
- Each session needs a clean baseline first (12 min default, 8 min minimum). An attack
  during the baseline is learned as normal and will not be detected.
- Capture on the master laptop sees only its own traffic plus broadcasts; board-to-board
  Wi-Fi traffic is invisible. Future work: make the master laptop the Wi-Fi hotspot
  (capture.py already knows its hotspot address, 192.168.137.1) so all traffic passes
  through it, and stage an attack that spreads from one board to the other.
- The real-lab attack is a single compromised board; attacks that spread across devices are
  measured on the simulated benchmark only (56.7% first guess, 90% top three on hard).
- laptop-i3 is the main false-alarm risk: three abnormal minutes in a row would flag it. If
  that happens after the board is flagged, the board is still named but confidence drops;
  if before, the verdict is wrong. Keep its loop running and sleep disabled, and report any
  such session as it happened.
- The multicast fix was found on the same 12 captures it improves; only the Step 20
  sessions are an independent check.
- The brief can be confidently wrong when the method is wrong; the validator is a
  transcription guard, not a correctness guarantee (docs/brief_comparison.md).
