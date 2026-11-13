# Final phase: live attribution - the plan

Version 3, 12 Nov 2026. Audit done 26 Oct against commit ee805cd (Step 14); decisions taken
11 Nov. **Status: approved - build it.** Deadline: everything working and rehearsed by
**Saturday 14 Nov, end of day**. No new features on Saturday; Saturday is for rehearsal.

Changed in version 3 (12 Nov): the first hardware rehearsal (rehearsal_01) failed - the
alert named laptop-i3 and the attacked board was never flagged. The fix became **Step 18**
and was done first; the incident report moved to Step 19; the old Step 19 (multicast fix)
is now part of Step 18 (change C1). Measured before/after: section 7, "12 Nov".

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
2. **The multicast fix goes in, measured and reported both ways** (Step 18, change C1).
3. **One incident report, everything in one place**, built deterministically from the
   evidence so it cannot fail in a demo; LLM wording is optional polish on top (Step 19).
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
  **Done 12 Nov as rehearsal_01 - it failed** (laptop-i3 named; esp32-02 never flagged).

**Step 18 - the rehearsal_01 fixes (done 12 Nov, before anything else)**
Root cause, analysed on `pcap/live/rehearsal_01.pcapng` with its answer file:
(1) esp32-02 dropped off and rejoined the network at +660..+702 s (ARP retries, a DHCP
broadcast at +695 s, a new MQTT session), inside baseline minute 11; that minute
(6 connections) inflated its baseline spread, so the attack minutes (3 connections incl.
port 4444) scored 2.4 < 4.0. (2) laptop-i3 was flagged by a flip-flop: minutes with only
its 2-second loop read iat_reg ~19, minutes with broadcast/multicast chatter ~2-5; and
multicast addresses counted as extra destinations. Three changes, each a module switch,
default ON, so the old rule can still be scored (`python -m src.evaluate --rules old`):
- **C1** `capture.MULTICAST_AS_BROADCAST`: IPv4/IPv6 multicast and 255.255.255.255 are
  named "broadcast" (the `endpoint_name` bug). Acts at conversion, so scoring it needs
  `--pcap-dir` (re-convert from the raw captures; the saved runs are never overwritten).
- **C2** `features.IAT_IGNORES_BROADCAST`: iat_reg is computed only over the device's
  connections whose destination is not "broadcast". The other six features unchanged.
- **C3** `detect.SKIP_REJOIN_MINUTES`: a baseline minute in which a device sent a DHCP
  broadcast (dst "broadcast", dport 67) is left out of THAT device's baseline.
  MIN_BASELINE_WINDOWS (8) is kept and counts only the minutes actually used. The minutes
  left out are in `state.json` ("rejoins") and on the live page: "<device> rejoined the
  network at HH:MM:SS; that minute is not used as normal".
- Results, both ways (none overwritten): `results/table_live.csv` stays the old rule;
  `results/table_live_fixed.csv`, `results/table_rehearsal_old.csv` /
  `table_rehearsal_fixed.csv`, `results/false_alarms_old.csv` / `false_alarms_fixed.csv`.
- Tests: `tests/test_step18.py` (unit tests per change; acceptance on rehearsal_01, the 12
  segments and the 24 attack-free sessions, skipping when the pcaps are absent).

**Step 18b - C3 narrowed to real (re)joins (done 12 Nov, after rehearsal_02)**
- **C3b** `detect.REJOIN_NEEDS_UNASSIGNED`: a rejoin minute needs a DHCP broadcast sent from
  0.0.0.0 (a device with no address yet: DISCOVER/REQUEST). Windows' DHCP INFORM (type 8)
  is sent from the laptop's own address and no longer counts. The fact travels in a new,
  ninth flow-table column `src_unassigned` (after the original eight); tables without it
  (runs saved before 18b, simulated runs) have no rejoins. `--rules step18` turns only C3b
  off, so Step 18 as measured can still be reproduced. Measured: section 7, "Step 18b".
- Also: `src/scenario.py` refuses, before sending the trigger, when the answer file
  already exists; `--force` replaces it. Tests: `tests/test_step18b.py`.

### Friday 13 Nov

**Step 19 - the incident report (the centrepiece)**
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
- **Done 12 Nov** as `src/incident.py` (`build_incident` -> plain dict; `render_html`,
  `render_text`; `containment_status`; `python -m src.incident <run> [--pcap] [--llm]`).
  The live engine builds it every analysis cycle, runs the CONTAINED check every cycle on
  the newest traffic, writes `reports/<session>.html` and, at STOP, `SHA256SUMS.txt` in
  the session folder. The live page shows all eight sections plus a download button; the
  replay page offers the same report in an expander. `template_brief` no longer says
  "spread"/"check the other devices" when one device is flagged. Measured: section 7,
  "Step 19". Two choices made while building it: no-port flows (ARP/ICMP) are never a
  section-4 pattern; and "time to detect" in the report is measured from the first
  unusual CONNECTION (the report may not know the trigger time - that is evaluate.py's).
- (The old "Step 19 - the multicast fix, measured" is now Step 18, change C1. Its table is
  `results/table_live_fixed.csv`, not `table_live_multicast.csv`. The README must still say
  that C1 was found by studying the 12 captures, C2/C3 by studying rehearsal_01, and that
  the fresh sessions of Step 20 are their independent test.)

### Saturday 14 Nov

**Step 20 - fresh sessions on the real lab (minimum 3, target 6)**
- First: `rehearsal_02` with `--origin esp32-03` (the first session under the Step 18 rules).
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

### Later - recorded, NOT started (ask Muheeb before starting either)

**Step 22 - a realistic beacon payload (the guide's request)**
- Replace the ~200-byte test beacon with a payload that looks like real command-and-control
  traffic, of about the same size, so the measured byte counts and the 30-s rhythm stay
  comparable. Needs re-flashing both boards (`firmware/sensor/sensor.ino`) - do it together
  with the deferred Wi-Fi-credentials change, after the demo. Re-measure: the 12-capture
  numbers will not transfer automatically.
**Step 23 - a visual redesign of the dashboard**
- Layout, colours and typography of the replay and live pages. Presentation only: no change
  to what is computed or shown as evidence; the AppTest render tests must stay green.

## 6. state.json (minimum fields)

`session, phase, updated_epoch, capture_start_epoch, now_seconds, baseline_seconds,
baseline_remaining_seconds, packets, flows, devices{name: {latest_score, strikes, onset,
scores_by_window}}, threshold, onsets, ranking, named, abstained, confidence_percent, path,
edges, report{...section 5 Step 19...}, first_alert_epoch, contained_epoch,
verdict_changes[...], rejoins{name: [{window, seconds, epoch}]} (Step 18),
incident{status, what_happened, when, where, how, why, impact, playbook, unsure,
containment, wording}, containment{available, device, watching, last_seen_*, quiet_seconds,
contained, contained_*}, report_file, addresses (Step 19)`

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
  detected at all (0/12). Do not try it. (Step 18's C2 is narrower: it leaves broadcast
  out of iat_reg ONLY; the other six measurements still count it.)

12 Nov, Step 18 - the rehearsal_01 fixes, measured both ways (old = all three switches
OFF, new = all ON; the 12 captures and rehearsal_01 re-converted from the raw pcaps):

| set | old rule | new rule |
|---|---|---|
| simulated `results/table1.csv` | - | byte-identical (no broadcast in simulated runs) |
| live batch, 12 real attacks: V5 top-1 | 11/12 (`table_live.csv`) | 12/12, all at 100% (`table_live_fixed.csv`) |
| live batch: laptop-i3 flagged | 2 of 12 | 0 of 12 |
| rehearsal_01: verdict | laptop-i3 named, esp32-02 never flagged | esp32-02 named, 100% |
| rehearsal_01 replayed live: alert | 665 s after the attack, wrong device | 185 s after the attack (esp32-02) |
| attack-free: 24 sessions of 25 min, 12-min baseline | 1 false alarm (laptop-i3, baseline2 #7) | 0 |

- Reproduce: `python -m src.evaluate --rules old|new --prefix live_batch --runs 12
  --pcap-dir pcap/segments`, the same with `--prefix rehearsal --runs 1 --pcap-dir pcap/live`,
  and `python -m src.evaluate --rules old|new --false-alarms pcap/baseline.pcapng
  pcap/baseline2.pcapng`. `--rules old` reproduces `table_live.csv` byte-for-byte, from the
  saved runs and from the raw captures alike.
- Each change alone and in pairs (C1 C2 C3; batch correct / laptop flagged in batch /
  rehearsal_01 correct / false alarms in 24): 000 11/2/no/1; 100 12/0/no/0; 010 4/9/no/1;
  001 10/3/yes/1; 110 12/0/no/0; 101 12/1/yes/0; 011 5/8/yes/1; **111 12/0/yes/0**.
  Only all three together fix everything; C2 without C1 is much worse (the multicast
  addresses then still count as destinations and the laptop's timing reads regular).
- rehearsal_01 alert after 185 s, not 229-230 s: the trigger landed 0.2 s before a minute
  boundary, so the first attack minute was already abnormal (180 s + 5 s grace).
- **Caveat 1 - the laptop's DHCP messages.** C3 also catches laptop-i3: Windows sends a
  DHCP INFORM broadcast (type 8 - "send me network settings", not a rejoin) in 2-4 of its
  12 baseline minutes in every session. The flow table has no DHCP message type, so the
  rule cannot tell INFORM from a real join (esp32-02 sent DISCOVER/REQUEST, types 1/3).
  Effect: those laptop minutes are left out too, and the live page says "laptop-i3
  rejoined the network" for them, which is not literally true.
- **Caveat 2 - a device can drop below the 8-minute minimum.** In the attack-free set,
  laptop-i3 had fewer than 8 usable baseline minutes in 7 of the 10 baseline2 sessions
  it was in (old rule: 2), so it was not judged there - "0 false alarms" includes those.
  The one old false alarm (baseline2 session 7) is fixed with the laptop really judged
  (9 minutes used). In the 12 attacks and rehearsal_01 the laptop is judged every time.
- The fixes were found on the captures they improve (C1 on the 12, C2/C3 on rehearsal_01).
  rehearsal_02 onwards (Step 20) is the independent check.

12 Nov, rehearsal_02 on hardware (`--origin esp32-03`, the first session under the Step 18
rules): **correct** - esp32-03 named at 100%, live alert 3 min 54 s after the trigger
(17:27:44). The trigger was first sent as `--run rehearsal_01` by mistake and the
rehearsal_02 command 20 s later; both answer files were repaired by hand (rehearsal_02's start
is the first command). Replayed from the recording: the third abnormal minute closes 225.1 s
after the trigger and the alert is raised 229.6 s after it (on the laptop, live, 234.5 s: the
real capture writes a file every 10 s and the engine waits for it to finish).

12 Nov, Step 18b - C3 narrowed to rejoins from 0.0.0.0. Rules: old = all off; step18 = C1-C3
on (as measured above); new = C1-C3 + C3b. All from the raw captures (`--pcap-dir`).

| set | old | step18 | new (18b) |
|---|---|---|---|
| 12 segments + rehearsal_01 + rehearsal_02: V5 correct | 12/14 | 14/14 | **14/14**, all at 100% |
| rehearsal_02 alone (first independent test) | correct | correct | correct |
| rejoin minutes found (14 attack runs) | - | laptop-i3 in all 14 runs, esp32-02 @11 in rehearsal_01 | **only esp32-02 @11 in rehearsal_01** |
| laptop-i3 flagged / not judged (14 attack runs) | flagged in 3 | 0 / 0 | 0 / 0 |
| attack-free, 24 sessions: false alarms | 1 | 0 | **0** |
| attack-free: laptop present but not judged (of 10) | 2 | 7 | **2** (baseline2 #3, #5) |
| live batch, B4 earliest onset (plain detector) top-1 | - | 91.7% | 100% (live_batch_04) |
| simulated `results/table1.csv` | - | byte-identical | byte-identical |

- Tables: `results/table_live_fixed.csv`, `table_rehearsal_fixed.csv` and
  `false_alarms_fixed.csv` are now the 18b rule; Step 18's versions are kept, reproduced by
  `--rules step18`, as `table_live_step18.csv`, `table_rehearsal_step18.csv`,
  `false_alarms_step18.csv` (per-run rows identical to the Step 18 commit's `*_fixed` files,
  apart from the "rules" label). `table_rehearsal_old.csv` and `table_rehearsal_fixed.csv`
  now hold both rehearsals (2 runs).
- rehearsal_02, laptop-i3: no whole minute after the baseline over the line (highest 3.17
  in the live replay). Offline, the 8-second stub at the very end of the capture (window 24,
  scored only in the final pass after STOP) reads 53.9; one minute cannot make an onset.
- Caveat 1 above is resolved: the laptop's INFORM minutes are used as normal again and the
  page no longer says "laptop-i3 rejoined". Caveat 2 is back to the pre-Step-18 level (2 of
  10 sessions; old rule: 2).
- C3b was designed after looking at rehearsal_01/02 and the attack-free captures, like C3.
  The Step 20 sessions remain the independent check.

12 Nov, Step 19 - the incident report and CONTAINED, measured on the real captures:
- Section 4 on all 14 attack captures (12 segments + 2 rehearsals, new rules): exactly one
  pattern, for the named board: `broker:4444`, every 30.0 s (median gap), 496 bytes sent /
  170 back (median wire bytes), 8 packets. 10 connections in each segment, 27 in
  rehearsal_01, 12 in rehearsal_02. At rehearsal_02's live alert the report already reads
  "esp32-03 made N connections to broker:4444 every ~30 s, ~496 bytes each".
- rehearsal_02 time to detect, as the report states it: first beacon 17:28:34 -> alert
  raised 17:31:38 on hardware = 3 min 04 s (from the trigger: 3 min 54 s - that figure
  needs the trigger time and so belongs to evaluate.py, Step 20).
- CONTAINED: no recording contains a real containment yet. Tested by replaying rehearsal_02
  through the live path with esp32-03's packets removed 275 s after the trigger (as if its
  power had been pulled): INCIDENT -> CONTAINED exactly 90 s after its last beacon; the
  verdict stays esp32-03; phases WAITING, LEARNING, MONITORING, INCIDENT, CONTAINED, STOPPED.
- The live final report equals the offline report on the same packets (what happened,
  where, how, impact) for rehearsal_02. The report is complete with no language model.
- Not changed: every verdict, score and table (the report only reads them); table1.csv
  byte-identical (`detect.baseline_reference` is a pure extraction of robust_scores' maths).

Not testable off the laptop: live capture through Npcap (Step 16a, first day).

13 Nov, Step 20a - `live_session_01` on hardware (`--origin esp32-02`), the first session with
a REAL containment (board powered off by hand, not packets cut in a replay): **correct**.
- esp32-02 named at 100%; laptop-i3 never flagged; no rejoin minutes. Trigger 11:26:49,
  INCIDENT 11:30:29 = **3 min 40 s** to the alert (220.3 s; the third abnormal minute closed
  at 218.4 s). In line with the ~4 min-by-design figure (rehearsal_02 was 3 min 54 s).
- Containment: the operator pulled the board ~20 s after the alert (last beacon 11:30:49);
  CONTAINED shown 11:32:19, exactly 90 s after that last beacon. This is the first time the
  Step 19 CONTAINED check has confirmed a real containment - until now it was only tested by
  removing packets from a replay. The verdict stayed esp32-02; phases ran
  WAITING -> LEARNING -> MONITORING -> INCIDENT -> CONTAINED -> STOPPED.
- Nothing odd. Scored with the new `evaluate.py` timing table (below).
- New in evaluate.py (Step 20): `live_timing` reads the live engine's own record of what it
  did (meta "live": first_alert, containment) and the answer file's trigger time - the one
  place allowed both - and prints "to detect / contained / after alert" per session, saved
  as `<out>_timing.csv`. No existing output changes (only live-engine runs have a "live"
  block). Reproduce: `python -m src.evaluate --prefix live_session --label live-sessions
  --runs 1 --out results/table_live_sessions.csv`.

13 Nov, fallback rung 3 fixed - the replay page now names the right board on every real
capture. The twelve `live_batch_*` runs and `rehearsal_01` in `data/` were converted before
Step 18 (old naming rule, no `src_unassigned`); the replay page analyses with today's rules,
so it was right on only 4 of the 12 batch runs and blamed laptop-i3 for rehearsal_01.
- `src/reconvert.py` converts each raw capture again under today's rules into a NEW run id
  (`live_batch_NN` -> `lab_batch_NN`, `rehearsal_01` -> `lab_rehearsal_01`), writing
  `"replaces": "<old id>"` into the new meta. `runs.replay_runs()` lists the new runs and
  hides the ones they replace; the old files are untouched. Run once:
  `python -m src.reconvert` (writes only gitignored `data/`).
- Measured after: the replay page's real captures (13 of them: 12 lab_batch + lab_rehearsal_01,
  plus live_session_01, rehearsal_02, live_test_01/02) all name the right board at 100%,
  0 abstain, 0 wrong (was 4/12 correct + rehearsal_01 wrong). A re-converted run is scored
  against the answer of the run it replaces (`evaluate.load_answer_for_run`) - one answer
  file per attack, never a copy. `lab_batch_NN`'s per-run V5/confidence/flagged equal
  `table_live_fixed_per_run.csv` (same packets, same rules).
- Nothing published moved: `--rules old` still rebuilds `table_live.csv`, and `--rules
  step18 --pcap-dir` still rebuilds `table_live_step18.csv`, `table_rehearsal_step18.csv`
  and `false_alarms_step18.csv`, all byte-for-byte. The new prefix is `lab_`, deliberately
  not `live_batch`/`rehearsal`, so `--prefix` still scores exactly the old twelve.
  (`table_live_per_run.csv` on disk predates the Step-18 record columns and already differed
  before this change - not reproduced here and not relied on.)

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
