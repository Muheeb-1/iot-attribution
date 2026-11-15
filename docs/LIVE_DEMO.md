# Live demo - the script for the judges

Version 2, 15 Nov 2026 (polish step P5), for the final build (tag `polish-p5`). Every time
below was measured in the hardware sessions of 12-13 Nov (rehearsal_02, live_session_01-07)
or in the polish-phase replays. Nothing here is a guess. If the demo does something this page
does not describe, say so plainly and use the fallback ladder (section 5).

**The whole session takes about 20 minutes:** 12 minutes of learning, then about 4 to the
alert, 1.5 to CONTAINED, and the stop. The learning part is not interesting to watch,
so **start the capture about 13 minutes before the judges sit down** (section 3). Use
those minutes for the slides or the Past sessions page.

---

## 1. One sentence to open with

> "This system watches the lab network live, learns what normal looks like, and when a
> device is attacked it tells you **which device the attack started from**, how sure it
> is, and exactly what to do - and then confirms from the traffic that you did it."

---

## 2. Before the day / 30 minutes before (checklist)

Tick every line. Each one is something that went wrong, or nearly did, in a real session.

- [ ] **Master laptop** (ASUS): on mains power, **sleep disabled** (Settings → System →
      Power → Screen and sleep → Never), wired to the router, **internet working** (for the
      AI summary; everything else works without it).
- [ ] **laptop-i3**: on mains power, sleep disabled, its **connect/disconnect loop
      running**. In live_session_02 the Enter key did not register and the loop never
      started. Check it in the Mosquitto window (terminal 1): laptop-i3 should connect
      and disconnect about every 2 seconds.
- [ ] **esp32-02 and esp32-03** powered and connected **before** the capture starts. The
      Mosquitto window shows both client ids connecting. Do not plug a board in during
      a session.
- [ ] The router is on and nothing else is being changed on the network.
- [ ] Pick the board you will attack (esp32-02 or esp32-03). Pick the session name: the
      live page shows the next free one while it is waiting (e.g. `live_session_08`).
      **Use the same name in all three commands** (engine, capture, scenario).
- [ ] Open `reports\live_session_07.pdf` (or `.html`) in a browser tab and leave it there.
      It is the last-resort fallback (rung 4). It is in the new design.
- [ ] `API_KEY.env` is in the repo folder (for `--llm cloud`). Ollama is **not** needed.

Every **ordinary** terminal starts with:

```powershell
cd "E:\Major Project\iot-attribution"
.venv\Scripts\activate
```

An **Administrator** terminal: Start menu → type `PowerShell` → right-click → *Run as
administrator*. Windows blocks the activate script there, so it needs one extra line first:

```powershell
cd "E:\Major Project\iot-attribution"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.venv\Scripts\activate
```

(`-Scope Process` changes it for this one window only.)

---

## 3. What to start, in what order

Six terminals. Start them in this order. `NN` = your session number, the same everywhere.
Put **terminal 2 (the attacker) beside the browser**, so the judges see both at once.

| # | terminal | command | what you should see |
|---|---|---|---|
| 1 | **Administrator** | `Stop-Service mosquitto` (only if the Windows service is running), then `cd "C:\Program Files\Mosquitto"` and `.\mosquitto -c "E:\T Softwares\Mosquitto\lab.config" -v`. Alternative: `& 'C:\Program Files\mosquitto\mosquitto.exe' -c lab\mosquitto_lab.conf -v` from the repo folder | the broker log; esp32-02, esp32-03 connected; laptop-i3 connecting/disconnecting every ~2 s |
| 2 | ordinary | `python -m src.listener` | "listening for beacons on 0.0.0.0:4444". This is **"the attacker"**: keep it visible beside the console |
| 3 | ordinary | `streamlit run dashboard/app.py` | browser opens on the **Live monitor**: "Waiting for a session" with the next free name. **Then open the sidebar (`>` at the top left) and click "Alert sound" off and on once.** A browser plays no sound until the page has been clicked (checked in Edge, 15 Nov). Close the sidebar again. The red band never depends on the sound. |
| 4 | ordinary | `python -m src.live --session live_session_NN --llm cloud` | the engine: one line per closed minute. (No key? It says so and uses the template wording.) |
| 5 | **Administrator** | `python -m src.live_capture --session live_session_NN` | the capture: "recording on ... (a new file every 10 s)", then a "recording N s, N files" line |
| 6 | ordinary | (keep it for the attack command) | |

**Start terminal 5 about 13 minutes before the judges arrive.** That minute is "C+0" below.

---

## 4. Minute by minute

`C` = capture started. `A` = the moment you press Enter on the attack command.

| when | the page shows | you do | you say |
|---|---|---|---|
| C+0 | blue band **"Learning normal behaviour"**, "Minute 1 of 12. Monitoring starts at hh:mm:ss." | nothing | (judges usually not here yet - slides or Past sessions) |
| C+0 to C+12 | each device lane says **"Learning"**; devices and packets counting up | **do not attack** - an attack during learning is learned as normal | "For twelve minutes it learns what normal looks like for every device - including this laptop, which is deliberately noisy." |
| C+12 (measured +12:09) | green band **"Monitoring 3 devices"**, "Baseline established at hh:mm:ss. No device is over the line."; every lane says **"Normal"** | in terminal 6: `python -m src.scenario --run live_session_NN --origin esp32-03` | "I am now sending one command that compromises one of these two boards. The system does not know which." |
| A+0:30 | nothing yet on the page | point at **terminal 2**: an "attacker received:" block - the board's MAC, IP, Wi-Fi name, readings | "That is the board leaking its data to an attacker, every 30 seconds. Small, quiet, regular - the way real malware calls home." |
| A+1 to A+3 | amber band **"Watching esp32-03"**, "1 of 3 minutes in a row over the line", then **"2 of 3 ... One more raises an incident."**; that board's lane shows red bars over the dashed line and says **"Watching 2 of 3"** | nothing | "One odd minute is not enough to accuse a device - this laptop has odd minutes all the time. It needs three in a row." |
| **A+3:16 to A+3:54** (measured) | red band, **ringing**: **"The attack started on esp32-03"**, state line "Incident, severity high", "Confidence 100%. No other device behaved abnormally. Alert raised at hh:mm:ss."; a quiet two-pip **tone** repeats; an **Acknowledge** button sits in the band. Under it the strip **"Not contained yet. Last connection to 192.168.0.200:4444 at ..."**. The right card becomes **"How it was found"**; below, the **Incident report**: incident number, severity, origin, confidence, **Analyst summary**, timeline, **attack techniques**, **what to do** | **click Acknowledge** (the ring and the tone stop; the band shows "Acknowledged hh:mm:ss" and the "to acknowledge" figure fills in) | "It names the board. Here is how it found it: a new destination, port 4444, every 30 seconds, 496 bytes - a place it never talked to while learning." |
| a few seconds after the alert | the Analyst summary's line turns green: **"Written by the AI analyst (gemini-3.6-flash). Every fact checked against the evidence."** (Before that it says "Template wording - the AI analyst is being asked.") | point at it | "A language model writes this summary - but only from facts we hand it, and every name, time and number is checked before it is shown. The verdict never comes from the model." |
| right after | "What to do": **Isolate esp32-03. Pull its power, or block MAC ... on the router.** | **unplug the attacked board's USB power** (the system recommends; a person acts) | "The system never acts by itself. It tells the operator exactly what to do - I am doing it now by hand." |
| about 90 s after the last beacon (measured 1 min 21 s to 2 min 14 s after the alert, incl. reaction time) | green band **"Contained at hh:mm:ss"**, "esp32-03 has made no connection to 192.168.0.200:4444 for 90 seconds."; the lane reads **"Offline, contained"**; "to contain" fills in; the "Isolate" step is ticked | click **Create PDF**, then **Download PDF** (a few seconds; Edge makes it) | "It waited 90 seconds of silence from that board and confirms from the traffic that the attack has stopped. Here is the report as a PDF." |
| after CONTAINED | | **terminal 5: Ctrl+C** (stops the capture; the engine makes its final pass and asks the AI once more, up to 25 s) | "Stopping the capture. Everything recorded is hashed - SHA-256 - so this is the evidence record." |
| a few seconds later | band "Session closed, contained", **"The attack started on esp32-03"**, "Final verdict from the whole capture."; note "Saved as data/live_session_NN.parquet"; **Download PDF** is offered straight away (the engine wrote `reports\live_session_NN.pdf`) | at the bottom open **"Lab validation"** and tick **"Compare with the recorded answer"** → **"Correct. The attack really did start on esp32-03."** | "Only now does it open the answer file the attack script wrote. It was right." |

If there is time, open **"Full technical detail (all eight sections)"** under the report: the
per-minute scores, what moved, the evidence connection ids, the SHA-256 list.

> **STOP THE CAPTURE BEFORE PLUGGING A CONTAINED BOARD BACK IN.**
> In live_session_05 the board was plugged back in before the capture was stopped. It
> rejoined the network 19 s after its last beacon, and that rejoin is in the report's
> technical detail (a DHCP request and an MQTT reconnection). CONTAINED was still genuine,
> because the reboot clears the attack. But the report then shows traffic the judges will ask
> about. Order: CONTAINED → Ctrl+C in terminal 5 → *then* plug the board in.

After the demo, plugging the board back in is enough: the reboot clears the attack flag.

---

## 5. If anything fails - the fallback ladder

Each rung was working at the last commit. Go down one rung at a time, and say so out loud:
"the live part has a problem, so I will show you the same page on a recording we made
on 13 November". Do not try to fix code in front of the judges.

### Rung 1 - live, small problems you can fix in under a minute

| symptom | do this |
|---|---|
| terminal 5 says **"This terminal is NOT running as Administrator"** | it refused before starting (it would otherwise hang silently). Open an Administrator PowerShell (with the `Set-ExecutionPolicy` line) and re-run the same command. Or use Wireshark's own window: Capture → Options → wired adapter (Ethernet) → Output tab → File `pcap\live\live_session_NN\ring.pcapng`, tick *Create a new file automatically* → *after 10 seconds* → Start. |
| `.venv\Scripts\activate` is refused in the Administrator window ("running scripts is disabled") | you skipped `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`. Type it, then activate again. |
| page stays on **"Waiting for the capture"** (or "Waiting for a session") | check terminal 5 is writing files, and that terminals 4 and 5 use **exactly** the same session name. |
| page shows **"The engine has not updated this page for ..."** | terminal 4 has stopped. Run the same `python -m src.live --session live_session_NN --llm cloud` again: it joins the running capture and re-reads every file. Nothing is lost. |
| no tone at the alert | the page was never clicked: open the sidebar and click "Alert sound" off and on. The red band and the Acknowledge button work without sound. |
| Analyst summary says **"Template wording - the AI analyst was not reachable."** | the internet or the key is not working. **Nothing else is affected**: say "the AI is offline, so the summary is the template's - built from the same measurements". |
| **Create PDF** gives "No PDF could be made on this computer" | click **Download HTML** and print it to PDF from the browser (Ctrl+P → Save as PDF). |
| **scenario.py refuses: answer file exists** | you typed a name that was already used. Re-type it with this session's name. Use `--force` **only** if you are sure the first trigger never went out. |
| **no "attacker received:" in terminal 2 within 60 s** of the attack | look at terminal 1: is the board connected, did the `ctrl/<board>` message arrive? If the trigger never reached the board, re-send with `--force`. If the board is not connected, **do not plug it in now** (a board joining mid-session is untested) - go to rung 2. |

### When to give up on rung 1

- No alert by **A+6 min** (the slowest measured was A+3:54): keep talking for two more
  minutes. Then go to rung 2.
- The page names the **wrong device**, abstains, or flags laptop-i3: **say so**. This is a
  measured system and that is a result. Show the evidence on the page, then go to rung 2 to
  show a normal run.

### Rung 2 - the same live page, driven by a recording (about 1.5 minutes)

Stop the live capture first (Ctrl+C in terminal 5; terminal 4 then finishes by itself). Then,
in terminal 4:

```powershell
python -m src.live --session replay_demo_01 --replay pcap\live\live_session_07.pcapng --speed 20 --llm cloud
```

The live page follows the newest session by itself. At speed 20 the 12-minute learning part
takes about 36 s, and the whole session about 1.5 minutes. Verified: esp32-03 named at
100%, the same alert and CONTAINED second as the real run, phases LEARNING → MONITORING →
INCIDENT → CONTAINED → STOPPED; with `--llm cloud` the AI summary passed (5.7 s at the alert,
5.0 s at the stop, 15 Nov). Things to know:
- the clock on the page shows the **recording's** times (19:17 to 19:35 on 13 Nov) - say so;
- the incident lasts only a few seconds at speed 20, so Acknowledge quickly; "to acknowledge"
  is your real reaction time;
- "Compare with the recorded answer" (in Lab validation) says "No answer file saved for this
  session", because the answer belongs to live_session_07. Say: "this is the recording of
  live_session_07; the board attacked was esp32-03".

A second replay needs a new name (`replay_demo_02`), or the same name with `--force`.

### Rung 3 - the Past sessions page (no live parts at all)

Top bar → **"Past sessions"**. It opens on the newest live session (live_session_07); or pick
live_session_03, or any `lab_batch_NN`, in the sidebar. The full analysis runs on the saved
traffic. The brief is written by the cloud model when `API_KEY.env` is there (checked, with
the template as fallback); if the internet is down and it hangs, pick **"Plain template"** in
the sidebar. At the bottom, open **"Lab validation"** and tick **"Compare with the recorded
answer"** → "Correct". Open the incident report in its expander. (Do not pick live_session_06:
it was aborted and has no attack.)

### Rung 4 - the saved report (no Python at all)

The browser tab with `reports\live_session_07.pdf` (or `.html`), opened in section 2. It is
the report of a real session in the final design, with real times: esp32-03, 100%, alert
19:33:27, contained 19:34:49. Re-created on 15 Nov from the saved session data with
`python -m src.incident live_session_07 --pdf` (template wording; every verdict and time
checked against the engine's own record of the day).

---

## 6. Judge Q&A - short, measured answers

**Why does it take about four minutes?**
Why about four minutes: the alert needs **three abnormal minutes in a row**. The minute in
which the attack starts is usually not abnormal yet: the command lands part-way through it,
and the first beacon comes 30 s later. So it is the end of the third full minute after that,
plus a few seconds to finish the capture file: 3 to 4 minutes. Measured: **3 min 16 s to
3 min 54 s in 7 hardware sessions.** It is a deliberate trade. In 12 recorded attacks the
innocent laptop had at least one abnormal minute in 9, two in a row in 1, and three in a row
in none. Alerting after one minute would have accused the wrong device most of the time.
Accusing the wrong device is worse than being late: someone would unplug a healthy machine.

**Why not just use anomaly detection?**
Anomaly detection tells you *something* is odd. It does not tell you *where it started*,
and the most anomalous device is often not the one attacked. Measured: "blame the
strangest-looking device" was right in **0 of 20 real attacks** (12 batch, 2 rehearsals, 6 live
sessions), because the noisy innocent laptop always looks strange. We do use anomaly
detection, as the first stage. V5 then adds the timing and the causal story: who went
abnormal first, who contacted whom, which new addresses they share. On the hard simulated
benchmark, where an attack spreads and hops through a server, "blame whoever went odd first"
is right 17% of the time and V5 56.7% (top three: 90%). Honestly: in our real lab the attack
stays on one board, so "first to go odd" is also right there. The story graph matters when
the attack spreads.

**Why is the attack so quiet?**
Because real malware is. A compromised IoT device that floods the network gets noticed
by anyone. One that sends 496 bytes every 30 seconds looks like a sensor reporting. That is
the hard case, so it is the one worth testing. Measured: "blame the biggest sender" was right
**0%** of the time on every real set - volume alone cannot find it. The system finds it by
**pattern**: a destination port (4444) the board never used while learning, extra
connections every minute, and machine-regular timing. It never reads the contents, so an
encrypted beacon would be found the same way. The payload is realistic (MAC, IP, Wi-Fi network
name, readings - never the password) and changed nothing on the wire: still one 496-byte
connection every 30 s.

**What can the capture point not see?**
The capture runs on the master laptop's wired port. It cannot see what it is not part of. It
sees everything to and from the master laptop (broker and beacon sink), plus every broadcast
and multicast. It **cannot see** board-to-board Wi-Fi traffic, or a board talking straight to
the internet through the router. Our attack beacons to the master laptop, so it is covered,
and the report states this limit. Future work: make the master laptop the Wi-Fi hotspot so
all traffic passes through it, and stage an attack that spreads between boards.

**Is the report written by an AI?**
No. The report - verdict, numbers, timeline, techniques, what to do - is built from the
measurements and is complete without any model. With `--llm cloud` a cloud model
(gemini-3.6-flash) writes only the short **Analyst summary**, from a handful of fixed facts
(device, time, address and port, interval, bytes). Every name, time and number in its text is
checked against those facts before it is shown; anything else is thrown away and the template
wording is shown, labelled as such. No packet contents and no Wi-Fi password are sent.

**Other questions that come up**

- *Does it block the attack?* No, by design. It recommends; a person acts. An automatic block on
  a wrong verdict would take a healthy device offline. It then **confirms** containment from the
  traffic (90 s of silence) - confirmed for real in all 6 live sessions.
- *What do the ATT&CK codes mean?* They name the standard technique the measured pattern is
  **consistent with** - T1571 non-standard port (4444), T1029 scheduled transfer (every 30 s),
  T1041 data leaving over the control channel (496 bytes out, 170 back). Rules, not guesses.
- *How is severity decided?* A fixed rule, printed on the report: critical if more than one
  device is flagged, high if one device has a new repeating destination, medium otherwise.
- *How do you know it is not tuned to these captures?* The three fixes of Step 18 were found on
  earlier captures. Everything recorded after them - rehearsal_02 and live sessions 01-07 - is
  an independent test: correct every time, at 100%. Old and new rules are both still scored.
- *False alarms?* 0 in 24 attack-free 25-minute sessions under today's rules (1 under the old
  rule). Caveat: in 2 of the 10 sessions with the laptop, the laptop had too little clean
  baseline to be judged.
- *What if the attack starts during learning?* It is learned as normal and not detected - a
  stated limit. That is why the attack waits for the green "Monitoring" band.
- *What if a session goes wrong?* It is kept and labelled, never deleted: session 02 (laptop
  loop off) and 05 (board back on early) are scored with notes; 06 (aborted, no attack) is shown
  as aborted and left out.
- *How would a real IDS differ?* See `docs/HOW_IT_WORKS.md`, section 9.
