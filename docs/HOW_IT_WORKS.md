# How it works - a guide for the viva

Written 15 Nov 2026 from the code at tag `polish-p5b`. Read this once, slowly, before the viva.
Every number in it was measured; where a number comes from is said next to it.

---

## 1. The project in four sentences

A small lab network has two ESP32 sensor boards, a noisy laptop, a phone and a router. We
record its traffic on the master laptop. When one board is attacked, the system works out
**which device the attack started from**, how sure it is, and what the operator should do.
Then it watches the traffic until the attack has stopped, and says so.

It does all of this **while the capture is still running**. The alert comes 3 to 4 minutes
after the attack starts.

---

## 2. The flow, in one picture

```
 the lab network
      |
      |  every packet to/from the master laptop, plus broadcasts
      v
 [ dumpcap ]  src/live_capture.py     a new capture file every 10 seconds
      |
      v
 [ capture ]  src/capture.py          packets -> connections ("flows"), devices named by MAC
      |
      v
 [ features ] src/features.py         7 numbers per device per minute
      |
      v
 [ detect ]   src/detect.py           "is this minute unusual FOR THIS DEVICE?"  score > 4.0
      |                               three unusual minutes in a row = the device is flagged
      v
 [ attribute ] src/attribute.py       "which flagged device STARTED it?"  (method V5)
      |
      v
 [ report ]   src/incident.py         the incident report + the CONTAINED check
      |        src/analyst.py          (optional) the AI's short summary, fact-checked
      v
 [ console ]  dashboard/live_page.py  the page the operator watches, redrawn every 3 s
```

`src/live.py` (the **engine**) is the box around the middle five steps. Every time a minute
of traffic is complete, it runs all of them again on everything recorded so far. It writes
the result to `pcap/live/<session>/state.json`. The page only reads that file.

---

## 3. What each terminal command starts

On the demo day there are six windows (`docs/LIVE_DEMO.md` has the exact order).

| Command | What it is | What it does |
|---|---|---|
| `.\mosquitto -c "E:\T Softwares\Mosquitto\lab.config" -v` (from `C:\Program Files\Mosquitto`) | The **MQTT broker** | The post office the boards report their readings to. The attack command also goes through it. Not part of our code. |
| `python -m src.listener` | **"The attacker"** | Listens on port 4444 of the master laptop. An attacked board sends it a small message every 30 s. It prints what the board leaks. |
| `streamlit run dashboard/app.py` | The **console** | Opens the browser page: Live monitor and Past sessions. |
| `python -m src.live --session live_session_NN --llm cloud` | The **engine** | Reads each finished capture file and re-runs the analysis every minute. Writes `state.json`, and the report at the end. `--llm cloud` adds the AI summary. |
| `python -m src.live_capture --session live_session_NN` | The **recorder** (Administrator) | Runs dumpcap on the wired adapter, with a new file every 10 s in `pcap/live/live_session_NN/`. It needs Administrator because Npcap is set to "admin only". |
| `python -m src.scenario --run live_session_NN --origin esp32-03` | The **attack** | Sends one MQTT "attack" command to one board, and writes the answer file (`groundtruth/live_session_NN.json`). |

Other commands you may be asked about:

| Command | What it does |
|---|---|
| `python -m src.live --session x --replay pcap\live\live_session_07.pcapng --speed 20` | Plays a recorded session through the same engine and the same page, 20 times faster. No hardware needed. |
| `python -m src.incident live_session_07 --pdf` | Rebuilds the incident report for a saved session, as HTML and PDF. |
| `python -m src.evaluate ...` | Scores the method against the answer files. It is the **only** program allowed to open them. |
| `python -m src.generate --runs 30` | Makes simulated incidents with a known answer (the benchmark). |
| `python -m pytest` | Runs all the tests (720 passed, 6 skipped at P5b). |

---

## 4. Each file in one line

**The method** (the same code runs in live mode, in replay mode and in the scoring)
- `src/windows.py` - the one place that turns a timestamp into a minute number.
- `src/capture.py` - reads a capture with tshark and turns packets into connections; names each device by its MAC address.
- `src/features.py` - turns one device's connections in one minute into 7 numbers.
- `src/detect.py` - learns each device's normal during the first 12 minutes, scores every later minute, and flags a device after 3 unusual minutes in a row.
- `src/attribute.py` - method V5: builds the "who could have caused whom" graph and ranks the suspects; it abstains when the top two are too close.
- `src/runs.py` - finds and loads a saved run from `data/`.

**Live mode**
- `src/live_capture.py` - starts dumpcap (Administrator), with a new file every 10 s.
- `src/live.py` - the engine: reads finished files, re-runs the method each minute, decides the phase, writes `state.json`, the report and the PDF.
- `src/incident.py` - the incident report (8 sections plus the designed 2-page version), the CONTAINED check, severity, ATT&CK techniques, and the PDF via Edge.
- `src/analyst.py` - asks the cloud AI for a short summary and checks it against the facts before it is shown.
- `src/report.py` - the older "brief", plus the fact checker (`validate_brief`) that the analyst also uses.

**The console**
- `dashboard/app.py` - the app's entry point and the Past sessions page (any saved run).
- `dashboard/live_page.py` - the Live monitor: reads `state.json` every 3 s; the Acknowledge button and the alert tone.
- `dashboard/theme.py` - the look: colours, the status band, the device lanes, the report cards.

**The lab tools**
- `src/scenario.py` - one attack, and the answer file.
- `src/run_attack.py` - a batch of attacks in one long capture (Step 13).
- `src/listener.py` - "the attacker": receives the beacons and prints them.
- `firmware/sensor/sensor.ino` - the ESP32 program: sends its readings over MQTT; on "attack", a 200-byte beacon every 30 s; "stop" ends it.
- `lab/mosquitto_lab.conf` - a broker configuration for the lab.

**Scoring and data**
- `src/evaluate.py` - marks the method against the answer files and four simple baselines.
- `src/generate.py` - the simulated benchmark (traffic with a hidden attack and a known answer).
- `src/reconvert.py` - re-converts the old real captures under today's rules.
- `sim.py`, `hard.py` - the original prototypes the published simulated numbers come from (never changed).

---

## 5. Detection and attribution are two different questions

**Detection asks: "Is this device behaving unusually right now?"** Every device is compared
only with **its own** normal, learned in the first 12 minutes. The noisy laptop is judged
against the noisy laptop, a quiet board against a quiet board. Each minute, each device gets 7
numbers:
- bytes sent and received
- number of connections, and different destinations
- new outside addresses, and connections to other lab devices
- how machine-regular the timing is

Each number is turned into "how far from this device's usual", using the median and the MAD
instead of the mean and standard deviation. That way one strange minute during learning
cannot hide a later attack. The numbers are weighted by how strongly they suggest a
compromise (a new outside address counts most, plain volume least), and a second opinion
(an Isolation Forest) looks at all seven together. A minute scoring over **4.0** is unusual.
**Three unusual minutes in a row** flag the device.

Why three? In 12 recorded attacks, the innocent laptop had at least one unusual minute in 9
of them, two in a row in 1, and three in a row in none. Alerting on one minute would have
blamed the wrong device most of the time.

**Attribution asks: "Of the flagged devices, which one did the attack START from?"** The
obvious answer, "whoever went odd first", is right only 17% of the time on the hard
simulated benchmark. An innocent device doing a backup often goes odd first. So V5 scores
**stories**: for each suspect, "if this were patient zero, how much of what followed would
it explain?" It draws an arrow from one device to another only when there is evidence:
- a real connection between them, in the right order
- a hop through the same outside host
- both devices contacting the same new address that neither had ever used before

It picks a shortlist of three by the whole story, then picks the winner by the shared new
addresses. If the top two are within 15%, it **abstains** and shows the shortlist instead of
guessing.

In our real lab the attack stays on one board, so "first to go odd" is also right there. The
story graph matters when an attack spreads, as in the simulated benchmark.

---

## 6. How the engine cannot know the answer

The attack script (`src/scenario.py`) writes the answer to `groundtruth/live_session_NN.json`.
If the engine could read that file, every result would be fake. Four things prevent it:

1. **A test reads the source code.** `tests/test_no_groundtruth_leak.py` fails if any file
   in `src/` other than `evaluate.py` even mentions the answer folder. `scenario.py` and
   `generate.py` may write answers but may not read any file at all.
2. **The engine only sees packets.** Its input is capture files: no file names that give
   anything away, no message contents (no payload field is read).
3. **The page opens the answer only after STOP.** "Compare with the recorded answer" (in Lab
   validation) works only when the session is finished, after the verdict is final.
4. **Replays give the same answer.** Replaying a recorded session gives the same device,
   onsets, alert second and CONTAINED second as on the day. `tests/test_polish_invariant.py`
   checks this after every change.

---

## 7. What the AI does, and what it does not do

**What it does.** With `--llm cloud`, when the alert is raised, the engine asks a cloud model
(`gemini-3.6-flash`) for a short "Analyst summary" in plain English: at most 4 sentences
(650 characters). The summary covers:
- what the device did
- what that pattern **usually** means: a small, same-size message on a fixed timer to a new
  address is the typical sign of a compromised device checking in with a server someone else
  controls
- why it matters: whoever receives the messages could collect data or send commands
- whether any other device changed
- one thing to check next

It runs in the background, with a limit of 25 s and one retry. If the server says "too many
requests" (HTTP 429), the retry waits 5 s first. It is asked once more when the session stops,
and once more if another device is flagged later. So a session makes 2 calls, minutes apart.

Measured the way a session calls (6 calls, one a minute, 15 Nov): **6 of 6 passed the fact
check, 1.6 to 5.2 s each.** An earlier, looser version passed 7 of 10 rapid calls. The 3
failures were the server refusing calls made seconds apart. That version also stacked
hedges ("may likely"), which the checker now refuses.

**What it is given.** Only facts that do not change minute to minute:
- the device and its address
- the time of its first unusual connection
- the destination address and port
- how often it connected, and the bytes sent and received each time
- whether the timing is machine-regular, and whether any other device was flagged

It gets no packet contents and no Wi-Fi password.

**How it is checked.** Before anything is shown, the answer goes through the project's fact
checker. Every device name, time, port and byte figure in it must be one of the facts it was
given. Running counts are refused, because they would be out of date a minute later. Claims
the measurements cannot show (passwords, stolen data, a named attacker) are refused too, and
so are two hedges stacked together ("may likely"). The interpretation is always worded as
"usually", "likely" or "consistent with", never as proven.

If the internet is down, the page and the report say "Template wording - the AI analyst was
not reachable". If the answer fails the check twice, they say "...did not pass the evidence
check". Either way they show the sentences built from the measurements.

**What it never does.** It does not detect, rank, decide the severity, choose the playbook
or contain anything. The verdict, every number and every recommended step come from the
code above. Without the AI the report is complete. The AI only words, and explains, the
summary.

---

## 8. The report and "CONTAINED"

At the alert the page shows the incident report, and the engine saves it as
`reports/<session>.html` and `.pdf` when the session stops. It contains:
- **key facts:** the incident number, severity, origin device and confidence
- **the summary,** and a **timeline:** baseline established, first unusual connection,
  alert, acknowledged, contained
- **ATT&CK techniques** the pattern is *consistent with:* non-standard port, scheduled
  transfer, data out over the control channel
- **what to do,** with the exact MAC and address

The full 8 technical sections are underneath.

**Severity** is a fixed rule: critical if more than one device is flagged, high if one
device has a new repeating destination, medium otherwise.

**The system never blocks anything.** A person pulls the board's power. The engine then
watches for the attack's connections. After **90 seconds with none** (three missed beacons)
it says "Contained at hh:mm:ss". This was confirmed for real in all 6 live sessions.

---

## 9. A real 24x7 IDS compared with this prototype

| | This prototype | A real intrusion detection system |
|---|---|---|
| Where it listens | One laptop's wired port: traffic to/from that laptop, plus broadcasts | Mirror ports or taps on every switch, the Wi-Fi controller, the internet edge |
| How long | One session of ~20 minutes, with a fresh 12-minute baseline each time | Always on; the baseline rolls forward and is relearned continuously |
| Attacks | One kind (a beacon from one board), staged by us | Many kinds; unknown; often several at once |
| What it reads | Only the shape of traffic (sizes, timing, destinations) | Shape plus signatures, DNS, TLS fingerprints, threat-intelligence lists |
| Response | Recommends; a person acts | Usually also recommends; automatic blocking only for very sure cases |
| Scale | 5 devices | Thousands, with alert triage and a team on shifts |

**What production would need:**
1. **See all the traffic.** Make the gateway or a switch mirror port the capture point. Today
   board-to-board Wi-Fi traffic is invisible.
2. **A rolling baseline**, so it can run for weeks, with planned "relearn" periods and
   protection against an attacker slowly teaching it a new normal.
3. **Incremental processing.** Re-running everything each minute is fine for 20 minutes and
   5 devices, not for a week and 1,000 devices.
4. **A device inventory that updates itself.** Today devices are named from a fixed MAC table.
5. **Alert handling:** a queue, assignment, escalation, and links to a SIEM and a ticketing system.
6. **Security of the system itself:** access control on the console, signed evidence,
   protected storage, and an audit log.
7. **More attack types tested**, including one that spreads between boards, and a measured
   false-alarm rate over days, not 24 sessions.
8. **The AI part** with a contract for data handling, or a model run locally on a capable
   server (our laptop took 45+ minutes per answer locally).

---

## 10. Numbers to remember

| What | Result | Where from |
|---|---|---|
| Live hardware sessions | 6 of 6 named the right board, at 100% | `results/table_live_sessions.csv` |
| Alert after the attack started | 3 min 16 s to 3 min 54 s | live sessions + rehearsal_02 |
| Contained after the alert | 1 min 21 s to 2 min 14 s, including the person's reaction | same |
| Real 12-attack batch | 12 of 12 (old rule 11 of 12) | `results/table_live_fixed.csv` |
| False alarms | 0 in 24 attack-free 25-minute sessions (old rule: 1) | `results/false_alarms_fixed.csv` |
| Hard simulated benchmark | V5 56.7% top-1, 90% top-3; "first to go odd" 17% | `results/table1.csv` |
| "Blame the biggest sender" on real attacks | 0% | same tables |
| AI summary | gemini-3.6-flash: 6 of 6 passed the fact check, 1.6-5.2 s each (one call a minute, as in a session) | P5b measurement |

---

## 11. Three questions you will probably be asked

**"Isn't this just anomaly detection?"** Anomaly detection is the first stage. It says
*something* is odd. Our contribution is the second stage: *where it started*. On real attacks,
"blame the strangest device" was right 0 times in 20, because the noisy laptop always looks
strange.

**"Why does it take four minutes?"** It waits for three unusual minutes in a row, on purpose.
Blaming the wrong device is worse than being late: someone would unplug a healthy machine.

**"What if the AI makes something up?"** It cannot get past the checker. Every name, time and
number in its text must be one of the facts it was given, or the text is thrown away and the
template is shown. And the AI never decides anything. It only words a summary of what the
code already found.
