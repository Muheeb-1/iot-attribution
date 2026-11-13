# IoT Incident Attribution

**In one sentence:** this project watches the network traffic of a small IoT lab,
works out *which device an attack started from*, and writes a plain-English
incident report with the response actions - while the capture is still running.

Final-year B.E. project, CSE (Data Science), BIET Davangere (VTU 2022 scheme),
team of four. Python 3.12 on Windows 11.

Status (13 Nov 2026): Steps 1-22 done. The live system has been tested on the real
lab hardware in 6 fresh attack sessions plus one rehearsal. It named the right board
at 100% confidence in all 7. The alert came 3 min 16 s to 3 min 54 s after the
attack started, and every containment was confirmed from the traffic. Step 23
(visual redesign) is recorded but not started. How to run the demo:
[`docs/LIVE_DEMO.md`](docs/LIVE_DEMO.md).

---

## Contents

1. [The problem, in plain English](#the-problem-in-plain-english)
2. [What this project does instead (method V5)](#what-this-project-does-instead)
3. [The lab](#the-lab)
4. [How it is put together](#how-it-is-put-together)
5. [Results](#results) - simulated, real lab (old vs new rules), live sessions
6. [The incident report, and why it can be trusted](#the-incident-report-and-why-it-can-be-trusted)
7. [Getting started](#getting-started)
8. [Running it](#running-it) - replay dashboard, live mode, scoring
9. [Rules this project does not break](#rules-this-project-does-not-break)
10. [Limits, stated honestly](#limits-stated-honestly)
11. [How it was built: Steps 1-22](#how-it-was-built-steps-1-22)

---

## The problem, in plain English

When something goes wrong on a network, lots of devices start behaving oddly at
once. The obvious question, "which one was hit **first**?", is surprisingly
hard, because:

* the noisiest device is usually a **victim** (or an innocent bystander), not the source;
* perfectly innocent devices have busy days too (backups, firmware updates, reconnects);
* the attacker may hop from device A to device B **through a shared server**,
  so there is no direct A→B traffic to point at.

So the naive answers ("blame whoever sent the most data", "blame whoever looks
strangest", "blame whoever went odd first") are wrong a lot of the time. On our
hard simulated benchmark the best of those standard approaches is right **17%**
of the time. On the real lab, "blame the strangest-looking device" was wrong in
**every one** of 20 real attacks (12 batch captures, 2 rehearsals, 6 live
sessions): the device that looks strangest is not the one that was attacked.

## What this project does instead

It reconstructs the *story*. For every device it asks: "if this device were
patient zero, how much of everything else that happened does that explain?"
The device whose story explains the most, that nothing else points at, and
that started earliest, is named as the origin.

That method is called **V5**. In outline:

1. **Features** - every device is summarised as 7 numbers per 60-second window
   (bytes out, bytes in, connections, distinct destinations, new outside
   destinations, lab devices contacted, timing regularity).
2. **Detection** - each device's first 12 minutes are learned as its "normal".
   After that, every minute is scored with a robust z-score plus an IsolationForest.
   A device is flagged only after **3 abnormal minutes in a row** (score > 4.0).
   That onset is the time it "went abnormal".
3. **Attribution** - a causal graph links devices whose abnormal behaviour could
   have caused each other: contact in the right order, or a shared never-before-seen
   indicator such as the same new address. Then a two-stage ranking names the
   origin. Below 15% confidence it **abstains** and hands over a shortlist of
   three instead of guessing.

On the hard benchmark V5 is right **56.7%** of the time first try and has the
true origin in its **top 3 90%** of the time; on the easy benchmark **100%**.
On the real lab, under today's rules, it has been right in every attack
recorded (see [Results](#results)).

## The lab

Everything below was measured from the captures, not taken from a datasheet.

| device | address | role |
|---|---|---|
| Router - TP-Link Archer C6 | 192.168.0.254 | the lab network |
| Master laptop (ASUS) | 192.168.0.200, wired | MQTT broker, beacon sink (port 4444), **capture point**, runs the engine and the dashboard |
| esp32-02, esp32-03 | .160, .203 (Wi-Fi) | sensor boards (temperature/humidity over MQTT); the attack targets |
| esp32-01 | .129 | in the inventory, off in recent captures |
| laptop-i3 | .218 (Wi-Fi) | the **noisy innocent device**: connects to and disconnects from the broker every ~2 s. Scored like every other device, never attacked |
| phone | - | background traffic |

**The attack.** An MQTT message `attack` on topic `ctrl/<board>` tells that
board's firmware (`firmware/sensor/sensor.ino`) to start beaconing. From then on it
opens one TCP connection to 192.168.0.200:4444 every 30 s. Each beacon is 496 bytes
on the wire and carries what malware on the board could really steal: id, MAC, IP,
gateway, Wi-Fi network *name* (never the password), signal, broker, topics, uptime,
free heap and the last four readings. The payload rotates through three parts so it
stays one ~200-byte message (Step 22). `stop` clears it without a reboot.
`src/scenario.py` sends the trigger and writes the answer file. `src/listener.py`
is the "attacker" receiving the beacons.

**What the capture point sees.** The master laptop is wired to the router, so it
sees all traffic to and from itself plus every broadcast/multicast. That covers
this attack, because the beacon comes to the master laptop. Board-to-board Wi-Fi
traffic, and traffic from a board straight to the internet, would be invisible.

## How it is put together

```
  pcap (Wireshark/dumpcap)   or   data/run_NNN.parquet (simulated incident)
        |
        v
  src/capture.py      tshark -> flow table (one row per connection; devices named by MAC)
        |
        v
  src/features.py     7 numbers per device per 60-second window
        |
        v
  src/detect.py       learn each device's "normal", find when it broke (3 minutes in a row)
        |
        v
  src/attribute.py    V5: build the story graph, rank the suspects, abstain if unsure
        |
        +--> src/incident.py   the 8-section incident report (deterministic, no LLM needed)
        +--> src/report.py     optional LLM wording, checked against the evidence
        |
        v
  dashboard/app.py         replay page: pick any saved run
  dashboard/live_page.py   live page: follows the session that is recording now
```

**Live mode** runs the *same* functions while the capture records:

```
 src/live_capture.py (Administrator)  -> pcap/live/<session>/ring_*.pcapng  (a new file every 10 s)
 src/live.py (the engine)             -> reads each FINISHED file; each time a minute closes,
                                         re-runs the unchanged pipeline on everything so far;
                                         writes pcap/live/<session>/state.json + reports/<session>.html
 dashboard/live_page.py               -> redraws from state.json every 3 s
```

Re-running everything instead of doing incremental maths means the live verdict
equals the offline verdict on the same packets *by construction*. One cycle takes
0.2-0.4 s. Only closed minutes are scored, so a half-finished minute can never
create or hide an alarm.

| File | What it is for |
|---|---|
| `src/windows.py` | The single helper that turns a timestamp into a 60-second window number. |
| `src/generate.py` | Invents realistic traffic plus a hidden attack (simulated benchmark, known answer). |
| `src/capture.py` | Real captures -> the same flow table the simulator writes. |
| `src/features.py`, `src/detect.py`, `src/attribute.py` | The method (above). |
| `src/report.py` | The incident brief: pydantic schema, evidence validator, template fallback; `--provider local` (Ollama `llama3.2:3b`) or `cloud` (Gemini). |
| `src/incident.py` | The 8-section incident report and the CONTAINED check. |
| `src/live.py`, `src/live_capture.py` | Live engine; ring capture (needs Administrator). |
| `src/scenario.py`, `src/run_attack.py`, `src/listener.py` | Lab tools: one attack + answer file; batch driver; beacon sink. |
| `src/evaluate.py` | Scores everything against the answers and the four baselines. The **only** reader of `groundtruth/`. |
| `src/reconvert.py` | Re-converts the old real captures under today's rules (fallback rung 3). |
| `firmware/sensor/sensor.ino` | ESP32 board firmware. `lab/mosquitto_lab.conf` - the lab broker. |
| `groundtruth/` | The answer files (gitignored). |
| `docs/LIVE_PLAN.md` | The live-phase plan, decisions, and every measurement (section 7). |
| `docs/LIVE_DEMO.md` | The demo script for the judges, with the fallback ladder and Q&A. |

## Results

Every number here is measured by `src/evaluate.py` and saved in `results/`. Where
a rule changed, the old and new rules are scored side by side on the same data,
and no old table has been overwritten.

"top-1" = the true origin was named first; "top-3" = it was in the first three.
The four baselines are the standard approaches V5 has to beat: B1 blame the biggest
sender, B2 blame the strangest-looking (highest anomaly score), B3 blame the busiest
(most connections), B4 blame whoever went abnormal first.

### 1. Simulated benchmark (30 runs each, `results/table1.csv`)

The prototype's numbers (`sim.py`, `hard.py`) reproduce exactly.

**Hard** - 12 devices, decoys, a stealthy attacker, 40% of hops relayed through a server:

| method | top-1 | top-3 | mean rank | abstained |
|---|---:|---:|---:|---:|
| B1 blame the biggest sender | 0% | 10% | 6.07 | - |
| B2 blame the strangest-looking | 10% | 47% | 4.10 | - |
| B3 blame the busiest | 3% | 10% | 5.63 | - |
| B4 blame whoever went odd first | 17% | 53% | 3.27 | - |
| V5, prototype indicator rule | 53.3% | 90% | 2.00 | 17% |
| **V5 attribution** (corrected rule) | **56.7%** | **90%** | **1.90** | 17% |

**Easy** - 7 devices, no decoys, no relayed hops:

| method | top-1 | top-3 | mean rank | abstained |
|---|---:|---:|---:|---:|
| B1 blame the biggest sender | 13% | 47% | 3.50 | - |
| B2 blame the strangest-looking | 10% | 43% | 3.57 | - |
| B3 blame the busiest | 13% | 83% | 3.13 | - |
| B4 blame whoever went odd first | 50% | 100% | 1.57 | - |
| V5, prototype indicator rule | 90% | 100% | 1.10 | 7% |
| **V5 attribution** (corrected rule) | **100%** | **100%** | **1.00** | 0% |

**The indicator-rule correction (Step 11).** The prototype demanded that the
*detected onsets* agree with the order of first contact before linking two devices
that shared a new address. That threw the evidence away in exactly the runs the
indicator exists to rescue: the ones where the detector was misled. Dropping that
test is the only change. It can only *add* links (enforced by a test):
hard top-1 53.3% → 56.7%, easy top-1 90% → 100%, easy abstentions 7% → 0%.

### 2. Real lab - the 12-attack batch (Step 13), old vs new rules

Twelve attacks on the real boards, recorded in one capture (`src/run_attack.py`),
cut into 12 runs. The first rehearsal on hardware (rehearsal_01) **failed** under
the old rule. The detector named laptop-i3, and the attacked board was never flagged.
Studying it gave three changes (Step 18), each a switch that can be turned back off:

* **C1** multicast and 255.255.255.255 are named "broadcast" (they had been
  counted as new destinations). This one was found on the 12 batch captures.
* **C2** the timing-regularity number ignores broadcast traffic (the laptop's
  regular 2-second loop made it flip-flop between "regular" and "irregular").
* **C3** a baseline minute in which a device (re)joined the network is not used as
  "normal" for that device. Step 18b narrowed this to DHCP sent from 0.0.0.0
  (a device with no address yet), so Windows' routine DHCP INFORM no longer counts.
  C2 and C3 were found on rehearsal_01.

`--rules old` = all off (as up to Step 17); `step18` = C1-C3; `new` = C1-C3 + 18b (today's default).

| set | measure | old | step18 | **new** |
|---|---|---:|---:|---:|
| 12 batch attacks | V5 top-1 | 11/12 (91.7%) | 12/12 | **12/12**, all at 100% |
| 12 batch attacks | B4 earliest onset top-1 | 91.7% | 91.7% | 100% |
| 12 batch attacks | B1 / B2 / B3 top-1 | 0% / 0% / 0% | 0% / 0% / 0% | 0% / 0% / 0% |
| 12 batch attacks | laptop-i3 wrongly flagged | 2 of 12 | 0 | 0 |
| 2 rehearsals | V5 top-1 | 1/2 (rehearsal_01 wrong, board never flagged) | 2/2 | **2/2** |
| 24 attack-free sessions (25 min each) | false alarms | 1 | 0 | **0** |
| attack-free, laptop present (10 sessions) | laptop not judged (too little clean baseline) | 2 | 7 | 2 |
| simulated `table1.csv` | - | - | byte-identical | byte-identical |

Files: `results/table_live.csv` (old, the originally published table),
`table_live_step18.csv`, `table_live_fixed.csv` (new); `table_rehearsal_old.csv`,
`_step18`, `_fixed`; `false_alarms_old.csv`, `_step18`, `_fixed`.
Every switch alone and in pairs is in `docs/LIVE_PLAN.md` section 7: only all
three together fix everything.

**Honest caveat:** C1-C3 were found on the very captures they improve. The
independent test is everything recorded after them: rehearsal_02 and the live
sessions below. All of them are correct.

### 3. Live sessions on hardware (Steps 20-22) - the independent test

Each session: start capture + engine, wait out the 12-minute baseline, send one
attack, wait for the alert, contain by hand (board unplugged), wait for CONTAINED,
stop. Nothing about the rules was changed after rehearsal_02. All times are the
lab laptop's clock (IST).

| session | origin | trigger | alert | to detect | CONTAINED | after alert | V5 | note |
|---|---|---|---|---:|---|---:|---|---|
| live_session_01 | esp32-02 | 11:26:49 | 11:30:29 | 3 min 40 s | 11:32:19 | 1 min 50 s | ✓ 100% | old firmware |
| live_session_02 | esp32-03 | 15:55:11 | 15:58:27 | 3 min 16 s | 16:00:41 | 2 min 14 s | ✓ 100% | **laptop loop off** |
| live_session_03 | esp32-02 | 17:12:13 | 17:16:08 | 3 min 54 s | 17:17:43 | 1 min 36 s | ✓ 100% | |
| live_session_04 | esp32-03 | 17:37:03 | 17:40:26 | 3 min 23 s | 17:42:03 | 1 min 37 s | ✓ 100% | |
| live_session_05 | esp32-02 | 18:44:06 | 18:47:53 | 3 min 47 s | 18:49:36 | 1 min 43 s | ✓ 100% | **board back on before STOP** |
| live_session_06 | - | - | - | - | - | - | not scored | **aborted**: stopped during baseline, no attack sent |
| live_session_07 | esp32-03 | 19:29:48 | 19:33:27 | 3 min 39 s | 19:34:49 | 1 min 21 s | ✓ 100% | |

(rehearsal_02, 12 Nov, esp32-03: also correct at 100%, alert 3 min 54 s after the trigger.)

| set | sessions | V5 top-1 | top-3 | abstained | B4 | B3 | B1 / B2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| all scored live sessions (`table_live_sessions.csv`) | 6 | **100%** | 100% | 0% | 100% | 17% | 0% / 0% |
| laptop loop on only (`table_live_sessions_loop_on.csv`) | 5 | **100%** | 100% | 0% | 100% | 0% | 0% / 0% |

What the notes mean (each is in `evaluate.SESSION_NOTES` / `ABORTED_SESSIONS`, and
printed beside the session in every table):

* **02 - laptop loop off.** laptop-i3's loop never started (22 laptop flows vs 564-614
  in the other sessions), so the main false-alarm risk was absent. Kept and scored.
  The second table leaves it out.
* **05 - board back on before STOP.** The operator powered esp32-02 back on 19 s
  after its last beacon (DHCP from 0.0.0.0 at 18:48:25, MQTT at 18:48:26). That was
  before CONTAINED was shown and before the capture was stopped. The reboot cleared
  the attack, so no beacon came back and CONTAINED is genuine. But the rejoin appears
  in the report's section 6 ("broadcast:67 (NEW) x1, broker:1883 x1"). Lesson, now
  in the demo script: **stop the capture before plugging a contained board back in.**
* **06 - aborted.** Stopped by the operator after 104 s of baseline. `scenario.py`
  refused a mistyped command (as designed), so no attack was sent: 0 beacons, no
  alert, no answer file. `evaluate.py` leaves it out of every scored set automatically.

Other things the files show:

* Every beacon in every session came from the attacked board: one connection every
  30.0 s, 496 bytes out. That is the same on the old (01) and new (02-07) firmware,
  because the detector never reads payloads.
* **"After alert"** includes the operator's reaction time plus the 90 s of silence
  the CONTAINED check waits for. In session 07 the last beacon (19:33:19) came 8.7 s
  *before* the alert was raised. The board was unplugged before its next beacon was
  due (19:33:49), so CONTAINED came 81 s after the alert.
* Replaying session 07's recording through the live path (`--replay`, speed 20) gives
  the same alert second (+968.9 s) and CONTAINED second (+1050.1 s) as the hardware run.

### Why the alert takes about four minutes

The trigger lands part-way through a minute, and the first beacon comes 30 s later,
so the minute the attack starts is usually not yet abnormal. Every later minute is.
The alert is raised when the **third** abnormal minute closes (plus 5 s grace and the
10-s capture file): **3 to 4 minutes** depending on where in the minute the attack
starts. Measured: 3 min 16 s to 3 min 54 s in 7 hardware sessions.

Three-in-a-row is deliberate. In the 12 batch attacks the innocent laptop had at
least one abnormal minute in 9 runs, two in a row in 1, and three in a row in none.
Alerting on one minute would have accused the wrong device in most runs.

## The incident report, and why it can be trusted

`src/incident.py` builds one report from the measurements alone, so **it is complete
without any language model and cannot fail in a demo**. It has eight sections:

1. **What happened** - one sentence ("spread" only if more than one device is flagged).
2. **When** - first unusual connection, each abnormal minute, alert time, time to detect.
3. **Where it started** - named device, confidence, full ranking, the devices that stayed normal.
4. **How** - the new behaviour, measured. On every real capture this comes out as exactly one
   pattern: `broker:4444`, every ~30 s, ~496 bytes.
5. **Why we believe it** - per-minute score against the threshold, what moved, evidence connection ids.
6. **Impact** - the affected device(s) and everything they talked to.
7. **What to do** - contain (exact MAC, IP, port), preserve evidence (session files + SHA-256),
   eradicate (re-flash, rotate credentials), recover, verify. **Recommended, never executed:**
   the operator acts by hand.
8. **What we are not sure about** - confidence in words, what the capture point cannot see.

**CONTAINED** is confirmed from the traffic: once the named device has made no connection
to the section-4 destination for 90 s, the page turns green with the time. Confirmed on real
containments in all 6 live sessions. The report is shown on the live page (with a download),
saved as `reports/<session>.html`, and in an expander on the replay page. At STOP a
`SHA256SUMS.txt` of the capture files is written as the evidence record.

**Optional LLM wording** (`src/report.py`). Language models invent things, so two guards
sit around it:

1. **The shape is forced** - a pydantic schema passed to the model; it cannot return free prose.
2. **The facts are checked** - every evidence id, device, address, port, timestamp and byte
   figure is checked against the evidence. Anything invented → regenerate once → if it fails
   again, the plain template is shown, marked `LLM_FALLBACK`. Nothing unverified is displayed.

Measured: over 20 hard simulated runs with `qwen3:4b` (Step 7, `results/report_validation.md`),
55% passed first time, 15% after one regeneration, and 30% fell back to the template. Step 14
compared the local `llama3.2:3b` (today's default) with cloud Gemini on two real captures
(`docs/brief_comparison.md`). Four briefs, **0 unbacked claims**. That comparison also shows
the limit: the validator stops *invention*, not *error*. When the analysis is wrong
(old-rule `live_batch_05`), a correct brief is a fluent account of the wrong device.

## Getting started

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m src.generate --runs 30 ; python -m src.generate --runs 30 --easy   # simulated runs
python -m pytest                                                             # full suite
```

The tests that need real captures or answer files skip cleanly when those are absent
(pcaps, `data/` and `groundtruth/` are gitignored). Also needed for real captures:
Wireshark (tshark, dumpcap, editcap, mergecap) with Npcap. For the lab: Mosquitto
and the Arduino IDE with the ESP32 core. Optional: Ollama with `llama3.2:3b` for local
LLM wording, or a Gemini key in `API_KEY.env` (never committed) for `--provider cloud`.

## Running it

**Replay dashboard** - works with nothing connected (no hardware, no internet, no LLM):

```powershell
streamlit run dashboard/app.py
```

Opens at <http://localhost:8501>. Pick a run, and the full analysis runs for real: the
network with the attack path in red, the timeline of when each device went abnormal, the
ranked suspects, the incident report, and a "reveal the true answer" tick. The sidebar's
"Live monitor" opens the live page. If the real captures have not been re-converted on
this machine, run `python -m src.reconvert` once (needs the pcaps).

**Live mode** - the full order, timings and fallbacks are in [`docs/LIVE_DEMO.md`](docs/LIVE_DEMO.md):

```powershell
python -m src.listener                               # beacon sink ("the attacker")
streamlit run dashboard/app.py                       # then "Live monitor" in the sidebar
python -m src.live --session live_session_08         # the engine (ordinary terminal)
python -m src.live_capture --session live_session_08 # the capture (ADMINISTRATOR terminal)
# ...12-minute baseline, page says "safe to launch the attack"...
python -m src.scenario --run live_session_08 --origin esp32-03
```

Without the lab, the same page can be driven by a recording:

```powershell
python -m src.live --session replay_demo_01 --replay pcap\live\live_session_07.pcapng --speed 20
```

**Scoring** (PowerShell, repo root):

```powershell
python -m src.evaluate --runs 30                     # simulated -> results/table1.csv
python -m src.evaluate --rules old --prefix live_batch --label live --runs 12 --out results/table_live.csv
python -m src.evaluate --prefix live_batch --label live-fixed --runs 12 --pcap-dir pcap/segments --out results/table_live_fixed.csv
python -m src.evaluate --prefix rehearsal --label rehearsal --runs 2 --pcap-dir pcap/live --out results/table_rehearsal_fixed.csv
python -m src.evaluate --false-alarms pcap/baseline.pcapng pcap/baseline2.pcapng --out results/false_alarms_fixed.csv
python -m src.evaluate --prefix live_session --label live-sessions --runs 7 --out results/table_live_sessions.csv
python -m src.evaluate --prefix live_session --label "live-sessions (laptop loop on)" --runs 7 --exclude live_session_02 --out results/table_live_sessions_loop_on.csv
python -m src.incident live_session_07               # rebuild one incident report -> reports/live_session_07.html
```

Add `--rules old` or `--rules step18` to any real-capture line to reproduce the earlier rule.

## Rules this project does not break

1. **No peeking at the answers.** Nothing in `src/` except `evaluate.py` may read
   `groundtruth/` (`generate.py` and `scenario.py` may write it and read nothing). Enforced by
   `tests/test_no_groundtruth_leak.py`. The dashboard reads an answer only after the analysis
   has finished, for the reveal tick.
2. **Numbers are measured, never asserted.** A change that can move a published figure is
   scored before and after, side by side, and old tables are kept.
3. **One implementation.** Live mode calls the same functions as offline analysis; there is no
   second copy of the method.
4. **Containment is recommended, never executed.** The operator acts; the engine only confirms.
5. **No secrets in the repository.** `API_KEY.env` and raw pcaps are gitignored.
   (Known loose end: the firmware still has the lab Wi-Fi credentials in a tracked file. It is
   deferred until after the demo, because changing them means re-flashing both boards.)

## Limits, stated honestly

* **About 4 minutes** from attack to confirmed alert, by design (3 one-minute windows).
* **A clean baseline is needed first** (12 minutes; 8 minimum). An attack during the baseline
  is learned as normal and will not be detected.
* **The capture point sees only the master laptop's traffic plus broadcasts.** Board-to-board
  Wi-Fi traffic is invisible. Future work: make the master laptop the Wi-Fi hotspot so all
  traffic passes through it, and stage an attack that spreads between boards.
* **The real-lab attack is one compromised board.** Attacks that spread across devices are
  measured on the simulated benchmark only (56.7% first guess, 90% top three on hard). On the
  one-board real lab, B4 "earliest onset" is also right every time; V5's story graph earns its
  keep when the attack spreads.
* **laptop-i3 is the main false-alarm risk.** Three abnormal minutes in a row would flag it.
  It has not happened in any session under today's rules: in every live session only the
  attacked board was flagged, including the 5 with the laptop's loop running.
* **The fixes were found on the captures they improve** (C1 on the batch, C2/C3 on rehearsal_01).
  rehearsal_02 and live sessions 01-07 are the independent check.
* **The brief can be confidently wrong when the method is wrong.** The validator is a
  transcription guard, not a correctness guarantee.

## How it was built: Steps 1-22

One commit per step, each with what changed, why, and the measured effect. The full plan
and measurements for Steps 15-22 are in `docs/LIVE_PLAN.md`.

| step | what | key result |
|---|---|---|
| Setup | venv, folders, git, requirements | |
| 1 | `src/windows.py` - the shared 60-second window helper; the groundtruth leak guard | |
| 2 | `src/generate.py` - simulated incidents, hard + easy, faithful port of the prototypes | |
| 3 | `src/features.py` - 7 numbers per device per window | |
| 4 | `src/detect.py` - robust z-score + IsolationForest, onset = 3 in a row | |
| 5 | `src/attribute.py` - method V5 | |
| 6 | `src/evaluate.py` - the results table | prototype numbers reproduce exactly |
| 7 | `src/report.py` - LLM brief, schema-forced, evidence-validated, template fallback | 30% fallback, measured |
| 8 | `dashboard/app.py` - Streamlit, offline replay | |
| 9 | `src/capture.py` - real captures -> the same flow table as the simulator | |
| 10 | `src/scenario.py`, `src/listener.py` - one real attack + its answer file | |
| 11 | Corrected indicator rule, scored side by side | hard 53.3% → 56.7%, easy 90% → 100% |
| 12 | `src/run_attack.py` batch driver; laptop-i3 a scored-but-unattackable candidate | |
| 13 | Score the real batch | 11/12 top-1 (old rule) |
| 14 | Cloud provider for the brief; local vs Gemini compared | 0 unbacked claims in 4 briefs |
| 15 | `src/live.py` - the live engine, unchanged pipeline while the capture records | live = offline 12/12 |
| 16 | 16a capture smoke test on the laptop; 16b `src/live_capture.py` | |
| 17 | `dashboard/live_page.py` - the live page | rehearsal_01 failed |
| 18 | The rehearsal_01 fixes C1-C3 (switches, old rule kept) | batch 11 → 12/12; false alarms 1 → 0 |
| 18b | C3 only for DHCP from 0.0.0.0; `scenario.py` refuses an existing answer file | 14/14; laptop never flagged |
| 19 | `src/incident.py` - the 8-section report; CONTAINED check | complete without an LLM |
| 20 | Fresh sessions on hardware; timing table; fallback rung 3 (`src/reconvert.py`) | first real containment |
| 21 | Sessions 01-07 scored; aborted-session handling; this README; `docs/LIVE_DEMO.md` | 6/6 top-1, 100% |
| 22 | Realistic stolen-data beacon (firmware re-flashed), readable listener | beacon unchanged on the wire |
| 23 | Visual redesign of the dashboard | recorded, **not started** |
