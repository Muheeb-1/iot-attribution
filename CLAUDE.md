# IoT Incident Attribution - project memory for Claude Code

Final-year B.E. project (CSE Data Science, BIET Davangere, VTU 2022 scheme, team of four;
repo owner Muheeb-1, https://github.com/Muheeb-1/iot-attribution). It reads network traffic
from a small IoT lab, works out which device an attack STARTED from (method V5), and writes
a validated plain-English incident brief with response actions, shown on a Streamlit page.
Windows 11 laptop, VS Code, PowerShell, Python 3.12 in `.venv`.

## Status - verified 26 Oct 2026 against commit ee805cd ("Step 14")

- Steps 1-14 are done and pushed. The local folder matched GitHub HEAD exactly; only
  gitignored data (pcaps, converted runs, answer files) exists locally.
- Tests: 249 passed, 6 skipped. They need simulated runs in `data/` first (see Commands).
- Simulated benchmark reproduces exactly: hard V5 56.7% top-1 / 90% top-3, easy 100% / 100%.
- Real lab (12 captured attacks, `results/table_live.csv`): V5 11/12 top-1, 12/12 top-3.
  The miss is `live_batch_05`: laptop-i3 was blamed. (That is the OLD rule - see Step 18.)
- README.md is stale: its status list stops at Step 8.

## Status - 12 Nov 2026, Step 18 done

- Steps 15-17 (live engine, `src/live_capture.py`, live page) and Step 18 are done and pushed.
- rehearsal_01 (first hardware rehearsal) FAILED under the old rule: laptop-i3 named,
  esp32-02 never flagged. Step 18 fixed it with three switches, all default ON
  (`capture.MULTICAST_AS_BROADCAST`, `features.IAT_IGNORES_BROADCAST`,
  `detect.SKIP_REJOIN_MINUTES`); `evaluate.py --rules old` turns all three off.
- Measured old -> new: live batch 11/12 -> 12/12 (`results/table_live_fixed.csv`), laptop-i3
  flagged 2 -> 0 of 12; rehearsal_01 wrong -> esp32-02 at 100%, live alert 185 s after the
  attack; attack-free 24 sessions 1 -> 0 false alarms; simulated table1.csv byte-identical.
  Details and two caveats (laptop's DHCP INFORM counts as a "rejoin"; laptop not judged in
  7 of 10 baseline2 sessions): `docs/LIVE_PLAN.md` section 7, "12 Nov".
- Tests: 458 passed, 6 skipped (12 Nov, with all pcaps present). Data in `data/` (old-rule conversions) is
  untouched; new-rule numbers for real captures come from `--pcap-dir` re-conversion.
- Next: rehearsal_02 on hardware with `--origin esp32-03`, then Step 19 (incident report).

## Status - 12 Nov 2026, rehearsal_02 + Step 18b done

- rehearsal_02 (hardware, esp32-03, first session the Step 18 rules never saw): CORRECT,
  esp32-03 at 100%, live alert 3 min 54 s after the trigger. The trigger was first sent as
  `--run rehearsal_01` by mistake; both answer files were repaired by hand - DO NOT change
  `groundtruth/rehearsal_01.json` or `rehearsal_02.json`. `scenario.py` now refuses (before
  sending anything) when the answer file exists; `--force` replaces it.
- Step 18b: C3 counts a rejoin minute only for a DHCP broadcast sent from 0.0.0.0
  (`detect.REJOIN_NEEDS_UNASSIGNED`; new 9th flow column `src_unassigned`). Rules are now
  `--rules new|step18|old`. Measured (LIVE_PLAN section 7, "Step 18b"): 14/14 correct (12
  segments + both rehearsals); rejoin minutes only esp32-02 @11 in rehearsal_01; laptop never
  flagged; attack-free 0 false alarms, laptop not judged in 2 of 10 (was 7); table1.csv
  byte-identical. Step 18's tables kept as `*_step18.csv`.
- Step 19 (incident report): `src/incident.py` - eight sections built from the measurements
  (no LLM needed), CONTAINED check (90 s without a connection to the section-4
  destinations), `reports/<session>.html` (gitignored), SHA256SUMS.txt at STOP. Live page
  shows it + download; replay page has it in an expander. `template_brief` says "spread"
  only when >1 device is flagged. CONTAINED was tested only by replaying rehearsal_02 with
  the board's packets cut - the first real containment is the next hardware run.
- Next: Step 20 (fresh sessions, contain by hand, wait for CONTAINED), then Step 21.

## Status - 13 Nov 2026, Step 20a + fallback rung 3 + Step 22 prepared

- Step 20a: `live_session_01` on hardware (`--origin esp32-02`) is CORRECT - esp32-02 at
  100%, alert 3 min 40 s after the trigger, and the FIRST real containment (board powered
  off by hand): CONTAINED 90 s after the last beacon. Nothing odd. `evaluate.py` now has a
  `live_timing` table (`<out>_timing.csv`) that reads the live engine's own record + the
  trigger time; no existing output changes. Details: LIVE_PLAN section 7, "Step 20a".
- Fallback rung 3 FIXED (the old DEMO RISK): `src/reconvert.py` re-converts the 12
  `live_batch_*` and `rehearsal_01` captures under today's rules into new `lab_*` runs
  (meta `"replaces"`); `runs.replay_runs()` hides the replaced originals. The replay page's
  13 real captures now all name the right board at 100% (was 4/12 + rehearsal_01 wrong).
  Old files untouched; `--rules old`/`step18` still reproduce `table_live.csv` and the
  `*_step18.csv` tables byte-for-byte. Run `python -m src.reconvert` once on a machine with
  the pcaps (writes only gitignored `data/`).
- Step 22 PREPARED, NOT FLASHED: `firmware/sensor/sensor.ino` beacon now carries real
  stolen-looking data (id, MAC, IP, gateway, Wi-Fi NAME only, signal, broker, topics,
  uptime, heap, last 4 readings), JSON padded to 200 bytes, ROTATING part 1/3->2/3->3/3 so
  it stays one 200-byte connection every 30 s - detector inputs unchanged (no payload in
  `TSHARK_FIELDS`/`FLOW_COLUMNS`; confirmed on the live_session_01 replay and in
  `tests/test_step22.py`). `src/listener.py` prints each beacon as an "attacker received:"
  block + a per-board profile. Exact Arduino re-flash steps for esp32-02/03: LIVE_PLAN
  section 5, Step 22. Boards still run the OLD firmware until flashed tomorrow.
- Tests: full suite green with the new `test_step20.py` (replay list + live timings) and
  `test_step22.py` (listener + firmware shape). Do not re-run the boards' numbers yet.
- Next: re-flash tomorrow (Step 22 proper, re-measure from fresh captures), then Step 21
  (README + LIVE_DEMO.md) and the dress rehearsals.

## Now - final phase, approved 11 Nov 2026

- Deadline: working and rehearsed by Saturday 14 Nov, end of day. Saturday is rehearsal only.
- Steps 15-21 and their day-by-day order are in `docs/LIVE_PLAN.md` section 5 (version 3,
  12 Nov: Step 18 = rehearsal_01 fixes, Step 19 = incident report); the decisions
  already taken are in its section 2. Do not reopen them without asking Muheeb.
- Recorded for later, NOT to be started without asking: Step 22 realistic beacon payload
  (guide's request, needs re-flashing), Step 23 visual redesign of the dashboard.
- Priority order when time is short: a demo that cannot fail > features > polish. Keep the
  fallback ladder working at every commit (live capture -> `--replay` on the live page ->
  the existing replay dashboard).
- Muheeb is not a programmer by training: report results in plain English, give exact
  commands to paste, and say clearly when something needs an Administrator terminal or a
  hand on the hardware.

## Pipeline (change behaviour only with a before/after measurement)

pcap -> `src/capture.py` (tshark -> flow table; devices named by MAC)
-> `src/features.py` (7 numbers per device per 60 s window)
-> `src/detect.py` (robust z-score + IsolationForest; onset = 3 windows in a row > 4.0)
-> `src/attribute.py` (V5: causal graph, two-stage ranking, abstain below 15%)
-> `src/report.py` (pydantic brief, evidence validator, template fallback;
   `--provider local` = Ollama llama3.2:3b, `--provider cloud` = Gemini, key in API_KEY.env)
-> `dashboard/app.py` (replay mode; a run is picked from `data/`, there is no pcap upload).

Lab tools: `src/scenario.py` (one attack, writes the answer file), `src/run_attack.py`
(batch driver, `--split`), `src/listener.py` (beacon sink on :4444),
`firmware/sensor/sensor.ino`. Prototypes `sim.py` / `hard.py` are the source of the
published numbers and stay untouched.

## The lab, as measured from the captures

- Router: TP-Link Archer C6, 192.168.0.254. Master laptop (ASUS, MAC cc:28:aa:75:4e:bd,
  192.168.0.200) runs the MQTT broker and the beacon sink, is wired to the router, and is
  the capture point. Every past capture used interface
  `\Device\NPF_{D913DCC8-4269-4A52-9617-38FEDDBB418A}` - confirm with `dumpcap -D`.
- Active boards: esp32-02 (.160) and esp32-03 (.203). esp32-01 (.129) is in the
  inventory but was off in recent captures. laptop-i3 (.218) is the noisy innocent device
  (connect/disconnect loop to the broker every ~2 s): scored, never attacked. phone = background.
- Attack: MQTT "attack" on `ctrl/<board>` -> the board opens a ~200-byte TCP beacon to
  192.168.0.200:4444 every 30 s. "stop" clears it without a reboot.
- The capture point only sees traffic to/from the master laptop plus broadcast/multicast.
  That covers this attack; board-to-board Wi-Fi traffic would be invisible.
- Npcap is installed with AdminOnly=1: an unelevated dumpcap hangs silently. Capture needs
  an Administrator terminal or Wireshark's own GUI. Reading pcap FILES needs no admin.

## Rules that must not be broken

1. Nothing in `src/` may mention or read the answer folder except `evaluate.py`;
   `generate.py` and `scenario.py` may write it but read nothing. Enforced by
   `tests/test_no_groundtruth_leak.py` - every new `src/` module must pass it. The dashboard
   may read answers only after the analysis has finished, for the "reveal" tick.
2. Numbers are measured, never asserted. If a change can move a published figure, re-run
   the evaluation (simulated AND live sets) and report both rules side by side, the way
   Step 11 scored `REQUIRE_ONSET_ORDER`. Never quietly overwrite an old figure.
3. Live mode reuses the existing functions unchanged (`capture.read_packets`,
   `capture.build_flows`, `features.build_features`, `detect.detect`, `attribute.attribute`,
   `report.*`). There must never be a second implementation of the method.
4. Containment is recommended, never executed. The operator acts by hand; the engine only
   confirms from the traffic that the attack connections have stopped.
5. Never commit or print secrets: `API_KEY.env`, Wi-Fi credentials, raw pcaps.
6. Work in numbered steps (next is Step 19). Tests with the code. One commit per step with a
   detailed message (what, why, measured effect), then push. Ask before pushing if unsure.
7. A step is done only when the full test suite passes and, for live features, a recorded
   capture replayed through the live path gives the same verdict as the offline pipeline.
8. Explain decisions in plain English in docstrings, like the existing files do.

## Commands (PowerShell, repo root)

```
.venv\Scripts\activate
python -m src.generate --runs 30 ; python -m src.generate --runs 30 --easy   # test data
python -m pytest                                      # all pass, 6 skipped expected (was 458 + Step 20/22 tests)
python -m src.evaluate --runs 30                      # simulated table -> results/table1.csv
# real attacks, OLD rule (the published table_live.csv, from the saved runs):
python -m src.evaluate --rules old --prefix live_batch --label live --runs 12 --out results/table_live.csv
# real attacks, NEW rule (Step 18; re-converted from the raw captures):
python -m src.evaluate --prefix live_batch --label live-fixed --runs 12 --pcap-dir pcap/segments --out results/table_live_fixed.csv
python -m src.evaluate [--rules old|step18] --prefix rehearsal --label rehearsal --runs 2 --pcap-dir pcap/live --out results/table_rehearsal_fixed.csv
python -m src.evaluate [--rules old] --false-alarms pcap/baseline.pcapng pcap/baseline2.pcapng --out results/false_alarms_fixed.csv
# live sessions (Step 20): also writes <out>_timing.csv (to-detect / contained, needs the live meta + answer):
python -m src.evaluate --prefix live_session --label live-sessions --runs <N> --out results/table_live_sessions.csv
python -m src.reconvert                               # fallback rung 3: re-convert the real captures into lab_* runs (needs the pcaps)
python -m src.live --session <name> [--replay <pcap>] [--speed 20]   # live engine (Step 15)
python -m src.live_capture --session <name>          # ADMINISTRATOR terminal: the capture
python -m src.incident <run_id> [--pcap <file>] [--llm local|cloud]   # full report -> reports/<run_id>.html
python -m src.capture pcap\<file>.pcapng --run <run_id> --baseline 720
streamlit run dashboard/app.py
python -m src.listener                                # beacon sink, on the master laptop
python -m src.scenario --run <run_id> [--origin esp32-02]   # one attack, answer file written (refuses an existing one; --force)
```

## Known loose ends (not yet fixed)

- `validate_brief` checks that a timestamp exists in the evidence, not that it matches the
  connection ids cited beside it (found in Step 14).
- Firmware has the Wi-Fi credentials hardcoded in a tracked, public file. Deferred until
  after the demo (changing them means re-flashing both boards). Do not touch before then.
  (Step 22's beacon sends the Wi-Fi network NAME but never the password - still deferred.)
- (Fixed: the template's "spread to other devices" wording - Step 19. Step 18's rejoin rule
  catching the laptop's DHCP INFORM - Step 18b. the `capture.endpoint_name` multicast bug in Step 18; the stale "qwen3:4b"
  sidebar text and the missing provider choice in Step 17. The replay-page DEMO RISK - old-rule
  `live_batch_*`/`rehearsal_01` runs named the wrong board - Step 20a fallback rung 3: re-converted
  into `lab_*` runs by `src/reconvert.py`, the old files kept for `--rules old`.)
