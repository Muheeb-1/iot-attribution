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
  The miss is `live_batch_05`: laptop-i3 was blamed.
- README.md is stale: its status list stops at Step 8.
- NOT built yet: live (real-time) attribution. That is the final phase. Before any work on
  it, read `docs/LIVE_PLAN.md` in full and follow it.

## Now - final phase, approved 11 Nov 2026

- Deadline: working and rehearsed by Saturday 14 Nov, end of day. Saturday is rehearsal only.
- Steps 15-21 and their day-by-day order are in `docs/LIVE_PLAN.md` section 5; the decisions
  already taken are in its section 2. Do not reopen them without asking Muheeb.
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
6. Work in numbered steps (next is Step 15). Tests with the code. One commit per step with a
   detailed message (what, why, measured effect), then push. Ask before pushing if unsure.
7. A step is done only when the full test suite passes and, for live features, a recorded
   capture replayed through the live path gives the same verdict as the offline pipeline.
8. Explain decisions in plain English in docstrings, like the existing files do.

## Commands (PowerShell, repo root)

```
.venv\Scripts\activate
python -m src.generate --runs 30 ; python -m src.generate --runs 30 --easy   # test data
python -m pytest                                      # 249 passed, 6 skipped expected
python -m src.evaluate --runs 30                      # simulated table -> results/table1.csv
python -m src.evaluate --prefix live_batch --label live --runs 12 --out results/table_live.csv
python -m src.capture pcap\<file>.pcapng --run <run_id> --baseline 720
streamlit run dashboard/app.py
python -m src.listener                                # beacon sink, on the master laptop
python -m src.scenario --run <run_id> [--origin esp32-02]   # one attack, answer file written
```

## Known loose ends (not yet fixed)

- Dashboard sidebar still says "qwen3:4b"; the local model is llama3.2:3b, and the page
  cannot select the cloud provider.
- `validate_brief` checks that a timestamp exists in the evidence, not that it matches the
  connection ids cited beside it (found in Step 14).
- Firmware has the Wi-Fi credentials hardcoded in a tracked, public file. Deferred until
  after the demo (changing them means re-flashing both boards). Do not touch before then.
- `report.template_brief` always says the attack "spread to other devices", even when one
  device is flagged (10 of the 12 real runs). Fixed in Step 18.
- `capture.endpoint_name`: the multicast-is-broadcast check sits after `if ip: return ip`
  and never fires for IP packets. Fixed, as a measured switch, in Step 19.
