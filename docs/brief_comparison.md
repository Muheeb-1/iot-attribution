# Incident briefs: Gemini vs. the local fallback

Four incident briefs over two real captured runs, one pair per provider, each
checked claim by claim against the evidence pack that produced it. Generated
2026-09-14 against the twelve-run live batch of Step 13.

## What this layer actually guarantees

The report layer is an **evidence-validated transcription guard**. Every brief is
forced into a fixed schema at generation time, and then every identifier, port,
timestamp and byte figure in it is checked against the evidence pack before
anything is shown. A brief that names a device that does not exist, or cites a
connection id that was never issued, is rejected and regenerated once; if it
fails twice the model is abandoned and a plain template is used, marked
`LLM_FALLBACK`.

**It bounds invention. It does not bound error.** The validator's third rule
requires the brief to match the analysis: the named device and the confidence
figure must be transcribed exactly, not adjusted. So when the attribution is
wrong, a *correct* brief is a fluent, well-sourced account of the wrong device.
That is not a defect in the guard - it is the guard working as designed, and
`live_batch_05` below is what it looks like.

## The two runs

| run | true origin | analysis named | confidence | V5 rank of true origin |
|---|---|---|---|---|
| `live_batch_01` | esp32-02 | esp32-02 | 100% (high) | 1 - clean win |
| `live_batch_05` | esp32-02 | **laptop-i3** | 28% (medium) | 2 - the one miss in twelve |

`live_batch_05` is the single run in the batch where V5 does not put the true
origin first. laptop-i3 - the noisy innocent laptop promoted to a scored
candidate in Step 12 - went abnormal at 00:12:00, one minute before esp32-02 at
00:13:00, and the earliest-onset rule took the bait.

## Results

| run | provider | model | outcome | attempts | time | claims checked | unbacked |
|---|---|---|---|---|---|---|---|
| `live_batch_01` | cloud | `gemini-3.6-flash` | llm | 2 | 94.3s | 21 | **0** |
| `live_batch_01` | local | `llama3.2:3b` | llm | 1 | 9.9s | 25 | **0** |
| `live_batch_05` | cloud | `gemini-3.6-flash` | llm | 1 | 4.4s | 42 | **0** |
| `live_batch_05` | local | `llama3.2:3b` | llm | 1 | 7.9s | 26 | **0** |

**No invented identifiers, in any of the four briefs.** Every connection id
cited exists, every device named is one of the four real devices, and every
port and byte figure traces to a real connection.

The two attempts on the Gemini `live_batch_01` brief were *not* a validation
rejection - attempt 1 was a 90-second HTTPS read timeout, which is also the
whole of that 94.3s. The brief that came back on attempt 2 was accepted as-is.

---

## Gemini 3.6 Flash - the primary

Fully grounded on both runs. Every timeline entry is time-consistent with the
connection it cites, the uncertainty fields describe things that are genuinely
unknown rather than reciting boilerplate, and the prose carries the specifics
(`496 bytes`, `port 4444`) that make a brief actionable instead of vague.

### `live_batch_01` - clean win

```
  The device esp32-02 showed suspicious behavior by repeatedly connecting to broker on port 4444.

  ORIGIN:  esp32-02   (confidence 100%, high)

  WHAT HAPPENED
    00:13:15  esp32-02    esp32-02 sent 496 bytes to broker on port 4444.
                          evidence: C000468
    00:13:45  esp32-02    esp32-02 sent another 496 bytes to broker on port 4444.
                          evidence: C000486
    00:14:15  esp32-02    esp32-02 sent a third batch of 496 bytes to broker on port 4444.
                          evidence: C000504

  AFFECTED DEVICES
    esp32-02

  WHAT TO DO
    1. [NOW] Disconnect esp32-02 from the network.
       why: It is the only device flagged for suspicious activity starting at 00:13:00.

  WHAT WE ARE NOT SURE ABOUT
    It is unclear what specific data was transmitted in the 496-byte payloads sent to broker.
```

Timeline consistency - **3/3** entries match their cited evidence:

| stated time | device | cites | actual time(s) of cited evidence | consistent |
|---|---|---|---|---|
| 00:13:15 | esp32-02 | `C000468` | 00:13:15 | yes |
| 00:13:45 | esp32-02 | `C000486` | 00:13:45 | yes |
| 00:14:15 | esp32-02 | `C000504` | 00:14:15 | yes |

### `live_batch_05` - the near-miss

```
  A security incident was detected starting from laptop-i3 which affected multiple devices on the network.

  ORIGIN:  laptop-i3   (confidence 28%, medium)

  WHAT HAPPENED
    00:12:01  laptop-i3   laptop-i3 sent data to the broker on port 1883.
                          evidence: C000409
    00:12:03  laptop-i3   laptop-i3 sent additional data to the broker on port 1883.
                          evidence: C000410
    00:12:05  laptop-i3   laptop-i3 continued sending data to the broker on port 1883.
                          evidence: C000411
    00:13:15  esp32-02    esp32-02 sent data to the broker on port 4444.
                          evidence: C000458
    00:13:17  esp32-02    esp32-02 sent a broadcast message on port 0.
                          evidence: C000460
    00:13:45  esp32-02    esp32-02 sent more data to the broker on port 4444.
                          evidence: C000476
    00:14:15  esp32-02    esp32-02 sent further data to the broker on port 4444.
                          evidence: C000494
    00:14:19  laptop-i3   laptop-i3 sent a broadcast message on port 67.
                          evidence: C000497

  AFFECTED DEVICES
    laptop-i3, esp32-02

  WHAT TO DO
    1. [NOW] Disconnect laptop-i3 from the network immediately.
       why: This device is identified as the likely origin of the suspicious network activity.
    2. [NOW] Inspect and isolate esp32-02.
       why: This device showed flagged behavior shortly after the initial network activity began.

  WHAT WE ARE NOT SURE ABOUT
    We are uncertain about the origin device due to a low confidence level of 28 percent, with esp32-02 also identified as a potential source.
```

Timeline consistency - **8/8** entries match their cited evidence:

| stated time | device | cites | actual time(s) of cited evidence | consistent |
|---|---|---|---|---|
| 00:12:01 | laptop-i3 | `C000409` | 00:12:01 | yes |
| 00:12:03 | laptop-i3 | `C000410` | 00:12:03 | yes |
| 00:12:05 | laptop-i3 | `C000411` | 00:12:05 | yes |
| 00:13:15 | esp32-02 | `C000458` | 00:13:15 | yes |
| 00:13:17 | esp32-02 | `C000460` | 00:13:17 | yes |
| 00:13:45 | esp32-02 | `C000476` | 00:13:45 | yes |
| 00:14:15 | esp32-02 | `C000494` | 00:14:15 | yes |
| 00:14:19 | laptop-i3 | `C000497` | 00:14:19 | yes |

---

## llama3.2:3b - the offline fallback

Runs on the machine with no key and no network, in a third of the time, and
invents no identifiers. It is rougher in ways the validator is not built to
catch, and the two defects below are why it is the fallback rather than the
primary.

### `live_batch_01`

```
  Incident Brief: Named Malicious Device

  ORIGIN:  esp32-02   (confidence 100%, high)

  WHAT HAPPENED
    00:12:00  esp32-02    Device came online
                          evidence: C000468, C000486, C000504
    00:13:00  esp32-02    Device was already online
                          evidence: C000468, C000486, C000504
    00:13:15  esp32-02    Established connection to broker
                          evidence: C000468
    00:13:45  esp32-02    Established connection to broker
                          evidence: C000486
    00:14:15  esp32-02    Established connection to broker
                          evidence: C000504

  AFFECTED DEVICES
    esp32-02

  WHAT TO DO
    1. [NOW] Alert incident team
       why: Device was identified as malicious

  WHAT WE ARE NOT SURE ABOUT
    Device could not be determined as the origin of the incident.
```

Timeline consistency - **3/5** entries match their cited evidence:

| stated time | device | cites | actual time(s) of cited evidence | consistent |
|---|---|---|---|---|
| 00:12:00 | esp32-02 | `C000468`, `C000486`, `C000504` | 00:13:15, 00:13:45, 00:14:15 | **no** |
| 00:13:00 | esp32-02 | `C000468`, `C000486`, `C000504` | 00:13:15, 00:13:45, 00:14:15 | **no** |
| 00:13:15 | esp32-02 | `C000468` | 00:13:15 | yes |
| 00:13:45 | esp32-02 | `C000486` | 00:13:45 | yes |
| 00:14:15 | esp32-02 | `C000504` | 00:14:15 | yes |

### `live_batch_05`

```
  Incident Brief: Named Malware on Network

  ORIGIN:  laptop-i3   (confidence 28%, medium)

  WHAT HAPPENED
    00:12:00  laptop-i3   Initial connection to broker
                          evidence: C000409, C000410, C000411
    00:13:00  esp32-02    Connection to broker
                          evidence: C000458, C000460, C000476, C000494
    00:14:19  laptop-i3   Broadcast to unknown destination
                          evidence: C000497

  AFFECTED DEVICES
    laptop-i3, esp32-02

  WHAT TO DO
    1. [NOW] Isolate laptop-i3
       why: Malware activity detected
    2. [NOW] Block esp32-02
       why: Malware activity detected

  WHAT WE ARE NOT SURE ABOUT
    The origin of the malware could not be determined. The shortlisted devices are laptop-i3 and esp32-02.
```

Timeline consistency - **1/3** entries match their cited evidence:

| stated time | device | cites | actual time(s) of cited evidence | consistent |
|---|---|---|---|---|
| 00:12:00 | laptop-i3 | `C000409`, `C000410`, `C000411` | 00:12:01, 00:12:03, 00:12:05 | **no** |
| 00:13:00 | esp32-02 | `C000458`, `C000460`, `C000476`, `C000494` | 00:13:15, 00:13:17, 00:13:45, 00:14:15 | **no** |
| 00:14:19 | laptop-i3 | `C000497` | 00:14:19 | yes |

### Defect 1: the uncertainty field contradicts the verdict

On `live_batch_01` the brief states a `100%`, `high`-confidence origin of
esp32-02, and then closes with:

> Device could not be determined as the origin of the incident.

The abstention phrasing leaks into a maximally confident named result. The
verdict and the confidence figure are both transcribed correctly - the
validator checks those - but the free-text field flatly contradicts them. The
same sentence appears on `live_batch_05` ("The origin of the malware could not
be determined"), where at 28% it is closer to defensible, which is probably why
the phrasing survives: it is right often enough to look like a habit rather
than a bug.

### Defect 2: over-labelling the activity as malware

`live_batch_05` is headlined "Named Malware on Network" and gives "Malware
activity detected" as the rationale for both recommended actions.
`live_batch_01` calls the device "malicious". **Nothing in the pipeline
determines that any of this is malware.** The analysis ranks devices by onset
and indicator edges; it does not classify payloads.

This passes because the validator is deliberately strict about identifiers and
numbers and deliberately relaxed about English - "the camera sent an unusual
amount of data" has to be allowed for the briefs to read like briefs. The
asymmetry is the right trade, but it is where the remaining risk lives: a
fabricated byte count is caught, an unfounded characterisation is not.

---

## What the validator does not catch

Across the four briefs the audit found one class of unbacked claim that passed
validation: **a timestamp that exists in the evidence, attached to connections
that happened at a different time.**

| provider | timeline entries consistent with cited evidence |
|---|---|
| gemini-3.6-flash (cloud) | **11/11** |
| llama3.2:3b (local) | **4/8** |

The four local failures are all the same shape. On `live_batch_01`:

```
00:12:00  esp32-02  "Device came online"
          cites C000468, C000486, C000504
          ...which happened at 00:13:15, 00:13:45 and 00:14:15
```

`00:12:00` is real - it is `baseline_ends` in the evidence pack - but it is not
an esp32-02 event, and none of the three cited connections is anywhere near it.
esp32-02's onset is `00:13:00`. The validator checks that a clock value appears
*somewhere* in the evidence, not that it is consistent with the ids cited beside
it, so the claim passes.

Closing this would mean checking each timeline entry's stated time against the
timestamps of the connections it cites - the check the audit tables above
perform. It is not currently part of `validate_brief`.

---

## `live_batch_05`: transcription, not hallucination

Both models name **laptop-i3** - an innocent device - and both are right to.
The analysis named laptop-i3 at 28% confidence; the validator requires the brief
to match. Neither model hallucinated: the Gemini brief sources all eight of its
timeline entries exactly, and then recommends

> Disconnect laptop-i3 from the network immediately.

The better brief is the more dangerous one. It is fluent, every figure in it is
real, every id resolves - and it points at the wrong machine with an action
marked `NOW`. The 28% confidence and the "we are uncertain about the origin
device" line are the only things standing between the reader and a confident
wrong call, and both are transcribed faithfully from the analysis rather than
supplied by the model.

This is the honest summary of the layer: **a brief is exactly as correct as the
attribution behind it, and the validator guarantees only that it is exactly as
correct - no more, and no less.** Improving the 11/12 comes from the detector
and the rule, never from the report layer.

---

## Evidence packs

### `live_batch_01`

Devices: `esp32-01`, `esp32-02`, `esp32-03`, `laptop-i3`

Onsets: esp32-02 00:13:00. Baseline ends 00:12:00, capture length 00:17:24.

| id | time | from | to | port | bytes |
|---|---|---|---|---|---|
| `C000468` | 00:13:15 | esp32-02 | broker | 4444 | 496 |
| `C000486` | 00:13:45 | esp32-02 | broker | 4444 | 496 |
| `C000504` | 00:14:15 | esp32-02 | broker | 4444 | 496 |

### `live_batch_05`

Devices: `esp32-01`, `esp32-02`, `esp32-03`, `laptop-i3`

Onsets: esp32-02 00:13:00, laptop-i3 00:12:00. Baseline ends 00:12:00, capture length 00:17:24.

| id | time | from | to | port | bytes |
|---|---|---|---|---|---|
| `C000409` | 00:12:01 | laptop-i3 | broker | 1883 | 246 |
| `C000410` | 00:12:03 | laptop-i3 | broker | 1883 | 246 |
| `C000411` | 00:12:05 | laptop-i3 | broker | 1883 | 246 |
| `C000458` | 00:13:15 | esp32-02 | broker | 4444 | 496 |
| `C000460` | 00:13:17 | esp32-02 | broadcast | 0 | 60 |
| `C000476` | 00:13:45 | esp32-02 | broker | 4444 | 496 |
| `C000494` | 00:14:15 | esp32-02 | broker | 4444 | 496 |
| `C000497` | 00:14:19 | laptop-i3 | broadcast | 67 | 1368 |

## Reproducing this

```sh
python -m src.report live_batch_01 --provider cloud     # gemini-3.6-flash
python -m src.report live_batch_01 --provider local     # llama3.2:3b
python -m src.report live_batch_05 --provider cloud --show-evidence
```

`--provider local` remains the CLI default, because it needs neither a key nor
a network and keeps the offline demo working on a machine with no internet.
`--provider cloud` reads `GEMINI_API_KEY` from `API_KEY.env`, which is
gitignored and never committed. Use cloud wherever a key is available - the
quality gap above is the reason.
