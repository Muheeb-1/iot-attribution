# IoT Incident Attribution

**In one sentence:** this project reads network traffic from a small office /
lab network, works out *which device the attack started from*, and writes a
plain-English incident report that a non-expert can act on.

---

## The problem, in plain English

When something goes wrong on a network, lots of devices start behaving oddly at
once. The obvious question — "which one was hit **first**?" — is surprisingly
hard, because:

* the noisiest device is usually a **victim**, not the source;
* perfectly innocent devices have busy days too (backups, firmware updates);
* the attacker may hop from device A to device B **through a shared server**,
  so there is no direct A→B traffic to point at.

So the naive answers ("blame whoever sent the most data", "blame whoever went
weird first") are wrong most of the time. On our hard benchmark the best of
those standard approaches is right **17%** of the time.

## What this project does instead

It reconstructs the *story*. For every device it asks: "if this device were
patient zero, how much of everything else that happened does that explain?"
The device whose story explains the most, that nothing else points at, and
that started earliest, is named as the origin.

That method is called **V5**, and on the same hard benchmark it is right
**56.7%** of the time first try, and has the true origin in its **top 3 90%**
of the time. On the easy benchmark it is right **100%** of the time. When it is
not confident it says so and hands over a shortlist of three instead of
guessing.

## How it is put together

```
  data/run_NNN.parquet          the network traffic for one simulated incident
        |
        v
  src/features.py               summarise each device, 60 seconds at a time
        |
        v
  src/detect.py                 learn each device's "normal", find when it broke
        |
        v
  src/attribute.py   <-- V5     build the story graph, rank the suspects
        |
        v
  src/report.py                 a local LLM writes the incident brief
        |
        v
  dashboard/app.py              one Streamlit page a human actually looks at
```

Supporting pieces:

| File | What it is for |
|---|---|
| `src/windows.py` | The single shared helper that turns a timestamp into a 60-second window number. Everything uses this one function so the maths can never drift between files. |
| `src/generate.py` | Invents realistic traffic plus a hidden attack, so we have data with a known right answer. |
| `src/evaluate.py` | Marks our homework: runs the whole pipeline many times and scores it against the truth and against four standard baselines. |
| `groundtruth/` | The true answers. **Only `src/evaluate.py` is ever allowed to look in here.** |

## The rule we do not break

`groundtruth/` holds the answer sheet. If any detection or attribution code
peeked at it, our accuracy numbers would be fiction — we would be measuring how
well the code can read the answers, not how well it can do the job.

So: **nothing inside `src/` except `evaluate.py` may read `groundtruth/`.**
This is enforced by an automated test (`tests/test_no_groundtruth_leak.py`)
which fails the build if any other file in `src/` so much as mentions the word.

## Where the numbers came from

Two prototypes were written and run first, before any project code existed:

* `sim.py` — the easy benchmark (7 devices). Method gets ~90%.
* `hard.py` — the hard benchmark (12 devices, decoys, stealthy attacker,
  relayed hops). Compares five methods; **V5 wins**.

The real project rebuilds **V5** properly, in separate testable files, and must
reproduce those numbers. If it does not, something is broken and we want to
know.

Rebuilding it that way exposed a bug in the prototype's shared-indicator rule
(see *Two indicator rules* below). The prototype's rule is kept and still
reproduces its original figures exactly; the corrected rule is what the project
now uses by default.

## Results

Measured over 30 runs of each benchmark (`python -m src.evaluate --runs 30`,
saved to `results/table1.csv`). Every prototype-rule figure reproduces the
prototype exactly.

**Both indicator rules are scored side by side, on identical detections**, so
the effect of the rule change is *measured, not asserted*. The two V5 rows in
each table below differ in one thing only: whether a shared-indicator link is
required to agree with the detected onsets. Everything else — the same runs,
the same detector output, the same ranking code — is held fixed.

### Hard benchmark - 12 devices, decoys, stealthy attacker, 40% relayed hops

| method | top-1 | top-3 | mean rank | abstained |
|---|---:|---:|---:|---:|
| B1 blame the biggest sender | 0% | 10% | 6.07 | - |
| B2 blame the strangest-looking | 10% | 47% | 4.10 | - |
| B3 blame the busiest | 3% | 10% | 5.63 | - |
| B4 blame whoever went odd first | 17% | 53% | 3.27 | - |
| V5, prototype indicator rule | 53.3% | 90% | 2.00 | 17% |
| **V5 attribution** (corrected rule) | **56.7%** | **90%** | **1.90** | 17% |

### Easy benchmark - 7 devices, no decoys, no relayed hops

| method | top-1 | top-3 | mean rank | abstained |
|---|---:|---:|---:|---:|
| B1 blame the biggest sender | 13% | 47% | 3.50 | - |
| B2 blame the strangest-looking | 10% | 43% | 3.57 | - |
| B3 blame the busiest | 13% | 83% | 3.13 | - |
| B4 blame whoever went odd first | 50% | 100% | 1.57 | - |
| V5, prototype indicator rule | 90% | 100% | 1.10 | 7% |
| **V5 attribution** (corrected rule) | **100%** | **100%** | **1.00** | 0% |

V5 is right about three times as often as the best standard approach on the
hard benchmark, and when it is unsure it says so instead of guessing.

### Two indicator rules, scored side by side

V5 draws a link between two devices that both contacted the same address they
had never contacted before. The prototype additionally demanded that the
*detected onsets* agree with the order of first contact before drawing that
link — and that extra test throws the evidence away in exactly the runs the
indicator exists to rescue, the ones where the detector was misled. On
`run_000` the origin touched the attacker's address 480 seconds before its
first victim did, but the victim had been flagged 27 minutes earlier by an
innocent backup, so the link was refused and the graph came out empty.

Dropping that test is the only change. Because it can only ever *permit* more
links, the corrected graph is always a superset of the prototype's — enforced
by a test. A second test enforces that the two rules really do produce
different graphs on real runs, so the improvement cannot be noise.

| | hard top-1 | hard top-3 | easy top-1 | easy abstained |
|---|---:|---:|---:|---:|
| prototype rule | 53.3% | 90% | 90% | 7% |
| corrected rule | 56.7% | 90% | 100% | 0% |
| difference | **+3.4** | +0 | **+10** | **-7** |

`python -m src.evaluate` prints this comparison, the count of indicator links
recovered, and every run whose true origin moved — in either direction.

## The incident brief, and why it can be trusted

The last stage hands the findings to a local language model (`qwen3:4b` via
Ollama) to turn into plain English a non-expert can act on. Language models
invent things, so two guards sit around it:

1. **The shape is forced.** The brief is a pydantic model, and that model's
   JSON schema is passed to Ollama as `format=`. The model physically cannot
   return prose, a missing field, or a different structure.
2. **The facts are checked.** Before anything is shown, every evidence id,
   device name, address, port, timestamp and byte figure in the text is
   checked against the evidence that was passed in. Anything invented is
   rejected and the brief is regenerated once. Reject twice and the system
   abandons the model, falls back to a plain template, and marks the brief
   `LLM_FALLBACK` so nobody mistakes it for generated text.

Nothing unverified is ever displayed. The fallback rate is measured, not
hoped for. Over 20 hard runs with `qwen3:4b`:

| outcome | share |
|---|---:|
| passed validation first time | 55% |
| passed after one regeneration | 15% |
| rejected twice, fell back to the plain template | 30% |

In roughly a third of runs the model cannot produce a brief this project is
willing to show, and the reader gets the template instead. That is the system
working, not failing - the alternative is displaying a confident brief that
cites an evidence id which does not exist. Full workings, including a
false-positive bug the first measurement exposed in the validator itself, are
in `results/report_validation.md`.

## Getting started

```bash
py -3.12 -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pytest -q                       # all tests must pass
```

## Running the dashboard

```bash
streamlit run dashboard/app.py
```

It opens at <http://localhost:8501>. One page: the network as a diagram with
the attack path in red, a timeline of when each device went abnormal, the
ranked suspects with confidence bars, and the incident brief.

**Replay mode is on by default.** It reads a capture already saved in `data/`
and skips the language model, so the page works with nothing connected — no
internet, no Ollama. The full analysis still runs for real; every number on the
page is computed live from the traffic. Turn replay mode off in the sidebar to
have the brief written by `qwen3:4b`.

If `data/` is empty, generate some captures first:

```bash
python -m src.generate --runs 30
python -m src.generate --runs 30 --easy
```

## Project status

Built in numbered steps; each step is committed separately so the history shows
how it was assembled.

- [x] Setup: environment, folders, git, this README
- [x] Step 1 — `src/windows.py` + its tests (time windows)
- [x] Step 2 — `src/generate.py` (scenario generator, hard + easy)
- [x] Step 3 — `src/features.py`
- [x] Step 4 — `src/detect.py`
- [x] Step 5 — `src/attribute.py` (V5, the core)
- [x] Step 6 — `src/evaluate.py` (the results table)
- [x] Step 7 — `src/report.py` (local LLM brief + validation)
- [x] Step 8 — `dashboard/app.py` (Streamlit, with offline replay)
